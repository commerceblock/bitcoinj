/*
 * Copyright 2013 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.oceanj.wallet;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkState;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.protobuf.ByteString;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;
import javax.annotation.Nullable;
import org.oceanj.core.ECKey;
import org.oceanj.utils.Threading;

/**
 * A {@link KeyChain} that implements the simplest model possible: it can have keys imported into it, and just acts as
 * a dumb bag of keys. It will, left to its own devices, always return the same key for usage by the wallet, although
 * it will automatically add one to itself if it's empty or if encryption is requested.
 */
public class BasicKeyChain implements KeyChain {
    private final ReentrantLock lock = Threading.lock("BasicKeyChain");

    // Maps used to let us quickly look up a key given data we find in transcations or the block chain.
    private final LinkedHashMap<ByteString, ECKey> hashToKeys;
    private final LinkedHashMap<ByteString, ECKey> pubkeyToKeys;
    private boolean isWatching;

    public BasicKeyChain() {
        hashToKeys = new LinkedHashMap<>();
        pubkeyToKeys = new LinkedHashMap<>();
    }

    @Override
    public ECKey getKey(@Nullable KeyPurpose ignored) {
        lock.lock();
        try {
            if (hashToKeys.isEmpty()) {
                final ECKey key = new ECKey();
                importKeyLocked(key);
            }
            return hashToKeys.values().iterator().next();
        } finally {
            lock.unlock();
        }
    }

    @Override
    public List<ECKey> getKeys(@Nullable KeyPurpose purpose, int numberOfKeys) {
        checkArgument(numberOfKeys > 0);
        lock.lock();
        try {
            if (hashToKeys.size() < numberOfKeys) {

                List<ECKey> keys = new ArrayList<>();
                for (int i = 0; i < numberOfKeys - hashToKeys.size(); i++) {
                    keys.add(new ECKey());
                }

                ImmutableList<ECKey> immutableKeys = ImmutableList.copyOf(keys);
                importKeysLocked(immutableKeys);
            }

            List<ECKey> keysToReturn = new ArrayList<>();
            int count = 0;
            while (hashToKeys.values().iterator().hasNext() && numberOfKeys != count) {
                keysToReturn.add(hashToKeys.values().iterator().next());
                count++;
            }
            return keysToReturn;
        } finally {
            lock.unlock();
        }
    }

    /** Returns a copy of the list of keys that this chain is managing. */
    public List<ECKey> getKeys() {
        lock.lock();
        try {
            return new ArrayList<>(hashToKeys.values());
        } finally {
            lock.unlock();
        }
    }

    public int importKeys(ECKey... keys) {
        return importKeys(ImmutableList.copyOf(keys));
    }

    public int importKeys(List<? extends ECKey> keys) {
        lock.lock();
        try {
            List<ECKey> actuallyAdded = new ArrayList<>(keys.size());
            for (final ECKey key : keys) {
                if (hasKey(key)) continue;
                actuallyAdded.add(key);
                importKeyLocked(key);
            }
            return actuallyAdded.size();
        } finally {
            lock.unlock();
        }
    }

    private void importKeyLocked(ECKey key) {
        if (hashToKeys.isEmpty()) {
            isWatching = key.isWatching();
        } else {
            if (key.isWatching() && !isWatching)
                throw new IllegalArgumentException("Key is watching but chain is not");
            if (!key.isWatching() && isWatching)
                throw new IllegalArgumentException("Key is not watching but chain is");
        }
        ECKey previousKey = pubkeyToKeys.put(ByteString.copyFrom(key.getPubKey()), key);
        hashToKeys.put(ByteString.copyFrom(key.getPubKeyHash()), key);
        checkState(previousKey == null);
    }

    private void importKeysLocked(List<ECKey> keys) {
        for (ECKey key : keys) {
            importKeyLocked(key);
        }
    }

    /**
     * Imports a key to the key chain. If key is present in the key chain, ignore it.
     */
    public void importKey(ECKey key) {
        lock.lock();
        try {
            if (hasKey(key)) return;
            importKeyLocked(key);
        } finally {
            lock.unlock();
        }
    }

    public ECKey findKeyFromPubHash(byte[] pubkeyHash) {
        lock.lock();
        try {
            return hashToKeys.get(ByteString.copyFrom(pubkeyHash));
        } finally {
            lock.unlock();
        }
    }

    public ECKey findKeyFromPubKey(byte[] pubkey) {
        lock.lock();
        try {
            return pubkeyToKeys.get(ByteString.copyFrom(pubkey));
        } finally {
            lock.unlock();
        }
    }

    @Override
    public boolean hasKey(ECKey key) {
        return findKeyFromPubKey(key.getPubKey()) != null;
    }

    @Override
    public int numKeys() {
        return pubkeyToKeys.size();
    }

    /** Whether this basic key chain is empty, full of regular (usable for signing) keys, or full of watching keys. */
    public enum State {
        EMPTY,
        WATCHING,
        REGULAR
    }

    /**
     * Returns whether this chain consists of pubkey only (watching) keys, regular keys (usable for signing), or
     * has no keys in it yet at all (thus we cannot tell).
     */
    public State isWatching() {
        lock.lock();
        try {
            if (hashToKeys.isEmpty())
                return State.EMPTY;
            return isWatching ? State.WATCHING : State.REGULAR;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Removes the given key from the keychain. Be very careful with this - losing a private key <b>destroys the
     * money associated with it</b>.
     * @return Whether the key was removed or not.
     */
    public boolean removeKey(ECKey key) {
        lock.lock();
        try {
            boolean a = hashToKeys.remove(ByteString.copyFrom(key.getPubKeyHash())) != null;
            boolean b = pubkeyToKeys.remove(ByteString.copyFrom(key.getPubKey())) != null;
            checkState(a == b);   // Should be in both maps or neither.
            return a;
        } finally {
            lock.unlock();
        }
    }

    public long getEarliestKeyCreationTime() {
        lock.lock();
        try {
            long time = Long.MAX_VALUE;
            for (ECKey key : hashToKeys.values())
                time = Math.min(key.getCreationTimeSeconds(), time);
            return time;
        } finally {
            lock.unlock();
        }
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //
    // Key rotation support
    //
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    /** Returns the first ECKey created after the given UNIX time, or null if there is none. */
    @Nullable
    public ECKey findOldestKeyAfter(long timeSecs) {
        lock.lock();
        try {
            ECKey oldest = null;
            for (ECKey key : hashToKeys.values()) {
                final long keyTime = key.getCreationTimeSeconds();
                if (keyTime > timeSecs) {
                    if (oldest == null || oldest.getCreationTimeSeconds() > keyTime)
                        oldest = key;
                }
            }
            return oldest;
        } finally {
            lock.unlock();
        }
    }

    /** Returns a list of all ECKeys created after the given UNIX time. */
    public List<ECKey> findKeysBefore(long timeSecs) {
        lock.lock();
        try {
            List<ECKey> results = Lists.newLinkedList();
            for (ECKey key : hashToKeys.values()) {
                final long keyTime = key.getCreationTimeSeconds();
                if (keyTime < timeSecs) {
                    results.add(key);
                }
            }
            return results;
        } finally {
            lock.unlock();
        }
    }
}
