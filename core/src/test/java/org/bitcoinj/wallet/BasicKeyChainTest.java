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

package org.bitcoinj.wallet;

import org.bitcoinj.core.BloomFilter;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Utils;
import org.bitcoinj.crypto.KeyCrypterException;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.junit.Assert.*;

public class BasicKeyChainTest {
    private BasicKeyChain chain;
    private AtomicReference<List<ECKey>> onKeysAdded;
    private AtomicBoolean onKeysAddedRan;

    @Before
    public void setup() {
        chain = new BasicKeyChain();
        onKeysAdded = new AtomicReference<>();
        onKeysAddedRan = new AtomicBoolean();
    }

    @Test
    @Ignore
    public void importKeys() {
        long now = Utils.currentTimeSeconds();
        Utils.setMockClock(now);
        final ECKey key1 = new ECKey();
        Utils.rollMockClock(86400);
        final ECKey key2 = new ECKey();
        final ArrayList<ECKey> keys = Lists.newArrayList(key1, key2);

        // Import two keys, check the event is correct.
        assertEquals(2, chain.importKeys(keys));
        assertEquals(2, chain.numKeys());
        assertTrue(onKeysAddedRan.getAndSet(false));
        assertArrayEquals(keys.toArray(), onKeysAdded.get().toArray());
        assertEquals(now, chain.getEarliestKeyCreationTime());
        // Check we ignore duplicates.
        final ECKey newKey = new ECKey();
        keys.add(newKey);
        assertEquals(1, chain.importKeys(keys));
        assertTrue(onKeysAddedRan.getAndSet(false));
        assertEquals(newKey, onKeysAdded.getAndSet(null).get(0));
        assertEquals(0, chain.importKeys(keys));
        assertFalse(onKeysAddedRan.getAndSet(false));
        assertNull(onKeysAdded.get());

        assertTrue(chain.hasKey(key1));
        assertTrue(chain.hasKey(key2));
        assertEquals(key1, chain.findKeyFromPubHash(key1.getPubKeyHash()));
        assertEquals(key2, chain.findKeyFromPubKey(key2.getPubKey()));
        assertNull(chain.findKeyFromPubKey(key2.getPubKeyHash()));
    }

    @Test
    public void removeKey() {
        ECKey key = new ECKey();
        chain.importKeys(key);
        assertEquals(1, chain.numKeys());
        assertTrue(chain.removeKey(key));
        assertEquals(0, chain.numKeys());
        assertFalse(chain.removeKey(key));
    }

    @Test
    @Ignore
    public void getKey() {
        ECKey key1 = chain.getKey(KeyChain.KeyPurpose.RECEIVE_FUNDS);
        assertTrue(onKeysAddedRan.getAndSet(false));
        assertEquals(key1, onKeysAdded.getAndSet(null).get(0));
        ECKey key2 = chain.getKey(KeyChain.KeyPurpose.CHANGE);
        assertFalse(onKeysAddedRan.getAndSet(false));
        assertEquals(key2, key1);
    }

    @Test
    public void keysBeforeAndAfter() throws Exception {
        Utils.setMockClock();
        long now = Utils.currentTimeSeconds();
        final ECKey key1 = new ECKey();
        Utils.rollMockClock(86400);
        final ECKey key2 = new ECKey();
        final List<ECKey> keys = Lists.newArrayList(key1, key2);
        assertEquals(2, chain.importKeys(keys));

        assertNull(chain.findOldestKeyAfter(now + 86400 * 2));
        assertEquals(key1, chain.findOldestKeyAfter(now - 1));
        assertEquals(key2, chain.findOldestKeyAfter(now + 86400 - 1));

        assertEquals(2, chain.findKeysBefore(now + 86400 * 2).size());
        assertEquals(1, chain.findKeysBefore(now + 1).size());
        assertEquals(0, chain.findKeysBefore(now - 1).size());
    }
}
