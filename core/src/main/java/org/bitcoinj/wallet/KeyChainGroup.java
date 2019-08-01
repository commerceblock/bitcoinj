/*
 * Copyright 2014 Mike Hearn
 * Copyright 2014 Andreas Schildbach
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

import com.google.common.collect.*;
import com.google.protobuf.*;
import org.bitcoinj.core.*;
import org.bitcoinj.crypto.*;
import org.bitcoinj.script.*;
import org.bitcoinj.utils.*;
import org.slf4j.*;
import org.spongycastle.crypto.params.*;

import javax.annotation.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;

import static com.google.common.base.Preconditions.*;

/**
 * <p>A KeyChainGroup is used by the a wallet and
 * manages: a {@link BasicKeyChain} object (which will normally be empty), and zero or more
 * {@link DeterministicKeyChain}s. A deterministic key chain will be created lazily/on demand
 * when a fresh or current key is requested, possibly being initialized from the private key bytes of the earliest non
 * rotating key in the basic key chain if one is available, or from a fresh random seed if not.</p>
 *
 * <p>If a key rotation time is set, it may be necessary to add a new DeterministicKeyChain with a fresh seed
 * and also preserve the old one, so funds can be swept from the rotating keys. In this case, there may be
 * more than one deterministic chain. The latest chain is called the active chain and is where new keys are served
 * from.</p>
 *
 * <p>The wallet delegates most key management tasks to this class. It is <b>not</b> thread safe and requires external
 * locking, i.e. by the wallet lock. The group then in turn delegates most operations to the key chain objects,
 * combining their responses together when necessary.</p>
 *
 * <p>Deterministic key chains have a concept of a lookahead size and threshold. Please see the discussion in the
 * class docs for {@link DeterministicKeyChain} for more information on this topic.</p>
 */
public class KeyChainGroup implements KeyBag {

    static {
        // Init proper random number generator, as some old Android installations have bugs that make it unsecure.
        if (Utils.isAndroidRuntime())
            new LinuxSecureRandom();
    }

    private static final Logger log = LoggerFactory.getLogger(KeyChainGroup.class);

    private BasicKeyChain basic;
    private NetworkParameters params;
    protected final LinkedList<DeterministicKeyChain> chains;
    // currentKeys is used for normal, non-multisig/married wallets. currentAddresses is used when we're handing out
    // P2SH addresses. They're mutually exclusive.
    private final EnumMap<KeyChain.KeyPurpose, DeterministicKey> currentKeys;
    private final EnumMap<KeyChain.KeyPurpose, Address> currentAddresses;

    /** Creates a keychain group with no basic chain, and a single, lazily created HD chain. */
    public KeyChainGroup(NetworkParameters params) {
        this(params, null, new ArrayList<DeterministicKeyChain>(1), null);
    }

    /** Creates a keychain group with no basic chain, and an HD chain initialized from the given seed. */
    public KeyChainGroup(NetworkParameters params, DeterministicSeed seed) {
        this(params, null, ImmutableList.of(new DeterministicKeyChain(seed)), null);
    }

    /**
     * Creates a keychain group with no basic chain, and an HD chain initialized from the given seed. Account path is
     * provided.
     */
    public KeyChainGroup(NetworkParameters params, DeterministicSeed seed, ImmutableList<ChildNumber> accountPath) {
        this(params, null, ImmutableList.of(new DeterministicKeyChain(seed, accountPath)), null);
    }

    /**
     * Creates a keychain group with no basic chain, and an HD chain that is watching the given watching key.
     * This HAS to be an account key as returned by {@link DeterministicKeyChain#getWatchingKey()}.
     */
    public KeyChainGroup(NetworkParameters params, DeterministicKey watchKey) {
        this(params, null, ImmutableList.of(DeterministicKeyChain.watch(watchKey)), null);
    }

    /**
     * Creates a keychain group with no basic chain, and an HD chain that is watching the given watching key.
     * This HAS to be an account key as returned by {@link DeterministicKeyChain#getWatchingKey()}.
     */
    public KeyChainGroup(NetworkParameters params, DeterministicKey watchKey, ImmutableList<ChildNumber> accountPath) {
        this(params, null, ImmutableList.of(DeterministicKeyChain.watch(watchKey, accountPath)), null);
    }

    // Used for deserialization.
    private KeyChainGroup(NetworkParameters params, @Nullable BasicKeyChain basicKeyChain, List<DeterministicKeyChain> chains,
        @Nullable EnumMap<KeyChain.KeyPurpose, DeterministicKey> currentKeys) {
        this.params = params;
        this.basic = basicKeyChain == null ? new BasicKeyChain() : basicKeyChain;
        this.chains = new LinkedList<>(checkNotNull(chains));
        this.currentKeys = currentKeys == null
            ? new EnumMap<KeyChain.KeyPurpose, DeterministicKey>(KeyChain.KeyPurpose.class)
            : currentKeys;
        this.currentAddresses = new EnumMap<>(KeyChain.KeyPurpose.class);
        maybeLookaheadScripts();
    }

    // This keeps married redeem data in sync with the number of keys issued
    private void maybeLookaheadScripts() {
        for (DeterministicKeyChain chain : chains) {
            chain.maybeLookAheadScripts();
        }
    }

    /** Imports the given keys into the basic chain, creating it if necessary. */
    public int importKeys(List<ECKey> keys) {
        return basic.importKeys(keys);
    }

    /** Imports the given keys into the basic chain, creating it if necessary. */
    public int importKeys(ECKey... keys) {
        return importKeys(ImmutableList.copyOf(keys));
    }

    @Override
    @Nullable
    public RedeemData findRedeemDataFromScriptHash(byte[] scriptHash) {
        // Iterate in reverse order, since the active keychain is the one most likely to have the hit
        for (Iterator<DeterministicKeyChain> iter = chains.descendingIterator() ; iter.hasNext() ; ) {
            DeterministicKeyChain chain = iter.next();
            RedeemData redeemData = chain.findRedeemDataByScriptHash(ByteString.copyFrom(scriptHash));
            if (redeemData != null)
                return redeemData;
        }
        return null;
    }

    @Nullable
    @Override
    public ECKey findKeyFromPubHash(byte[] pubkeyHash) {
        ECKey result;
        if ((result = basic.findKeyFromPubHash(pubkeyHash)) != null)
            return result;
        for (DeterministicKeyChain chain : chains) {
            if ((result = chain.findKeyFromPubHash(pubkeyHash)) != null)
                return result;
        }
        return null;
    }

    @Nullable
    @Override
    public ECKey findKeyFromPubKey(byte[] pubkey) {
        ECKey result;
        if ((result = basic.findKeyFromPubKey(pubkey)) != null)
            return result;
        for (DeterministicKeyChain chain : chains) {
            if ((result = chain.findKeyFromPubKey(pubkey)) != null)
                return result;
        }
        return null;
    }

    private static EnumMap<KeyChain.KeyPurpose, DeterministicKey> createCurrentKeysMap(List<DeterministicKeyChain> chains) {
        DeterministicKeyChain activeChain = chains.get(chains.size() - 1);

        EnumMap<KeyChain.KeyPurpose, DeterministicKey> currentKeys = new EnumMap<>(KeyChain.KeyPurpose.class);

        // assuming that only RECEIVE and CHANGE keys are being used at the moment, we will treat latest issued external key
        // as current RECEIVE key and latest issued internal key as CHANGE key. This should be changed as soon as other
        // kinds of KeyPurpose are introduced.
        if (activeChain.getIssuedExternalKeys() > 0) {
            DeterministicKey currentExternalKey = activeChain.getKeyByPath(
                HDUtils.append(
                    HDUtils.concat(activeChain.getAccountPath(), DeterministicKeyChain.EXTERNAL_SUBPATH),
                    new ChildNumber(activeChain.getIssuedExternalKeys() - 1)));
            currentKeys.put(KeyChain.KeyPurpose.RECEIVE_FUNDS, currentExternalKey);
        }

        if (activeChain.getIssuedInternalKeys() > 0) {
            DeterministicKey currentInternalKey = activeChain.getKeyByPath(
                HDUtils.append(
                    HDUtils.concat(activeChain.getAccountPath(), DeterministicKeyChain.INTERNAL_SUBPATH),
                    new ChildNumber(activeChain.getIssuedInternalKeys() - 1)));
            currentKeys.put(KeyChain.KeyPurpose.CHANGE, currentInternalKey);
        }
        return currentKeys;
    }

    public String toString(boolean includePrivateKeys) {
        final StringBuilder builder = new StringBuilder();
        if (basic != null) {
            List<ECKey> keys = basic.getKeys();
            Collections.sort(keys, ECKey.AGE_COMPARATOR);
            for (ECKey key : keys)
                key.formatKeyWithAddress(builder, params);
        }
        for (DeterministicKeyChain chain : chains)
            builder.append(chain.toString(includePrivateKeys, params)).append('\n');
        return builder.toString();
    }
}