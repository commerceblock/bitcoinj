/*
 * Copyright 2011 Google Inc.
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

package org.oceanj.core;

import com.google.common.base.Objects;
import org.oceanj.params.*;
import org.oceanj.script.*;

import org.oceanj.utils.MonetaryFormat;

import javax.annotation.*;
import java.math.*;
import java.util.*;

import static org.oceanj.core.Coin.*;
import org.oceanj.utils.VersionTally;

/**
 * <p>NetworkParameters contains the data needed for working with an instantiation of a Bitcoin chain.</p>
 *
 * <p>This is an abstract class, concrete instantiations can be found in the params package. There are four:
 * one for the main network ({@link BitcoinMainNetParams}), one for the public test network, and two others that are
 * intended for unit testing and local app development purposes. Although this class contains some aliases for
 * them, you are encouraged to call the static get() methods on each specific params class directly.</p>
 */
public abstract class NetworkParameters {
    /**
     * The alert signing key originally owned by Satoshi, and now passed on to Gavin along with a few others.
     */
    public static final byte[] SATOSHI_KEY = Utils.HEX.decode("04fc9702847840aaf195de8442ebecedf5b095cdbb9bc716bda9110971b28a49e0ead8564ff0db22209e0374782c093bb899692d524e9d6a6956e7c5ecbcd68284");

    /** The string returned by getId() for the main, production network where people trade things. */
    public static final String ID_BTC_MAINNET = "org.bitcoin.production";
    /** The string returned by getId() for the testnet. */
    public static final String ID_BTC_TESTNET = "org.bitcoin.test";
    /** The string returned by getId() for regtest mode. */
    public static final String ID_BTC_REGTEST = "org.bitcoin.regtest";
    /** Unit test network. */
    public static final String ID_BTC_UNITTESTNET = "org.oceanj.unittest";

    /** The string returned by getId() for the main, production ocean network where people trade things. */
    public static final String ID_OCEAN_MAINNET = "org.ocean.production";
    /** The string returned by getId() for the testnet. */
    public static final String ID_OCEAN_TESTNET = "org.ocean.test";

    /** The string returned by getId() for the main, production gold network where people trade things. */
    public static final String ID_GOLD_MAINNET = "org.gold.production";
    /** The string returned by getId() for the testnet. */
    public static final String ID_GOLD_TESTNET = "org.gold.test";

    /** The string used by the payment protocol to represent the main net. */
    public static final String PAYMENT_PROTOCOL_ID_MAINNET = "main";
    /** The string used by the payment protocol to represent the test net. */
    public static final String PAYMENT_PROTOCOL_ID_TESTNET = "test";
    /** The string used by the payment protocol to represent unit testing (note that this is non-standard). */
    public static final String PAYMENT_PROTOCOL_ID_UNIT_TESTS = "unittest";
    public static final String PAYMENT_PROTOCOL_ID_REGTEST = "regtest";

    // TODO: Seed nodes should be here as well.

    protected String uriScheme;
    protected BigInteger maxTarget;
    protected long packetMagic;  // Indicates message origin network and is used to seek to the next message when stream state is unknown.
    protected int addressHeader;
    protected int p2shHeader;
    protected int dumpedPrivateKeyHeader;
    protected byte[] alertSigningKey;
    protected int bip32HeaderPub;
    protected int bip32HeaderPriv;
    protected String bech32Prefix;
    protected byte bech32Separator;

    /** Used to check majorities for block version upgrade */
    protected int majorityEnforceBlockUpgrade;
    protected int majorityRejectBlockOutdated;
    protected int majorityWindow;

    /**
     * See getId(). This may be null for old deserialized wallets. In that case we derive it heuristically
     * by looking at the port number.
     */
    protected String id;

    /**
     * The depth of blocks required for a coinbase transaction to be spendable.
     */
    protected int spendableCoinbaseDepth;

    protected int[] acceptableAddressCodes;
    protected transient MessageSerializer defaultSerializer = null;

    protected NetworkParameters() {
        alertSigningKey = SATOSHI_KEY;
    }

    /**
     * Blocks with a timestamp after this should enforce BIP 16, aka "Pay to script hash". This BIP changed the
     * network rules in a soft-forking manner, that is, blocks that don't follow the rules are accepted but not
     * mined upon and thus will be quickly re-orged out as long as the majority are enforcing the rule.
     */
    public static final int BIP16_ENFORCE_TIME = 1333238400;
    
    /**
     * The maximum number of coins to be generated
     */
    public static final long MAX_COINS = 21000000;

    /**
     * The maximum money to be generated
     */
    public static final Coin MAX_MONEY = COIN.multiply(MAX_COINS);

    /** Alias for BitcoinTestNet3Params.get(), use that instead. */
    @Deprecated
    public static NetworkParameters testNet() {
        return BitcoinTestNet3Params.get();
    }

    /** Alias for BitcoinTestNet2Params.get(), use that instead. */
    @Deprecated
    public static NetworkParameters testNet2() {
        return BitcoinTestNet2Params.get();
    }

    /** Alias for BitcoinTestNet3Params.get(), use that instead. */
    @Deprecated
    public static NetworkParameters testNet3() {
        return BitcoinTestNet3Params.get();
    }

    /** Alias for BitcoinMainNetParams.get(), use that instead */
    @Deprecated
    public static NetworkParameters prodNet() {
        return BitcoinMainNetParams.get();
    }

    /** Returns a testnet params modified to allow any difficulty target. */
    @Deprecated
    public static NetworkParameters unitTests() {
        return BitcoinUnitTestParams.get();
    }

    /** Returns a standard regression test params (similar to unitTests) */
    @Deprecated
    public static NetworkParameters regTests() {
        return BitcoinRegBitcoinTestParams.get();
    }

    /**
     * A Java package style string acting as unique ID for these parameters
     */
    public String getId() {
        return id;
    }

    public abstract String getPaymentProtocolId();

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        return getId().equals(((NetworkParameters)o).getId());
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(getId());
    }

    /** Returns the network parameters for the given string ID or NULL if not recognized. */
    @Nullable
    public static NetworkParameters fromID(String id) {
        if (id.equals(ID_BTC_MAINNET)) {
            return BitcoinMainNetParams.get();
        } else if (id.equals(ID_BTC_TESTNET)) {
            return BitcoinTestNet3Params.get();
        } else if (id.equals(ID_BTC_UNITTESTNET)) {
            return BitcoinUnitTestParams.get();
        } else if (id.equals(ID_BTC_REGTEST)) {
            return BitcoinRegBitcoinTestParams.get();
        } else if (id.equals(ID_OCEAN_MAINNET)) {
            return OceanMainNetParams.get();
        } else if (id.equals(ID_OCEAN_TESTNET)) {
            return OceanTestNetParams.get();
        } else if (id.equals(ID_GOLD_MAINNET)) {
            return GoldMainNetParams.get();
        } else if (id.equals(ID_GOLD_TESTNET)) {
            return GoldTestNetParams.get();
        } else {
            return null;
        }
    }

    /** Returns the network parameters for the given string paymentProtocolID or NULL if not recognized. */
    @Nullable
    public static NetworkParameters fromPmtProtocolID(String pmtProtocolId) {
        if (pmtProtocolId.equals(PAYMENT_PROTOCOL_ID_MAINNET)) {
            return GoldMainNetParams.get();
        } else if (pmtProtocolId.equals(PAYMENT_PROTOCOL_ID_TESTNET)) {
            return GoldTestNetParams.get();
        } else if (pmtProtocolId.equals(PAYMENT_PROTOCOL_ID_UNIT_TESTS)) {
            return BitcoinUnitTestParams.get();
        } else if (pmtProtocolId.equals(PAYMENT_PROTOCOL_ID_REGTEST)) {
            return BitcoinRegBitcoinTestParams.get();
        } else {
            return null;
        }
    }

    public int getSpendableCoinbaseDepth() {
        return spendableCoinbaseDepth;
    }

    /** The header bytes that identify the start of a packet on this network. */
    public long getPacketMagic() {
        return packetMagic;
    }

    /**
     * First byte of a base58 encoded address. See {@link org.oceanj.core.Address}. This is the same as acceptableAddressCodes[0] and
     * is the one used for "normal" addresses. Other types of address may be encountered with version codes found in
     * the acceptableAddressCodes array.
     */
    public int getAddressHeader() {
        return addressHeader;
    }

    /**
     * First byte of a base58 encoded P2SH address.  P2SH addresses are defined as part of BIP0013.
     */
    public int getP2SHHeader() {
        return p2shHeader;
    }

    /** First byte of a base58 encoded dumped private key. See {@link org.oceanj.core.DumpedPrivateKey}. */
    public int getDumpedPrivateKeyHeader() {
        return dumpedPrivateKeyHeader;
    }

    /**
     * The version codes that prefix addresses which are acceptable on this network. Although Satoshi intended these to
     * be used for "versioning", in fact they are today used to discriminate what kind of data is contained in the
     * address and to prevent accidentally sending coins across chains which would destroy them.
     */
    public int[] getAcceptableAddressCodes() {
        return acceptableAddressCodes;
    }

    /**
     * If we are running in testnet-in-a-box mode, we allow connections to nodes with 0 non-genesis blocks.
     */
    public boolean allowEmptyPeerChain() {
        return true;
    }

    /** Maximum target represents the easiest allowable proof of work. */
    public BigInteger getMaxTarget() {
        return maxTarget;
    }

    /**
     * The key used to sign {@link org.oceanj.core.AlertMessage}s. You can use {@link org.oceanj.core.ECKey#verify(byte[], byte[], byte[])} to verify
     * signatures using it.
     */
    public byte[] getAlertSigningKey() {
        return alertSigningKey;
    }

    /** Returns the 4 byte header for BIP32 (HD) wallet - public key part. */
    public int getBip32HeaderPub() {
        return bip32HeaderPub;
    }

    /** Returns the 4 byte header for BIP32 (HD) wallet - private key part. */
    public int getBip32HeaderPriv() {
        return bip32HeaderPriv;
    }

    /**
     * Returns the number of coins that will be produced in total, on this
     * network. Where not applicable, a very large number of coins is returned
     * instead (i.e. the main coin issue for Dogecoin).
     */
    public abstract Coin getMaxMoney();

    /**
     * Any standard (ie pay-to-address) output smaller than this value will
     * most likely be rejected by the network.
     */
    public abstract Coin getMinNonDustOutput();

    /**
     * The monetary object for this currency.
     */
    public abstract MonetaryFormat getMonetaryFormat();

    /**
     * Scheme part for URIs, for example "bitcoin".
     */
    public String getUriScheme() {
        return uriScheme;
    }

    /**
     * Returns whether this network has a maximum number of coins (finite supply) or
     * not. Always returns true for Bitcoin, but exists to be overriden for other
     * networks.
     */
    public abstract boolean hasMaxMoney();

    /**
     * Return the default serializer for this network. This is a shared serializer.
     * @return the default serializer for this network.
     */
    public final MessageSerializer getDefaultSerializer() {
        // Construct a default serializer if we don't have one
        if (null == this.defaultSerializer) {
            // Don't grab a lock unless we absolutely need it
            synchronized(this) {
                // Now we have a lock, double check there's still no serializer
                // and create one if so.
                if (null == this.defaultSerializer) {
                    // As the serializers are intended to be immutable, creating
                    // two due to a race condition should not be a problem, however
                    // to be safe we ensure only one exists for each network.
                    this.defaultSerializer = getSerializer(false);
                }
            }
        }
        return defaultSerializer;
    }

    /**
     * Construct and return a custom serializer.
     */
    public abstract BitcoinSerializer getSerializer(boolean parseRetain);

    /**
     * The number of blocks in the last {@link #getMajorityWindow()} blocks
     * at which to trigger a notice to the user to upgrade their client, where
     * the client does not understand those blocks.
     */
    public int getMajorityEnforceBlockUpgrade() {
        return majorityEnforceBlockUpgrade;
    }

    /**
     * The number of blocks in the last {@link #getMajorityWindow()} blocks
     * at which to enforce the requirement that all new blocks are of the
     * newer type (i.e. outdated blocks are rejected).
     */
    public int getMajorityRejectBlockOutdated() {
        return majorityRejectBlockOutdated;
    }

    /**
     * The sampling window from which the version numbers of blocks are taken
     * in order to determine if a new block version is now the majority.
     */
    public int getMajorityWindow() {
        return majorityWindow;
    }

    /**
     * The flags indicating which block validation tests should be applied to
     * the given block. Enables support for alternative blockchains which enable
     * tests based on different criteria.
     * 
     * @param block block to determine flags for.
     * @param height height of the block, if known, null otherwise. Returned
     * tests should be a safe subset if block height is unknown.
     */
    public EnumSet<Block.VerifyFlag> getBlockVerificationFlags(final Block block,
            final VersionTally tally, final Integer height) {
        final EnumSet<Block.VerifyFlag> flags = EnumSet.noneOf(Block.VerifyFlag.class);

        if (block.isBIP34()) {
            final Integer count = tally.getCountAtOrAbove(Block.BLOCK_VERSION_BIP34);
            if (null != count && count >= getMajorityEnforceBlockUpgrade()) {
                flags.add(Block.VerifyFlag.HEIGHT_IN_COINBASE);
            }
        }
        return flags;
    }

    /**
     * The flags indicating which script validation tests should be applied to
     * the given transaction. Enables support for alternative blockchains which enable
     * tests based on different criteria.
     *
     * @param block block the transaction belongs to.
     * @param transaction to determine flags for.
     * @param height height of the block, if known, null otherwise. Returned
     * tests should be a safe subset if block height is unknown.
     */
    public EnumSet<Script.VerifyFlag> getTransactionVerificationFlags(final Block block,
            final Transaction transaction, final VersionTally tally, final Integer height) {
        final EnumSet<Script.VerifyFlag> verifyFlags = EnumSet.noneOf(Script.VerifyFlag.class);
        if (block.getTimeSeconds() >= NetworkParameters.BIP16_ENFORCE_TIME)
            verifyFlags.add(Script.VerifyFlag.P2SH);

        // Start enforcing CHECKLOCKTIMEVERIFY, (BIP65) for block.nVersion=4
        // blocks, when 75% of the network has upgraded:
        if (block.getVersion() >= Block.BLOCK_VERSION_BIP65 &&
            tally.getCountAtOrAbove(Block.BLOCK_VERSION_BIP65) > this.getMajorityEnforceBlockUpgrade()) {
            verifyFlags.add(Script.VerifyFlag.CHECKLOCKTIMEVERIFY);
        }

        return verifyFlags;
    }

    public String getBech32AddressPrefix() {
        return bech32Prefix;
    }

    public byte getBech32AddressSeparator() {
        return bech32Separator;
    }

    public abstract int getProtocolVersionNum(final ProtocolVersion version);

    public static enum ProtocolVersion {
        MINIMUM(70000),
        PONG(60001),
        BLOOM_FILTER(70000),
        CURRENT(70012);

        private final int bitcoinProtocol;

        ProtocolVersion(final int bitcoinProtocol) {
            this.bitcoinProtocol = bitcoinProtocol;
        }

        public int getBitcoinProtocolVersion() {
            return bitcoinProtocol;
        }
    }
}
