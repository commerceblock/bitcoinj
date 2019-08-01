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

package org.bitcoinj.params;

import org.bitcoinj.core.Utils;

/**
 * Parameters for the old version 2 testnet. This is not useful to you - it exists only because some unit tests are
 * based on it.
 */
public class BitcoinTestNet2Params extends AbstractNetParams {
    public static final int TESTNET_MAJORITY_WINDOW = 100;
    public static final int TESTNET_MAJORITY_REJECT_BLOCK_OUTDATED = 75;
    public static final int TESTNET_MAJORITY_ENFORCE_BLOCK_UPGRADE = 51;

    public BitcoinTestNet2Params() {
        super();
        init();
    }

    private void init() {
        id = ID_BTC_TESTNET;
        packetMagic = 0xfabfb5daL;
        addressHeader = 111;
        p2shHeader = 196;
        acceptableAddressCodes = new int[] { addressHeader, p2shHeader };
        maxTarget = Utils.decodeCompactBits(0x1d0fffffL);
        dumpedPrivateKeyHeader = 239;
        spendableCoinbaseDepth = 100;

        uriScheme = "bitcoin";
        bip32HeaderPub = 0x043587CF;
        bip32HeaderPriv = 0x04358394;
        bech32Prefix = "tb";
        bech32Separator = 0x31; // 1

        majorityEnforceBlockUpgrade = TESTNET_MAJORITY_ENFORCE_BLOCK_UPGRADE;
        majorityRejectBlockOutdated = TESTNET_MAJORITY_REJECT_BLOCK_OUTDATED;
        majorityWindow = TESTNET_MAJORITY_WINDOW;
    }

    private static BitcoinTestNet2Params instance;
    public static synchronized BitcoinTestNet2Params get() {
        if (instance == null) {
            instance = new BitcoinTestNet2Params();
        }
        return instance;
    }

    @Override
    public String getPaymentProtocolId() {
        return null;
    }
}
