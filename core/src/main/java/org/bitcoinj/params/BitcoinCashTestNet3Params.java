/*
 * Copyright 2013 Google Inc.
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

package org.bitcoinj.params;

import java.util.Date;
import org.bitcoinj.core.Utils;

/**
 * Parameters for the testnet, a separate public instance of Bitcoin that has relaxed rules suitable for development
 * and testing of applications and new Bitcoin versions.
 */
public class BitcoinCashTestNet3Params extends AbstractNetParams {
    public BitcoinCashTestNet3Params() {
        super();
        id = ID_BCH_TESTNET;
        // Genesis hash is 000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943
        packetMagic = 0xf4e5f3f4L;
        maxTarget = Utils.decodeCompactBits(0x1d00ffffL);
        addressHeader = 111;
        p2shHeader = 196;
        acceptableAddressCodes = new int[] { addressHeader, p2shHeader };
        dumpedPrivateKeyHeader = 239;
        spendableCoinbaseDepth = 100;
        alertSigningKey = Utils.HEX.decode("04302390343f91cc401d56d68b123028bf52e5fca1939df127f63c6467cdf9c8e2c14b61104cf817d0b780da337893ecc4aaff1309e536162dabbdb45200ca2b0a");

        uriScheme = "bitcoincash";
        bip32HeaderPub = 0x043587CF;
        bip32HeaderPriv = 0x04358394;
        bech32Prefix = "bchtest";
        bech32Separator = 0x3a; // :

        majorityEnforceBlockUpgrade = BitcoinTestNet2Params.TESTNET_MAJORITY_ENFORCE_BLOCK_UPGRADE;
        majorityRejectBlockOutdated = BitcoinTestNet2Params.TESTNET_MAJORITY_REJECT_BLOCK_OUTDATED;
        majorityWindow = BitcoinTestNet2Params.TESTNET_MAJORITY_WINDOW;
    }

    private static BitcoinCashTestNet3Params instance;
    public static synchronized BitcoinCashTestNet3Params get() {
        if (instance == null) {
            instance = new BitcoinCashTestNet3Params();
        }
        return instance;
    }

    @Override
    public String getPaymentProtocolId() {
        return PAYMENT_PROTOCOL_ID_TESTNET;
    }

    // February 16th 2012
    private static final Date testnetDiffDate = new Date(1329264000000L);
}
