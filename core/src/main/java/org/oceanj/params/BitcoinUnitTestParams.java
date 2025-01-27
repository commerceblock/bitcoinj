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

package org.oceanj.params;

import java.math.BigInteger;

/**
 * Network parameters used by the oceanj unit tests (and potentially your own). This lets you solve a block using
 * {@link org.oceanj.core.Block#solve()} by setting difficulty to the easiest possible.
 */
public class BitcoinUnitTestParams extends AbstractNetParams {
    public static final int UNITNET_MAJORITY_WINDOW = 8;
    public static final int TESTNET_MAJORITY_REJECT_BLOCK_OUTDATED = 6;
    public static final int TESTNET_MAJORITY_ENFORCE_BLOCK_UPGRADE = 4;

    public BitcoinUnitTestParams() {
        super();
        id = ID_BTC_UNITTESTNET;
        packetMagic = 0x0b110907;
        addressHeader = 111;
        p2shHeader = 196;
        acceptableAddressCodes = new int[] { addressHeader, p2shHeader };
        maxTarget = new BigInteger("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16);
        dumpedPrivateKeyHeader = 239;
        spendableCoinbaseDepth = 5;
        bip32HeaderPub = 0x043587CF;
        bip32HeaderPriv = 0x04358394;

        majorityEnforceBlockUpgrade = 3;
        majorityRejectBlockOutdated = 4;
        majorityWindow = 7;
    }

    private static BitcoinUnitTestParams instance;
    public static synchronized BitcoinUnitTestParams get() {
        if (instance == null) {
            instance = new BitcoinUnitTestParams();
        }
        return instance;
    }

    @Override
    public String getPaymentProtocolId() {
        return "unittest";
    }
}
