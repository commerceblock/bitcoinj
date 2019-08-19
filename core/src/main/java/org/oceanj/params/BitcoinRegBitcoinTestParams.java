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
 * Network parameters for the regression test mode of bitcoind in which all blocks are trivially solvable.
 */
public class BitcoinRegBitcoinTestParams extends BitcoinTestNet2Params {
    private static final BigInteger MAX_TARGET = new BigInteger("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16);

    public BitcoinRegBitcoinTestParams() {
        super();
        // Difficulty adjustments are disabled for regtest. 
        // By setting the block interval for difficulty adjustments to Integer.MAX_VALUE we make sure difficulty never changes.    
        maxTarget = MAX_TARGET;
        id = ID_BTC_REGTEST;

        majorityEnforceBlockUpgrade = BitcoinMainNetParams.MAINNET_MAJORITY_ENFORCE_BLOCK_UPGRADE;
        majorityRejectBlockOutdated = BitcoinMainNetParams.MAINNET_MAJORITY_REJECT_BLOCK_OUTDATED;
        majorityWindow = BitcoinMainNetParams.MAINNET_MAJORITY_WINDOW;
    }

    @Override
    public boolean allowEmptyPeerChain() {
        return true;
    }

    private static BitcoinRegBitcoinTestParams instance;
    public static synchronized BitcoinRegBitcoinTestParams get() {
        if (instance == null) {
            instance = new BitcoinRegBitcoinTestParams();
        }
        return instance;
    }

    @Override
    public String getPaymentProtocolId() {
        return PAYMENT_PROTOCOL_ID_REGTEST;
    }
}
