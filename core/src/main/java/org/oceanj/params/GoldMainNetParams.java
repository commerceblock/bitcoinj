/*
 * Copyright 2013 Google Inc.
 * Copyright 2015 Andreas Schildbach
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

import org.oceanj.core.Utils;

/**
 * Parameters for the main production network on which people trade goods and services.
 */
public class GoldMainNetParams extends AbstractNetParams {
    public static final int MAINNET_MAJORITY_WINDOW = 1000;
    public static final int MAINNET_MAJORITY_REJECT_BLOCK_OUTDATED = 950;
    public static final int MAINNET_MAJORITY_ENFORCE_BLOCK_UPGRADE = 750;
    public static final String URI_SCHEME = "bitcoin";

    public GoldMainNetParams() {
        super();
        maxTarget = Utils.decodeCompactBits(0x1d00ffffL);
        dumpedPrivateKeyHeader = 180;
        addressHeader = 38;
        p2shHeader = 97;
        acceptableAddressCodes = new int[] { addressHeader, p2shHeader };
        packetMagic = 0xf9beb4d9L;

        uriScheme = URI_SCHEME;
        bip32HeaderPub = 0x0488b21e; //The 4 byte header that serializes in base58 to "xpub".
        bip32HeaderPriv = 0x0488ade4; //The 4 byte header that serializes in base58 to "xprv"
        bech32Prefix = "bc";
        bech32Separator = 0x31; // 1

        majorityEnforceBlockUpgrade = MAINNET_MAJORITY_ENFORCE_BLOCK_UPGRADE;
        majorityRejectBlockOutdated = MAINNET_MAJORITY_REJECT_BLOCK_OUTDATED;
        majorityWindow = MAINNET_MAJORITY_WINDOW;

        id = ID_GOLD_MAINNET;
        spendableCoinbaseDepth = 100;
    }

    private static GoldMainNetParams instance;
    public static synchronized GoldMainNetParams get() {
        if (instance == null) {
            instance = new GoldMainNetParams();
        }
        return instance;
    }

    @Override
    public String getPaymentProtocolId() {
        return PAYMENT_PROTOCOL_ID_MAINNET;
    }
}
