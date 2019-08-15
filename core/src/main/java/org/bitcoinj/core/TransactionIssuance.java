/*
 * Copyright (c) 2019 The CommerceBlock Developers
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

package org.bitcoinj.core;

public class TransactionIssuance {
    private byte[] assetBlindingNonce;
    private byte[] assetEntropy;
    private byte[] assetamount;
    private byte[] tokenamount;
    private boolean isInitialized;
    int issuanceLength;

    public TransactionIssuance(){
        this.isInitialized = false;
        this.issuanceLength = 0;
    };

    public TransactionIssuance(byte[] assetBlindingNonce, byte[] assetEntropy,
        byte[] assetamount, byte[] tokenamount) {
        this.assetBlindingNonce = assetBlindingNonce;
        this.assetEntropy = assetEntropy;
        this.assetamount = assetamount;
        this.tokenamount = tokenamount;
        this.issuanceLength = 64 + assetamount.length + tokenamount.length;
        this.isInitialized = true;
    }

    public byte[] getAssetBlindingNonce() {
        return assetBlindingNonce;
    }

    public byte[] getAssetEntropy() {
        return assetEntropy;
    }

    public byte[] getAssetAmount() {
        return assetamount;
    }

    public byte[] getTokenAmount() {
        return tokenamount;
    }

    public boolean isValid() {
        return isInitialized;
    }

    public int getLength() {
        return issuanceLength;
    }
}
