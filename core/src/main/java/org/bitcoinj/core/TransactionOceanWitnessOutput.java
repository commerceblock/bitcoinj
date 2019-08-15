/*
 * * Copyright (c) 2019 The CommerceBlock Developers
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
import java.util.ArrayList;

public class TransactionOceanWitnessOutput {
    private byte[] surjectionProof;
    private byte[] rangeProof;
    private boolean isInitialized;

    public TransactionOceanWitnessOutput(){
        this.isInitialized = false;
    };

    public TransactionOceanWitnessOutput(byte[] surjectionProof, byte[] rangeProof) {
        this.surjectionProof = surjectionProof;
        this.rangeProof = rangeProof;
        this.isInitialized = true;
    }

    public byte[] getSurjectionProof() {
        return surjectionProof;
    }

    public byte[] getRangeProof() {
        return rangeProof;
    }

    public boolean isValid() {
        return isInitialized;
    }
}
