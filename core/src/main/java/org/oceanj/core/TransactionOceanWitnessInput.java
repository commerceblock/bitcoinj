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

package org.oceanj.core;
import java.util.ArrayList;

public class TransactionOceanWitnessInput {
    private byte[] issuanceRangeProof;
    private byte[] inflationRangeProof;
    private ArrayList<byte[]> scriptWitness;
    private ArrayList<byte[]> peginWitness;
    private boolean isInitialized;

    public TransactionOceanWitnessInput(){
        this.isInitialized = false;
    };

    public TransactionOceanWitnessInput(byte[] issuanceRangeProof, byte[] inflationRangeProof,
        ArrayList<byte[]> scriptWitness, ArrayList<byte[]> peginWitness) {
        this.issuanceRangeProof = issuanceRangeProof;
        this.inflationRangeProof = inflationRangeProof;
        this.scriptWitness = scriptWitness;
        this.peginWitness = peginWitness;
        this.isInitialized = true;
    }

    public byte[] getIssuanceRangeProof() {
        return issuanceRangeProof;
    }

    public byte[] getInflationRangeProof() {
        return inflationRangeProof;
    }

    public ArrayList<byte[]> getScriptWitness() {
        return scriptWitness;
    }

    public ArrayList<byte[]> getPeginWitness() {
        return peginWitness;
    }

    public boolean isValid() {
        return isInitialized;
    }
}
