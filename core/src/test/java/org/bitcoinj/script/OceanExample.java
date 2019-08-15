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

package org.bitcoinj.script;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bitcoinj.core.*;
import org.bitcoinj.core.Transaction.SigHash;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.params.BitcoinMainNetParams;
import org.bitcoinj.params.BitcoinTestNet3Params;
import org.bitcoinj.script.Script.VerifyFlag;
import com.google.common.base.Charsets;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;

import org.hamcrest.core.IsNot;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.*;

import static org.bitcoinj.core.Utils.HEX;

class OceanExample {
    public static void runExample(){
        /*const raw = {
          "flag": 0,
          "ins": [
            {
              "hash": "060977d597a965d139eb87ea8c44693f70376d92e6e6f48422b53a49d7638c82",
              "index": 56,
            }
          ],
          "outs": [
            {
              "value": 10000000000000,
              "data": "76a9144ded105f3a0b4b09d6792df58a114deefdab54b688ac",
              "asset": "0128fc54e0a1d5c9405a3719191e1398e99afed4f26a743213b3afbedd868fb8ce",
              "nonce": "00"
            },
            {
              "value": 10000000000000,
              "data": "76a914b62117b2778caa01237a0cc081b2556a1c324fad88ac",
              "asset": "0128fc54e0a1d5c9405a3719191e1398e99afed4f26a743213b3afbedd868fb8ce",
              "nonce": "00"
            },
            {
              "nValue": "01000000e8d4a2025c",
              "data": "76a914ec07dce2b29a58354471c27da0204ef720cbc61688ac",
              "asset": "0128fc54e0a1d5c9405a3719191e1398e99afed4f26a743213b3afbedd868fb8ce",
              "nonce": "00"
            },
            //Fee
            {
              "nValue": "010000000000030da4",
              "data": "",
              "asset": "0128fc54e0a1d5c9405a3719191e1398e99afed4f26a743213b3afbedd868fb8ce",
              "nonce": "00"
            }
          ],
        }*/

        ECKey keytest = DumpedPrivateKey.fromBase58(PARAMS, "cUH7h1VX4nC7yLPafYJQcLY2ihvKrdKZQPMFrrKf8hfQA37QaxFB").getKey();

        Transaction tx = new Transaction(PARAMS);
        tx.setVersion(2);   
        tx.setLockTime(0);
        tx.setFlag(false);

        TransactionOutput txOutput = new TransactionOutput(PARAMS, tx, Utils.HEX.decode("0128fc54e0a1d5c9405a3719191e1398e99afed4f26a743213b3afbedd868fb8ce"),
            Utils.HEX.decode("01000009184e72a000"), Utils.HEX.decode("00"),
            new Script(Utils.HEX.decode("76a9144ded105f3a0b4b09d6792df58a114deefdab54b688ac")).getProgram());
        tx.addOutput(txOutput);

        TransactionOutput txOutput2 = new TransactionOutput(PARAMS, tx, Utils.HEX.decode("0128fc54e0a1d5c9405a3719191e1398e99afed4f26a743213b3afbedd868fb8ce"),
            Utils.HEX.decode("01000009184e72a000"), Utils.HEX.decode("00"),
            new Script(Utils.HEX.decode("76a914b62117b2778caa01237a0cc081b2556a1c324fad88ac")).getProgram());
        tx.addOutput(txOutput2);

        TransactionOutput txOutput3 = new TransactionOutput(PARAMS, tx, Utils.HEX.decode("0128fc54e0a1d5c9405a3719191e1398e99afed4f26a743213b3afbedd868fb8ce"),
            Utils.HEX.decode("01000000e8d4a2025c"), Utils.HEX.decode("00"),
            new Script(Utils.HEX.decode("76a914ec07dce2b29a58354471c27da0204ef720cbc61688ac")).getProgram());
        tx.addOutput(txOutput3);

        TransactionOutput txOutput4 = new TransactionOutput(PARAMS, tx, Utils.HEX.decode("0128fc54e0a1d5c9405a3719191e1398e99afed4f26a743213b3afbedd868fb8ce"),
            Utils.HEX.decode("010000000000030da4"), Utils.HEX.decode("00"),
            Utils.HEX.decode(""));
        tx.addOutput(txOutput4);

        tx.addSignedInput(new TransactionOutPoint(PARAMS, 56, new Sha256Hash(Utils.HEX.decode("060977d597a965d139eb87ea8c44693f70376d92e6e6f48422b53a49d7638c82"))),
            new Script(Utils.HEX.decode("76a914cbd2fbe7639a0149a4612b956ba1717d20a1020188ac")), keytest);

        System.out.println("real hex: " + Utils.HEX.encode(tx.bitcoinSerialize()));

    }
    public static void main(String[] args) {
        OceanExample.runExample();
    }
}
