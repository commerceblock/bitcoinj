/*
 * Copyright 2011 Google Inc.
 * Copyright 2016 Andreas Schildbach
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

package org.oceanj.testing;

import org.oceanj.core.*;
import org.oceanj.crypto.TransactionSignature;
import org.oceanj.script.ScriptBuilder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Random;

import static org.oceanj.core.Coin.*;
import static com.google.common.base.Preconditions.checkState;

public class FakeTxBuilder {
    private static final byte[] dummyAsset = Utils.HEX.decode("01e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d");
    private static final byte[] dummyNonce = Utils.HEX.decode("00");
    private static final byte[] dummyValue = Utils.HEX.decode("010000000005f5e100");

    /** Create a fake transaction, without change. */
    public static Transaction createFakeTx(final NetworkParameters params) {
        return createFakeTxWithoutChangeAddress(params, dummyAsset, dummyValue, dummyNonce, new ECKey().toAddress(params));
    }

    /** Create a fake transaction, without change. */
    public static Transaction createFakeTxWithoutChange(final NetworkParameters params, final TransactionOutput output) {
        Transaction prevTx = FakeTxBuilder.createFakeTx(params, dummyAsset, dummyValue, dummyNonce, new ECKey().toAddress(params));
        Transaction tx = new Transaction(params);
        tx.addOutput(output);
        tx.addInput(prevTx.getOutput(0));
        return tx;
    }

    /** Create a fake coinbase transaction. */
    public static Transaction createFakeCoinbaseTx(final NetworkParameters params) {
        TransactionOutPoint outpoint = new TransactionOutPoint(params, -1, Sha256Hash.ZERO_HASH);
        TransactionInput input = new TransactionInput(params, null, new byte[0], outpoint);
        Transaction tx = new Transaction(params);
        tx.addInput(input);
        TransactionOutput outputToMe = new TransactionOutput(params, tx, dummyAsset,
            Coin.getOceanNValue(Coin.FIFTY_COINS), dummyNonce, new ECKey().toAddress(params));
        tx.addOutput(outputToMe);

        checkState(tx.isCoinBase());
        return tx;
    }

    /**
     * Create a fake TX of sufficient realism to exercise the unit tests. Two outputs, one to us, one to somewhere
     * else to simulate change. There is one random input.
     */
    public static Transaction createFakeTxWithChangeAddress(NetworkParameters params, byte[] asset, byte[] nValue,
            byte[] nonce, Address to, Address changeOutput) {
        Transaction t = new Transaction(params);
        TransactionOutput outputToMe = new TransactionOutput(params, t, asset, nValue, nonce, to);
        t.addOutput(outputToMe);
        TransactionOutput change = new TransactionOutput(params, t, asset, Coin.getOceanNValue(valueOf(1, 11)), nonce, changeOutput);
        t.addOutput(change);
        // Make a previous tx simply to send us sufficient coins. This prev tx is not really valid but it doesn't
        // matter for our purposes.
        Transaction prevTx = new Transaction(params);
        TransactionOutput prevOut = new TransactionOutput(params, prevTx, asset, nValue, nonce, to);
        prevTx.addOutput(prevOut);
        // Connect it.
        t.addInput(prevOut).setScriptSig(ScriptBuilder.createInputScript(TransactionSignature.dummy()));
        // Fake signature.
        // Serialize/deserialize to ensure internal state is stripped, as if it had been read from the wire.
        return roundTripTransaction(params, t);
    }

    /**
     * Create a fake TX for unit tests, for use with unit tests that need greater control. One outputs, 2 random inputs,
     * split randomly to create randomness.
     */
    public static Transaction createFakeTxWithoutChangeAddress(NetworkParameters params, byte[] asset, byte[] nValue,
            byte[] nonce, Address to) {

        Transaction t = new Transaction(params);
        TransactionOutput outputToMe = new TransactionOutput(params, t, asset, nValue, nonce, to);
        t.addOutput(outputToMe);

        Coin coinValue = Coin.FIFTY_COINS;
        if(nValue.length == Message.CONFIDENTIAL_VALUE) {
            byte[] valueArray = new byte[Message.CONFIDENTIAL_VALUE-1];
            System.arraycopy(nValue, 1, valueArray, 0, Message.CONFIDENTIAL_VALUE-1);
            valueArray = Utils.reverseBytes(valueArray);
            coinValue = Coin.valueOf(Utils.readInt64(valueArray, 0));
        }
        // Make a random split in the output value so we get a distinct hash when we call this multiple times with same args
        long split = new Random().nextLong();
        if (split < 0) { split *= -1; }
        if (split == 0) { split = 15; }
        while (split > coinValue.getValue()) {
            split /= 2;
        }

        // Make a previous tx simply to send us sufficient coins. This prev tx is not really valid but it doesn't
        // matter for our purposes.
        Transaction prevTx1 = new Transaction(params);
        TransactionOutput prevOut1 = new TransactionOutput(params, prevTx1, asset,
            Coin.getOceanNValue(Coin.valueOf(split)), nonce, to);
        prevTx1.addOutput(prevOut1);
        // Connect it.
        t.addInput(prevOut1).setScriptSig(ScriptBuilder.createInputScript(TransactionSignature.dummy()));
        // Fake signature.

        // Do it again
        Transaction prevTx2 = new Transaction(params);
        TransactionOutput prevOut2 = new TransactionOutput(params, prevTx2, asset,
            Coin.getOceanNValue(Coin.valueOf(coinValue.getValue() - split)), nonce, to);
        prevTx2.addOutput(prevOut2);
        t.addInput(prevOut2).setScriptSig(ScriptBuilder.createInputScript(TransactionSignature.dummy()));

        // Serialize/deserialize to ensure internal state is stripped, as if it had been read from the wire.
        return roundTripTransaction(params, t);
    }

    /**
     * Create a fake TX of sufficient realism to exercise the unit tests. Two outputs, one to us, one to somewhere
     * else to simulate change. There is one random input.
     */
    public static Transaction createFakeTx(NetworkParameters params, byte[] asset, byte[] nValue,
            byte[] nonce, Address to) {
        return createFakeTxWithChangeAddress(params, asset, nValue, nonce, to, new ECKey().toAddress(params));
    }

    /**
     * Create a fake TX of sufficient realism to exercise the unit tests. Two outputs, one to us, one to somewhere
     * else to simulate change. There is one random input.
     */
    public static Transaction createFakeTx(NetworkParameters params, byte[] asset, byte[] nValue,
        byte[] nonce, ECKey to) {

        Transaction t = new Transaction(params);
        TransactionOutput outputToMe = new TransactionOutput(params, t, asset, nValue, nonce, to);
        t.addOutput(outputToMe);
        TransactionOutput change = new TransactionOutput(params, t, asset, Coin.getOceanNValue(valueOf(1, 11)),
        nonce, new ECKey());
        t.addOutput(change);
        // Make a previous tx simply to send us sufficient coins. This prev tx is not really valid but it doesn't
        // matter for our purposes.
        Transaction prevTx = new Transaction(params);
        TransactionOutput prevOut = new TransactionOutput(params, prevTx, asset, nValue, nonce, to);
        prevTx.addOutput(prevOut);
        // Connect it.
        t.addInput(prevOut);
        // Serialize/deserialize to ensure internal state is stripped, as if it had been read from the wire.
        return roundTripTransaction(params, t);
    }

    /**
     * Transaction[0] is a feeder transaction, supplying BTC to Transaction[1]
     */
    public static Transaction[] createFakeTx(NetworkParameters params, byte[] asset, byte[] nValue,
            byte[] nonce, Address to, Address from) {
        // Create fake TXes of sufficient realism to exercise the unit tests. This transaction send BTC from the
        // from address, to the to address with to one to somewhere else to simulate change.
        Transaction t = new Transaction(params);
        TransactionOutput outputToMe = new TransactionOutput(params, t, asset, nValue, nonce, to);
        t.addOutput(outputToMe);
        TransactionOutput change = new TransactionOutput(params, t, asset, Coin.getOceanNValue(valueOf(1, 11)),
        nonce, new ECKey().toAddress(params));
        t.addOutput(change);
        // Make a feeder tx that sends to the from address specified. This feeder tx is not really valid but it doesn't
        // matter for our purposes.
        Transaction feederTx = new Transaction(params);
        TransactionOutput feederOut = new TransactionOutput(params, feederTx, asset, nValue, nonce, from);
        feederTx.addOutput(feederOut);

        // make a previous tx that sends from the feeder to the from address
        Transaction prevTx = new Transaction(params);
        TransactionOutput prevOut = new TransactionOutput(params, prevTx, asset, nValue, nonce, to);
        prevTx.addOutput(prevOut);

        // Connect up the txes
        prevTx.addInput(feederOut);
        t.addInput(prevOut);

        // roundtrip the tx so that they are just like they would be from the wire
        return new Transaction[]{roundTripTransaction(params, prevTx), roundTripTransaction(params,t)};
    }

    /**
     * Roundtrip a transaction so that it appears as if it has just come from the wire
     */
    public static Transaction roundTripTransaction(NetworkParameters params, Transaction tx) {
        try {
            MessageSerializer bs = params.getDefaultSerializer();
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bs.serialize(tx, bos);
            return (Transaction) bs.deserialize(ByteBuffer.wrap(bos.toByteArray()));
        } catch (IOException e) {
            throw new RuntimeException(e);   // Should not happen.
        }
    }

    public static class DoubleSpends {
        public Transaction t1, t2, prevTx;
    }

    /**
     * Creates two transactions that spend the same (fake) output. t1 spends to "to". t2 spends somewhere else.
     * The fake output goes to the same address as t2.
     */
    public static DoubleSpends createFakeDoubleSpendTxns(NetworkParameters params, Address to) {
        DoubleSpends doubleSpends = new DoubleSpends();
        Address someBadGuy = new ECKey().toAddress(params);

        doubleSpends.prevTx = new Transaction(params);
        TransactionOutput prevOut = new TransactionOutput(params, doubleSpends.prevTx, dummyAsset, dummyValue, dummyNonce, someBadGuy);
        doubleSpends.prevTx.addOutput(prevOut);

        doubleSpends.t1 = new Transaction(params);
        TransactionOutput o1 = new TransactionOutput(params, doubleSpends.t1, dummyAsset, dummyValue, dummyNonce, to);
        doubleSpends.t1.addOutput(o1);
        doubleSpends.t1.addInput(prevOut);

        doubleSpends.t2 = new Transaction(params);
        doubleSpends.t2.addInput(prevOut);
        TransactionOutput o2 = new TransactionOutput(params, doubleSpends.t2, dummyAsset, dummyValue, dummyNonce, someBadGuy);
        doubleSpends.t2.addOutput(o2);

        try {
            doubleSpends.t1 = params.getDefaultSerializer().makeTransaction(doubleSpends.t1.bitcoinSerialize());
            doubleSpends.t2 = params.getDefaultSerializer().makeTransaction(doubleSpends.t2.bitcoinSerialize());
        } catch (ProtocolException e) {
            throw new RuntimeException(e);
        }
        return doubleSpends;
    }
}
