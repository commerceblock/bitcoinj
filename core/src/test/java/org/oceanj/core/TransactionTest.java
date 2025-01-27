/*
 * Copyright 2014 Google Inc.
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

package org.oceanj.core;

import org.oceanj.core.TransactionConfidence.*;
import org.oceanj.crypto.TransactionSignature;
import org.oceanj.params.*;
import org.oceanj.script.*;
import org.oceanj.testing.*;
import org.junit.*;

import java.math.BigInteger;
import java.util.*;
import static org.oceanj.core.Utils.HEX;

import static org.junit.Assert.*;

/**
 * Just check the Transaction.verify() method. Most methods that have complicated logic in Transaction are tested
 * elsewhere, e.g. signing and hashing are well exercised by the wallet tests, the full block chain tests and so on.
 * The verify method is also exercised by the full block chain tests, but it can also be used by API users alone,
 * so we make sure to cover it here as well.
 */
public class TransactionTest {
    private static final NetworkParameters PARAMS = BitcoinUnitTestParams.get();
    private static final Address ADDRESS = new ECKey().toAddress(PARAMS);
    public static final byte[] ASSET = Utils.HEX.decode("01e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d");
    public static final byte[] NONCE = Utils.HEX.decode("00");
    public static final byte[] VALUE = Utils.HEX.decode("010000000005f5e100");

    private Transaction tx;

    @Before
    public void setUp() throws Exception {
        Context context = new Context(PARAMS);
        tx = FakeTxBuilder.createFakeTx(PARAMS);
    }

    @Test(expected = VerificationException.EmptyInputsOrOutputs.class)
    public void emptyOutputs() throws Exception {
        tx.clearOutputs();
        tx.verify();
    }

    @Test(expected = VerificationException.EmptyInputsOrOutputs.class)
    public void emptyInputs() throws Exception {
        tx.clearInputs();
        tx.verify();
    }

    @Test(expected = VerificationException.LargerThanMaxBlockSize.class)
    public void tooHuge() throws Exception {
        tx.getInput(0).setScriptBytes(new byte[Block.MAX_BLOCK_SIZE]);
        tx.verify();
    }

    @Test(expected = VerificationException.DuplicatedOutPoint.class)
    public void duplicateOutPoint() throws Exception {
        TransactionInput input = tx.getInput(0);
        input.setScriptBytes(new byte[1]);
        tx.addInput(input.duplicateDetached());
        tx.verify();
    }

    @Test(expected = VerificationException.NegativeValueOutput.class)
    public void negativeOutput() throws Exception {
        tx.getOutput(0).setValue(Coin.NEGATIVE_SATOSHI);
        tx.verify();
    }

    @Test(expected = VerificationException.ExcessiveValue.class)
    public void exceedsMaxMoney2() throws Exception {
        Coin half = PARAMS.getMaxMoney().divide(2).add(Coin.SATOSHI);
        tx.getOutput(0).setValue(half);
        tx.addOutput(ASSET, Coin.getOceanNValue(half), NONCE, ADDRESS);
        tx.verify();
    }

    @Test(expected = VerificationException.UnexpectedCoinbaseInput.class)
    public void coinbaseInputInNonCoinbaseTX() throws Exception {
        tx.addInput(Sha256Hash.ZERO_HASH, 0xFFFFFFFFL, new ScriptBuilder().data(new byte[10]).build());
        tx.verify();
    }

    @Test(expected = VerificationException.CoinbaseScriptSizeOutOfRange.class)
    public void coinbaseScriptSigTooSmall() throws Exception {
        tx.clearInputs();
        tx.addInput(Sha256Hash.ZERO_HASH, 0xFFFFFFFFL, new ScriptBuilder().build());
        tx.verify();
    }

    @Test(expected = VerificationException.CoinbaseScriptSizeOutOfRange.class)
    public void coinbaseScriptSigTooLarge() throws Exception {
        tx.clearInputs();
        TransactionInput input = tx.addInput(Sha256Hash.ZERO_HASH, 0xFFFFFFFFL, new ScriptBuilder().data(new byte[99]).build());
        assertEquals(101, input.getScriptBytes().length);
        tx.verify();
    }

    @Test
    public void testOptimalEncodingMessageSize() {
        Transaction tx = new Transaction(PARAMS);

        int length = tx.length;

        // add basic transaction input, check the length
        tx.addOutput(new TransactionOutput(PARAMS, null, ASSET, VALUE, NONCE, ADDRESS));
        length += getCombinedLength(tx.getOutputs());

        // add basic output, check the length
        length += getCombinedLength(tx.getInputs());

        // optimal encoding size should equal the length we just calculated
        assertEquals(tx.getOptimalEncodingMessageSize(), length);
    }

    private int getCombinedLength(List<? extends Message> list) {
        int sumOfAllMsgSizes = 0;
        for (Message m: list) { sumOfAllMsgSizes += m.getMessageSize() + 1; }
        return sumOfAllMsgSizes;
    }

    @Test
    public void testIsMatureReturnsFalseIfTransactionIsCoinbaseAndConfidenceTypeIsNotEqualToBuilding() {
        Transaction tx = FakeTxBuilder.createFakeCoinbaseTx(PARAMS);

        tx.getConfidence().setConfidenceType(ConfidenceType.UNKNOWN);
        assertEquals(tx.isMature(), false);

        tx.getConfidence().setConfidenceType(ConfidenceType.PENDING);
        assertEquals(tx.isMature(), false);

        tx.getConfidence().setConfidenceType(ConfidenceType.DEAD);
        assertEquals(tx.isMature(), false);
    }

    @Test
    public void testCLTVPaymentChannelTransactionSpending() {
        BigInteger time = BigInteger.valueOf(20);

        ECKey from = new ECKey(), to = new ECKey(), incorrect = new ECKey();
        Script outputScript = ScriptBuilder.createCLTVPaymentChannelOutput(time, from, to);

        Transaction tx = new Transaction(PARAMS);
        tx.addInput(new TransactionInput(PARAMS, tx, new byte[] {}));
        tx.getInput(0).setSequenceNumber(0);
        tx.setLockTime(time.subtract(BigInteger.ONE).longValue());
        TransactionSignature fromSig =
                tx.calculateSignature(
                        0,
                        from,
                        outputScript,
                        Transaction.SigHash.SINGLE,
                        false);
        TransactionSignature toSig =
                tx.calculateSignature(
                        0,
                        to,
                        outputScript,
                        Transaction.SigHash.SINGLE,
                        false);
        TransactionSignature incorrectSig =
                tx.calculateSignature(
                        0,
                        incorrect,
                        outputScript,
                        Transaction.SigHash.SINGLE,
                        false);
        Script scriptSig =
                ScriptBuilder.createCLTVPaymentChannelInput(fromSig, toSig);
        Script refundSig =
                ScriptBuilder.createCLTVPaymentChannelRefund(fromSig);
        Script invalidScriptSig1 =
                ScriptBuilder.createCLTVPaymentChannelInput(fromSig, incorrectSig);
        Script invalidScriptSig2 =
                ScriptBuilder.createCLTVPaymentChannelInput(incorrectSig, toSig);

        try {
            scriptSig.correctlySpends(tx, 0, outputScript, Script.ALL_VERIFY_FLAGS);
        } catch (ScriptException e) {
            e.printStackTrace();
            fail("Settle transaction failed to correctly spend the payment channel");
        }

        try {
            refundSig.correctlySpends(tx, 0, outputScript, Script.ALL_VERIFY_FLAGS);
            fail("Refund passed before expiry");
        } catch (ScriptException e) { }
        try {
            invalidScriptSig1.correctlySpends(tx, 0, outputScript, Script.ALL_VERIFY_FLAGS);
            fail("Invalid sig 1 passed");
        } catch (ScriptException e) { }
        try {
            invalidScriptSig2.correctlySpends(tx, 0, outputScript, Script.ALL_VERIFY_FLAGS);
            fail("Invalid sig 2 passed");
        } catch (ScriptException e) { }
    }

    @Test
    public void testCLTVPaymentChannelTransactionRefund() {
        BigInteger time = BigInteger.valueOf(20);

        ECKey from = new ECKey(), to = new ECKey(), incorrect = new ECKey();
        Script outputScript = ScriptBuilder.createCLTVPaymentChannelOutput(time, from, to);

        Transaction tx = new Transaction(PARAMS);
        tx.addInput(new TransactionInput(PARAMS, tx, new byte[] {}));
        tx.getInput(0).setSequenceNumber(0);
        tx.setLockTime(time.add(BigInteger.ONE).longValue());
        TransactionSignature fromSig =
                tx.calculateSignature(
                        0,
                        from,
                        outputScript,
                        Transaction.SigHash.SINGLE,
                        false);
        TransactionSignature incorrectSig =
                tx.calculateSignature(
                        0,
                        incorrect,
                        outputScript,
                        Transaction.SigHash.SINGLE,
                        false);
        Script scriptSig =
                ScriptBuilder.createCLTVPaymentChannelRefund(fromSig);
        Script invalidScriptSig =
                ScriptBuilder.createCLTVPaymentChannelRefund(incorrectSig);

        try {
            scriptSig.correctlySpends(tx, 0, outputScript, Script.ALL_VERIFY_FLAGS);
        } catch (ScriptException e) {
            e.printStackTrace();
            fail("Refund failed to correctly spend the payment channel");
        }

        try {
            invalidScriptSig.correctlySpends(tx, 0, outputScript, Script.ALL_VERIFY_FLAGS);
            fail("Invalid sig passed");
        } catch (ScriptException e) { }
    }

    @Test
    public void testToStringWhenIteratingOverAnInputCatchesAnException() {
        Transaction tx = FakeTxBuilder.createFakeTx(PARAMS);
        TransactionInput ti = new TransactionInput(PARAMS, tx, new byte[0]) {
            @Override
            public Script getScriptSig() throws ScriptException {
                throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "");
            }
        };

        tx.addInput(ti);
        assertEquals(tx.toString().contains("[exception: "), true);
    }

    @Test
    public void testToStringWhenThereAreZeroInputs() {
        Transaction tx = new Transaction(PARAMS);
        assertEquals(tx.toString().contains("No inputs!"), true);
    }

    @Test
    public void testTheTXByHeightComparator() {
        Transaction tx1 = FakeTxBuilder.createFakeTx(PARAMS);
        tx1.getConfidence().setAppearedAtChainHeight(1);

        Transaction tx2 = FakeTxBuilder.createFakeTx(PARAMS);
        tx2.getConfidence().setAppearedAtChainHeight(2);

        Transaction tx3 = FakeTxBuilder.createFakeTx(PARAMS);
        tx3.getConfidence().setAppearedAtChainHeight(3);

        SortedSet<Transaction> set = new TreeSet<>(Transaction.SORT_TX_BY_HEIGHT);
        set.add(tx2);
        set.add(tx1);
        set.add(tx3);

        Iterator<Transaction> iterator = set.iterator();

        assertEquals(tx1.equals(tx2), false);
        assertEquals(tx1.equals(tx3), false);
        assertEquals(tx1.equals(tx1), true);

        assertEquals(iterator.next().equals(tx3), true);
        assertEquals(iterator.next().equals(tx2), true);
        assertEquals(iterator.next().equals(tx1), true);
        assertEquals(iterator.hasNext(), false);
    }

    @Test(expected = ScriptException.class)
    public void testAddSignedInputThrowsExceptionWhenScriptIsNotToRawPubKeyAndIsNotToAddress() {
        ECKey key = new ECKey();
        Address addr = key.toAddress(PARAMS);
        Transaction fakeTx = FakeTxBuilder.createFakeTx(PARAMS, ASSET, VALUE, NONCE, addr);

        Transaction tx = new Transaction(PARAMS);
        tx.addOutput(fakeTx.getOutput(0));

        Script script = ScriptBuilder.createOpReturnScript(new byte[0]);

        tx.addSignedInput(fakeTx.getOutput(0).getOutPointFor(), script, key);
    }

    @Test
    public void testPrioSizeCalc() throws Exception {
        Transaction tx1 = FakeTxBuilder.createFakeTx(PARAMS, ASSET, VALUE, NONCE, ADDRESS);
        int size1 = tx1.getMessageSize();
        int size2 = tx1.getMessageSizeForPriorityCalc();
        assertEquals(113, size1 - size2);
        tx1.getInput(0).setScriptSig(new Script(new byte[109]));
        assertEquals(149, tx1.getMessageSizeForPriorityCalc());
        tx1.getInput(0).setScriptSig(new Script(new byte[110]));
        assertEquals(149, tx1.getMessageSizeForPriorityCalc());
        tx1.getInput(0).setScriptSig(new Script(new byte[111]));
        assertEquals(150, tx1.getMessageSizeForPriorityCalc());
    }

    @Test
    public void testAddContractHashCheck() throws VerificationException {
        final byte[] transactionBytes = HEX.decode(
                "010000000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff010000006a4730440220560ab7f8ca79912d4636a1092eda47231bf673ab7c161ac4b7fc2a16ca45c96f0220017696a8eddcc1346cacac0d27c27adacdb3817f76d8d47c4f3dd9d8c5d839a601210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ffffffff0101e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d0100000000000186a0001976a914000000000000000000000000000000000000000088ac00000000");
        Transaction transaction = PARAMS.getDefaultSerializer().makeTransaction(transactionBytes);
        transaction.addContract(new Sha256Hash("e6e3e96c0a928d8d1fa0003b0079f6cddd18330fb42deb014465e7cefbb08a85"));
        assertEquals("010000000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff010000006a4730440220560ab7f8ca79912d4636a1092eda47231bf673ab7c161ac4b7fc2a16ca45c96f0220017696a8eddcc1346cacac0d27c27adacdb3817f76d8d47c4f3dd9d8c5d839a601210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ffffffff0201e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d0100000000000186a0001976a914000000000000000000000000000000000000000088ac0001000000000000000000226a20e6e3e96c0a928d8d1fa0003b0079f6cddd18330fb42deb014465e7cefbb08a8500000000",
            Utils.HEX.encode(transaction.bitcoinSerialize()));
    }

    @Test
    public void testAddContractBytesCheck() throws VerificationException {
        final byte[] transactionBytes = HEX.decode(
                "010000000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff010000006a4730440220560ab7f8ca79912d4636a1092eda47231bf673ab7c161ac4b7fc2a16ca45c96f0220017696a8eddcc1346cacac0d27c27adacdb3817f76d8d47c4f3dd9d8c5d839a601210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ffffffff0101e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d0100000000000186a0001976a914000000000000000000000000000000000000000088ac00000000");
        Transaction transaction = PARAMS.getDefaultSerializer().makeTransaction(transactionBytes);
        transaction.addContract(Utils.HEX.decode("e6e3e96c0a928d8d1fa0003b0079f6cddd18330fb42deb014465e7cefbb08a85"));
        assertEquals("010000000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff010000006a4730440220560ab7f8ca79912d4636a1092eda47231bf673ab7c161ac4b7fc2a16ca45c96f0220017696a8eddcc1346cacac0d27c27adacdb3817f76d8d47c4f3dd9d8c5d839a601210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ffffffff0201e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d0100000000000186a0001976a914000000000000000000000000000000000000000088ac0001000000000000000000226a20e6e3e96c0a928d8d1fa0003b0079f6cddd18330fb42deb014465e7cefbb08a8500000000",
            Utils.HEX.encode(transaction.bitcoinSerialize()));
    }

    @Test
    public void testCoinbaseHeightCheck() throws VerificationException {
        // Coinbase transaction from block 300,000
        final byte[] transactionBytes = HEX.decode(
                "0100000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4803e09304062f503253482f0403c86d53087ceca141295a00002e522cfabe6d6d7561cf262313da1144026c8f7a43e3899c44f6145f39a36507d36679a8b700610400000000000000000000000101e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d0100000000954070c8001976a91480ad90d403581fa3bf46086a91b2d9d4125db6c188ac00000000");
        final int height = 300000;
        final Transaction transaction = PARAMS.getDefaultSerializer().makeTransaction(transactionBytes);
        transaction.checkCoinBaseHeight(height);
    }

    /**
     * Test a coinbase transaction whose script has nonsense after the block height.
     * See https://github.com/bitcoinj/bitcoinj/issues/1097
     */
    @Test
    public void testCoinbaseHeightCheckWithDamagedScript() throws VerificationException {
        // Coinbase transaction from block 224,430
        final byte[] transactionBytes = HEX.decode(
            "0100000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3b03ae6c0300044bd7031a0400000000522cfabe6d6d00000000000000b7b8bf0100000068692066726f6d20706f6f6c7365727665726aac1eeeed88ffffffff0101e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d0100000000977558e0001976a91421c0d001728b3feaf115515b7c135e779e9f442f88ac00000000");
        final int height = 224430;
        final Transaction transaction = PARAMS.getDefaultSerializer().makeTransaction(transactionBytes);
        transaction.checkCoinBaseHeight(height);
    }

    @Test
    public void optInFullRBF() {
        // a standard transaction as wallets would create
        Transaction tx = FakeTxBuilder.createFakeTx(PARAMS);
        assertFalse(tx.isOptInFullRBF());

        tx.getInputs().get(0).setSequenceNumber(TransactionInput.NO_SEQUENCE - 2);
        assertTrue(tx.isOptInFullRBF());
    }
}
