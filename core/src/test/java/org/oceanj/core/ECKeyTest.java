/*
 * Copyright 2011 Google Inc.
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

package org.oceanj.core;

import org.oceanj.core.ECKey.ECDSASignature;
import org.oceanj.crypto.TransactionSignature;
import org.oceanj.params.BitcoinMainNetParams;
import org.oceanj.params.BitcoinTestNet3Params;
import org.oceanj.params.BitcoinUnitTestParams;
import org.oceanj.utils.BriefLogFormatter;
import com.google.common.collect.Lists;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.ListeningExecutorService;
import com.google.common.util.concurrent.MoreExecutors;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.math.BigInteger;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;

import static org.oceanj.core.Utils.HEX;
import static org.oceanj.core.Utils.reverseBytes;
import static com.google.common.base.Preconditions.checkNotNull;
import static org.junit.Assert.*;

public class ECKeyTest {
    private static final Logger log = LoggerFactory.getLogger(ECKeyTest.class);

    private static CharSequence PASSWORD1 = "my hovercraft has eels";
    private static CharSequence WRONG_PASSWORD = "it is a snowy day today";

    @Before
    public void setUp() throws Exception {
        BriefLogFormatter.init();
    }

    @Test
    public void sValue() throws Exception {
        // Check that we never generate an S value that is larger than half the curve order. This avoids a malleability
        // issue that can allow someone to change a transaction [hash] without invalidating the signature.
        final int ITERATIONS = 10;
        ListeningExecutorService executor = MoreExecutors.listeningDecorator(Executors.newFixedThreadPool(ITERATIONS));
        List<ListenableFuture<ECKey.ECDSASignature>> sigFutures = Lists.newArrayList();
        final ECKey key = new ECKey();
        for (byte i = 0; i < ITERATIONS; i++) {
            final Sha256Hash hash = Sha256Hash.of(new byte[]{i});
            sigFutures.add(executor.submit(new Callable<ECKey.ECDSASignature>() {
                @Override
                public ECKey.ECDSASignature call() throws Exception {
                    return key.sign(hash);
                }
            }));
        }
        List<ECKey.ECDSASignature> sigs = Futures.allAsList(sigFutures).get();
        for (ECKey.ECDSASignature signature : sigs) {
            assertTrue(signature.isCanonical());
        }
        final ECDSASignature first = sigs.get(0);
        final ECKey.ECDSASignature duplicate = new ECKey.ECDSASignature(first.r, first.s);
        assertEquals(first, duplicate);
        assertEquals(first.hashCode(), duplicate.hashCode());

        final ECKey.ECDSASignature highS = new ECKey.ECDSASignature(first.r, ECKey.CURVE.getN().subtract(first.s));
        assertFalse(highS.isCanonical());
    }

    @Test
    public void testSignatures() throws Exception {
        // Test that we can construct an ECKey from a private key (deriving the public from the private), then signing
        // a message with it.
        BigInteger privkey = new BigInteger(1, HEX.decode("180cb41c7c600be951b5d3d0a7334acc7506173875834f7a6c4c786a28fcbb19"));
        ECKey key = ECKey.fromPrivate(privkey);
        byte[] output = key.sign(Sha256Hash.ZERO_HASH).encodeToDER();
        assertTrue(key.verify(Sha256Hash.ZERO_HASH.getBytes(), output));

        // Test interop with a signature from elsewhere.
        byte[] sig = HEX.decode(
                "3046022100dffbc26774fc841bbe1c1362fd643609c6e42dcb274763476d87af2c0597e89e022100c59e3c13b96b316cae9fa0ab0260612c7a133a6fe2b3445b6bf80b3123bf274d");
        assertTrue(key.verify(Sha256Hash.ZERO_HASH.getBytes(), sig));
    }

    @Test
    public void testASN1Roundtrip() throws Exception {
        byte[] privkeyASN1 = HEX.decode(
                "3082011302010104205c0b98e524ad188ddef35dc6abba13c34a351a05409e5d285403718b93336a4aa081a53081a2020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f300604010004010704410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141020101a144034200042af7a2aafe8dafd7dc7f9cfb58ce09bda7dce28653ab229b98d1d3d759660c672dd0db18c8c2d76aa470448e876fc2089ab1354c01a6e72cefc50915f4a963ee");
        ECKey decodedKey = ECKey.fromASN1(privkeyASN1);

        // Now re-encode and decode the ASN.1 to see if it is equivalent (it does not produce the exact same byte
        // sequence, some integers are padded now).
        ECKey roundtripKey = ECKey.fromASN1(decodedKey.toASN1());

        assertArrayEquals(decodedKey.getPrivKeyBytes(), roundtripKey.getPrivKeyBytes());

        for (ECKey key : new ECKey[] {decodedKey, roundtripKey}) {
            byte[] message = reverseBytes(HEX.decode(
                    "11da3761e86431e4a54c176789e41f1651b324d240d599a7067bee23d328ec2a"));
            byte[] output = key.sign(Sha256Hash.wrap(message)).encodeToDER();
            assertTrue(key.verify(message, output));

            output = HEX.decode(
                    "304502206faa2ebc614bf4a0b31f0ce4ed9012eb193302ec2bcaccc7ae8bb40577f47549022100c73a1a1acc209f3f860bf9b9f5e13e9433db6f8b7bd527a088a0e0cd0a4c83e9");
            assertTrue(key.verify(message, output));
        }
        
        // Try to sign with one key and verify with the other.
        byte[] message = reverseBytes(HEX.decode(
            "11da3761e86431e4a54c176789e41f1651b324d240d599a7067bee23d328ec2a"));
        assertTrue(roundtripKey.verify(message, decodedKey.sign(Sha256Hash.wrap(message)).encodeToDER()));
        assertTrue(decodedKey.verify(message, roundtripKey.sign(Sha256Hash.wrap(message)).encodeToDER()));
    }

    @Test
    public void testKeyPairRoundtrip() throws Exception {
        byte[] privkeyASN1 = HEX.decode(
                "3082011302010104205c0b98e524ad188ddef35dc6abba13c34a351a05409e5d285403718b93336a4aa081a53081a2020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f300604010004010704410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141020101a144034200042af7a2aafe8dafd7dc7f9cfb58ce09bda7dce28653ab229b98d1d3d759660c672dd0db18c8c2d76aa470448e876fc2089ab1354c01a6e72cefc50915f4a963ee");
        ECKey decodedKey = ECKey.fromASN1(privkeyASN1);

        // Now re-encode and decode the ASN.1 to see if it is equivalent (it does not produce the exact same byte
        // sequence, some integers are padded now).
        ECKey roundtripKey =
            ECKey.fromPrivateAndPrecalculatedPublic(decodedKey.getPrivKey(), decodedKey.getPubKeyPoint());

        for (ECKey key : new ECKey[] {decodedKey, roundtripKey}) {
            byte[] message = reverseBytes(HEX.decode(
                    "11da3761e86431e4a54c176789e41f1651b324d240d599a7067bee23d328ec2a"));
            byte[] output = key.sign(Sha256Hash.wrap(message)).encodeToDER();
            assertTrue(key.verify(message, output));

            output = HEX.decode(
                    "304502206faa2ebc614bf4a0b31f0ce4ed9012eb193302ec2bcaccc7ae8bb40577f47549022100c73a1a1acc209f3f860bf9b9f5e13e9433db6f8b7bd527a088a0e0cd0a4c83e9");
            assertTrue(key.verify(message, output));
        }
        
        // Try to sign with one key and verify with the other.
        byte[] message = reverseBytes(HEX.decode(
            "11da3761e86431e4a54c176789e41f1651b324d240d599a7067bee23d328ec2a"));
        assertTrue(roundtripKey.verify(message, decodedKey.sign(Sha256Hash.wrap(message)).encodeToDER()));
        assertTrue(decodedKey.verify(message, roundtripKey.sign(Sha256Hash.wrap(message)).encodeToDER()));

        // Verify bytewise equivalence of public keys (i.e. compression state is preserved)
        ECKey key = new ECKey();
        ECKey key2 = ECKey.fromASN1(key.toASN1());
        assertArrayEquals(key.getPubKey(), key2.getPubKey());
    }

    @Test
    public void base58Encoding() throws Exception {
        String addr = "mqAJmaxMcG5pPHHc3H3NtyXzY7kGbJLuMF";
        String privkey = "92shANodC6Y4evT5kFzjNFQAdjqTtHAnDTLzqBBq4BbKUPyx6CD";
        ECKey key = DumpedPrivateKey.fromBase58(BitcoinTestNet3Params.get(), privkey).getKey();
        assertEquals(privkey, key.getPrivateKeyEncoded(BitcoinTestNet3Params.get()).toString());
        assertEquals(addr, key.toAddress(BitcoinTestNet3Params.get()).toString());
    }

    @Test
    public void base58Encoding_leadingZero() throws Exception {
        String privkey = "91axuYLa8xK796DnBXXsMbjuc8pDYxYgJyQMvFzrZ6UfXaGYuqL";
        ECKey key = DumpedPrivateKey.fromBase58(BitcoinTestNet3Params.get(), privkey).getKey();
        assertEquals(privkey, key.getPrivateKeyEncoded(BitcoinTestNet3Params.get()).toString());
        assertEquals(0, key.getPrivKeyBytes()[0]);
    }

    @Test
    public void base58Encoding_stress() throws Exception {
        // Replace the loop bound with 1000 to get some keys with leading zero byte
        for (int i = 0 ; i < 20 ; i++) {
            ECKey key = new ECKey();
            ECKey key1 = DumpedPrivateKey.fromBase58(BitcoinTestNet3Params.get(),
                    key.getPrivateKeyEncoded(BitcoinTestNet3Params.get()).toString()).getKey();
            assertEquals(Utils.HEX.encode(key.getPrivKeyBytes()),
                    Utils.HEX.encode(key1.getPrivKeyBytes()));
        }
    }

    @Test
    public void signTextMessage() throws Exception {
        ECKey key = new ECKey();
        String message = "聡中本";
        String signatureBase64 = key.signMessage(message);
        log.info("Message signed with " + key.toAddress(BitcoinMainNetParams.get()) + ": " + signatureBase64);
        // Should verify correctly.
        key.verifyMessage(message, signatureBase64);
        try {
            key.verifyMessage("Evil attacker says hello!", signatureBase64);
            fail();
        } catch (SignatureException e) {
            // OK.
        }
    }

    @Test
    public void verifyMessage() throws Exception {
        // Test vector generated by Bitcoin-Qt.
        String message = "hello";
        String sigBase64 = "HxNZdo6ggZ41hd3mM3gfJRqOQPZYcO8z8qdX2BwmpbF11CaOQV+QiZGGQxaYOncKoNW61oRuSMMF8udfK54XqI8=";
        Address expectedAddress = Address.fromBase58(BitcoinMainNetParams.get(), "14YPSNPi6NSXnUxtPAsyJSuw3pv7AU3Cag");
        ECKey key = ECKey.signedMessageToKey(message, sigBase64);
        Address gotAddress = key.toAddress(BitcoinMainNetParams.get());
        assertEquals(expectedAddress, gotAddress);
    }

    @Test
    public void keyRecovery() throws Exception {
        ECKey key = new ECKey();
        String message = "Hello World!";
        Sha256Hash hash = Sha256Hash.of(message.getBytes());
        ECKey.ECDSASignature sig = key.sign(hash);
        key = ECKey.fromPublicOnly(key.getPubKeyPoint());
        boolean found = false;
        for (int i = 0; i < 4; i++) {
            ECKey key2 = ECKey.recoverFromSignature(i, sig, hash, true);
            checkNotNull(key2);
            if (key.equals(key2)) {
                found = true;
                break;
            }
        }
        assertTrue(found);
    }

    @Test
    public void testToString() throws Exception {
        ECKey key = ECKey.fromPrivate(BigInteger.TEN).decompress(); // An example private key.
        NetworkParameters params = BitcoinMainNetParams.get();
        assertEquals("ECKey{pub HEX=04a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7893aba425419bc27a3b6c7e693a24c696f794c2ed877a1593cbee53b037368d7, isPubKeyOnly=false}", key.toString());
    }

    @Test
    public void testGetPrivateKeyAsHex() throws Exception {
        ECKey key = ECKey.fromPrivate(BigInteger.TEN).decompress(); // An example private key.
        assertEquals("000000000000000000000000000000000000000000000000000000000000000a", key.getPrivateKeyAsHex());
    }

    @Test
    public void testGetPublicKeyAsHex() throws Exception {
        ECKey key = ECKey.fromPrivate(BigInteger.TEN).decompress(); // An example private key.
        assertEquals("04a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7893aba425419bc27a3b6c7e693a24c696f794c2ed877a1593cbee53b037368d7", key.getPublicKeyAsHex());
    }

    @Test
    public void roundTripDumpedPrivKey() throws Exception {
        ECKey key = new ECKey();
        assertTrue(key.isCompressed());
        NetworkParameters params = BitcoinUnitTestParams.get();
        String base58 = key.getPrivateKeyEncoded(params).toString();
        ECKey key2 = DumpedPrivateKey.fromBase58(params, base58).getKey();
        assertTrue(key2.isCompressed());
        assertTrue(Arrays.equals(key.getPrivKeyBytes(), key2.getPrivKeyBytes()));
        assertTrue(Arrays.equals(key.getPubKey(), key2.getPubKey()));
    }

    @Test
    public void clear() throws Exception {
        ECKey unencryptedKey = new ECKey();

        checkSomeBytesAreNonZero(unencryptedKey.getPrivKeyBytes());
    }

    @Test
    public void testCanonicalSigs() throws Exception {
        // Tests the canonical sigs from Bitcoin Core unit tests
        InputStream in = getClass().getResourceAsStream("sig_canonical.json");

        // Poor man's JSON parser (because pulling in a lib for this is overkill)
        while (in.available() > 0) {
            while (in.available() > 0 && in.read() != '"') ;
            if (in.available() < 1)
                break;

            StringBuilder sig = new StringBuilder();
            int c;
            while (in.available() > 0 && (c = in.read()) != '"')
                sig.append((char)c);

            assertTrue(TransactionSignature.isEncodingCanonical(HEX.decode(sig.toString())));
        }
        in.close();
    }

    @Test
    public void testNonCanonicalSigs() throws Exception {
        // Tests the noncanonical sigs from Bitcoin Core unit tests
        InputStream in = getClass().getResourceAsStream("sig_noncanonical.json");

        // Poor man's JSON parser (because pulling in a lib for this is overkill)
        while (in.available() > 0) {
            while (in.available() > 0 && in.read() != '"') ;
            if (in.available() < 1)
                break;

            StringBuilder sig = new StringBuilder();
            int c;
            while (in.available() > 0 && (c = in.read()) != '"')
                sig.append((char)c);

            try {
                final String sigStr = sig.toString();
                assertFalse(TransactionSignature.isEncodingCanonical(HEX.decode(sigStr)));
            } catch (IllegalArgumentException e) {
                // Expected for non-hex strings in the JSON that we should ignore
            }
        }
        in.close();
    }

    @Test
    public void testCreatedSigAndPubkeyAreCanonical() throws Exception {
        // Tests that we will not generate non-canonical pubkeys or signatures
        // We dump failed data to error log because this test is not expected to be deterministic
        ECKey key = new ECKey();
        if (!ECKey.isPubKeyCanonical(key.getPubKey())) {
            log.error(Utils.HEX.encode(key.getPubKey()));
            fail();
        }

        byte[] hash = new byte[32];
        new Random().nextBytes(hash);
        byte[] sigBytes = key.sign(Sha256Hash.wrap(hash)).encodeToDER();
        byte[] encodedSig = Arrays.copyOf(sigBytes, sigBytes.length + 1);
        encodedSig[sigBytes.length] = Transaction.SigHash.ALL.byteValue();
        if (!TransactionSignature.isEncodingCanonical(encodedSig)) {
            log.error(Utils.HEX.encode(sigBytes));
            fail();
        }
    }

    private static boolean checkSomeBytesAreNonZero(byte[] bytes) {
        if (bytes == null) return false;
        for (byte b : bytes) if (b != 0) return true;
        return false;
    }

    @Test
    public void testPublicKeysAreEqual() {
        ECKey key = new ECKey();
        ECKey pubKey1 = ECKey.fromPublicOnly(key.getPubKeyPoint());
        assertTrue(pubKey1.isCompressed());
        ECKey pubKey2 = pubKey1.decompress();
        assertEquals(pubKey1, pubKey2);
        assertEquals(pubKey1.hashCode(), pubKey2.hashCode());
    }

    @Test(expected = IllegalArgumentException.class)
    public void fromPrivate_exceedsSize() {
        final byte[] bytes = new byte[33];
        bytes[0] = 42;
        ECKey.fromPrivate(bytes);
    }
}
