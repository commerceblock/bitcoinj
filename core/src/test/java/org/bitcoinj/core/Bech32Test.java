/*
 * Copyright 2011 Google Inc.
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

import junit.framework.TestCase;
import org.bitcoinj.core.Bech32.Bech32Parts;
import org.bitcoinj.core.SegwitAddress.SegwitAddressParts;
import org.bitcoinj.params.BitcoinMainNetParams;
import org.bitcoinj.params.BitcoinTestNet3Params;
import org.junit.Test;
import org.spongycastle.util.encoders.Hex;

public class Bech32Test extends TestCase {

    @Test
    public void testValidChecksum() throws Exception {

        for(String address : VALID_CHECKSUM)   {

            Bech32Parts part = Bech32.decode(BitcoinMainNetParams.get(), address);
            assertNotNull(part.getPrefix());
            assertNotNull(part.getData());
        }
    }

    @Test
    public void testInvalidChecksum() throws Exception {

        for(String address : INVALID_CHECKSUM)   {

            try{
                Bech32.decode(BitcoinMainNetParams.get(), address);
                fail("Invalid checksum should not pass.");
            }
            catch(Exception e) {
                assertTrue("Checksum failed as expected.",true);
            }
        }
    }

    @Test
    public void testValidAddress() {

        for (String[] addressPair : VALID_ADDRESS) {

            String address = addressPair[0];
            String scriptPubKeyHex = addressPair[1];

            NetworkParameters params;
            if (address.startsWith("bc") || address.startsWith("BC")) {
                params = BitcoinMainNetParams.get();
            } else {
                params = BitcoinTestNet3Params.get();
            }

            SegwitAddressParts segp = SegwitAddress.decode(params, address);
            assertNotNull(segp);

            byte witVer = segp.getVersion();
            byte[] witProg = segp.getProgram();
            assertTrue(SegwitAddress.isValidVersion(witVer));

            byte[] pubkey = SegwitAddress.getScriptPubkey(witVer, witProg);
            assertTrue(Hex.toHexString(pubkey).equalsIgnoreCase(scriptPubKeyHex));

            String segwitAddress = SegwitAddress.encode(params, witVer, witProg);
            assertTrue(address.equalsIgnoreCase(segwitAddress));

            int idx = address.lastIndexOf("1");
            String part1 = address.substring(0, idx);
            String separator = "1";
            String part2 = address.substring(idx + 1);
            String segwitAddr = part1+separator+part2;

            SegwitAddressParts segwitParts = SegwitAddress.decode(params, segwitAddr);
            assertNotSame(witProg, segwitParts.getProgram());
        }
    }

    @Test
    public void testInvalidAddress() throws Exception {

        for (String address : INVALID_ADDRESS) {

            try {
                NetworkParameters params;
                if (address.startsWith("bc") || address.startsWith("BC")) {
                    params = BitcoinMainNetParams.get();
                } else {
                    params = BitcoinTestNet3Params.get();
                }

                Bech32Parts bech32 = Bech32.decode(params, address);
                SegwitAddressParts segwit = SegwitAddress.decode(params, address);
                fail(address+" Invalid address decode should not pass.");
            } catch (Exception e) {
                assertTrue("Address decode failed as expected.", true);
            }
        }
    }

    // test vectors - https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
    private static final String[] VALID_CHECKSUM = {
        "A12UEL5L",
        "a12uel5l",
        "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
        "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
        "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
        "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
        "?1ezyfcl"
    };

    private static final String[] INVALID_CHECKSUM = {
        new String(new char[] { 0x20f }) + " 1nwldj5", //HRP character out of range
        new String(new char[] { 0x7f }) + "1axkwrx", //HRP character out of range
        "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx", //overall max length exceeded
        "pzry9x0s0muk", //No separator character
        "1pzry9x0s0muk", //Empty HRP
        "x1b4n0q5v", //Invalid data character
        "li1dgmt3", //Too short checksum
        "de1lg7wt" + new String(new char[] { 0xff }), //Invalid character in checksum
        "A1G7SGD8", //checksum calculated with uppercase form of HRP
        "10a06t8", //empty HRP
        "1qzzfhee" //empty HRP
    };

    // segwit addresses - hex scriptPubKey
    private static final String[][] VALID_ADDRESS = {
        // example provided in BIP
        new String[] { "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"},
        // test vectors
        new String[] { "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "0014751e76e8199196d454941c45d1b3a323f1433bd6"},
        new String[] { "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx", "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"},
        new String[] { "BC1SW50QA3JX3S", "6002751e"},
        new String[] { "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj", "5210751e76e8199196d454941c45d1b3a323"},
        new String[] { "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7","00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"},
        new String[] { "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy", "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"},

    };

    // test vectors
    private static final String[] INVALID_ADDRESS = {
        "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty", // Invalid human-readable part
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", // Invalid checksum
        "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2", // Invalid witness version
        "bc1rw5uspcuh", // Invalid program length
        "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90", // Invalid program length
        "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P", // Invalid program length for witness version 0 (per BIP141)
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7", //mixed case
        "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du", // zero padding of more than 4 bits
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv", // Non-zero padding in 8-to-5 conversion
        "bc1gmk9yu" // Empty data section
    };
}
