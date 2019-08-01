package org.bitcoinj.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.bitcoinj.params.BitcoinCashMainNetParams;
import org.bitcoinj.params.BitcoinCashTestNet3Params;
import org.bitcoinj.testData.CashAddressTestData;
import org.bitcoinj.testData.CashAddressTestList;
import org.junit.Test;
import org.spongycastle.util.encoders.Hex;

public class CashAddressTest {

    @Test
    public void validVectorTest() throws Exception {

        CashAddressTestList list = CashAddressTestList.getValidBech32();
        for (CashAddressTestData item : list.cases) {

            // encode
            byte[] versionAndData = Hex.decode(item.hex);
            byte[] data = new byte[versionAndData.length - 1];
            System.arraycopy(versionAndData, 1, data, 0, data.length);
            String encode = CashAddress.encode(item.prefix, item.type, data);

            assertEquals(encode, item.str.toLowerCase());

            // decode
            CashAddress decode = CashAddress.decode(item.str);
            assertEquals(item.prefix, decode.prefix);
            assertEquals(item.type, decode.scriptType);
            assertEquals(item.hex, decode.hash);
        }
    }

    @Test
    public void toLegacyMainnet() throws Exception {

        CashAddressTestList list = CashAddressTestList.getCashToLegacyMainNetwork();
        for (CashAddressTestData item : list.cases) {
            assertEquals(item.legacy, CashAddress.toLegacy(BitcoinCashMainNetParams.get(), item.str));
        }
    }

    @Test
    public void toLegacyTestnet() throws Exception {

        CashAddressTestList list = CashAddressTestList.getCashToLegacyTestNetwork();
        for (CashAddressTestData item : list.cases) {
            assertEquals(item.legacy, CashAddress.toLegacy(BitcoinCashTestNet3Params.get(), item.str));
        }
    }

    @Test
    public void decodeInvalidTest() throws Exception {

        CashAddressTestList list = CashAddressTestList.getInvalidAddress();
        for (CashAddressTestData item : list.cases) {

            try {
                CashAddress.decode(item.str);
                fail("This should not pass");
            }catch (Exception e) {
                assertTrue(true);
            }
        }
    }

    @Test
    public void decodeInvalidScriptTypeTest() throws Exception {

        try {
            byte[] versionAndData = Hex.decode("0076a04053bda0a88bda5177b86a15c3b29f559873");
            byte[] data = new byte[versionAndData.length - 1];
            System.arraycopy(versionAndData, 1, data, 0, data.length);
            CashAddress.encode("bitcoincash", "segwit", data);
            fail("This should not pass");
        }catch (Exception e) {
            assertTrue(true);
        }
    }

    @Test
    public void decodeInvalidHashTest() throws Exception {

        try {
            byte[] versionAndData = Hex.decode("asljdhgasljdhfasldjhfaslhjdgasdasd");
            byte[] data = new byte[versionAndData.length - 1];
            System.arraycopy(versionAndData, 1, data, 0, data.length);
            CashAddress.encode("bitcoincash", "pubkeyhash", data);
            fail("This should not pass");
        }catch (Exception e) {
            assertTrue(true);
        }
    }

    @Test
    public void decodeMismatchHashTest() throws Exception {

        try {
            byte[] versionAndData = Hex.decode("0076a04053bda0aa15c3b29f559873");
            byte[] data = new byte[versionAndData.length - 1];
            System.arraycopy(versionAndData, 1, data, 0, data.length);
            CashAddress.encode("bitcoincash", CashAddress.P2SH, data);
            fail("This should not pass");
        }catch (Exception e) {
            assertTrue(true);
        }
    }
}