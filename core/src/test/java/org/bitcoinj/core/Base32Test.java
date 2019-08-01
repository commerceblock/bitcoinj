package org.bitcoinj.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.Arrays;
import java.util.Iterator;
import org.bitcoinj.testData.Base32Data;
import org.junit.Test;
import org.spongycastle.util.encoders.Hex;

public class Base32Test {

    private JsonNode getTestVectors() {
        JsonNode root = null;
        try {
            root = new ObjectMapper().readTree(Base32Data.base32);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return root;
    }

    String str = "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a";
    String prefix = "bitcoincash";
    String type = "pubkeyhash";
    String hex = "0076a04053bda0a88bda5177b86a15c3b29f559873";
    byte[] words = {0, 1, 27, 10, 0, 16, 2, 19, 23, 22, 16, 10, 17, 2, 30, 26, 10, 5, 27, 27, 16, 26, 16, 21, 24, 14, 25, 9, 30, 21, 12, 24, 14, 12};

    private byte[] toBytes(JsonNode jsonNode, String key) {
        return new String(jsonNode.get(key).toString()).getBytes();
    }

    @Test
    public void fromFails() {

        JsonNode testData = getTestVectors();
        Iterator<JsonNode> it = testData.path("fromWords").findValue("invalid").iterator();

        while (it.hasNext()) {
            JsonNode next = it.next();

            byte[] words = toBytes(next, "words");
            try {
                Base32.fromWords(words);
            }catch (Exception e) {
                System.out.println("yay ");
            }
        }

//        assertEquals(Base32.encode(prefix, words), str.toLowerCase());
    }

    @Test
    public void encodeTest() throws Exception {

        JsonNode testData = getTestVectors();
        System.out.println(testData.path("fromWords").toString());

        assertEquals(Base32.encode(prefix, words), str.toLowerCase());
    }

    @Test(expected = AddressFormatException.class)
    public void encodeExceedsBase32LengthTest() throws Exception {

        byte[] words = {14,20,15,7,13,26,0,25,18,6,11,13,8,21,4,20,3,17,2,29,3,14,20,15,7,13,26,0,25,18,6,11,13,8,21,4,20,3,17,2,29,14,20,15,7,13,26,0,25,18,6,11,13,8,21,4,20,3,17,2,29,14,20,15,7,13,26,0,25,18,6,11,13,8,21,4,20,3,17,2,29};
        Base32.encode(prefix, words);
        fail("Exceeds Base32 maximum length");
    }

    @Test(expected = AddressFormatException.class)
    public void encodeNon5bitWordTest() throws Exception {

        byte[] words = {0, 1, 32, 10, 0, 16, 2, 19, 23, 22, 16, 10, 17, 2, 30, 26, 10, 5, 27, 27, 16, 26, 16, 21, 24, 14, 25, 9, 30, 21, 12, 24, 14, 12};
        Base32.encode(prefix, words);
        fail("Non 5-bit word");
    }

    @Test
    public void testDecode() throws Exception {

        Base32 result = Base32.decode(str);
        assertEquals(result.prefix, prefix);
        assertEquals(Hex.toHexString(result.words), Hex.toHexString(words));
    }

    @Test
    public void testToWords() throws Exception {
        byte[] versionAndData = Hex.decode(hex);

        byte[] toWords = Base32.toWords(versionAndData);
        assertEquals(Hex.toHexString(toWords), Hex.toHexString(words));
    }

    @Test
    public void testFromWords() throws Exception {

        byte[] fromWords = Base32.fromWords(words);
        assertEquals(hex, Hex.toHexString(fromWords));
    }

    @Test(expected = AddressFormatException.class)
    public void testExcessPaddingFromWords() throws Exception {

        byte[] words = {14,20,15,7,13,26,0,25,18,6,11,13,8,21,4,20,3,17,2,29,3,0};
        Base32.fromWords(words);
        fail("Excess padding");
    }

    @Test(expected = AddressFormatException.class)
    public void testNonZeroPaddingFromWords() throws Exception {

        byte[] words = {3,1,17,17,8,15,0,20,24,20,11,6,16,1,5,29,3,4,16,3,6,21,22,26,2,13,22,9,16,21,19,24,25,21,6,18,15,8,13,24,24,24,25,9,12,1,4,16,6,9,17,1};
        Base32.fromWords(words);
        fail("Non-zero padding");
    }
}
