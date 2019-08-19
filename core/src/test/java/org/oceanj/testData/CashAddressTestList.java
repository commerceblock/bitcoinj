package org.oceanj.testData;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.ArrayList;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonAutoDetect(fieldVisibility = Visibility.NONE,
    getterVisibility = Visibility.NONE,
    setterVisibility = Visibility.NONE,
    creatorVisibility = Visibility.NONE,
    isGetterVisibility = Visibility.NONE)
public class CashAddressTestList {

    @JsonProperty("cases")
    public ArrayList<CashAddressTestData> cases;

    public static CashAddressTestList getValidBech32() throws IOException {
        return toList(validBech32);
    }

    public static CashAddressTestList getInvalidAddress() throws IOException {
        return toList(invalidAddress);
    }

    public static CashAddressTestList getInvalidAddress2() throws IOException {
        return toList(invalidAddress2);
    }

    public static CashAddressTestList getCashToLegacyMainNetwork() throws IOException {
        return toList(cashToLegacyMain);
    }

    public static CashAddressTestList getCashToLegacyTestNetwork() throws IOException {
        return toList(cashToLegacyTest);
    }

    public static CashAddressTestList toList(String vectors) throws IOException {
        return new ObjectMapper().readValue(vectors, CashAddressTestList.class);
    }

    public static final String validBech32 = "{\n"
        + "\"cases\": [{\n"
        + "\"string\": \"bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a\",\n"
        + "\"prefix\": \"bitcoincash\",\n"
        + "\"type\": \"pubkeyhash\",\n"
        + "\"hex\": \"0076a04053bda0a88bda5177b86a15c3b29f559873\",\n"
        + "\"words\": [0, 1, 27, 10, 0, 16, 2, 19, 23, 22, 16, 10, 17, 2, 30, 26, 10, 5, 27, 27, 16, 26, 16, 21, 24, 14, 25, 9, 30, 21, 12, 24, 14, 12]\n"
        + "},\n"
        + "{\n"
        + "\"string\": \"bchtest:ppm2qsznhks23z7629mms6s4cwef74vcwvhanqgjxu\",\n"
        + "\"prefix\": \"bchtest\",\n"
        + "\"type\": \"scripthash\",\n"
        + "\"hex\": \"0876a04053bda0a88bda5177b86a15c3b29f559873\",\n"
        + "\"words\": [1, 1, 27, 10, 0, 16, 2, 19, 23, 22, 16, 10, 17, 2, 30, 26, 10, 5, 27, 27, 16, 26, 16, 21, 24, 14, 25, 9, 30, 21, 12, 24, 14, 12]\n"
        + "},\n"
        + "{\n"
        + "\"string\": \"bchreg:pqzg22ty3m437frzk4y0gvvyqj02jpfv7udqugqkne\",\n"
        + "\"prefix\": \"bchreg\",\n"
        + "\"type\": \"scripthash\",\n"
        + "\"hex\": \"08048529648eeb1f2462b548f43184049ea9052cf7\",\n"
        + "\"words\": [1, 0, 2, 8, 10, 10, 11, 4, 17, 27, 21, 17, 30, 9, 3, 2, 22, 21, 4, 15, 8, 12, 12, 4, 0, 18, 15, 10, 18, 1, 9, 12, 30, 28]\n"
        + "},\n"
        + "{\n"
        + "\"string\": \"bitcoincash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy\",\n"
        + "\"prefix\": \"bitcoincash\",\n"
        + "\"type\": \"pubkeyhash\",\n"
        + "\"legacy\": \"1KXrWXciRDZUpQwQmuM1DbwsKDLYAYsVLR\",\n"
        + "\"hex\": \"00cb481232299cd5743151ac4b2d63ae198e7bb0a9\",\n"
        + "\"words\": [0, 3, 5, 20, 16, 4, 17, 18, 5, 6, 14, 13, 10, 29, 1, 17, 10, 6, 22, 4, 22, 11, 11, 3, 21, 24, 12, 24, 28, 30, 29, 16, 21, 4]\n"
        + "},\n"
        + "{\n"
        + "\"string\": \"bitcoincash:qqq3728yw0y47sqn6l2na30mcw6zm78dzqre909m2r\",\n"
        + "\"prefix\": \"bitcoincash\",\n"
        + "\"type\": \"pubkeyhash\",\n"
        + "\"legacy\": \"16w1D5WRVKJuZUsSRzdLp9w3YGcgoxDXb\",\n"
        + "\"hex\": \"00011f28e473c95f4013d7d53ec5fbc3b42df8ed10\",\n"
        + "\"words\": [0, 0, 0, 17, 30, 10, 7, 4, 14, 15, 4, 21, 30, 16, 0, 19, 26, 31, 10, 19, 29, 17, 15, 27, 24, 14, 26, 2, 27, 30, 7, 13, 2, 0]\n"
        + "},\n"
        + "{\n"
        + "\"string\": \"bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq\",\n"
        + "\"prefix\": \"bitcoincash\",\n"
        + "\"type\": \"scripthash\",\n"
        + "\"legacy\": \"3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC\",\n"
        + "\"hex\": \"0876a04053bda0a88bda5177b86a15c3b29f559873\",\n"
        + "\"words\": [1, 1, 27, 10, 0, 16, 2, 19, 23, 22, 16, 10, 17, 2, 30, 26, 10, 5, 27, 27, 16, 26, 16, 21, 24, 14, 25, 9, 30, 21, 12, 24, 14, 12]\n"
        + "},\n"
        + "{\n"
        + "\"string\": \"bitcoincash:pr95sy3j9xwd2ap32xkykttr4cvcu7as4yc93ky28e\",\n"
        + "\"prefix\": \"bitcoincash\",\n"
        + "\"type\": \"scripthash\",\n"
        + "\"legacy\": \"3LDsS579y7sruadqu11beEJoTjdFiFCdX4\",\n"
        + "\"hex\": \"08cb481232299cd5743151ac4b2d63ae198e7bb0a9\",\n"
        + "\"words\": [1, 3, 5, 20, 16, 4, 17, 18, 5, 6, 14, 13, 10, 29, 1, 17, 10, 6, 22, 4, 22, 11, 11, 3, 21, 24, 12, 24, 28, 30, 29, 16, 21, 4]\n"
        + "},\n"
        + "{\n"
        + "\"string\": \"bitcoincash:pqq3728yw0y47sqn6l2na30mcw6zm78dzq5ucqzc37\",\n"
        + "\"prefix\": \"bitcoincash\",\n"
        + "\"type\": \"scripthash\",\n"
        + "\"legacy\": \"31nwvkZwyPdgzjBJZXfDmSWsC4ZLKpYyUw\",\n"
        + "\"hex\": \"08011f28e473c95f4013d7d53ec5fbc3b42df8ed10\",\n"
        + "\"words\": [1, 0, 0, 17, 30, 10, 7, 4, 14, 15, 4, 21, 30, 16, 0, 19, 26, 31, 10, 19, 29, 17, 15, 27, 24, 14, 26, 2, 27, 30, 7, 13, 2, 0]\n"
        + "}\n"
        + "]\n"
        + "}";


    public static final String invalidAddress = "{\n"
        + "\"cases\": [{\n"
        + "\"string\": \"bitcoincash:qqyq78nf2w\",\n"
        + "\"exception\": \"Hash length does not match version\"\n"
        + "},\n"
        + "{\n"
        + "\"string\": \"bitcoincash:a5a8yrhz\",\n"
        + "\"exception\": \"Empty payload in address\"\n"
        + "},\n"
        + "{\n"
        + "\"string\": \"bitcoincash:qdpyysjzgfpyysjzgfpyysjzgfpyysjzgg8zlhfxky\",\n"
        + "\"exception\": \"Mismatch between script type and hash length\"\n"
        + "},\n"
        + "{\n"
        + "\"string\": \"bitcoincash:yppyysjzgfpyysjzgfpyysjzgfpyysjzggc5ldue0t\",\n"
        + "\"exception\": \"Invalid script type\"\n"
        + "},\n"
        + "{\n"
        + "\"string\": \"bitcoincash:lapyysjzgfpyysjzgfpyysjzgfpyysjzggp9pz6yrw\",\n"
        + "\"exception\": \"Invalid version, most significant bit is reserved\"\n"
        + "}\n"
        + "]\n"
        + "}";

    public static final String invalidAddress2 = "{\n"
        + "\"cases\": [\n"
        + "      {\n"
        + "        \"string\": \"bitcoincashqpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a\",\n"
        + "        \"exception\": \"No separator character for bitcoincashqpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a\"\n"
        + "      },\n"
        + "      {\n"
        + "        \"string\": \":qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a\",\n"
        + "        \"exception\": \"Missing prefix for :qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a\"\n"
        + "      },\n"
        + "      {\n"
        + "        \"string\": \"bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6z\",\n"
        + "        \"exception\": \"Invalid checksum for bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6z\"\n"
        + "      },\n"
        + "      {\n"
        + "        \"string\": \"bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcw1y22gdx6z\",\n"
        + "        \"exception\": \"Unknown character 1\"\n"
        + "      },\n"
        + "      {\n"
        + "        \"string\": \"bitcoincash:gdx6z\",\n"
        + "        \"exception\": \"Data too short\"\n"
        + "      },\n"
        + "      {\n"
        + "        \"string\": \"abxca\",\n"
        + "        \"exception\": \"too short\"\n"
        + "      },\n"
        + "      {\n"
        + "        \"string\": \"abxcaabxcaabxcaabxcaabxcaabxcaabxcaabxcaabxcaabxcaabxcaabxcaabxcaabxcaabxcaabxcaabxcaabxcaabxcaabxcaabxcaabxcaabxcaabxcaabxcaabxca\",\n"
        + "        \"exception\": \"too long\"\n"
        + "      },\n"
        + "      {\n"
        + "        \"string\": \"bitcoincash:pqQ3728yW0y47sqN6l2na30mcW6zm78dZq5ucqzc37\",\n"
        + "        \"exception\": \"Mixed-case string bitcoincash:pqQ3728yW0y47sqN6l2na30mcW6zm78dZq5ucqzc37\"\n"
        + "      }\n"
        + "    ]\n"
        + "}";

    public static final String cashToLegacyMain = "{\"cases\": [\n"
        + "    {\"string\": \"bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a\",\n"
        + "    \"legacy\": \"1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu\"},\n"
        + "  \t{\"string\": \"bitcoincash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy\",\n"
        + "    \"legacy\": \"1KXrWXciRDZUpQwQmuM1DbwsKDLYAYsVLR\"},\n"
        + "  \t{\"string\": \"bitcoincash:qqq3728yw0y47sqn6l2na30mcw6zm78dzqre909m2r\",\n"
        + "    \"legacy\": \"16w1D5WRVKJuZUsSRzdLp9w3YGcgoxDXb\"},\n"
        + "  \t{\"string\": \"bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq\",\n"
        + "    \"legacy\": \"3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC\"},\n"
        + "  \t{\"string\": \"bitcoincash:pr95sy3j9xwd2ap32xkykttr4cvcu7as4yc93ky28e\",\n"
        + "    \"legacy\": \"3LDsS579y7sruadqu11beEJoTjdFiFCdX4\"},\n"
        + "    {\"string\": \"bitcoincash:pqq3728yw0y47sqn6l2na30mcw6zm78dzq5ucqzc37\",\n"
        + "    \"legacy\": \"31nwvkZwyPdgzjBJZXfDmSWsC4ZLKpYyUw\"}\n"
        + "]}";

    public static final String cashToLegacyTest = "{\"cases\": [\n"
        + "    {\"string\": \"bchtest:ppm2qsznhks23z7629mms6s4cwef74vcwvhanqgjxu\",\n"
        + "    \"legacy\": \"2N44ThNe8NXHyv4bsX8AoVCXquBRW94Ls7W\"},\n"
        + "  \t{\"string\": \"bchtest:qzc5q87w069lzg7g3gzx0c8dz83mn7l02sutknlgmj\",\n"
        + "    \"legacy\": \"mwgAiSPoVrdFEp8RwznsMHvRhRHRGBKw7a\"},\n"
        + "  \t{\"string\": \"bchtest:qptx8x58rk948wqgk2uwd729z6vmx6hg5gmzlvewfu\",\n"
        + "    \"legacy\": \"moPjj8eE78rNWZYauZS2jkB8PnCTo6F94o\"},\n"
        + "  \t{\"string\": \"bchtest:qq30wmv70rw62fygl7rwzgq0lgu04h7f6yrnt4l3ng\",\n"
        + "    \"legacy\": \"mihqgBuq7mcQk22ZURDccrsjYKMn8YMh9N\"},\n"
        + "  \t{\"string\": \"bchtest:qpequnsd7fm4e02kfsfkvrz2czctav52yq7u3sty6t\",\n"
        + "    \"legacy\": \"mqv2TqwSozpkHLGxwvZHqd6geAB3SZ8odL\"}\n"
        + "]}";
}