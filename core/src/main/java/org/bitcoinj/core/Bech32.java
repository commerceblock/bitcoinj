package org.bitcoinj.core;

import java.util.Locale;

/**
 * https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
 *
 * BIP 173 is a proposal for a new SegWit address format to replace BIP 142. This format is not
 * required for using segwit, but is more efficient, flexible, and nicer to use.
 *
 * The format is base 32 and uses a simple checksum algorithm with strong error detection
 * properties. Reference code in several languages as well as a website demonstrating it are
 * included.
 */
public class Bech32 {

    private static final String CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    /**
     * @param params NetworkParameters that will provide the human-readable part and separator,
     * which is intended to convey the type of data, or anything else that is relevant to the
     * reader. This part MUST contain 1 to 83 US-ASCII characters, with each character having a
     * value in the range [33-126]. HRP validity may be further restricted by specific
     * applications.
     * @param data part, which is at least 6 characters long and only consists of alphanumeric
     * characters excluding "1", "b", "i", and "o"[4]. Represents the characters after conversion
     * using the bip173 conversion table.
     * @return
     */
    public static String encode(NetworkParameters params, byte[] data) throws AddressFormatException {

        String prefix = params.getBech32AddressPrefix();
        byte separator = params.getBech32AddressSeparator();

        byte[] checksum = createChecksum(prefix.getBytes(), data);
        byte[] combined = new byte[checksum.length + data.length];

        System.arraycopy(data, 0, combined, 0, data.length);
        System.arraycopy(checksum, 0, combined, data.length, checksum.length);

        byte[] xlat = new byte[combined.length];
        for (int i = 0; i < combined.length; i++) {
            xlat[i] = (byte) CHARSET.charAt(combined[i]);
        }

        byte[] ret = new byte[prefix.getBytes().length + xlat.length + 1];
        System.arraycopy(prefix.getBytes(), 0, ret, 0, prefix.getBytes().length);
        System.arraycopy(new byte[]{separator}, 0, ret, prefix.getBytes().length, 1);
        System.arraycopy(xlat, 0, ret, prefix.getBytes().length + 1, xlat.length);

        return new String(ret);
    }

    public static Bech32Parts decode(NetworkParameters params, String bech) throws AddressFormatException {

        byte[] buffer = bech.getBytes();
        for (byte b : buffer) {
            if (b < 0x21 || b > 0x7e) {
                throw new AddressFormatException("bech32 characters out of range");
            }
        }

        if (!bech.equals(bech.toLowerCase(Locale.ROOT)) && !bech
            .equals(bech.toUpperCase(Locale.ROOT))) {
            throw new AddressFormatException("bech32 cannot mix upper and lower case");
        }

        bech = bech.toLowerCase();
        int pos = bech.lastIndexOf(params.getBech32AddressSeparator());
        if (pos < 1) {
            throw new AddressFormatException("bech32 missing separator");
        } else if (pos + 7 > bech.length()) {
            throw new AddressFormatException("bech32 separator misplaced");
        } else if (bech.length() < 8) {
            throw new AddressFormatException("bech32 input too short");
        } else if (bech.length() > 90) {
            throw new AddressFormatException("bech32 input too long");
        } else {
            ;
        }

        String s = bech.substring(pos + 1);
        for (int i = 0; i < s.length(); i++) {
            if (CHARSET.indexOf(s.charAt(i)) == -1) {
                throw new AddressFormatException("bech32 characters  out of range");
            }
        }

        byte[] prefix = bech.substring(0, pos).getBytes();

        byte[] data = new byte[bech.length() - pos - 1];
        for (int j = 0, i = pos + 1; i < bech.length(); i++, j++) {
            data[j] = (byte) CHARSET.indexOf(bech.charAt(i));
        }

        if (!verifyChecksum(prefix, data)) {
            throw new AddressFormatException("invalid bech32 checksum");
        }

        byte[] ret = new byte[data.length - 6];
        System.arraycopy(data, 0, ret, 0, data.length - 6);

        return new Bech32Parts(new String(prefix), ret);
    }

    private static int polymod(byte[] values) {

        final int[] GENERATORS = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};

        int chk = 1;

        for (byte b : values) {
            byte top = (byte) (chk >> 0x19);
            chk = b ^ ((chk & 0x1ffffff) << 5);
            for (int i = 0; i < 5; i++) {
                chk ^= ((top >> i) & 1) == 1 ? GENERATORS[i] : 0;
            }
        }

        return chk;
    }

    private static byte[] hrpExpand(byte[] hrp) {

        byte[] buf1 = new byte[hrp.length];
        byte[] buf2 = new byte[hrp.length];
        byte[] mid = new byte[1];

        for (int i = 0; i < hrp.length; i++) {
            buf1[i] = (byte) (hrp[i] >> 5);
        }
        mid[0] = 0x00;
        for (int i = 0; i < hrp.length; i++) {
            buf2[i] = (byte) (hrp[i] & 0x1f);
        }

        byte[] ret = new byte[(hrp.length * 2) + 1];
        System.arraycopy(buf1, 0, ret, 0, buf1.length);
        System.arraycopy(mid, 0, ret, buf1.length, mid.length);
        System.arraycopy(buf2, 0, ret, buf1.length + mid.length, buf2.length);

        return ret;
    }

    private static boolean verifyChecksum(byte[] hrp, byte[] data) {

        byte[] exp = hrpExpand(hrp);

        byte[] values = new byte[exp.length + data.length];
        System.arraycopy(exp, 0, values, 0, exp.length);
        System.arraycopy(data, 0, values, exp.length, data.length);

        return (1 == polymod(values));
    }

    private static byte[] createChecksum(byte[] hrp, byte[] data) {

        final byte[] zeroes = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        byte[] expanded = hrpExpand(hrp);
        byte[] values = new byte[zeroes.length + expanded.length + data.length];

        System.arraycopy(expanded, 0, values, 0, expanded.length);
        System.arraycopy(data, 0, values, expanded.length, data.length);
        System.arraycopy(zeroes, 0, values, expanded.length + data.length, zeroes.length);

        int polymod = polymod(values) ^ 1;
        byte[] ret = new byte[6];
        for (int i = 0; i < ret.length; i++) {
            ret[i] = (byte) ((polymod >> 5 * (5 - i)) & 0x1f);
        }

        return ret;
    }

    public static class Bech32Parts {

        private String prefix;
        private byte[] data;

        public Bech32Parts(String prefix, byte[] data) {
            this.prefix = prefix;
            this.data = data;
        }

        public String getPrefix() {
            return prefix;
        }

        public byte[] getData() {
            return data;
        }
    }
}