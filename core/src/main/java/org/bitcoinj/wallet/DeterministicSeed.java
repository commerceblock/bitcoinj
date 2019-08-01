/*
 * Copyright 2014 Google Inc.
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

package org.bitcoinj.wallet;

import org.bitcoinj.core.Utils;
import org.bitcoinj.crypto.*;

import com.google.common.base.Charsets;
import com.google.common.base.Objects;
import com.google.common.base.Splitter;
import org.spongycastle.crypto.params.KeyParameter;

import javax.annotation.Nullable;
import java.security.SecureRandom;
import java.util.List;

import static com.google.common.base.Preconditions.checkArgument;
import static org.bitcoinj.core.Utils.HEX;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

/**
 * Holds the seed bytes for the BIP32 deterministic wallet algorithm, inside a
 * {@link DeterministicKeyChain}. The purpose of this wrapper is to simplify the encryption
 * code.
 */
public class DeterministicSeed {
    // It would take more than 10^12 years to brute-force a 128 bit seed using $1B worth of computing equipment.
    public static final int DEFAULT_SEED_ENTROPY_BITS = 128;
    public static final int MAX_SEED_ENTROPY_BITS = 512;

    @Nullable private final byte[] seed;
    @Nullable private final List<String> mnemonicCode; // only one of mnemonicCode/encryptedMnemonicCode will be set
    private long creationTimeSeconds;

    public DeterministicSeed(String mnemonicCode, byte[] seed, String passphrase, long creationTimeSeconds) throws UnreadableWalletException {
        this(decodeMnemonicCode(mnemonicCode), seed, passphrase, creationTimeSeconds);
    }

    public DeterministicSeed(byte[] seed, List<String> mnemonic, long creationTimeSeconds) {
        this.seed = checkNotNull(seed);
        this.mnemonicCode = checkNotNull(mnemonic);
        this.creationTimeSeconds = creationTimeSeconds;
    }

    /**
     * Constructs a seed from a BIP 39 mnemonic code. See {@link org.bitcoinj.crypto.MnemonicCode} for more
     * details on this scheme.
     * @param mnemonicCode A list of words.
     * @param seed The derived seed, or pass null to derive it from mnemonicCode (slow)
     * @param passphrase A user supplied passphrase, or an empty string if there is no passphrase
     * @param creationTimeSeconds When the seed was originally created, UNIX time.
     */
    public DeterministicSeed(List<String> mnemonicCode, @Nullable byte[] seed, String passphrase, long creationTimeSeconds) {
        this((seed != null ? seed : MnemonicCode.toSeed(mnemonicCode, checkNotNull(passphrase))), mnemonicCode, creationTimeSeconds);
    }

    /**
     * Constructs a seed from a BIP 39 mnemonic code. See {@link org.bitcoinj.crypto.MnemonicCode} for more
     * details on this scheme.
     * @param random Entropy source
     * @param bits number of bits, must be divisible by 32
     * @param passphrase A user supplied passphrase, or an empty string if there is no passphrase
     * @param creationTimeSeconds When the seed was originally created, UNIX time.
     */
    public DeterministicSeed(SecureRandom random, int bits, String passphrase, long creationTimeSeconds) {
        this(getEntropy(random, bits), checkNotNull(passphrase), creationTimeSeconds);
    }

    /**
     * Constructs a seed from a BIP 39 mnemonic code. See {@link org.bitcoinj.crypto.MnemonicCode} for more
     * details on this scheme.
     * @param entropy entropy bits, length must be divisible by 32
     * @param passphrase A user supplied passphrase, or an empty string if there is no passphrase
     * @param creationTimeSeconds When the seed was originally created, UNIX time.
     */
    public DeterministicSeed(byte[] entropy, String passphrase, long creationTimeSeconds) {
        checkArgument(entropy.length % 4 == 0, "entropy size in bits not divisible by 32");
        checkArgument(entropy.length * 8 >= DEFAULT_SEED_ENTROPY_BITS, "entropy size too small");
        checkNotNull(passphrase);

        try {
            this.mnemonicCode = MnemonicCode.INSTANCE.toMnemonic(entropy);
        } catch (MnemonicException.MnemonicLengthException e) {
            // cannot happen
            throw new RuntimeException(e);
        }
        this.seed = MnemonicCode.toSeed(mnemonicCode, passphrase);
        this.creationTimeSeconds = creationTimeSeconds;
    }

    private static byte[] getEntropy(SecureRandom random, int bits) {
        checkArgument(bits <= MAX_SEED_ENTROPY_BITS, "requested entropy size too large");

        byte[] seed = new byte[bits / 8];
        random.nextBytes(seed);
        return seed;
    }

    @Override
    public String toString() {
        return "DeterministicSeed " + toHexString() + " " + Utils.SPACE_JOINER.join(mnemonicCode);
    }

    /** Returns the seed as hex or null if encrypted. */
    @Nullable
    public String toHexString() {
        return seed != null ? HEX.encode(seed) : null;
    }

    @Nullable
    public byte[] getSecretBytes() {
        return getMnemonicAsBytes();
    }

    @Nullable
    public byte[] getSeedBytes() {
        return seed;
    }

    public long getCreationTimeSeconds() {
        return creationTimeSeconds;
    }

    public void setCreationTimeSeconds(long creationTimeSeconds) {
        this.creationTimeSeconds = creationTimeSeconds;
    }

    private byte[] getMnemonicAsBytes() {
        return Utils.SPACE_JOINER.join(mnemonicCode).getBytes(Charsets.UTF_8);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DeterministicSeed other = (DeterministicSeed) o;
        return creationTimeSeconds == other.creationTimeSeconds
            && Objects.equal(mnemonicCode, other.mnemonicCode);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(creationTimeSeconds, mnemonicCode);
    }

    /**
     * Check if our mnemonic is a valid mnemonic phrase for our word list.
     * Does nothing if we are encrypted.
     *
     * @throws org.bitcoinj.crypto.MnemonicException if check fails
     */
    public void check() throws MnemonicException {
        if (mnemonicCode != null)
            MnemonicCode.INSTANCE.check(mnemonicCode);
    }

    byte[] getEntropyBytes() throws MnemonicException {
        return MnemonicCode.INSTANCE.toEntropy(mnemonicCode);
    }

    /** Get the mnemonic code, or null if unknown. */
    @Nullable
    public List<String> getMnemonicCode() {
        return mnemonicCode;
    }

    private static List<String> decodeMnemonicCode(byte[] mnemonicCode) {
        return decodeMnemonicCode(Utils.toString(mnemonicCode, "UTF-8"));
    }

    private static List<String> decodeMnemonicCode(String mnemonicCode) {
        return Splitter.on(" ").splitToList(mnemonicCode);
    }
}
