/*
 * Copyright 2011 Google Inc.
 * Copyright 2014 Andreas Schildbach
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

import com.google.common.annotations.*;
import com.google.common.base.*;
import com.google.common.collect.*;
import org.oceanj.script.*;
import org.slf4j.*;

import javax.annotation.*;
import java.io.*;
import java.math.*;
import java.util.*;

import static org.oceanj.core.Coin.*;
import static org.oceanj.core.Sha256Hash.*;

/**
 * <p>A block is a group of transactions, and is one of the fundamental data structures of the Bitcoin system.
 * It records a set of {@link Transaction}s together with some data that links it into a place in the global block
 * chain, and proves that a difficult calculation was done over its contents. See
 * <a href="http://www.bitcoin.org/bitcoin.pdf">the Bitcoin technical paper</a> for
 * more detail on blocks. <p/>
 *
 * <p>To get a block, you can either build one from the raw bytes you can get from another implementation, or request one
 * specifically using {@link Peer#getBlock(Sha256Hash)}, or grab one from a downloaded {@link BlockChain}.</p>
 *
 * <p>Instances of this class are not safe for use by multiple threads.</p>
 */
public class Block extends Message {
    /**
     * Flags used to control which elements of block validation are done on
     * received blocks.
     */
    public enum VerifyFlag {
        /** Check that block height is in coinbase transaction (BIP 34). */
        HEIGHT_IN_COINBASE
    }

    private static final Logger log = LoggerFactory.getLogger(Block.class);

    /** Minimum header size for both which is changed upon block read/initialization. */
    public int HEADER_SIZE_HASH = 173;
    public int HEADER_SIZE_FULL = 173;

    static final long ALLOWED_TIME_DRIFT = 2 * 60 * 60; // Same value as Bitcoin Core.

    /**
     * A constant shared by the entire network: how large in bytes a block is allowed to be. One day we may have to
     * upgrade everyone to change this, so Bitcoin can continue to grow. For now it exists as an anti-DoS measure to
     * avoid somebody creating a titanically huge but valid block and forcing everyone to download/store it forever.
     */
    public static final int MAX_BLOCK_SIZE = 1 * 1000 * 1000;
    /**
     * A "sigop" is a signature verification operation. Because they're expensive we also impose a separate limit on
     * the number in a block to prevent somebody mining a huge block that has way more sigops than normal, so is very
     * expensive/slow to verify.
     */
    public static final int MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE / 50;

    /** Value to use if the block height is unknown */
    public static final int BLOCK_HEIGHT_UNKNOWN = -1;
    /** Height of the first block */
    public static final int BLOCK_HEIGHT_GENESIS = 0;

    public static final long BLOCK_VERSION_GENESIS = 1;
    /** Block version introduced in BIP 34: Height in coinbase */
    public static final long BLOCK_VERSION_BIP34 = 2;
    /** Block version introduced in BIP 66: Strict DER signatures */
    public static final long BLOCK_VERSION_BIP66 = 3;
    /** Block version introduced in BIP 65: OP_CHECKLOCKTIMEVERIFY */
    public static final long BLOCK_VERSION_BIP65 = 4;

    // Fields defined as part of the protocol format.
    private long version;
    private Sha256Hash prevBlockHash, merkleRoot;
    private byte[] contractHash, attestationHash, mappingHash;
    private long time;
    private long blockHeight;
    private int challengeLength, proofLength;
    private Script challengeScript, proofScript;

    // TODO: Get rid of all the direct accesses to this field. It's a long-since unnecessary holdover from the Dalvik days.
    /** If null, it means this object holds only the headers. */
    @Nullable List<Transaction> transactions;

    /** Stores the hash of the block. If null, getHash() will recalculate it. */
    private Sha256Hash hash;

    protected boolean headerBytesValid;
    protected boolean transactionBytesValid;

    // Blocks can be encoded in a way that will use more bytes than is optimal (due to VarInts having multiple encodings)
    // MAX_BLOCK_SIZE must be compared to the optimal encoding, not the actual encoding, so when parsing, we keep track
    // of the size of the ideal encoding in addition to the actual message size (which Message needs)
    protected int optimalEncodingMessageSize;

    /** Special case constructor, used for the genesis node, cloneAsHeader and unit tests. */
    Block(NetworkParameters params, long setVersion) {
        super(params);
        // Set up a few basic things. We are not complete after this though.
        version = setVersion;
        time = System.currentTimeMillis() / 1000;
        prevBlockHash = Sha256Hash.ZERO_HASH;
        contractHash = new byte[32];
        Arrays.fill( contractHash, (byte) 0 );
        attestationHash = new byte[32];
        Arrays.fill( attestationHash, (byte) 0 );
        mappingHash = new byte[32];
        Arrays.fill( mappingHash, (byte) 0 );

        length = HEADER_SIZE_FULL;
    }

    /**
     * Constructs a block object from the Bitcoin wire format.
     * @deprecated Use {@link BitcoinSerializer#makeBlock(byte[])} instead.
     */
    @Deprecated
    public Block(NetworkParameters params, byte[] payloadBytes) throws ProtocolException {
        super(params, payloadBytes, 0, params.getDefaultSerializer(), payloadBytes.length);
    }

    /**
     * Construct a block object from the Bitcoin wire format.
     * @param params NetworkParameters object.
     * @param payloadBytes the payload to extract the block from.
     * @param serializer the serializer to use for this message.
     * @param length The length of message if known.  Usually this is provided when deserializing of the wire
     * as the length will be provided as part of the header.  If unknown then set to Message.UNKNOWN_LENGTH
     * @throws ProtocolException
     */
    public Block(NetworkParameters params, byte[] payloadBytes, MessageSerializer serializer, int length)
            throws ProtocolException {
        super(params, payloadBytes, 0, serializer, length);
    }

    /**
     * Construct a block object from the Bitcoin wire format.
     * @param params NetworkParameters object.
     * @param payloadBytes the payload to extract the block from.
     * @param offset The location of the first payload byte within the array.
     * @param serializer the serializer to use for this message.
     * @param length The length of message if known.  Usually this is provided when deserializing of the wire
     * as the length will be provided as part of the header.  If unknown then set to Message.UNKNOWN_LENGTH
     * @throws ProtocolException
     */
    public Block(NetworkParameters params, byte[] payloadBytes, int offset, MessageSerializer serializer, int length)
            throws ProtocolException {
        super(params, payloadBytes, offset, serializer, length);
    }

    /**
     * Construct a block object from the Bitcoin wire format. Used in the case of a block
     * contained within another message (i.e. for AuxPoW header).
     *
     * @param params NetworkParameters object.
     * @param payloadBytes Bitcoin protocol formatted byte array containing message content.
     * @param offset The location of the first payload byte within the array.
     * @param parent The message element which contains this block, maybe null for no parent.
     * @param serializer the serializer to use for this block.
     * @param length The length of message if known.  Usually this is provided when deserializing of the wire
     * as the length will be provided as part of the header.  If unknown then set to Message.UNKNOWN_LENGTH
     * @throws ProtocolException
     */
    public Block(NetworkParameters params, byte[] payloadBytes, int offset, @Nullable Message parent, MessageSerializer serializer, int length)
            throws ProtocolException {
        // TODO: Keep the parent
        super(params, payloadBytes, offset, serializer, length);
    }

    /**
     * Construct a block object from the Bitcoin wire format. Used in the case of a block
     * contained within another message (i.e. for AuxPoW header). This case includes a flag which can
     * tell our block to only parse as far as the end of header (no transactions)
     *
     * @param params NetworkParameters object.
     * @param payloadBytes Bitcoin protocol formatted byte array containing message content.
     * @param offset The location of the first payload byte within the array.
     * @param parent The message element which contains this block, maybe null for no parent.
     * @param serializer the serializer to use for this block.
     * @param length The length of message if known.  Usually this is provided when deserializing of the wire
     * @param headersOnly The flag which determines if a block should terminate the payloard parse before transactions.
     * as the length will be provided as part of the header.  If unknown then set to Message.UNKNOWN_LENGTH
     * @throws ProtocolException
     */
    public Block(NetworkParameters params, byte[] payloadBytes, int offset, MessageSerializer serializer,
        int length, boolean headersOnly)
            throws ProtocolException {
        super(params, payloadBytes, offset, serializer, length, headersOnly);
    }

    /**
     * Construct a block initialized with all the given fields.
     * @param version This should usually be set to 1 or 2, depending on if the height is in the coinbase input.
     * @param prevBlockHash Reference to previous block in the chain or {@link Sha256Hash#ZERO_HASH} if genesis.
     * @param merkleRoot The root of the merkle tree formed by the transactions.
     * @param contractHash The contract hash that public and private keys are tweaked by.
     * @param attestationHash 
     * @param mappingHash The asset mapping hash.
     * @param time UNIX time when the block was mined.
     * @param blockHeight Arbitrary number to make the block hash lower than the target.
     * @param challengeScript Script that must be satisfied for the block to be valid.
     * @param proofScript The proof that is combined with challengeScript to produce OP_TRUE.
     * @param transactions List of transactions including the coinbase.
     */
    public Block(NetworkParameters params, long version, Sha256Hash prevBlockHash, Sha256Hash merkleRoot,
        byte[] contractHash, byte[] attestationHash, byte[] mappingHash, long time,
        long blockHeight, int challengeLength, Script challengeScript, int proofLength,
        Script proofScript, List<Transaction> transactions) {
        super(params);
        this.version = version;
        this.prevBlockHash = prevBlockHash;
        this.merkleRoot = merkleRoot;
        this.contractHash = contractHash;
        this.attestationHash = attestationHash;
        this.mappingHash = mappingHash;
        this.time = time;
        this.blockHeight = blockHeight;
        this.challengeLength = challengeLength;
        this.challengeScript = challengeScript;
        HEADER_SIZE_HASH = 172 + (new VarInt(challengeLength)).getOriginalSizeInBytes() + 
            challengeScript.getProgram().length;
        this.proofLength = proofLength;
        this.proofScript = proofScript;
        HEADER_SIZE_FULL = HEADER_SIZE_HASH + (new VarInt(proofLength)).getOriginalSizeInBytes() + 
            proofScript.getProgram().length;
        this.transactions = new LinkedList<>();
        this.transactions.addAll(transactions);
    }


    /**
     * Parse transactions from the block.
     *
     * @param transactionsOffset Offset of the transactions within the block.
     * Useful for non-Bitcoin chains where the block header may not be a fixed
     * size.
     */
    protected void parseTransactions(final int transactionsOffset) throws ProtocolException {
        cursor = transactionsOffset;
        optimalEncodingMessageSize = HEADER_SIZE_FULL;
        if (payload.length == cursor) {
            // This message is just a header, it has no transactions.
            transactionBytesValid = false;
            return;
        }

        int numTransactions = (int) readVarInt();
        optimalEncodingMessageSize += VarInt.sizeOf(numTransactions);
        transactions = new ArrayList<>(numTransactions);
        for (int i = 0; i < numTransactions; i++) {
            Transaction tx = new Transaction(params, payload, cursor, this, serializer, UNKNOWN_LENGTH);
            // Label the transaction as coming from the P2P network, so code that cares where we first saw it knows.
            tx.getConfidence().setSource(TransactionConfidence.Source.NETWORK);
            transactions.add(tx);
            cursor += tx.getMessageSize();
            optimalEncodingMessageSize += tx.getOptimalEncodingMessageSize();
        }
        transactionBytesValid = serializer.isParseRetainMode();
    }

    @Override
    protected void parse() throws ProtocolException {
        // header
        cursor = offset;
        version = readUint32();
        prevBlockHash = readHash();
        merkleRoot = readHash();
        contractHash = readBytes(32);
        attestationHash = readBytes(32);
        mappingHash = readBytes(32);
        time = readUint32();
        blockHeight = readUint32();
        challengeLength = (int) readVarInt();
        int headerCursor = cursor;

        if (challengeLength > 0) {
            challengeScript = new Script(readBytes(challengeLength));
            headerCursor = cursor;
            proofLength = (int) readVarInt();
            if (proofLength > 0) {
                proofScript = new Script(readBytes(proofLength));
            }
        }

        HEADER_SIZE_HASH = 172 + (new VarInt(challengeLength)).getOriginalSizeInBytes() + 
            ((challengeScript != null && challengeScript.getProgram() != null) ? challengeScript.getProgram().length : 0);
        HEADER_SIZE_FULL = HEADER_SIZE_HASH + (new VarInt(proofLength)).getOriginalSizeInBytes() + 
            ((proofScript != null && proofScript.getProgram() != null) ? proofScript.getProgram().length : 0);
            
        hash = Sha256Hash.wrapReversed(Sha256Hash.hashTwice(payload, offset, HEADER_SIZE_HASH));
        headerBytesValid = serializer.isParseRetainMode();

        if (readIncomplete){
            transactionBytesValid = false;
            return;
        }

        // transactions
        parseTransactions(offset + HEADER_SIZE_FULL);
        length = cursor - offset;
    }

    public int getOptimalEncodingMessageSize() {
        if (optimalEncodingMessageSize != 0)
            return optimalEncodingMessageSize;
        optimalEncodingMessageSize = bitcoinSerialize().length;
        return optimalEncodingMessageSize;
    }

    // default for testing
    void writeHeader(OutputStream stream, boolean forHash) throws IOException {
        // try for cached write first
        if (headerBytesValid && payload != null) {
            int headerLength = HEADER_SIZE_FULL;
            if (forHash)
                headerLength = HEADER_SIZE_HASH;
            if (payload.length >= offset + headerLength) {
                stream.write(payload, offset, headerLength);
                return;
            }
        }
        // fall back to manual write
        Utils.uint32ToByteStreamLE(version, stream);
        stream.write(prevBlockHash.getReversedBytes());
        stream.write(getMerkleRoot().getReversedBytes());
        stream.write(contractHash);
        stream.write(attestationHash);
        stream.write(mappingHash);
        Utils.uint32ToByteStreamLE(time, stream);
        Utils.uint32ToByteStreamLE(blockHeight, stream);

        if (challengeLength > 0) {
            Script.writeBytes(stream, challengeScript.getProgram());
        } else
            stream.write(new VarInt(0).encode());

        if (forHash)
            return;

        if (proofLength > 0) {
            Script.writeBytes(stream, proofScript.getProgram());
        } else
            stream.write(new VarInt(0).encode());
    }

    private void writeTransactions(OutputStream stream) throws IOException {
        // check for no transaction conditions first
        // must be a more efficient way to do this but I'm tired atm.
        if (transactions == null) {
            return;
        }

        // confirmed we must have transactions either cached or as objects.
        if (transactionBytesValid && payload != null && payload.length >= offset + length) {
            stream.write(payload, offset + HEADER_SIZE_FULL, length - HEADER_SIZE_FULL);
            return;
        }

        if (transactions != null) {
            stream.write(new VarInt(transactions.size()).encode());
            for (Transaction tx : transactions) {
                tx.bitcoinSerialize(stream);
            }
        }
    }

    /**
     * Special handling to check if we have a valid byte array for both header
     * and transactions
     *
     * @throws IOException
     */
    @Override
    public byte[] bitcoinSerialize() {
        // we have completely cached byte array.
        if (headerBytesValid && transactionBytesValid) {
            Preconditions.checkNotNull(payload, "Bytes should never be null if headerBytesValid && transactionBytesValid");
            if (length == payload.length) {
                return payload;
            } else {
                // byte array is offset so copy out the correct range.
                byte[] buf = new byte[length];
                System.arraycopy(payload, offset, buf, 0, length);
                return buf;
            }
        }

        // At least one of the two cacheable components is invalid
        // so fall back to stream write since we can't be sure of the length.
        ByteArrayOutputStream stream = new UnsafeByteArrayOutputStream(length == UNKNOWN_LENGTH ? HEADER_SIZE_FULL + guessTransactionsLength() : length);
        try {
            writeHeader(stream, false);
            writeTransactions(stream);
        } catch (IOException e) {
            // Cannot happen, we are serializing to a memory stream.
        }
        return stream.toByteArray();
    }

    @Override
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        writeHeader(stream, false);
        // We may only have enough data to write the header.
        writeTransactions(stream);
    }

    /**
     * Provides a reasonable guess at the byte length of the transactions part of the block.
     * The returned value will be accurate in 99% of cases and in those cases where not will probably slightly
     * oversize.
     *
     * This is used to preallocate the underlying byte array for a ByteArrayOutputStream.  If the size is under the
     * real value the only penalty is resizing of the underlying byte array.
     */
    private int guessTransactionsLength() {
        if (transactionBytesValid)
            return payload.length - HEADER_SIZE_FULL;
        if (transactions == null)
            return 0;
        int len = VarInt.sizeOf(transactions.size());
        for (Transaction tx : transactions) {
            // 255 is just a guess at an average tx length
            len += tx.length == UNKNOWN_LENGTH ? 255 : tx.length;
        }
        return len;
    }

    @Override
    protected void unCache() {
        // Since we have alternate uncache methods to use internally this will only ever be called by a child
        // transaction so we only need to invalidate that part of the cache.
        unCacheTransactions();
    }

    private void unCacheHeader() {
        headerBytesValid = false;
        if (!transactionBytesValid)
            payload = null;
        hash = null;
    }

    private void unCacheTransactions() {
        transactionBytesValid = false;
        if (!headerBytesValid)
            payload = null;
        // Current implementation has to uncache headers as well as any change to a tx will alter the merkle root. In
        // future we can go more granular and cache merkle root separately so rest of the header does not need to be
        // rewritten.
        unCacheHeader();
        // Clear merkleRoot last as it may end up being parsed during unCacheHeader().
        merkleRoot = null;
    }

    /**
     * Calculates the block hash by serializing the block and hashing the
     * resulting bytes.
     */
    private Sha256Hash calculateHash() {
        try {
            ByteArrayOutputStream bos = new UnsafeByteArrayOutputStream(HEADER_SIZE_HASH);
            writeHeader(bos, true);
            return Sha256Hash.wrapReversed(Sha256Hash.hashTwice(bos.toByteArray()));
        } catch (IOException e) {
            throw new RuntimeException(e); // Cannot happen.
        }
    }

    /**
     * Returns the hash of the block (which for a valid, solved block should be below the target) in the form seen on
     * the block explorer. If you call this on block 1 in the mainnet chain
     * you will get "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048".
     */
    public String getHashAsString() {
        return getHash().toString();
    }

    /**
     * Returns the hash of the block (which for a valid, solved block should be
     * below the target). Big endian.
     */
    @Override
    public Sha256Hash getHash() {
        if (hash == null)
            hash = calculateHash();
        return hash;
    }

    /** Returns a copy of the block, but without any transactions. */
    public Block cloneAsHeader() {
        Block block = new Block(params, BLOCK_VERSION_GENESIS);
        copyBitcoinHeaderTo(block);
        return block;
    }

    /** Copy the block without transactions into the provided empty block. */
    protected final void copyBitcoinHeaderTo(final Block block) {
        block.prevBlockHash = prevBlockHash;
        block.merkleRoot = getMerkleRoot();
        block.contractHash = contractHash;
        block.attestationHash = attestationHash;
        block.mappingHash = mappingHash;
        block.version = version;
        block.time = time;
        block.blockHeight = blockHeight;
        block.challengeLength = challengeLength;
        block.challengeScript = challengeScript;
        block.proofLength = proofLength;
        block.proofScript = proofScript;
        block.transactions = null;
        block.hash = getHash();
    }

    /**
     * Returns a multi-line string containing a description of the contents of
     * the block. Use for debugging purposes only.
     */
    @Override
    public String toString() {
        StringBuilder s = new StringBuilder();
        s.append(" block: \n");
        s.append("   hash: ").append(getHashAsString()).append('\n');
        s.append("   version: ").append(version);
        String bips = Joiner.on(", ").skipNulls().join(isBIP34() ? "BIP34" : null, isBIP66() ? "BIP66" : null,
                isBIP65() ? "BIP65" : null);
        if (!bips.isEmpty())
            s.append(" (").append(bips).append(')');
        s.append('\n');
        s.append("   previous block: ").append(getPrevBlockHash()).append("\n");
        s.append("   contract hash: ").append(Utils.HEX.encode(contractHash)).append("\n");
        s.append("   attestation hash: ").append(Utils.HEX.encode(attestationHash)).append("\n");
        s.append("   mapping hash: ").append(Utils.HEX.encode(mappingHash)).append("\n");
        s.append("   time: ").append(time).append(" (").append(Utils.dateTimeFormat(time * 1000)).append(")\n");
        s.append("   block height: ").append(blockHeight).append("\n");
        if (transactions != null && transactions.size() > 0) {
            s.append("   merkle root: ").append(getMerkleRoot()).append("\n");
            s.append("   with ").append(transactions.size()).append(" transaction(s):\n");
            for (Transaction tx : transactions) {
                s.append(tx);
            }
        }
        return s.toString();
    }

    /** Returns true if the hash of the block is OK (lower than difficulty target). */
    protected boolean checkProofOfWork(boolean throwException) throws VerificationException {
        // TODO This function is obsolete in ocean!!!!
        
        /*BigInteger target = getDifficultyTargetAsInteger();

        BigInteger h = getHash().toBigInteger();
        if (h.compareTo(target) > 0) {
            // Proof of work check failed!
            if (throwException)
                throw new VerificationException("Hash is higher than target: " + getHashAsString() + " vs "
                        + target.toString(16));
            else
                return false;
        }*/
        return true;
    }

    private void checkTimestamp() throws VerificationException {
        final long allowedTime = Utils.currentTimeSeconds() + ALLOWED_TIME_DRIFT;
        if (time > allowedTime)
            throw new VerificationException(String.format(Locale.US,
                    "Block too far in future: %s (%d) vs allowed %s (%d)", Utils.dateTimeFormat(time * 1000), time,
                    Utils.dateTimeFormat(allowedTime * 1000), allowedTime));
    }

    private void checkSigOps() throws VerificationException {
        // Check there aren't too many signature verifications in the block. This is an anti-DoS measure, see the
        // comments for MAX_BLOCK_SIGOPS.
        int sigOps = 0;
        for (Transaction tx : transactions) {
            sigOps += tx.getSigOpCount();
        }
        if (sigOps > MAX_BLOCK_SIGOPS)
            throw new VerificationException("Block had too many Signature Operations");
    }

    private void checkMerkleRoot() throws VerificationException {
        Sha256Hash calculatedRoot = calculateMerkleRoot();
        if (!calculatedRoot.equals(merkleRoot)) {
            log.error("Merkle tree did not verify");
            throw new VerificationException("Merkle hashes do not match: " + calculatedRoot + " vs " + merkleRoot);
        }
    }

    private Sha256Hash calculateMerkleRoot() {
        List<byte[]> tree = buildMerkleTree();
        return Sha256Hash.wrap(tree.get(tree.size() - 1));
    }

    private List<byte[]> buildMerkleTree() {
        // The Merkle root is based on a tree of hashes calculated from the transactions:
        //
        //     root
        //      / \
        //   A      B
        //  / \    / \
        // t1 t2 t3 t4
        //
        // The tree is represented as a list: t1,t2,t3,t4,A,B,root where each
        // entry is a hash.
        //
        // The hashing algorithm is double SHA-256. The leaves are a hash of the serialized contents of the transaction.
        // The interior nodes are hashes of the concenation of the two child hashes.
        //
        // This structure allows the creation of proof that a transaction was included into a block without having to
        // provide the full block contents. Instead, you can provide only a Merkle branch. For example to prove tx2 was
        // in a block you can just provide tx2, the hash(tx1) and B. Now the other party has everything they need to
        // derive the root, which can be checked against the block header. These proofs aren't used right now but
        // will be helpful later when we want to download partial block contents.
        //
        // Note that if the number of transactions is not even the last tx is repeated to make it so (see
        // tx3 above). A tree with 5 transactions would look like this:
        //
        //         root
        //        /     \
        //       1        5
        //     /   \     / \
        //    2     3    4  4
        //  / \   / \   / \
        // t1 t2 t3 t4 t5 t5
        ArrayList<byte[]> tree = new ArrayList<>();
        // Start by adding all the hashes of the transactions as leaves of the tree.
        for (Transaction t : transactions) {
            tree.add(t.getHash().getBytes());
        }
        int levelOffset = 0; // Offset in the list where the currently processed level starts.
        // Step through each level, stopping when we reach the root (levelSize == 1).
        for (int levelSize = transactions.size(); levelSize > 1; levelSize = (levelSize + 1) / 2) {
            // For each pair of nodes on that level:
            for (int left = 0; left < levelSize; left += 2) {
                // The right hand node can be the same as the left hand, in the case where we don't have enough
                // transactions.
                int right = Math.min(left + 1, levelSize - 1);
                byte[] leftBytes = Utils.reverseBytes(tree.get(levelOffset + left));
                byte[] rightBytes = Utils.reverseBytes(tree.get(levelOffset + right));
                tree.add(Utils.reverseBytes(hashTwice(leftBytes, 0, 32, rightBytes, 0, 32)));
            }
            // Move to the next level.
            levelOffset += levelSize;
        }
        return tree;
    }

    /**
     * Verify the transactions on a block.
     *
     * @param height block height, if known, or -1 otherwise. If provided, used
     * to validate the coinbase input script of v2 and above blocks.
     * @throws VerificationException if there was an error verifying the block.
     */
    private void checkTransactions(final int height, final EnumSet<VerifyFlag> flags)
            throws VerificationException {
        // The first transaction in a block must always be a coinbase transaction.
        if (!transactions.get(0).isCoinBase())
            throw new VerificationException("First tx is not coinbase");
        if (flags.contains(Block.VerifyFlag.HEIGHT_IN_COINBASE) && height >= BLOCK_HEIGHT_GENESIS) {
            transactions.get(0).checkCoinBaseHeight(height);
        }
        // The rest must not be.
        for (int i = 1; i < transactions.size(); i++) {
            if (transactions.get(i).isCoinBase())
                throw new VerificationException("TX " + i + " is coinbase when it should not be.");
        }
    }

    /**
     * Checks the block data to ensure it follows the rules laid out in the network parameters. Specifically,
     * throws an exception if the proof of work is invalid, or if the timestamp is too far from what it should be.
     * This is <b>not</b> everything that is required for a block to be valid, only what is checkable independent
     * of the chain and without a transaction index.
     *
     * @throws VerificationException
     */
    public void verifyHeader() throws VerificationException {
        // Prove that this block is OK. It might seem that we can just ignore most of these checks given that the
        // network is also verifying the blocks, but we cannot as it'd open us to a variety of obscure attacks.
        //
        // Firstly we need to ensure this block does in fact represent real work done. If the difficulty is high
        // enough, it's probably been done by the network.
        checkProofOfWork(true);
        checkTimestamp();
    }

    /**
     * Checks the block contents
     *
     * @param height block height, if known, or -1 otherwise. If valid, used
     * to validate the coinbase input script of v2 and above blocks.
     * @param flags flags to indicate which tests should be applied (i.e.
     * whether to test for height in the coinbase transaction).
     * @throws VerificationException if there was an error verifying the block.
     */
    public void verifyTransactions(final int height, final EnumSet<VerifyFlag> flags) throws VerificationException {
        // Now we need to check that the body of the block actually matches the headers. The network won't generate
        // an invalid block, but if we didn't validate this then an untrusted man-in-the-middle could obtain the next
        // valid block from the network and simply replace the transactions in it with their own fictional
        // transactions that reference spent or non-existant inputs.
        if (transactions.isEmpty())
            throw new VerificationException("Block had no transactions");
        if (this.getOptimalEncodingMessageSize() > MAX_BLOCK_SIZE)
            throw new VerificationException("Block larger than MAX_BLOCK_SIZE");
        checkTransactions(height, flags);
        checkMerkleRoot();
        checkSigOps();
        for (Transaction transaction : transactions)
            transaction.verify();
        }

    /**
     * Verifies both the header and that the transactions hash to the merkle root.
     *
     * @param height block height, if known, or -1 otherwise.
     * @param flags flags to indicate which tests should be applied (i.e.
     * whether to test for height in the coinbase transaction).
     * @throws VerificationException if there was an error verifying the block.
     */
    public void verify(final int height, final EnumSet<VerifyFlag> flags) throws VerificationException {
        verifyHeader();
        verifyTransactions(height, flags);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        return getHash().equals(((Block)o).getHash());
    }

    @Override
    public int hashCode() {
        return getHash().hashCode();
    }

    /**
     * Returns the merkle root in big endian form, calculating it from transactions if necessary.
     */
    public Sha256Hash getMerkleRoot() {
        if (merkleRoot == null) {
            //TODO check if this is really necessary.
            unCacheHeader();
            merkleRoot = calculateMerkleRoot();
        }
        return merkleRoot;
    }

    /** Exists only for unit testing. */
    void setMerkleRoot(Sha256Hash value) {
        unCacheHeader();
        merkleRoot = value;
        hash = null;
    }

    /** Adds a transaction to this block. The nonce and merkle root are invalid after this. */
    public void addTransaction(Transaction t) {
        addTransaction(t, true);
    }

    /** Adds a transaction to this block, with or without checking the sanity of doing so */
    void addTransaction(Transaction t, boolean runSanityChecks) {
        unCacheTransactions();
        if (transactions == null) {
            transactions = new ArrayList<>();
        }
        t.setParent(this);
        if (runSanityChecks && transactions.size() == 0 && !t.isCoinBase())
            throw new RuntimeException("Attempted to add a non-coinbase transaction as the first transaction: " + t);
        else if (runSanityChecks && transactions.size() > 0 && t.isCoinBase())
            throw new RuntimeException("Attempted to add a coinbase transaction when there already is one: " + t);
        transactions.add(t);
        adjustLength(transactions.size(), t.length);
        // Force a recalculation next time the values are needed.
        merkleRoot = null;
        hash = null;
    }

    /** Returns the version of the block data structure as defined by the Bitcoin protocol. */
    public long getVersion() {
        return version;
    }

    /**
     * Returns the hash of the previous block in the chain, as defined by the block header.
     */
    public Sha256Hash getPrevBlockHash() {
        return prevBlockHash;
    }

    void setPrevBlockHash(Sha256Hash prevBlockHash) {
        unCacheHeader();
        this.prevBlockHash = prevBlockHash;
        this.hash = null;
    }

    /**
     * Returns the time at which the block was solved and broadcast, according to the clock of the solving node. This
     * is measured in seconds since the UNIX epoch (midnight Jan 1st 1970).
     */
    public long getTimeSeconds() {
        return time;
    }

    /**
     * Returns the time at which the block was solved and broadcast, according to the clock of the solving node.
     */
    public Date getTime() {
        return new Date(getTimeSeconds()*1000);
    }

    public void setTime(long time) {
        unCacheHeader();
        this.time = time;
        this.hash = null;
    }

    /** Returns an immutable list of transactions held in this block, or null if this object represents just a header. */
    @Nullable
    public List<Transaction> getTransactions() {
        return transactions == null ? null : ImmutableList.copyOf(transactions);
    }

    // ///////////////////////////////////////////////////////////////////////////////////////////////
    // Unit testing related methods.

    @VisibleForTesting
    boolean isHeaderBytesValid() {
        return headerBytesValid;
    }

    @VisibleForTesting
    boolean isTransactionBytesValid() {
        return transactionBytesValid;
    }

    /**
     * Return whether this block contains any transactions.
     *
     * @return  true if the block contains transactions, false otherwise (is
     * purely a header).
     */
    public boolean hasTransactions() {
        return !this.transactions.isEmpty();
    }

    /**
     * Returns whether this block conforms to
     * <a href="https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki">BIP34: Height in Coinbase</a>.
     */
    public boolean isBIP34() {
        return version >= BLOCK_VERSION_BIP34;
    }

    /**
     * Returns whether this block conforms to
     * <a href="https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki">BIP66: Strict DER signatures</a>.
     */
    public boolean isBIP66() {
        return version >= BLOCK_VERSION_BIP66;
    }

    /**
     * Returns whether this block conforms to
     * <a href="https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki">BIP65: OP_CHECKLOCKTIMEVERIFY</a>.
     */
    public boolean isBIP65() {
        return version >= BLOCK_VERSION_BIP65;
    }
}
