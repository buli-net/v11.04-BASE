/*
 * Taproot key-path signer for P2TR (bc1p) paper wallets.
 * bitcoinj 0.17.1 can parse and send to P2TR but cannot spend from P2TR yet,
 * so we implement BIP340 / BIP341 manually here.
 */

package wallet.util;

import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.core.TransactionWitness;
import org.bitcoinj.core.UTXO;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.script.Script;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.List;

public final class TaprootSweeper {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private TaprootSweeper() {
    }

    public static boolean isP2TR(Script scriptPubKey) {
        byte[] program = scriptPubKey.getProgram();
        return program.length == 34 && program[0] == 0x51;
    }

    public static void signTaprootInput(Transaction tx, int inputIndex, List<UTXO> utxos, ECKey key) throws Exception {
        ECKey tweakedKey = tweakPrivateKey(key);
        byte[] sighash = calculateTaprootSighash(tx, inputIndex, utxos);
        byte[] signature = signSchnorr(tweakedKey, sighash);
        setWitnessCompat(tx.getInput(inputIndex), TransactionWitness.of(signature));
    }

    private static ECKey tweakPrivateKey(ECKey key) throws Exception {
        byte[] compressed = key.getPubKey();
        boolean isOdd = (compressed[0] & 1) == 1;

        org.bouncycastle.jce.spec.ECNamedCurveParameterSpec spec =
                org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256k1");
        BigInteger n = spec.getN();
        BigInteger privateKey = key.getPrivKey();

        if (isOdd) {
            privateKey = n.subtract(privateKey);
        }

        byte[] xOnly = new byte[32];
        System.arraycopy(compressed, 1, xOnly, 0, 32);

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] tag = sha256.digest("TapTweak".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        sha256.reset();
        sha256.update(tag);
        sha256.update(xOnly);
        BigInteger tweak = new BigInteger(1, sha256.digest());

        return ECKey.fromPrivate(privateKey.add(tweak).mod(n), true);
    }

    private static byte[] calculateTaprootSighash(Transaction tx, int inputIndex, List<UTXO> utxos) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        for (UTXO u : utxos) {
            bos.write(u.getHash().getReversedBytes());
            writeUInt32LE(bos, u.getIndex());
        }
        byte[] hashPrevouts = sha256Double(bos.toByteArray());
        bos.reset();

        for (UTXO u : utxos) {
            writeUInt64LE(bos, u.getValue().value);
        }
        byte[] hashAmounts = sha256Double(bos.toByteArray());
        bos.reset();

        for (UTXO u : utxos) {
            byte[] spk = u.getScript().getProgram();
            writeCompactSize(bos, spk.length);
            bos.write(spk);
        }
        byte[] hashScriptPubKeys = sha256Double(bos.toByteArray());
        bos.reset();

        for (int i = 0; i < utxos.size(); i++) {
            writeUInt32LE(bos, TransactionInput.NO_SEQUENCE - 2);
        }
        byte[] hashSequences = sha256Double(bos.toByteArray());
        bos.reset();

        for (TransactionOutput out : tx.getOutputs()) {
            writeUInt64LE(bos, out.getValue().value);
            byte[] spk = out.getScriptPubKey().getProgram();
            writeCompactSize(bos, spk.length);
            bos.write(spk);
        }
        byte[] hashOutputs = sha256Double(bos.toByteArray());

        ByteArrayOutputStream ss = new ByteArrayOutputStream();
        ss.write(0x00);
        ss.write(0x00);
        writeUInt32LE(ss, tx.getVersion());
        writeUInt32LE(ss, tx.getLockTime());
        ss.write(hashPrevouts);
        ss.write(hashAmounts);
        ss.write(hashScriptPubKeys);
        ss.write(hashSequences);
        ss.write(hashOutputs);
        ss.write(0x00);
        writeUInt32LE(ss, inputIndex);

        return taggedHash("TapSighash", ss.toByteArray());
    }

    private static byte[] signSchnorr(ECKey privateKey, byte[] message32) throws Exception {
        org.bouncycastle.jce.spec.ECNamedCurveParameterSpec spec =
                org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256k1");
        BigInteger n = spec.getN();
        BigInteger d = privateKey.getPrivKey();

        if ((spec.getG().multiply(d).normalize().getEncoded(true)[0] & 1) == 1) {
            d = n.subtract(d);
        }

        BigInteger k = null;
        org.bouncycastle.math.ec.ECPoint R = null;

        while (R == null) {
            byte[] randomBytes = new byte[32];
            SECURE_RANDOM.nextBytes(randomBytes);
            k = new BigInteger(1, randomBytes).mod(n);
            if (k.signum() == 0) continue;
            R = spec.getG().multiply(k).normalize();
            if ((R.getEncoded(true)[0] & 1) == 1) {
                k = n.subtract(k);
            }
            if (k.signum() == 0) {
                R = null;
            }
        }

        byte[] rX = new byte[32];
        System.arraycopy(R.getEncoded(true), 1, rX, 0, 32);

        byte[] pX = new byte[32];
        System.arraycopy(spec.getG().multiply(d).normalize().getEncoded(true), 1, pX, 0, 32);

        ByteArrayOutputStream eb = new ByteArrayOutputStream();
        eb.write(rX);
        eb.write(pX);
        eb.write(message32);

        BigInteger e = new BigInteger(1, taggedHash("BIP0340/challenge", eb.toByteArray())).mod(n);
        BigInteger s = k.add(e.multiply(d)).mod(n);

        ByteArrayOutputStream sig = new ByteArrayOutputStream();
        sig.write(rX);

        byte[] sBytes = s.toByteArray();
        byte[] s32 = new byte[32];
        if (sBytes.length > 32) {
            System.arraycopy(sBytes, sBytes.length - 32, s32, 0, 32);
        } else {
            System.arraycopy(sBytes, 0, s32, 32 - sBytes.length, sBytes.length);
        }
        sig.write(s32);

        return sig.toByteArray();
    }

    private static void setWitnessCompat(TransactionInput input, TransactionWitness witness) throws Exception {
        try {
            Method m = TransactionInput.class.getMethod("setWitness", TransactionWitness.class);
            m.invoke(input, witness);
            return;
        } catch (Throwable ignore) {}
        try {
            Method m = TransactionInput.class.getDeclaredMethod("setWitness", TransactionWitness.class);
            m.setAccessible(true);
            m.invoke(input, witness);
            return;
        } catch (Throwable ignore) {}
        try {
            Field f = TransactionInput.class.getDeclaredField("witness");
            f.setAccessible(true);
            f.set(input, witness);
            return;
        } catch (Throwable ignore) {}
        Method m = Transaction.class.getMethod("setWitness", int.class, TransactionWitness.class);
        m.invoke(input.getParentTransaction(), input.getIndex(), witness);
    }

    private static byte[] taggedHash(String tag, byte[] message) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] tagHash = sha256.digest(tag.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        sha256.reset();
        sha256.update(tagHash);
        sha256.update(message);
        return sha256.digest();
    }

    private static byte[] sha256Double(byte[] data) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        return sha256.digest(sha256.digest(data));
    }

    private static void writeUInt32LE(ByteArrayOutputStream os, long value) {
        os.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt((int) value).array(), 0, 4);
    }

    private static void writeUInt64LE(ByteArrayOutputStream os, long value) {
        os.write(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(value).array(), 0, 8);
    }

    private static void writeCompactSize(ByteArrayOutputStream os, long value) {
        if (value < 253) {
            os.write((int) value);
        } else if (value < 0x10000) {
            os.write(253);
            writeUInt32LE(os, value);
        } else {
            os.write(254);
            writeUInt64LE(os, value);
        }
    }
}
