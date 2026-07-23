/*
 * Copyright the original author or authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

package wallet.ui.send;

import android.os.Handler;
import android.os.Looper;

import org.bitcoinj.base.Coin;
import org.bitcoinj.core.InsufficientMoneyException;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.core.TransactionWitness;
import org.bitcoinj.core.UTXO;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.script.Script;
import org.bitcoinj.wallet.SendRequest;
import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.wallet.Wallet.CouldNotAdjustDownwards;
import org.bitcoinj.wallet.Wallet.TransactionCompletionException;
import org.bitcoinj.wallet.WalletTransaction;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import wallet.Constants;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public abstract class SendCoinsOfflineTask {

    private final Wallet wallet;
    private final Handler backgroundHandler;
    private final Handler callbackHandler;
    private static final Logger log = LoggerFactory.getLogger(SendCoinsOfflineTask.class);
    private static final SecureRandom secureRandom = new SecureRandom();

    public SendCoinsOfflineTask(final Wallet wallet, final Handler backgroundHandler) {
        this.wallet = wallet;
        this.backgroundHandler = backgroundHandler;
        this.callbackHandler = new Handler(Looper.myLooper());
    }

    public final void sendCoinsOffline(final SendRequest sendRequest) {
        backgroundHandler.post(() -> {
            org.bitcoinj.core.Context.propagate(Constants.CONTEXT);
            try {
                log.info("sending: {}", sendRequest);

                Transaction tmp;
                try {
                    tmp = wallet.sendCoinsOffline(sendRequest);
                } catch (Throwable e) {
                    log.warn("native sweep failed, try taproot manual: {}", e.toString());
                    tmp = sweepWithTaproot(sendRequest);
                }

                final Transaction transaction = tmp;
                log.info("send successful: {}", transaction.getTxId());

                callbackHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            onSuccess(transaction);
                        } catch (Throwable t) {
                            log.error("onSuccess crashed", t);
                            onFailure(new Exception(t));
                        }
                    }
                });

            } catch (final InsufficientMoneyException x) {
                callbackHandler.post(() -> onInsufficientMoney(x.missing));
            } catch (final ECKey.KeyIsEncryptedException x) {
                callbackHandler.post(() -> onFailure(x));
            } catch (final Wallet.BadWalletEncryptionKeyException x) {
                final boolean isEncrypted = wallet.isEncrypted();
                callbackHandler.post(() -> {
                    if (isEncrypted) onInvalidEncryptionKey();
                    else onFailure(x);
                });
            } catch (final CouldNotAdjustDownwards x) {
                callbackHandler.post(() -> onEmptyWalletFailed(x));
            } catch (final TransactionCompletionException x) {
                callbackHandler.post(() -> onFailure(x));
            } catch (final Throwable x) {
                log.error("sweep throwable", x);
                final Exception ex = new Exception(x);
                callbackHandler.post(() -> onFailure(ex));
            }
        });
    }

    private Transaction sweepWithTaproot(SendRequest sendRequest) throws Exception {
        List<UTXO> utxos = new ArrayList<>();
        long total = 0;
        for (WalletTransaction wt : wallet.getWalletTransactions()) {
            for (TransactionOutput out : wt.getTransaction().getOutputs()) {
                if (out.getValue().isNegative() || out.getValue().isZero()) continue;
                utxos.add(new UTXO(wt.getTransaction().getTxId(), out.getIndex(), out.getValue(), 0, false, out.getScriptPubKey()));
                total += out.getValue().value;
            }
        }
        if (utxos.isEmpty()) throw new InsufficientMoneyException(Coin.valueOf(546));

        Transaction tx = new Transaction(Constants.NETWORK_PARAMETERS);
        for (UTXO u : utxos) tx.addInput(u.getHash(), u.getIndex(), new Script(new byte[]{}));

        if (sendRequest.tx.getOutputs().isEmpty()) throw new RuntimeException("No dest");
        Script dest = sendRequest.tx.getOutput(0).getScriptPubKey();

        long fee = 1000;
        if (sendRequest.feePerKb!= null) fee = 200 * sendRequest.feePerKb.value / 1000 + 500;
        if (total <= fee) throw new InsufficientMoneyException(Coin.valueOf(fee));
        long outVal = total - fee;
        if (outVal < 546) outVal = 546;
        tx.addOutput(Coin.valueOf(outVal), dest);

        List<ECKey> allKeys = new ArrayList<>();
        try { allKeys.addAll(wallet.getImportedKeys()); } catch (Throwable ignore) {}
        try { if (wallet.getActiveKeyChain()!= null) allKeys.addAll(wallet.getActiveKeyChain().getLeafKeys()); } catch (Throwable ignore) {}

        if (allKeys.isEmpty()) throw new RuntimeException("No private keys");

        for (int i = 0; i < utxos.size(); i++) {
            UTXO u = utxos.get(i);
            byte[] prog = u.getScript().getProgram();
            boolean signed = false;

            if (prog.length == 34 && prog[0] == 0x51) {
                for (ECKey k : allKeys) {
                    try {
                        if (k.getPrivKey() == null) continue;
                        ECKey tweaked = findTweakedKey(prog, k);
                        byte[] sighash = calcTapSighashBIP341(tx, i, utxos);
                        byte[] sig = signSchnorrBIP340(tweaked, sighash);
                        setWitnessReflection(tx.getInput(i), TransactionWitness.of(sig));
                        signed = true;
                        break;
                    } catch (Throwable ignore) {}
                }
            }

            if (!signed) {
                for (ECKey k : allKeys) {
                    try {
                        if (k.getPrivKey() == null) continue;
                        org.bitcoinj.crypto.TransactionSignature sig = tx.calculateWitnessSignature(i, k, u.getScript(), u.getValue(), Transaction.SigHash.ALL, false);
                        setWitnessReflection(tx.getInput(i), TransactionWitness.of(sig.encodeToBitcoin(), k.getPubKey()));
                        signed = true;
                        break;
                    } catch (Throwable ignore) {}
                }
            }

            if (!signed) {
                for (ECKey k : allKeys) {
                    try {
                        if (k.getPrivKey() == null) continue;
                        org.bitcoinj.crypto.TransactionSignature sig = tx.calculateSignature(i, k, u.getScript(), Transaction.SigHash.ALL, false);
                        Script scriptSig = org.bitcoinj.script.ScriptBuilder.createInputScript(sig, k);
                        setScriptSigReflection(tx.getInput(i), scriptSig);
                        signed = true;
                        break;
                    } catch (Throwable ignore) {}
                }
            }

            if (!signed) throw new RuntimeException("Cannot sign input " + i);
        }
        return tx;
    }

    private ECKey findTweakedKey(byte[] prog, ECKey anyKey) throws Exception {
        byte[] xOnly = new byte[32];
        System.arraycopy(prog, 2, xOnly, 0, 32);
        for (ECKey k : wallet.getImportedKeys()) {
            try {
                if (k.getPubKey() == null) continue;
                byte[] x = new byte[32];
                System.arraycopy(k.getPubKey(), 1, x, 0, 32);
                if (java.util.Arrays.equals(x, xOnly)) return k;
            } catch (Throwable ignore) {}
        }
        return deriveTweakedKey(anyKey);
    }

    private void setScriptSigReflection(TransactionInput input, Script scriptSig) {
        try {
            try { Method m = TransactionInput.class.getMethod("setScriptSig", Script.class); m.invoke(input, scriptSig); return; } catch (Throwable e) {}
            try { Method m = TransactionInput.class.getDeclaredMethod("setScriptSig", Script.class); m.setAccessible(true); m.invoke(input, scriptSig); return; } catch (Throwable e) {}
            try { Field f = TransactionInput.class.getDeclaredField("scriptBytes"); f.setAccessible(true); f.set(input, scriptSig.getProgram()); return; } catch (Throwable e) {}
            Field f = TransactionInput.class.getDeclaredField("scriptSig"); f.setAccessible(true); f.set(input, scriptSig);
        } catch (Throwable e) { throw new RuntimeException(e); }
    }

    private void setWitnessReflection(TransactionInput input, TransactionWitness witness) {
        try {
            try { Method m = TransactionInput.class.getMethod("setWitness", TransactionWitness.class); m.invoke(input, witness); return; } catch (Throwable e) {}
            try { Method m = TransactionInput.class.getDeclaredMethod("setWitness", TransactionWitness.class); m.setAccessible(true); m.invoke(input, witness); return; } catch (Throwable e) {}
            try { Field f = TransactionInput.class.getDeclaredField("witness"); f.setAccessible(true); f.set(input, witness); return; } catch (Throwable e) {}
            try { Method m2 = Transaction.class.getMethod("setWitness", int.class, TransactionWitness.class); m2.invoke(input.getParentTransaction(), input.getIndex(), witness); return; } catch (Throwable e) {}
            Field f = TransactionInput.class.getDeclaredField("witness"); f.setAccessible(true); f.set(input, witness);
        } catch (Throwable e) { throw new RuntimeException(e); }
    }

    private ECKey deriveTweakedKey(ECKey internalKey) throws Exception {
        if (internalKey.getPrivKey() == null) throw new RuntimeException("No priv");
        byte[] comp = internalKey.getPubKey();
        boolean odd = (comp[0] & 1) == 1;
        org.bouncycastle.jce.spec.ECNamedCurveParameterSpec spec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256k1");
        BigInteger n = spec.getN();
        BigInteger priv = internalKey.getPrivKey();
        if (odd) priv = n.subtract(priv);
        byte[] xOnly = new byte[32];
        System.arraycopy(comp, 1, xOnly, 0, 32);
        byte[] tweakBytes = taggedHash("TapTweak", xOnly);
        BigInteger tweak = new BigInteger(1, tweakBytes);
        return ECKey.fromPrivate(priv.add(tweak).mod(n), true);
    }

    private byte[] calcTapSighashBIP341(Transaction tx, int inputIndex, List<UTXO> utxos) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        for (UTXO u : utxos) { bos.write(u.getHash().getReversedBytes()); writeU32(bos, u.getIndex()); }
        byte[] hashPrevouts = sha256(sha256(bos.toByteArray())); bos.reset();
        for (UTXO u : utxos) writeU64(bos, u.getValue().value);
        byte[] hashAmounts = sha256(sha256(bos.toByteArray())); bos.reset();
        for (UTXO u : utxos) { byte[] spk = u.getScript().getProgram(); writeCompact(bos, spk.length); bos.write(spk); }
        byte[] hashSPKs = sha256(sha256(bos.toByteArray())); bos.reset();
        for (int i = 0; i < utxos.size(); i++) writeU32(bos, TransactionInput.NO_SEQUENCE - 2);
        byte[] hashSeqs = sha256(sha256(bos.toByteArray())); bos.reset();
        for (TransactionOutput out : tx.getOutputs()) { writeU64(bos, out.getValue().value); byte[] spk = out.getScriptPubKey().getProgram(); writeCompact(bos, spk.length); bos.write(spk); }
        byte[] hashOutputs = sha256(sha256(bos.toByteArray()));

        ByteArrayOutputStream ss = new ByteArrayOutputStream();
        ss.write(0x00);
        ss.write(0x00);
        writeU32(ss, tx.getVersion());
        writeU32(ss, tx.getLockTime());
        ss.write(hashPrevouts);
        ss.write(hashAmounts);
        ss.write(hashSPKs);
        ss.write(hashSeqs);
        ss.write(hashOutputs);
        ss.write(0x00);
        writeU32(ss, inputIndex);
        return taggedHash("TapSighash", ss.toByteArray());
    }

    private byte[] signSchnorrBIP340(ECKey priv, byte[] msg32) throws Exception {
        if (priv.getPrivKey() == null) throw new RuntimeException("No priv");
        org.bouncycastle.jce.spec.ECNamedCurveParameterSpec spec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256k1");
        BigInteger n = spec.getN();
        BigInteger d = priv.getPrivKey();
        if ((spec.getG().multiply(d).normalize().getEncoded(true)[0] & 1) == 1) d = n.subtract(d);
        BigInteger k = null;
        org.bouncycastle.math.ec.ECPoint R = null;
        do {
            byte[] rnd = new byte[32]; secureRandom.nextBytes(rnd);
            k = new BigInteger(1, rnd).mod(n);
            if (k.signum() == 0) continue;
            R = spec.getG().multiply(k).normalize();
            if ((R.getEncoded(true)[0] & 1) == 1) k = n.subtract(k);
        } while (k == null || k.signum() == 0 || R == null);
        byte[] rX = new byte[32]; System.arraycopy(R.getEncoded(true), 1, rX, 0, 32);
        byte[] pX = new byte[32]; System.arraycopy(spec.getG().multiply(d).normalize().getEncoded(true), 1, pX, 0, 32);
        ByteArrayOutputStream eb = new ByteArrayOutputStream(); eb.write(rX); eb.write(pX); eb.write(msg32);
        BigInteger e = new BigInteger(1, taggedHash("BIP0340/challenge", eb.toByteArray())).mod(n);
        BigInteger s = k.add(e.multiply(d)).mod(n);
        ByteArrayOutputStream sig = new ByteArrayOutputStream(); sig.write(rX);
        byte[] sB = s.toByteArray(); byte[] s32 = new byte[32];
        if (sB.length > 32) System.arraycopy(sB, sB.length - 32, s32, 0, 32);
        else System.arraycopy(sB, 0, s32, 32 - sB.length, sB.length);
        sig.write(s32);
        return sig.toByteArray();
    }

    private byte[] taggedHash(String tag, byte[] msg) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] th = sha.digest(tag.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        sha.reset(); sha.update(th); sha.update(msg); return sha.digest();
    }
    private byte[] sha256(byte[] b) throws Exception { return MessageDigest.getInstance("SHA-256").digest(b); }
    private void writeU32(ByteArrayOutputStream os, long v) { os.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt((int) v).array(), 0, 4); }
    private void writeU64(ByteArrayOutputStream os, long v) { os.write(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(v).array(), 0, 8); }
    private void writeCompact(ByteArrayOutputStream os, long v) { if (v < 253) os.write((int) v); else if (v < 0x10000) { os.write(253); writeU32(os, v); } else { os.write(254); writeU64(os, v); } }

    protected abstract void onSuccess(Transaction transaction);
    protected abstract void onInsufficientMoney(Coin missing);
    protected abstract void onInvalidEncryptionKey();
    protected void onEmptyWalletFailed(Exception exception) { onFailure(exception); }
    protected abstract void onFailure(Exception exception);
}
