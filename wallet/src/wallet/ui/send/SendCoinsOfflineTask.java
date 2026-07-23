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

                boolean hasP2TR = false;
                try {
                    for (WalletTransaction wt : wallet.getWalletTransactions()) {
                        for (TransactionOutput out : wt.getTransaction().getOutputs()) {
                            byte[] prog = out.getScriptPubKey().getProgram();
                            if (prog.length == 34 && prog[0] == 0x51) {
                                hasP2TR = true;
                                break;
                            }
                        }
                        if (hasP2TR) {
                            break;
                        }
                    }
                } catch (Throwable ignore) {
                }

                final Transaction transaction;
                if (hasP2TR) {
                    transaction = sweepTaproot(sendRequest);
                } else {
                    transaction = wallet.sendCoinsOffline(sendRequest);
                }

                log.info("send successful, transaction committed: {}", transaction.getTxId());
                callbackHandler.post(() -> onSuccess(transaction));

            } catch (final InsufficientMoneyException x) {
                if (x.missing!= null) {
                    log.info("send failed, {} missing", x.missing.toFriendlyString());
                } else {
                    log.info("send failed, insufficient coins");
                }
                callbackHandler.post(() -> onInsufficientMoney(x.missing));

            } catch (final ECKey.KeyIsEncryptedException x) {
                log.info("send failed, key is encrypted: {}", x.getMessage());
                callbackHandler.post(() -> onFailure(x));

            } catch (final Wallet.BadWalletEncryptionKeyException x) {
                log.info("send failed, bad spending password: {}", x.getMessage());
                final boolean isEncrypted = wallet.isEncrypted();
                callbackHandler.post(() -> {
                    if (isEncrypted) {
                        onInvalidEncryptionKey();
                    } else {
                        onFailure(x);
                    }
                });

            } catch (final CouldNotAdjustDownwards x) {
                log.info("send failed, could not adjust downwards: {}", x.getMessage());
                callbackHandler.post(() -> onEmptyWalletFailed(x));

            } catch (final TransactionCompletionException x) {
                log.info("send failed, cannot complete: {}", x.getMessage());
                callbackHandler.post(() -> onFailure(x));

            } catch (final Throwable x) {
                log.info("send failed: {}", x.getMessage());
                callbackHandler.post(() -> onFailure(new Exception(x)));
            }
        });
    }

    private Transaction sweepTaproot(SendRequest sendRequest) throws Exception {
        List<UTXO> utxos = new ArrayList<>();
        long total = 0;

        for (WalletTransaction wt : wallet.getWalletTransactions()) {
            for (TransactionOutput out : wt.getTransaction().getOutputs()) {
                if (out.getValue().isNegative() || out.getValue().isZero()) {
                    continue;
                }
                utxos.add(new UTXO(
                        wt.getTransaction().getTxId(),
                        out.getIndex(),
                        out.getValue(),
                        0,
                        false,
                        out.getScriptPubKey()
                ));
                total += out.getValue().value;
            }
        }

        if (utxos.isEmpty()) {
            throw new InsufficientMoneyException(Coin.valueOf(546));
        }

        Transaction tx = new Transaction(Constants.NETWORK_PARAMETERS);
        for (UTXO u : utxos) {
            tx.addInput(u.getHash(), u.getIndex(), new Script(new byte[]{}));
        }

        if (sendRequest.tx.getOutputs().isEmpty()) {
            throw new RuntimeException("No destination");
        }

        Script dest = sendRequest.tx.getOutput(0).getScriptPubKey();

        long fee = 1000;
        if (sendRequest.feePerKb!= null) {
            fee = sendRequest.feePerKb.value * 150 / 1000 + 10;
            if (fee < 150) {
                fee = 150;
            }
        }

        if (total <= fee) {
            throw new InsufficientMoneyException(Coin.valueOf(fee));
        }

        long outVal = total - fee;
        if (outVal < 546) {
            outVal = 546;
        }

        tx.addOutput(Coin.valueOf(outVal), dest);

        List<ECKey> keys = new ArrayList<>();
        try {
            keys.addAll(wallet.getImportedKeys());
        } catch (Throwable ignore) {
        }

        for (int i = 0; i < utxos.size(); i++) {
            UTXO u = utxos.get(i);
            byte[] prog = u.getScript().getProgram();
            boolean signed = false;

            if (prog.length == 34 && prog[0] == 0x51) {
                for (ECKey k : keys) {
                    try {
                        if (k.getPrivKey() == null) continue;
                        ECKey tweaked = deriveTweaked(k);
                        byte[] sighash = calcSighash(tx, i, utxos);
                        byte[] sig = signSchnorr(tweaked, sighash);
                        setWitness(tx.getInput(i), TransactionWitness.of(sig));
                        signed = true;
                        break;
                    } catch (Throwable ignore) {
                    }
                }
            }

            if (!signed) {
                for (ECKey k : keys) {
                    try {
                        org.bitcoinj.crypto.TransactionSignature sig =
                                tx.calculateWitnessSignature(i, k, u.getScript(), u.getValue(), Transaction.SigHash.ALL, false);
                        setWitness(tx.getInput(i), TransactionWitness.of(sig.encodeToBitcoin(), k.getPubKey()));
                        signed = true;
                        break;
                    } catch (Throwable ignore) {
                    }
                }
            }

            if (!signed) {
                for (ECKey k : keys) {
                    try {
                        org.bitcoinj.crypto.TransactionSignature sig =
                                tx.calculateSignature(i, k, u.getScript(), Transaction.SigHash.ALL, false);
                        Script s = org.bitcoinj.script.ScriptBuilder.createInputScript(sig, k);
                        setScriptSig(tx.getInput(i), s);
                        signed = true;
                        break;
                    } catch (Throwable ignore) {
                    }
                }
            }

            if (!signed) {
                throw new RuntimeException("Cannot sign " + i);
            }
        }

        return tx;
    }

    private void setScriptSig(TransactionInput in, Script s) throws Exception {
        try {
            Method m = TransactionInput.class.getMethod("setScriptSig", Script.class);
            m.invoke(in, s);
            return;
        } catch (Throwable e) {
        }

        try {
            Method m = TransactionInput.class.getDeclaredMethod("setScriptSig", Script.class);
            m.setAccessible(true);
            m.invoke(in, s);
            return;
        } catch (Throwable e) {
        }

        Field f = TransactionInput.class.getDeclaredField("scriptBytes");
        f.setAccessible(true);
        f.set(in, s.getProgram());
    }

    private void setWitness(TransactionInput in, TransactionWitness w) throws Exception {
        try {
            Method m = TransactionInput.class.getMethod("setWitness", TransactionWitness.class);
            m.invoke(in, w);
            return;
        } catch (Throwable e) {
        }

        try {
            Method m = TransactionInput.class.getDeclaredMethod("setWitness", TransactionWitness.class);
            m.setAccessible(true);
            m.invoke(in, w);
            return;
        } catch (Throwable e) {
        }

        try {
            Field f = TransactionInput.class.getDeclaredField("witness");
            f.setAccessible(true);
            f.set(in, w);
            return;
        } catch (Throwable e) {
        }

        Method m2 = Transaction.class.getMethod("setWitness", int.class, TransactionWitness.class);
        m2.invoke(in.getParentTransaction(), in.getIndex(), w);
    }

    private ECKey deriveTweaked(ECKey k) throws Exception {
        byte[] comp = k.getPubKey();
        boolean odd = (comp[0] & 1) == 1;

        org.bouncycastle.jce.spec.ECNamedCurveParameterSpec spec =
                org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256k1");

        BigInteger n = spec.getN();
        BigInteger d = k.getPrivKey();

        if (odd) {
            d = n.subtract(d);
        }

        byte[] xOnly = new byte[32];
        System.arraycopy(comp, 1, xOnly, 0, 32);

        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] tag = sha.digest("TapTweak".getBytes(java.nio.charset.StandardCharsets.UTF_8));

        sha.reset();
        sha.update(tag);
        sha.update(xOnly);

        BigInteger tweak = new BigInteger(1, sha.digest());
        return ECKey.fromPrivate(d.add(tweak).mod(n), true);
    }

    private byte[] calcSighash(Transaction tx, int idx, List<UTXO> utxos) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        for (UTXO u : utxos) {
            bos.write(u.getHash().getReversedBytes());
            writeU32(bos, u.getIndex());
        }
        byte[] hp = sha(sha(bos.toByteArray()));
        bos.reset();

        for (UTXO u : utxos) {
            writeU64(bos, u.getValue().value);
        }
        byte[] ha = sha(sha(bos.toByteArray()));
        bos.reset();

        for (UTXO u : utxos) {
            byte[] spk = u.getScript().getProgram();
            writeCompact(bos, spk.length);
            bos.write(spk);
        }
        byte[] hs = sha(sha(bos.toByteArray()));
        bos.reset();

        for (int i = 0; i < utxos.size(); i++) {
            writeU32(bos, TransactionInput.NO_SEQUENCE - 2);
        }
        byte[] hseq = sha(sha(bos.toByteArray()));
        bos.reset();

        for (TransactionOutput out : tx.getOutputs()) {
            writeU64(bos, out.getValue().value);
            byte[] spk = out.getScriptPubKey().getProgram();
            writeCompact(bos, spk.length);
            bos.write(spk);
        }
        byte[] hout = sha(sha(bos.toByteArray()));

        ByteArrayOutputStream ss = new ByteArrayOutputStream();
        ss.write(0x00);
        ss.write(0x00);
        writeU32(ss, tx.getVersion());
        writeU32(ss, tx.getLockTime());
        ss.write(hp);
        ss.write(ha);
        ss.write(hs);
        ss.write(hseq);
        ss.write(hout);
        ss.write(0x00);
        writeU32(ss, idx);

        return tagged("TapSighash", ss.toByteArray());
    }

    private byte[] signSchnorr(ECKey priv, byte[] m32) throws Exception {
        org.bouncycastle.jce.spec.ECNamedCurveParameterSpec spec =
                org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256k1");

        BigInteger n = spec.getN();
        BigInteger d = priv.getPrivKey();

        if ((spec.getG().multiply(d).normalize().getEncoded(true)[0] & 1) == 1) {
            d = n.subtract(d);
        }

        BigInteger k = null;
        org.bouncycastle.math.ec.ECPoint R = null;

        do {
            byte[] rnd = new byte[32];
            secureRandom.nextBytes(rnd);
            k = new BigInteger(1, rnd).mod(n);
            if (k.signum() == 0) continue;
            R = spec.getG().multiply(k).normalize();
            if ((R.getEncoded(true)[0] & 1) == 1) {
                k = n.subtract(k);
            }
        } while (k == null || k.signum() == 0 || R == null);

        byte[] rX = new byte[32];
        System.arraycopy(R.getEncoded(true), 1, rX, 0, 32);

        byte[] pX = new byte[32];
        System.arraycopy(spec.getG().multiply(d).normalize().getEncoded(true), 1, pX, 0, 32);

        ByteArrayOutputStream eb = new ByteArrayOutputStream();
        eb.write(rX);
        eb.write(pX);
        eb.write(m32);

        BigInteger e = new BigInteger(1, tagged("BIP0340/challenge", eb.toByteArray())).mod(n);
        BigInteger s = k.add(e.multiply(d)).mod(n);

        ByteArrayOutputStream sig = new ByteArrayOutputStream();
        sig.write(rX);

        byte[] sb = s.toByteArray();
        byte[] s32 = new byte[32];
        if (sb.length > 32) {
            System.arraycopy(sb, sb.length - 32, s32, 0, 32);
        } else {
            System.arraycopy(sb, 0, s32, 32 - sb.length, sb.length);
        }

        sig.write(s32);
        return sig.toByteArray();
    }

    private byte[] tagged(String t, byte[] m) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] th = sha.digest(t.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        sha.reset();
        sha.update(th);
        sha.update(m);
        return sha.digest();
    }

    private byte[] sha(byte[] b) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(b);
    }

    private void writeU32(ByteArrayOutputStream os, long v) {
        os.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt((int) v).array(), 0, 4);
    }

    private void writeU64(ByteArrayOutputStream os, long v) {
        os.write(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(v).array(), 0, 8);
    }

    private void writeCompact(ByteArrayOutputStream os, long v) {
        if (v < 253) {
            os.write((int) v);
        } else if (v < 0x10000) {
            os.write(253);
            writeU32(os, v);
        } else {
            os.write(254);
            writeU64(os, v);
        }
    }

    protected abstract void onSuccess(Transaction transaction);
    protected abstract void onInsufficientMoney(Coin missing);
    protected abstract void onInvalidEncryptionKey();

    protected void onEmptyWalletFailed(Exception exception) {
        onFailure(exception);
    }

    protected abstract void onFailure(Exception exception);
}
