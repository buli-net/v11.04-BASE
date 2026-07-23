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
import wallet.util.TaprootSweeper;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

public abstract class SendCoinsOfflineTask {

    private final Wallet wallet;
    private final Handler backgroundHandler;
    private final Handler callbackHandler;

    private static final Logger log = LoggerFactory.getLogger(SendCoinsOfflineTask.class);

    public SendCoinsOfflineTask(final Wallet wallet, final Handler backgroundHandler) {
        this.wallet = wallet;
        this.backgroundHandler = backgroundHandler;
        this.callbackHandler = new Handler(Looper.myLooper());
    }

    public final void sendCoinsOffline(final SendRequest sendRequest) {
        backgroundHandler.post(new Runnable() {
            @Override
            public void run() {
                org.bitcoinj.core.Context.propagate(Constants.CONTEXT);

                try {
                    log.info("sending: {}", sendRequest);

                    List<UTXO> utxos = new ArrayList<>();
                    long total = 0;
                    boolean hasP2TR = false;

                    for (WalletTransaction wt : wallet.getWalletTransactions()) {
                        for (TransactionOutput out : wt.getTransaction().getOutputs()) {
                            if (out.getValue().isZero() || out.getValue().isNegative()) continue;
                            utxos.add(new UTXO(wt.getTransaction().getTxId(), out.getIndex(), out.getValue(), 0, false, out.getScriptPubKey()));
                            total += out.getValue().value;
                            if (TaprootSweeper.isP2TR(out.getScriptPubKey())) hasP2TR = true;
                        }
                    }

                    if (utxos.isEmpty() || total == 0) {
                        throw new CouldNotAdjustDownwards();
                    }

                    final Transaction transaction;
                    if (hasP2TR) {
                        transaction = sweepTaproot(sendRequest, utxos, total);
                    } else {
                        transaction = wallet.sendCoinsOffline(sendRequest);
                    }

                    log.info("send successful, transaction committed: {}", transaction.getTxId());
                    callbackHandler.post(new Runnable() {
                        @Override
                        public void run() {
                            onSuccess(transaction);
                        }
                    });

                } catch (final InsufficientMoneyException x) {
                    if (x.missing!= null)
                        log.info("send failed, {} missing", x.missing.toFriendlyString());
                    else
                        log.info("send failed, insufficient coins");
                    callbackHandler.post(new Runnable() {
                        @Override
                        public void run() {
                            onInsufficientMoney(x.missing);
                        }
                    });

                } catch (final ECKey.KeyIsEncryptedException x) {
                    log.info("send failed, key is encrypted: {}", x.getMessage());
                    callbackHandler.post(new Runnable() {
                        @Override
                        public void run() {
                            onFailure(x);
                        }
                    });

                } catch (final Wallet.BadWalletEncryptionKeyException x) {
                    log.info("send failed, bad spending password: {}", x.getMessage());
                    final boolean isEncrypted = wallet.isEncrypted();
                    callbackHandler.post(new Runnable() {
                        @Override
                        public void run() {
                            if (isEncrypted)
                                onInvalidEncryptionKey();
                            else
                                onFailure(x);
                        }
                    });

                } catch (final CouldNotAdjustDownwards x) {
                    log.info("send failed, empty paper wallet: {}", x.getMessage());
                    callbackHandler.post(new Runnable() {
                        @Override
                        public void run() {
                            onEmptyWalletFailed(x);
                        }
                    });

                } catch (final TransactionCompletionException x) {
                    log.info("send failed, cannot complete: {}", x.getMessage());
                    callbackHandler.post(new Runnable() {
                        @Override
                        public void run() {
                            onFailure(x);
                        }
                    });

                } catch (final Throwable x) {
                    log.info("send failed: {}", x.getMessage());
                    callbackHandler.post(new Runnable() {
                        @Override
                        public void run() {
                            onFailure(new Exception(x));
                        }
                    });
                }
            }
        });
    }

    private Transaction sweepTaproot(SendRequest req, List<UTXO> utxos, long total) throws Exception {
        if (utxos.isEmpty() || total == 0) throw new CouldNotAdjustDownwards();

        Transaction tx = new Transaction(Constants.NETWORK_PARAMETERS);
        for (UTXO u : utxos) {
            tx.addInput(u.getHash(), u.getIndex(), new Script(new byte[]{}));
        }

        if (req.tx.getOutputs().isEmpty()) throw new RuntimeException("No destination");
        Script dest = req.tx.getOutput(0).getScriptPubKey();

        long feePerKb = (req.feePerKb!= null)? req.feePerKb.value : Transaction.DEFAULT_TX_FEE.value;
        long fee = feePerKb * 150 / 1000;
        if (total <= fee) throw new CouldNotAdjustDownwards();

        long outVal = total - fee;
        if (outVal < 546) outVal = 546;

        tx.addOutput(Coin.valueOf(outVal), dest);

        for (int i = 0; i < utxos.size(); i++) {
            UTXO u = utxos.get(i);
            boolean signed = false;

            if (TaprootSweeper.isP2TR(u.getScript())) {
                for (ECKey k : wallet.getImportedKeys()) {
                    try {
                        if (k.getPrivKey() == null) continue;
                        TaprootSweeper.signTaprootInput(tx, i, utxos, k);
                        signed = true;
                        break;
                    } catch (Throwable ignore) {}
                }
            }

            if (!signed) {
                for (ECKey k : wallet.getImportedKeys()) {
                    try {
                        org.bitcoinj.crypto.TransactionSignature sig =
                                tx.calculateWitnessSignature(i, k, u.getScript(), u.getValue(), Transaction.SigHash.ALL, false);
                        setWitnessCompat(tx.getInput(i), TransactionWitness.of(sig.encodeToBitcoin(), k.getPubKey()));
                        signed = true;
                        break;
                    } catch (Throwable ignore) {}
                }
            }

            if (!signed) throw new RuntimeException("Cannot sign input " + i);
        }
        return tx;
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

    protected abstract void onSuccess(Transaction transaction);
    protected abstract void onInsufficientMoney(Coin missing);
    protected abstract void onInvalidEncryptionKey();
    protected void onEmptyWalletFailed(Exception exception) { onFailure(exception); }
    protected abstract void onFailure(Exception exception);
}
