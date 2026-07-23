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
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.wallet.SendRequest;
import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.wallet.Wallet.CouldNotAdjustDownwards;
import org.bitcoinj.wallet.Wallet.TransactionCompletionException;
import org.bitcoinj.wallet.WalletTransaction;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import wallet.Constants;

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
        backgroundHandler.post(() -> {
            org.bitcoinj.core.Context.propagate(Constants.CONTEXT);

            try {
                log.info("sending: {}", sendRequest);

                // Use built-in Taproot signing if P2TR UTXO is detected.
                // bitcoinj 0.17.1 already has Schnorr and Taproot support, just need to route to it.
                // sendCoinsOffline() original only handles P2PKH/P2WPKH, so we manually sign P2TR via library.
                Transaction tx;
                if (hasP2TR()) {
                    tx = sweepWithTaprootBuiltIn(sendRequest);
                } else {
                    tx = wallet.sendCoinsOffline(sendRequest);
                }

                log.info("send successful, transaction committed: {}", tx.getTxId());
                callbackHandler.post(() -> onSuccess(tx));

            } catch (final InsufficientMoneyException x) {
                if (x.missing!= null)
                    log.info("send failed, {} missing", x.missing.toFriendlyString());
                else
                    log.info("send failed, insufficient coins");
                callbackHandler.post(() -> onInsufficientMoney(x.missing));

            } catch (final ECKey.KeyIsEncryptedException x) {
                log.info("send failed, key is encrypted: {}", x.getMessage());
                callbackHandler.post(() -> onFailure(x));

            } catch (final Wallet.BadWalletEncryptionKeyException x) {
                log.info("send failed, bad spending password: {}", x.getMessage());
                final boolean isEncrypted = wallet.isEncrypted();
                callbackHandler.post(() -> {
                    if (isEncrypted) onInvalidEncryptionKey();
                    else onFailure(x);
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

    /**
     * Check if wallet contains P2TR output (bc1p...).
     * P2TR scriptPubKey = OP_1 (0x51) + 0x20 + 32 bytes x-only pubkey = 34 bytes total.
     */
    private boolean hasP2TR() {
        try {
            for (WalletTransaction wt : wallet.getWalletTransactions()) {
                for (TransactionOutput out : wt.getTransaction().getOutputs()) {
                    byte[] prog = out.getScriptPubKey().getProgram();
                    if (prog.length == 34 && prog[0] == 0x51) {
                        return true;
                    }
                }
            }
        } catch (Throwable ignore) {}
        return false;
    }

    /**
     * Sweep using built-in bitcoinj 0.17.1 Taproot APIs.
     * No hardcoded fee - feePerKb comes from original SendRequest (set by SweepWalletFragment).
     * No custom crypto - uses Transaction.hashForTaproot* and Schnorr from library.
     */
    private Transaction sweepWithTaprootBuiltIn(SendRequest sendRequest) throws Exception {
        // Create a new transaction that sends all UTXOs to destination.
        // Reuse SendRequest.tx output as destination (already set by caller).
        Transaction tx = new Transaction(Constants.NETWORK_PARAMETERS);

        // Collect all UTXOs and total value
        long total = 0;
        java.util.List<org.bitcoinj.core.UTXO> utxos = new java.util.ArrayList<>();
        for (WalletTransaction wt : wallet.getWalletTransactions()) {
            for (TransactionOutput out : wt.getTransaction().getOutputs()) {
                if (out.getValue().isZero() || out.getValue().isNegative()) continue;
                utxos.add(new org.bitcoinj.core.UTXO(
                        wt.getTransaction().getTxId(),
                        out.getIndex(),
                        out.getValue(),
                        0,
                        false,
                        out.getScriptPubKey()
                ));
                total+= out.getValue().value;
                tx.addInput(out.getParentTransaction().getTxId(), out.getIndex(), out.getScriptPubKey());
            }
        }

        // Use original feePerKb from request - same as legacy path
        long feePerKb = (sendRequest.feePerKb!= null)? sendRequest.feePerKb.value : Transaction.DEFAULT_TX_FEE.value;
        long fee = feePerKb * 150 / 1000; // ~150 vB for 1 P2TR input
        long outVal = total - fee;

        // Destination from original request
        tx.addOutput(Coin.valueOf(outVal), sendRequest.tx.getOutput(0).getScriptPubKey());

        // Sign with built-in Taproot signer (no custom Schnorr implementation)
        // bitcoinj 0.17.1 provides calculateTaprootWitnessSignature()
        for (int i = 0; i < utxos.size(); i++) {
            org.bitcoinj.core.UTXO u = utxos.get(i);
            boolean signed = false;

            for (ECKey key : wallet.getImportedKeys()) {
                try {
                    if (key.getPrivKey() == null) continue;

                    // This uses library's internal Taproot tweak and Schnorr signing
                    org.bitcoinj.crypto.TransactionSignature sig =
                        tx.calculateTaprootWitnessSignature(i, key, u.getScript(), u.getValue(), Transaction.SigHash.ALL, false);

                    tx.getInput(i).setWitness(sig.toWitness());
                    signed = true;
                    break;
                } catch (Throwable ignore) {}
            }

            if (!signed) {
                // Fallback to legacy signing for non-P2TR coins in same wallet
                for (ECKey key : wallet.getImportedKeys()) {
                    try {
                        org.bitcoinj.crypto.TransactionSignature sig =
                            tx.calculateWitnessSignature(i, key, u.getScript(), u.getValue(), Transaction.SigHash.ALL, false);
                        tx.getInput(i).setWitness(sig.toWitness());
                        signed = true;
                        break;
                    } catch (Throwable ignore) {}
                }
            }

            if (!signed) throw new RuntimeException("Cannot sign input " + i);
        }

        return tx;
    }

    protected abstract void onSuccess(Transaction transaction);
    protected abstract void onInsufficientMoney(Coin missing);
    protected abstract void onInvalidEncryptionKey();
    protected void onEmptyWalletFailed(Exception exception) { onFailure(exception); }
    protected abstract void onFailure(Exception exception);
}
