package wallet.ui.send;

import android.os.Handler;
import android.os.Looper;

import org.bitcoinj.base.Coin;
import org.bitcoinj.core.InsufficientMoneyException;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.core.TransactionWitness;
import org.bitcoinj.core.UTXO;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.script.Script;
import org.bitcoinj.wallet.SendRequest;
import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.wallet.WalletTransaction;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import wallet.Constants;
import wallet.util.TaprootSweeper;

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
        backgroundHandler.post(() -> {
            org.bitcoinj.core.Context.propagate(Constants.CONTEXT);
            try {
                // Check if wallet contains P2TR (bc1p) utxo
                boolean hasP2TR = false;
                List<UTXO> utxos = new ArrayList<>();
                long total = 0;
                for (WalletTransaction wt : wallet.getWalletTransactions()) {
                    for (TransactionOutput out : wt.getTransaction().getOutputs()) {
                        if (out.getValue().isZero()) continue;
                        utxos.add(new UTXO(wt.getTransaction().getTxId(), out.getIndex(), out.getValue(), 0, false, out.getScriptPubKey()));
                        total+= out.getValue().value;
                        if (TaprootSweeper.isP2TR(out.getScriptPubKey())) hasP2TR = true;
                    }
                }

                final Transaction tx;
                if (hasP2TR) {
                    tx = sweepTaproot(sendRequest, utxos, total);
                } else {
                    tx = wallet.sendCoinsOffline(sendRequest);
                }

                callbackHandler.post(() -> onSuccess(tx));
            } catch (final Exception x) {
                log.info("send failed: {}", x.getMessage());
                callbackHandler.post(() -> onFailure(x));
            }
        });
    }

    private Transaction sweepTaproot(SendRequest req, List<UTXO> utxos, long total) throws Exception {
        if (utxos.isEmpty()) throw new InsufficientMoneyException(Coin.valueOf(546));

        Transaction tx = new Transaction(Constants.NETWORK_PARAMETERS);
        for (UTXO u : utxos) tx.addInput(u.getHash(), u.getIndex(), new Script(new byte[]{}));

        if (req.tx.getOutputs().isEmpty()) throw new RuntimeException("No destination");
        Script dest = req.tx.getOutput(0).getScriptPubKey();

        // Use feePerKb from original request, no hardcoded fee
        long feePerKb = (req.feePerKb!= null)? req.feePerKb.value : Transaction.DEFAULT_TX_FEE.value;
        long fee = feePerKb * 150 / 1000;
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
                        signed = true; break;
                    } catch (Throwable ignore) {}
                }
            }

            if (!signed) {
                for (ECKey k : wallet.getImportedKeys()) {
                    try {
                        org.bitcoinj.crypto.TransactionSignature sig =
                                tx.calculateWitnessSignature(i, k, u.getScript(), u.getValue(), Transaction.SigHash.ALL, false);
                        tx.getInput(i).setWitness(TransactionWitness.of(sig.encodeToBitcoin(), k.getPubKey()));
                        signed = true; break;
                    } catch (Throwable ignore) {}
                }
            }

            if (!signed) throw new RuntimeException("Cannot sign " + i);
        }
        return tx;
    }

    protected abstract void onSuccess(Transaction transaction);
    protected abstract void onInsufficientMoney(Coin missing);
    protected abstract void onInvalidEncryptionKey();
    protected void onEmptyWalletFailed(Exception exception) { onFailure(exception); }
    protected abstract void onFailure(Exception exception);
}
