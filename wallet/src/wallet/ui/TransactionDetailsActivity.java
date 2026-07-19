package wallet.ui;

import android.app.ActionBar;
import android.app.Activity;
import android.app.Dialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.provider.MediaStore;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;

import org.bitcoinj.base.Coin;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionConfidence;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutPoint;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptException;
import org.bitcoinj.script.ScriptPattern;
import org.bitcoinj.wallet.Wallet;

import java.io.OutputStream;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import wallet.R;
import wallet.WalletApplication;

/**
 * Transaction Details screen.
 * Shows amount, status, fee, and full input/output breakdown.
 * Compatible with AppTheme.My.Preference, extends android.app.Activity.
 * Fixed for mainnet, signet, testnet3 - handles missing prevOut via witness extraction.
 */
public class TransactionDetailsActivity extends Activity {
    // Main amount / status views
    private TextView tvDirection, tvAmount, tvStatus, tvFee, tvTime, tvHeight, tvMeta, tvTxid;
    // Age view - time elapsed since transaction
    private TextView tvAge;
    // Full input/output list views
    private TextView tvFrom, tvTo;
    // Actual counterparty sender/receiver views (single address)
    private TextView tvActualFrom, tvActualTo;

    // QR live
    private ImageView ivQr;
    private Bitmap currentQrBitmap;
    private TextView tvTxidCopy;

    // --- LIVE PATCH: keep tx/wallet/params for listener ---
    private Transaction tx;
    private Wallet wallet;
    private NetworkParameters params;

    private final TransactionConfidence.Listener confidenceListener = new TransactionConfidence.Listener() {
        @Override
        public void onConfidenceChanged(TransactionConfidence confidence, TransactionConfidence.Listener.ChangeReason reason) {
            runOnUiThread(() -> refreshLiveFields());
        }
    };

    private Dialog qrDialog;
    private ImageView qrDialogImageView;

    // Age ticker - updates the Age field every second
    private final Handler ageHandler = new Handler(Looper.getMainLooper());
    private final Runnable ageRunnable = new Runnable() {
        @Override
        public void run() {
            refreshLiveFields();
            long now = System.currentTimeMillis();
            ageHandler.postDelayed(this, 1000 - (now % 1000));
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_transaction_details);

        ActionBar ab = getActionBar();
        if (ab!= null) {
            ab.setDisplayHomeAsUpEnabled(true);
            ab.setTitle(R.string.tx_details_title);
        }

        tvDirection = findViewById(R.id.tv_direction);
        tvAmount = findViewById(R.id.tv_amount);
        tvStatus = findViewById(R.id.tv_status);
        tvFee = findViewById(R.id.tv_fee);
        tvTime = findViewById(R.id.tv_time);
        tvHeight = findViewById(R.id.tv_height);
        tvMeta = findViewById(R.id.tv_meta);
        tvTxid = findViewById(R.id.tv_txid);
        tvAge = findViewById(R.id.tv_age);
        tvFrom = findViewById(R.id.tv_from);
        tvTo = findViewById(R.id.tv_to);
        tvActualFrom = findViewById(R.id.tv_actual_from);
        tvActualTo = findViewById(R.id.tv_actual_to);
        ivQr = findViewById(R.id.iv_tx_qr);
        tvTxidCopy = findViewById(R.id.tv_txid_copy);

        if (tvStatus!= null) { tvStatus.setGravity(Gravity.END); tvStatus.setTextAlignment(TextView.TEXT_ALIGNMENT_VIEW_END); }
        if (tvFee!= null) { tvFee.setGravity(Gravity.END); tvFee.setTextAlignment(TextView.TEXT_ALIGNMENT_VIEW_END); }
        if (tvTime!= null) { tvTime.setGravity(Gravity.END); tvTime.setTextAlignment(TextView.TEXT_ALIGNMENT_VIEW_END); }
        if (tvHeight!= null) { tvHeight.setGravity(Gravity.END); tvHeight.setTextAlignment(TextView.TEXT_ALIGNMENT_VIEW_END); }
        if (tvMeta!= null) { tvMeta.setGravity(Gravity.END); tvMeta.setTextAlignment(TextView.TEXT_ALIGNMENT_VIEW_END); }
        if (tvAge!= null) { tvAge.setGravity(Gravity.END); tvAge.setTextAlignment(TextView.TEXT_ALIGNMENT_VIEW_END); }

        String txidStr = getIntent().getStringExtra("txid");
        if (txidStr == null) {
            Toast.makeText(this, getString(R.string.tx_details_missing_txid), Toast.LENGTH_SHORT).show();
            finish();
            return;
        }

        WalletApplication app = (WalletApplication) getApplication();
        wallet = app.getWallet();
        if (wallet == null) {
            Toast.makeText(this, getString(R.string.tx_details_wallet_not_ready), Toast.LENGTH_SHORT).show();
            finish();
            return;
        }
        params = wallet.getNetworkParameters();

        try {
            tx = wallet.getTransaction(Sha256Hash.wrap(txidStr));
        } catch (Exception e) {
            tx = null;
        }
        if (tx == null) {
            Toast.makeText(this, getString(R.string.tx_details_transaction_not_found), Toast.LENGTH_SHORT).show();
            finish();
            return;
        }

        // --- Amount and direction ---
        Coin value = Coin.ZERO;
        try {
            Coin v = tx.getValue(wallet);
            if (v!= null) value = v;
        } catch (Exception ignored) {}
        boolean isSend = value.isNegative();
        Coin absValue = isSend? value.negate() : value;

        tvDirection.setText(isSend? getString(R.string.tx_details_sent) : getString(R.string.tx_details_received));
        tvAmount.setText((isSend? "-" : "+") + absValue.toPlainString() + " BTC");
        try {
            tvAmount.setTextColor(getResources().getColor(
                isSend? R.color.tx_amount_sent : R.color.tx_amount_recv));
        } catch (Exception ignored) {}

        refreshLiveFields();

        // --- Fee: try native getFee(), then manually calculate if all inputs are known ---
        Coin fee = null;
        try { fee = tx.getFee(); } catch (Exception ignored) {}
        // Manual fallback: if we are the sender we have all prevOuts in wallet, so we can calculate totalIn - totalOut
        if (fee == null) {
            try {
                Coin totalInCalc = Coin.ZERO;
                boolean allKnown = true;
                if (tx.getInputs()!= null) {
                    for (TransactionInput in : tx.getInputs()) {
                        TransactionOutput connected = getConnectedOutput(in);
                        if (connected == null || connected.getValue() == null) { allKnown = false; break; }
                        totalInCalc = totalInCalc.add(connected.getValue());
                    }
                } else {
                    allKnown = false;
                }
                if (allKnown) {
                    Coin totalOutCalc = Coin.ZERO;
                    if (tx.getOutputs()!= null) {
                        for (TransactionOutput out : tx.getOutputs()) {
                            if (out.getValue()!= null) totalOutCalc = totalOutCalc.add(out.getValue());
                        }
                    }
                    fee = totalInCalc.subtract(totalOutCalc);
                }
            } catch (Exception ignored) {}
        }
        tvFee.setText(fee!= null? fee.toPlainString() + " BTC" : "—");

        Date updateTime = null;
        try { updateTime = tx.getUpdateTime(); } catch (Exception ignored) {}
        if (updateTime!= null) {
            tvTime.setText(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(updateTime));
        } else {
            tvTime.setText("—");
        }

        int size = 0, weight = 0;
        boolean rbf = false;
        try { size = tx.getMessageSize(); } catch (Exception ignored) {}
        try { weight = tx.getWeight(); } catch (Exception ignored) {}
        try { rbf = tx.isOptInFullRBF(); } catch (Exception ignored) {}

        String feeRate = "";
        if (fee!= null && weight > 0) {
            try {
                long satPerVbyte = fee.getValue() * 4 / weight;
                feeRate = " · " + satPerVbyte + " sat/vB";
            } catch (Exception ignored) {}
        }
        tvMeta.setText(size + " bytes · " + weight + " wu" + feeRate + (rbf? " · RBF" : ""));

        // --- Actual sender / receiver: For receiving, From is external address extracted via witness if needed ---
        String actualFrom = null;
        String actualTo = null;
        try {
            if (isSend) {
                actualTo = getOutputAddress(tx, params, wallet, false);
                actualFrom = getInputAddress(tx, params, wallet, true);
            } else {
                actualFrom = getInputAddress(tx, params, wallet, false);
                actualTo = getOutputAddress(tx, params, wallet, true);
            }
            if (actualFrom == null) actualFrom = getInputAddress(tx, params, wallet, null);
            if (actualTo == null) actualTo = getOutputAddress(tx, params, wallet, null);
        } catch (Exception ignored) {}
        if (actualFrom == null) actualFrom = "—";
        if (actualTo == null) actualTo = "—";

        tvActualFrom.setText(actualFrom);
        tvActualTo.setText(actualTo);
        copyOnClick(tvActualFrom, actualFrom);
        copyOnClick(tvActualTo, actualTo);

        // --- Full input / output list: Fixed for signet/testnet3 where prevOut is missing ---
        StringBuilder fromSb = new StringBuilder();
        Coin totalFrom = Coin.ZERO;
        int inCount = 0;
        if (tx.getInputs()!= null) {
            for (TransactionInput in : tx.getInputs()) {
                inCount++;
                Coin v = null;
                String addr = "unknown";
                String type = "nonstandard";
                try {
                    // Try to get connected output from wallet DB (works for mainnet and for self-spends)
                    TransactionOutput connected = getConnectedOutput(in);
                    if (connected!= null) {
                        v = connected.getValue();
                        // Primary: get address from scriptPubKey of prevOut
                        addr = getAddressFromScript(connected.getScriptPubKey(), params);
                        // Fallback: extract from witness pubkey if script parsing fails
                        if (addr == null) addr = getAddressFromWitness(in, params);
                        if (addr == null) addr = "unknown";
                        type = getAddressType(addr, connected.getScriptPubKey());
                    } else {
                        // No prevOut in DB (common for signet/testnet3 faucet receives and cross-wallet receives)
                        // Extract address directly from witness stack (P2WPKH = last push is compressed pubkey 33 bytes)
                        String witnessAddr = getAddressFromWitness(in, params);
                        if (witnessAddr!= null) {
                            addr = witnessAddr;
                            type = getAddressType(addr, null);
                        }
                    }
                } catch (Exception ignored) {}
                if (v!= null) totalFrom = totalFrom.add(v);
                fromSb.append(addr).append(" (").append(type).append(") - ")
                   .append(v!= null? v.toPlainString() + " BTC" : "? BTC").append("\n");
            }
        }

        String fromText = getString(R.string.tx_details_total_from, totalFrom.toPlainString(), inCount) + "\n" + fromSb.toString().trim();

        StringBuilder toSb = new StringBuilder();
        Coin totalTo = Coin.ZERO;
        int outCount = tx.getOutputs()!= null? tx.getOutputs().size() : 0;
        if (tx.getOutputs()!= null) {
            for (TransactionOutput out : tx.getOutputs()) {
                Coin v = out.getValue();
                if (v!= null) totalTo = totalTo.add(v);
                String addr = getAddressFromScript(out.getScriptPubKey(), params);
                if (addr == null) addr = "unknown";
                String type = getAddressType(addr, out.getScriptPubKey());
                toSb.append(addr).append(" (").append(type).append(") - ")
                 .append(v!= null? v.toPlainString() + " BTC" : "? BTC").append("\n");
            }
        }

        String toText = getString(R.string.tx_details_total_to, totalTo.toPlainString(), outCount) + "\n" + toSb.toString().trim();

        tvFrom.setSingleLine(false);
        tvTo.setSingleLine(false);
        tvFrom.setText(fromText);
        tvTo.setText(toText);
        copyOnClick(tvFrom, fromText);
        copyOnClick(tvTo, toText);

        String hash = tx.getTxId().toString();
        tvTxid.setText(hash);
        copyOnClick(tvTxid, hash);

        setupQr();
        updateLiveQr();
        setupParallaxScroll();
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (tx!= null && tx.getConfidence()!= null) {
            tx.getConfidence().addEventListener(confidenceListener);
        }
        refreshLiveFields();
        ageHandler.post(ageRunnable);
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (tx!= null && tx.getConfidence()!= null) {
            tx.getConfidence().removeEventListener(confidenceListener);
        }
        ageHandler.removeCallbacks(ageRunnable);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.transaction_details_activity_options, menu);
        return true;
    }

    @Override
    public boolean onPrepareOptionsMenu(Menu menu) {
        final int networkSignificantColor = getResources().getColor(R.color.fg_on_dark_bg_network_significant);
        final View decor = getWindow().getDecorView();
        decor.post(() -> {
            ArrayList<View> actionMenuViews = new ArrayList<>();
            findViewsByClass(decor, "ActionMenuView", actionMenuViews);
            for (View amv : actionMenuViews) {
                if (!(amv instanceof ViewGroup)) continue;
                ViewGroup vg = (ViewGroup) amv;
                for (int i = 0; i < vg.getChildCount(); i++) {
                    View itemView = vg.getChildAt(i);
                    if (itemView.getClass().getSimpleName().contains("ActionMenuItemView")) {
                        findAndWhiteText(itemView, networkSignificantColor);
                    }
                }
            }
        });
        return super.onPrepareOptionsMenu(menu);
    }

    private void findAndWhiteText(View root, int color) {
        if (root instanceof TextView) {
            ((TextView) root).setTextColor(color);
            return;
        }
        if (root instanceof ViewGroup) {
            ViewGroup vg = (ViewGroup) root;
            for (int i = 0; i < vg.getChildCount(); i++) {
                findAndWhiteText(vg.getChildAt(i), color);
            }
        }
    }

    private void findViewsByClass(View root, String className, ArrayList<View> out) {
        if (root.getClass().getSimpleName().contains(className)) out.add(root);
        if (root instanceof ViewGroup) {
            ViewGroup vg = (ViewGroup) root;
            for (int i = 0; i < vg.getChildCount(); i++) {
                findViewsByClass(vg.getChildAt(i), className, out);
            }
        }
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == android.R.id.home) {
            finish();
            return true;
        }
        if (item.getItemId() == R.id.transaction_details_options_copy) {
            copyFullTx();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    /**
     * Try to get the connected output for an input.
     * 1. Try outpoint.getConnectedOutput() - bitcoinj sets this when tx is in wallet
     * 2. Fallback: look up prev tx hash in current wallet (wallet.getTransaction)
     * This is why mainnet receives often work while signet faucet receives don't - faucet prev tx is not in wallet DB.
     */
    private TransactionOutput getConnectedOutput(TransactionInput in) {
        try {
            TransactionOutPoint outpoint = in.getOutpoint();
            if (outpoint == null) return null;
            // First try: directly connected (set by bitcoinj when available)
            TransactionOutput connected = outpoint.getConnectedOutput();
            if (connected!= null) return connected;
            // Second try: lookup prev transaction in wallet
            if (wallet!= null) {
                Transaction prev = wallet.getTransaction(outpoint.getHash());
                if (prev!= null) {
                    return prev.getOutput((int) outpoint.getIndex());
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    /**
     * Extract sender address from witness stack.
     * For P2WPKH (native segwit v0): witness = [signature, pubkey], pubkey is 33 bytes compressed (or 65 uncompressed)
     * We hash the pubkey and create Segwit v0 address (tb1q... / bc1q...)
     * For P2TR (taproot v1): witness = [signature] 64 bytes, cannot recover address without prevOut, return null
     * This method fixes From = — for signet/testnet3 self-wallet sends where prevOut is not in DB.
     */
    private String getAddressFromWitness(TransactionInput in, NetworkParameters params) {
        try {
            if (in.getWitness() == null) return null;
            int count = in.getWitness().getPushCount();
            if (count == 0) return null;
            // Scan from last to first to find a pubkey (P2WPKH case)
            for (int i = count - 1; i >= 0; i--) {
                byte[] push = in.getWitness().getPush(i);
                if (push == null) continue;
                // Compressed pubkey 33 bytes or uncompressed 65 bytes
                if (push.length == 33 || push.length == 65) {
                    try {
                        org.bitcoinj.crypto.ECKey key = org.bitcoinj.crypto.ECKey.fromPublicOnly(push);
                        // Use fromProgram(v0, hash160) instead of fromKey() for better compatibility across bitcoinj versions and networks (mainnet, signet, testnet3)
                        byte[] hash = key.getPubKeyHash();
                        return org.bitcoinj.base.SegwitAddress.fromProgram(params, 0, hash).toString();
                    } catch (Exception ignored) {}
                }
                // For P2TR x-only pubkey (32 bytes) - can create v1 address
                if (push.length == 32) {
                    try {
                        return org.bitcoinj.base.SegwitAddress.fromProgram(params, 1, push).toString();
                    } catch (Exception ignored) {}
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    private String getAddressFromScript(Script script, NetworkParameters params) {
        if (script == null) return null;
        try {
            return script.getToAddress(params).toString();
        } catch (ScriptException e) {
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    private String getAddressType(String addr, Script script) {
        try {
            if (script!= null && ScriptPattern.isOpReturn(script)) return "OP_RETURN";
        } catch (Exception ignored) {}
        if (addr == null) return "nonstandard";
        if (addr.startsWith("bc1q") || addr.startsWith("tb1q")) return "P2WPKH";
        if (addr.startsWith("bc1p") || addr.startsWith("tb1p")) return "P2TR";
        if (addr.startsWith("bc1") || addr.startsWith("tb1")) return "P2WSH";
        if (addr.startsWith("3") || addr.startsWith("2")) return "P2SH";
        if (addr.startsWith("1") || addr.startsWith("m") || addr.startsWith("n")) return "P2PKH";
        return "nonstandard";
    }

    private String getInputAddress(Transaction tx, NetworkParameters params, Wallet wallet, Boolean mineOnly) {
        if (tx.getInputs() == null) return null;
        for (TransactionInput in : tx.getInputs()) {
            try {
                TransactionOutput connected = getConnectedOutput(in);
                if (connected!= null) {
                    if (mineOnly!= null) {
                        boolean isMine;
                        try { isMine = connected.isMine(wallet); } catch (Exception e) { continue; }
                        if (isMine!= mineOnly) continue;
                    }
                    // Try scriptPubKey first, then witness fallback
                    String a = getAddressFromScript(connected.getScriptPubKey(), params);
                    if (a == null) a = getAddressFromWitness(in, params);
                    if (a!= null) return a;
                } else {
                    // No connected output (signet/testnet3 cross-wallet receive)
                    // Try to extract from witness directly
                    if (mineOnly == null ||!mineOnly) {
                        String wa = getAddressFromWitness(in, params);
                        if (wa!= null) return wa;
                    }
                    try {
                        String a = getAddressFromScript(in.getScriptSig(), params);
                        if (a!= null) return a;
                    } catch (Exception ignored) {}
                }
            } catch (Exception ignored) {}
        }
        return null;
    }

    private String getOutputAddress(Transaction tx, NetworkParameters params, Wallet wallet, Boolean mineOnly) {
        if (tx.getOutputs() == null) return null;
        for (TransactionOutput out : tx.getOutputs()) {
            try {
                if (mineOnly!= null) {
                    boolean isMine;
                    try { isMine = out.isMine(wallet); } catch (Exception e) { continue; }
                    if (isMine!= mineOnly) continue;
                }
                String a = getAddressFromScript(out.getScriptPubKey(), params);
                if (a!= null) return a;
            } catch (Exception ignored) {}
        }
        return null;
    }

    private void copyOnClick(TextView tv, String text) {
        if (tv == null) return;
        tv.setOnClickListener(v -> copy(text));
    }

    private void copy(String text) {
        try {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            cm.setPrimaryClip(ClipData.newPlainText("tx", text));
            Toast.makeText(this, getString(R.string.tx_details_copied), Toast.LENGTH_SHORT).show();
        } catch (Exception ignored) {}
    }

    private boolean isDark() {
        return (getResources().getConfiguration().uiMode
            & android.content.res.Configuration.UI_MODE_NIGHT_MASK)
            == android.content.res.Configuration.UI_MODE_NIGHT_YES;
    }

    private void setupQr() {
        if (ivQr!= null) {
            ivQr.setOnClickListener(v -> showQrDialog());
        }
        if (tvTxidCopy!= null) {
            tvTxidCopy.setVisibility(android.view.View.GONE);
        }
    }

private String buildLiveTxText() {
    String ageStr = getTv(tvAge);
    return getString(R.string.qr_direction) + ": " + getTv(tvDirection) + "\n"
            + getString(R.string.qr_amount) + ": " + getTv(tvAmount) + "\n\n"
            + getString(R.string.qr_sender_receiver) + "\n"
            + getString(R.string.qr_from) + ": " + getTv(tvActualFrom) + "\n"
            + getString(R.string.qr_to) + ": " + getTv(tvActualTo) + "\n\n"
            + getString(R.string.qr_tx_details) + "\n"
            + getString(R.string.qr_status) + ": " + getTv(tvStatus) + "\n"
            + getString(R.string.qr_fee) + ": " + getTv(tvFee) + "\n"
            + getString(R.string.qr_size_weight) + ": " + getTv(tvMeta) + "\n"
            + getString(R.string.qr_confirmations) + ": " + getTv(tvHeight) + "\n"
            + getString(R.string.qr_time) + ": " + getTv(tvTime) + "\n"
            + getString(R.string.qr_age) + ": " + ageStr + "\n\n"
            + getString(R.string.qr_sent_details) + "\n" + getTv(tvFrom) + "\n\n"
            + getString(R.string.qr_received_details) + "\n" + getTv(tvTo) + "\n\n"
            + getString(R.string.qr_txid) + "\n" + getTv(tvTxid);
}

    private String getTv(TextView tv) {
        return tv!= null && tv.getText()!= null? tv.getText().toString() : "";
    }

    private void updateLiveQr() {
        try {
            String text = buildLiveTxText();
            if (ivQr!= null) {
                currentQrBitmap = encodeQr(text, 768);
                ivQr.setImageBitmap(currentQrBitmap);
            }
            if (qrDialog!= null && qrDialog.isShowing() && qrDialogImageView!= null) {
                Bitmap big = encodeQr(text, 1024);
                qrDialogImageView.setImageBitmap(big);
                currentQrBitmap = big;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void copyFullTx() {
        copy(buildLiveTxText());
    }

    private void showQrDialog() {
        boolean dark = isDark();
        int bgColor = dark? Color.BLACK : Color.WHITE;
 int dialogTheme = dark
 ? android.R.style.Theme_Black_NoTitleBar_Fullscreen
    : android.R.style.Theme_Light_NoTitleBar_Fullscreen;
qrDialog = new Dialog(this, dialogTheme);
qrDialog.getWindow().setFlags(
    android.view.WindowManager.LayoutParams.FLAG_FULLSCREEN,
    android.view.WindowManager.LayoutParams.FLAG_FULLSCREEN);
if (android.os.Build.VERSION.SDK_INT >= 21) {
    qrDialog.getWindow().setStatusBarColor(bgColor);
}
qrDialog.getWindow().getDecorView().setSystemUiVisibility(
   android.view.View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN
  | android.view.View.SYSTEM_UI_FLAG_FULLSCREEN);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(bgColor);
        root.setLayoutParams(new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));
        qrDialogImageView = new ImageView(this);
        qrDialogImageView.setScaleType(ImageView.ScaleType.FIT_CENTER);
        qrDialogImageView.setPadding(48, 48, 48, 48);
        LinearLayout.LayoutParams imgLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f);
        qrDialogImageView.setLayoutParams(imgLp);
        qrDialogImageView.setOnClickListener(v -> qrDialog.dismiss());
        root.addView(qrDialogImageView);
        LinearLayout bar = new LinearLayout(this);
        bar.setOrientation(LinearLayout.HORIZONTAL);
        bar.setGravity(Gravity.CENTER);
        bar.setPadding(16, 24, 16, 48);
        bar.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        bar.addView(makeActionButton(android.R.drawable.ic_menu_save, getString(R.string.tx_details_save), dark, v -> saveQrBitmap()));
        bar.addView(makeActionButton(android.R.drawable.ic_menu_share, getString(R.string.tx_details_share), dark, v -> shareTx()));
        bar.addView(makeActionButton(android.R.drawable.ic_menu_search, getString(R.string.tx_details_explore), dark, v -> exploreTx()));
        root.addView(bar);
        qrDialog.setContentView(root);
        qrDialog.setCancelable(true);
        qrDialog.setOnDismissListener(d -> {
            qrDialog = null;
            qrDialogImageView = null;
        });
        qrDialog.show();
        updateLiveQr();
    }

    private LinearLayout makeActionButton(int iconRes, String label, boolean dark, android.view.View.OnClickListener onClick) {
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        col.setLayoutParams(lp);
        col.setClickable(true);
        col.setOnClickListener(onClick);
        col.setPadding(8, 8, 8, 8);
        ImageView iv = new ImageView(this);
        iv.setImageResource(iconRes);
        int iconSize = (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, 36, getResources().getDisplayMetrics());
        LinearLayout.LayoutParams ivLp = new LinearLayout.LayoutParams(iconSize, iconSize);
        ivLp.gravity = Gravity.CENTER;
        iv.setLayoutParams(ivLp);
        col.addView(iv);
        TextView tv = new TextView(this);
        tv.setText(label);
        tv.setTextColor(dark? 0xFFBBBBBB : 0xFF666666);
        tv.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        tv.setGravity(Gravity.CENTER);
        tv.setPadding(0, 8, 0, 0);
        col.addView(tv);
        return col;
    }

    private void saveQrBitmap() {
        try {
            Bitmap bmp = currentQrBitmap;
            if (bmp == null) {
                bmp = encodeQr(buildLiveTxText(), 1024);
            }
            String filename = "tx_" + (tx!= null? tx.getTxId().toString().substring(0, 8) : "qr") + "_" + System.currentTimeMillis() + ".png";
            ContentValues values = new ContentValues();
            values.put(MediaStore.Images.Media.DISPLAY_NAME, filename);
            values.put(MediaStore.Images.Media.MIME_TYPE, "image/png");
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                values.put(MediaStore.Images.Media.RELATIVE_PATH, Environment.DIRECTORY_PICTURES + "/WalletQR");
                values.put(MediaStore.Images.Media.IS_PENDING, 1);
            }
            Uri uri = getContentResolver().insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, values);
            if (uri == null) { Toast.makeText(this, getString(R.string.tx_details_save_failed), Toast.LENGTH_SHORT).show(); return; }
            try (OutputStream os = getContentResolver().openOutputStream(uri)) {
                bmp.compress(Bitmap.CompressFormat.PNG, 100, os);
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                values.clear();
                values.put(MediaStore.Images.Media.IS_PENDING, 0);
                getContentResolver().update(uri, values, null, null);
            }
            Toast.makeText(this, getString(R.string.tx_details_saved_to_pictures), Toast.LENGTH_SHORT).show();
        } catch (Exception e) {
            Toast.makeText(this, getString(R.string.tx_details_save_failed_msg, e.getMessage()), Toast.LENGTH_SHORT).show();
        }
    }

    private void shareTx() {
        try {
            String txid = tx!= null? tx.getTxId().toString() : getTv(tvTxid);
            String shareText = buildLiveTxText() + "\n\nhttps://mempool.space/tx/" + txid;
            Intent i = new Intent(Intent.ACTION_SEND);
            i.setType("text/plain");
            i.putExtra(Intent.EXTRA_TEXT, shareText);
            startActivity(Intent.createChooser(i, getString(R.string.tx_details_share_tx)));
        } catch (Exception ignored) {}
    }

    private void exploreTx() {
        try {
            String txid = tx!= null? tx.getTxId().toString() : getTv(tvTxid);
            Intent i = new Intent(Intent.ACTION_VIEW, Uri.parse("https://mempool.space/tx/" + txid));
            startActivity(i);
        } catch (Exception e) {
            Toast.makeText(this, getString(R.string.tx_details_no_browser), Toast.LENGTH_SHORT).show();
        }
    }

    public static Bitmap encodeQr(String text, int size) throws WriterException {
        QRCodeWriter writer = new QRCodeWriter();
        Map<EncodeHintType, Object> hints = new HashMap<>();
        hints.put(EncodeHintType.MARGIN, 1);
        hints.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.L);
        BitMatrix bitMatrix = writer.encode(text, BarcodeFormat.QR_CODE, size, size, hints);
        int w = bitMatrix.getWidth();
        int h = bitMatrix.getHeight();
        Bitmap bmp = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888);
        for (int x = 0; x < w; x++) {
            for (int y = 0; y < h; y++) {
                bmp.setPixel(x, y, bitMatrix.get(x, y)? Color.BLACK : Color.WHITE);
            }
        }
        return bmp;
    }

private String formatAge(Date txTime) {
    if (txTime == null) return "—";
    java.util.Calendar then = java.util.Calendar.getInstance();
    then.setTime(txTime);
    java.util.Calendar now = java.util.Calendar.getInstance();
    int years = now.get(java.util.Calendar.YEAR) - then.get(java.util.Calendar.YEAR);
    int months = now.get(java.util.Calendar.MONTH) - then.get(java.util.Calendar.MONTH);
    int days = now.get(java.util.Calendar.DAY_OF_MONTH) - then.get(java.util.Calendar.DAY_OF_MONTH);
    int hours = now.get(java.util.Calendar.HOUR_OF_DAY) - then.get(java.util.Calendar.HOUR_OF_DAY);
    int minutes = now.get(java.util.Calendar.MINUTE) - then.get(java.util.Calendar.MINUTE);
    int seconds = now.get(java.util.Calendar.SECOND) - then.get(java.util.Calendar.SECOND);
    if (seconds < 0) { seconds += 60; minutes--; }
    if (minutes < 0) { minutes += 60; hours--; }
    if (hours < 0) { hours += 24; days--; }
    if (days < 0) {
        java.util.Calendar temp = (java.util.Calendar) now.clone();
        temp.add(java.util.Calendar.MONTH, -1);
        int daysInLastMonth = temp.getActualMaximum(java.util.Calendar.DAY_OF_MONTH);
        days += daysInLastMonth;
        months--;
    }
    if (months < 0) { months += 12; years--; }
    String result = "";
    if (years > 0) result += years + " " + getString(years == 1? R.string.qr_year : R.string.qr_years) + " ";
    if (months > 0) result += months + " " + getString(months == 1? R.string.qr_month : R.string.qr_months) + " ";
    if (days > 0) result += days + " " + getString(days == 1? R.string.qr_day : R.string.qr_days) + " ";
    if (hours > 0 || result.length() > 0) result += hours + " " + getString(hours == 1? R.string.qr_hour : R.string.qr_hours) + " ";
    if (minutes > 0 || result.length() > 0) result += minutes + " " + getString(minutes == 1? R.string.qr_minute : R.string.qr_minutes) + " ";
    result += seconds + " " + getString(seconds == 1? R.string.qr_second : R.string.qr_seconds) + " ";
    result += getString(R.string.qr_ago);
    return result;
}

    private void refreshLiveFields() {
        if (tx == null || tvStatus == null || tvHeight == null) return;
        TransactionConfidence confidence = tx.getConfidence();
        int depth = 0;
        int height = 0;
        if (confidence!= null) {
            try { depth = confidence.getDepthInBlocks(); } catch (Exception ignored) {}
            try { height = confidence.getAppearedAtChainHeight(); } catch (Exception ignored) {}
        }
        String statusText;
        int statusColorRes;
        if (depth <= 0) {
            statusText = getString(R.string.tx_details_status_pending);
            statusColorRes = R.color.tx_status_pending;
        } else if (depth < 7) {
            statusText = getString(R.string.tx_details_status_building);
            statusColorRes = R.color.tx_status_building;
        } else {
            statusText = getString(R.string.tx_details_status_confirmed);
            statusColorRes = R.color.tx_status_ok;
        }
        tvStatus.setText(statusText);
        try {
            tvStatus.setTextColor(getResources().getColor(statusColorRes));
        } catch (Exception ignored) {}
        String confStr;
        if (depth <= 0) {
            confStr = getString(R.string.tx_details_unconfirmed);
        } else {
            confStr = getString(R.string.tx_details_confirmations_value, depth, height);
        }
        tvHeight.setText(confStr);
        if (tvAge!= null) {
            Date updateTime = null;
            try { updateTime = tx.getUpdateTime(); } catch (Exception ignored) {}
            tvAge.setText(formatAge(updateTime));
        }
        updateLiveQr();
    }

    private void setupParallaxScroll() {
        final View scroll = findViewById(R.id.nested_scroll);
        final View cardHeader = findViewById(R.id.card_header);
        if (scroll == null || cardHeader == null) return;
        androidx.coordinatorlayout.widget.CoordinatorLayout.LayoutParams layoutParams =
            new androidx.coordinatorlayout.widget.CoordinatorLayout.LayoutParams(
                cardHeader.getLayoutParams().width,
                cardHeader.getLayoutParams().height);
        layoutParams.setBehavior(new QuickReturnBehavior());
        cardHeader.setLayoutParams(layoutParams);
        cardHeader.addOnLayoutChangeListener(new View.OnLayoutChangeListener() {
            @Override
            public void onLayoutChange(View v, int left, int top, int right, int bottom,
                                       int oldLeft, int oldTop, int oldRight, int oldBottom) {
                int height = bottom - top;
                int extra = (int) (8 * getResources().getDisplayMetrics().density);
                scroll.setPadding(scroll.getPaddingLeft(), height + extra,
                    scroll.getPaddingRight(), scroll.getPaddingBottom());
            }
        });
    }

    public static final class QuickReturnBehavior extends androidx.coordinatorlayout.widget.CoordinatorLayout.Behavior<View> {
        @Override
        public boolean onStartNestedScroll(androidx.coordinatorlayout.widget.CoordinatorLayout coordinatorLayout,
                                           View child, View directTargetChild, View target,
                                           int nestedScrollAxes, int type) {
            return (nestedScrollAxes & androidx.core.view.ViewCompat.SCROLL_AXIS_VERTICAL)!= 0;
        }
        @Override
        public void onNestedScroll(androidx.coordinatorlayout.widget.CoordinatorLayout coordinatorLayout,
                                   View child, View target, int dxConsumed, int dyConsumed,
                                   int dxUnconsumed, int dyUnconsumed, int type) {
            float newTrans = child.getTranslationY() - dyConsumed;
            float min = -child.getHeight();
            float max = 0;
            if (newTrans < min) newTrans = min;
            if (newTrans > max) newTrans = max;
            child.setTranslationY(newTrans);
        }
    }
}
