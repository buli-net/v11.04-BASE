package wallet.ui;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.provider.MediaStore;
import android.text.method.HideReturnsTransformationMethod;
import android.text.method.PasswordTransformationMethod;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewParent;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.core.content.FileProvider;
import androidx.print.PrintHelper;

import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.base.Network;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.params.TestNet3Params;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import wallet.Constants;
import wallet.R;
import wallet.util.Qr;
import wallet.util.Bip38Helper;

public class PaperWalletActivity extends AbstractWalletActivity {
    private static final int QR_SIZE = 512;

    private View cardView;
    private ImageView qrAddressView, qrKeyView;
    private TextView addressView, privKeyView, publicLabelView, privKeyLabelView;

    private Button toggleKeyButton, privKeyFormatBtn;
    private Button toggleAddressBtn, publicFormatBtn;

    private CheckBox encryptToggle, showPassToggle;
    private EditText passView, passConfirmView;
    private TextView bip38HintView;

    private boolean keyVisible = true;
    private boolean publicVisible = true;
    private boolean privKeyHexMode = false;
    private boolean publicHexMode = false;
    private boolean bip38Mode = false;

    private String currentAddress = "";
    private String currentPubKeyHex = "";
    private String currentPrivKeyWif = "";
    private String currentPrivKeyHex = "";
    private String currentPrivKeyBip38 = "";

    private ScriptType addressType = ScriptType.P2WPKH;

    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    private String getFileProviderAuthority() {
        return getPackageName() + ".file_attachment";
    }

    @Override
    protected void onCreate(final Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_paper_wallet);

        if (getActionBar()!= null)
            getActionBar().setDisplayHomeAsUpEnabled(true);

        setTitle(R.string.paper_wallet_activity_title);

        cardView = findViewById(R.id.paper_wallet_card);
        qrAddressView = findViewById(R.id.paper_wallet_qr_address);
        qrKeyView = findViewById(R.id.paper_wallet_qr_key);
        addressView = findViewById(R.id.paper_wallet_address);
        privKeyView = findViewById(R.id.paper_wallet_key);
        publicLabelView = findViewById(R.id.paper_wallet_public_label);
        privKeyLabelView = findViewById(R.id.paper_wallet_key_label);

        encryptToggle = findViewById(R.id.paper_wallet_encrypt_toggle);
        showPassToggle = findViewById(R.id.paper_wallet_show_pass);
        passView = findViewById(R.id.paper_wallet_passphrase);
        passConfirmView = findViewById(R.id.paper_wallet_passphrase_confirm);
        bip38HintView = findViewById(R.id.paper_wallet_bip38_hint);

        if (qrAddressView!= null) qrAddressView.setScaleType(ImageView.ScaleType.FIT_CENTER);
        if (qrKeyView!= null) qrKeyView.setScaleType(ImageView.ScaleType.FIT_CENTER);

        findViewById(R.id.paper_wallet_copy_address).setOnClickListener(v -> {
            String key = publicHexMode ? currentPubKeyHex : currentAddress;
            copyText(getString(R.string.paper_wallet_public_label), key);
        });
        findViewById(R.id.paper_wallet_copy_privkey).setOnClickListener(v -> {
            String key = bip38Mode? currentPrivKeyBip38 : (privKeyHexMode? currentPrivKeyHex : currentPrivKeyWif);
            copyText(getString(R.string.paper_wallet_private_label), key);
        });

        addressView.setOnClickListener(v -> togglePublicFormat());
        privKeyView.setOnClickListener(v -> togglePrivKeyFormat());

        toggleAddressBtn = findViewById(R.id.paper_wallet_toggle_address);
        toggleAddressBtn.setOnClickListener(v -> togglePublicVisibility());

        publicFormatBtn = findViewById(R.id.paper_wallet_public_format);
        if (publicFormatBtn!= null) {
            publicFormatBtn.setOnClickListener(v -> togglePublicFormat());
        }

        toggleKeyButton = findViewById(R.id.paper_wallet_toggle_key);
        toggleKeyButton.setOnClickListener(v -> toggleKeyVisibility());

        privKeyFormatBtn = findViewById(R.id.paper_wallet_privkey_format);
        if (privKeyFormatBtn!= null) {
            privKeyFormatBtn.setOnClickListener(v -> togglePrivKeyFormat());
        }

        encryptToggle.setOnCheckedChangeListener((b, checked) -> {
            int vis = checked? View.VISIBLE : View.GONE;
            showPassToggle.setVisibility(vis);
            passView.setVisibility(vis);
            passView.setEnabled(checked);
            passConfirmView.setVisibility(vis);
            passConfirmView.setEnabled(checked);
            bip38HintView.setVisibility(vis);
            updatePrivKeyView();
        });

        showPassToggle.setOnCheckedChangeListener((b, checked) -> {
            if (checked) {
                passView.setTransformationMethod(HideReturnsTransformationMethod.getInstance());
                passConfirmView.setTransformationMethod(HideReturnsTransformationMethod.getInstance());
            } else {
                passView.setTransformationMethod(PasswordTransformationMethod.getInstance());
                passConfirmView.setTransformationMethod(PasswordTransformationMethod.getInstance());
            }
            passView.setSelection(passView.getText().length());
            passConfirmView.setSelection(passConfirmView.getText().length());
        });

        generateNew();
    }

    private Network getNetwork() {
        NetworkParameters params = Constants.NETWORK_PARAMETERS;
        String id = params.getId().toLowerCase();
        if (id.contains("regtest")) return BitcoinNetwork.REGTEST;
        if (id.contains("test") || id.contains("signet")) return BitcoinNetwork.TESTNET;
        return BitcoinNetwork.MAINNET;
    }

    private Bitmap makeQr(String text) {
        Bitmap qr = Qr.bitmap(text);
        return Bitmap.createScaledBitmap(qr, QR_SIZE, QR_SIZE, false);
    }

    private void generateNew() {
        final Network network = getNetwork();
        final boolean doBip38 = encryptToggle!= null && encryptToggle.isChecked();
        String p1 = passView!= null? passView.getText().toString() : "";
        String p2 = passConfirmView!= null? passConfirmView.getText().toString() : "";

        if (doBip38) {
            if (p1.isEmpty()) {
                Toast.makeText(this, R.string.paper_wallet_passphrase_empty, Toast.LENGTH_SHORT).show();
                return;
            }
            if (!p1.equals(p2)) {
                Toast.makeText(this, R.string.paper_wallet_passphrase_mismatch, Toast.LENGTH_SHORT).show();
                return;
            }
        }

        final ECKey key = new ECKey();

        currentAddress = key.toAddress(addressType, network).toString();
        currentPubKeyHex = key.getPublicKeyAsHex();
        NetworkParameters params = Constants.NETWORK_PARAMETERS;
        String id = params.getId().toLowerCase();
        boolean isTestOrSignet = id.contains("test") || id.contains("signet");
        NetworkParameters wifParams = isTestOrSignet ? TestNet3Params.get() : params;
        currentPrivKeyWif = key.getPrivateKeyEncoded(wifParams).toBase58();
        currentPrivKeyHex = key.getPrivateKeyAsHex();
        privKeyHexMode = false;
        publicHexMode = false;
        bip38Mode = false;
        currentPrivKeyBip38 = "";

        updatePublicView();
        updatePrivKeyView();

        if (!doBip38) {
            Toast.makeText(this, R.string.paper_wallet_generated, Toast.LENGTH_SHORT).show();
            return;
        }

        final String passphrase = p1;
        final ECKey keyFinal = key;
        Toast.makeText(this, R.string.paper_wallet_encrypting_bip38, Toast.LENGTH_SHORT).show();

        executor.execute(() -> {
            try {
                currentPrivKeyBip38 = Bip38Helper.encrypt(keyFinal, passphrase, network);
                bip38Mode = true;
                runOnUiThread(() -> {
                    updatePrivKeyView();
                    Toast.makeText(this, R.string.paper_wallet_bip38_ready, Toast.LENGTH_SHORT).show();
                });
            } catch (Exception e) {
                runOnUiThread(() -> {
                    Toast.makeText(this, getString(R.string.paper_wallet_bip38_failed, e.getMessage()), Toast.LENGTH_LONG).show();
                });
            }
        });
    }

    private void updatePublicView() {
        String base = getString(R.string.paper_wallet_public_label);
        String displayKey;
        String suffix;
        if (publicHexMode) {
            displayKey = currentPubKeyHex;
            suffix = " (" + getString(R.string.paper_wallet_public_format_hex) + ")";
        } else {
            displayKey = currentAddress;
            suffix = " (" + getString(R.string.paper_wallet_public_format_bech32) + ")";
        }

        if (publicVisible) {
            addressView.setText(displayKey);
            toggleAddressBtn.setText(R.string.paper_wallet_hide);
            toggleAddressBtn.setCompoundDrawablesWithIntrinsicBounds(0, R.drawable.ic_eye_off_24dp, 0, 0);
            if (publicFormatBtn!= null) {
                publicFormatBtn.setText(publicHexMode? R.string.paper_wallet_public_format_hex : R.string.paper_wallet_public_format_bech32);
            }
            if (publicLabelView!= null) publicLabelView.setText(base + suffix);
            if (qrAddressView!= null &&!displayKey.isEmpty()) qrAddressView.setImageBitmap(makeQr(displayKey));
            else if (qrAddressView!= null) qrAddressView.setImageBitmap(null);
        } else {
            addressView.setText("••••••••••••••••••••••••");
            toggleAddressBtn.setText(R.string.paper_wallet_show);
            toggleAddressBtn.setCompoundDrawablesWithIntrinsicBounds(0, R.drawable.ic_eye_on_24dp, 0, 0);
            if (publicLabelView!= null) publicLabelView.setText(base);
            if (qrAddressView!= null) qrAddressView.setImageBitmap(null);
        }
    }

    private void updatePrivKeyView() {
        String base = getString(R.string.paper_wallet_private_label);
        String displayKey;
        String suffix;
        if (bip38Mode &&!currentPrivKeyBip38.isEmpty()) {
            displayKey = currentPrivKeyBip38;
            suffix = " (" + getString(R.string.paper_wallet_private_format_bip38) + ")";
        } else {
            displayKey = privKeyHexMode? currentPrivKeyHex : currentPrivKeyWif;
            suffix = privKeyHexMode? " (" + getString(R.string.paper_wallet_private_format_hex) + ")" : " (" + getString(R.string.paper_wallet_private_format_wif) + ")";
        }

        if (keyVisible) {
            privKeyView.setText(displayKey);
            toggleKeyButton.setText(R.string.paper_wallet_hide_key);
            toggleKeyButton.setCompoundDrawablesWithIntrinsicBounds(0, R.drawable.ic_eye_off_24dp, 0, 0);
            if (privKeyFormatBtn!= null) {
                privKeyFormatBtn.setEnabled(!bip38Mode);
                privKeyFormatBtn.setText(bip38Mode? R.string.paper_wallet_private_format_bip38 : (privKeyHexMode? R.string.paper_wallet_private_format_hex : R.string.paper_wallet_private_format_wif));
                privKeyFormatBtn.setAlpha(bip38Mode? 0.5f : 1.0f);
            }
            if (privKeyLabelView!= null) privKeyLabelView.setText(base + suffix);
            if (qrKeyView!= null &&!displayKey.isEmpty()) qrKeyView.setImageBitmap(makeQr(displayKey));
            else if (qrKeyView!= null) qrKeyView.setImageBitmap(null);
        } else {
            privKeyView.setText("••••••••••••••••••••••••");
            toggleKeyButton.setText(R.string.paper_wallet_show_key);
            toggleKeyButton.setCompoundDrawablesWithIntrinsicBounds(0, R.drawable.ic_eye_on_24dp, 0, 0);
            if (privKeyLabelView!= null) privKeyLabelView.setText(base);
            if (qrKeyView!= null) qrKeyView.setImageBitmap(null);
        }
    }

    private void togglePublicVisibility() {
        publicVisible =!publicVisible;
        updatePublicView();
    }

    private void togglePublicFormat() {
        if (!publicVisible) return;
        publicHexMode =!publicHexMode;
        updatePublicView();
        Toast.makeText(this, getString(R.string.paper_wallet_public_format_toast, publicHexMode? "HEX" : "ADDRESS"), Toast.LENGTH_SHORT).show();
    }

    private void toggleKeyVisibility() {
        keyVisible =!keyVisible;
        updatePrivKeyView();
    }

    private void togglePrivKeyFormat() {
        if (!keyVisible || bip38Mode) return;
        privKeyHexMode =!privKeyHexMode;
        updatePrivKeyView();
        Toast.makeText(this, getString(R.string.paper_wallet_private_format_toast, privKeyHexMode? "HEX" : "WIF"), Toast.LENGTH_SHORT).show();
    }

    private void copyText(String label, String text) {
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        cm.setPrimaryClip(ClipData.newPlainText(label, text));
        Toast.makeText(this, getString(R.string.paper_wallet_copied, label), Toast.LENGTH_SHORT).show();
    }

    private Bitmap buildPrintBitmap() {
        View printView = getLayoutInflater().inflate(R.layout.paper_wallet_print, null);
        String publicForPrint = addressView.getText().toString();
        String privKeyForPrint = privKeyView.getText().toString();
        if (!publicVisible) publicForPrint = getString(R.string.paper_wallet_hidden);
        if (!keyVisible) privKeyForPrint = getString(R.string.paper_wallet_hidden);
        ((TextView) printView.findViewById(R.id.print_address)).setText(publicForPrint);
        ((TextView) printView.findViewById(R.id.print_privkey)).setText(privKeyForPrint);
        if (publicVisible && !publicForPrint.equals(getString(R.string.paper_wallet_hidden))) {
            ((ImageView) printView.findViewById(R.id.print_qr_address)).setImageBitmap(makeQr(publicForPrint));
        }
        if (keyVisible && !privKeyForPrint.equals(getString(R.string.paper_wallet_hidden))) {
            ((ImageView) printView.findViewById(R.id.print_qr_key)).setImageBitmap(makeQr(privKeyForPrint));
        }
        TextView printPublicLabel = printView.findViewById(R.id.print_public_label);
        if (printPublicLabel!= null) {
            String s = getString(R.string.paper_wallet_public_label) + (publicHexMode? " (" + getString(R.string.paper_wallet_public_format_hex) + ")" : " (" + getString(R.string.paper_wallet_public_format_bech32) + ")");
            printPublicLabel.setText(s);
        }
        TextView printPrivLabel = printView.findViewById(R.id.print_privkey_label);
        if (printPrivLabel!= null) {
            String s = getString(R.string.paper_wallet_private_label) + (bip38Mode? " (" + getString(R.string.paper_wallet_private_format_bip38) + ")" : (privKeyHexMode? " (" + getString(R.string.paper_wallet_private_format_hex) + ")" : " (" + getString(R.string.paper_wallet_private_format_wif) + ")"));
            printPrivLabel.setText(s);
        }
        int widthSpec = View.MeasureSpec.makeMeasureSpec(720, View.MeasureSpec.EXACTLY);
        int heightSpec = View.MeasureSpec.makeMeasureSpec(0, View.MeasureSpec.UNSPECIFIED);
        printView.measure(widthSpec, heightSpec);
        printView.layout(0, 0, printView.getMeasuredWidth(), printView.getMeasuredHeight());
        Bitmap bitmap = Bitmap.createBitmap(printView.getMeasuredWidth(), printView.getMeasuredHeight(), Bitmap.Config.ARGB_8888);
        Canvas canvas = new Canvas(bitmap);
        canvas.drawColor(0xFFFFFFFF);
        printView.draw(canvas);
        return bitmap;
    }

    private File getShareFile() throws Exception {
        File dir = new File(getCacheDir(), "paperwallet");
        dir.mkdirs();
        File file = new File(dir, "paperwallet_" + System.currentTimeMillis() + ".png");
        try (FileOutputStream out = new FileOutputStream(file)) {
            buildPrintBitmap().compress(Bitmap.CompressFormat.PNG, 100, out);
        }
        return file;
    }

    private void savePaperWallet() {
        try {
            Bitmap bitmap = buildPrintBitmap();
            String filename = "paperwallet_" + System.currentTimeMillis() + ".png";
            ContentValues values = new ContentValues();
            values.put(MediaStore.Images.Media.DISPLAY_NAME, filename);
            values.put(MediaStore.Images.Media.MIME_TYPE, "image/png");
            values.put(MediaStore.Images.Media.RELATIVE_PATH, Environment.DIRECTORY_PICTURES + "/PaperWallet");
            Uri uri = getContentResolver().insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, values);
            try (OutputStream out = getContentResolver().openOutputStream(uri)) {
                bitmap.compress(Bitmap.CompressFormat.PNG, 100, out);
            }
            Toast.makeText(this, getString(R.string.paper_wallet_saved, filename), Toast.LENGTH_LONG).show();
        } catch (Exception e) {
            Toast.makeText(this, getString(R.string.paper_wallet_save_failed, e.getMessage()), Toast.LENGTH_SHORT).show();
        }
    }

    private void exportWalletTxt() {
        try {
            String typeName = publicHexMode ? getString(R.string.paper_wallet_public_format_hex) : (addressType == ScriptType.P2PKH? getString(R.string.paper_wallet_public_format_legacy) : getString(R.string.paper_wallet_public_format_bech32));
            StringBuilder sb = new StringBuilder();
            sb.append(getString(R.string.paper_wallet_activity_title)).append("\n");
            sb.append(getString(R.string.paper_wallet_public_type, typeName)).append("\n");
            sb.append(getString(R.string.paper_wallet_public_label)).append(": ").append(publicVisible ? addressView.getText().toString() : getString(R.string.paper_wallet_hidden)).append("\n");
            sb.append(getString(R.string.paper_wallet_private_label)).append(": ").append(keyVisible ? privKeyView.getText().toString() : getString(R.string.paper_wallet_hidden)).append("\n");
            if (bip38Mode &&!currentPrivKeyBip38.isEmpty()) {
                sb.append(getString(R.string.paper_wallet_bip38_hint)).append("\n");
            }
            String filename = "paperwallet_" + System.currentTimeMillis() + ".txt";
            ContentValues values = new ContentValues();
            values.put(MediaStore.Files.FileColumns.DISPLAY_NAME, filename);
            values.put(MediaStore.Files.FileColumns.MIME_TYPE, "text/plain");
            values.put(MediaStore.Files.FileColumns.RELATIVE_PATH, Environment.DIRECTORY_DOCUMENTS + "/PaperWallet");
            Uri uri = getContentResolver().insert(MediaStore.Files.getContentUri("external"), values);
            try (OutputStream out = getContentResolver().openOutputStream(uri)) {
                out.write(sb.toString().getBytes(StandardCharsets.UTF_8));
            }
            Toast.makeText(this, getString(R.string.paper_wallet_exported, filename), Toast.LENGTH_LONG).show();
        } catch (Exception e) {
            Toast.makeText(this, getString(R.string.paper_wallet_export_failed, e.getMessage()), Toast.LENGTH_SHORT).show();
        }
    }

    private void sharePaperWallet() {
        try {
            File file = getShareFile();
            Uri uri = FileProvider.getUriForFile(this, getFileProviderAuthority(), file);
            Intent intent = new Intent(Intent.ACTION_SEND);
            intent.setType("image/png");
            intent.putExtra(Intent.EXTRA_STREAM, uri);
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivity(Intent.createChooser(intent, getString(R.string.paper_wallet_share)));
        } catch (Exception e) {
            Toast.makeText(this, getString(R.string.paper_wallet_share_failed, e.getMessage()), Toast.LENGTH_SHORT).show();
        }
    }

    private void printPaperWallet() {
        try {
            PrintHelper helper = new PrintHelper(this);
            helper.setScaleMode(PrintHelper.SCALE_MODE_FIT);
            helper.printBitmap(getString(R.string.paper_wallet_activity_title) + " - " + currentAddress, buildPrintBitmap());
        } catch (Exception e) {
            Toast.makeText(this, getString(R.string.paper_wallet_print_failed, e.getMessage()), Toast.LENGTH_SHORT).show();
        }
    }

    @Override
    public boolean onCreateOptionsMenu(final Menu menu) {
        getMenuInflater().inflate(R.menu.paper_wallet_options, menu);
        return true;
    }

    @Override
    public boolean onPrepareOptionsMenu(Menu menu) {
        // AUTO: chỉ trắng chữ đang nằm thật trên bar, không đụng popup 3 chấm
        final int white = Color.WHITE;
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
                        // tìm TextView con
                        findAndWhiteText(itemView, white);
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
    public boolean onOptionsItemSelected(final MenuItem item) {
        int id = item.getItemId();
        if (id == android.R.id.home) {
            finish();
            return true;
        } else if (id == R.id.paper_wallet_options_refresh) {
            generateNew();
            return true;
        } else if (id == R.id.paper_wallet_options_save) {
            savePaperWallet();
            return true;
        } else if (id == R.id.paper_wallet_options_share) {
            sharePaperWallet();
            return true;
        } else if (id == R.id.paper_wallet_options_print) {
            printPaperWallet();
            return true;
        } else if (id == R.id.paper_wallet_options_export) {
            exportWalletTxt();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        executor.shutdownNow();
    }
}
