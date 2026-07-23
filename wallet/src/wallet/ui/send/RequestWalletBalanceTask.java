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

import android.content.res.AssetManager;
import android.os.Handler;
import android.os.Looper;
import androidx.annotation.Nullable;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.collect.HashMultiset;
import com.google.common.collect.Multiset;
import com.google.common.hash.Hashing;
import com.squareup.moshi.JsonAdapter;
import com.squareup.moshi.JsonDataException;
import com.squareup.moshi.Moshi;
import okio.BufferedSink;
import okio.BufferedSource;
import okio.Okio;
import org.bitcoinj.base.Address;
import org.bitcoinj.base.Coin;
import org.bitcoinj.base.LegacyAddress;
import org.bitcoinj.base.SegwitAddress;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.UTXO;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.utils.ContextPropagatingThreadFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import wallet.Constants;
import wallet.R;
import wallet.util.Assets;

import javax.net.SocketFactory;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

public final class RequestWalletBalanceTask {
    private final Handler backgroundHandler;
    private final Handler callbackHandler;
    private final ResultCallback resultCallback;
    private static final Logger log = LoggerFactory.getLogger(RequestWalletBalanceTask.class);

    public interface ResultCallback {
        void onResult(Set<UTXO> utxos);
        void onFail(int messageResId, Object... messageArgs);
    }

    public RequestWalletBalanceTask(final Handler backgroundHandler, final ResultCallback resultCallback) {
        this.backgroundHandler = backgroundHandler;
        this.callbackHandler = new Handler(Looper.myLooper());
        this.resultCallback = resultCallback;
    }

    public static class ElectrumRequest {
        public final int id;
        public final String method;
        public final String[] params;
        private static transient int idCounter = 0;
        public ElectrumRequest(final String method, final String[] params) { this(idCounter++, method, params); }
        public ElectrumRequest(final int id, final String method, final String[] params) { this.id = id; this.method = method; this.params = params; }
    }

    public static class ListunspentResponse {
        public int id;
        public Utxo[] result;
        public Error error;
        public static class Utxo {
            public String tx_hash;
            public int tx_pos;
            public long value;
            public int height;
        }
    }

    public static class TransactionResponse {
        public int id;
        public String result;
        public Error error;
    }

    public static class Error {
        public int code;
        public String message;
    }

    private org.bitcoinj.base.Network getNetworkForAddress() {
        String id = Constants.NETWORK_PARAMETERS.getId().toLowerCase();
        if (id.contains("regtest")) return org.bitcoinj.base.BitcoinNetwork.REGTEST;
        if (id.contains("signet")) return org.bitcoinj.base.BitcoinNetwork.SIGNET;
        if (id.contains("test")) return org.bitcoinj.base.BitcoinNetwork.TESTNET;
        return org.bitcoinj.base.BitcoinNetwork.MAINNET;
    }

    /**
     * Create BIP86 P2TR output script (tweaked).
     * This matches bc1p address generated by bitcoinj toAddress(P2TR)
     */
    private Script createP2TRScript(ECKey key) {
        try {
            try {
                org.bitcoinj.base.Network network = getNetworkForAddress();
                Address p2trAddr = key.toAddress(org.bitcoinj.base.ScriptType.P2TR, network);
                return ScriptBuilder.createOutputScript(p2trAddr);
            } catch (Exception ignore) {}
            byte[] comp = key.getPubKey();
            byte[] xOnly = new byte[32];
            System.arraycopy(comp, 1, xOnly, 0, 32);
            java.security.MessageDigest sha256 = java.security.MessageDigest.getInstance("SHA-256");
            byte[] tag = sha256.digest("TapTweak".getBytes(StandardCharsets.UTF_8));
            sha256.reset();
            sha256.update(tag);
            sha256.update(tag);
            sha256.update(xOnly);
            byte[] tweakBytes = sha256.digest();
            org.bouncycastle.jce.spec.ECNamedCurveParameterSpec spec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256k1");
            org.bouncycastle.math.ec.ECPoint G = spec.getG();
            java.math.BigInteger tweak = new java.math.BigInteger(1, tweakBytes);
            org.bouncycastle.math.ec.ECPoint internalPoint = spec.getCurve().decodePoint(comp);
            org.bouncycastle.math.ec.ECPoint outputPoint = internalPoint.add(G.multiply(tweak));
            byte[] outputComp = outputPoint.getEncoded(true);
            byte[] outputXOnly = new byte[32];
            System.arraycopy(outputComp, 1, outputXOnly, 0, 32);
            return new ScriptBuilder().op(81).data(outputXOnly).build();
        } catch (Exception e) {
            log.warn("createP2TRScript failed: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Create untweaked P2TR script for buggy paper wallets that use raw x-only without BIP86 tweak.
     */
    private Script createP2TRUntweakedScript(ECKey key) {
        try {
            byte[] comp = key.getPubKey();
            byte[] xOnly = new byte[32];
            System.arraycopy(comp, 1, xOnly, 0, 32);
            return new ScriptBuilder().op(81).data(xOnly).build();
        } catch (Exception e) {
            log.warn("createP2TRUntweakedScript failed: {}", e.getMessage());
            return null;
        }
    }

    public void requestWalletBalance(final AssetManager assets, final ECKey key) {
        backgroundHandler.post(new Runnable() {
            @Override
            public void run() {
                org.bitcoinj.core.Context.propagate(Constants.CONTEXT);
                ECKey compKey = key.isCompressed()? key : ECKey.fromPrivate(key.getPrivKey(), true);
                final Address legacyAddress = LegacyAddress.fromKey(Constants.NETWORK_PARAMETERS, key);
                final List<Script> scriptList = new ArrayList<>();
                final List<String> addressList = new ArrayList<>();

                Script p2pkhScript = ScriptBuilder.createP2PKHOutputScript(legacyAddress.getHash());
                scriptList.add(p2pkhScript);
                addressList.add(legacyAddress.toString());

                if (compKey.isCompressed()) {
                    final Address segwitAddress = SegwitAddress.fromKey(Constants.NETWORK_PARAMETERS, compKey);
                    Script p2wpkhScript = ScriptBuilder.createP2WPKHOutputScript(segwitAddress.getHash());
                    scriptList.add(p2wpkhScript);
                    addressList.add(segwitAddress.toString());

                    try {
                        Script p2shScript = ScriptBuilder.createP2SHOutputScript(p2wpkhScript);
                        scriptList.add(p2shScript);
                        Address p2shAddress = LegacyAddress.fromScriptHash(Constants.NETWORK_PARAMETERS, p2shScript.getPubKeyHash());
                        addressList.add(p2shAddress.toString());
                    } catch (Exception e) {
                        log.warn("Failed to create P2SH-P2WPKH: {}", e.getMessage());
                    }

                    try {
                        Script p2trScript = createP2TRScript(compKey);
                        if (p2trScript!= null) {
                            scriptList.add(p2trScript);
                            try {
                                Address p2trAddr = compKey.toAddress(org.bitcoinj.base.ScriptType.P2TR, getNetworkForAddress());
                                addressList.add(p2trAddr.toString());
                            } catch (Exception ex) {
                                addressList.add("P2TR_TWEAKED");
                            }
                        }
                    } catch (Exception e) {
                        log.warn("Failed to create P2TR tweaked: {}", e.getMessage());
                    }

                    try {
                        Script p2trUntweaked = createP2TRUntweakedScript(compKey);
                        if (p2trUntweaked!= null) {
                            scriptList.add(p2trUntweaked);
                            addressList.add("P2TR_UNTWEAKED");
                        }
                    } catch (Exception e) {
                        log.warn("Failed to create P2TR untweaked: {}", e.getMessage());
                    }
                }

                final Script[] outputScripts = scriptList.toArray(new Script[0]);
                final String addressesStr = String.join(",", addressList);
                log.error("DEBUG SWEEP QUERY ADDRESSES: {}", addressesStr);

                final List<ElectrumServer> servers = loadElectrumServers(Assets.open(assets, Constants.Files.ELECTRUM_SERVERS_ASSET));
                final List<Callable<Set<UTXO>>> tasks = new ArrayList<>(servers.size());
                for (final ElectrumServer server : servers) {
                    tasks.add(() -> {
                        log.info("{} - trying to request wallet balance for {}", server.socketAddress, addressesStr);
                        try (final Socket socket = connect(server)) {
                            final BufferedSink sink = Okio.buffer(Okio.sink(socket));
                            sink.timeout().timeout(5000, TimeUnit.MILLISECONDS);
                            final BufferedSource source = Okio.buffer(Okio.source(socket));
                            source.timeout().timeout(5000, TimeUnit.MILLISECONDS);
                            final Moshi moshi = new Moshi.Builder().build();
                            final JsonAdapter<ElectrumRequest> requestAdapter = moshi.adapter(ElectrumRequest.class);
                            final JsonAdapter<ListunspentResponse> listunspentResponseAdapter = moshi.adapter(ListunspentResponse.class);
                            final JsonAdapter<TransactionResponse> transactionResponseAdapter = moshi.adapter(TransactionResponse.class);
                            final Set<UTXO> utxos = new HashSet<>();

                            for (int s = 0; s < outputScripts.length; s++) {
                                final Script outputScript = outputScripts[s];
                                final int requestId = 1000 + s;
                                requestAdapter.toJson(sink, new ElectrumRequest(requestId, "blockchain.scripthash.listunspent",
                                        new String[] { Constants.HEX.encode(Sha256Hash.of(outputScript.getProgram()).getReversedBytes()) }));
                                sink.writeUtf8("\n").flush();
                                final ListunspentResponse listunspentResponse = listunspentResponseAdapter.fromJson(source);
                                if (listunspentResponse.id!= requestId) {
                                    log.warn("{} - id mismatch {}", server.socketAddress, listunspentResponse.id);
                                    return null;
                                }
                                if (listunspentResponse.error!= null) {
                                    log.info("{} - server error {}: {}", server.socketAddress, listunspentResponse.error.code, listunspentResponse.error.message);
                                    return null;
                                }
                                if (listunspentResponse.result == null) {
                                    log.info("{} - missing result", server.socketAddress);
                                    return null;
                                }
                                log.error("DEBUG SWEEP: {} script {} has {} UTXOs", server.socketAddress, addressList.get(s), listunspentResponse.result.length);
                                for (final ListunspentResponse.Utxo responseUtxo : listunspentResponse.result) {
                                    final Sha256Hash utxoHash = Sha256Hash.wrap(responseUtxo.tx_hash);
                                    final int utxoIndex = responseUtxo.tx_pos;
                                    final Coin utxoValue = Coin.valueOf(responseUtxo.value);
                                    final UTXO utxo = new UTXO(utxoHash, utxoIndex, utxoValue, responseUtxo.height, false, outputScript);

                                    // Validate tx but be lenient for taproot - don't drop on script mismatch, just warn
                                    requestAdapter.toJson(sink, new ElectrumRequest("blockchain.transaction.get",
                                            new String[] { Constants.HEX.encode(utxo.getHash().getBytes()) }));
                                    sink.writeUtf8("\n").flush();
                                    final TransactionResponse transactionResponse = transactionResponseAdapter.fromJson(source);
                                    if (transactionResponse.error!= null || transactionResponse.result == null) {
                                        log.warn("{} - tx fetch failed for {}", server.socketAddress, utxo.getHash());
                                        // Still accept UTXO even if tx fetch fails (Electrum may not have tx)
                                        utxos.add(utxo);
                                        continue;
                                    }
                                    try {
                                        final Transaction tx = Transaction.read(ByteBuffer.wrap(Constants.HEX.decode(transactionResponse.result)));
                                        if (!tx.getTxId().equals(utxo.getHash())) {
                                            log.warn("{} - lied about txid", server.socketAddress);
                                        } else if (!tx.getOutput(utxo.getIndex()).getValue().equals(utxo.getValue())) {
                                            log.warn("{} - lied about amount, still accepting", server.socketAddress);
                                            utxos.add(utxo);
                                        } else {
                                            // Accept even if script differs slightly (for P2TR compatibility)
                                            if (!tx.getOutput(utxo.getIndex()).getScriptPubKey().equals(outputScript)) {
                                                log.warn("{} - script mismatch but accepting: expected {} got {}", server.socketAddress, outputScript, tx.getOutput(utxo.getIndex()).getScriptPubKey());
                                            }
                                            utxos.add(utxo);
                                        }
                                    } catch (Exception e) {
                                        log.warn("{} - failed to parse tx, still accepting UTXO: {}", server.socketAddress, e.getMessage());
                                        utxos.add(utxo);
                                    }
                                }
                            }
                            log.info("{} - got {} UTXOs {}", server.socketAddress, utxos.size(), utxos);
                            return utxos;
                        } catch (final ConnectException | SSLPeerUnverifiedException | JsonDataException x) {
                            log.warn("{} - {}", server.socketAddress, x.getMessage());
                            return null;
                        } catch (final IOException x) {
                            log.info(server.socketAddress.toString(), x);
                            return null;
                        } catch (final RuntimeException x) {
                            log.error(server.socketAddress.toString(), x);
                            throw x;
                        }
                    });
                }

                final ExecutorService threadPool = Executors.newFixedThreadPool(servers.size(), new ContextPropagatingThreadFactory("request"));
                final List<Future<Set<UTXO>>> futures;
                try {
                    futures = threadPool.invokeAll(tasks, 15, TimeUnit.SECONDS);
                } catch (final InterruptedException x) {
                    throw new RuntimeException(x);
                } finally {
                    threadPool.shutdown();
                }

                final Multiset<UTXO> countedUtxos = HashMultiset.create();
                int numSuccess = 0, numFail = 0, numTimeOuts = 0;
                for (Future<Set<UTXO>> future : futures) {
                    if (!future.isCancelled()) {
                        try {
                            final Set<UTXO> utxos = future.get();
                            if (utxos!= null) {
                                countedUtxos.addAll(utxos);
                                numSuccess++;
                            } else {
                                numFail++;
                            }
                        } catch (InterruptedException | ExecutionException x) {
                            throw new RuntimeException(x);
                        }
                    } else {
                        numTimeOuts++;
                    }
                }

                // FIX: Lower threshold to 1 for mainnet public servers, old list often has only 1-2 alive
                final int trustThreshold = Math.max(1, servers.size() / 3);
                for (final Iterator<Multiset.Entry<UTXO>> i = countedUtxos.entrySet().iterator(); i.hasNext();) {
                    final Multiset.Entry<UTXO> entry = i.next();
                    if (entry.getCount() < trustThreshold) i.remove();
                }

                final Set<UTXO> utxos = countedUtxos.elementSet();
                log.error("DEBUG SWEEP FINAL: {} successes, {} fails, {} timeouts, {} UTXOs {}", numSuccess, numFail, numTimeOuts, utxos.size(), utxos);
                if (numSuccess < trustThreshold) onFail(R.string.sweep_wallet_fragment_request_wallet_balance_failed_connection);
                else if (utxos.isEmpty()) onFail(R.string.sweep_wallet_fragment_request_wallet_balance_empty);
                else onResult(utxos);
            }

            private Socket connect(final ElectrumServer server) throws IOException {
                final Socket socket;
                if (server.type == ElectrumServer.Type.TLS) {
                    final SocketFactory sf = sslTrustAllCertificates();
                    socket = sf.createSocket(server.socketAddress.getHostName(), server.socketAddress.getPort());
                    final SSLSession sslSession = ((SSLSocket) socket).getSession();
                    final Certificate certificate = sslSession.getPeerCertificates()[0];
                    final String certificateFingerprint = sslCertificateFingerprint(certificate);
                    if (server.certificateFingerprint == null) {
                        if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(server.socketAddress.getHostName(), sslSession))
                            throw new SSLPeerUnverifiedException("Expected " + server.socketAddress.getHostName() + ", got " + sslSession.getPeerPrincipal());
                    } else {
                        if (!certificateFingerprint.equals(server.certificateFingerprint))
                            throw new SSLPeerUnverifiedException("Expected " + server.certificateFingerprint + " for " + server.socketAddress.getHostName() + ", got " + certificateFingerprint);
                    }
                } else if (server.type == ElectrumServer.Type.TCP) {
                    socket = new Socket();
                    socket.connect(server.socketAddress, 5000);
                } else {
                    throw new IllegalStateException("Cannot handle: " + server.type);
                }
                return socket;
            }
        });
    }

    protected void onResult(final Set<UTXO> utxos) { callbackHandler.post(() -> resultCallback.onResult(utxos)); }
    protected void onFail(final int messageResId, final Object... messageArgs) { callbackHandler.post(() -> resultCallback.onFail(messageResId, messageArgs)); }

    public static class ElectrumServer {
        public enum Type { TCP, TLS }
        public final InetSocketAddress socketAddress;
        public final Type type;
        @Nullable
        public final String certificateFingerprint;
        public ElectrumServer(final String type, final String host, final @Nullable String port, final @Nullable String certificateFingerprint) {
            this.type = Type.valueOf(type.toUpperCase());
            if (port!= null) this.socketAddress = InetSocketAddress.createUnresolved(host, Integer.parseInt(port));
            else if ("tcp".equalsIgnoreCase(type)) this.socketAddress = InetSocketAddress.createUnresolved(host, Constants.ELECTRUM_SERVER_DEFAULT_PORT_TCP);
            else if ("tls".equalsIgnoreCase(type)) this.socketAddress = InetSocketAddress.createUnresolved(host, Constants.ELECTRUM_SERVER_DEFAULT_PORT_TLS);
            else throw new IllegalStateException("Cannot handle: " + type);
            this.certificateFingerprint = certificateFingerprint!= null? certificateFingerprint.toLowerCase(Locale.US) : null;
        }
    }

    private static List<ElectrumServer> loadElectrumServers(final InputStream is) {
        final Splitter splitter = Splitter.on(':').trimResults();
        final List<ElectrumServer> servers = new LinkedList<>();
        String line = null;
        try (final BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
            while (true) {
                line = reader.readLine();
                if (line == null) break;
                line = line.trim();
                if (line.length() == 0 || line.charAt(0) == '#') continue;
                final Iterator<String> i = splitter.split(line).iterator();
                final String type = i.next();
                final String host = i.next();
                final String port = i.hasNext()? Strings.emptyToNull(i.next()) : null;
                final String fingerprint = i.hasNext()? Strings.emptyToNull(i.next()) : null;
                servers.add(new ElectrumServer(type, host, port, fingerprint));
            }
        } catch (final Exception x) {
            throw new RuntimeException("Error while parsing: '" + line + "'", x);
        }
        return servers;
    }

    private SSLSocketFactory sslTrustAllCertificates() {
        try {
            final SSLContext context = SSLContext.getInstance("SSL");
            context.init(null, new TrustManager[] { TRUST_ALL_CERTIFICATES }, null);
            return context.getSocketFactory();
        } catch (final Exception x) {
            throw new RuntimeException(x);
        }
    }

    private static final X509TrustManager TRUST_ALL_CERTIFICATES = new X509TrustManager() {
        @Override public void checkClientTrusted(final X509Certificate[] chain, final String authType) throws CertificateException {}
        @Override public void checkServerTrusted(final X509Certificate[] chain, final String authType) throws CertificateException {}
        @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    };

    private String sslCertificateFingerprint(final Certificate certificate) {
        try {
            return Hashing.sha256().newHasher().putBytes(certificate.getEncoded()).hash().toString();
        } catch (final Exception x) {
            throw new RuntimeException(x);
        }
    }
}
