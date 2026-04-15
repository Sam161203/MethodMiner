import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

public final class JsonRpcCollector implements HttpHandler, AutoCloseable {
    private static final long REQUEST_TTL_MILLIS = 30_000L;
    private static final long UI_NOTIFICATION_INTERVAL_MILLIS = 500L;

    private final MontoyaApi api;
    private final StorageManager storageManager;
    private final JsonRpcIndex index;
    private final AuthContextStore authContextStore;
    private final JsonRpcParser parser;

    private final ConcurrentHashMap<Integer, PendingExchange> pendingExchanges = new ConcurrentHashMap<>();
    private final ExecutorService workerExecutor = Executors.newSingleThreadExecutor(r -> new Thread(r, "jsonrpc-collector-worker"));
    private final ScheduledExecutorService sweeperExecutor = Executors.newSingleThreadScheduledExecutor(r -> new Thread(r, "jsonrpc-collector-sweeper"));
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();
    private final List<RecordListener> recordListeners = new CopyOnWriteArrayList<>();
    private final List<Runnable> resetListeners = new CopyOnWriteArrayList<>();

    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final AtomicLong lastUiNotificationEpochMillis = new AtomicLong(0L);

    public JsonRpcCollector(
            MontoyaApi api,
            StorageManager storageManager,
            JsonRpcIndex index,
            AuthContextStore authContextStore,
            ObjectMapper objectMapper
    ) {
        this.api = Objects.requireNonNull(api, "api must not be null");
        this.storageManager = Objects.requireNonNull(storageManager, "storageManager must not be null");
        this.index = Objects.requireNonNull(index, "index must not be null");
        this.authContextStore = Objects.requireNonNull(authContextStore, "authContextStore must not be null");
        // Use a conservative default for "large response" filtering in the UI.
        this.parser = new JsonRpcParser(Objects.requireNonNull(objectMapper, "objectMapper must not be null"), 10 * 1024);

        sweeperExecutor.scheduleAtFixedRate(this::flushStalePendingRequests, 5, 5, TimeUnit.SECONDS);
    }

    public void registerIndexUpdateListener(Runnable listener) {
        if (listener != null) {
            listeners.add(listener);
        }
    }

    public void registerRecordListener(RecordListener listener) {
        if (listener != null) {
            recordListeners.add(listener);
        }
    }

    public void registerResetListener(Runnable listener) {
        if (listener != null) {
            resetListeners.add(listener);
        }
    }

    public JsonRpcIndex index() {
        return index;
    }

    public StorageManager storageManager() {
        return storageManager;
    }

    public void warmIndexFromDiskAsync() {
        if (closed.get()) {
            return;
        }

        workerExecutor.submit(() -> {
            final int[] replayCount = {0};
            storageManager.replayRawRecords(new StorageManager.RecordReplayListener() {
                @Override
                public void onRecord(JsonRpcRecord record) {
                    try {
                        if (!MyGeotabScope.isAllowedUrl(record.request().url())) {
                            return;
                        }
                        JsonRpcNormalizedRecord normalizedRecord = parser.normalize(record);
                        AuthContextStore.AuthContext context = authContextStore.observeRecord(record, normalizedRecord.methodName());
                        index.addRecord(normalizedRecord, record, context.contextKey());
                        logContextAndStore(context.contextKey(), normalizedRecord.methodName());
                        notifyRecordListeners(record, normalizedRecord, true);
                        replayCount[0]++;
                        if (replayCount[0] % 250 == 0) {
                            notifyListeners();
                        }
                    } catch (Exception ex) {
                        storageManager.appendError(new StorageManager.ErrorRecord(
                                Instant.now(),
                                record.messageId(),
                                record.request().url(),
                                "replay-normalize-error",
                                ex.getMessage(),
                                snippet(record.request().bodyText())
                        ));
                    }
                }

                @Override
                public void onError(int lineNumber, String lineContent, Exception exception) {
                    storageManager.appendError(new StorageManager.ErrorRecord(
                            Instant.now(),
                            null,
                            "",
                            "replay-parse-error",
                            "Line " + lineNumber + ": " + exception.getMessage(),
                            snippet(lineContent)
                    ));
                }
            });

            notifyListeners();
        });
    }

    public void resetAllData() {
        if (closed.get()) {
            return;
        }

        Future<?> future = workerExecutor.submit(() -> {
            pendingExchanges.clear();
            index.clear();
            storageManager.resetAll();
            for (Runnable listener : resetListeners) {
                try {
                    listener.run();
                } catch (Exception ex) {
                    api.logging().logToError("Reset listener failed.", ex);
                }
            }
        });

        waitForFuture(future, "reset collector state");
        notifyListeners();
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        if (closed.get()) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        if (!"POST".equalsIgnoreCase(safeMethod(requestToBeSent))) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        if (!MyGeotabScope.isAllowedUrl(safeUrl(requestToBeSent))) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        try {
            HttpRequest requestCopy = requestToBeSent.copyToTempFile();
            PendingExchange pending = new PendingExchange(
                    requestToBeSent.messageId(),
                    Instant.now(),
                    safeToolName(requestToBeSent.toolSource().toolType()),
                    requestCopy,
                    null
            );
            pendingExchanges.put(requestToBeSent.messageId(), pending);
        } catch (Exception ex) {
            api.logging().logToError("Failed to snapshot outgoing request for JSON-RPC collector.", ex);
        }

        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        if (closed.get()) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        PendingExchange fallbackPending = pendingExchanges.remove(responseReceived.messageId());

        HttpRequest associatedRequest = safeInitiatingRequest(responseReceived);
        String requestSource = "response.initiatingRequest";
        if ((associatedRequest == null || safeBodyText(associatedRequest).isBlank() || safeUrl(associatedRequest).isBlank())
                && fallbackPending != null
                && fallbackPending.request != null
            && (!safeBodyText(fallbackPending.request).isBlank() || !safeUrl(fallbackPending.request).isBlank())) {
            associatedRequest = fallbackPending.request;
            requestSource = "request.fallbackPending";
        }

        api.logging().logToOutput("[LogicHunter][HTTP-IN] "
                + safeMethod(associatedRequest)
                + " "
                + safePath(associatedRequest));
        logPipeline("response-received",
                safeMethod(associatedRequest),
                safeUrl(associatedRequest),
                "source=" + requestSource + " bodyLen=" + safeBodyText(associatedRequest).length());

        if (associatedRequest == null) {
            logSkip("missing-associated-request", "", "");
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        if (!"POST".equalsIgnoreCase(safeMethod(associatedRequest))) {
            logSkip("non-post", safeMethod(associatedRequest), safeUrl(associatedRequest));
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        if (!MyGeotabScope.isAllowedUrl(safeUrl(associatedRequest))) {
            logSkip("out-of-scope", safeMethod(associatedRequest), safeUrl(associatedRequest));
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        try {
            HttpRequest requestCopy = associatedRequest.copyToTempFile();
            PendingExchange pending = new PendingExchange(
                    responseReceived.messageId(),
                    fallbackPending == null ? Instant.now() : fallbackPending.timestamp,
                    safeToolName(responseReceived.toolSource().toolType()),
                    requestCopy,
                    responseReceived.copyToTempFile()
            );
            workerExecutor.submit(() -> processPendingExchange(pending));
        } catch (Exception ex) {
            api.logging().logToError("Failed to snapshot incoming request/response for JSON-RPC collector.", ex);
        }

        return ResponseReceivedAction.continueWith(responseReceived);
    }

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }

        sweeperExecutor.shutdown();

        List<PendingExchange> remaining = new ArrayList<>(pendingExchanges.values());
        pendingExchanges.clear();
        for (PendingExchange pending : remaining) {
            workerExecutor.submit(() -> processPendingExchange(pending));
        }

        workerExecutor.shutdown();
        try {
            if (!workerExecutor.awaitTermination(20, TimeUnit.SECONDS)) {
                workerExecutor.shutdownNow();
            }
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            workerExecutor.shutdownNow();
        }

        storageManager.close();
    }

    private void processPendingExchange(PendingExchange pending) {
        try {
            JsonRpcRecord record = buildRawRecord(pending);
            logPipeline("record-built", record.request().httpMethod(), record.request().url(),
                    "bodyLen=" + safeValue(record.request().bodyText()).length());

            if (!MyGeotabScope.isAllowedUrl(record.request().url())) {
                logSkip("out-of-scope", record.request().httpMethod(), record.request().url());
                return;
            }
            JsonRpcParser.ProbeResult probe = parser.probeRequestBody(record.request().bodyText());
            logPipeline("probe", record.request().httpMethod(), record.request().url(),
                    "kind=" + probe.kind() + " reason=" + probe.reason());

            if (probe.isMalformedJson()) {
                logSkip("parse-failed", record.request().httpMethod(), record.request().url());
                storageManager.appendError(new StorageManager.ErrorRecord(
                        Instant.now(),
                        record.messageId(),
                        record.request().url(),
                        "malformed-json",
                        probe.error(),
                        snippet(record.request().bodyText())
                ));
                return;
            }

            if (!probe.isCandidate()) {
                String skipReason = classifySkipReason(probe.reason());
                logSkip(skipReason, record.request().httpMethod(), record.request().url());
                return;
            }

            storageManager.appendRaw(record);

            List<JsonRpcNormalizedRecord> normalizedRecords = parser.normalizeAll(record);
            if (normalizedRecords.isEmpty()) {
                logSkip("missing-method", record.request().httpMethod(), record.request().url());
                return;
            }

            for (JsonRpcNormalizedRecord normalized : normalizedRecords) {
                AuthContextStore.AuthContext context = authContextStore.observeRecord(record, normalized.methodName());
                String contextKey = context.contextKey();
                logContext(context);
                storageManager.appendNormalized(normalized);
                index.addRecord(normalized, record, contextKey);
                logStore(contextKey, normalized.methodName());
                notifyRecordListeners(record, normalized, false);
                logParsed(normalized.methodName());
            }

            JsonRpcIndex.Stats stats = index.snapshotStats();
            logPipeline("indexed", record.request().httpMethod(), record.request().url(),
                    "records=" + stats.totalRecords() + " methods=" + stats.distinctMethods());

            notifyListenersThrottled();
        } catch (JsonProcessingException ex) {
            logSkip("parse-failed", safeMethod(pending.request), safeUrl(pending.request));
            storageManager.appendError(new StorageManager.ErrorRecord(
                    Instant.now(),
                    pending.messageId,
                    safeUrl(pending.request),
                    "normalize-error",
                    ex.getOriginalMessage(),
                    snippet(safeBodyText(pending.request))
            ));
        } catch (Exception ex) {
            api.logging().logToError("Unexpected collector pipeline failure.", ex);
        }
    }

    private JsonRpcRecord buildRawRecord(PendingExchange pending) {
        HttpRequest request = pending.request;
        HttpResponse response = pending.response;

        JsonRpcRecord.RequestData requestData = JsonRpcRecord.RequestData.fromCaptured(
                safeUrl(request),
                safeMethod(request),
                headersToStrings(request.headers()),
                safeBodyText(request),
                request.body().getBytes(),
                request.toString(),
                request.toByteArray().getBytes()
        );

        JsonRpcRecord.ResponseData responseData = response == null
                ? JsonRpcRecord.ResponseData.missing()
                : JsonRpcRecord.ResponseData.fromCaptured(
                (int) response.statusCode(),
                headersToStrings(response.headers()),
                safeBodyText(response),
                response.body().getBytes(),
                response.toString(),
                response.toByteArray().getBytes()
        );

        return new JsonRpcRecord(
                null,
                pending.messageId,
                pending.timestamp,
                pending.toolName,
                requestData,
                responseData
        );
    }

    private void flushStalePendingRequests() {
        if (closed.get()) {
            return;
        }

        long cutoff = System.currentTimeMillis() - REQUEST_TTL_MILLIS;
        for (Map.Entry<Integer, PendingExchange> entry : pendingExchanges.entrySet()) {
            PendingExchange pending = entry.getValue();
            if (pending.timestamp.toEpochMilli() <= cutoff && pendingExchanges.remove(entry.getKey(), pending)) {
                workerExecutor.submit(() -> processPendingExchange(pending));
            }
        }
    }

    private void notifyListenersThrottled() {
        long now = System.currentTimeMillis();
        long previous = lastUiNotificationEpochMillis.get();
        if (now - previous < UI_NOTIFICATION_INTERVAL_MILLIS) {
            return;
        }
        if (lastUiNotificationEpochMillis.compareAndSet(previous, now)) {
            notifyListeners();
        }
    }

    private void notifyListeners() {
        for (Runnable listener : listeners) {
            try {
                listener.run();
            } catch (Exception ex) {
                api.logging().logToError("UI listener failed.", ex);
            }
        }
    }

    private void notifyRecordListeners(JsonRpcRecord rawRecord, JsonRpcNormalizedRecord normalizedRecord, boolean replayed) {
        for (RecordListener listener : recordListeners) {
            try {
                listener.onRecord(rawRecord, normalizedRecord, replayed);
            } catch (Exception ex) {
                api.logging().logToError("Record listener failed.", ex);
            }
        }
    }

    private void waitForFuture(Future<?> future, String description) {
        try {
            future.get(20, TimeUnit.SECONDS);
        } catch (Exception ex) {
            api.logging().logToError("Failed to " + description + ".", ex);
        }
    }

    private static String safeUrl(HttpRequest request) {
        if (request == null) {
            return "";
        }
        try {
            String direct = request.url();
            if (direct != null && !direct.isBlank()) {
                return direct;
            }
        } catch (Exception ignored) {
            // Fall through to reconstruction.
        }

        String reconstructed = reconstructUrlFromRequest(request);
        return reconstructed == null ? "" : reconstructed;
    }

    private static String safeMethod(HttpRequest request) {
        if (request == null) {
            return "";
        }
        try {
            String method = request.method();
            if (method != null && !method.isBlank()) {
                return method;
            }
        } catch (Exception ignored) {
            // Fall through to raw extraction.
        }

        String rawLine = firstRequestLine(safeRawHttp(request));
        if (!rawLine.isBlank()) {
            String[] parts = rawLine.split("\\s+");
            if (parts.length >= 1) {
                return parts[0].trim();
            }
        }

        return "";
    }

    private static String safePath(HttpRequest request) {
        String fromUrl = safePath(safeUrl(request));
        if (!fromUrl.isBlank()) {
            return fromUrl;
        }

        String requestPath = safeRequestPath(request);
        return normalizePathCandidate(requestPath);
    }

    private static String safePath(String url) {
        if (url == null || url.isBlank()) {
            return "";
        }

        if (url.startsWith("/")) {
            return url;
        }

        try {
            URI uri = URI.create(url);
            String path = uri.getRawPath();
            if (path == null || path.isBlank()) {
                path = "/";
            }
            if (uri.getRawQuery() != null && !uri.getRawQuery().isBlank()) {
                path += "?" + uri.getRawQuery();
            }
            return path;
        } catch (Exception ignored) {
            return normalizePathCandidate(url);
        }
    }

    private static String reconstructUrlFromRequest(HttpRequest request) {
        if (request == null) {
            return "";
        }

        String host = hostFromRequest(request);
        if (host.isBlank()) {
            host = hostFromRawHttp(safeRawHttp(request));
        }
        if (host.isBlank()) {
            return "";
        }

        boolean secure = true;
        try {
            HttpService service = request.httpService();
            if (service != null) {
                secure = service.secure();
            }
        } catch (Exception ignored) {
            // Keep default scheme.
        }

        String path = normalizePathCandidate(safeRequestPath(request));
        if (path.isBlank()) {
            path = "/";
        }
        if (!path.startsWith("/")) {
            path = "/" + path;
        }

        String scheme = secure ? "https" : "http";
        return scheme + "://" + host + path;
    }

    private static String safeRequestPath(HttpRequest request) {
        if (request == null) {
            return "";
        }

        try {
            String path = request.path();
            if (path != null && !path.isBlank()) {
                return path;
            }
        } catch (Exception ignored) {
            // Fall through to raw extraction.
        }

        String rawLine = firstRequestLine(safeRawHttp(request));
        if (!rawLine.isBlank()) {
            String[] parts = rawLine.split("\\s+");
            if (parts.length >= 2) {
                return parts[1].trim();
            }
        }

        return "";
    }

    private static String normalizePathCandidate(String candidate) {
        if (candidate == null || candidate.isBlank()) {
            return "";
        }

        String trimmed = candidate.trim();
        if (trimmed.startsWith("/")) {
            return trimmed;
        }

        if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
            return safePath(trimmed);
        }

        return "/" + trimmed;
    }

    private static String hostFromRequest(HttpRequest request) {
        if (request == null) {
            return "";
        }

        try {
            HttpService service = request.httpService();
            if (service != null && service.host() != null && !service.host().isBlank()) {
                return service.host().trim();
            }
        } catch (Exception ignored) {
            // Continue with header extraction.
        }

        try {
            String host = request.headerValue("Host");
            if (host != null && !host.isBlank()) {
                return host.trim();
            }
        } catch (Exception ignored) {
            // Continue with raw extraction.
        }

        return "";
    }

    private static String safeRawHttp(HttpRequest request) {
        if (request == null) {
            return "";
        }
        try {
            String raw = request.toString();
            return raw == null ? "" : raw;
        } catch (Exception ignored) {
            return "";
        }
    }

    private static String firstRequestLine(String rawHttp) {
        if (rawHttp == null || rawHttp.isBlank()) {
            return "";
        }

        int crlf = rawHttp.indexOf("\r\n");
        if (crlf >= 0) {
            return rawHttp.substring(0, crlf);
        }

        int lf = rawHttp.indexOf('\n');
        if (lf >= 0) {
            return rawHttp.substring(0, lf);
        }

        return rawHttp;
    }

    private static String hostFromRawHttp(String rawHttp) {
        if (rawHttp == null || rawHttp.isBlank()) {
            return "";
        }

        String[] lines = rawHttp.split("\\r?\\n");
        for (String line : lines) {
            if (line == null) {
                continue;
            }

            if (line.regionMatches(true, 0, "Host:", 0, 5)) {
                String host = line.substring(5).trim();
                if (!host.isBlank()) {
                    return host;
                }
            }

            if (line.isBlank()) {
                break;
            }
        }

        return "";
    }

    private void logParsed(String methodName) {
        api.logging().logToOutput("[LogicHunter][PARSED] method=" + safeValue(methodName));
    }

    private void logContext(AuthContextStore.AuthContext context) {
        if (context == null) {
            return;
        }
        api.logging().logToOutput("[LogicHunter][CONTEXT] key=" + safeValue(context.contextKey())
                + " host=" + safeValue(MyGeotabScope.extractHost(context.lastSeenUrl()))
                + " database=" + safeValue(context.database())
                + " sessionId=" + shortValue(context.sessionId())
                + " userName=" + safeValue(context.userName()));
    }

    private void logStore(String contextKey, String methodName) {
        api.logging().logToOutput("[LogicHunter][STORE] context=" + safeValue(contextKey)
                + " method=" + safeValue(methodName));
    }

    private void logContextAndStore(String contextKey, String methodName) {
        api.logging().logToOutput("[LogicHunter][CONTEXT] key=" + safeValue(contextKey));
        api.logging().logToOutput("[LogicHunter][STORE] context=" + safeValue(contextKey)
                + " method=" + safeValue(methodName));
    }

    private void logPipeline(String stage, String method, String url, String detail) {
        api.logging().logToOutput("[LogicHunter][PIPELINE] stage=" + safeValue(stage)
                + " method=" + safeValue(method)
                + " path=" + safePath(url)
                + (detail == null || detail.isBlank() ? "" : " " + detail));
    }

    private void logSkip(String reason, String method, String url) {
        api.logging().logToOutput("[LogicHunter][SKIP] reason=" + safeValue(reason)
                + " method=" + safeValue(method)
                + " path=" + safePath(url)
                + " host=" + safeValue(MyGeotabScope.extractHost(url)));
    }

    private static String classifySkipReason(String probeReason) {
        if (probeReason == null || probeReason.isBlank()) {
            return "not-json";
        }
        if ("missing-method".equalsIgnoreCase(probeReason)) {
            return "missing-method";
        }
        if ("not-json".equalsIgnoreCase(probeReason) || "empty-body".equalsIgnoreCase(probeReason)) {
            return "not-json";
        }
        return probeReason;
    }

    private static String safeValue(String value) {
        return value == null ? "" : value;
    }

    private static String shortValue(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        return value.length() <= 24 ? value : value.substring(0, 24) + "...";
    }

    private static HttpRequest safeInitiatingRequest(HttpResponseReceived responseReceived) {
        if (responseReceived == null) {
            return null;
        }
        try {
            return responseReceived.initiatingRequest();
        } catch (Exception ignored) {
            return null;
        }
    }

    private static String safeBodyText(HttpRequest request) {
        if (request == null) {
            return "";
        }
        try {
            String bodyText = request.bodyToString();
            if (bodyText != null && !bodyText.isBlank()) {
                return bodyText;
            }
        } catch (Exception ignored) {
            // Fall back to raw bytes when bodyToString cannot decode reliably.
        }

        try {
            byte[] bodyBytes = request.body().getBytes();
            if (bodyBytes != null && bodyBytes.length > 0) {
                return new String(bodyBytes, StandardCharsets.UTF_8);
            }
        } catch (Exception ignored) {
            // Keep empty on decode failure.
        }

        String rawHttp = safeRawHttp(request);
        String rawBody = bodyFromRawHttp(rawHttp);
        if (rawBody != null && !rawBody.isBlank()) {
            return rawBody;
        }

        return "";
    }

    private static String bodyFromRawHttp(String rawHttp) {
        if (rawHttp == null || rawHttp.isBlank()) {
            return "";
        }

        int separator = rawHttp.indexOf("\r\n\r\n");
        if (separator >= 0) {
            return rawHttp.substring(separator + 4);
        }

        separator = rawHttp.indexOf("\n\n");
        if (separator >= 0) {
            return rawHttp.substring(separator + 2);
        }

        return "";
    }

    private static String safeBodyText(HttpResponse response) {
        if (response == null) {
            return "";
        }
        try {
            String bodyText = response.bodyToString();
            if (bodyText != null && !bodyText.isBlank()) {
                return bodyText;
            }
        } catch (Exception ignored) {
            // Fall back to raw bytes when bodyToString cannot decode reliably.
        }

        try {
            byte[] bodyBytes = response.body().getBytes();
            if (bodyBytes != null && bodyBytes.length > 0) {
                return new String(bodyBytes, StandardCharsets.UTF_8);
            }
        } catch (Exception ignored) {
            // Keep empty on decode failure.
        }

        return "";
    }

    private static List<String> headersToStrings(List<HttpHeader> headers) {
        if (headers == null || headers.isEmpty()) {
            return List.of();
        }
        List<String> result = new ArrayList<>(headers.size());
        for (HttpHeader header : headers) {
            result.add(header == null ? "" : header.toString());
        }
        return result;
    }

    private static String snippet(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        return value.length() <= 512 ? value : value.substring(0, 512);
    }

    private static String safeToolName(ToolType toolType) {
        return toolType == null ? "Unknown" : toolType.toolName();
    }

    private static final class PendingExchange {
        private final int messageId;
        private final Instant timestamp;
        private final String toolName;
        private final HttpRequest request;
        private final HttpResponse response;

        private PendingExchange(int messageId, Instant timestamp, String toolName, HttpRequest request, HttpResponse response) {
            this.messageId = messageId;
            this.timestamp = timestamp;
            this.toolName = toolName;
            this.request = request;
            this.response = response;
        }
    }

    public interface RecordListener {
        void onRecord(JsonRpcRecord rawRecord, JsonRpcNormalizedRecord normalizedRecord, boolean replayed);
    }
}
