package com.methodminer.burp;

import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import com.methodminer.protocol.HttpExchange;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Lightweight Burp HTTP handler that bridges all captured traffic into the
 * v2 {@link TrafficIngestor} pipeline.
 *
 * <p>It converts each completed HTTP request/response pair into a Burp-agnostic
 * {@link HttpExchange} and invokes {@link TrafficIngestor#ingest(HttpExchange)}.
 * Protocol detection and filtering are handled by the v2 pipeline itself.</p>
 *
 * <p>This handler is strictly passive — it never modifies requests or responses.</p>
 */
public final class BurpTrafficBridge implements HttpHandler {

    private final TrafficIngestor trafficIngestor;
    private final Logging logging;
    private final AtomicBoolean firstIngestLogged = new AtomicBoolean(false);

    public BurpTrafficBridge(TrafficIngestor trafficIngestor, Logging logging) {
        this.trafficIngestor = Objects.requireNonNull(trafficIngestor, "trafficIngestor");
        this.logging = Objects.requireNonNull(logging, "logging");
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        // Passthrough — we only need the completed request/response pair.
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        try {
            HttpRequest request = safeInitiatingRequest(responseReceived);
            if (request == null) {
                return ResponseReceivedAction.continueWith(responseReceived);
            }

            HttpExchange exchange = toHttpExchange(request, responseReceived);
            if (exchange != null) {
                trafficIngestor.ingest(exchange);
                if (firstIngestLogged.compareAndSet(false, true)) {
                    logging.logToOutput("[Method Miner] v2 ingest active (first exchange): "
                            + exchange.method() + " " + exchange.uri());
                }
            }
        } catch (Exception ex) {
            logging.logToOutput("[Method Miner][V2-BRIDGE] ingest failed: " + ex.getMessage());
        }

        return ResponseReceivedAction.continueWith(responseReceived);
    }

    /**
     * Convert Burp Montoya request/response objects into a Burp-agnostic {@link HttpExchange}.
     */
    private static HttpExchange toHttpExchange(HttpRequest request, HttpResponseReceived response) {
        String url = safeUrl(request);
        if (url.isBlank()) {
            return null;
        }

        URI uri;
        try {
            uri = URI.create(url);
        } catch (Exception ex) {
            return null;
        }

        String method = safeMethod(request);
        if (method.isBlank()) {
            return null;
        }

        Map<String, List<String>> requestHeaders = extractHeaders(request.headers());
        Map<String, List<String>> responseHeaders = extractHeaders(response.headers());

        Optional<String> requestBody = optionalBody(safeBodyText(request));
        Optional<String> responseBody = optionalBody(safeResponseBody(response));

        int statusCode;
        try {
            statusCode = (int) response.statusCode();
        } catch (Exception ex) {
            statusCode = 0;
        }

        UUID exchangeId = stableExchangeId(url, method, requestBody.orElse(""));

        return new HttpExchange(
                exchangeId,
                uri,
                method,
                requestHeaders,
                requestBody,
                statusCode,
                responseHeaders,
                responseBody,
                Instant.now()
        );
    }

    private static Map<String, List<String>> extractHeaders(List<HttpHeader> headers) {
        if (headers == null || headers.isEmpty()) {
            return Map.of();
        }

        Map<String, List<String>> result = new LinkedHashMap<>();
        for (HttpHeader header : headers) {
            if (header == null) {
                continue;
            }
            String name = header.name();
            String value = header.value();
            if (name == null || name.isBlank()) {
                continue;
            }
            result.computeIfAbsent(name, ignored -> new ArrayList<>())
                    .add(value == null ? "" : value);
        }

        Map<String, List<String>> immutable = new LinkedHashMap<>();
        for (var entry : result.entrySet()) {
            immutable.put(entry.getKey(), List.copyOf(entry.getValue()));
        }
        return Map.copyOf(immutable);
    }

    private static Optional<String> optionalBody(String body) {
        if (body == null || body.isBlank()) {
            return Optional.empty();
        }
        return Optional.of(body);
    }

    private static UUID stableExchangeId(String url, String method, String body) {
        String key = "burp-bridge:" + method + ":" + url + ":" + body.hashCode() + ":" + System.nanoTime();
        return UUID.nameUUIDFromBytes(key.getBytes(StandardCharsets.UTF_8));
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

    private static String safeUrl(HttpRequest request) {
        if (request == null) {
            return "";
        }
        try {
            String url = request.url();
            if (url != null && !url.isBlank()) {
                return url;
            }
        } catch (Exception ignored) {
            // Fall through.
        }
        return "";
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
            // Fall through.
        }
        return "";
    }

    private static String safeBodyText(HttpRequest request) {
        if (request == null) {
            return "";
        }
        try {
            String body = request.bodyToString();
            if (body != null && !body.isBlank()) {
                return body;
            }
        } catch (Exception ignored) {
            // Fall through.
        }
        try {
            byte[] bytes = request.body().getBytes();
            if (bytes != null && bytes.length > 0) {
                return new String(bytes, StandardCharsets.UTF_8);
            }
        } catch (Exception ignored) {
            // Fall through.
        }
        return "";
    }

    private static String safeResponseBody(HttpResponse response) {
        if (response == null) {
            return "";
        }
        try {
            String body = response.bodyToString();
            if (body != null && !body.isBlank()) {
                return body;
            }
        } catch (Exception ignored) {
            // Fall through.
        }
        try {
            byte[] bytes = response.body().getBytes();
            if (bytes != null && bytes.length > 0) {
                return new String(bytes, StandardCharsets.UTF_8);
            }
        } catch (Exception ignored) {
            // Fall through.
        }
        return "";
    }
}
