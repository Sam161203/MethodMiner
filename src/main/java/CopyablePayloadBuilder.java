import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Utility for building copy-paste-ready payloads with body credentials.
 * Output is intentionally header-clean: no Authorization/Cookie headers are emitted.
 */
public final class CopyablePayloadBuilder {
    private static final String DEFAULT_HOST = "example.com";
    private static final String DEFAULT_PATH = "/jsonrpc";

    private CopyablePayloadBuilder() {
    }

    public static String wrapPayloadWithContext(
            String methodName,
            String jsonBody,
            AuthContextStore authContextStore,
            JsonRpcIndex index
    ) {
        String url = resolveUrl(methodName, index);
        if (url == null || url.isBlank()) {
            url = "https://" + DEFAULT_HOST + DEFAULT_PATH;
        }

        String body = extractJsonBody(jsonBody);
        if (body.isBlank()) {
            body = "{}";
        }

        String host = hostFromUrl(url);
        String path = pathFromUrl(url);
        String http = buildCanonicalHttpRequest(host, path, body);

        StringBuilder builder = new StringBuilder();
        builder.append("=== TARGET ===\n");
        builder.append("POST ").append(url).append("\n\n");
        builder.append("=== HTTP ===\n");
        builder.append(http).append("\n\n");
        builder.append("=== cURL ===\n");
        builder.append(buildCurl("https://" + host + path, body));
        return builder.toString();
    }

    public static String buildCurlForSuggestion(
            AttackSuggestion suggestion,
            AuthContextStore authContextStore,
            JsonRpcIndex index
    ) {
        String url = resolveUrlForSuggestion(suggestion, index);
        String body = extractBodyForSuggestion(suggestion);
        return buildCurl(url, body);
    }

    public static String buildHttpRequest(
            AttackSuggestion suggestion,
            AuthContextStore authContextStore,
            JsonRpcIndex index
    ) {
        String body = extractBodyForSuggestion(suggestion);

        String host = DEFAULT_HOST;
        String path = DEFAULT_PATH;
        String url = resolveUrlForSuggestion(suggestion, index);
        if (url != null && !url.isBlank()) {
            host = hostFromUrl(url);
            path = pathFromUrl(url);
        }

        if (suggestion != null && suggestion.host() != null && !suggestion.host().isBlank()) {
            host = normalizeHost(suggestion.host());
        }

        return buildCanonicalHttpRequest(host, path, body);
    }

    /**
     * Kept for compatibility with existing call sites. The auth context is intentionally ignored.
     */
    public static String buildCurl(String url, AuthContextStore.AuthContext context, String jsonBody) {
        return buildCurl(url, jsonBody);
    }

    public static String extractJsonBody(String payload) {
        if (payload == null || payload.isBlank()) {
            return "{}";
        }

        String normalized = payload.replace("\r\n", "\n");

        int bodyMarker = normalized.indexOf("=== BODY ===");
        if (bodyMarker >= 0) {
            String afterMarker = normalized.substring(bodyMarker + "=== BODY ===".length()).trim();
            int nextSection = afterMarker.indexOf("\n===");
            String bodySection = nextSection >= 0 ? afterMarker.substring(0, nextSection).trim() : afterMarker;
            if (!bodySection.isBlank()) {
                return bodySection;
            }
        }

        RawRequest raw = RawRequest.parse(normalized);
        if (!raw.body().isBlank()) {
            String candidate = raw.body().trim();
            int notesStart = candidate.indexOf("\nExpected secure:");
            return notesStart >= 0 ? candidate.substring(0, notesStart).trim() : candidate;
        }

        if (normalized.startsWith("POST ")) {
            int split = normalized.indexOf("\n\n");
            if (split >= 0) {
                String candidate = normalized.substring(split + 2).trim();
                int notesStart = candidate.indexOf("\nExpected secure:");
                return notesStart >= 0 ? candidate.substring(0, notesStart).trim() : candidate;
            }
        }

        return normalized.trim();
    }

    private static String extractBodyForSuggestion(AttackSuggestion suggestion) {
        if (suggestion == null) {
            return "{}";
        }

        String body = extractJsonBody(suggestion.effectivePayload());
        return body.isBlank() ? "{}" : body;
    }

    private static String buildCanonicalHttpRequest(String host, String path, String body) {
        String resolvedHost = (host == null || host.isBlank()) ? DEFAULT_HOST : normalizeHost(host);
        String resolvedPath = (path == null || path.isBlank()) ? DEFAULT_PATH : normalizePath(path);
        String resolvedBody = (body == null || body.isBlank()) ? "{}" : body.trim();

        return "POST " + resolvedPath + " HTTP/2\n"
                + "Host: " + resolvedHost + "\n"
                + "Content-Type: text/plain;charset=UTF-8\n\n"
                + resolvedBody;
    }

    private static String buildCurl(String url, String jsonBody) {
        String targetUrl = (url == null || url.isBlank()) ? "https://" + DEFAULT_HOST + DEFAULT_PATH : url;
        String compactBody = jsonBody == null ? "{}" : jsonBody.replaceAll("\\s+", " ").trim();

        return "curl -X POST '" + targetUrl + "' "
                + "-H 'Content-Type: text/plain;charset=UTF-8' "
                + "-d '" + escapeSingleQuotes(compactBody) + "'";
    }

    private static String resolveUrlForSuggestion(AttackSuggestion suggestion, JsonRpcIndex index) {
        if (suggestion != null && suggestion.host() != null && !suggestion.host().isBlank()) {
            return "https://" + normalizeHost(suggestion.host()) + DEFAULT_PATH;
        }

        String resolved = resolveUrl(suggestion == null ? "" : suggestion.primaryMethod(), index);
        if (resolved != null && !resolved.isBlank()) {
            String host = hostFromUrl(resolved);
            String path = pathFromUrl(resolved);
            return "https://" + host + path;
        }

        return "https://" + DEFAULT_HOST + DEFAULT_PATH;
    }

    private static String resolveUrl(String methodName, JsonRpcIndex index) {
        if (methodName == null || methodName.isBlank() || "(multiple)".equals(methodName)) {
            return "";
        }

        Optional<JsonRpcIndex.MethodDetails> details = index.snapshotMethodDetails(methodName);
        if (details.isPresent()) {
            JsonRpcRecord rawRecord = details.get().primaryRawRecord();
            if (rawRecord != null && rawRecord.request() != null) {
                String url = rawRecord.request().url();
                return url == null ? "" : url;
            }
        }
        return "";
    }

    private static String hostFromUrl(String url) {
        if (url == null || url.isBlank()) {
            return DEFAULT_HOST;
        }

        try {
            URI uri = new URI(url);
            String host = uri.getHost();
            if (host != null && !host.isBlank()) {
                return normalizeHost(host);
            }
        } catch (Exception ignored) {
            // Fall through.
        }

        return DEFAULT_HOST;
    }

    private static String pathFromUrl(String url) {
        if (url == null || url.isBlank()) {
            return DEFAULT_PATH;
        }

        try {
            URI uri = new URI(url);
            String path = uri.getRawPath();
            if (path != null && !path.isBlank()) {
                return normalizePath(path);
            }
        } catch (Exception ignored) {
            // Fall through.
        }

        return DEFAULT_PATH;
    }

    private static String normalizeHost(String host) {
        if (host == null || host.isBlank()) {
            return DEFAULT_HOST;
        }

        String normalized = host.trim().toLowerCase(Locale.ROOT);
        int colon = normalized.indexOf(':');
        if (colon > 0 && normalized.indexOf(']') < 0) {
            normalized = normalized.substring(0, colon);
        }
        while (normalized.endsWith(".")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized.isBlank() ? DEFAULT_HOST : normalized;
    }

    private static String normalizePath(String path) {
        if (path == null || path.isBlank()) {
            return DEFAULT_PATH;
        }
        String trimmed = path.trim();
        return trimmed.startsWith("/") ? trimmed : "/" + trimmed;
    }

    private static String normalizeRawRequest(String rawHttp) {
        if (rawHttp == null || rawHttp.isBlank()) {
            return "";
        }
        return rawHttp.contains("\\r\\n") && !rawHttp.contains("\r\n")
                ? rawHttp.replace("\\r\\n", "\r\n")
                : rawHttp;
    }

    private static String escapeSingleQuotes(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("'", "'\\''");
    }

    private record RawRequest(String path, List<String> headers, String body) {
        private static RawRequest parse(String rawHttp) {
            String normalized = normalizeRawRequest(rawHttp);
            if (normalized.isBlank()) {
                return new RawRequest(DEFAULT_PATH, List.of(), "");
            }

            int split = normalized.indexOf("\r\n\r\n");
            int separatorLength = 4;
            if (split < 0) {
                split = normalized.indexOf("\n\n");
                separatorLength = 2;
            }

            if (split < 0) {
                return new RawRequest(DEFAULT_PATH, List.of(), "");
            }

            String head = normalized.substring(0, split);
            String body = normalized.substring(split + separatorLength);
            String[] lines = head.split("\\r?\\n");
            if (lines.length == 0) {
                return new RawRequest(DEFAULT_PATH, List.of(), body);
            }

            String path = DEFAULT_PATH;
            String[] requestParts = lines[0].split("\\s+");
            if (requestParts.length >= 2 && requestParts[1] != null && !requestParts[1].isBlank()) {
                path = normalizePath(requestParts[1]);
            }

            List<String> headers = new ArrayList<>();
            for (int i = 1; i < lines.length; i++) {
                String line = lines[i];
                if (line != null && !line.isBlank()) {
                    headers.add(line.trim());
                }
            }

            return new RawRequest(path, List.copyOf(headers), body);
        }
    }
}
