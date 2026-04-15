import java.util.Optional;

/**
 * Utility for building copy-paste-ready exploit payloads with real session data.
 * Produces formatted HTTP requests, cURL commands, and raw payloads.
 */
public final class CopyablePayloadBuilder {
    private CopyablePayloadBuilder() {}

    /**
     * Wraps a JSON body with full HTTP context (URL, headers, cURL) using real captured session data.
     */
    public static String wrapPayloadWithContext(
            String methodName,
            String jsonBody,
            AuthContextStore authContextStore,
            JsonRpcIndex index
    ) {
        String url = resolveUrl(methodName, index);
        AuthContextStore.AuthContext adminCtx = authContextStore.firstContextByRole(RoleType.ADMIN);
        AuthContextStore.AuthContext lowPrivCtx = authContextStore.firstContextByRole(RoleType.LOW_PRIV);

        StringBuilder sb = new StringBuilder();

        sb.append("=== TARGET ===\n");
        sb.append("POST ").append(url.isBlank() ? "<target_url>/jsonrpc" : url).append("\n\n");

        if (lowPrivCtx != null && hasAnyHeader(lowPrivCtx)) {
            sb.append("=== HEADERS (LOW_PRIV session — use these to test) ===\n");
            sb.append("Content-Type: application/json\n");
            appendHeaders(sb, lowPrivCtx);
            sb.append("\n");
        } else if (adminCtx != null && hasAnyHeader(adminCtx)) {
            sb.append("=== HEADERS (ADMIN session — captured) ===\n");
            sb.append("Content-Type: application/json\n");
            appendHeaders(sb, adminCtx);
            sb.append("\n");
        }

        sb.append("=== BODY ===\n");
        sb.append(jsonBody).append("\n\n");

        if (lowPrivCtx != null && hasAnyHeader(lowPrivCtx)) {
            sb.append("=== cURL (LOW_PRIV — test this) ===\n");
            sb.append(buildCurl(url, lowPrivCtx, jsonBody)).append("\n\n");
        }

        if (adminCtx != null && hasAnyHeader(adminCtx)) {
            sb.append("=== cURL (ADMIN — for comparison) ===\n");
            sb.append(buildCurl(url, adminCtx, jsonBody)).append("\n\n");
        }

        if (lowPrivCtx != null && adminCtx != null && hasAnyHeader(lowPrivCtx) && hasAnyHeader(adminCtx)) {
            sb.append("=== SWAP HEADERS TO TEST ===\n");
            sb.append("LOW_PRIV:\n");
            appendHeaders(sb, lowPrivCtx);
            sb.append("\nADMIN:\n");
            appendHeaders(sb, adminCtx);
            sb.append("\n");
        }

        return sb.toString().trim();
    }

    /**
     * Builds a cURL command for a specific suggestion using real captured session data.
     */
    public static String buildCurlForSuggestion(
            AttackSuggestion suggestion,
            AuthContextStore authContextStore,
            JsonRpcIndex index
    ) {
        if (suggestion.repeaterRequest() != null && !suggestion.repeaterRequest().isBlank()) {
            RawRequest rawRequest = RawRequest.parse(suggestion.repeaterRequest());
            String path = rawRequest.path();
            String host = suggestion.host() == null ? "" : suggestion.host();
            String url = host.isBlank() ? resolveUrl(suggestion.primaryMethod(), index) : "https://" + host + path;
            return buildCurlFromRaw(url, rawRequest.headers(), rawRequest.body());
        }

        String methodName = suggestion.primaryMethod();
        String url = resolveUrl(methodName, index);
        String jsonBody = extractJsonBody(suggestion.exploitPayload());
        AuthContextStore.AuthContext lowPrivCtx = authContextStore.firstContextByRole(RoleType.LOW_PRIV);
        if (lowPrivCtx == null) {
            lowPrivCtx = authContextStore.firstContextByRole(RoleType.ADMIN);
        }
        return buildCurl(url, lowPrivCtx, jsonBody);
    }

    /**
     * Builds a raw HTTP request for clipboard (URL + headers + body, no section markers).
     */
    public static String buildHttpRequest(
            AttackSuggestion suggestion,
            AuthContextStore authContextStore,
            JsonRpcIndex index
    ) {
        if (suggestion.repeaterRequest() != null && !suggestion.repeaterRequest().isBlank()) {
            return suggestion.repeaterRequest();
        }

        String methodName = suggestion.primaryMethod();
        String url = resolveUrl(methodName, index);
        String jsonBody = extractJsonBody(suggestion.exploitPayload());
        AuthContextStore.AuthContext ctx = authContextStore.firstContextByRole(RoleType.LOW_PRIV);
        if (ctx == null) {
            ctx = authContextStore.firstContextByRole(RoleType.ADMIN);
        }

        StringBuilder sb = new StringBuilder();
        sb.append("POST ").append(url.isBlank() ? "<target_url>/jsonrpc" : url).append(" HTTP/1.1\n");
        sb.append("Content-Type: application/json\n");
        if (ctx != null) {
            appendHeaders(sb, ctx);
        }
        sb.append("\n");
        sb.append(jsonBody);
        return sb.toString();
    }

    /**
     * Builds a cURL command string.
     */
    public static String buildCurl(String url, AuthContextStore.AuthContext context, String jsonBody) {
        String targetUrl = url == null || url.isBlank() ? "<target_url>/jsonrpc" : url;

        StringBuilder curl = new StringBuilder();
        curl.append("curl -X POST '").append(targetUrl).append("'");

        curl.append(" \\\n  -H 'Content-Type: application/json'");

        if (context != null) {
            if (!context.rawCookieHeader().isBlank()) {
                curl.append(" \\\n  -H 'Cookie: ").append(escapeSingleQuotes(context.rawCookieHeader())).append("'");
            }
            if (!context.rawAuthorizationHeader().isBlank()) {
                curl.append(" \\\n  -H 'Authorization: ").append(escapeSingleQuotes(context.rawAuthorizationHeader())).append("'");
            }
        }

        String compactBody = jsonBody == null ? "{}" : jsonBody.replaceAll("\\s+", " ").trim();
        curl.append(" \\\n  -d '").append(escapeSingleQuotes(compactBody)).append("'");

        return curl.toString();
    }

    /**
     * Extracts the JSON body from a formatted payload string (between === BODY === markers).
     */
    public static String extractJsonBody(String exploitPayload) {
        if (exploitPayload == null || exploitPayload.isBlank()) {
            return "{}";
        }

        RawRequest raw = RawRequest.parse(exploitPayload);
        if (!raw.body().isBlank()) {
            return raw.body().trim();
        }

        int bodyStart = exploitPayload.indexOf("=== BODY ===");
        if (bodyStart >= 0) {
            String afterMarker = exploitPayload.substring(bodyStart + "=== BODY ===".length()).trim();
            int nextSection = afterMarker.indexOf("\n===");
            if (nextSection >= 0) {
                return afterMarker.substring(0, nextSection).trim();
            }
            return afterMarker.trim();
        }

        // No section markers — entire payload is the JSON body
        return exploitPayload.trim();
    }

    private static String buildCurlFromRaw(String url, java.util.List<String> headers, String body) {
        String targetUrl = (url == null || url.isBlank()) ? "<target_url>/jsonrpc" : url;
        StringBuilder curl = new StringBuilder();
        curl.append("curl -X POST '").append(targetUrl).append("'");

        boolean contentTypePresent = false;
        for (String header : headers) {
            if (header == null || header.isBlank()) {
                continue;
            }
            String lowered = header.toLowerCase();
            if (lowered.startsWith("host:")) {
                continue;
            }
            if (lowered.startsWith("content-length:")) {
                continue;
            }
            if (lowered.startsWith("connection:")) {
                continue;
            }
            if (lowered.startsWith("content-type:")) {
                contentTypePresent = true;
            }
            curl.append(" \\\n  -H '").append(escapeSingleQuotes(header.trim())).append("'");
        }

        if (!contentTypePresent) {
            curl.append(" \\\n  -H 'Content-Type: application/json'");
        }

        String compactBody = body == null ? "{}" : body.replaceAll("\\s+", " ").trim();
        curl.append(" \\\n  -d '").append(escapeSingleQuotes(compactBody)).append("'");
        return curl.toString();
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

    private static boolean hasAnyHeader(AuthContextStore.AuthContext ctx) {
        return ctx != null
                && (!ctx.rawAuthorizationHeader().isBlank() || !ctx.rawCookieHeader().isBlank());
    }

    private static void appendHeaders(StringBuilder sb, AuthContextStore.AuthContext ctx) {
        if (!ctx.rawCookieHeader().isBlank()) {
            sb.append("Cookie: ").append(ctx.rawCookieHeader()).append("\n");
        }
        if (!ctx.rawAuthorizationHeader().isBlank()) {
            sb.append("Authorization: ").append(ctx.rawAuthorizationHeader()).append("\n");
        }
    }

    private static String escapeSingleQuotes(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("'", "'\\''");
    }

    private record RawRequest(String path, java.util.List<String> headers, String body) {
        private static RawRequest parse(String rawHttp) {
            if (rawHttp == null || rawHttp.isBlank()) {
                return new RawRequest("/jsonrpc", java.util.List.of(), "");
            }

            boolean escapedMode = rawHttp.contains("\\r\\n") && !rawHttp.contains("\r\n");
            String parseable = escapedMode ? rawHttp.replace("\\r\\n", "\r\n") : rawHttp;

            int split = parseable.indexOf("\r\n\r\n");
            int separatorLength = 4;
            if (split < 0) {
                split = parseable.indexOf("\n\n");
                separatorLength = 2;
            }

            if (split < 0) {
                return new RawRequest("/jsonrpc", java.util.List.of(), "");
            }

            String head = parseable.substring(0, split);
            String body = parseable.substring(split + separatorLength);
            String[] lines = head.split("\\r?\\n");
            if (lines.length == 0) {
                return new RawRequest("/jsonrpc", java.util.List.of(), body);
            }

            String path = "/jsonrpc";
            String[] requestLineParts = lines[0].split(" ");
            if (requestLineParts.length >= 2 && requestLineParts[1] != null && !requestLineParts[1].isBlank()) {
                path = requestLineParts[1];
            }

            java.util.List<String> headers = new java.util.ArrayList<>();
            for (int i = 1; i < lines.length; i++) {
                String line = lines[i];
                if (!line.isBlank()) {
                    headers.add(line.trim());
                }
            }

            return new RawRequest(path, headers, body);
        }
    }
}
