import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CopyOnWriteArrayList;

public final class AuthContextStore {
    private static final Set<String> DATABASE_KEYS = Set.of("database", "db", "dbName", "databaseName");
    private static final Set<String> USER_KEYS = Set.of("user", "userName", "username", "email", "login");
    private static final Set<String> SESSION_KEYS = Set.of("session", "sessionId", "sid", "token", "jwt");

    private final ObjectMapper objectMapper;

    private final ConcurrentMap<String, AuthContext> contextStore = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, String> recordToContextKey = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Set<String>> methodToContextKeys = new ConcurrentHashMap<>();
    private final List<Runnable> updateListeners = new CopyOnWriteArrayList<>();

    public AuthContextStore(ObjectMapper objectMapper) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
    }

    public void registerUpdateListener(Runnable listener) {
        if (listener != null) {
            updateListeners.add(listener);
        }
    }

    public AuthContext observeRecord(JsonRpcRecord rawRecord, String methodName) {
        if (rawRecord == null) {
            return AuthContext.unknown("unknown-context");
        }

        JsonNode requestNode = parseJson(rawRecord.request().bodyText());
        JsonNode responseNode = parseJson(rawRecord.response().bodyText());

        String database = firstKnownValue(requestNode, responseNode, DATABASE_KEYS);
        String userName = firstKnownValue(requestNode, responseNode, USER_KEYS);
        String sessionId = firstKnownSession(rawRecord.request().headers(), requestNode, responseNode);

        String normalizedDatabase = defaultIfBlank(database, "unknown-db");
        String normalizedUser = defaultIfBlank(userName, "unknown-user");
        String normalizedSession = defaultIfBlank(sessionId, "");

        String authHeader = extractFullHeaderValue(rawRecord.request().headers(), "authorization");
        String cookieHeader = extractFullHeaderValue(rawRecord.request().headers(), "cookie");
        String requestUrl = safeValue(rawRecord.request().url());

        String key = buildStableContextKey(
                requestUrl,
                rawRecord.request().headers(),
                normalizedDatabase,
                normalizedUser,
                normalizedSession,
                authHeader,
                cookieHeader
        );

        AuthContext context = contextStore.compute(key, (ignored, existing) -> {
            RoleType role = existing == null ? RoleType.UNKNOWN : existing.role();
            String sessionValue = normalizedSession.isBlank() && existing != null ? existing.sessionId() : normalizedSession;
            String databaseValue = normalizedDatabase.equals("unknown-db") && existing != null ? existing.database() : normalizedDatabase;
            String userValue = normalizedUser.equals("unknown-user") && existing != null ? existing.userName() : normalizedUser;
            String authVal = authHeader.isBlank() && existing != null ? existing.rawAuthorizationHeader() : authHeader;
            String cookieVal = cookieHeader.isBlank() && existing != null ? existing.rawCookieHeader() : cookieHeader;
            String urlVal = requestUrl.isBlank() && existing != null ? existing.lastSeenUrl() : requestUrl;
            return new AuthContext(key, databaseValue, sessionValue, userValue, role, authVal, cookieVal, urlVal);
        });

        if (rawRecord.recordId() != null && !rawRecord.recordId().isBlank()) {
            recordToContextKey.put(rawRecord.recordId(), key);
        }

        if (methodName != null && !methodName.isBlank()) {
            methodToContextKeys.computeIfAbsent(methodName, ignored -> ConcurrentHashMap.newKeySet()).add(key);
        }

        return context;
    }

    public RoleType roleForRecordId(String recordId) {
        if (recordId == null || recordId.isBlank()) {
            return RoleType.UNKNOWN;
        }
        String key = recordToContextKey.get(recordId);
        if (key == null) {
            return RoleType.UNKNOWN;
        }
        AuthContext context = contextStore.get(key);
        return context == null ? RoleType.UNKNOWN : context.role();
    }

    public RoleType roleForMethod(String methodName) {
        if (methodName == null || methodName.isBlank()) {
            return RoleType.UNKNOWN;
        }

        Set<String> keys = methodToContextKeys.get(methodName);
        if (keys == null || keys.isEmpty()) {
            return RoleType.UNKNOWN;
        }

        RoleType resolved = null;
        for (String key : keys) {
            AuthContext context = contextStore.get(key);
            if (context == null) {
                continue;
            }
            RoleType role = context.role();
            if (resolved == null) {
                resolved = role;
                continue;
            }
            if (resolved != role) {
                return RoleType.UNKNOWN;
            }
        }

        return resolved == null ? RoleType.UNKNOWN : resolved;
    }

    public RoleType roleForContextKey(String contextKey) {
        if (contextKey == null || contextKey.isBlank()) {
            return RoleType.UNKNOWN;
        }
        AuthContext context = contextStore.get(contextKey);
        return context == null ? RoleType.UNKNOWN : context.role();
    }

    public boolean setRoleForMethod(String methodName, RoleType roleType) {
        if (methodName == null || methodName.isBlank()) {
            return false;
        }

        Set<String> keys = methodToContextKeys.get(methodName);
        if (keys == null || keys.isEmpty()) {
            return false;
        }

        boolean updated = false;
        for (String key : keys) {
            updated = setRoleForContextKey(key, roleType) || updated;
        }
        return updated;
    }

    public List<String> contextKeysForMethod(String methodName) {
        if (methodName == null || methodName.isBlank()) {
            return List.of();
        }
        Set<String> keys = methodToContextKeys.get(methodName);
        if (keys == null || keys.isEmpty()) {
            return List.of();
        }
        return List.copyOf(keys);
    }

    public boolean setRoleForRecord(String recordId, RoleType roleType) {
        if (recordId == null || recordId.isBlank()) {
            return false;
        }
        String key = recordToContextKey.get(recordId);
        if (key == null) {
            return false;
        }
        return setRoleForContextKey(key, roleType);
    }

    public boolean setRoleForContextKey(String contextKey, RoleType roleType) {
        if (contextKey == null || contextKey.isBlank()) {
            return false;
        }

        RoleType nextRole = roleType == null ? RoleType.UNKNOWN : roleType;
        AuthContext updated = contextStore.computeIfPresent(contextKey, (ignored, existing) ->
                new AuthContext(existing.contextKey(), existing.database(), existing.sessionId(), existing.userName(), nextRole,
                        existing.rawAuthorizationHeader(), existing.rawCookieHeader(), existing.lastSeenUrl())
        );

        if (updated == null) {
            return false;
        }

        notifyListeners();
        return true;
    }

    public String contextKeyForRecord(String recordId) {
        if (recordId == null || recordId.isBlank()) {
            return "";
        }
        String key = recordToContextKey.get(recordId);
        return key == null ? "" : key;
    }

    public List<AuthContext> snapshotContexts() {
        List<AuthContext> contexts = new ArrayList<>(contextStore.values());
        contexts.sort((left, right) -> left.contextKey().compareToIgnoreCase(right.contextKey()));
        return contexts;
    }

    public AuthContext firstContextByRole(RoleType role) {
        if (role == null) {
            return null;
        }
        for (AuthContext ctx : contextStore.values()) {
            if (ctx.role() == role) {
                return ctx;
            }
        }
        return null;
    }

    public void clear() {
        contextStore.clear();
        recordToContextKey.clear();
        methodToContextKeys.clear();
        notifyListeners();
    }

    private void notifyListeners() {
        for (Runnable listener : updateListeners) {
            try {
                listener.run();
            } catch (Exception ignored) {
                // UI updates should not break processing.
            }
        }
    }

    private JsonNode parseJson(String body) {
        if (body == null || body.isBlank()) {
            return null;
        }
        try {
            return objectMapper.readTree(body);
        } catch (Exception ignored) {
            return null;
        }
    }

    private static String firstKnownSession(List<String> headers, JsonNode requestNode, JsonNode responseNode) {
        String fromHeaders = extractSessionFromHeaders(headers);
        if (!fromHeaders.isBlank()) {
            return fromHeaders;
        }

        String fromRequest = findFirstByKeys(requestNode, SESSION_KEYS);
        if (!fromRequest.isBlank()) {
            return fromRequest;
        }

        return findFirstByKeys(responseNode, SESSION_KEYS);
    }

    private static String extractSessionFromHeaders(List<String> headers) {
        if (headers == null || headers.isEmpty()) {
            return "";
        }

        for (String header : headers) {
            if (header == null || header.isBlank()) {
                continue;
            }
            String lowered = header.toLowerCase(Locale.ROOT);
            if (lowered.startsWith("cookie:")) {
                String value = header.substring(header.indexOf(':') + 1);
                String[] segments = value.split(";");
                for (String segment : segments) {
                    String part = segment.trim();
                    int equals = part.indexOf('=');
                    if (equals < 1) {
                        continue;
                    }
                    String key = part.substring(0, equals).trim().toLowerCase(Locale.ROOT);
                    String val = part.substring(equals + 1).trim();
                    if (key.contains("session") || key.equals("sid") || key.contains("token")) {
                        return val;
                    }
                }
            }

            if (lowered.startsWith("authorization:")) {
                String value = header.substring(header.indexOf(':') + 1).trim();
                if (!value.isBlank()) {
                    return value.length() > 120 ? value.substring(0, 120) : value;
                }
            }
        }

        return "";
    }

    private static String firstKnownValue(JsonNode requestNode, JsonNode responseNode, Set<String> keys) {
        String request = findFirstByKeys(requestNode, keys);
        if (!request.isBlank()) {
            return request;
        }
        return findFirstByKeys(responseNode, keys);
    }

    private static String findFirstByKeys(JsonNode root, Set<String> candidateKeys) {
        if (root == null) {
            return "";
        }

        if (root.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = root.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields.next();
                String fieldName = entry.getKey();
                JsonNode value = entry.getValue();

                for (String key : candidateKeys) {
                    if (fieldName.equalsIgnoreCase(key)) {
                        String resolved = leafValue(value);
                        if (!resolved.isBlank()) {
                            return resolved;
                        }
                    }
                }

                String nested = findFirstByKeys(value, candidateKeys);
                if (!nested.isBlank()) {
                    return nested;
                }
            }
        }

        if (root.isArray()) {
            for (JsonNode item : root) {
                String nested = findFirstByKeys(item, candidateKeys);
                if (!nested.isBlank()) {
                    return nested;
                }
            }
        }

        return "";
    }

    private static String leafValue(JsonNode node) {
        if (node == null || node.isNull()) {
            return "";
        }
        if (node.isTextual() || node.isNumber() || node.isBoolean()) {
            String value = node.asText("");
            return value.length() <= 120 ? value : value.substring(0, 120);
        }
        if (node.isArray() && node.size() > 0) {
            return leafValue(node.get(0));
        }
        return "";
    }

    private static String defaultIfBlank(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }

    private static String safeValue(String value) {
        return value == null ? "" : value;
    }

    private static String extractFullHeaderValue(List<String> headers, String headerName) {
        if (headers == null || headers.isEmpty() || headerName == null) {
            return "";
        }
        String prefix = headerName.toLowerCase(Locale.ROOT) + ":";
        for (String header : headers) {
            if (header != null && header.toLowerCase(Locale.ROOT).startsWith(prefix)) {
                return header.substring(header.indexOf(':') + 1).trim();
            }
        }
        return "";
    }

    private static String buildStableContextKey(
            String requestUrl,
            List<String> headers,
            String database,
            String userName,
            String sessionId,
            String authHeader,
            String cookieHeader
    ) {
        String host = extractHost(requestUrl);
        String db = normalizeKeyComponent(database, 80, "unknown-db");
        String user = normalizeKeyComponent(userName, 80, "unknown-user");

        // Context key uses only host + database + userName.
        // SessionId, referer path, auth fingerprint, and cookie fingerprint are intentionally
        // excluded: they change on re-login, page navigation, or cookie rotation, causing
        // the same user to fragment into many contexts. The identity triple (host, db, user)
        // is stable and unique per account session in the MyGeotab JSON-RPC API.
        return "ctx"
                + "|host=" + normalizeKeyComponent(host, 80, "unknown-host")
                + "|db=" + db
                + "|user=" + user;
    }

    private static String normalizeKeyComponent(String value, int maxLen, String fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }

        String normalized = value.trim().toLowerCase(Locale.ROOT)
                .replace('|', '_')
                .replace('\n', ' ')
                .replace('\r', ' ');

        if (normalized.length() > maxLen) {
            return normalized.substring(0, maxLen);
        }
        return normalized;
    }

    private static String extractHost(String url) {
        if (url == null || url.isBlank()) {
            return "";
        }
        try {
            URI uri = URI.create(url);
            return uri.getHost() == null ? "" : uri.getHost();
        } catch (Exception ignored) {
            return "";
        }
    }

    private static String extractSourceContext(String requestUrl, List<String> headers) {
        String referer = extractFullHeaderValue(headers, "referer");
        if (!referer.isBlank()) {
            String fromReferer = extractPath(referer);
            if (!fromReferer.isBlank()) {
                return fromReferer;
            }
        }

        String requestPath = extractPath(requestUrl);
        if (!requestPath.isBlank()) {
            return requestPath;
        }

        return "unknown-src";
    }

    private static String extractPath(String raw) {
        if (raw == null || raw.isBlank()) {
            return "";
        }

        if (raw.startsWith("/")) {
            return raw;
        }

        try {
            URI uri = URI.create(raw);
            String path = uri.getPath();
            if (path == null || path.isBlank()) {
                path = "/";
            }
            if (uri.getQuery() != null && !uri.getQuery().isBlank()) {
                path += "?" + uri.getQuery();
            }
            return path;
        } catch (Exception ignored) {
            return "";
        }
    }

    private static String shortFingerprint(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < 8; i++) {
                builder.append(String.format("%02x", hash[i]));
            }
            return builder.toString();
        } catch (Exception ignored) {
            return Integer.toHexString(value.hashCode());
        }
    }

    public record AuthContext(
            String contextKey,
            String database,
            String sessionId,
            String userName,
            RoleType role,
            String rawAuthorizationHeader,
            String rawCookieHeader,
            String lastSeenUrl
    ) {
        public static AuthContext unknown(String key) {
            return new AuthContext(key, "unknown-db", "", "unknown-user", RoleType.UNKNOWN, "", "", "");
        }
    }
}
