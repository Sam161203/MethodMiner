import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CopyOnWriteArrayList;

public final class AuthContextStore {
    private final ObjectMapper objectMapper;

    // Context store key: host + database + sessionId + userName
    private final ConcurrentMap<String, SessionState> sessions = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, RoleType> rolesByContextKey = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, String> recordToContextKey = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Set<String>> methodToContextKeys = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Set<String>> sessionIdToContextKeys = new ConcurrentHashMap<>();
    private final List<Runnable> updateListeners = new CopyOnWriteArrayList<>();

    public AuthContextStore(ObjectMapper objectMapper) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
    }

    public void registerUpdateListener(Runnable listener) {
        if (listener != null) {
            updateListeners.add(listener);
        }
    }

    public Credentials extractCredentials(String requestBody) {
        JsonNode root = parseJson(requestBody);
        if (root == null) {
            return null;
        }

        if (root.isObject()) {
            return extractFromCall(root);
        }

        if (root.isArray()) {
            for (JsonNode item : root) {
                if (item != null && item.isObject()) {
                    Credentials credentials = extractFromCall(item);
                    if (credentials != null) {
                        return credentials;
                    }
                }
            }
        }

        return null;
    }

    public AuthContext observeRecord(JsonRpcRecord rawRecord, String methodName) {
        if (rawRecord == null) {
            return AuthContext.unknown("unknown-session");
        }

        Credentials credentials = extractCredentials(rawRecord.request().bodyText());
        if (credentials == null || credentials.sessionId().isBlank()) {
            return AuthContext.unknown("unknown-session");
        }

        String sessionId = credentials.sessionId();
        String host = defaultIfBlank(extractHost(rawRecord.request().url()), "unknown-host");
        String database = defaultIfBlank(credentials.database(), "unknown-db");
        String userName = defaultIfBlank(credentials.userName(), "unknown-user");
        String contextKey = resolveCompatibleContextKey(host, database, sessionId, userName);
        String typeName = defaultIfBlank(credentials.typeName(), "Unknown");
        String method = defaultIfBlank(methodName, credentials.methodName());
        Instant now = rawRecord.timestamp() == null ? Instant.now() : rawRecord.timestamp();
        List<String> securityGroups = extractSecurityGroups(rawRecord.response().bodyText());
        String lastSeenUrl = rawRecord.request().url() == null ? "" : rawRecord.request().url();

        sessions.compute(contextKey, (ignored, existing) -> {
            SessionState next = existing == null
                    ? new SessionState(contextKey, host, sessionId, database, userName)
                    : existing;

            if (!database.isBlank() && !"unknown-db".equals(database)) {
                next.database = database;
            }
            if (!userName.isBlank() && !"unknown-user".equals(userName)) {
                next.userName = userName;
            }
            if (!host.isBlank() && !"unknown-host".equals(host)) {
                next.host = host;
            }

            next.lastSeen = now;
            next.lastSeenUrl = lastSeenUrl;
            next.requestCount = next.requestCount + 1;
            next.role = rolesByContextKey.getOrDefault(contextKey, next.role);
            for (String group : securityGroups) {
                if (group != null && !group.isBlank()) {
                    next.securityGroups.add(group.trim());
                }
            }

            return next;
        });

        String recordId = rawRecord.recordId();
        if (recordId != null && !recordId.isBlank()) {
            recordToContextKey.put(recordId, contextKey);
        }
        sessionIdToContextKeys.computeIfAbsent(sessionId, ignored -> ConcurrentHashMap.newKeySet()).add(contextKey);

        if (method != null && !method.isBlank()) {
            String methodOnly = method;
            String methodTypeKey = method + ":" + typeName;
            methodToContextKeys.computeIfAbsent(methodOnly, ignored -> ConcurrentHashMap.newKeySet()).add(contextKey);
            methodToContextKeys.computeIfAbsent(methodTypeKey, ignored -> ConcurrentHashMap.newKeySet()).add(contextKey);
        }

        notifyListeners();
        return toAuthContext(sessions.get(contextKey));
    }

    public boolean setRole(String contextKeyOrSessionId, RoleType role) {
        if (contextKeyOrSessionId == null || contextKeyOrSessionId.isBlank()) {
            return false;
        }

        RoleType nextRole = role == null ? RoleType.UNKNOWN : role;
        SessionState updated = sessions.computeIfPresent(contextKeyOrSessionId, (ignored, existing) -> {
            if (shouldBlockRoleOverwrite(existing.role, nextRole)) {
                return existing;
            }
            applyRoleToState(existing.contextKey, existing, nextRole);
            return existing;
        });

        if (updated == null) {
            Set<String> contextKeys = sessionIdToContextKeys.get(contextKeyOrSessionId);
            if (contextKeys == null || contextKeys.isEmpty()) {
                return false;
            }

            boolean anyUpdated = false;
            for (String contextKey : contextKeys) {
                SessionState contextUpdated = sessions.computeIfPresent(contextKey, (ignored, existing) -> {
                    if (shouldBlockRoleOverwrite(existing.role, nextRole)) {
                        return existing;
                    }
                    applyRoleToState(existing.contextKey, existing, nextRole);
                    return existing;
                });
                anyUpdated = anyUpdated || (contextUpdated != null && contextUpdated.role == nextRole);
            }

            if (!anyUpdated) {
                return false;
            }

            notifyListeners();
            return true;
        }

        notifyListeners();
        return updated.role == nextRole;
    }

    public RoleType roleForRecordId(String recordId) {
        if (recordId == null || recordId.isBlank()) {
            return RoleType.UNKNOWN;
        }
        String contextKey = recordToContextKey.get(recordId);
        return roleForContextKey(contextKey);
    }

    public RoleType roleForMethod(String methodName) {
        if (methodName == null || methodName.isBlank()) {
            return RoleType.UNKNOWN;
        }

        Set<String> contextKeys = methodToContextKeys.get(methodName);
        if ((contextKeys == null || contextKeys.isEmpty()) && !methodName.contains(":")) {
            List<String> collected = new ArrayList<>();
            for (Map.Entry<String, Set<String>> entry : methodToContextKeys.entrySet()) {
                if (entry.getKey().startsWith(methodName + ":")) {
                    collected.addAll(entry.getValue());
                }
            }
            contextKeys = Set.copyOf(collected);
        }

        if (contextKeys == null || contextKeys.isEmpty()) {
            return RoleType.UNKNOWN;
        }

        boolean hasAdmin = false;
        boolean hasLowPriv = false;
        boolean hasUnknown = false;
        for (String contextKey : contextKeys) {
            RoleType role = roleForContextKey(contextKey);
            switch (role) {
                case ADMIN -> hasAdmin = true;
                case LOW_PRIV -> hasLowPriv = true;
                case UNKNOWN -> hasUnknown = true;
                default -> {
                }
            }
        }

        if (hasAdmin && hasLowPriv) {
            return RoleType.MIXED;
        }
        if (hasAdmin) {
            return RoleType.ADMIN;
        }
        if (hasLowPriv) {
            return RoleType.LOW_PRIV;
        }
        return hasUnknown ? RoleType.UNKNOWN : RoleType.UNKNOWN;
    }

    public RoleType roleForContextKey(String contextKey) {
        if (contextKey == null || contextKey.isBlank()) {
            return RoleType.UNKNOWN;
        }
        RoleType stored = rolesByContextKey.get(contextKey);
        if (stored != null) {
            return stored;
        }
        SessionState state = sessions.get(contextKey);
        return state == null ? RoleType.UNKNOWN : state.role;
    }

    // Compatibility method for existing UI call sites.
    public boolean setRoleForMethod(String methodName, RoleType roleType) {
        if (methodName == null || methodName.isBlank()) {
            return false;
        }

        Set<String> contextKeys = methodToContextKeys.get(methodName);
        if ((contextKeys == null || contextKeys.isEmpty()) && !methodName.contains(":")) {
            Set<String> merged = new LinkedHashSet<>();
            for (Map.Entry<String, Set<String>> entry : methodToContextKeys.entrySet()) {
                if (entry.getKey().startsWith(methodName + ":")) {
                    merged.addAll(entry.getValue());
                }
            }
            contextKeys = merged;
        }

        if (contextKeys == null || contextKeys.isEmpty()) {
            return false;
        }

        boolean updated = false;
        for (String contextKey : contextKeys) {
            updated = setRole(contextKey, roleType) || updated;
        }
        return updated;
    }

    public List<String> contextKeysForMethod(String methodName) {
        if (methodName == null || methodName.isBlank()) {
            return List.of();
        }

        Set<String> exact = methodToContextKeys.get(methodName);
        if (exact != null && !exact.isEmpty()) {
            return List.copyOf(exact);
        }

        if (methodName.contains(":")) {
            return List.of();
        }

        Set<String> merged = new LinkedHashSet<>();
        for (Map.Entry<String, Set<String>> entry : methodToContextKeys.entrySet()) {
            if (entry.getKey().startsWith(methodName + ":")) {
                merged.addAll(entry.getValue());
            }
        }
        return List.copyOf(merged);
    }

    public boolean setRoleForRecord(String recordId, RoleType roleType) {
        if (recordId == null || recordId.isBlank()) {
            return false;
        }
        String contextKey = recordToContextKey.get(recordId);
        return setRole(contextKey, roleType);
    }

    public boolean setRoleForContextKey(String contextKey, RoleType roleType) {
        return setRole(contextKey, roleType);
    }

    public String contextKeyForRecord(String recordId) {
        if (recordId == null || recordId.isBlank()) {
            return "";
        }
        String contextKey = recordToContextKey.get(recordId);
        return contextKey == null ? "" : contextKey;
    }

    /**
     * Non-mutating context lookup — returns the current AuthContext for a request
     * without incrementing counters, updating timestamps, or triggering listeners.
     * Use this in downstream services that already had their record observed by the collector.
     */
    public AuthContext lookupContext(String requestBody, String requestUrl) {
        Credentials credentials = extractCredentials(requestBody);
        if (credentials == null || credentials.sessionId().isBlank()) {
            return AuthContext.unknown("unknown-session");
        }
        String host = defaultIfBlank(extractHost(requestUrl), "unknown-host");
        String database = defaultIfBlank(credentials.database(), "unknown-db");
        String userName = defaultIfBlank(credentials.userName(), "unknown-user");
        String contextKey = resolveCompatibleContextKey(host, database, credentials.sessionId(), userName);
        SessionState state = sessions.get(contextKey);
        if (state == null) {
            return AuthContext.unknown("unknown-session");
        }
        return toAuthContext(state);
    }

    public List<AuthContext> snapshotContexts() {
        List<AuthContext> out = new ArrayList<>();
        for (SessionState state : sessions.values()) {
            out.add(toAuthContext(state));
        }
        out.sort(Comparator.comparing(AuthContext::lastSeen, Comparator.nullsLast(Comparator.reverseOrder())));
        return out;
    }

    public List<SessionView> snapshotSessions() {
        List<SessionView> out = new ArrayList<>();
        for (SessionState state : sessions.values()) {
            out.add(new SessionView(
                    state.contextKey,
                    state.sessionId,
                    state.host,
                    state.database,
                    state.userName,
                    state.role,
                    state.lastSeen,
                    state.requestCount,
                    List.copyOf(state.securityGroups)
            ));
        }
        out.sort(Comparator.comparing(SessionView::lastSeen, Comparator.nullsLast(Comparator.reverseOrder())));
        return out;
    }

    public AuthContext firstContextByRole(RoleType role) {
        if (role == null) {
            return null;
        }

        AuthContext selected = null;
        for (SessionState state : sessions.values()) {
            if (state.role != role) {
                continue;
            }
            AuthContext candidate = toAuthContext(state);
            if (selected == null) {
                selected = candidate;
                continue;
            }
            Instant selectedSeen = selected.lastSeen();
            Instant candidateSeen = candidate.lastSeen();
            if (selectedSeen == null || (candidateSeen != null && candidateSeen.isAfter(selectedSeen))) {
                selected = candidate;
            }
        }
        return selected;
    }

    public void clear() {
        sessions.clear();
        rolesByContextKey.clear();
        recordToContextKey.clear();
        methodToContextKeys.clear();
        sessionIdToContextKeys.clear();
        notifyListeners();
    }

    private String resolveCompatibleContextKey(String host, String database, String sessionId, String userName) {
        String exact = buildContextKey(host, database, sessionId, userName);
        if (sessions.containsKey(exact)) {
            return exact;
        }

        List<String> contextKeys = new ArrayList<>(sessionIdToContextKeys.getOrDefault(sessionId, Set.of()));
        List<SessionState> compatibleStates = new ArrayList<>();
        String bestMatch = "";
        int bestScore = Integer.MIN_VALUE;

        for (String contextKey : contextKeys) {
            SessionState state = sessions.get(contextKey);
            if (state == null) {
                continue;
            }
            if (!defaultIfBlank(state.host, "unknown-host").equals(defaultIfBlank(host, "unknown-host"))) {
                continue;
            }
            if (!isCompatibleContextValue(database, state.database)) {
                continue;
            }
            if (!isCompatibleContextValue(userName, state.userName)) {
                continue;
            }
            compatibleStates.add(state);

            int score = 0;
            if (equalsIgnoreCaseSafe(database, state.database)) {
                score += 3;
            } else if (!isUnknownValue(database) && !isUnknownValue(state.database)) {
                score -= 8;
            }

            if (equalsIgnoreCaseSafe(userName, state.userName)) {
                score += 3;
            } else if (!isUnknownValue(userName) && !isUnknownValue(state.userName)) {
                score -= 8;
            }

            if (!isUnknownValue(state.database)) {
                score += 1;
            }
            if (!isUnknownValue(state.userName)) {
                score += 1;
            }

            if (score > bestScore) {
                bestScore = score;
                bestMatch = contextKey;
            }
        }

        // Reconcile only partial-data contexts; never merge if multiple known candidates exist.
        if (isUnknownValue(database) || isUnknownValue(userName)) {
            boolean ambiguousDatabase = isUnknownValue(database)
                    && countDistinctKnownValues(compatibleStates, true) > 1;
            boolean ambiguousUser = isUnknownValue(userName)
                    && countDistinctKnownValues(compatibleStates, false) > 1;
            if (ambiguousDatabase || ambiguousUser) {
                return exact;
            }
        }

        return bestMatch.isBlank() ? exact : bestMatch;
    }

    private static int countDistinctKnownValues(List<SessionState> states, boolean databaseField) {
        Set<String> known = new LinkedHashSet<>();
        for (SessionState state : states) {
            if (state == null) {
                continue;
            }
            String value = databaseField ? state.database : state.userName;
            if (isUnknownValue(value)) {
                continue;
            }
            known.add(defaultIfBlank(value, "").trim().toLowerCase(Locale.ROOT));
        }
        return known.size();
    }

    private static boolean isCompatibleContextValue(String incoming, String existing) {
        if (equalsIgnoreCaseSafe(incoming, existing)) {
            return true;
        }
        return isUnknownValue(incoming) || isUnknownValue(existing);
    }

    private static boolean isUnknownValue(String value) {
        String normalized = defaultIfBlank(value, "").trim().toLowerCase(Locale.ROOT);
        return normalized.isBlank()
                || "unknown".equals(normalized)
                || "unknown-db".equals(normalized)
                || "unknown-user".equals(normalized)
                || "unknown-host".equals(normalized);
    }

    private static boolean equalsIgnoreCaseSafe(String left, String right) {
        return defaultIfBlank(left, "").equalsIgnoreCase(defaultIfBlank(right, ""));
    }

    private static boolean shouldBlockRoleOverwrite(RoleType currentRole, RoleType nextRole) {
        // Allow any role transition — users must be able to correct mistaken tags
        // and switch between ADMIN / LOW_PRIV without a two-step UNKNOWN reset.
        return false;
    }

    private void applyRoleToState(String contextKey, SessionState state, RoleType nextRole) {
        state.role = nextRole;
        if (nextRole == RoleType.UNKNOWN) {
            rolesByContextKey.remove(contextKey);
            return;
        }
        rolesByContextKey.put(contextKey, nextRole);
    }

    private Credentials extractFromCall(JsonNode callNode) {
        if (callNode == null || !callNode.isObject()) {
            return null;
        }

        JsonNode paramsNode = callNode.get("params");
        if (paramsNode == null || paramsNode.isNull()) {
            return null;
        }

        JsonNode credentialsNode = paramsNode.get("credentials");
        if (credentialsNode == null || credentialsNode.isNull() || !credentialsNode.isObject()) {
            return null;
        }

        String sessionId = asText(credentialsNode.get("sessionId"));
        if (sessionId.isBlank()) {
            return null;
        }

        String database = asText(credentialsNode.get("database"));
        String userName = asText(credentialsNode.get("userName"));
        String typeName = asText(paramsNode.get("typeName"));
        String methodName = asText(callNode.get("method"));

        return new Credentials(sessionId, database, userName, typeName, methodName);
    }

    private List<String> extractSecurityGroups(String responseBody) {
        JsonNode response = parseJson(responseBody);
        if (response == null) {
            return List.of();
        }

        LinkedHashSet<String> out = new LinkedHashSet<>();
        collectSecurityGroupsFromNode(response, out, 0);
        return List.copyOf(out);
    }

    private void collectSecurityGroupsFromNode(JsonNode node, Set<String> out, int depth) {
        if (node == null || node.isNull() || node.isMissingNode() || depth > 8 || out.size() >= 40) {
            return;
        }

        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext() && out.size() < 40) {
                Map.Entry<String, JsonNode> entry = fields.next();
                String key = entry.getKey() == null ? "" : entry.getKey().toLowerCase(Locale.ROOT);
                JsonNode value = entry.getValue();

                if (key.contains("securitygroup") || key.equals("groups") || key.contains("group")) {
                    collectGroupValue(value, out);
                }

                collectSecurityGroupsFromNode(value, out, depth + 1);
            }
            return;
        }

        if (node.isArray()) {
            for (JsonNode item : node) {
                collectSecurityGroupsFromNode(item, out, depth + 1);
                if (out.size() >= 40) {
                    return;
                }
            }
        }
    }

    private void collectGroupValue(JsonNode node, Set<String> out) {
        if (node == null || node.isNull() || out.size() >= 40) {
            return;
        }

        if (node.isTextual() || node.isNumber() || node.isBoolean()) {
            String value = node.asText("").trim();
            if (!value.isBlank()) {
                out.add(value);
            }
            return;
        }

        if (node.isObject()) {
            String id = asText(node.get("id"));
            String name = asText(node.get("name"));
            String joined = !name.isBlank() ? name : id;
            if (!joined.isBlank()) {
                out.add(joined);
            }
            return;
        }

        if (node.isArray()) {
            for (JsonNode item : node) {
                collectGroupValue(item, out);
                if (out.size() >= 40) {
                    return;
                }
            }
        }
    }

    private AuthContext toAuthContext(SessionState state) {
        if (state == null) {
            return AuthContext.unknown("unknown-session");
        }

        return new AuthContext(
                state.contextKey,
                defaultIfBlank(state.database, "unknown-db"),
                state.sessionId,
                defaultIfBlank(state.userName, "unknown-user"),
                state.role,
                "",
                "",
                defaultIfBlank(state.lastSeenUrl, ""),
                state.lastSeen,
                state.requestCount,
                List.copyOf(state.securityGroups)
        );
    }

    private void notifyListeners() {
        for (Runnable listener : updateListeners) {
            try {
                listener.run();
            } catch (Exception ignored) {
                // Listener failures should not interrupt ingestion.
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

    private static String asText(JsonNode node) {
        if (node == null || node.isNull()) {
            return "";
        }
        String value = node.asText("");
        return value == null ? "" : value.trim();
    }

    private static String defaultIfBlank(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }

    private static String extractHost(String url) {
        if (url == null || url.isBlank()) {
            return "";
        }
        return defaultIfBlank(MyGeotabScope.extractHost(url), "");
    }

    private static String buildContextKey(String host, String database, String sessionId, String userName) {
        return "host=" + defaultIfBlank(host, "unknown-host")
                + "|db=" + defaultIfBlank(database, "unknown-db")
                + "|sid=" + defaultIfBlank(sessionId, "unknown-session")
                + "|user=" + defaultIfBlank(userName, "unknown-user");
    }

    private static final class SessionState {
        private final String contextKey;
        private String host;
        private final String sessionId;
        private String database;
        private String userName;
        private RoleType role;
        private Instant lastSeen;
        private int requestCount;
        private final LinkedHashSet<String> securityGroups;
        private String lastSeenUrl;

        private SessionState(String contextKey, String host, String sessionId, String database, String userName) {
            this.contextKey = contextKey;
            this.host = host;
            this.sessionId = sessionId;
            this.database = database;
            this.userName = userName;
            this.role = RoleType.UNKNOWN;
            this.lastSeen = Instant.now();
            this.requestCount = 0;
            this.securityGroups = new LinkedHashSet<>();
            this.lastSeenUrl = "";
        }
    }

    public record Credentials(
            String sessionId,
            String database,
            String userName,
            String typeName,
            String methodName
    ) {
    }

    public record SessionView(
            String contextKey,
            String sessionId,
            String host,
            String database,
            String userName,
            RoleType role,
            Instant lastSeen,
            int requestCount,
            List<String> securityGroups
    ) {
    }

    public record AuthContext(
            String contextKey,
            String database,
            String sessionId,
            String userName,
            RoleType role,
            String rawAuthorizationHeader,
            String rawCookieHeader,
            String lastSeenUrl,
            Instant lastSeen,
            int requestCount,
            List<String> securityGroups
    ) {
        public static AuthContext unknown(String key) {
            return new AuthContext(key, "unknown-db", "", "unknown-user", RoleType.UNKNOWN,
                    "", "", "", Instant.now(), 0, List.of());
        }
    }
}
