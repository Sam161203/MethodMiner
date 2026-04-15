import burp.api.montoya.logging.Logging;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

public final class EntityStoreService implements AutoCloseable {
    private static final int MAX_METHODS_PER_ENTITY = 80;
    private static final int MAX_CONTEXTS_PER_ENTITY = 80;
    private static final int MAX_PATHS_PER_ENTITY = 40;
    private static final int MAX_SAMPLES_PER_ENTITY = 24;
    private static final long NOTIFY_INTERVAL_MILLIS = 500L;

    private static final Pattern EMAIL_PATTERN = Pattern.compile("(?i)^[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}$");

    private final ObjectMapper objectMapper;
    private final Logging logging;
    private final AuthContextStore authContextStore;

    private final ExecutorService analyzerExecutor = Executors.newSingleThreadExecutor(
            runnable -> new Thread(runnable, "jsonrpc-entity-store")
    );
    private final List<Runnable> updateListeners = new CopyOnWriteArrayList<>();
    private final ConcurrentMap<String, EntityAggregate> entities = new ConcurrentHashMap<>();

    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final AtomicLong lastUiNotificationEpochMillis = new AtomicLong(0L);

    public EntityStoreService(ObjectMapper objectMapper, Logging logging) {
        this(objectMapper, logging, null);
    }

    public EntityStoreService(ObjectMapper objectMapper, Logging logging, AuthContextStore authContextStore) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
        this.logging = Objects.requireNonNull(logging, "logging must not be null");
        this.authContextStore = authContextStore;
    }

    public void registerUpdateListener(Runnable listener) {
        if (listener != null) {
            updateListeners.add(listener);
        }
    }

    public void ingestRecordAsync(JsonRpcRecord rawRecord, JsonRpcNormalizedRecord normalizedRecord, boolean replayed) {
        if (closed.get()) {
            return;
        }

        analyzerExecutor.submit(() -> {
            try {
                ingestRecordSync(rawRecord, normalizedRecord);
                notifyListenersThrottled();
            } catch (Exception ex) {
                logging.logToError("Entity store failed while processing record.", ex);
            }
        });
    }

    void ingestRecordSync(JsonRpcRecord rawRecord, JsonRpcNormalizedRecord normalizedRecord) {
        if (rawRecord == null || normalizedRecord == null) {
            return;
        }

        String authContext = authContextStore == null
            ? authContextFingerprint(rawRecord)
            : authContextStore.observeRecord(rawRecord, normalizedRecord.methodName()).contextKey();
        List<EntityOccurrence> requestValues = extractEntityOccurrences(rawRecord.request().bodyText(), ValueOrigin.REQUEST);
        List<EntityOccurrence> responseValues = extractEntityOccurrences(rawRecord.response().bodyText(), ValueOrigin.RESPONSE);

        List<EntityOccurrence> allValues = new ArrayList<>(requestValues.size() + responseValues.size());
        allValues.addAll(requestValues);
        allValues.addAll(responseValues);

        for (EntityOccurrence occurrence : allValues) {
            entities.computeIfAbsent(occurrence.canonicalValue(), key -> new EntityAggregate(
                    occurrence.canonicalValue(),
                    occurrence.preview(),
                    occurrence.entityType()
            )).observe(
                    occurrence,
                    normalizedRecord.methodName(),
                    authContext,
                    normalizedRecord.timestamp(),
                    normalizedRecord.responseStatus()
            );
        }
    }

    public List<EntityRow> snapshotRows() {
        List<EntityRow> rows = new ArrayList<>();
        for (EntityAggregate aggregate : entities.values()) {
            rows.add(aggregate.toRow());
        }

        rows.sort(Comparator
                .comparingInt(EntityRow::riskScore).reversed()
                .thenComparingInt(EntityRow::uniqueMethods).reversed()
                .thenComparingLong(EntityRow::observations).reversed()
                .thenComparing(EntityRow::preview, String.CASE_INSENSITIVE_ORDER));
        return rows;
    }

    public Optional<EntityDetails> snapshotEntityDetails(String entityKey) {
        EntityAggregate aggregate = entities.get(entityKey);
        if (aggregate == null) {
            return Optional.empty();
        }
        return Optional.of(aggregate.toDetails());
    }

    public EntityStats snapshotStats() {
        long total = 0;
        long crossMethod = 0;
        long crossContext = 0;
        for (EntityAggregate aggregate : entities.values()) {
            EntityRow row = aggregate.toRow();
            total++;
            if (row.crossMethodReuse()) {
                crossMethod++;
            }
            if (row.crossContextReuse()) {
                crossContext++;
            }
        }
        return new EntityStats(total, crossMethod, crossContext);
    }

    public ObjectNode buildManualExportBundle(String entityKey) {
        EntityDetails details = snapshotEntityDetails(entityKey)
                .orElseThrow(() -> new IllegalArgumentException("Unknown entity key: " + entityKey));

        ObjectNode root = objectMapper.createObjectNode();
        root.put("generatedAt", Instant.now().toString());
        root.put("mode", "manual-only");
        root.put("entityKey", details.row().entityKey());
        root.put("entityType", details.row().entityType().displayName());
        root.put("preview", details.row().preview());
        root.put("risk", details.row().riskDisplay());
        root.put("crossMethodReuse", details.row().crossMethodReuse());
        root.put("crossContextReuse", details.row().crossContextReuse());
        root.put("note", "Entity reuse export is for manual validation in Repeater only. No requests are sent automatically.");

        ArrayNode methodArray = objectMapper.createArrayNode();
        for (String method : details.methods()) {
            methodArray.add(method);
        }
        root.set("methods", methodArray);

        ArrayNode producerArray = objectMapper.createArrayNode();
        for (String method : details.producerMethods()) {
            producerArray.add(method);
        }
        root.set("producerMethods", producerArray);

        ArrayNode consumerArray = objectMapper.createArrayNode();
        for (String method : details.consumerMethods()) {
            consumerArray.add(method);
        }
        root.set("consumerMethods", consumerArray);

        ArrayNode contextArray = objectMapper.createArrayNode();
        for (String context : details.authContexts()) {
            contextArray.add(context);
        }
        root.set("authContexts", contextArray);

        ArrayNode pathArray = objectMapper.createArrayNode();
        for (String path : details.paths()) {
            pathArray.add(path);
        }
        root.set("paths", pathArray);

        ArrayNode sampleArray = objectMapper.createArrayNode();
        for (String sample : details.samples()) {
            sampleArray.add(sample);
        }
        root.set("samples", sampleArray);

        ArrayNode reasoningArray = objectMapper.createArrayNode();
        for (String reason : details.riskReasons()) {
            reasoningArray.add(reason);
        }
        root.set("riskReasons", reasoningArray);

        ArrayNode testPlan = objectMapper.createArrayNode();
        for (String step : manualTestPlan(details)) {
            testPlan.add(step);
        }
        root.set("manualTestPlan", testPlan);

        return root;
    }

    public void clear() {
        entities.clear();
        notifyListeners();
    }

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }

        analyzerExecutor.shutdown();
        try {
            if (!analyzerExecutor.awaitTermination(15, TimeUnit.SECONDS)) {
                analyzerExecutor.shutdownNow();
            }
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            analyzerExecutor.shutdownNow();
        }
    }

    private void notifyListenersThrottled() {
        long now = System.currentTimeMillis();
        long previous = lastUiNotificationEpochMillis.get();
        if (now - previous < NOTIFY_INTERVAL_MILLIS) {
            return;
        }
        if (lastUiNotificationEpochMillis.compareAndSet(previous, now)) {
            notifyListeners();
        }
    }

    private void notifyListeners() {
        for (Runnable listener : updateListeners) {
            try {
                listener.run();
            } catch (Exception ex) {
                logging.logToError("Entity store listener failed.", ex);
            }
        }
    }

    private List<EntityOccurrence> extractEntityOccurrences(String body, ValueOrigin origin) {
        if (body == null || body.isBlank()) {
            return List.of();
        }

        final JsonNode root;
        try {
            root = objectMapper.readTree(body);
        } catch (Exception ignored) {
            return List.of();
        }

        List<EntityOccurrence> out = new ArrayList<>();
        visitNode(root, "$", "", origin, out);
        return out;
    }

    private void visitNode(JsonNode node, String path, String keyName, ValueOrigin origin, List<EntityOccurrence> out) {
        if (node == null) {
            return;
        }

        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                String childKey = field.getKey();
                String childPath = "$".equals(path) ? "$." + childKey : path + "." + childKey;
                JsonNode child = field.getValue();

                addOccurrenceIfCandidate(child, childPath, childKey, origin, out);
                visitNode(child, childPath, childKey, origin, out);
            }
            return;
        }

        if (node.isArray()) {
            for (int i = 0; i < node.size(); i++) {
                JsonNode child = node.get(i);
                String arrayKey = keyName.isBlank() ? "array" : keyName + "[]";
                String childPath = path + "[" + i + "]";

                addOccurrenceIfCandidate(child, childPath, arrayKey, origin, out);
                visitNode(child, childPath, arrayKey, origin, out);
            }
        }
    }

    private void addOccurrenceIfCandidate(
            JsonNode node,
            String path,
            String keyName,
            ValueOrigin origin,
            List<EntityOccurrence> out
    ) {
        if (node == null) {
            return;
        }

        String loweredKey = keyName == null ? "" : keyName.toLowerCase(Locale.ROOT);
        if ("jsonrpc".equals(loweredKey) || "method".equals(loweredKey)) {
            return;
        }
        if ("$.id".equals(path)) {
            return;
        }

        if (node.isValueNode()) {
            String canonical = canonicalizeScalar(node, loweredKey, path);
            if (canonical == null) {
                return;
            }

            EntityType entityType = classifyEntityType(loweredKey, path, canonical);
            String preview = preview(canonical);
            out.add(new EntityOccurrence(canonical, preview, path, entityType, origin));
            return;
        }

        if ((node.isObject() || node.isArray()) && shouldTrackObjectReference(loweredKey, node)) {
            String serialized = node.toString();
            String canonical = "objref:" + shortHash(serialized);
            String preview = "object-ref:" + shortHash(serialized);
            out.add(new EntityOccurrence(canonical, preview, path, EntityType.OBJECT_REFERENCE, origin));
        }
    }

    private static String canonicalizeScalar(JsonNode node, String loweredKey, String path) {
        if (node.isNull() || node.isBoolean()) {
            return null;
        }

        final String raw;
        if (node.isTextual()) {
            raw = node.asText("").trim();
        } else if (node.isNumber()) {
            raw = node.asText("");
        } else {
            return null;
        }

        if (raw.isBlank()) {
            return null;
        }

        boolean idLike = isIdLikeKey(loweredKey) || path.endsWith(".id") || path.contains("_id");
        if (!idLike && raw.length() < 4) {
            return null;
        }

        if (!idLike && raw.contains(" ") && raw.length() > 48) {
            return null;
        }

        String canonical = raw;
        if (EMAIL_PATTERN.matcher(canonical).matches()) {
            canonical = canonical.toLowerCase(Locale.ROOT);
        }

        if (!idLike && canonical.length() > 140) {
            canonical = "hash:" + shortHash(canonical);
        }

        return canonical;
    }

    private static boolean shouldTrackObjectReference(String loweredKey, JsonNode node) {
        if (loweredKey == null || loweredKey.isBlank()) {
            return false;
        }

        boolean referenceHint = loweredKey.contains("ref")
                || loweredKey.contains("object")
                || loweredKey.contains("item")
                || loweredKey.contains("entity");

        if (!referenceHint) {
            return false;
        }

        if (node.isObject()) {
            return node.size() > 0 && node.size() <= 14;
        }

        if (node.isArray()) {
            return node.size() > 0 && node.size() <= 10;
        }

        return false;
    }

    private static EntityType classifyEntityType(String loweredKey, String path, String value) {
        if (loweredKey.contains("tenant") || loweredKey.contains("organization") || loweredKey.contains("org")) {
            return EntityType.TENANT_ID;
        }
        if (loweredKey.contains("user") || loweredKey.contains("login")) {
            return EntityType.USER_ID;
        }
        if (loweredKey.contains("account") || loweredKey.contains("customer") || loweredKey.contains("billing")) {
            return EntityType.ACCOUNT_ID;
        }
        if (loweredKey.contains("order")) {
            return EntityType.ORDER_ID;
        }
        if (loweredKey.contains("device")) {
            return EntityType.DEVICE_ID;
        }
        if (loweredKey.contains("report") || loweredKey.contains("export")) {
            return EntityType.REPORT_ID;
        }
        if (loweredKey.contains("session") || loweredKey.contains("token") || loweredKey.contains("jwt") || loweredKey.contains("auth")) {
            return EntityType.SESSION_TOKEN;
        }
        if (loweredKey.contains("email") || EMAIL_PATTERN.matcher(value).matches()) {
            return EntityType.EMAIL;
        }
        if (loweredKey.contains("ref") || loweredKey.contains("object")) {
            return EntityType.OBJECT_REFERENCE;
        }

        if (isIdLikeKey(loweredKey) || path.endsWith(".id") || path.contains("_id")) {
            return EntityType.GENERIC_ID;
        }

        return EntityType.OTHER;
    }

    private static boolean isIdLikeKey(String loweredKey) {
        if (loweredKey == null || loweredKey.isBlank()) {
            return false;
        }
        return loweredKey.equals("id")
                || loweredKey.endsWith("id")
                || loweredKey.contains("_id")
                || loweredKey.contains("tenant")
                || loweredKey.contains("user")
                || loweredKey.contains("account")
                || loweredKey.contains("order")
                || loweredKey.contains("device")
                || loweredKey.contains("report")
                || loweredKey.contains("session")
                || loweredKey.contains("token")
                || loweredKey.contains("ref");
    }

    private static String authContextFingerprint(JsonRpcRecord rawRecord) {
        String host = extractHost(rawRecord.request().url());
        String authScheme = "none";
        String cookieHash = "none";

        List<String> headers = rawRecord.request().headers();
        StringBuilder cookieMaterial = new StringBuilder();
        for (String header : headers) {
            if (header == null || header.isBlank()) {
                continue;
            }
            String lowered = header.toLowerCase(Locale.ROOT);
            if (lowered.startsWith("authorization:")) {
                int split = header.indexOf(':');
                String value = split > -1 ? header.substring(split + 1).trim() : "";
                authScheme = value.contains(" ") ? value.substring(0, value.indexOf(' ')) : value;
                if (authScheme.isBlank()) {
                    authScheme = "present";
                }
            }
            if (lowered.startsWith("cookie:")) {
                cookieMaterial.append(header.trim()).append('|');
            }
        }

        if (!cookieMaterial.isEmpty()) {
            cookieHash = shortHash(cookieMaterial.toString());
        }

        return "host=" + defaultIfBlank(host, "unknown")
                + "|auth=" + defaultIfBlank(authScheme, "none")
                + "|cookie=" + defaultIfBlank(cookieHash, "none");
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

    private static List<String> manualTestPlan(EntityDetails details) {
        List<String> plan = new ArrayList<>();
        plan.add("Capture at least two authenticated contexts (for example user A and user B) in Burp Proxy.");
        plan.add("Replay a producer request to obtain fresh identifiers from context A.");
        plan.add("Use Repeater to inject the same identifier into consumer methods under context B.");
        if (details.row().crossContextReuse()) {
            plan.add("Because this entity was seen across multiple auth contexts, prioritize ownership validation and tenant-boundary checks.");
        }
        if (details.row().entityType().isSensitive()) {
            plan.add("Entity type is security-sensitive. Validate authorization checks before and after identifier substitution.");
        }
        plan.add("Document status code, response class differences, and any unauthorized data access behavior.");
        return plan;
    }

    private static String shortHash(String value) {
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

    private static String preview(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        return value.length() <= 72 ? value : value.substring(0, 72) + "...";
    }

    private static String defaultIfBlank(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }

    private enum ValueOrigin {
        REQUEST,
        RESPONSE
    }

    private record EntityOccurrence(
            String canonicalValue,
            String preview,
            String path,
            EntityType entityType,
            ValueOrigin origin
    ) {
    }

    public enum EntityType {
        TENANT_ID("Tenant ID", true),
        USER_ID("User ID", true),
        ACCOUNT_ID("Account ID", true),
        ORDER_ID("Order ID", true),
        DEVICE_ID("Device ID", true),
        REPORT_ID("Report ID", true),
        SESSION_TOKEN("Session/Token", true),
        EMAIL("Email", true),
        GENERIC_ID("Generic ID", true),
        OBJECT_REFERENCE("Object Reference", false),
        OTHER("Other", false);

        private final String displayName;
        private final boolean sensitive;

        EntityType(String displayName, boolean sensitive) {
            this.displayName = displayName;
            this.sensitive = sensitive;
        }

        public String displayName() {
            return displayName;
        }

        public boolean isSensitive() {
            return sensitive;
        }
    }

    private static final class EntityAggregate {
        private final String entityKey;
        private final String preview;
        private final EntityType entityType;

        private long observations;
        private Instant firstSeen;
        private Instant lastSeen;

        private final Set<String> methods = new TreeSet<>();
        private final Set<String> producerMethods = new TreeSet<>();
        private final Set<String> consumerMethods = new TreeSet<>();
        private final Set<String> authContexts = new TreeSet<>();
        private final Set<Integer> statuses = new TreeSet<>();
        private final LimitedSet<String> paths = new LimitedSet<>(MAX_PATHS_PER_ENTITY);
        private final ArrayDeque<String> samples = new ArrayDeque<>();

        private EntityAggregate(String entityKey, String preview, EntityType entityType) {
            this.entityKey = entityKey;
            this.preview = preview;
            this.entityType = entityType;
        }

        synchronized void observe(
                EntityOccurrence occurrence,
                String methodName,
                String authContext,
                Instant timestamp,
                Integer statusCode
        ) {
            observations++;

            if (firstSeen == null || timestamp.isBefore(firstSeen)) {
                firstSeen = timestamp;
            }
            if (lastSeen == null || timestamp.isAfter(lastSeen)) {
                lastSeen = timestamp;
            }

            if (methods.size() < MAX_METHODS_PER_ENTITY || methods.contains(methodName)) {
                methods.add(methodName);
            }

            if (occurrence.origin() == ValueOrigin.RESPONSE) {
                producerMethods.add(methodName);
            } else {
                consumerMethods.add(methodName);
            }

            if (authContexts.size() < MAX_CONTEXTS_PER_ENTITY || authContexts.contains(authContext)) {
                authContexts.add(authContext);
            }

            paths.add(occurrence.origin().name().toLowerCase(Locale.ROOT) + ":" + occurrence.path());

            if (samples.size() >= MAX_SAMPLES_PER_ENTITY) {
                samples.removeFirst();
            }
            samples.addLast("method=" + methodName + " | " + occurrence.origin().name().toLowerCase(Locale.ROOT)
                    + " | path=" + occurrence.path() + " | value=" + occurrence.preview());

            if (statusCode != null) {
                statuses.add(statusCode);
            }
        }

        synchronized EntityRow toRow() {
            RiskComputation risk = computeRisk();
            return new EntityRow(
                    entityKey,
                    preview,
                    entityType,
                    observations,
                    methods.size(),
                    authContexts.size(),
                    producerMethods.size(),
                    consumerMethods.size(),
                    methods.size() > 1,
                    authContexts.size() > 1,
                    firstSeen,
                    lastSeen,
                    risk.score,
                    risk.level
            );
        }

        synchronized EntityDetails toDetails() {
            EntityRow row = toRow();
            RiskComputation risk = computeRisk();

            List<String> sampleCopy = new ArrayList<>(samples);
            return new EntityDetails(
                    row,
                    List.copyOf(methods),
                    List.copyOf(producerMethods),
                    List.copyOf(consumerMethods),
                    List.copyOf(authContexts),
                    List.copyOf(paths),
                    sampleCopy,
                    risk.reasons
            );
        }

        private RiskComputation computeRisk() {
            int score = 0;
            List<String> reasons = new ArrayList<>();

            if (entityType.isSensitive()) {
                score += 20;
                reasons.add("Sensitive entity type: " + entityType.displayName());
            }

            if (producerMethods.size() > 0 && consumerMethods.size() > 0) {
                score += 12;
                reasons.add("Observed in both response and request payloads.");
            }

            if (methods.size() > 1) {
                int contribution = 16 + Math.min(18, (methods.size() - 1) * 3);
                score += contribution;
                reasons.add("Entity reused across methods: " + methods.size());
            }

            if (authContexts.size() > 1) {
                int contribution = 18 + Math.min(16, (authContexts.size() - 1) * 2);
                score += contribution;
                reasons.add("Entity seen across auth contexts: " + authContexts.size());
            }

            if (observations >= 5) {
                score += 8;
                reasons.add("Observed repeatedly in traffic: " + observations + " occurrences.");
            }

            if (statuses.stream().anyMatch(code -> code >= 200 && code < 300)
                    && statuses.stream().anyMatch(code -> code >= 400 && code < 500)) {
                score += 10;
                reasons.add("Entity appears in both success and client-error responses.");
            }

            if (entityType == EntityType.OBJECT_REFERENCE) {
                score += 6;
                reasons.add("Object reference token may map to backend object lookups.");
            }

            score = Math.min(score, 100);
            return new RiskComputation(score, SecurityFinding.RiskLevel.fromScore(score), reasons);
        }
    }

    private record RiskComputation(int score, SecurityFinding.RiskLevel level, List<String> reasons) {
    }

    private static final class LimitedSet<T> extends LinkedHashSet<T> {
        private final int maxSize;

        private LimitedSet(int maxSize) {
            this.maxSize = maxSize;
        }

        @Override
        public boolean add(T value) {
            boolean changed = super.add(value);
            if (size() > maxSize) {
                Iterator<T> iterator = iterator();
                if (iterator.hasNext()) {
                    iterator.next();
                    iterator.remove();
                }
            }
            return changed;
        }
    }

    public record EntityRow(
            String entityKey,
            String preview,
            EntityType entityType,
            long observations,
            int uniqueMethods,
            int authContexts,
            int producerMethods,
            int consumerMethods,
            boolean crossMethodReuse,
            boolean crossContextReuse,
            Instant firstSeen,
            Instant lastSeen,
            int riskScore,
            SecurityFinding.RiskLevel riskLevel
    ) {
        public String riskDisplay() {
            return riskLevel.displayName() + " (" + riskScore + ")";
        }
    }

    public record EntityDetails(
            EntityRow row,
            List<String> methods,
            List<String> producerMethods,
            List<String> consumerMethods,
            List<String> authContexts,
            List<String> paths,
            List<String> samples,
            List<String> riskReasons
    ) {
        public ObjectNode toJson(ObjectMapper mapper) {
            ObjectNode root = mapper.createObjectNode();
            root.put("entityKey", row.entityKey());
            root.put("preview", row.preview());
            root.put("entityType", row.entityType().displayName());
            root.put("risk", row.riskDisplay());
            root.put("observations", row.observations());
            root.put("crossMethodReuse", row.crossMethodReuse());
            root.put("crossContextReuse", row.crossContextReuse());
            root.put("firstSeen", row.firstSeen() == null ? "" : row.firstSeen().toString());
            root.put("lastSeen", row.lastSeen() == null ? "" : row.lastSeen().toString());

            root.set("methods", toArray(mapper, methods));
            root.set("producerMethods", toArray(mapper, producerMethods));
            root.set("consumerMethods", toArray(mapper, consumerMethods));
            root.set("authContexts", toArray(mapper, authContexts));
            root.set("paths", toArray(mapper, paths));
            root.set("samples", toArray(mapper, samples));
            root.set("riskReasons", toArray(mapper, riskReasons));
            return root;
        }

        private static ArrayNode toArray(ObjectMapper mapper, List<String> values) {
            ArrayNode array = mapper.createArrayNode();
            for (String value : values) {
                array.add(value == null ? "" : value);
            }
            return array;
        }
    }

    public record EntityStats(long totalEntities, long crossMethodEntities, long crossContextEntities) {
    }
}
