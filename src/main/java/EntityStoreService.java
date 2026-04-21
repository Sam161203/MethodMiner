import burp.api.montoya.logging.Logging;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

public final class EntityStoreService implements AutoCloseable {
    private static final int MAX_METHODS_PER_ENTITY = 80;
    private static final int MAX_CONTEXTS_PER_ENTITY = 80;
    private static final int MAX_SAMPLES_PER_ENTITY = 24;
    private static final long NOTIFY_INTERVAL_MILLIS = 500L;

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

        AuthContextStore.AuthContext context = authContextStore == null
                ? AuthContextStore.AuthContext.unknown("unknown-session")
                : authContextStore.lookupContext(rawRecord.request().bodyText(), rawRecord.request().url());

        List<ExtractedEntity> extracted = extractEntities(
            rawRecord.request().bodyText(),
                rawRecord.response().bodyText(),
                normalizedRecord.typeName(),
                defaultIfBlank(context.database(), "unknown-db"),
            defaultIfBlank(context.contextKey(), "")
        );

        for (ExtractedEntity entity : extracted) {
            entities.compute(entity.entityId(), (ignored, existing) -> {
                EntityAggregate aggregate = existing == null ? new EntityAggregate(entity.entityId()) : existing;
                aggregate.observe(entity, normalizedRecord.methodName(), normalizedRecord.timestamp());
                return aggregate;
            });
        }
    }

    public List<ExtractedEntity> snapshotExtractedEntities() {
        List<ExtractedEntity> out = new ArrayList<>();
        for (EntityAggregate aggregate : entities.values()) {
            out.add(aggregate.toExtractedEntity());
        }
        out.sort(Comparator.comparing(ExtractedEntity::entityId, String.CASE_INSENSITIVE_ORDER));
        return out;
    }

    public Optional<ExtractedEntity> snapshotExtractedEntity(String entityId) {
        if (entityId == null || entityId.isBlank()) {
            return Optional.empty();
        }
        EntityAggregate aggregate = entities.get(entityId);
        return aggregate == null ? Optional.empty() : Optional.of(aggregate.toExtractedEntity());
    }

    public List<EntityRow> snapshotRows() {
        List<EntityRow> rows = new ArrayList<>();
        for (EntityAggregate aggregate : entities.values()) {
            rows.add(aggregate.toRow());
        }

        rows.sort(Comparator
                .comparingInt(EntityRow::riskScore).reversed()
            .thenComparingInt(EntityRow::authContexts).reversed()
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

    private static List<String> manualTestPlan(EntityDetails details) {
        List<String> plan = new ArrayList<>();
        plan.add("Capture at least two authenticated contexts (for example user A and user B) in Burp Proxy.");
        plan.add("Capture an entity ID from admin or higher-privileged session responses.");
        plan.add("Replay with LOW_PRIV credentials while keeping method and search shape unchanged.");
        if (details.row().crossContextReuse()) {
            plan.add("Because this entity was seen across multiple auth contexts, prioritize ownership validation and tenant-boundary checks.");
        }
        if (details.row().entityType().isSensitive()) {
            plan.add("Entity type is security-sensitive. Validate authorization checks before and after identifier substitution.");
        }
        plan.add("Document status code, response class differences, and any unauthorized data access behavior.");
        return plan;
    }

    private static String defaultIfBlank(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }

    private List<ExtractedEntity> extractEntities(
            String requestBody,
            String responseBody,
            String fallbackTypeName,
            String database,
            String contextKey
    ) {
        List<ExtractedEntity> out = new ArrayList<>();
        LinkedHashSet<String> dedupe = new LinkedHashSet<>();

        JsonNode requestRoot = parseJson(requestBody);
        if (requestRoot != null) {
            collectRequestEntities(requestRoot, fallbackTypeName, database, contextKey, out, dedupe);
        }

        JsonNode responseRoot = parseJson(responseBody);
        if (responseRoot != null) {
            collectResponseEntities(responseRoot, fallbackTypeName, database, contextKey, out, dedupe);
        }

        return List.copyOf(out);
    }

    private JsonNode parseJson(String payload) {
        if (payload == null || payload.isBlank()) {
            return null;
        }
        try {
            return objectMapper.readTree(payload);
        } catch (Exception ignored) {
            return null;
        }
    }

    private void collectRequestEntities(
            JsonNode requestRoot,
            String fallbackTypeName,
            String database,
            String contextKey,
            List<ExtractedEntity> out,
            Set<String> dedupe
    ) {
        if (requestRoot.isObject()) {
            JsonNode params = requestRoot.path("params");
            if (!params.isMissingNode() && !params.isNull()) {
                collectIdLikeValues(
                        params,
                        "$.params",
                        fallbackTypeName,
                        database,
                        contextKey,
                        ExtractionSource.REQUEST,
                        out,
                        dedupe,
                        0
                );
            }
        }

        if (requestRoot.isArray()) {
            for (int i = 0; i < requestRoot.size(); i++) {
                JsonNode call = requestRoot.get(i);
                if (call == null || !call.isObject()) {
                    continue;
                }
                JsonNode params = call.path("params");
                if (params.isMissingNode() || params.isNull()) {
                    continue;
                }
                collectIdLikeValues(
                        params,
                        "$.calls[" + i + "].params",
                        fallbackTypeName,
                        database,
                        contextKey,
                        ExtractionSource.REQUEST,
                        out,
                        dedupe,
                        0
                );
            }
        }
    }

    private void collectResponseEntities(
            JsonNode responseRoot,
            String fallbackTypeName,
            String database,
            String contextKey,
            List<ExtractedEntity> out,
            Set<String> dedupe
    ) {
        JsonNode resultNode = responseRoot.path("result");
        if (resultNode.isMissingNode() || resultNode.isNull()) {
            resultNode = responseRoot.path("data");
        }
        if (resultNode.isMissingNode() || resultNode.isNull()) {
            resultNode = responseRoot;
        }

        collectIdLikeValues(
                resultNode,
                "$.result",
                fallbackTypeName,
                database,
                contextKey,
                ExtractionSource.RESPONSE,
                out,
                dedupe,
                0
        );
    }

    private void collectIdLikeValues(
            JsonNode node,
            String path,
            String fallbackTypeName,
            String database,
            String contextKey,
            ExtractionSource source,
            List<ExtractedEntity> out,
            Set<String> dedupe,
            int depth
    ) {
        if (node == null || node.isNull() || node.isMissingNode() || depth > 10 || out.size() >= 300) {
            return;
        }

        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext() && out.size() < 300) {
                Map.Entry<String, JsonNode> entry = fields.next();
                String key = entry.getKey() == null ? "" : entry.getKey();
                JsonNode value = entry.getValue();
                String childPath = path + "." + key;

                if (source == ExtractionSource.REQUEST && "credentials".equalsIgnoreCase(key)) {
                    continue;
                }

                if (isIdLikeKey(key) && isUsefulScalar(value)) {
                    String entityId = asText(value);
                    if (!entityId.isBlank()) {
                        String dedupeKey = source + "|" + childPath + "|" + entityId;
                        if (dedupe.add(dedupeKey)) {
                            String typeName = inferTypeNameFromKey(key, fallbackTypeName);
                            out.add(new ExtractedEntity(
                                    entityId,
                                    typeName,
                                    defaultIfBlank(database, "unknown-db"),
                                    defaultIfBlank(contextKey, ""),
                                    key,
                                    false,
                                    source.name().toLowerCase(Locale.ROOT) + ":" + childPath,
                                    List.of(defaultIfBlank(contextKey, ""))
                            ));
                        }
                    }
                }

                collectIdLikeValues(value, childPath, fallbackTypeName, database, contextKey, source, out, dedupe, depth + 1);
            }
            return;
        }

        if (node.isArray()) {
            for (int i = 0; i < node.size() && out.size() < 300; i++) {
                collectIdLikeValues(
                        node.get(i),
                        path + "[" + i + "]",
                        fallbackTypeName,
                        database,
                        contextKey,
                        source,
                        out,
                        dedupe,
                        depth + 1
                );
            }
        }
    }

    private static boolean isUsefulScalar(JsonNode node) {
        if (node == null || node.isNull()) {
            return false;
        }
        if (!(node.isTextual() || node.isNumber() || node.isBoolean())) {
            return false;
        }

        String value = asText(node);
        return !value.isBlank() && value.length() <= 160;
    }

    private static boolean isIdLikeKey(String key) {
        if (key == null || key.isBlank()) {
            return false;
        }

        String lowered = key.toLowerCase(Locale.ROOT);
        if ("sessionid".equals(lowered)
                || "database".equals(lowered)
                || "db".equals(lowered)
                || "username".equals(lowered)
                || "token".equals(lowered)
                || "authorization".equals(lowered)) {
            return false;
        }

        return lowered.equals("id")
                || lowered.endsWith("id")
                || lowered.contains("_id")
                || lowered.contains("entity")
                || lowered.contains("tenant")
                || lowered.contains("user")
                || lowered.contains("group")
                || lowered.contains("device")
                || lowered.contains("report")
                || lowered.contains("rule")
                || lowered.contains("order")
                || lowered.contains("account")
                || lowered.contains("organization")
            || lowered.contains("org")
            || lowered.contains("policy")
            || lowered.contains("asset")
            || lowered.contains("driver")
            || lowered.contains("zone")
            || lowered.contains("company");
    }

    private static String inferTypeNameFromKey(String key, String fallbackTypeName) {
        if (key == null || key.isBlank()) {
            return defaultIfBlank(fallbackTypeName, "Unknown");
        }

        String lowered = key.toLowerCase(Locale.ROOT);
        if (lowered.contains("tenant") || lowered.contains("organization") || lowered.contains("org")) {
            return "Tenant";
        }
        if (lowered.contains("user") || lowered.contains("email")) {
            return "User";
        }
        if (lowered.contains("device")) {
            return "Device";
        }
        if (lowered.contains("report")) {
            return "Report";
        }
        if (lowered.contains("group") || lowered.contains("account")) {
            return "Account";
        }
        return defaultIfBlank(fallbackTypeName, "Unknown");
    }

    private enum ExtractionSource {
        REQUEST,
        RESPONSE
    }

    private static String asText(JsonNode node) {
        if (node == null || node.isNull()) {
            return "";
        }
        return node.asText("").trim();
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
        private final String entityId;

        private long observations;
        private Instant firstSeen;
        private Instant lastSeen;
        private String typeName = "Unknown";
        private String database = "unknown-db";
        private String name = "";
        private boolean isGlobalReportingGroup;
        private String raw = "";

        private final Set<String> methods = new LinkedHashSet<>();
        private final Set<String> seenContexts = new LinkedHashSet<>();
        private final ArrayDeque<String> samples = new ArrayDeque<>();

        private EntityAggregate(String entityId) {
            this.entityId = entityId;
        }

        synchronized void observe(
                ExtractedEntity entity,
                String methodName,
                Instant timestamp
        ) {
            observations++;

            if (firstSeen == null || timestamp.isBefore(firstSeen)) {
                firstSeen = timestamp;
            }
            if (lastSeen == null || timestamp.isAfter(lastSeen)) {
                lastSeen = timestamp;
            }

            this.typeName = defaultIfBlank(entity.typeName(), this.typeName);
            this.database = defaultIfBlank(entity.database(), this.database);
            if (!entity.name().isBlank()) {
                this.name = entity.name();
            }
            this.isGlobalReportingGroup = this.isGlobalReportingGroup || entity.isGlobalReportingGroup();
            this.raw = defaultIfBlank(entity.raw(), this.raw);

            if (methods.size() < MAX_METHODS_PER_ENTITY || methods.contains(methodName)) {
                methods.add(methodName);
            }

            if (seenContexts.size() < MAX_CONTEXTS_PER_ENTITY || seenContexts.contains(entity.contextKey())) {
                if (entity.contextKey() != null && !entity.contextKey().isBlank()) {
                    seenContexts.add(entity.contextKey());
                }
            }

            if (samples.size() >= MAX_SAMPLES_PER_ENTITY) {
                samples.removeFirst();
            }
            samples.addLast("method=" + methodName
                    + " | context=" + defaultIfBlank(entity.contextKey(), "")
                    + " | db=" + defaultIfBlank(entity.database(), "")
                    + " | id=" + entity.entityId());
        }

        synchronized EntityRow toRow() {
            RiskComputation risk = computeRisk();
            EntityType entityType = classifyEntityType(typeName, entityId);
            String preview = !name.isBlank() ? name : entityId;
            return new EntityRow(
                    entityId,
                    preview,
                    entityType,
                    observations,
                    methods.size(),
                    seenContexts.size(),
                    methods.size(),
                    0,
                    methods.size() > 1,
                    seenContexts.size() > 1,
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
                    List.copyOf(methods),
                    List.of(),
                    List.copyOf(seenContexts),
                    List.of(raw),
                    sampleCopy,
                    risk.reasons
            );
        }

        synchronized ExtractedEntity toExtractedEntity() {
            return new ExtractedEntity(
                    entityId,
                    defaultIfBlank(typeName, "Unknown"),
                    defaultIfBlank(database, "unknown-db"),
                    seenContexts.isEmpty() ? "" : seenContexts.iterator().next(),
                    name,
                    isGlobalReportingGroup,
                    raw,
                    List.copyOf(seenContexts)
            );
        }

        private RiskComputation computeRisk() {
            int score = 0;
            List<String> reasons = new ArrayList<>();

            if (classifyEntityType(typeName, entityId).isSensitive()) {
                score += 20;
                reasons.add("Sensitive entity type: " + typeName);
            }

            if (methods.size() > 1) {
                int contribution = 16 + Math.min(18, (methods.size() - 1) * 3);
                score += contribution;
                reasons.add("Entity reused across methods: " + methods.size());
            }

            if (seenContexts.size() > 1) {
                int contribution = 18 + Math.min(16, (seenContexts.size() - 1) * 2);
                score += contribution;
                reasons.add("Entity seen across contexts: " + seenContexts.size());
            }

            if (observations >= 5) {
                score += 8;
                reasons.add("Observed repeatedly in traffic: " + observations + " occurrences.");
            }

            if (isGlobalReportingGroup) {
                score += 12;
                reasons.add("Global reporting group observed.");
            }

            score = Math.min(score, 100);
            return new RiskComputation(score, SecurityFinding.RiskLevel.fromScore(score), reasons);
        }

        private static EntityType classifyEntityType(String typeName, String entityId) {
            String loweredType = typeName == null ? "" : typeName.toLowerCase(Locale.ROOT);
            String loweredId = entityId == null ? "" : entityId.toLowerCase(Locale.ROOT);

            if (loweredType.contains("user") || loweredId.startsWith("u") || loweredId.startsWith("b1")) {
                return EntityType.USER_ID;
            }
            if (loweredType.contains("group") || loweredId.startsWith("g") || loweredId.startsWith("b29")) {
                return EntityType.ACCOUNT_ID;
            }
            if (loweredType.contains("device")) {
                return EntityType.DEVICE_ID;
            }
            return EntityType.GENERIC_ID;
        }
    }

    private record RiskComputation(int score, SecurityFinding.RiskLevel level, List<String> reasons) {
    }

    public record ExtractedEntity(
            String entityId,
            String typeName,
            String database,
            String contextKey,
            String name,
            boolean isGlobalReportingGroup,
            String raw,
            List<String> seenInContexts
    ) {
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
