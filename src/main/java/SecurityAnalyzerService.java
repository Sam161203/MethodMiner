import burp.api.montoya.logging.Logging;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.net.URI;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
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

public final class SecurityAnalyzerService implements AutoCloseable {
    private static final List<String> SENSITIVE_METHOD_TERMS = List.of(
            "admin", "user", "security", "export", "report", "device", "token",
            "session", "permission", "billing", "order", "account", "tenant"
    );

    private static final Set<String> DATABASE_KEYS = Set.of("database", "db", "dbName", "databaseName");
    private static final Set<String> USER_KEYS = Set.of("user", "userName", "username", "email", "login");
    private static final Set<String> SESSION_KEYS = Set.of("session", "sessionId", "sid", "token", "jwt");

    private static final Pattern EMAIL_PATTERN = Pattern.compile("(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}");
    private static final Pattern INTERNAL_URL_PATTERN = Pattern.compile(
            "(?i)(https?://(?:127\\.0\\.0\\.1|localhost|10\\.|172\\.(?:1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.|.*(?:internal|backend|svc)))|(?:/internal/)|(?:backend[-_/]route)"
    );

    private static final long NOTIFY_INTERVAL_MILLIS = 500L;
    private static final int MAX_SAMPLES_PER_METHOD = 20;
    private static final int MAX_CONTEXTS_PER_METHOD = 200;
    private static final int MAX_EXPOSURE_SIGNALS = 30;

    private final ObjectMapper objectMapper;
    private final JsonRpcIndex index;
    private final AuthContextStore authContextStore;
    private final Logging logging;

    private final ExecutorService analyzerExecutor = Executors.newSingleThreadExecutor(r -> new Thread(r, "jsonrpc-security-analyzer"));
    private final List<Runnable> updateListeners = new CopyOnWriteArrayList<>();
    private final ConcurrentMap<String, MethodAggregate> methods = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, FindingFlags> findingFlags = new ConcurrentHashMap<>();

    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final AtomicLong lastUiNotificationEpochMillis = new AtomicLong(0L);

    public SecurityAnalyzerService(ObjectMapper objectMapper, JsonRpcIndex index, AuthContextStore authContextStore, Logging logging) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
        this.index = Objects.requireNonNull(index, "index must not be null");
        this.authContextStore = Objects.requireNonNull(authContextStore, "authContextStore must not be null");
        this.logging = Objects.requireNonNull(logging, "logging must not be null");
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
                logging.logToError("Security analyzer failed while processing record.", ex);
            }
        });
    }

    void ingestRecordSync(JsonRpcRecord rawRecord, JsonRpcNormalizedRecord normalizedRecord) {
        if (rawRecord == null || normalizedRecord == null) {
            return;
        }

        methods.computeIfAbsent(normalizedRecord.methodName(), MethodAggregate::new)
            .observe(rawRecord, normalizedRecord, objectMapper, authContextStore);
    }

    public List<SecurityFinding> snapshotFindings() {
        List<SecurityFinding> findings = new ArrayList<>();
        for (MethodAggregate aggregate : methods.values()) {
            findings.addAll(aggregate.buildFindings(findingFlags, index, objectMapper, authContextStore));
        }

        findings.sort(Comparator
                .comparingInt(SecurityFinding::riskScore).reversed()
                .thenComparing(SecurityFinding::lastSeen, Comparator.nullsLast(Comparator.reverseOrder()))
                .thenComparing(SecurityFinding::method, String.CASE_INSENSITIVE_ORDER)
                .thenComparing(SecurityFinding::trigger, String.CASE_INSENSITIVE_ORDER));
        return findings;
    }

    public Optional<MethodSecurityDetails> snapshotMethodDetails(String methodName) {
        MethodAggregate aggregate = methods.get(methodName);
        if (aggregate == null) {
            return Optional.empty();
        }
        return Optional.of(aggregate.toDetails(index, findingFlags, objectMapper, authContextStore));
    }

    public void markReviewed(String findingId, boolean reviewed) {
        findingFlags.compute(findingId, (key, state) -> {
            FindingFlags result = state == null ? new FindingFlags() : state;
            result.reviewed = reviewed;
            return result;
        });
        notifyListeners();
    }

    public void markExportedForMethod(String methodName) {
        for (SecurityFinding finding : snapshotFindings()) {
            if (!finding.method().equals(methodName)) {
                continue;
            }
            findingFlags.compute(finding.findingId(), (key, state) -> {
                FindingFlags result = state == null ? new FindingFlags() : state;
                result.exported = true;
                return result;
            });
        }
        notifyListeners();
    }

    public ObjectNode buildManualExportBundle(String methodName) {
        MethodAggregate aggregate = methods.get(methodName);
        if (aggregate == null) {
            throw new IllegalArgumentException("No analysis data available for method: " + methodName);
        }
        return aggregate.buildManualExportBundle(objectMapper, index, authContextStore);
    }

    public void clear() {
        methods.clear();
        findingFlags.clear();
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
                logging.logToError("Security analysis UI listener failed.", ex);
            }
        }
    }

    private static final class MethodAggregate {
        private final String methodName;

        private long count;
        private Instant firstSeen;
        private Instant lastSeen;
        private boolean hasEmptyParams;
        private boolean hasLargeResponse;
        private long responseJsonSamples;

        private final Set<String> sensitiveMethodHits = new TreeSet<>();
        private final Set<String> responseShapeSignatures = new TreeSet<>();
        private final Set<Integer> statusCodes = new TreeSet<>();
        private final Set<String> exposureSignals = new TreeSet<>();
        private final Map<String, FieldStats> responseFieldStats = new HashMap<>();
        private final Map<String, ContextStats> authContexts = new LinkedHashMap<>();
        private final ArrayDeque<SampleObservation> samples = new ArrayDeque<>();

        private MethodAggregate(String methodName) {
            this.methodName = methodName;
        }

        synchronized void observe(
            JsonRpcRecord rawRecord,
            JsonRpcNormalizedRecord normalizedRecord,
            ObjectMapper objectMapper,
            AuthContextStore authContextStore
        ) {
            count++;

            Instant timestamp = normalizedRecord.timestamp();
            if (firstSeen == null || timestamp.isBefore(firstSeen)) {
                firstSeen = timestamp;
            }
            if (lastSeen == null || timestamp.isAfter(lastSeen)) {
                lastSeen = timestamp;
            }

            hasEmptyParams = hasEmptyParams || normalizedRecord.emptyParams();
            hasLargeResponse = hasLargeResponse || normalizedRecord.largeResponse();
            responseShapeSignatures.add(normalizedRecord.responseShapeSignature());
            if (normalizedRecord.responseStatus() != null) {
                statusCodes.add(normalizedRecord.responseStatus());
            }

            registerSensitiveMethodHits();

            AuthContextStore.AuthContext taggedContext = authContextStore.observeRecord(rawRecord, normalizedRecord.methodName());
            AuthContext authContext = extractAuthContext(rawRecord, objectMapper, taggedContext);
            addAuthContextObservation(authContext, normalizedRecord);

            SchemaObservation schemaObservation = parseResponseSchema(rawRecord.response().bodyText(), objectMapper);
            if (schemaObservation != null) {
                responseJsonSamples++;
                mergeSchemaObservation(schemaObservation);
            }

            SampleObservation sample = createSampleObservation(
                    rawRecord,
                    normalizedRecord,
                    authContext,
                    taggedContext,
                    schemaObservation,
                    objectMapper
            );
            addSample(sample);
        }

        synchronized List<SecurityFinding> buildFindings(
                ConcurrentMap<String, FindingFlags> states,
                JsonRpcIndex index,
                ObjectMapper objectMapper,
                AuthContextStore authContextStore
        ) {
            MethodRisk risk = computeMethodRisk(index, objectMapper, authContextStore);
            SchemaDriftSummary schemaDriftSummary = schemaDriftSummary();
            AuthContextSummary authContextSummary = authContextSummary(objectMapper, authContextStore);

            List<SecurityFinding> findings = new ArrayList<>();
            findings.add(createFinding(
                    states,
                    "method_risk",
                    risk,
                    "Passive risk score derived from method name, rarity, response behavior, and data exposure signals. "
                            + joinLimited(risk.reasons(), 8)
            ));

            if (schemaDriftSummary.hasDrift()) {
                findings.add(createFinding(
                        states,
                        "schema_drift",
                        risk,
                        "Schema drift detected: " + joinLimited(schemaDriftSummary.reasons(), 8)
                ));
            }

            if (authContextSummary.hasComparablePair() && authContextSummary.behaviorDiffersAcrossContexts()) {
                findings.add(createFinding(
                        states,
                        "auth_context_correlation",
                        risk,
                        authContextSummary.summaryText()
                ));
            }

            if (!exposureSignals.isEmpty()) {
                findings.add(createFinding(
                        states,
                        "tenant_identity_exposure",
                        risk,
                        "Sensitive identity/tenant/account fields detected in responses: " + joinLimited(new ArrayList<>(exposureSignals), 8)
                ));
            }

            return findings;
        }

        synchronized MethodSecurityDetails toDetails(
                JsonRpcIndex index,
                ConcurrentMap<String, FindingFlags> states,
            ObjectMapper objectMapper,
            AuthContextStore authContextStore
        ) {
            MethodRisk risk = computeMethodRisk(index, objectMapper, authContextStore);
            SchemaDriftSummary schemaDriftSummary = schemaDriftSummary();
            AuthContextSummary authContextSummary = authContextSummary(objectMapper, authContextStore);

            List<SecurityFinding> findings = buildFindings(states, index, objectMapper, authContextStore);
            List<SampleView> sampleViews = new ArrayList<>();
            int ordinal = 1;
            for (SampleObservation sample : samples) {
            RoleType currentRole = authContextStore.roleForContextKey(sample.contextKey);
                String label = "#" + ordinal + " " + sample.timestamp + " status="
                        + (sample.statusCode == null ? "n/a" : sample.statusCode)
                        + " class=" + sample.responseClass.displayName
                + " role=" + currentRole.displayName()
                        + " context=" + sample.contextSummary;
                sampleViews.add(new SampleView(
                        sample.sampleId,
                        label,
                        sample.timestamp,
                        sample.statusCode,
                        sample.contextKey,
                currentRole.displayName(),
                        sample.contextSummary,
                        sample.requestRaw,
                        sample.paramsText,
                        sample.responseRaw,
                    sample.schemaText,
                    sample.responseClass.displayName
                ));
                ordinal++;
            }

            List<String> riskReasons = new ArrayList<>(risk.reasons());
            List<String> driftReasons = new ArrayList<>(schemaDriftSummary.reasons());
            List<String> exposures = new ArrayList<>(exposureSignals);

            List<AuthContextView> authContextViews = new ArrayList<>();
            for (ContextStats contextStats : authContexts.values()) {
                authContextViews.add(new AuthContextView(
                        contextStats.context.host(),
                        contextStats.context.database(),
                        contextStats.context.userName(),
                        contextStats.context.sessionId(),
                        contextStats.context.role(),
                        contextStats.context.cookieFingerprint(),
                        contextStats.context.contextKey(),
                        contextStats.count,
                        new ArrayList<>(contextStats.statusCodes),
                        new ArrayList<>(contextStats.responseShapes)
                ));
            }

            authContextViews.sort(Comparator.comparingLong(AuthContextView::count).reversed());

            return new MethodSecurityDetails(
                    methodName,
                    count,
                    firstSeen,
                    lastSeen,
                    risk,
                    riskReasons,
                    driftReasons,
                    authContextSummary.behaviorDiffersAcrossContexts(),
                    authContextSummary.summaryText(),
                    authContextViews,
                    exposures,
                    new ArrayList<>(statusCodes),
                    new ArrayList<>(responseShapeSignatures),
                    sampleViews,
                    findings
            );
        }

        synchronized ObjectNode buildManualExportBundle(ObjectMapper mapper, JsonRpcIndex index, AuthContextStore authContextStore) {
            MethodRisk risk = computeMethodRisk(index, mapper, authContextStore);
            AuthContextSummary authSummary = authContextSummary(mapper, authContextStore);
            ObjectNode root = mapper.createObjectNode();
            root.put("generatedAt", Instant.now().toString());
            root.put("mode", "manual-only");
            root.put("method", methodName);
            root.put("risk", risk.level().displayName() + " (" + risk.score() + ")");
            root.put("note", "Manual review bundle only. No requests are sent automatically by this extension.");
            root.put("whatItAppearsToControl", deriveControlNote(risk));
            root.put("authContextSummary", authSummary.summaryText());

            ArrayNode sampleArray = mapper.createArrayNode();
            for (SampleObservation sample : samples) {
                sampleArray.add(sample.toExportJson(mapper, authContextStore.roleForContextKey(sample.contextKey)));
            }
            root.set("samples", sampleArray);
            return root;
        }

        private SecurityFinding createFinding(
                ConcurrentMap<String, FindingFlags> states,
                String trigger,
                MethodRisk risk,
                String whyFlagged
        ) {
            String findingId = methodName + "|" + trigger;
            FindingFlags state = states.computeIfAbsent(findingId, ignored -> new FindingFlags());
            return new SecurityFinding(
                    findingId,
                    methodName,
                    risk.score(),
                    risk.level(),
                    trigger,
                    whyFlagged,
                    firstSeen,
                    lastSeen,
                    state.exported,
                    state.reviewed
            );
        }

        private MethodRisk computeMethodRisk(JsonRpcIndex index, ObjectMapper objectMapper, AuthContextStore authContextStore) {
            int score = 0;
            List<String> reasons = new ArrayList<>();

            if (!sensitiveMethodHits.isEmpty()) {
                int contribution = Math.min(30, sensitiveMethodHits.size() * 8);
                score += contribution;
                reasons.add("Sensitive method term(s): " + String.join(", ", sensitiveMethodHits));
            }

            if (hasEmptyParams) {
                score += 8;
                reasons.add("Observed empty/null params in requests.");
            }

            if (count <= 1) {
                score += 6;
                reasons.add("Method is rare (seen once), which is often high-signal for manual review.");
            }

            if (hasLargeResponse) {
                score += 10;
                reasons.add("Method produced large responses.");
            }

            if (responseShapeSignatures.size() > 1) {
                score += 12;
                reasons.add("Response shape differs across samples.");
            }

            if (!exposureSignals.isEmpty()) {
                int contribution = Math.min(30, exposureSignals.size() * 4);
                score += contribution;
                reasons.add("Response contains identity/tenant/permission or internal metadata.");
            }

            SchemaDriftSummary driftSummary = schemaDriftSummary();
            if (driftSummary.hasDrift()) {
                score += 10;
                reasons.add("Schema drift detected for response fields/types/statuses.");
            }

            AuthContextSummary authSummary = authContextSummary(objectMapper, authContextStore);
            if (authSummary.hasComparablePair() && authSummary.behaviorDiffersAcrossContexts()) {
                score += 12;
                reasons.add("Method behavior differs across auth contexts.");
            }

            JsonRpcIndex.MethodRow methodRow = index.snapshotMethodRows().stream()
                    .filter(row -> row.methodName().equals(methodName))
                    .findFirst()
                    .orElse(null);

            if (methodRow != null && methodRow.isRare() && count > 1) {
                score += 4;
                reasons.add("Method still appears infrequently relative to other traffic.");
            }

            score = Math.min(score, 100);
            return new MethodRisk(score, SecurityFinding.RiskLevel.fromScore(score), reasons);
        }

        private SchemaDriftSummary schemaDriftSummary() {
            List<String> reasons = new ArrayList<>();

            if (responseJsonSamples > 1) {
                List<String> fieldPresenceDrift = new ArrayList<>();
                List<String> typeDrift = new ArrayList<>();
                List<String> nullableDrift = new ArrayList<>();
                List<String> arrayLengthDrift = new ArrayList<>();
                List<String> nestingDrift = new ArrayList<>();

                for (Map.Entry<String, FieldStats> entry : responseFieldStats.entrySet()) {
                    String path = entry.getKey();
                    FieldStats stats = entry.getValue();

                    if (stats.presenceCount < responseJsonSamples) {
                        fieldPresenceDrift.add(path + "(" + stats.presenceCount + "/" + responseJsonSamples + ")");
                    }

                    Set<String> nonNullTypes = new TreeSet<>(stats.types);
                    nonNullTypes.remove("null");
                    if (nonNullTypes.size() > 1) {
                        typeDrift.add(path + "=" + String.join("|", nonNullTypes));
                    }

                    if (stats.hasNull && stats.hasNonNull) {
                        nullableDrift.add(path);
                    }

                    if (stats.minArrayLength != null && stats.maxArrayLength != null
                            && !stats.minArrayLength.equals(stats.maxArrayLength)) {
                        arrayLengthDrift.add(path + "=" + stats.minArrayLength + ".." + stats.maxArrayLength);
                    }

                    if (stats.minDepth != Integer.MAX_VALUE && stats.maxDepth != Integer.MIN_VALUE
                            && stats.minDepth != stats.maxDepth) {
                        nestingDrift.add(path + "=" + stats.minDepth + ".." + stats.maxDepth);
                    }
                }

                if (!fieldPresenceDrift.isEmpty()) {
                    reasons.add("Fields appearing/disappearing: " + joinLimited(fieldPresenceDrift, 8));
                }
                if (!typeDrift.isEmpty()) {
                    reasons.add("Field type changes: " + joinLimited(typeDrift, 8));
                }
                if (!nullableDrift.isEmpty()) {
                    reasons.add("Nullable vs non-null drift: " + joinLimited(nullableDrift, 8));
                }
                if (!arrayLengthDrift.isEmpty()) {
                    reasons.add("Array length drift: " + joinLimited(arrayLengthDrift, 8));
                }
                if (!nestingDrift.isEmpty()) {
                    reasons.add("Object/array nesting depth drift: " + joinLimited(nestingDrift, 8));
                }
            }

            if (statusCodes.size() > 1) {
                reasons.add("Different HTTP statuses for same method: " + statusCodes);
            }

            return new SchemaDriftSummary(!reasons.isEmpty(), reasons);
        }

        private AuthContextSummary authContextSummary(ObjectMapper mapper, AuthContextStore authContextStore) {
            List<SampleObservation> adminSamples = new ArrayList<>();
            List<SampleObservation> lowPrivSamples = new ArrayList<>();

            for (SampleObservation sample : samples) {
                RoleType roleType = authContextStore.roleForContextKey(sample.contextKey);
                if (roleType == RoleType.ADMIN) {
                    adminSamples.add(sample);
                } else if (roleType == RoleType.LOW_PRIV) {
                    lowPrivSamples.add(sample);
                }
            }

            if (adminSamples.isEmpty() || lowPrivSamples.isEmpty()) {
                return new AuthContextSummary(
                        false,
                        false,
                        "No ADMIN + LOW_PRIV pair tagged yet. Tag both roles to enable auth differential findings."
                );
            }

            RoleResponseSummary adminSummary = summarizeRoleResponses(adminSamples, mapper);
            RoleResponseSummary lowSummary = summarizeRoleResponses(lowPrivSamples, mapper);

            List<String> newFields = new ArrayList<>();
            for (String field : adminSummary.fieldNames()) {
                if (!lowSummary.fieldNames().contains(field)) {
                    newFields.add(field);
                }
            }

            List<String> sharedOwnership = new ArrayList<>();
            for (String signature : adminSummary.ownershipSignatures()) {
                if (lowSummary.ownershipSignatures().contains(signature)) {
                    sharedOwnership.add(signature);
                }
            }

            boolean drift = adminSummary.maxObjects() != lowSummary.maxObjects()
                    || !adminSummary.statuses().equals(lowSummary.statuses())
                    || !newFields.isEmpty()
                    || !sharedOwnership.isEmpty();

            if (!drift) {
                return new AuthContextSummary(
                        true,
                        false,
                        "ADMIN and LOW_PRIV behavior currently looks consistent for this method."
                );
            }

            StringBuilder summary = new StringBuilder();
            summary.append("[AUTH DIFFERENCE DETECTED]\n\n");
            summary.append("ADMIN -> ").append(adminSummary.maxObjects()).append(" results\n");
            summary.append("LOW_PRIV -> ").append(lowSummary.maxObjects()).append(" results\n\n");
            summary.append("New fields visible:\n");

            if (newFields.isEmpty()) {
                summary.append("* (none)");
            } else {
                int max = Math.min(8, newFields.size());
                for (int i = 0; i < max; i++) {
                    summary.append("* ").append(newFields.get(i)).append("\n");
                }
                if (newFields.size() > max) {
                    summary.append("* ... +").append(newFields.size() - max).append(" more\n");
                }
            }

            if (adminSummary.maxObjects() > 0 && lowSummary.maxObjects() == 0) {
                summary.append("\n🔥 Possible Access Control Issue");
            }

            if (!sharedOwnership.isEmpty()) {
                summary.append("\n\nShared ownership identifiers in ADMIN + LOW_PRIV responses:\n");
                int maxShared = Math.min(6, sharedOwnership.size());
                for (int i = 0; i < maxShared; i++) {
                    summary.append("* ").append(sharedOwnership.get(i)).append("\n");
                }
                if (sharedOwnership.size() > maxShared) {
                    summary.append("* ... +").append(sharedOwnership.size() - maxShared).append(" more\n");
                }
            }

            return new AuthContextSummary(true, true, summary.toString().trim());
        }

        private RoleResponseSummary summarizeRoleResponses(List<SampleObservation> roleSamples, ObjectMapper mapper) {
            int maxObjects = 0;
            Set<Integer> statuses = new TreeSet<>();
            Set<String> fieldNames = new TreeSet<>();
            Set<String> ownershipSignatures = new TreeSet<>();

            for (SampleObservation sample : roleSamples) {
                if (sample.statusCode != null) {
                    statuses.add(sample.statusCode);
                }

                ResponseDataSummary responseSummary = summarizeResponseBody(sample.responseBody, mapper);
                maxObjects = Math.max(maxObjects, responseSummary.objectCount());
                fieldNames.addAll(responseSummary.fieldNames());
                ownershipSignatures.addAll(responseSummary.ownershipSignatures());
            }

            return new RoleResponseSummary(maxObjects, statuses, fieldNames, ownershipSignatures);
        }

        private ResponseDataSummary summarizeResponseBody(String responseBody, ObjectMapper mapper) {
            if (responseBody == null || responseBody.isBlank()) {
                return new ResponseDataSummary(0, Set.of(), Set.of());
            }

            try {
                JsonNode root = mapper.readTree(responseBody);
                JsonNode dataNode = root;
                if (root.isObject()) {
                    JsonNode result = root.path("result");
                    if (!result.isMissingNode() && !result.isNull()) {
                        dataNode = result;
                    } else {
                        JsonNode data = root.path("data");
                        if (!data.isMissingNode() && !data.isNull()) {
                            dataNode = data;
                        }
                    }
                }

                int objectCount = estimateObjectCount(dataNode);
                Set<String> fields = collectFields(dataNode, "result", 0, 3, 50);
                Set<String> ownershipSignatures = collectOwnershipSignatures(dataNode, "result", 0, 4, 60);
                return new ResponseDataSummary(objectCount, fields, ownershipSignatures);
            } catch (Exception ignored) {
                return new ResponseDataSummary(0, Set.of(), Set.of());
            }
        }

        private static int estimateObjectCount(JsonNode node) {
            if (node == null || node.isNull() || node.isMissingNode()) {
                return 0;
            }
            if (node.isArray()) {
                return node.size();
            }
            if (node.isObject()) {
                return node.size() == 0 ? 0 : 1;
            }
            return 1;
        }

        private static Set<String> collectFields(JsonNode node, String prefix, int depth, int maxDepth, int maxFields) {
            Set<String> out = new TreeSet<>();
            collectFieldsRecursive(node, prefix, depth, maxDepth, maxFields, out);
            return out;
        }

        private static void collectFieldsRecursive(
                JsonNode node,
                String prefix,
                int depth,
                int maxDepth,
                int maxFields,
                Set<String> out
        ) {
            if (node == null || node.isNull() || depth > maxDepth || out.size() >= maxFields) {
                return;
            }

            if (node.isObject()) {
                Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
                while (fields.hasNext() && out.size() < maxFields) {
                    Map.Entry<String, JsonNode> entry = fields.next();
                    String childPath = prefix + "." + entry.getKey();
                    out.add(childPath);
                    collectFieldsRecursive(entry.getValue(), childPath, depth + 1, maxDepth, maxFields, out);
                }
                return;
            }

            if (node.isArray()) {
                String childPath = prefix + "[]";
                out.add(childPath);
                if (node.size() > 0) {
                    collectFieldsRecursive(node.get(0), childPath, depth + 1, maxDepth, maxFields, out);
                    if (node.size() > 1) {
                        collectFieldsRecursive(node.get(node.size() - 1), childPath, depth + 1, maxDepth, maxFields, out);
                    }
                }
            }
        }

        private static Set<String> collectOwnershipSignatures(JsonNode node, String prefix, int depth, int maxDepth, int maxItems) {
            Set<String> signatures = new TreeSet<>();
            collectOwnershipSignaturesRecursive(node, prefix, depth, maxDepth, maxItems, signatures);
            return signatures;
        }

        private static void collectOwnershipSignaturesRecursive(
                JsonNode node,
                String prefix,
                int depth,
                int maxDepth,
                int maxItems,
                Set<String> out
        ) {
            if (node == null || node.isNull() || depth > maxDepth || out.size() >= maxItems) {
                return;
            }

            if (node.isObject()) {
                Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
                while (fields.hasNext() && out.size() < maxItems) {
                    Map.Entry<String, JsonNode> entry = fields.next();
                    String key = entry.getKey();
                    JsonNode value = entry.getValue();
                    String childPath = prefix + "." + key;

                    if (isOwnershipKey(key) && (value.isTextual() || value.isNumber() || value.isBoolean())) {
                        String valueText = value.asText("");
                        if (!valueText.isBlank()) {
                            String truncated = valueText.length() > 80 ? valueText.substring(0, 80) : valueText;
                            out.add(childPath + "=" + truncated);
                        }
                    }

                    collectOwnershipSignaturesRecursive(value, childPath, depth + 1, maxDepth, maxItems, out);
                }
                return;
            }

            if (node.isArray() && node.size() > 0) {
                String childPath = prefix + "[]";
                collectOwnershipSignaturesRecursive(node.get(0), childPath, depth + 1, maxDepth, maxItems, out);
                if (node.size() > 1) {
                    collectOwnershipSignaturesRecursive(node.get(node.size() - 1), childPath, depth + 1, maxDepth, maxItems, out);
                }
            }
        }

        private static boolean isOwnershipKey(String key) {
            if (key == null || key.isBlank()) {
                return false;
            }
            String lowered = key.toLowerCase(Locale.ROOT);
            return lowered.equals("id")
                    || lowered.endsWith("id")
                    || lowered.contains("_id")
                    || lowered.contains("tenant")
                    || lowered.contains("user")
                    || lowered.contains("account")
                    || lowered.contains("organization")
                    || lowered.contains("org")
                    || lowered.contains("company")
                    || lowered.contains("database")
                    || lowered.equals("db");
        }

        private void registerSensitiveMethodHits() {
            String lowered = methodName.toLowerCase(Locale.ROOT);
            for (String term : SENSITIVE_METHOD_TERMS) {
                if (lowered.contains(term)) {
                    sensitiveMethodHits.add(term);
                }
            }
        }

        private void addAuthContextObservation(AuthContext context, JsonRpcNormalizedRecord normalizedRecord) {
            if (authContexts.size() >= MAX_CONTEXTS_PER_METHOD && !authContexts.containsKey(context.fingerprintKey())) {
                authContexts.computeIfAbsent("_context_overflow", key -> new ContextStats(AuthContext.overflowContext()))
                        .observe(normalizedRecord);
                return;
            }

            authContexts.computeIfAbsent(context.fingerprintKey(), key -> new ContextStats(context))
                    .observe(normalizedRecord);
        }

        private void mergeSchemaObservation(SchemaObservation observation) {
            for (Map.Entry<String, SamplePathStats> entry : observation.pathStats.entrySet()) {
                FieldStats stats = responseFieldStats.computeIfAbsent(entry.getKey(), key -> new FieldStats());
                stats.observe(entry.getValue());
            }

            for (String signal : observation.exposureSignals) {
                if (exposureSignals.size() < MAX_EXPOSURE_SIGNALS) {
                    exposureSignals.add(signal);
                }
            }
        }

        private SampleObservation createSampleObservation(
                JsonRpcRecord rawRecord,
                JsonRpcNormalizedRecord normalizedRecord,
                AuthContext context,
            AuthContextStore.AuthContext taggedContext,
                SchemaObservation schemaObservation,
                ObjectMapper objectMapper
        ) {
            String paramsText = extractParamsText(rawRecord.request().bodyText(), objectMapper);
            String schemaText = schemaObservation == null
                    ? (rawRecord.response().present() ? "Response is non-JSON or empty." : "Response missing.")
                    : schemaObservation.prettySummary();
            ResponseClass responseClass = classifyResponse(normalizedRecord.responseStatus(), rawRecord.response().bodyText());

            return new SampleObservation(
                    rawRecord.recordId(),
                    rawRecord.timestamp(),
                    rawRecord.request().rawHttpText(),
                    rawRecord.request().bodyText(),
                    rawRecord.request().headers(),
                    paramsText,
                    rawRecord.response().present() ? rawRecord.response().rawHttpText() : "(missing response)",
                    rawRecord.response().bodyText(),
                    schemaText,
                    context.summary(),
                    normalizedRecord.responseStatus(),
                    responseClass,
                    taggedContext.contextKey(),
                    taggedContext.role()
            );
        }

        private void addSample(SampleObservation observation) {
            if (samples.size() >= MAX_SAMPLES_PER_METHOD) {
                samples.removeFirst();
            }
            samples.addLast(observation);
        }

        private String deriveControlNote(MethodRisk risk) {
            List<String> hints = new ArrayList<>();

            for (String term : sensitiveMethodHits) {
                switch (term) {
                    case "admin", "security", "permission", "role" -> hints.add("authorization and privilege boundaries");
                    case "billing", "order" -> hints.add("transaction and pricing logic");
                    case "account", "user", "tenant" -> hints.add("account and tenant data separation");
                    case "export", "report" -> hints.add("bulk data disclosure controls");
                    case "session", "token" -> hints.add("session/token handling");
                    case "device" -> hints.add("device ownership and cross-user access controls");
                    default -> {
                    }
                }
            }

            if (!exposureSignals.isEmpty()) {
                hints.add("sensitive identity metadata exposure");
            }

            if (hints.isEmpty()) {
                hints.add("general business logic and authorization checks");
            }

            Set<String> uniqueHints = new TreeSet<>(hints);
            return "Method likely controls: " + String.join(", ", uniqueHints)
                    + ". Risk score: " + risk.level().displayName() + " (" + risk.score() + ").";
        }

        private record RoleResponseSummary(
            int maxObjects,
            Set<Integer> statuses,
            Set<String> fieldNames,
            Set<String> ownershipSignatures
        ) {
        }

        private record ResponseDataSummary(int objectCount, Set<String> fieldNames, Set<String> ownershipSignatures) {
        }
    }

    public record MethodRisk(int score, SecurityFinding.RiskLevel level, List<String> reasons) {
    }

    public record MethodSecurityDetails(
            String methodName,
            long observationCount,
            Instant firstSeen,
            Instant lastSeen,
            MethodRisk methodRisk,
            List<String> riskReasons,
            List<String> schemaDriftReasons,
            boolean authContextBehaviorDiffers,
            String authContextSummary,
            List<AuthContextView> authContexts,
            List<String> exposureSignals,
            List<Integer> statusCodes,
            List<String> responseShapeSignatures,
            List<SampleView> samples,
            List<SecurityFinding> findings
    ) {
        public ObjectNode toJson(ObjectMapper mapper) {
            ObjectNode root = mapper.createObjectNode();
            root.put("methodName", methodName);
            root.put("observationCount", observationCount);
            root.put("firstSeen", firstSeen == null ? "" : firstSeen.toString());
            root.put("lastSeen", lastSeen == null ? "" : lastSeen.toString());
            root.put("risk", methodRisk.level().displayName() + " (" + methodRisk.score() + ")");
            root.put("authContextBehaviorDiffers", authContextBehaviorDiffers);
            root.put("authContextSummary", authContextSummary);

            ArrayNode riskReasonsArray = mapper.createArrayNode();
            for (String reason : riskReasons) {
                riskReasonsArray.add(reason);
            }
            root.set("riskReasons", riskReasonsArray);

            ArrayNode driftArray = mapper.createArrayNode();
            for (String reason : schemaDriftReasons) {
                driftArray.add(reason);
            }
            root.set("schemaDriftReasons", driftArray);

            ArrayNode exposureArray = mapper.createArrayNode();
            for (String signal : exposureSignals) {
                exposureArray.add(signal);
            }
            root.set("exposureSignals", exposureArray);

            ArrayNode statusArray = mapper.createArrayNode();
            for (Integer status : statusCodes) {
                statusArray.add(status);
            }
            root.set("statusCodes", statusArray);

            ArrayNode responseShapeArray = mapper.createArrayNode();
            for (String shape : responseShapeSignatures) {
                responseShapeArray.add(shape);
            }
            root.set("responseShapeSignatures", responseShapeArray);

            ArrayNode contextArray = mapper.createArrayNode();
            for (AuthContextView context : authContexts) {
                contextArray.add(context.toJson(mapper));
            }
            root.set("authContexts", contextArray);

            ArrayNode sampleArray = mapper.createArrayNode();
            for (SampleView sample : samples) {
                ObjectNode sampleNode = mapper.createObjectNode();
                sampleNode.put("sampleId", sample.sampleId());
                sampleNode.put("label", sample.label());
                sampleNode.put("timestamp", sample.timestamp() == null ? "" : sample.timestamp().toString());
                sampleNode.put("statusCode", sample.statusCode() == null ? -1 : sample.statusCode());
                sampleNode.put("contextKey", sample.contextKey());
                sampleNode.put("roleTag", sample.roleTag());
                sampleNode.put("contextSummary", sample.contextSummary());
                sampleNode.put("responseClass", sample.responseClass());
                sampleArray.add(sampleNode);
            }
            root.set("sampleSummaries", sampleArray);

            ArrayNode findingArray = mapper.createArrayNode();
            for (SecurityFinding finding : findings) {
                ObjectNode findingNode = mapper.createObjectNode();
                findingNode.put("findingId", finding.findingId());
                findingNode.put("risk", finding.riskDisplay());
                findingNode.put("trigger", finding.trigger());
                findingNode.put("whyFlagged", finding.whyFlagged());
                findingNode.put("exported", finding.exported());
                findingNode.put("reviewed", finding.reviewed());
                findingArray.add(findingNode);
            }
            root.set("findings", findingArray);

            return root;
        }
    }

    public record AuthContextView(
            String host,
            String database,
            String userName,
            String sessionId,
            String role,
            String cookieFingerprint,
            String contextKey,
            long count,
            List<Integer> statusCodes,
            List<String> responseShapes
    ) {
        public ObjectNode toJson(ObjectMapper mapper) {
            ObjectNode node = mapper.createObjectNode();
            node.put("host", host);
            node.put("database", database);
            node.put("userName", userName);
            node.put("sessionId", sessionId);
            node.put("role", role);
            node.put("cookieFingerprint", cookieFingerprint);
            node.put("contextKey", contextKey);
            node.put("count", count);

            ArrayNode statusArray = mapper.createArrayNode();
            for (Integer statusCode : statusCodes) {
                statusArray.add(statusCode);
            }
            node.set("statusCodes", statusArray);

            ArrayNode shapeArray = mapper.createArrayNode();
            for (String responseShape : responseShapes) {
                shapeArray.add(responseShape);
            }
            node.set("responseShapes", shapeArray);

            return node;
        }
    }

    public record SampleView(
            String sampleId,
            String label,
            Instant timestamp,
            Integer statusCode,
            String contextKey,
            String roleTag,
            String contextSummary,
            String requestRaw,
            String paramsText,
            String responseRaw,
            String schemaText,
            String responseClass
    ) {
    }

    private static final class FieldStats {
        private int presenceCount;
        private final Set<String> types = new TreeSet<>();
        private boolean hasNull;
        private boolean hasNonNull;
        private int minDepth = Integer.MAX_VALUE;
        private int maxDepth = Integer.MIN_VALUE;
        private Integer minArrayLength;
        private Integer maxArrayLength;

        void observe(SamplePathStats samplePathStats) {
            presenceCount++;
            for (String type : samplePathStats.types) {
                types.add(type);
                if ("null".equals(type)) {
                    hasNull = true;
                } else {
                    hasNonNull = true;
                }
            }

            minDepth = Math.min(minDepth, samplePathStats.minDepth);
            maxDepth = Math.max(maxDepth, samplePathStats.maxDepth);

            if (samplePathStats.minArrayLength != null) {
                minArrayLength = minArrayLength == null
                        ? samplePathStats.minArrayLength
                        : Math.min(minArrayLength, samplePathStats.minArrayLength);
            }
            if (samplePathStats.maxArrayLength != null) {
                maxArrayLength = maxArrayLength == null
                        ? samplePathStats.maxArrayLength
                        : Math.max(maxArrayLength, samplePathStats.maxArrayLength);
            }
        }
    }

    private static final class SamplePathStats {
        private final Set<String> types = new TreeSet<>();
        private int minDepth = Integer.MAX_VALUE;
        private int maxDepth = Integer.MIN_VALUE;
        private Integer minArrayLength;
        private Integer maxArrayLength;

        void observeType(String type, int depth, Integer arrayLength) {
            types.add(type);
            minDepth = Math.min(minDepth, depth);
            maxDepth = Math.max(maxDepth, depth);
            if (arrayLength != null) {
                minArrayLength = minArrayLength == null ? arrayLength : Math.min(minArrayLength, arrayLength);
                maxArrayLength = maxArrayLength == null ? arrayLength : Math.max(maxArrayLength, arrayLength);
            }
        }

        String summarize() {
            String depthText = minDepth == Integer.MAX_VALUE ? "n/a" : (minDepth + ".." + maxDepth);
            String lengthText = (minArrayLength == null || maxArrayLength == null)
                    ? ""
                    : " len=" + minArrayLength + ".." + maxArrayLength;
            return String.join("|", types) + " depth=" + depthText + lengthText;
        }
    }

    private record SchemaObservation(Map<String, SamplePathStats> pathStats, Set<String> exposureSignals) {
        String prettySummary() {
            List<String> rows = new ArrayList<>();
            List<String> keys = new ArrayList<>(pathStats.keySet());
            keys.sort(String::compareTo);
            for (String key : keys) {
                rows.add(key + " -> " + pathStats.get(key).summarize());
            }
            return rows.isEmpty() ? "(no schema fields)" : String.join("\n", rows);
        }
    }

    private record SchemaDriftSummary(boolean hasDrift, List<String> reasons) {
    }

    private record AuthContextSummary(boolean hasComparablePair, boolean behaviorDiffersAcrossContexts, String summaryText) {
    }

    private static final class ContextStats {
        private final AuthContext context;
        private long count;
        private final Set<Integer> statusCodes = new TreeSet<>();
        private final Set<String> responseShapes = new TreeSet<>();

        private ContextStats(AuthContext context) {
            this.context = context;
        }

        private void observe(JsonRpcNormalizedRecord normalizedRecord) {
            count++;
            if (normalizedRecord.responseStatus() != null) {
                statusCodes.add(normalizedRecord.responseStatus());
            }
            responseShapes.add(normalizedRecord.responseShapeSignature());
        }
    }

    private record AuthContext(
            String host,
            String database,
            String userName,
            String sessionId,
            String role,
            String cookieFingerprint,
            String contextKey
    ) {
        private static AuthContext overflowContext() {
            return new AuthContext("(varied)", "(varied)", "(varied)", "(varied)", "(varied)", "overflow", "overflow-context");
        }

        private String fingerprintKey() {
            return host + "|" + database + "|" + userName + "|" + sessionId + "|" + role + "|" + cookieFingerprint + "|" + contextKey;
        }

        private String summary() {
            return "host=" + host
                    + ", db=" + database
                    + ", user=" + userName
                    + ", session=" + sessionId
                    + ", role=" + role
                    + ", fp=" + cookieFingerprint
                    + ", key=" + contextKey;
        }
    }

    private static final class SampleObservation {
        private final String sampleId;
        private final Instant timestamp;
        private final String requestRaw;
        private final String requestBody;
        private final List<String> requestHeaders;
        private final String paramsText;
        private final String responseRaw;
        private final String responseBody;
        private final String schemaText;
        private final String contextSummary;
        private final Integer statusCode;
        private final ResponseClass responseClass;
        private final String contextKey;
        private final RoleType roleTag;

        private SampleObservation(
                String sampleId,
                Instant timestamp,
                String requestRaw,
                String requestBody,
                List<String> requestHeaders,
                String paramsText,
                String responseRaw,
                String responseBody,
                String schemaText,
                String contextSummary,
                Integer statusCode,
                ResponseClass responseClass,
                String contextKey,
                RoleType roleTag
        ) {
            this.sampleId = sampleId;
            this.timestamp = timestamp;
            this.requestRaw = requestRaw == null ? "" : requestRaw;
            this.requestBody = requestBody == null ? "" : requestBody;
            this.requestHeaders = requestHeaders == null ? List.of() : List.copyOf(requestHeaders);
            this.paramsText = paramsText == null ? "" : paramsText;
            this.responseRaw = responseRaw == null ? "" : responseRaw;
            this.responseBody = responseBody == null ? "" : responseBody;
            this.schemaText = schemaText == null ? "" : schemaText;
            this.contextSummary = contextSummary == null ? "" : contextSummary;
            this.statusCode = statusCode;
            this.responseClass = responseClass == null ? ResponseClass.UNKNOWN : responseClass;
            this.contextKey = contextKey == null ? "" : contextKey;
            this.roleTag = roleTag == null ? RoleType.UNKNOWN : roleTag;
        }

        private ObjectNode toExportJson(ObjectMapper mapper, RoleType currentRoleTag) {
            RoleType effectiveRole = currentRoleTag == null ? roleTag : currentRoleTag;
            ObjectNode sampleNode = mapper.createObjectNode();
            sampleNode.put("sampleId", sampleId == null ? "" : sampleId);
            sampleNode.put("timestamp", timestamp == null ? "" : timestamp.toString());
            sampleNode.put("context", contextSummary);
            sampleNode.put("contextKey", contextKey);
            sampleNode.put("roleTag", effectiveRole.displayName());
            sampleNode.put("statusCode", statusCode == null ? -1 : statusCode);
            sampleNode.put("responseClass", responseClass.displayName);

            ObjectNode requestNode = mapper.createObjectNode();
            requestNode.put("rawHttp", requestRaw);
            requestNode.put("body", requestBody);

            ArrayNode headers = mapper.createArrayNode();
            for (String header : requestHeaders) {
                headers.add(header);
            }
            requestNode.set("headers", headers);

            ArrayNode variants = mapper.createArrayNode();
            variants.add(variantNode(mapper, "original_request", requestBody, requestHeaders, List.of()));

            ObjectNode parsed = parseRequestObject(requestBody, mapper);
            if (parsed != null) {
                ObjectNode withoutParams = parsed.deepCopy();
                withoutParams.remove("params");
                variants.add(variantNode(mapper, "empty_params_variant", withoutParams.toString(), requestHeaders, List.of()));

                ObjectNode nullParams = parsed.deepCopy();
                nullParams.putNull("params");
                variants.add(variantNode(mapper, "null_params_variant", nullParams.toString(), requestHeaders, List.of()));

                ObjectNode harmlessExtraField = parsed.deepCopy();
                harmlessExtraField.put("_collector_manual_review", true);
                variants.add(variantNode(mapper, "extra_harmless_field_variant", harmlessExtraField.toString(), requestHeaders, List.of()));

                CredentialMutation credentialMutation = removeCredentials(parsed, requestHeaders, mapper);
                variants.add(variantNode(
                        mapper,
                        "removed_credentials_variant",
                        credentialMutation.body(),
                        credentialMutation.headers(),
                        credentialMutation.removedTokens()
                ));

                CrossContextTemplate crossContextTemplate = buildCrossContextTemplate(parsed, requestHeaders);
                variants.add(variantNode(
                    mapper,
                    "cross_context_id_swap_template",
                    crossContextTemplate.body(),
                    crossContextTemplate.headers(),
                    List.of(),
                    crossContextTemplate.notes()
                ));
            }

            requestNode.set("manualVariants", variants);
            sampleNode.set("request", requestNode);

            ObjectNode responseNode = mapper.createObjectNode();
            responseNode.put("rawHttp", responseRaw);
            responseNode.put("body", responseBody);
            responseNode.put("schema", schemaText);
            responseNode.put("responseClass", responseClass.displayName);
            sampleNode.set("response", responseNode);

            return sampleNode;
        }

        private static ObjectNode parseRequestObject(String requestBody, ObjectMapper mapper) {
            if (requestBody == null || requestBody.isBlank()) {
                return null;
            }
            try {
                JsonNode node = mapper.readTree(requestBody);
                if (node instanceof ObjectNode objectNode) {
                    return objectNode;
                }
            } catch (JsonProcessingException ignored) {
                // Parsing can fail for malformed payloads; export still includes original.
            }
            return null;
        }

        private static CredentialMutation removeCredentials(ObjectNode parsedRequest, List<String> originalHeaders, ObjectMapper mapper) {
            ObjectNode mutatedBody = parsedRequest.deepCopy();
            List<String> keptHeaders = new ArrayList<>();
            List<String> removedTokens = new ArrayList<>();

            for (String header : originalHeaders) {
                if (header == null) {
                    continue;
                }
                String lower = header.toLowerCase(Locale.ROOT);
                if (lower.startsWith("authorization:")
                        || lower.startsWith("cookie:")
                        || lower.startsWith("x-api-key:")
                        || lower.startsWith("x-auth-token:")) {
                    removedTokens.add(header);
                } else {
                    keptHeaders.add(header);
                }
            }

            JsonNode paramsNode = mutatedBody.path("params");
            if (paramsNode instanceof ObjectNode paramsObject) {
                List<String> fieldsToRemove = new ArrayList<>();
                Iterator<String> fieldNames = paramsObject.fieldNames();
                while (fieldNames.hasNext()) {
                    String fieldName = fieldNames.next();
                    String lowered = fieldName.toLowerCase(Locale.ROOT);
                    if (lowered.contains("password")
                            || lowered.contains("token")
                            || lowered.contains("secret")
                            || lowered.contains("apikey")
                            || lowered.contains("auth")
                            || lowered.contains("session")) {
                        fieldsToRemove.add(fieldName);
                    }
                }
                for (String field : fieldsToRemove) {
                    paramsObject.remove(field);
                    removedTokens.add("params." + field);
                }
            }

            return new CredentialMutation(mutatedBody.toString(), keptHeaders, removedTokens);
        }

        private static CrossContextTemplate buildCrossContextTemplate(ObjectNode parsedRequest, List<String> originalHeaders) {
            ObjectNode mutatedBody = parsedRequest.deepCopy();
            List<String> notes = new ArrayList<>();
            List<String> strippedHeaders = stripAuthHeaders(originalHeaders);

            JsonNode paramsNode = mutatedBody.path("params");
            if (paramsNode instanceof ObjectNode paramsObject) {
                Iterator<String> fieldNames = paramsObject.fieldNames();
                List<String> fieldsToSwap = new ArrayList<>();
                while (fieldNames.hasNext()) {
                    String fieldName = fieldNames.next();
                    String lowered = fieldName.toLowerCase(Locale.ROOT);
                    if (isCrossContextField(lowered)) {
                        fieldsToSwap.add(fieldName);
                    }
                }

                for (String field : fieldsToSwap) {
                    paramsObject.put(field, "<swap_from_other_context>");
                    notes.add("Replace params." + field + " with a value captured under a different user/tenant.");
                }
            }

            if (!strippedHeaders.equals(originalHeaders)) {
                notes.add("Replay with alternate auth headers to validate context isolation.");
            }

            if (notes.isEmpty()) {
                notes.add("Swap user/tenant/account/report identifiers from another authenticated context and compare responses.");
            }

            return new CrossContextTemplate(mutatedBody.toString(), strippedHeaders, notes);
        }

        private static List<String> stripAuthHeaders(List<String> headers) {
            List<String> kept = new ArrayList<>();
            for (String header : headers) {
                if (header == null) {
                    continue;
                }
                String lowered = header.toLowerCase(Locale.ROOT);
                if (lowered.startsWith("authorization:")
                        || lowered.startsWith("cookie:")
                        || lowered.startsWith("x-api-key:")
                        || lowered.startsWith("x-auth-token:")) {
                    continue;
                }
                kept.add(header);
            }
            return kept;
        }

        private static boolean isCrossContextField(String lowered) {
            return lowered.equals("id")
                    || lowered.endsWith("id")
                    || lowered.contains("_id")
                    || lowered.contains("tenant")
                    || lowered.contains("user")
                    || lowered.contains("account")
                    || lowered.contains("order")
                    || lowered.contains("device")
                    || lowered.contains("report")
                    || lowered.contains("session")
                    || lowered.contains("token");
        }

        private static ObjectNode variantNode(
                ObjectMapper mapper,
                String name,
                String body,
                List<String> headers,
                List<String> removedTokens
        ) {
            return variantNode(mapper, name, body, headers, removedTokens, List.of());
        }

        private static ObjectNode variantNode(
                ObjectMapper mapper,
                String name,
                String body,
                List<String> headers,
                List<String> removedTokens,
                List<String> notes
        ) {
            ObjectNode node = mapper.createObjectNode();
            node.put("name", name);
            node.put("body", body == null ? "" : body);

            ArrayNode headerArray = mapper.createArrayNode();
            for (String header : headers) {
                headerArray.add(header);
            }
            node.set("headers", headerArray);

            ArrayNode removedArray = mapper.createArrayNode();
            for (String token : removedTokens) {
                removedArray.add(token);
            }
            node.set("removedCredentials", removedArray);

            ArrayNode notesArray = mapper.createArrayNode();
            for (String note : notes) {
                notesArray.add(note);
            }
            node.set("notes", notesArray);
            return node;
        }
    }

    private record CredentialMutation(String body, List<String> headers, List<String> removedTokens) {
    }

    private record CrossContextTemplate(String body, List<String> headers, List<String> notes) {
    }

    private static final class FindingFlags {
        private volatile boolean exported;
        private volatile boolean reviewed;
    }

    private static AuthContext extractAuthContext(
            JsonRpcRecord rawRecord,
            ObjectMapper objectMapper,
            AuthContextStore.AuthContext taggedContext
    ) {
        String host = extractHost(rawRecord.request().url());

        JsonNode requestNode = parseJson(rawRecord.request().bodyText(), objectMapper);
        JsonNode responseNode = parseJson(rawRecord.response().bodyText(), objectMapper);

        String database = defaultIfBlank(taggedContext.database(), firstKnownValue(requestNode, responseNode, DATABASE_KEYS));
        String userName = defaultIfBlank(taggedContext.userName(), firstKnownValue(requestNode, responseNode, USER_KEYS));
        String sessionId = defaultIfBlank(taggedContext.sessionId(), firstKnownValue(requestNode, responseNode, SESSION_KEYS));
        String role = taggedContext.role() == null ? RoleType.UNKNOWN.displayName() : taggedContext.role().displayName();

        String fingerprint = cookieFingerprint(rawRecord.request().headers(), sessionId);

        return new AuthContext(
                defaultIfBlank(host, "unknown-host"),
                defaultIfBlank(database, "unknown-db"),
                defaultIfBlank(userName, "unknown-user"),
                defaultIfBlank(sessionId, "unknown-session"),
                defaultIfBlank(role, "unknown-role"),
            defaultIfBlank(fingerprint, "no-cookie-fp"),
            defaultIfBlank(taggedContext.contextKey(), "unknown-context")
        );
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

    private static JsonNode parseJson(String body, ObjectMapper objectMapper) {
        if (body == null || body.isBlank()) {
            return null;
        }
        try {
            return objectMapper.readTree(body);
        } catch (Exception ignored) {
            return null;
        }
    }

    private static String firstKnownValue(JsonNode requestNode, JsonNode responseNode, Set<String> candidateKeys) {
        String fromRequest = findFirstByKeys(requestNode, candidateKeys);
        if (!fromRequest.isBlank()) {
            return fromRequest;
        }
        return findFirstByKeys(responseNode, candidateKeys);
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
                for (String candidateKey : candidateKeys) {
                    if (fieldName.equalsIgnoreCase(candidateKey)) {
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

    private static String cookieFingerprint(List<String> headers, String extractedSessionId) {
        if (headers == null || headers.isEmpty()) {
            return extractedSessionId == null || extractedSessionId.isBlank() ? "" : shortHash(extractedSessionId);
        }

        StringBuilder material = new StringBuilder();
        for (String header : headers) {
            if (header == null || header.isBlank()) {
                continue;
            }
            String lowered = header.toLowerCase(Locale.ROOT);
            if (lowered.startsWith("cookie:")) {
                material.append(header).append("|");
            }
            if (lowered.startsWith("authorization:")) {
                int split = header.indexOf(':');
                if (split > 0) {
                    String authValue = header.substring(split + 1).trim();
                    String scheme = authValue.contains(" ") ? authValue.substring(0, authValue.indexOf(' ')) : authValue;
                    material.append("authorization-scheme=").append(scheme).append("|");
                }
            }
        }

        if (extractedSessionId != null && !extractedSessionId.isBlank()) {
            material.append("session=").append(extractedSessionId);
        }

        return material.isEmpty() ? "" : shortHash(material.toString());
    }

    private static String shortHash(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes());
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < Math.min(hash.length, 8); i++) {
                builder.append(String.format("%02x", hash[i]));
            }
            return builder.toString();
        } catch (Exception ignored) {
            return String.valueOf(value.hashCode());
        }
    }

    private static SchemaObservation parseResponseSchema(String responseBody, ObjectMapper objectMapper) {
        if (responseBody == null || responseBody.isBlank()) {
            return null;
        }

        JsonNode root;
        try {
            root = objectMapper.readTree(responseBody);
        } catch (Exception ignored) {
            return null;
        }

        Map<String, SamplePathStats> pathStats = new HashMap<>();
        Set<String> exposureSignals = new TreeSet<>();
        visitNode(root, "$", 0, pathStats, exposureSignals);
        return new SchemaObservation(pathStats, exposureSignals);
    }

    private static void visitNode(
            JsonNode node,
            String path,
            int depth,
            Map<String, SamplePathStats> pathStats,
            Set<String> exposureSignals
    ) {
        if (node == null) {
            return;
        }

        if (node.isObject()) {
            SamplePathStats objectStats = pathStats.computeIfAbsent(path, ignored -> new SamplePathStats());
            objectStats.observeType("object", depth, null);

            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                String childPath = "$".equals(path) ? "$." + field.getKey() : path + "." + field.getKey();
                JsonNode child = field.getValue();

                SamplePathStats childStats = pathStats.computeIfAbsent(childPath, ignored -> new SamplePathStats());
                childStats.observeType(typeName(child), depth + 1, child.isArray() ? child.size() : null);
                detectExposure(field.getKey(), child, childPath, exposureSignals);

                visitNode(child, childPath, depth + 1, pathStats, exposureSignals);
            }
            return;
        }

        if (node.isArray()) {
            SamplePathStats arrayStats = pathStats.computeIfAbsent(path, ignored -> new SamplePathStats());
            arrayStats.observeType("array", depth, node.size());

            for (JsonNode item : node) {
                String itemPath = path + "[]";
                SamplePathStats itemStats = pathStats.computeIfAbsent(itemPath, ignored -> new SamplePathStats());
                itemStats.observeType(typeName(item), depth + 1, item.isArray() ? item.size() : null);
                visitNode(item, itemPath, depth + 1, pathStats, exposureSignals);
            }
            return;
        }

        SamplePathStats primitiveStats = pathStats.computeIfAbsent(path, ignored -> new SamplePathStats());
        primitiveStats.observeType(typeName(node), depth, null);
    }

    private static void detectExposure(String fieldName, JsonNode value, String path, Set<String> signals) {
        if (signals.size() >= MAX_EXPOSURE_SIGNALS || fieldName == null) {
            return;
        }

        String lowered = fieldName.toLowerCase(Locale.ROOT);

        if (lowered.contains("tenant") || lowered.contains("organization") || lowered.contains("orgid")) {
            signals.add("Tenant/organization field at " + path);
        }
        if (lowered.equals("db") || lowered.contains("database")) {
            signals.add("Database field at " + path);
        }
        if (lowered.contains("userid") || lowered.contains("accountid") || lowered.endsWith("id") || lowered.contains("_id")) {
            signals.add("ID-like field at " + path);
        }
        if (lowered.contains("session") || lowered.contains("token") || lowered.contains("jwt")) {
            signals.add("Session/token field at " + path);
        }
        if (lowered.contains("role") || lowered.contains("permission")) {
            signals.add("Role/permission field at " + path);
        }
        if (lowered.contains("account") || lowered.contains("billing")) {
            signals.add("Account metadata field at " + path);
        }
        if (lowered.contains("endpoint") || lowered.contains("route") || lowered.contains("backend")) {
            signals.add("Hidden endpoint/backend route field at " + path);
        }
        if (lowered.contains("email")) {
            signals.add("Email field at " + path);
        }

        if (value != null && value.isTextual()) {
            String text = value.asText("");
            if (EMAIL_PATTERN.matcher(text).find()) {
                signals.add("Email value at " + path);
            }
            if (INTERNAL_URL_PATTERN.matcher(text).find()) {
                signals.add("Internal URL/route value at " + path);
            }
        }
    }

    private static String typeName(JsonNode node) {
        if (node == null) {
            return "missing";
        }
        if (node.isNull()) {
            return "null";
        }
        if (node.isTextual()) {
            return "string";
        }
        if (node.isBoolean()) {
            return "boolean";
        }
        if (node.isIntegralNumber()) {
            return "integer";
        }
        if (node.isFloatingPointNumber()) {
            return "number";
        }
        if (node.isArray()) {
            return "array";
        }
        if (node.isObject()) {
            return "object";
        }
        return node.getNodeType().name().toLowerCase(Locale.ROOT);
    }

    private static String extractParamsText(String requestBody, ObjectMapper objectMapper) {
        if (requestBody == null || requestBody.isBlank()) {
            return "(missing request body)";
        }

        try {
            JsonNode root = objectMapper.readTree(requestBody);
            if (!root.isObject()) {
                return "(request body is not a JSON object)";
            }

            JsonNode params = root.path("params");
            if (params.isMissingNode()) {
                return "(params missing)";
            }

            if (params.isNull()) {
                return "null";
            }

            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(params);
        } catch (Exception ex) {
            return "(unable to parse params: " + ex.getMessage() + ")";
        }
    }

    private static ResponseClass classifyResponse(Integer statusCode, String responseBody) {
        String lower = responseBody == null ? "" : responseBody.toLowerCase(Locale.ROOT);

        if (statusCode != null) {
            if (statusCode >= 500) {
                return ResponseClass.SERVER_ERROR;
            }
            if (statusCode == 401) {
                return ResponseClass.AUTH_REQUIRED;
            }
            if (statusCode == 403) {
                return ResponseClass.PERMISSION_ERROR;
            }
            if (statusCode == 404) {
                return ResponseClass.NOT_FOUND;
            }
            if (statusCode >= 400) {
                if (lower.contains("validation") || lower.contains("invalid")) {
                    return ResponseClass.VALIDATION_ERROR;
                }
                if (lower.contains("forbidden") || lower.contains("permission") || lower.contains("denied")) {
                    return ResponseClass.PERMISSION_ERROR;
                }
            }
            if (statusCode >= 200 && statusCode < 300) {
                if (lower.contains("\"error\"")) {
                    return ResponseClass.ERROR_IN_SUCCESS;
                }
                return ResponseClass.SUCCESS_RESULT;
            }
        }

        if (lower.contains("forbidden") || lower.contains("permission") || lower.contains("denied")) {
            return ResponseClass.PERMISSION_ERROR;
        }
        if (lower.contains("unauthorized") || lower.contains("auth") || lower.contains("login")) {
            return ResponseClass.AUTH_REQUIRED;
        }
        if (lower.contains("not found") || lower.contains("missing")) {
            return ResponseClass.NOT_FOUND;
        }
        if (lower.contains("validation") || lower.contains("invalid")) {
            return ResponseClass.VALIDATION_ERROR;
        }
        if (lower.contains("\"result\"") || lower.contains("\"data\"")) {
            return ResponseClass.SUCCESS_RESULT;
        }

        return ResponseClass.UNKNOWN;
    }

    private enum ResponseClass {
        SUCCESS_RESULT("success"),
        ERROR_IN_SUCCESS("error-in-success"),
        AUTH_REQUIRED("auth-required"),
        PERMISSION_ERROR("permission-error"),
        NOT_FOUND("not-found"),
        VALIDATION_ERROR("validation-error"),
        SERVER_ERROR("server-error"),
        UNKNOWN("unknown");

        private final String displayName;

        ResponseClass(String displayName) {
            this.displayName = displayName;
        }
    }

    private static String joinLimited(List<String> values, int maxItems) {
        if (values == null || values.isEmpty()) {
            return "";
        }
        List<String> copy = new ArrayList<>(values);
        if (copy.size() > maxItems) {
            List<String> limited = new ArrayList<>(copy.subList(0, maxItems));
            limited.add("... +" + (copy.size() - maxItems) + " more");
            copy = limited;
        }
        return String.join("; ", copy);
    }

    private static String defaultIfBlank(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }
}
