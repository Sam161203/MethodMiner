import burp.api.montoya.logging.Logging;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public final class AttackSuggestionService implements AutoCloseable {
    private static final String DEFAULT_TARGET_HOST = "example.com";
    private static final String DEFAULT_TARGET_PATH = "/jsonrpc";

    private static final Set<String> SUPPRESSED_METHOD_TERMS = Set.of(
            "jsonp", "cors", "addin", "add-in", "addins", "message", "messages",
            "audit", "audit-log", "auditlog", "ui-only", "uionly",
            "password", "password-complexity", "dos"
    );

    private static final int MAX_SUGGESTIONS = 400;

    private final ObjectMapper objectMapper;
    private final JsonRpcIndex index;
    private final SecurityAnalyzerService securityAnalyzer;
    private final WorkflowGraphService workflowGraphService;
    private final EntityStoreService entityStoreService;
    private final AuthContextStore authContextStore;
    private final Logging logging;

    private final ExecutorService analyzerExecutor = Executors.newSingleThreadExecutor(
            runnable -> new Thread(runnable, "jsonrpc-attack-suggestions")
    );
    private final List<Runnable> updateListeners = new CopyOnWriteArrayList<>();
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final AtomicBoolean recomputeQueued = new AtomicBoolean(false);

    private final Map<String, RequestObservation> observations = new ConcurrentHashMap<>();

    private volatile List<AttackSuggestion> latestSuggestions = List.of();
    private volatile Map<String, AttackSuggestion> suggestionsById = Map.of();
    private volatile Map<String, AttackExecutionFinding> executionFindingsBySuggestionId = Map.of();
    private volatile AttackExecutionService attackExecutionService;

    public AttackSuggestionService(
            ObjectMapper objectMapper,
            JsonRpcIndex index,
            SecurityAnalyzerService securityAnalyzer,
            WorkflowGraphService workflowGraphService,
            EntityStoreService entityStoreService,
            AuthContextStore authContextStore,
            Logging logging
    ) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
        this.index = Objects.requireNonNull(index, "index must not be null");
        this.securityAnalyzer = Objects.requireNonNull(securityAnalyzer, "securityAnalyzer must not be null");
        this.workflowGraphService = Objects.requireNonNull(workflowGraphService, "workflowGraphService must not be null");
        this.entityStoreService = Objects.requireNonNull(entityStoreService, "entityStoreService must not be null");
        this.authContextStore = Objects.requireNonNull(authContextStore, "authContextStore must not be null");
        this.logging = Objects.requireNonNull(logging, "logging must not be null");

        this.securityAnalyzer.registerUpdateListener(this::requestRecomputeAsync);
        this.workflowGraphService.registerUpdateListener(this::requestRecomputeAsync);
        this.entityStoreService.registerUpdateListener(this::requestRecomputeAsync);
        this.authContextStore.registerUpdateListener(this::requestRecomputeAsync);
    }

    public void registerUpdateListener(Runnable listener) {
        if (listener != null) {
            updateListeners.add(listener);
        }
    }

    public void ingestRecordAsync(JsonRpcRecord rawRecord, JsonRpcNormalizedRecord normalizedRecord, boolean replayed) {
        observeRecord(rawRecord, normalizedRecord);
        requestRecomputeAsync();
    }

    public void requestRecomputeAsync() {
        if (closed.get()) {
            return;
        }
        if (!recomputeQueued.compareAndSet(false, true)) {
            return;
        }

        analyzerExecutor.submit(() -> {
            try {
                recomputeSync();
            } catch (Exception ex) {
                logging.logToError("Attack suggestion recompute failed.", ex);
            } finally {
                recomputeQueued.set(false);
            }
        });
    }

    void recomputeSync() {
        Map<String, AttackSuggestion> deduplicated = new LinkedHashMap<>();

        List<RequestObservation> snapshot = new ArrayList<>(observations.values());
        snapshot.sort(Comparator.comparing(RequestObservation::timestamp));

        Map<String, AuthContextStore.SessionView> contextsByKey = new HashMap<>();
        for (AuthContextStore.SessionView session : authContextStore.snapshotSessions()) {
            contextsByKey.put(session.contextKey(), session);
        }

        Map<String, EntityStoreService.ExtractedEntity> entitiesById = new HashMap<>();
        for (EntityStoreService.ExtractedEntity entity : entityStoreService.snapshotExtractedEntities()) {
            entitiesById.put(entity.entityId(), entity);
        }

        List<JsonRpcIndex.MethodStoreView> methodStore = index.snapshotMethodStoreViews();
        Map<String, Set<String>> methodToContexts = buildMethodContextMap(methodStore);
        Map<String, List<MethodDiffEvidence>> methodDiffEvidence = buildMethodDiffEvidence(methodStore, contextsByKey);
        Map<String, Set<String>> entityToContexts = buildEntityContextMap(entitiesById);
        WorkflowGraphService.WorkflowGraphSnapshot workflowSnapshot = workflowGraphService.snapshot();

        runPrivilegeDiffDetector(methodDiffEvidence, contextsByKey, entitiesById, workflowSnapshot, deduplicated);
        runBolaDetector(snapshot, entitiesById, contextsByKey, methodStore, methodDiffEvidence, entityToContexts, workflowSnapshot, deduplicated);
        runMulticallDetector(snapshot, contextsByKey, methodStore, methodDiffEvidence, entityToContexts, methodToContexts, workflowSnapshot, deduplicated);
        runCrossTenantDetector(snapshot, entitiesById, contextsByKey, methodStore, methodDiffEvidence, entityToContexts, workflowSnapshot, deduplicated);
        runSearchEnumerationDetector(snapshot, contextsByKey, methodStore, methodToContexts, workflowSnapshot, deduplicated);
        runMethodAccessDetector(methodStore, contextsByKey, workflowSnapshot, deduplicated);

        List<AttackSuggestion> next = new ArrayList<>(deduplicated.values());
        next.sort(Comparator
                .comparingInt(AttackSuggestion::priorityScore).reversed()
                .thenComparing(AttackSuggestion::findingType, String.CASE_INSENSITIVE_ORDER)
                .thenComparing(AttackSuggestion::method, String.CASE_INSENSITIVE_ORDER)
                .thenComparing(AttackSuggestion::entityId, String.CASE_INSENSITIVE_ORDER));

        if (next.size() > MAX_SUGGESTIONS) {
            next = new ArrayList<>(next.subList(0, MAX_SUGGESTIONS));
        }

        Map<String, AttackSuggestion> byId = new LinkedHashMap<>();
        for (AttackSuggestion suggestion : next) {
            byId.put(suggestion.suggestionId(), suggestion);
        }

        latestSuggestions = List.copyOf(next);
        suggestionsById = Map.copyOf(byId);
        logging.logToOutput("[LogicHunter][SUGGEST] observations=" + snapshot.size() + " generated=" + next.size());
        notifyListeners();
    }

    public List<AttackSuggestion> snapshotSuggestions() {
        return latestSuggestions;
    }

    public Optional<AttackSuggestion> snapshotSuggestion(String suggestionId) {
        return Optional.ofNullable(suggestionsById.get(suggestionId));
    }

    public void setAttackExecutionService(AttackExecutionService attackExecutionService) {
        this.attackExecutionService = attackExecutionService;
    }

    public Optional<AttackExecutionFinding> executeSuggestionValidation(String suggestionId) {
        AttackExecutionService executionService = attackExecutionService;
        if (executionService == null || suggestionId == null || suggestionId.isBlank()) {
            return Optional.empty();
        }

        AttackSuggestion suggestion = suggestionsById.get(suggestionId);
        if (suggestion == null) {
            return Optional.empty();
        }

        Optional<AttackExecutionFinding> result = executionService.executeForSuggestion(suggestion);
        if (result.isEmpty()) {
            return Optional.empty();
        }

        Map<String, AttackExecutionFinding> next = new LinkedHashMap<>(executionFindingsBySuggestionId);
        next.put(suggestionId, result.get());
        executionFindingsBySuggestionId = Map.copyOf(next);
        notifyListeners();
        return result;
    }

    public Map<String, AttackExecutionFinding> snapshotExecutionFindings() {
        return executionFindingsBySuggestionId;
    }

    public Optional<AttackExecutionFinding> snapshotExecutionFinding(String suggestionId) {
        return Optional.ofNullable(executionFindingsBySuggestionId.get(suggestionId));
    }

    public boolean hasAttackExecutionService() {
        return attackExecutionService != null;
    }

    public boolean isAttackSafeMode() {
        AttackExecutionService executionService = attackExecutionService;
        return executionService == null || executionService.isSafeMode();
    }

    public void setAttackSafeMode(boolean safeMode) {
        AttackExecutionService executionService = attackExecutionService;
        if (executionService == null) {
            return;
        }
        executionService.setSafeMode(safeMode);
    }

    public void setAttackMaxRequestsPerFinding(int maxRequests) {
        AttackExecutionService executionService = attackExecutionService;
        if (executionService == null) {
            return;
        }
        executionService.setMaxRequestsPerFinding(maxRequests);
    }

    public int attackMaxRequestsPerFinding() {
        AttackExecutionService executionService = attackExecutionService;
        return executionService == null ? 0 : executionService.maxRequestsPerFinding();
    }

    public List<AttackExecutionFinding> executeTopSuggestionValidations(int limit) {
        if (limit <= 0) {
            return List.of();
        }

        List<AttackExecutionFinding> out = new ArrayList<>();
        int max = Math.min(limit, latestSuggestions.size());
        for (int i = 0; i < max; i++) {
            AttackSuggestion suggestion = latestSuggestions.get(i);
            executeSuggestionValidation(suggestion.suggestionId()).ifPresent(out::add);
        }
        return List.copyOf(out);
    }

    public ObjectNode buildManualExportBundle(String suggestionId) {
        AttackSuggestion suggestion = snapshotSuggestion(suggestionId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown suggestion ID: " + suggestionId));

        ObjectNode root = objectMapper.createObjectNode();
        root.put("generatedAt", Instant.now().toString());
        root.put("mode", "manual-only");
        root.put("suggestionId", suggestion.suggestionId());
        root.put("title", suggestion.findingTitle());
        root.put("category", suggestion.findingType());
        root.put("host", suggestion.host());
        root.put("method", suggestion.method());
        root.put("typeName", suggestion.typeName());
        root.put("attackPath", suggestion.attackPath());
        root.put("reason", suggestion.whySuspicious());
        root.put("confidenceScore", suggestion.confidenceScore());
        root.put("effectivenessScore", suggestion.effectivenessScore());
        root.put("expectedResult", suggestion.expectedResult());
        root.put("ifVulnerableImpact", suggestion.impact());
        root.put("repeaterRequest", suggestion.repeaterRequest());
        root.put("observation", suggestion.observation());
        root.put("evidence", suggestion.evidence());
        root.put("sessionId", suggestion.sessionId());
        root.put("entityId", suggestion.entityId());
        root.put("adminResponse", suggestion.adminResponse());
        root.put("lowPrivResponse", suggestion.lowPrivResponse());
        root.put("payload", suggestion.payload());
        root.put("curlCommand", buildCurlCommand(suggestion));
        root.put("bugcrowdMarkdown", suggestion.bugcrowdMarkdown());
        root.put("formattedFinding", suggestion.toFormattedFinding());

        AttackExecutionFinding executionFinding = executionFindingsBySuggestionId.get(suggestionId);
        if (executionFinding != null) {
            ObjectNode executionNode = objectMapper.createObjectNode();
            executionNode.put("findingId", executionFinding.findingId());
            executionNode.put("category", executionFinding.category());
            executionNode.put("severity", executionFinding.severity().displayName());
            executionNode.put("confirmed", executionFinding.confirmed());
            executionNode.put("method", executionFinding.method());
            executionNode.put("entityId", executionFinding.entityId());
            executionNode.put("sourceContext", executionFinding.sourceContext());
            executionNode.put("targetContext", executionFinding.targetContext());
            executionNode.put("sourceRole", executionFinding.sourceRole().displayName());
            executionNode.put("targetRole", executionFinding.targetRole().displayName());
            executionNode.put("responseClassification", executionFinding.responseClassification());
            executionNode.put("exploitChain", executionFinding.exploitChain());
            executionNode.put("summary", executionFinding.summary());
            executionNode.put("payloadUsed", executionFinding.payloadUsed());
            executionNode.put("executedAt", executionFinding.executedAt() == null ? "" : executionFinding.executedAt().toString());
            root.set("attackExecution", executionNode);
        }

        if (!suggestion.method().isBlank()) {
            String lookupKey = suggestion.method() + ":" + defaultIfBlank(suggestion.typeName(), "Unknown");
            index.snapshotMethodDetails(lookupKey)
                    .ifPresent(details -> root.set("methodMetadata", details.toMetadataJson(objectMapper)));
        }

        return root;
    }

    public void clear() {
        observations.clear();
        latestSuggestions = List.of();
        suggestionsById = Map.of();
        executionFindingsBySuggestionId = Map.of();
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

    private void observeRecord(JsonRpcRecord rawRecord, JsonRpcNormalizedRecord normalizedRecord) {
        if (rawRecord == null || normalizedRecord == null) {
            return;
        }

        String host = MyGeotabScope.extractHost(rawRecord.request().url());
        if (!MyGeotabScope.isAllowedHost(host)) {
            return;
        }

        if (isSuppressedMethod(normalizedRecord.methodName())) {
            return;
        }

        AuthContextStore.Credentials credentials = authContextStore.extractCredentials(rawRecord.request().bodyText());
        if (credentials == null) {
            return;
        }

        AuthContextStore.AuthContext observedContext = authContextStore.lookupContext(rawRecord.request().bodyText(), rawRecord.request().url());

        ParsedRequest parsed = parseRequest(rawRecord.request().bodyText(), normalizedRecord);
        if (parsed == null) {
            return;
        }

        String observationId = defaultIfBlank(rawRecord.recordId(), "record")
                + "|" + normalizedRecord.methodName()
                + "|" + defaultIfBlank(normalizedRecord.typeName(), parsed.typeName());

        RequestObservation observation = new RequestObservation(
                observationId,
                rawRecord.recordId(),
                rawRecord.timestamp() == null ? Instant.now() : rawRecord.timestamp(),
                host,
            normalizedRecord.methodName(),
            defaultIfBlank(parsed.wrapperMethod(), normalizedRecord.methodName()),
                defaultIfBlank(parsed.typeName(), normalizedRecord.typeName()),
            defaultIfBlank(observedContext.contextKey(), ""),
            defaultIfBlank(observedContext.sessionId(), credentials.sessionId()),
            defaultIfBlank(observedContext.database(), defaultIfBlank(credentials.database(), "unknown-db")),
            defaultIfBlank(observedContext.userName(), defaultIfBlank(credentials.userName(), "unknown-user")),
                parsed.entityIds(),
                parsed.multiCall(),
                parsed.emptySearchInSubCall(),
                parsed.subCallTypeNames(),
            parsed.subCallMethods(),
            parsed.hasWriteSubCall(),
            parsed.hasMixedPrivilegeChain(),
                normalizedRecord.paramsMode(),
                parsed.notification(),
                rawRecord.request().bodyText() == null ? "" : rawRecord.request().bodyText(),
                rawRecord.response().bodyText() == null ? "" : rawRecord.response().bodyText(),
                rawRecord.response().statusCode(),
                parsed.broadSearch()
        );

        observations.put(observationId, observation);
    }

    private ParsedRequest parseRequest(String requestBody, JsonRpcNormalizedRecord normalizedRecord) {
        JsonNode root = parseJson(requestBody);
        if (root == null) {
            return null;
        }

        JsonNode call = root;
        if (root.isArray() && root.size() > 0 && root.get(0).isObject()) {
            call = root.get(0);
        }

        if (call == null || !call.isObject()) {
            return null;
        }

        JsonNode params = call.get("params");
        if (params == null || params.isNull()) {
            return null;
        }

        String wrapperMethod = asText(call.get("method"));
        String typeName = "";
        if (params.isObject()) {
            typeName = asText(params.get("typeName"));
        }
        if (typeName.isBlank()) {
            typeName = normalizedRecord.typeName();
        }

        LinkedHashSet<String> entityIds = new LinkedHashSet<>();
        collectEntityIdsFromParams(params, "", entityIds, 0);

        boolean multiCall = wrapperMethod.toLowerCase(Locale.ROOT).contains("multicall") || normalizedRecord.batchRequest();
        boolean emptySearchInSubCall = false;
        LinkedHashSet<String> subTypeNames = new LinkedHashSet<>();
        LinkedHashSet<String> subCallMethods = new LinkedHashSet<>();
        boolean hasWriteSubCall = false;
        boolean hasMixedPrivilegeChain = false;
        if (multiCall && params.isObject()) {
            MultiCallInfo info = parseMultiCallInfo(params);
            emptySearchInSubCall = info.emptySearchInSubCall();
            subTypeNames.addAll(info.subCallTypeNames());
            subCallMethods.addAll(info.subCallMethods());
            hasWriteSubCall = info.hasWriteSubCall();
            hasMixedPrivilegeChain = info.hasMixedPrivilegeChain();
        }

        // Detect standalone broad/unrestricted search patterns
        boolean broadSearch = false;
        if (!multiCall && params.isObject()) {
            String methodLower = wrapperMethod.toLowerCase(Locale.ROOT);
            boolean isReadMethod = methodLower.startsWith("get") || methodLower.startsWith("find")
                    || methodLower.startsWith("list") || methodLower.startsWith("search");
            if (isReadMethod) {
                JsonNode searchNode = params.get("search");
                if (searchNode == null || searchNode.isMissingNode()) {
                    broadSearch = true; // No search clause at all
                } else if (searchNode.isObject()) {
                    if (searchNode.size() == 0) {
                        broadSearch = true; // Empty search: {}
                    } else {
                        boolean hasIdConstraint = false;
                        java.util.Iterator<String> fieldNames = searchNode.fieldNames();
                        while (fieldNames.hasNext()) {
                            String field = fieldNames.next().toLowerCase(Locale.ROOT);
                            if (isEntityKey(field)) {
                                hasIdConstraint = true;
                                break;
                            }
                        }
                        if (!hasIdConstraint) {
                            broadSearch = true; // Search has no ID constraint (e.g. {isDeviceCommunicating:true})
                        }
                    }
                }
            }
        }

        boolean notification = !call.has("id") || call.path("id").isNull();

        return new ParsedRequest(
                wrapperMethod,
                typeName,
                List.copyOf(entityIds),
                multiCall,
                emptySearchInSubCall,
                List.copyOf(subTypeNames),
                List.copyOf(subCallMethods),
                hasWriteSubCall,
                hasMixedPrivilegeChain,
                notification,
                broadSearch
        );
    }

    private void collectEntityIdsFromParams(JsonNode node, String keyName, Set<String> out, int depth) {
        if (node == null || node.isNull() || node.isMissingNode() || depth > 8) {
            return;
        }

        if (node.isObject()) {
            node.fields().forEachRemaining(entry -> {
                String key = entry.getKey() == null ? "" : entry.getKey();
                if ("credentials".equalsIgnoreCase(key)) {
                    return;
                }
                collectEntityIdsFromParams(entry.getValue(), key, out, depth + 1);
            });
            return;
        }

        if (node.isArray()) {
            for (JsonNode child : node) {
                collectEntityIdsFromParams(child, keyName, out, depth + 1);
            }
            return;
        }

        if (!node.isValueNode()) {
            return;
        }

        String lowered = keyName.toLowerCase(Locale.ROOT);
        if (!isEntityKey(lowered)) {
            return;
        }

        String value = asText(node);
        if (!value.isBlank()) {
            out.add(value);
        }
    }

    private MultiCallInfo parseMultiCallInfo(JsonNode params) {
        LinkedHashSet<String> subTypeNames = new LinkedHashSet<>();
        LinkedHashSet<String> subCallMethods = new LinkedHashSet<>();
        boolean emptySearch = false;
        boolean hasWrite = false;
        boolean hasRead = false;

        JsonNode calls = params.path("calls");
        if (!calls.isArray()) {
            calls = params.path("requests");
        }
        if (!calls.isArray()) {
            calls = params.path("operations");
        }

        if (calls.isArray()) {
            for (JsonNode subCall : calls) {
                JsonNode subParams = subCall.path("params");
                JsonNode subSearch = subParams.path("search");
                if (subSearch.isObject() && subSearch.size() == 0) {
                    emptySearch = true;
                }

                String subMethod = asText(subCall.get("method"));
                if (!subMethod.isBlank()) {
                    subCallMethods.add(subMethod);
                    if (isWriteLikeMethod(subMethod)) {
                        hasWrite = true;
                    } else {
                        hasRead = true;
                    }
                }

                String subType = asText(subParams.get("typeName"));
                if (!subType.isBlank()) {
                    subTypeNames.add(subType);
                }
            }
        }

        return new MultiCallInfo(
                emptySearch,
                List.copyOf(subTypeNames),
                List.copyOf(subCallMethods),
                hasWrite,
                hasWrite && hasRead
        );
    }

    private void runBolaDetector(
            List<RequestObservation> observations,
            Map<String, EntityStoreService.ExtractedEntity> entitiesById,
            Map<String, AuthContextStore.SessionView> contextsByKey,
            List<JsonRpcIndex.MethodStoreView> methodStore,
            Map<String, List<MethodDiffEvidence>> methodDiffEvidence,
            Map<String, Set<String>> entityToContexts,
            WorkflowGraphService.WorkflowGraphSnapshot workflowSnapshot,
            Map<String, AttackSuggestion> out
    ) {
        for (RequestObservation observation : observations) {
            if (isSuppressedMethod(observation.method()) || observation.requestEntityIds().isEmpty()) {
                continue;
            }

            String targetContext = defaultIfBlank(observation.contextKey(), "");
            if (targetContext.isBlank()) {
                continue;
            }

            RoleType targetRole = roleFor(targetContext, contextsByKey);

            for (String entityId : observation.requestEntityIds()) {
                EntityStoreService.ExtractedEntity entity = entitiesById.get(entityId);
                if (entity == null) {
                    continue;
                }

                Set<String> seenContexts = new LinkedHashSet<>(entityToContexts.getOrDefault(entityId, Set.of()));
                seenContexts.add(targetContext);
                if (seenContexts.size() < 2) {
                    continue;
                }

                String sourceContext = pickSourceContext(seenContexts, targetContext, contextsByKey);
                if (sourceContext.isBlank()) {
                    continue;
                }

                RoleType sourceRole = roleFor(sourceContext, contextsByKey);
                String sourceResponse = findResponseForContext(methodStore, sourceContext, observation.method(), observation.typeName());
                String targetResponse = defaultIfBlank(observation.responseBody(), "");
                String sourceResponseClass = classifyResponse(sourceResponse);
                String targetResponseClass = classifyResponse(targetResponse);

                String methodKey = buildMethodKey(observation.method(), observation.typeName());
                String observedDifference = findMethodDifference(
                        methodDiffEvidence,
                        methodKey,
                        sourceContext,
                        targetContext,
                        sourceResponse,
                        targetResponse
                );

                if (observedDifference.isBlank() && !(targetRole == RoleType.LOW_PRIV && sourceRole == RoleType.ADMIN)) {
                    continue;
                }

                if (observedDifference.isBlank()) {
                    observedDifference = "Method " + observation.method() + ":" + observation.typeName()
                            + " reuses entity '" + entityId + "' across contexts " + seenContexts
                            + "; sourceRole=" + sourceRole.displayName() + " sourceResponse=" + sourceResponseClass
                            + "; targetRole=" + targetRole.displayName() + " targetResponse=" + targetResponseClass + ".";
                }

                String confidence = confidenceFor(targetContext, sourceContext, contextsByKey);
                if ("LOW".equals(confidence)) {
                    continue;
                }

                String exactAttackAction = "Replay " + observation.method() + ":" + observation.typeName()
                        + " while authenticated as target context " + targetContext
                        + " and inject entityId='" + entityId + "' captured from source context " + sourceContext + ".";
                String exploitChain = buildExploitChain(observation, sourceContext, targetContext, entityId, workflowSnapshot);
                if (!exploitChain.isBlank()) {
                    exactAttackAction = exactAttackAction + " " + exploitChain;
                }

                String payload = buildPayloadHttp(observation, entityId);
                String curl = buildCurlCommand(payload);

                AttackSuggestion finding = buildFinding(
                        "BOLA_IDOR",
                        "Authorization / BOLA-IDOR",
                        confidence,
                        observation,
                        sourceContext,
                        targetContext,
                        entityId,
                        observedDifference,
                        exactAttackAction,
                        sourceResponse,
                        targetResponse,
                        payload,
                        curl,
                        "Unauthorized object access and ownership bypass through cross-context identifier replay.",
                        "BOLA/IDOR replay"
                );
                putFinding(out, finding);
            }
        }
    }

    private void runPrivilegeDiffDetector(
            Map<String, List<MethodDiffEvidence>> methodDiffEvidence,
            Map<String, AuthContextStore.SessionView> contextsByKey,
            Map<String, EntityStoreService.ExtractedEntity> entitiesById,
            WorkflowGraphService.WorkflowGraphSnapshot workflowSnapshot,
            Map<String, AttackSuggestion> out
    ) {
        for (Map.Entry<String, List<MethodDiffEvidence>> entry : methodDiffEvidence.entrySet()) {
            String methodKey = entry.getKey();
            String method = methodFromKey(methodKey);
            String typeName = typeFromKey(methodKey);

            for (MethodDiffEvidence evidence : entry.getValue()) {
                if (evidence.sourceContext().equals(evidence.targetContext())) {
                    continue;
                }

                RoleType sourceRole = roleFor(evidence.sourceContext(), contextsByKey);
                RoleType targetRole = roleFor(evidence.targetContext(), contextsByKey);
                if (targetRole == RoleType.ADMIN) {
                    continue; // "Replay as ADMIN" is not a useful attack suggestion
                }
                if (sourceRole == targetRole && sourceRole != RoleType.UNKNOWN) {
                    continue; // Same known privilege level — skip
                }

                String confidence = confidenceFor(evidence.targetContext(), evidence.sourceContext(), contextsByKey);
                if ("LOW".equals(confidence)) {
                    continue;
                }

                AuthContextStore.SessionView targetContext = contextsByKey.get(evidence.targetContext());
                if (targetContext == null) {
                    continue;
                }

                String entityId = extractEntityIdFromResponse(evidence.sourceResponse(), entitiesById);
                if (entityId.isBlank()) {
                    entityId = extractEntityIdFromResponse(evidence.targetResponse(), entitiesById);
                }

                String fallbackRequest = buildFallbackBody(
                        method,
                        typeName,
                        targetContext.database(),
                        targetContext.sessionId(),
                        targetContext.userName(),
                        entityId
                );

                RequestObservation pseudo = new RequestObservation(
                        methodKey + "|" + evidence.targetContext(),
                        "",
                        Instant.now(),
                    defaultIfBlank(targetContext.host(), DEFAULT_TARGET_HOST),
                        method,
                        method,
                        typeName,
                        evidence.targetContext(),
                        defaultIfBlank(targetContext.sessionId(), ""),
                        defaultIfBlank(targetContext.database(), "unknown-db"),
                        defaultIfBlank(targetContext.userName(), "unknown-user"),
                        entityId.isBlank() ? List.of() : List.of(entityId),
                        false,
                        false,
                        List.of(),
                        List.of(),
                        false,
                        false,
                        "named",
                        false,
                        fallbackRequest,
                        defaultIfBlank(evidence.targetResponse(), ""),
                        null,
                        false
                );

                String payload = buildPayloadHttp(pseudo, entityId);
                String curl = buildCurlCommand(payload);
                String exactAttackAction = "Replay the same request fingerprint for " + method + ":" + typeName
                        + " from source context " + evidence.sourceContext()
                        + " into target context " + evidence.targetContext()
                        + " and compare response structure and fields.";
                String exploitChain = buildExploitChain(pseudo, evidence.sourceContext(), evidence.targetContext(), entityId, workflowSnapshot);
                if (!exploitChain.isBlank()) {
                    exactAttackAction = exactAttackAction + " " + exploitChain;
                }

                AttackSuggestion finding = buildFinding(
                        "PRIVILEGE_DIFF",
                        "Privilege Differential",
                        confidence,
                        pseudo,
                        evidence.sourceContext(),
                        evidence.targetContext(),
                        entityId,
                        defaultIfBlank(evidence.reason(), "Comparable request fingerprint produces divergent responses."),
                        exactAttackAction,
                        defaultIfBlank(evidence.sourceResponse(), ""),
                        defaultIfBlank(evidence.targetResponse(), ""),
                        payload,
                        curl,
                        "Privilege boundary weakness through response-level authorization drift.",
                        "Privilege differential"
                );
                putFinding(out, finding);
            }
        }
    }

    private void runMulticallDetector(
            List<RequestObservation> observations,
            Map<String, AuthContextStore.SessionView> contextsByKey,
            List<JsonRpcIndex.MethodStoreView> methodStore,
            Map<String, List<MethodDiffEvidence>> methodDiffEvidence,
            Map<String, Set<String>> entityToContexts,
            Map<String, Set<String>> methodToContexts,
            WorkflowGraphService.WorkflowGraphSnapshot workflowSnapshot,
            Map<String, AttackSuggestion> out
    ) {
        for (RequestObservation observation : observations) {
            if (!observation.multiCall()) {
                continue;
            }

            List<String> reasons = new ArrayList<>();
            if (observation.emptySearchInSubCall()) {
                reasons.add("ExecuteMultiCall contains sub-call with search:{} allowing broad enumeration behavior.");
            }
            if (observation.hasWriteSubCall()) {
                reasons.add("ExecuteMultiCall contains write-like sub-call mixed with read access in one chain.");
            }
            if (observation.hasMixedPrivilegeChain()) {
                reasons.add("ExecuteMultiCall chain mixes read and write semantics that can hide unauthorized state changes.");
            }
            if (!observation.subCallMethods().isEmpty()) {
                reasons.add("ExecuteMultiCall sub-call breakdown: " + observation.subCallMethods());
            }

            boolean adminOnlySubType = hasAdminOnlySubType(
                    observation.subCallTypeNames(),
                    methodStore,
                    contextsByKey,
                    observation.contextKey()
            );
            if (adminOnlySubType) {
                reasons.add("One or more sub-call type names are only seen in ADMIN contexts.");
            }

            if (reasons.isEmpty()) {
                continue;
            }

            String targetContext = defaultIfBlank(observation.contextKey(), "");
            if (targetContext.isBlank()) {
                continue;
            }

            String sourceContext = pickSourceContextForSubCalls(
                    observation.subCallMethods(),
                    methodToContexts,
                    targetContext,
                    contextsByKey
            );
            if (sourceContext.isBlank()) {
                sourceContext = pickSourceContext(
                        methodToContexts.getOrDefault(buildMethodKey(observation.method(), observation.typeName()), Set.of()),
                        targetContext,
                        contextsByKey
                );
            }

            if (sourceContext.isBlank() && reasons.size() < 2) {
                continue;
            }

            RoleType targetRole = roleFor(targetContext, contextsByKey);
            String confidence;
            if (targetRole == RoleType.LOW_PRIV && (observation.hasWriteSubCall() || adminOnlySubType)) {
                confidence = "HIGH";
            } else if (targetRole == RoleType.LOW_PRIV || adminOnlySubType || observation.hasMixedPrivilegeChain()) {
                confidence = "MEDIUM";
            } else {
                confidence = "LOW";
            }
            if ("LOW".equals(confidence)) {
                continue;
            }

            String sourceResponse = sourceContext.isBlank()
                    ? ""
                    : findResponseForContext(methodStore, sourceContext, observation.method(), observation.typeName());
            String targetResponse = defaultIfBlank(observation.responseBody(), "");
            String sourceResponseClass = classifyResponse(sourceResponse);
            String targetResponseClass = classifyResponse(targetResponse);

            String methodKey = buildMethodKey(observation.method(), observation.typeName());
            String diff = findMethodDifference(
                    methodDiffEvidence,
                    methodKey,
                    sourceContext,
                    targetContext,
                    sourceResponse,
                    targetResponse
            );

            String observedDifference = String.join(" ", reasons);
            if (!diff.isBlank()) {
                observedDifference = observedDifference + " Structural diff: " + diff;
            }
            observedDifference = observedDifference
                    + " Source response class=" + sourceResponseClass
                    + ", target response class=" + targetResponseClass + ".";

            String entityId = observation.requestEntityIds().isEmpty() ? "" : observation.requestEntityIds().get(0);
            if (entityId.isBlank() && !observation.subCallTypeNames().isEmpty()) {
                String synthetic = observation.subCallTypeNames().get(0);
                entityId = synthetic == null ? "" : synthetic;
            }

            if (!entityId.isBlank() && !observation.hasWriteSubCall() && !observation.hasMixedPrivilegeChain()) {
                Set<String> contexts = entityToContexts.getOrDefault(entityId, Set.of());
                if (contexts.size() < 2 && sourceContext.isBlank()) {
                    continue;
                }
            }

            String exactAttackAction = "Replay ExecuteMultiCall from target context " + targetContext
                    + " with sub-call methods " + observation.subCallMethods()
                    + " and verify whether entities or fields associated with source context "
                    + defaultIfBlank(sourceContext, "(inferred privileged path)") + " are returned or modified.";
            String exploitChain = buildExploitChain(observation, defaultIfBlank(sourceContext, targetContext), targetContext, entityId, workflowSnapshot);
            if (!exploitChain.isBlank()) {
                exactAttackAction = exactAttackAction + " " + exploitChain;
            }

            String payload = buildPayloadHttp(observation, entityId);
            String curl = buildCurlCommand(payload);

            AttackSuggestion finding = buildFinding(
                    "MULTICALL_CHAIN",
                    "Batch / ExecuteMultiCall",
                    confidence,
                    observation,
                    defaultIfBlank(sourceContext, targetContext),
                    targetContext,
                    entityId,
                    observedDifference,
                    exactAttackAction,
                    sourceResponse,
                    targetResponse,
                    payload,
                    curl,
                    "Hidden write + read chain can leak privileged objects or mutate unauthorized state in a single request.",
                    "ExecuteMultiCall abuse"
            );
            putFinding(out, finding);
        }
    }

    private void runCrossTenantDetector(
            List<RequestObservation> observations,
            Map<String, EntityStoreService.ExtractedEntity> entitiesById,
            Map<String, AuthContextStore.SessionView> contextsByKey,
            List<JsonRpcIndex.MethodStoreView> methodStore,
            Map<String, List<MethodDiffEvidence>> methodDiffEvidence,
            Map<String, Set<String>> entityToContexts,
            WorkflowGraphService.WorkflowGraphSnapshot workflowSnapshot,
            Map<String, AttackSuggestion> out
    ) {
        for (RequestObservation observation : observations) {
            if (isSuppressedMethod(observation.method()) || observation.requestEntityIds().isEmpty()) {
                continue;
            }

            String targetContext = defaultIfBlank(observation.contextKey(), "");
            if (targetContext.isBlank()) {
                continue;
            }

            for (String entityId : observation.requestEntityIds()) {
                EntityStoreService.ExtractedEntity entity = entitiesById.get(entityId);
                if (entity == null) {
                    continue;
                }

                String sourceDatabase = defaultIfBlank(entity.database(), "");
                String targetDatabase = defaultIfBlank(observation.database(), "");
                if (sourceDatabase.isBlank() || targetDatabase.isBlank() || sourceDatabase.equalsIgnoreCase(targetDatabase)) {
                    continue;
                }

                Set<String> contexts = new LinkedHashSet<>(entityToContexts.getOrDefault(entityId, Set.of()));
                contexts.add(targetContext);
                if (contexts.size() < 2) {
                    continue;
                }

                String sourceContext = defaultIfBlank(entity.contextKey(), "");
                if (sourceContext.isBlank() || sourceContext.equals(targetContext)) {
                    sourceContext = pickSourceContext(contexts, targetContext, contextsByKey);
                }
                if (sourceContext.isBlank()) {
                    continue;
                }

                String sourceResponse = findResponseForContext(methodStore, sourceContext, observation.method(), observation.typeName());
                String targetResponse = defaultIfBlank(observation.responseBody(), "");
                String sourceResponseClass = classifyResponse(sourceResponse);
                String targetResponseClass = classifyResponse(targetResponse);
                String methodKey = buildMethodKey(observation.method(), observation.typeName());
                String diff = findMethodDifference(
                        methodDiffEvidence,
                        methodKey,
                        sourceContext,
                        targetContext,
                        sourceResponse,
                        targetResponse
                );

                String observedDifference = "Entity " + entityId + " originally observed in database '" + sourceDatabase
                        + "' but replayed in database '" + targetDatabase + "'.";
                if (!diff.isBlank()) {
                    observedDifference = observedDifference + " Structural diff: " + diff;
                }
                observedDifference = observedDifference
                    + " Source response class=" + sourceResponseClass
                    + ", target response class=" + targetResponseClass + ".";

                String confidence = confidenceFor(targetContext, sourceContext, contextsByKey);
                if ("LOW".equals(confidence) && diff.isBlank()) {
                    continue;
                }

                String exactAttackAction = "Use entityId='" + entityId + "' from source database '" + sourceDatabase
                        + "' while authenticated to target database '" + targetDatabase
                        + "' under context " + targetContext + " and validate cross-tenant object retrieval.";
                String exploitChain = buildExploitChain(observation, sourceContext, targetContext, entityId, workflowSnapshot);
                if (!exploitChain.isBlank()) {
                    exactAttackAction = exactAttackAction + " " + exploitChain;
                }

                String payload = buildPayloadHttp(observation, entityId);
                String curl = buildCurlCommand(payload);

                AttackSuggestion finding = buildFinding(
                        "CROSS_TENANT",
                        "Cross-Tenant / Cross-Database",
                        confidence,
                        observation,
                        sourceContext,
                        targetContext,
                        entityId,
                        observedDifference,
                        exactAttackAction,
                        sourceResponse,
                        targetResponse,
                        payload,
                        curl,
                        "Tenant isolation failure enables data access across organization boundaries.",
                        "Cross-tenant replay"
                );
                putFinding(out, finding);
            }
        }
    }

    // ── NEW DETECTOR: Search Enumeration ──────────────────────────────────────
    // Fires on standalone read methods (Get/Find/List/Search) with empty or
    // no-ID-constraint search parameters — catches patterns like
    // Get:DeviceStatusInfo {search:{isDeviceCommunicating:true}} that the
    // entity-based BOLA detector misses because there's no entity ID in the request.
    private void runSearchEnumerationDetector(
            List<RequestObservation> observations,
            Map<String, AuthContextStore.SessionView> contextsByKey,
            List<JsonRpcIndex.MethodStoreView> methodStore,
            Map<String, Set<String>> methodToContexts,
            WorkflowGraphService.WorkflowGraphSnapshot workflowSnapshot,
            Map<String, AttackSuggestion> out
    ) {
        for (RequestObservation observation : observations) {
            if (!observation.broadSearch()) {
                continue;
            }
            if (isSuppressedMethod(observation.method())) {
                continue;
            }

            String targetContext = defaultIfBlank(observation.contextKey(), "");
            if (targetContext.isBlank()) {
                continue;
            }

            // Skip if response is an error or permission denial — server is protecting correctly
            String responseClass = classifyResponse(observation.responseBody());
            if ("permission_error".equals(responseClass) || "error".equals(responseClass)
                    || "empty_result".equals(responseClass) || "empty".equals(responseClass)) {
                continue;
            }

            RoleType targetRole = roleFor(targetContext, contextsByKey);

            String methodKey = buildMethodKey(observation.method(), observation.typeName());
            Set<String> contexts = methodToContexts.getOrDefault(methodKey, Set.of());
            String sourceContext = pickSourceContext(contexts, targetContext, contextsByKey);

            String confidence;
            if (targetRole == RoleType.LOW_PRIV) {
                confidence = "HIGH";
            } else if (!sourceContext.isBlank()) {
                confidence = "MEDIUM";
            } else {
                confidence = "MEDIUM";
            }

            String observedDifference = "Method " + observation.method() + ":" + observation.typeName()
                    + " uses broad/unrestricted search parameters (no entity-ID constraint)."
                    + " Response class=" + responseClass + ".";

            if (!sourceContext.isBlank()) {
                String sourceResponse = findResponseForContext(methodStore, sourceContext, observation.method(), observation.typeName());
                String sourceResponseClass = classifyResponse(sourceResponse);
                if (!"empty".equals(sourceResponseClass)) {
                    observedDifference += " Source(" + roleFor(sourceContext, contextsByKey).displayName()
                            + ") response class=" + sourceResponseClass + ".";
                }
            }

            String exactAttackAction = "Send " + observation.method() + ":" + observation.typeName()
                    + " with empty or broad search parameters as LOW_PRIV user."
                    + " If response contains objects, verify whether each belongs to the authenticated user."
                    + " Absence of ownership filtering indicates BOLA.";
            String exploitChain = buildExploitChain(observation, defaultIfBlank(sourceContext, targetContext),
                    targetContext, "", workflowSnapshot);
            if (!exploitChain.isBlank()) {
                exactAttackAction = exactAttackAction + " " + exploitChain;
            }

            String payload = buildPayloadHttp(observation, "");
            String curl = buildCurlCommand(payload);

            String sourceResponse = sourceContext.isBlank() ? ""
                    : findResponseForContext(methodStore, sourceContext, observation.method(), observation.typeName());

            AttackSuggestion finding = buildFinding(
                    "SEARCH_ENUM",
                    "Search Enumeration / Mass Object Access",
                    confidence,
                    observation,
                    defaultIfBlank(sourceContext, targetContext),
                    targetContext,
                    "",
                    observedDifference,
                    exactAttackAction,
                    sourceResponse,
                    defaultIfBlank(observation.responseBody(), ""),
                    payload,
                    curl,
                    "Broad search without ownership filter enables enumeration of objects belonging to other users/tenants.",
                    "Search enumeration"
            );
            putFinding(out, finding);
        }
    }

    // ── NEW DETECTOR: Method-Level Access Control ─────────────────────────────
    // Fires when a security-sensitive method (name contains admin, security,
    // billing, permission, token, export, etc.) has been called by both ADMIN
    // and LOW_PRIV contexts, and the LOW_PRIV response was NOT a permission error.
    // Catches GetReportSecurityIdentifiers, ExportReport, etc.
    private void runMethodAccessDetector(
            List<JsonRpcIndex.MethodStoreView> methodStore,
            Map<String, AuthContextStore.SessionView> contextsByKey,
            WorkflowGraphService.WorkflowGraphSnapshot workflowSnapshot,
            Map<String, AttackSuggestion> out
    ) {
        List<String> sensitiveTerms = List.of(
                "admin", "security", "export", "billing", "permission",
                "token", "grant", "assign", "reportschedule", "systemsetting",
                "clearance", "certificate", "credential"
        );

        for (JsonRpcIndex.MethodStoreView view : methodStore) {
            if (isSuppressedMethod(view.method())) {
                continue;
            }

            String methodLower = view.method().toLowerCase(Locale.ROOT);
            String typeNameLower = view.typeName().toLowerCase(Locale.ROOT);
            boolean sensitive = false;
            for (String term : sensitiveTerms) {
                if (methodLower.contains(term) || typeNameLower.contains(term)) {
                    sensitive = true;
                    break;
                }
            }
            if (!sensitive) {
                continue;
            }

            List<String> sessions = view.seenInSessions();
            if (sessions.size() < 2) {
                continue;
            }

            String adminContext = "";
            String lowPrivContext = "";
            for (String session : sessions) {
                RoleType role = roleFor(session, contextsByKey);
                if (role == RoleType.ADMIN && adminContext.isBlank()) {
                    adminContext = session;
                } else if (role == RoleType.LOW_PRIV && lowPrivContext.isBlank()) {
                    lowPrivContext = session;
                }
            }

            if (adminContext.isBlank() || lowPrivContext.isBlank()) {
                continue;
            }

            // Get responses for both contexts
            String adminResponse = "";
            String lowPrivResponse = "";
            for (JsonRpcIndex.SessionSnapshot snap : view.sessionSnapshots()) {
                if (adminContext.equals(snap.sessionId())) {
                    adminResponse = defaultIfBlank(snap.lastResponse(), "");
                }
                if (lowPrivContext.equals(snap.sessionId())) {
                    lowPrivResponse = defaultIfBlank(snap.lastResponse(), "");
                }
            }

            String lowPrivResponseClass = classifyResponse(lowPrivResponse);
            // If LOW_PRIV got a definitive permission error, server is protecting correctly
            if ("permission_error".equals(lowPrivResponseClass)) {
                continue;
            }

            String method = view.method();
            String typeName = defaultIfBlank(view.typeName(), "Unknown");

            AuthContextStore.SessionView lowPrivView = contextsByKey.get(lowPrivContext);
            if (lowPrivView == null) {
                continue;
            }

            String observedDifference = "Security-sensitive method " + method + ":" + typeName
                    + " is accessible to LOW_PRIV context " + lowPrivContext
                    + ". LOW_PRIV response class=" + lowPrivResponseClass + ".";

            String fallbackRequest = buildFallbackBody(
                    method, typeName,
                    defaultIfBlank(lowPrivView.database(), ""),
                    defaultIfBlank(lowPrivView.sessionId(), ""),
                    defaultIfBlank(lowPrivView.userName(), ""), ""
            );

            RequestObservation pseudo = new RequestObservation(
                    method + ":" + typeName + "|method_access|" + lowPrivContext,
                    "", Instant.now(),
                    defaultIfBlank(lowPrivView.host(), DEFAULT_TARGET_HOST),
                    method, method, typeName, lowPrivContext,
                    defaultIfBlank(lowPrivView.sessionId(), ""),
                    defaultIfBlank(lowPrivView.database(), "unknown-db"),
                    defaultIfBlank(lowPrivView.userName(), "unknown-user"),
                    List.of(), false, false, List.of(), List.of(), false, false,
                    "named", false, fallbackRequest,
                    defaultIfBlank(lowPrivResponse, ""), null, false
            );

            String payload = buildPayloadHttp(pseudo, "");
            String curl = buildCurlCommand(payload);

            AttackSuggestion finding = buildFinding(
                    "METHOD_ACCESS",
                    "Sensitive Method Access",
                    "HIGH",
                    pseudo,
                    adminContext,
                    lowPrivContext,
                    "",
                    observedDifference,
                    "Call " + method + ":" + typeName + " as LOW_PRIV and check if response contains admin-only data.",
                    adminResponse,
                    lowPrivResponse,
                    payload,
                    curl,
                    "LOW_PRIV user can invoke security-sensitive method that requires elevated privileges.",
                    "Method-level access control bypass"
            );
            putFinding(out, finding);
        }
    }

    private void putFinding(Map<String, AttackSuggestion> out, AttackSuggestion finding) {
        // Dedup by type+session+entity+method — omit attackPath to avoid duplicate explosion
        // when the same BOLA pattern is found from multiple source contexts.
        String key = finding.findingType() + "|" + finding.sessionId() + "|" + finding.entityId() + "|"
                + finding.method() + "|" + finding.typeName();
        out.putIfAbsent(key, finding);
    }

    private AttackSuggestion buildFinding(
            String findingType,
            String category,
            String confidence,
            RequestObservation observation,
            String sourceContext,
            String targetContext,
            String entityId,
            String observedDifference,
            String exactAttackAction,
            String adminResponse,
            String lowPrivResponse,
            String payload,
            String curl,
            String impact,
            String pathSegment
    ) {
        int confidenceScore = switch (confidence) {
            case "HIGH" -> 90;
            case "MEDIUM" -> 75;
            default -> 60;
        };
        int effectiveness = switch (confidence) {
            case "HIGH" -> 88;
            case "MEDIUM" -> 74;
            default -> 60;
        };
        int priority = calculatePriorityScore(findingType, observation, confidenceScore, entityId);
        SecurityFinding.RiskLevel risk = SecurityFinding.RiskLevel.fromScore(priority);
        AttackSuggestion.Confidence confidenceEnum = switch (confidence) {
            case "HIGH" -> AttackSuggestion.Confidence.HIGH;
            case "MEDIUM" -> AttackSuggestion.Confidence.MEDIUM;
            default -> AttackSuggestion.Confidence.LOW;
        };

        String method = defaultIfBlank(observation.method(), "Get");
        String typeName = defaultIfBlank(observation.typeName(), "Unknown");
        RoleType sourceRole = roleFor(sourceContext, contextsByContextFromSessionId(sourceContext, targetContext, observation.contextKey()));
        RoleType targetRole = roleFor(targetContext, contextsByContextFromSessionId(sourceContext, targetContext, observation.contextKey()));
        String title = findingType + " - " + method + ":" + typeName;
        String expected = "{ \"result\": [], \"error\": \"InvalidUserException\" }";
        String vulnerable = "result[] contains object data";

        String attackPath = method + ":" + typeName + " -> "
                + defaultIfBlank(sourceContext, "(unknown-source)")
                + " => "
                + defaultIfBlank(targetContext, "(unknown-target)")
                + " -> " + pathSegment;

        String observedBehavior = "Observed behavior:\n"
                + "- Source context: " + defaultIfBlank(sourceContext, "(unknown)") + "\n"
                + "- Target context: " + defaultIfBlank(targetContext, "(unknown)") + "\n"
            + "- Roles: source=" + sourceRole.displayName() + ", target=" + targetRole.displayName() + "\n"
            + "- Priority: " + risk.displayName().toUpperCase(Locale.ROOT) + "\n"
                + "- Entity used: " + defaultIfBlank(entityId, "(none)") + "\n"
                + "- Difference: " + defaultIfBlank(observedDifference, "No direct structural diff; entity/context reuse indicates exploitable path.");

        String whyExploitable = "Why this is exploitable:\n"
                + "- Same business method can be reached from two contexts with divergent behavior.\n"
                + "- Replayed identifiers/context state can drive object access or privilege boundaries incorrectly.\n"
                + "- This path is evidence-backed by captured traffic correlations.";

        String evidence = "sourceContext=" + defaultIfBlank(sourceContext, "")
                + ", targetContext=" + defaultIfBlank(targetContext, "")
                + ", database=" + observation.database()
                + ", userName=" + observation.userName()
                + ", entityId=" + defaultIfBlank(entityId, "(none)")
                + "\nobservedDifference=" + defaultIfBlank(observedDifference, "(none)")
                + "\nexactAttackAction=" + defaultIfBlank(exactAttackAction,
                "Replay captured request in target context with source entity identifiers.");

        String comparison = buildComparisonBlock(adminResponse, lowPrivResponse);
        if (!comparison.isBlank()) {
            evidence = evidence + "\n" + comparison;
        }

        String bugcrowd = buildBugcrowdMarkdown(
                title,
                observation,
                sourceContext,
                targetContext,
                entityId,
                observedDifference,
                exactAttackAction,
                adminResponse,
                lowPrivResponse,
                impact,
                curl
        );

        String exploitActionPayload = "Exact attack to try:\n"
                + defaultIfBlank(exactAttackAction,
                "Replay the same request in target context using source entity values.")
                + "\n\n" + payload;

        return new AttackSuggestion(
                suggestionId(findingType + "|" + defaultIfBlank(sourceContext, "") + "|" + defaultIfBlank(targetContext, "")
                        + "|" + method + "|" + typeName + "|" + entityId),
                category,
                title,
                priority,
                risk,
                confidenceEnum,
                AttackSuggestion.Verdict.LIKELY_VULNERABILITY,
                method,
                attackPath,
                observedBehavior,
                whyExploitable,
                exploitActionPayload,
                expected,
                vulnerable,
                impact,
                evidence,
                defaultIfBlank(observation.host(), DEFAULT_TARGET_HOST),
                confidenceScore,
                effectiveness,
                rawRequestOnly(payload),
                findingType,
                confidence,
                defaultIfBlank(targetContext, observation.contextKey()),
                defaultIfBlank(entityId, ""),
                method,
                typeName,
                defaultIfBlank(adminResponse, ""),
                defaultIfBlank(lowPrivResponse, ""),
                payload,
                bugcrowd
        );
    }

    private Map<String, AuthContextStore.SessionView> contextsByContextFromSessionId(String sourceContext, String targetContext, String fallbackContext) {
        Map<String, AuthContextStore.SessionView> contexts = new HashMap<>();
        for (AuthContextStore.SessionView session : authContextStore.snapshotSessions()) {
            if (session == null || session.contextKey() == null || session.contextKey().isBlank()) {
                continue;
            }
            if (session.contextKey().equals(sourceContext)
                    || session.contextKey().equals(targetContext)
                    || session.contextKey().equals(fallbackContext)) {
                contexts.put(session.contextKey(), session);
            }
        }
        return contexts;
    }

    private int calculatePriorityScore(String findingType, RequestObservation observation, int confidenceScore, String entityId) {
        int score = confidenceScore;
        boolean writeLike = isWriteLikeMethod(observation.method()) || observation.hasWriteSubCall();
        boolean escalationLike = "PRIVILEGE_DIFF".equals(findingType) || observation.hasMixedPrivilegeChain();
        boolean idorLike = "BOLA_IDOR".equals(findingType) || "CROSS_TENANT".equals(findingType);
        boolean sensitiveEntity = entityId != null && !entityId.isBlank();

        if (writeLike || escalationLike) {
            score = Math.max(score, 85);
        }
        if (idorLike && sensitiveEntity) {
            score = Math.max(score, 68);
        }
        if (!writeLike && !escalationLike && idorLike) {
            score = Math.max(score, 40);
        }
        return Math.min(score, 100);
    }

    private String buildExploitChain(
            RequestObservation observation,
            String sourceContext,
            String targetContext,
            String entityId,
            WorkflowGraphService.WorkflowGraphSnapshot workflowSnapshot
    ) {
        if (workflowSnapshot == null) {
            return "";
        }

        String method = defaultIfBlank(observation.method(), "");
        if (method.isBlank()) {
            return "";
        }

        for (WorkflowGraphService.ChainView chain : workflowSnapshot.chains()) {
            if (chain == null || chain.methodSequence() == null || chain.methodSequence().isEmpty()) {
                continue;
            }
            if (!chain.methodSequence().contains(method)) {
                continue;
            }

            List<String> steps = chain.methodSequence();
            if (steps.size() < 2) {
                continue;
            }

            StringBuilder builder = new StringBuilder();
            builder.append("Exploit chain: ")
                    .append("step 1 extract entity '")
                    .append(defaultIfBlank(entityId, "id"))
                    .append("' from ")
                    .append(steps.get(0))
                    .append(" under ")
                    .append(defaultIfBlank(sourceContext, "source context"))
                    .append("; step 2 replay via ")
                    .append(steps.get(Math.min(1, steps.size() - 1)))
                    .append(" under ")
                    .append(defaultIfBlank(targetContext, "target context"))
                    .append(".");
            return builder.toString();
        }

        if (isWriteLikeMethod(method) || observation.hasWriteSubCall()) {
            return "Exploit chain: step 1 extract reusable ID from a privileged Get response; step 2 replay it into "
                    + method + " to test unauthorized write behavior.";
        }
        return "";
    }

    private String buildBugcrowdMarkdown(
            String summary,
            RequestObservation observation,
            String sourceContext,
            String targetContext,
            String entityId,
            String observedDifference,
            String exactAttackAction,
            String adminResponse,
            String lowPrivResponse,
            String impact,
            String curl
    ) {
        String adminSession = extractSessionIdFromResponseContext(observation, adminResponse);
        String lowResponsePreview = truncate(defaultIfBlank(lowPrivResponse, ""), 300);
        return "## Summary\n"
                + summary + "\n\n"
                + "## Observed behavior\n"
                + "- Source context: " + defaultIfBlank(sourceContext, "unknown") + "\n"
                + "- Target context: " + defaultIfBlank(targetContext, "unknown") + "\n"
                + "- Entity used: " + defaultIfBlank(entityId, "unknown") + "\n"
                + "- Difference: " + defaultIfBlank(observedDifference, "No direct structural diff recorded") + "\n\n"
                + "## Why this is exploitable\n"
                + "The same functional path can be replayed across contexts with identifiers learned from another context, "
                + "causing ownership/privilege boundaries to weaken.\n\n"
                + "## Exact attack to try\n"
                + "1. " + defaultIfBlank(exactAttackAction,
                "Replay captured request in target context using source entity IDs.") + "\n"
                + "2. Validate whether unauthorized object data is returned.\n\n"
                + "## Steps to Reproduce\n"
                + "1. Authenticate as source context (session/context: " + defaultIfBlank(adminSession, "unknown") + ")\n"
                + "2. Capture response for " + observation.method() + " returning entity "
                + defaultIfBlank(entityId, "unknown") + "\n"
                + "3. Authenticate as target user (context: " + defaultIfBlank(targetContext, observation.contextKey()) + ")\n"
                + "4. Replay request with target credentials using entity ID from step 2\n"
                + "5. Observe: " + lowResponsePreview + "\n\n"
                + "## Impact\n"
                + impact + "\n\n"
                + "## Proof of Concept\n"
                + "```bash\n"
                + curl + "\n"
                + "```\n\n"
                + "## Expected vs Actual\n"
                + "Expected: access denied / empty result\n"
                + "Actual: " + defaultIfBlank(lowPrivResponse, "") + "\n";
    }

    private String extractSessionIdFromResponseContext(RequestObservation observation, String adminResponse) {
        if (adminResponse == null || adminResponse.isBlank()) {
            return "";
        }
        for (RequestObservation candidate : observations.values()) {
            if (!candidate.method().equals(observation.method())) {
                continue;
            }
            if (Objects.equals(candidate.responseBody(), adminResponse)) {
                return defaultIfBlank(candidate.contextKey(), candidate.sessionId());
            }
        }
        return "";
    }

    private String rawRequestOnly(String payload) {
        if (payload == null || payload.isBlank()) {
            return "";
        }
        int marker = payload.indexOf("\nExpected secure:");
        if (marker < 0) {
            return payload;
        }
        return payload.substring(0, marker).trim();
    }

    private String buildPayloadHttp(RequestObservation observation, String entityId) {
        String requestBody = mutateRequestBody(
                observation.requestBody(),
                observation.method(),
                observation.typeName(),
                observation.database(),
                observation.sessionId(),
                observation.userName(),
                entityId
        );

        return "POST /apiv1 HTTP/2\n"
            + "Host: " + defaultIfBlank(observation.host(), DEFAULT_TARGET_HOST) + "\n"
                + "Content-Type: text/plain;charset=UTF-8\n\n"
                + requestBody
                + "\n\nExpected secure:  { \"result\": [], \"error\": \"InvalidUserException\" }"
                + "\nVulnerable if:    result[] contains object data";
    }

    private String mutateRequestBody(
            String originalBody,
            String method,
            String typeName,
            String database,
            String sessionId,
            String userName,
            String entityId
    ) {
        JsonNode root = parseJson(originalBody);
        if (root == null) {
            return buildFallbackBody(method, typeName, database, sessionId, userName, entityId);
        }

        JsonNode call = root;
        if (root.isArray() && root.size() > 0 && root.get(0).isObject()) {
            call = root.get(0);
        }

        if (!(call instanceof ObjectNode callObject)) {
            return buildFallbackBody(method, typeName, database, sessionId, userName, entityId);
        }

        if (!defaultIfBlank(method, "").isBlank()) {
            callObject.put("method", defaultIfBlank(method, "Get"));
        }

        JsonNode paramsNode = callObject.get("params");
        ObjectNode paramsObject;
        if (paramsNode instanceof ObjectNode node) {
            paramsObject = node;
        } else {
            paramsObject = objectMapper.createObjectNode();
            callObject.set("params", paramsObject);
        }

        if (!defaultIfBlank(typeName, "").isBlank()) {
            paramsObject.put("typeName", typeName);
        }

        ObjectNode credentialsNode;
        JsonNode existingCredentials = paramsObject.get("credentials");
        if (existingCredentials instanceof ObjectNode node) {
            credentialsNode = node;
        } else {
            credentialsNode = objectMapper.createObjectNode();
            paramsObject.set("credentials", credentialsNode);
        }

        credentialsNode.put("database", defaultIfBlank(database, ""));
        credentialsNode.put("sessionId", defaultIfBlank(sessionId, ""));
        credentialsNode.put("userName", defaultIfBlank(userName, ""));

        if (entityId != null && !entityId.isBlank()) {
            applyEntityIdMutation(paramsObject, entityId);
        }

        try {
            return objectMapper.writeValueAsString(root);
        } catch (Exception ignored) {
            return buildFallbackBody(method, typeName, database, sessionId, userName, entityId);
        }
    }

    private String buildFallbackBody(
            String method,
            String typeName,
            String database,
            String sessionId,
            String userName,
            String entityId
    ) {
        ObjectNode root = objectMapper.createObjectNode();
        root.put("method", defaultIfBlank(method, "Get"));

        ObjectNode params = objectMapper.createObjectNode();
        params.put("typeName", defaultIfBlank(typeName, "User"));

        ObjectNode search = objectMapper.createObjectNode();
        search.put("id", defaultIfBlank(entityId, ""));
        params.set("search", search);

        ObjectNode credentials = objectMapper.createObjectNode();
        credentials.put("database", defaultIfBlank(database, ""));
        credentials.put("sessionId", defaultIfBlank(sessionId, ""));
        credentials.put("userName", defaultIfBlank(userName, ""));
        params.set("credentials", credentials);

        root.set("params", params);
        try {
            return objectMapper.writeValueAsString(root);
        } catch (Exception ignored) {
            return "{\"method\":\"Get\",\"params\":{\"typeName\":\"User\",\"search\":{\"id\":\"\"},\"credentials\":{\"database\":\"\",\"sessionId\":\"\",\"userName\":\"\"}}}";
        }
    }

    private void applyEntityIdMutation(ObjectNode paramsObject, String entityId) {
        JsonNode searchNode = paramsObject.get("search");
        if (searchNode instanceof ObjectNode searchObject) {
            if (searchObject.has("id")) {
                searchObject.put("id", entityId);
                return;
            }

            for (String field : List.of("deviceId", "userId", "groupId", "reportId", "entityId")) {
                if (searchObject.has(field)) {
                    searchObject.put(field, entityId);
                    return;
                }
            }

            searchObject.put("id", entityId);
            return;
        }

        ObjectNode createdSearch = objectMapper.createObjectNode();
        createdSearch.put("id", entityId);
        paramsObject.set("search", createdSearch);
    }

    private String buildCurlCommand(AttackSuggestion suggestion) {
        return buildCurlCommand(suggestion.payload());
    }

    private String buildCurlCommand(String payload) {
        String raw = rawRequestOnly(payload);
        String host = defaultIfBlank(extractHeader(raw, "Host"), DEFAULT_TARGET_HOST);
        String path = extractRequestPath(raw);
        int bodyIndex = raw.indexOf("\n\n");
        String body = bodyIndex < 0 ? "{}" : raw.substring(bodyIndex + 2).trim();
        String compact = body.replace("\r", "").replace("\n", " ").replace("  ", " ").trim();
        return "curl -X POST 'https://" + host + path + "' "
                + "-H 'Content-Type: text/plain;charset=UTF-8' "
                + "-d '" + compact.replace("'", "'\\''") + "'";
    }

    private String extractHeader(String rawRequest, String headerName) {
        if (rawRequest == null || rawRequest.isBlank() || headerName == null || headerName.isBlank()) {
            return "";
        }
        String prefix = headerName.toLowerCase(Locale.ROOT) + ":";
        for (String line : rawRequest.split("\\r?\\n")) {
            if (line == null || line.isBlank()) {
                break;
            }
            String lowered = line.toLowerCase(Locale.ROOT);
            if (!lowered.startsWith(prefix)) {
                continue;
            }
            String value = line.substring(line.indexOf(':') + 1).trim();
            int colon = value.indexOf(':');
            if (colon > 0 && value.indexOf(']') < 0) {
                return value.substring(0, colon);
            }
            return value;
        }
        return "";
    }

    private String extractRequestPath(String rawRequest) {
        if (rawRequest == null || rawRequest.isBlank()) {
            return DEFAULT_TARGET_PATH;
        }
        String[] lines = rawRequest.split("\\r?\\n", 2);
        if (lines.length == 0 || lines[0].isBlank()) {
            return DEFAULT_TARGET_PATH;
        }
        String[] parts = lines[0].trim().split("\\s+");
        if (parts.length < 2 || parts[1].isBlank()) {
            return DEFAULT_TARGET_PATH;
        }
        return parts[1].startsWith("/") ? parts[1] : "/" + parts[1];
    }

    private String findResponseForContext(
            List<JsonRpcIndex.MethodStoreView> methodStore,
            String contextKey,
            String method,
            String typeName
    ) {
        if (contextKey == null || contextKey.isBlank()) {
            return "";
        }

        String key = buildMethodKey(method, typeName);
        for (JsonRpcIndex.MethodStoreView view : methodStore) {
            if (!view.key().equals(key)) {
                continue;
            }
            for (JsonRpcIndex.SessionSnapshot snapshot : view.sessionSnapshots()) {
                if (contextKey.equals(snapshot.sessionId())) {
                    return defaultIfBlank(snapshot.lastResponse(), "");
                }
            }
        }

        return "";
    }

    private String extractEntityIdFromResponse(String responseBody, Map<String, EntityStoreService.ExtractedEntity> entitiesById) {
        JsonNode root = parseJson(responseBody);
        if (root != null) {
            String id = extractFirstId(root, 0);
            if (!id.isBlank()) {
                return id;
            }
        }

        for (String known : entitiesById.keySet()) {
            if (responseBody != null && responseBody.contains("\"" + known + "\"")) {
                return known;
            }
        }

        return "";
    }

    private String extractFirstId(JsonNode node, int depth) {
        if (node == null || node.isNull() || node.isMissingNode() || depth > 8) {
            return "";
        }

        if (node.isObject()) {
            String directId = asText(node.get("id"));
            if (!directId.isBlank()) {
                return directId;
            }
            java.util.Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields.next();
                String nested = extractFirstId(entry.getValue(), depth + 1);
                if (!nested.isBlank()) {
                    return nested;
                }
            }
            return "";
        }

        if (node.isArray()) {
            for (JsonNode child : node) {
                String nested = extractFirstId(child, depth + 1);
                if (!nested.isBlank()) {
                    return nested;
                }
            }
        }

        return "";
    }

    private Map<String, Set<String>> buildMethodContextMap(List<JsonRpcIndex.MethodStoreView> methodStore) {
        Map<String, Set<String>> map = new HashMap<>();
        for (JsonRpcIndex.MethodStoreView view : methodStore) {
            Set<String> contexts = map.computeIfAbsent(view.key(), ignored -> new LinkedHashSet<>());
            for (String context : view.seenInSessions()) {
                if (context != null && !context.isBlank()) {
                    contexts.add(context);
                }
            }
        }
        return map;
    }

    private Map<String, List<MethodDiffEvidence>> buildMethodDiffEvidence(
            List<JsonRpcIndex.MethodStoreView> methodStore,
            Map<String, AuthContextStore.SessionView> contextsByKey
    ) {
        Map<String, List<MethodDiffEvidence>> map = new HashMap<>();

        for (JsonRpcIndex.MethodStoreView view : methodStore) {
            List<JsonRpcIndex.SessionSnapshot> snapshots = view.sessionSnapshots();
            if (snapshots.size() < 2) {
                continue;
            }

            for (int i = 0; i < snapshots.size(); i++) {
                JsonRpcIndex.SessionSnapshot source = snapshots.get(i);
                if (source.comparableRequestFingerprint() == null || source.comparableRequestFingerprint().isBlank()) {
                    continue;
                }

                for (int j = i + 1; j < snapshots.size(); j++) {
                    JsonRpcIndex.SessionSnapshot target = snapshots.get(j);
                    if (!Objects.equals(source.comparableRequestFingerprint(), target.comparableRequestFingerprint())) {
                        continue;
                    }
                    if (Objects.equals(source.responseHash(), target.responseHash())) {
                        continue;
                    }

                    String reason = evaluateMethodDifference(source.lastResponse(), target.lastResponse(), view.key());
                    if (reason.isBlank()) {
                        continue;
                    }

                    String sourceContext = defaultIfBlank(source.sessionId(), "");
                    String targetContext = defaultIfBlank(target.sessionId(), "");
                    if (sourceContext.isBlank() || targetContext.isBlank()) {
                        continue;
                    }

                    if (!contextsByKey.containsKey(sourceContext) || !contextsByKey.containsKey(targetContext)) {
                        continue;
                    }

                    map.computeIfAbsent(view.key(), ignored -> new ArrayList<>())
                            .add(new MethodDiffEvidence(
                                    view.key(),
                                    sourceContext,
                                    targetContext,
                                    reason,
                                    defaultIfBlank(source.lastResponse(), ""),
                                    defaultIfBlank(target.lastResponse(), "")
                            ));

                    map.computeIfAbsent(view.key(), ignored -> new ArrayList<>())
                            .add(new MethodDiffEvidence(
                                    view.key(),
                                    targetContext,
                                    sourceContext,
                                    reason,
                                    defaultIfBlank(target.lastResponse(), ""),
                                    defaultIfBlank(source.lastResponse(), "")
                            ));
                }
            }
        }

        return map;
    }

    private Map<String, Set<String>> buildEntityContextMap(Map<String, EntityStoreService.ExtractedEntity> entitiesById) {
        Map<String, Set<String>> map = new HashMap<>();
        for (Map.Entry<String, EntityStoreService.ExtractedEntity> entry : entitiesById.entrySet()) {
            EntityStoreService.ExtractedEntity entity = entry.getValue();
            LinkedHashSet<String> contexts = new LinkedHashSet<>();
            if (entity.contextKey() != null && !entity.contextKey().isBlank()) {
                contexts.add(entity.contextKey());
            }
            for (String context : entity.seenInContexts()) {
                if (context != null && !context.isBlank()) {
                    contexts.add(context);
                }
            }
            map.put(entry.getKey(), contexts);
        }
        return map;
    }

    private String evaluateMethodDifference(String sourceResponse, String targetResponse, String methodKey) {
        if ((sourceResponse == null || sourceResponse.isBlank()) && (targetResponse == null || targetResponse.isBlank())) {
            return "";
        }

        String left = defaultIfBlank(sourceResponse, "");
        String right = defaultIfBlank(targetResponse, "");
        if (left.equals(right)) {
            return "";
        }

        JsonNode leftJson = parseJson(left);
        JsonNode rightJson = parseJson(right);

        if (leftJson == null || rightJson == null) {
            int delta = Math.abs(left.length() - right.length());
            if (delta < 40) {
                return "";
            }
            return "Response size differs by " + delta + " bytes for method " + defaultIfBlank(methodKey, "unknown");
        }

        Set<String> leftFields = new LinkedHashSet<>();
        Set<String> rightFields = new LinkedHashSet<>();
        collectFieldNames(leftJson, leftFields, 0);
        collectFieldNames(rightJson, rightFields, 0);

        Set<String> sourceOnly = new LinkedHashSet<>(leftFields);
        sourceOnly.removeAll(rightFields);
        Set<String> targetOnly = new LinkedHashSet<>(rightFields);
        targetOnly.removeAll(leftFields);

        int leftNodes = countNodes(leftJson, 0);
        int rightNodes = countNodes(rightJson, 0);
        int nodeDelta = Math.abs(leftNodes - rightNodes);

        List<String> signals = new ArrayList<>();
        if (!sourceOnly.isEmpty()) {
            signals.add("source-only fields=" + sourceOnly.stream().limit(6).toList());
        }
        if (!targetOnly.isEmpty()) {
            signals.add("target-only fields=" + targetOnly.stream().limit(6).toList());
        }
        if (nodeDelta >= 6) {
            signals.add("JSON node count differs: source=" + leftNodes + ", target=" + rightNodes);
        }

        JsonNode leftResult = leftJson.path("result");
        JsonNode rightResult = rightJson.path("result");
        if (leftResult.isArray() && rightResult.isArray() && leftResult.size() != rightResult.size()) {
            signals.add("result[] size differs: source=" + leftResult.size() + ", target=" + rightResult.size());
        }

        if (signals.isEmpty()) {
            return "";
        }
        return String.join("; ", signals);
    }

    private void collectFieldNames(JsonNode node, Set<String> out, int depth) {
        if (node == null || node.isNull() || node.isMissingNode() || depth > 6) {
            return;
        }

        if (node.isObject()) {
            java.util.Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields.next();
                out.add(entry.getKey());
                collectFieldNames(entry.getValue(), out, depth + 1);
            }
            return;
        }

        if (node.isArray()) {
            int limit = Math.min(node.size(), 8);
            for (int i = 0; i < limit; i++) {
                collectFieldNames(node.get(i), out, depth + 1);
            }
        }
    }

    private int countNodes(JsonNode node, int depth) {
        if (node == null || node.isNull() || node.isMissingNode() || depth > 12) {
            return 0;
        }

        int total = 1;
        if (node.isObject()) {
            java.util.Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                total += countNodes(fields.next().getValue(), depth + 1);
            }
        } else if (node.isArray()) {
            int limit = Math.min(node.size(), 20);
            for (int i = 0; i < limit; i++) {
                total += countNodes(node.get(i), depth + 1);
            }
        }
        return total;
    }

    private String findMethodDifference(
            Map<String, List<MethodDiffEvidence>> methodDiffEvidence,
            String methodKey,
            String sourceContext,
            String targetContext,
            String sourceResponse,
            String targetResponse
    ) {
        for (MethodDiffEvidence evidence : methodDiffEvidence.getOrDefault(methodKey, List.of())) {
            if (Objects.equals(evidence.sourceContext(), sourceContext)
                    && Objects.equals(evidence.targetContext(), targetContext)) {
                return defaultIfBlank(evidence.reason(), "");
            }
        }
        return evaluateMethodDifference(sourceResponse, targetResponse, methodKey);
    }

    private String pickSourceContext(
            Set<String> contexts,
            String targetContext,
            Map<String, AuthContextStore.SessionView> contextsByKey
    ) {
        if (contexts == null || contexts.isEmpty()) {
            return "";
        }

        for (String context : contexts) {
            if (Objects.equals(context, targetContext)) {
                continue;
            }
            if (roleFor(context, contextsByKey) == RoleType.ADMIN) {
                return context;
            }
        }

        for (String context : contexts) {
            if (!Objects.equals(context, targetContext)) {
                return context;
            }
        }

        return "";
    }

    private String pickSourceContextForSubCalls(
            List<String> subCallMethods,
            Map<String, Set<String>> methodToContexts,
            String targetContext,
            Map<String, AuthContextStore.SessionView> contextsByKey
    ) {
        LinkedHashSet<String> candidates = new LinkedHashSet<>();
        for (String subMethod : subCallMethods) {
            if (subMethod == null || subMethod.isBlank()) {
                continue;
            }

            for (Map.Entry<String, Set<String>> entry : methodToContexts.entrySet()) {
                if (!entry.getKey().startsWith(subMethod + ":")) {
                    continue;
                }
                candidates.addAll(entry.getValue());
            }
        }

        return pickSourceContext(candidates, targetContext, contextsByKey);
    }

    private boolean hasAdminOnlySubType(
            List<String> subTypeNames,
            List<JsonRpcIndex.MethodStoreView> methodStore,
            Map<String, AuthContextStore.SessionView> contextsByKey,
            String currentContextKey
    ) {
        RoleType currentRole = roleFor(currentContextKey, contextsByKey);
        if (currentRole == RoleType.ADMIN) {
            return false;
        }

        for (String typeName : subTypeNames) {
            if (typeName == null || typeName.isBlank()) {
                continue;
            }

            boolean seen = false;
            boolean onlyAdmin = true;
            for (JsonRpcIndex.MethodStoreView view : methodStore) {
                if (!typeName.equalsIgnoreCase(view.typeName())) {
                    continue;
                }
                for (String contextKey : view.seenInSessions()) {
                    seen = true;
                    if (roleFor(contextKey, contextsByKey) != RoleType.ADMIN) {
                        onlyAdmin = false;
                    }
                }
            }

            if (seen && onlyAdmin) {
                return true;
            }
        }

        return false;
    }

    private String confidenceFor(
            String targetContext,
            String sourceContext,
            Map<String, AuthContextStore.SessionView> contextsByKey
    ) {
        RoleType targetRole = roleFor(targetContext, contextsByKey);
        RoleType sourceRole = roleFor(sourceContext, contextsByKey);
        if (targetRole == RoleType.LOW_PRIV && sourceRole == RoleType.ADMIN) {
            return "HIGH";
        }
        if (targetRole == RoleType.LOW_PRIV && sourceRole != RoleType.LOW_PRIV) {
            return "HIGH";
        }
        if (targetRole == RoleType.LOW_PRIV || sourceRole == RoleType.ADMIN) {
            return "MEDIUM";
        }
        if (targetRole != sourceRole && targetRole != RoleType.UNKNOWN) {
            return "MEDIUM";
        }
        // Both UNKNOWN: pre-tagging discovery — generate findings at reduced confidence
        // so the extension isn't silent until roles are manually tagged.
        if (targetRole == RoleType.UNKNOWN || sourceRole == RoleType.UNKNOWN) {
            return "MEDIUM";
        }
        return "LOW";
    }

    private RoleType roleFor(String contextKey, Map<String, AuthContextStore.SessionView> contextsByKey) {
        if (contextKey == null || contextKey.isBlank()) {
            return RoleType.UNKNOWN;
        }
        AuthContextStore.SessionView session = contextsByKey.get(contextKey);
        return session == null ? RoleType.UNKNOWN : session.role();
    }

    private boolean isWriteLikeMethod(String methodName) {
        String lowered = methodName == null ? "" : methodName.toLowerCase(Locale.ROOT);
        return lowered.startsWith("set")
                || lowered.startsWith("add")
                || lowered.startsWith("create")
                || lowered.startsWith("update")
                || lowered.startsWith("delete")
                || lowered.startsWith("remove")
                || lowered.startsWith("assign")
                || lowered.startsWith("grant")
                || lowered.contains("save")
                || lowered.contains("write")
                || lowered.contains("edit");
    }

    private JsonNode parseJson(String text) {
        if (text == null || text.isBlank()) {
            return null;
        }
        try {
            return objectMapper.readTree(text);
        } catch (Exception ignored) {
            return null;
        }
    }

    private boolean isSuppressedMethod(String methodName) {
        String lowered = methodName == null ? "" : methodName.toLowerCase(Locale.ROOT);
        for (String term : SUPPRESSED_METHOD_TERMS) {
            if (lowered.contains(term)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isEntityKey(String loweredKey) {
        if (loweredKey == null || loweredKey.isBlank()) {
            return false;
        }
        // Credential fields are not entity identifiers
        if ("sessionid".equals(loweredKey) || "database".equals(loweredKey) || "username".equals(loweredKey)
                || "date".equals(loweredKey)) {
            return false;
        }

        // Exact match for bare "id"
        if ("id".equals(loweredKey)) {
            return true;
        }

        // Suffix-based ID detection — catches deviceId, userId, groupId, ruleId, etc.
        // but NOT boolean filters like isDeviceCommunicating, isActive, hasPermission.
        if (loweredKey.endsWith("id") && loweredKey.length() > 2) {
            // Verify it's camelCase or snake_case ID, not a word ending in "id" like "valid", "hybrid"
            char preceding = loweredKey.charAt(loweredKey.length() - 3);
            if (preceding == '_' || Character.isLowerCase(preceding)) {
                // Check the preceding segment looks like an entity type, not gibberish
                return true;
            }
        }

        // Explicit underscore-based ID fields
        if (loweredKey.contains("_id") || loweredKey.contains("_key")) {
            return true;
        }

        // GroupCompanyId and similar compound identifiers
        if (loweredKey.equals("groupcompanyid")) {
            return true;
        }

        return false;
    }

    private String buildComparisonBlock(String adminResponse, String lowResponse) {
        if ((adminResponse == null || adminResponse.isBlank()) && (lowResponse == null || lowResponse.isBlank())) {
            return "";
        }

        String admin = truncate(defaultIfBlank(adminResponse, ""), 350);
        String low = truncate(defaultIfBlank(lowResponse, ""), 350);
        String structuralDiff = evaluateMethodDifference(adminResponse, lowResponse, "");
        if (structuralDiff.isBlank()) {
            return "adminResponse=" + admin + "\nlowPrivResponse=" + low;
        }
        return "adminResponse=" + admin + "\nlowPrivResponse=" + low + "\nstructuralDiff=" + structuralDiff;
    }

    private String classifyResponse(String responseBody) {
        if (responseBody == null || responseBody.isBlank()) {
            return "empty";
        }

        JsonNode root = parseJson(responseBody);
        if (root == null) {
            return "non_json";
        }

        JsonNode error = root.path("error");
        if (!error.isMissingNode() && !error.isNull()) {
            String message = asText(error.path("message")).toLowerCase(Locale.ROOT);
            int code = error.path("code").asInt(0);
            if (message.contains("forbidden") || message.contains("permission") || message.contains("unauthor")
                    || message.contains("invaliduser") || code == 401 || code == 403) {
                return "permission_error";
            }
            return "error";
        }

        JsonNode result = root.path("result");
        if (result.isArray() && result.size() == 0) {
            return "empty_result";
        }
        if (result.isObject() && result.size() == 0) {
            return "empty_result";
        }
        if (!result.isMissingNode() && !result.isNull()) {
            return "success_with_data";
        }
        return "success";
    }

    private String buildMethodKey(String method, String typeName) {
        return defaultIfBlank(method, "Get") + ":" + defaultIfBlank(typeName, "Unknown");
    }

    private String methodFromKey(String methodKey) {
        int index = methodKey.indexOf(':');
        return index < 0 ? methodKey : methodKey.substring(0, index);
    }

    private String typeFromKey(String methodKey) {
        int index = methodKey.indexOf(':');
        return index < 0 ? "Unknown" : methodKey.substring(index + 1);
    }

    private void notifyListeners() {
        for (Runnable listener : updateListeners) {
            try {
                listener.run();
            } catch (Exception ex) {
                logging.logToError("Attack suggestions listener failed.", ex);
            }
        }
    }

    private static String suggestionId(String seed) {
        return Integer.toHexString(Objects.hash(seed));
    }

    private static String asText(JsonNode node) {
        if (node == null || node.isNull()) {
            return "";
        }
        return node.asText("").trim();
    }

    private static String defaultIfBlank(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }

    private static String truncate(String value, int maxLength) {
        if (value == null) {
            return "";
        }
        if (value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, maxLength);
    }

    private record ParsedRequest(
            String wrapperMethod,
            String typeName,
            List<String> entityIds,
            boolean multiCall,
            boolean emptySearchInSubCall,
            List<String> subCallTypeNames,
            List<String> subCallMethods,
            boolean hasWriteSubCall,
            boolean hasMixedPrivilegeChain,
            boolean notification,
            boolean broadSearch
    ) {
    }

    private record MultiCallInfo(
            boolean emptySearchInSubCall,
            List<String> subCallTypeNames,
            List<String> subCallMethods,
            boolean hasWriteSubCall,
            boolean hasMixedPrivilegeChain
    ) {
    }

    private record MethodDiffEvidence(
            String methodKey,
            String sourceContext,
            String targetContext,
            String reason,
            String sourceResponse,
            String targetResponse
    ) {
    }

    private record RequestObservation(
            String observationId,
            String recordId,
            Instant timestamp,
            String host,
            String method,
            String wrapperMethod,
            String typeName,
            String contextKey,
            String sessionId,
            String database,
            String userName,
            List<String> requestEntityIds,
            boolean multiCall,
            boolean emptySearchInSubCall,
            List<String> subCallTypeNames,
            List<String> subCallMethods,
            boolean hasWriteSubCall,
            boolean hasMixedPrivilegeChain,
            String paramsMode,
            boolean notification,
            String requestBody,
            String responseBody,
            Integer responseStatus,
            boolean broadSearch
    ) {
    }
}
