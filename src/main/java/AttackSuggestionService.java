import burp.api.montoya.logging.Logging;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
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
    private static final int MAX_SUGGESTIONS = 220;
    private static final int MIN_STRONG_SIGNALS_FOR_SUGGESTION = 2;
    private static final int MAX_OBSERVED_ITEMS = 6_000;

    private static final Set<String> SUPPRESSED_METHOD_TERMS = Set.of(
            "jsonp", "cors", "addin", "add-in", "addins", "message", "messages", "audit", "auditlog",
            "password", "dos", "rate", "ratelimit", "ui-only", "uionly"
    );

    private static final Set<String> TENANT_KEYS = Set.of(
            "tenant", "database", "db", "group", "groupid", "groupcompanyid", "company", "organization", "org"
    );

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

    private final Map<String, ObservedItem> observedItems = new ConcurrentHashMap<>();
    private final ArrayDeque<String> observedOrder = new ArrayDeque<>();
    private final Object observedOrderLock = new Object();

    private volatile List<AttackSuggestion> latestSuggestions = List.of();
    private volatile Map<String, AttackSuggestion> suggestionsById = Map.of();

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

        List<ObservedItem> snapshot = new ArrayList<>(observedItems.values());
        snapshot.sort(Comparator.comparing(ObservedItem::timestamp));

        Map<String, List<ObservedItem>> grouped = new LinkedHashMap<>();
        for (ObservedItem item : snapshot) {
            if (!MyGeotabScope.isAllowedHost(item.host())) {
                continue;
            }
            if (isSuppressedMethod(item.methodName())) {
                continue;
            }
            String groupKey = item.methodName() + "|" + defaultIfBlank(item.typeName(), "none");
            grouped.computeIfAbsent(groupKey, ignored -> new ArrayList<>()).add(item);
        }

        Map<String, Integer> methodRiskScores = new HashMap<>();
        for (SecurityFinding finding : securityAnalyzer.snapshotFindings()) {
            methodRiskScores.merge(finding.method(), finding.riskScore(), Math::max);
        }

        WorkflowGraphService.WorkflowGraphSnapshot workflowSnapshot = workflowGraphService.snapshot();
        Map<String, Integer> chainEdgeCounts = buildChainEdgeCounts(workflowSnapshot);
        Map<String, Integer> chainCounts = buildChainCounts(workflowSnapshot);
        Map<String, String> preferredChains = buildPreferredChainPaths(workflowSnapshot);

        for (Map.Entry<String, List<ObservedItem>> entry : grouped.entrySet()) {
            List<ObservedItem> items = entry.getValue();
            if (items.isEmpty()) {
                continue;
            }

            ContextPair pair = selectContextPair(items);
            ObservedItem base = pair != null && pair.lowContextItem() != null
                    ? pair.lowContextItem()
                    : items.get(items.size() - 1);
            ObservedItem high = pair != null ? pair.highContextItem() : null;

                MethodContext reclassifiedContext = reclassifyMethodContext(
                    items,
                    methodRiskScores.getOrDefault(base.methodName(), 0),
                    pair
                );

                EntitySwapTarget swapTarget = selectEntitySwapTarget(items, high, base);
                String preferredChainPath = preferredChains.getOrDefault(base.methodName(), base.methodName());

                SignalSet signals = buildSignals(
                    items,
                    pair,
                    methodRiskScores.getOrDefault(base.methodName(), 0),
                    chainEdgeCounts.getOrDefault(base.methodName(), 0),
                    chainCounts.getOrDefault(base.methodName(), 0),
                    reclassifiedContext,
                    !preferredChainPath.equals(base.methodName())
                );

                if (!signals.provenSignal()) {
                continue;
                }

                emitCrossTenantSuggestion(deduplicated, base, swapTarget, signals, reclassifiedContext, preferredChainPath, pair);
                emitCredentialSwapSuggestions(deduplicated, base, high, signals, reclassifiedContext, preferredChainPath, pair);
                emitLowPrivReplaySuggestion(deduplicated, base, signals, reclassifiedContext, preferredChainPath);
                emitAuthDifferentialSuggestion(deduplicated, base, high, pair, signals, reclassifiedContext, preferredChainPath);
                emitBatchAuthorizationSuggestion(deduplicated, base, swapTarget, signals, reclassifiedContext, preferredChainPath);
                emitNotificationSuggestion(deduplicated, base, signals, reclassifiedContext, preferredChainPath);
                emitParamEncodingSuggestion(deduplicated, base, signals, reclassifiedContext, preferredChainPath);
                emitNestedParamIntegritySuggestion(deduplicated, base, signals, reclassifiedContext, preferredChainPath);
                emitEntityReplaySuggestion(deduplicated, base, swapTarget, signals, reclassifiedContext, preferredChainPath, pair);
        }

        List<AttackSuggestion> next = new ArrayList<>(deduplicated.values());
        next.sort(Comparator
                .comparingInt(AttackSuggestion::priorityScore).reversed()
                .thenComparingInt(AttackSuggestion::confidenceScore).reversed()
                .thenComparing(AttackSuggestion::category, String.CASE_INSENSITIVE_ORDER)
                .thenComparing(AttackSuggestion::findingTitle, String.CASE_INSENSITIVE_ORDER));

        if (next.size() > MAX_SUGGESTIONS) {
            next = new ArrayList<>(next.subList(0, MAX_SUGGESTIONS));
        }

        Map<String, AttackSuggestion> byId = new LinkedHashMap<>();
        for (AttackSuggestion suggestion : next) {
            byId.put(suggestion.suggestionId(), suggestion);
        }

        latestSuggestions = List.copyOf(next);
        suggestionsById = Map.copyOf(byId);
        logging.logToOutput("[LogicHunter][SUGGEST] grouped=" + grouped.size() + " generated=" + next.size());
        notifyListeners();
    }

    public List<AttackSuggestion> snapshotSuggestions() {
        return latestSuggestions;
    }

    public Optional<AttackSuggestion> snapshotSuggestion(String suggestionId) {
        return Optional.ofNullable(suggestionsById.get(suggestionId));
    }

    public ObjectNode buildManualExportBundle(String suggestionId) {
        AttackSuggestion suggestion = snapshotSuggestion(suggestionId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown suggestion ID: " + suggestionId));

        ObjectNode root = objectMapper.createObjectNode();
        root.put("generatedAt", Instant.now().toString());
        root.put("mode", "manual-only");
        root.put("suggestionId", suggestion.suggestionId());
        root.put("title", suggestion.findingTitle());
        root.put("category", suggestion.category());
        root.put("host", suggestion.host());
        root.put("method", suggestion.primaryMethod());
        root.put("attackPath", suggestion.attackPath());
        root.put("reason", suggestion.whySuspicious());
        root.put("confidenceScore", suggestion.confidenceScore());
        root.put("effectivenessScore", suggestion.effectivenessScore());
        root.put("expectedResult", suggestion.expectedResult());
        root.put("ifVulnerableImpact", suggestion.impact());
        root.put("repeaterRequest", suggestion.repeaterRequest());
        root.put("observation", suggestion.observation());
        root.put("evidence", suggestion.evidence());
        root.put("formattedFinding", suggestion.toFormattedFinding());

        ArrayNode checklist = objectMapper.createArrayNode();
        checklist.add("Use the exact repeaterRequest bytes without rebuilding headers/body manually.");
        checklist.add("Replay under LOW_PRIV and compare against ADMIN context behavior.");
        checklist.add("Record differences in database, sessionId, userName, status, and object ownership fields.");
        checklist.add("Confirm unauthorized object access/state-change before reporting.");
        root.set("manualChecklist", checklist);

        if (!suggestion.primaryMethod().isBlank() && !"(multiple)".equals(suggestion.primaryMethod())) {
            index.snapshotMethodDetails(suggestion.primaryMethod())
                    .ifPresent(details -> root.set("methodMetadata", details.toMetadataJson(objectMapper)));
        }

        return root;
    }

    public void clear() {
        synchronized (observedOrderLock) {
            observedItems.clear();
            observedOrder.clear();
        }
        latestSuggestions = List.of();
        suggestionsById = Map.of();
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

        List<CallView> calls = parseCallViews(rawRecord.request().bodyText());
        if (calls.isEmpty()) {
            calls = List.of(new CallView(
                    0,
                    normalizedRecord.methodName(),
                    normalizedRecord.typeName(),
                    normalizedRecord.rpcVersion(),
                    normalizedRecord.batchRequest(),
                    normalizedRecord.notificationRequest(),
                    normalizedRecord.paramsMode(),
                    normalizedRecord.nestedMethods(),
                    objectMapper.createObjectNode(),
                    objectMapper.createObjectNode()
            ));
        }

        JsonNode responseNode = parseJson(rawRecord.response().bodyText());
        ResponseSnapshot responseSnapshot = summarizeResponse(rawRecord.response().statusCode(), responseNode, rawRecord.response().bodyText());

        for (CallView call : calls) {
            AuthContextStore.AuthContext auth = authContextStore.observeRecord(rawRecord, call.methodName());
            RoleType role = authContextStore.roleForContextKey(auth.contextKey());

            TenantSnapshot tenant = buildTenantSnapshot(call.paramsNode(), responseNode, auth);
            EntitySnapshot entity = buildEntitySnapshot(call.paramsNode(), responseNode, auth);
            MethodClassification classification = classifyMethod(call, responseSnapshot, tenant, entity);

            RpcContext rpcContext = new RpcContext(
                    call.rpcVersion(),
                    call.batchRequest(),
                    call.notificationRequest(),
                    call.paramsMode(),
                    call.nestedMethods(),
                    call.callIndex()
            );

            MethodContext methodContext = new MethodContext(
                    classification.mode(),
                    classification.adminSensitive(),
                    classification.wrapper(),
                    classification.notificationCapable(),
                    classification.metaTelemetry(),
                    call.typeName()
            );

            AuthSnapshot authSnapshot = new AuthSnapshot(
                    auth.contextKey(),
                    safe(auth.database()),
                    safe(auth.sessionId()),
                    safe(auth.userName()),
                    role
            );

            ObservedItem item = new ObservedItem(
                    rawRecord.recordId() + "#" + call.callIndex(),
                    rawRecord.recordId(),
                    rawRecord.timestamp(),
                    host,
                    call.methodName(),
                    safe(call.typeName()),
                    call.callIndex(),
                    rawRecord.request().rawHttpText(),
                    rawRecord.response().rawHttpText(),
                    rpcContext,
                    authSnapshot,
                    tenant,
                    methodContext,
                    entity,
                    responseSnapshot
            );

            rememberObservedItem(item);
            logObservation(item);
        }
    }

    private void rememberObservedItem(ObservedItem item) {
        synchronized (observedOrderLock) {
            if (!observedItems.containsKey(item.observationId())) {
                observedOrder.addLast(item.observationId());
            }
            observedItems.put(item.observationId(), item);

            while (observedOrder.size() > MAX_OBSERVED_ITEMS) {
                String evictedId = observedOrder.removeFirst();
                observedItems.remove(evictedId);
            }
        }
    }

    private void emitCrossTenantSuggestion(
            Map<String, AttackSuggestion> deduplicated,
            ObservedItem base,
            EntitySwapTarget swapTarget,
            SignalSet signals,
            MethodContext methodContext,
            String chainPath,
            ContextPair pair
    ) {
        if (!swapTarget.present()) {
            return;
        }
        // Relax: allow cross-tenant suggestions when tenantReplayable even without chain evidence
        if (!signals.chainConnected() && !signals.tenantReplayable()) {
            return;
        }
        if (!signals.tenantReplayable() && !signals.idsReusedAcrossContexts() && !signals.authDifferenceDetected()) {
            return;
        }

        String mutated = mutateUsingSwapTarget(base, swapTarget);
        if (mutated.equals(base.httpRequestRaw())) {
            return;
        }

        createAndPut(
                deduplicated,
                base,
                swapTarget.newValue(),
                "Cross-Tenant / Cross-Database Access",
                "Cross-tenant ID swap on " + base.methodName(),
                composeAttackPath(base.methodName(), chainPath, "id swap:" + swapTarget.fieldKey()),
                reasonFor("Entity ID from a different context is replayed in the same request shape.", signals),
                "Mutates one captured field using a real value seen in another tenant/account context.",
                "Server should reject the request with authorization error and zero foreign-object data.",
                "Response returns or mutates foreign tenant objects under the current context.",
                "Unauthorized cross-database or cross-tenant object access.",
                evidenceFor(base, signals, methodContext, chainPath, pair),
                mutated,
                signals,
                true,
                methodContext.isWriteOrAdminSensitive()
        );
    }

    private void emitCredentialSwapSuggestions(
            Map<String, AttackSuggestion> deduplicated,
            ObservedItem base,
            ObservedItem high,
            SignalSet signals,
            MethodContext methodContext,
            String chainPath,
            ContextPair pair
    ) {
        if (high == null || !signals.authPairAvailable()) {
            return;
        }
        // Relax: allow credential suggestions when tenantReplayable even without chain evidence
        if (!signals.chainConnected() && !signals.tenantReplayable()) {
            return;
        }
        if (!signals.authDifferenceDetected() && !signals.tenantReplayable()) {
            return;
        }

        if (!high.authContext().database().isBlank() && !high.authContext().database().equals(base.authContext().database())) {
            String mutated = RepeaterRequestMutator.mutateCredentialField(
                    base.httpRequestRaw(), base.rpcContext().callIndex(), "database", high.authContext().database());
                createCredentialSuggestion(deduplicated, base, "database", high.authContext().database(), mutated, signals, methodContext, chainPath, pair);
        }

        if (!high.authContext().sessionId().isBlank() && !high.authContext().sessionId().equals(base.authContext().sessionId())) {
            String mutated = RepeaterRequestMutator.mutateCredentialField(
                    base.httpRequestRaw(), base.rpcContext().callIndex(), "sessionId", high.authContext().sessionId());
                createCredentialSuggestion(deduplicated, base, "sessionId", high.authContext().sessionId(), mutated, signals, methodContext, chainPath, pair);
        }

        if (!high.authContext().userName().isBlank() && !high.authContext().userName().equals(base.authContext().userName())) {
            String mutated = RepeaterRequestMutator.mutateCredentialField(
                    base.httpRequestRaw(), base.rpcContext().callIndex(), "userName", high.authContext().userName());
            createCredentialSuggestion(deduplicated, base, "userName", high.authContext().userName(), mutated, signals, methodContext, chainPath, pair);
        }
    }

    private void createCredentialSuggestion(
            Map<String, AttackSuggestion> deduplicated,
            ObservedItem base,
            String credentialField,
            String targetValue,
            String mutated,
            SignalSet signals,
            MethodContext methodContext,
            String chainPath,
            ContextPair pair
    ) {
        if (mutated == null || mutated.isBlank() || mutated.equals(base.httpRequestRaw())) {
            return;
        }

        createAndPut(
                deduplicated,
                base,
                credentialField,
                "Method-Level Authorization Bypass",
                "Credential mutation (" + credentialField + ") on " + base.methodName(),
                composeAttackPath(base.methodName(), chainPath, "credentials." + credentialField),
                reasonFor("Credentials." + credentialField + " differs across contexts and is directly attacker-controlled.", signals),
                "Replays the exact request while swapping only credentials." + credentialField + " with a real captured value.",
                "Server should reject credential-context mismatch and block cross-context action.",
                "Server accepts swapped credentials and processes request in unauthorized context.",
                "Privilege escalation or cross-database access via credential confusion.",
                evidenceFor(base, signals, methodContext, chainPath, pair),
                mutated,
                signals,
                true,
                true
        );
    }

    private void emitLowPrivReplaySuggestion(
            Map<String, AttackSuggestion> deduplicated,
            ObservedItem base,
            SignalSet signals,
            MethodContext methodContext,
            String chainPath
    ) {
        if (base.authContext().role() != RoleType.LOW_PRIV) {
            return;
        }
        if (!methodContext.isWriteOrAdminSensitive()) {
            return;
        }
        if (!signals.chainConnected()) {
            return;
        }
        if (!signals.lowPrivWriteSucceeded() && !signals.wrapperWriteReachable()) {
            return;
        }

        createAndPut(
                deduplicated,
                base,
                "low-priv-replay",
                "Privilege Escalation / Write Replay",
                "Low-priv replay of state-changing method " + base.methodName(),
                composeAttackPath(base.methodName(), chainPath, "low-priv replay"),
                reasonFor("Low-priv context observed on a write/admin-sensitive method; replay validates unauthorized state change risk.", signals),
                "Uses the exact LOW_PRIV request bytes with no structural changes.",
                "Server should enforce role checks and return explicit authorization denial.",
                "LOW_PRIV request succeeds and changes backend state or privileged settings.",
                "Unauthorized state changes and vertical privilege escalation.",
                evidenceFor(base, signals, methodContext, chainPath),
                base.httpRequestRaw(),
                signals,
                false,
                true
        );
    }

    private void emitAuthDifferentialSuggestion(
            Map<String, AttackSuggestion> deduplicated,
            ObservedItem base,
            ObservedItem high,
            ContextPair pair,
            SignalSet signals,
            MethodContext methodContext,
            String chainPath
    ) {
        if (pair == null || high == null || !signals.authDifferenceDetected() || !signals.roleDifferenceSeen()) {
            return;
        }

        createAndPut(
                deduplicated,
                base,
                "auth-diff",
                "Method-Level Authorization Bypass",
                "Auth differential on " + base.methodName(),
                composeAttackPath(base.methodName(), chainPath, "auth differential"),
                reasonFor("Same method+typeName behaves differently across sessionId/database/userName contexts.", signals),
                "Compares outcomes across paired contexts with A↔B credential/entity swaps.",
                "Behavior should be consistent with strict authorization boundaries for both contexts.",
                "One context gains unauthorized object access or state-change capability.",
                "Cross-account data leakage and privilege boundary bypass.",
                evidenceFor(base, signals, methodContext, chainPath, pair),
                base.httpRequestRaw(),
                signals,
                false,
                methodContext.isWriteOrAdminSensitive()
        );
    }

    private void emitBatchAuthorizationSuggestion(
            Map<String, AttackSuggestion> deduplicated,
            ObservedItem base,
            EntitySwapTarget swapTarget,
            SignalSet signals,
            MethodContext methodContext,
            String chainPath
    ) {
        if (!base.rpcContext().batchRequest() && !methodContext.wrapper() && base.rpcContext().nestedMethods().isEmpty()) {
            return;
        }
        if (!signals.wrapperWriteReachable() && !signals.authDifferenceDetected()) {
            return;
        }

        String mutated = swapTarget.present()
                ? mutateUsingSwapTarget(base, swapTarget)
                : base.httpRequestRaw();

        createAndPut(
                deduplicated,
                base,
                swapTarget.present() ? swapTarget.newValue() : "batch",
                "Method-Level Authorization Bypass",
                "Batch / MultiCall authorization check for " + base.methodName(),
                composeAttackPath(base.methodName(), chainPath, "nested authorization"),
                reasonFor("Batch/wrapper call can mix privilege contexts; per-call authorization must be validated.", signals),
                "Replays captured batch/multicall shape with context-swapped entity/credential values.",
                "Every nested call should enforce authorization independently.",
                "Unauthorized nested calls succeed when outer request is accepted.",
                "Privilege pivot inside batched execution path.",
                evidenceFor(base, signals, methodContext, chainPath),
                mutated,
                signals,
                swapTarget.present(),
                true
        );
    }

    private void emitNotificationSuggestion(
            Map<String, AttackSuggestion> deduplicated,
            ObservedItem base,
            SignalSet signals,
            MethodContext methodContext,
            String chainPath
    ) {
        if (base.rpcContext().notificationRequest()) {
            return;
        }
        if (!methodContext.notificationCapable() || !methodContext.isWriteOrAdminSensitive()) {
            return;
        }
        if (!signals.chainConnected()) {
            return;
        }

        String mutated = RepeaterRequestMutator.removeRequestId(base.httpRequestRaw(), base.rpcContext().callIndex());
        if (mutated.equals(base.httpRequestRaw())) {
            return;
        }

        createAndPut(
                deduplicated,
                base,
                "notification",
                "Unauthorized State Change",
                "Notification-mode auth check on " + base.methodName(),
                composeAttackPath(base.methodName(), chainPath, "remove id"),
                reasonFor("Removing JSON-RPC id converts request to notification and can bypass response-gated auth paths.", signals),
                "Patches only the id field to send an otherwise identical notification request.",
                "Authorization and state-change checks must remain identical with or without id.",
                "Notification path bypasses checks and performs unauthorized action.",
                "Silent unauthorized operations without traceable response body.",
                evidenceFor(base, signals, methodContext, chainPath),
                mutated,
                signals,
                true,
                methodContext.isWriteOrAdminSensitive()
        );
    }

    private void emitParamEncodingSuggestion(
            Map<String, AttackSuggestion> deduplicated,
            ObservedItem base,
            SignalSet signals,
            MethodContext methodContext,
            String chainPath
    ) {
        if (!signals.authDifferenceDetected() && !signals.responseRichnessMismatch()) {
            return;
        }

        String mutated;
        String mode;
        if ("named".equals(base.rpcContext().paramsMode())) {
            mutated = RepeaterRequestMutator.convertNamedToPositional(base.httpRequestRaw(), base.rpcContext().callIndex());
            mode = "named->positional";
        } else if ("positional".equals(base.rpcContext().paramsMode())) {
            mutated = RepeaterRequestMutator.convertPositionalToNamed(base.httpRequestRaw(), base.rpcContext().callIndex());
            mode = "positional->named";
        } else {
            return;
        }

        if (mutated.equals(base.httpRequestRaw())) {
            return;
        }

        createAndPut(
                deduplicated,
                base,
                mode,
                "Method-Level Authorization Bypass",
                "Param encoding conversion on " + base.methodName(),
                composeAttackPath(base.methodName(), chainPath, mode),
                reasonFor("Authorization logic may diverge between named and positional parameter handlers.", signals),
                "Converts params encoding while preserving method, credentials, and endpoint bytes.",
                "Equivalent parameter encodings should enforce identical authorization decisions.",
                "One encoding bypasses checks and returns unauthorized data/actions.",
                "Parser differential leading to authorization bypass.",
                evidenceFor(base, signals, methodContext, chainPath),
                mutated,
                signals,
                true,
                methodContext.isWriteOrAdminSensitive()
        );
    }

    private void emitNestedParamIntegritySuggestion(
            Map<String, AttackSuggestion> deduplicated,
            ObservedItem base,
            SignalSet signals,
            MethodContext methodContext,
            String chainPath
    ) {
        if (!signals.chainConnected()) {
            return;
        }
        if (!signals.authDifferenceDetected() && !signals.responseRichnessMismatch() && !signals.tenantReplayable()) {
            return;
        }

        String removed = RepeaterRequestMutator.removeOneNestedParam(base.httpRequestRaw(), base.rpcContext().callIndex());
        String extra = RepeaterRequestMutator.addExtraParam(base.httpRequestRaw(), base.rpcContext().callIndex(), "lhExtra", "probe");
        String reordered = RepeaterRequestMutator.reorderParams(base.httpRequestRaw(), base.rpcContext().callIndex());

        String mutated = !removed.equals(base.httpRequestRaw()) ? removed
                : (!extra.equals(base.httpRequestRaw()) ? extra : reordered);

        if (mutated.equals(base.httpRequestRaw())) {
            return;
        }

        createAndPut(
                deduplicated,
                base,
                "nested-params",
                "Method-Level Authorization Bypass",
                "Missing/extra/reordered nested params check on " + base.methodName(),
                composeAttackPath(base.methodName(), chainPath, "nested param mutation"),
                reasonFor("Nested parameter validation can fail-open when fields are missing, reordered, or unexpected.", signals),
                "Mutates only params object shape while preserving full request context and credentials.",
                "Server should reject malformed shape and never fall back to permissive authorization defaults.",
                "Malformed nested params still execute unauthorized data access/state changes.",
                "Fail-open parser behavior with authorization impact.",
                evidenceFor(base, signals, methodContext, chainPath),
                mutated,
                signals,
                true,
                methodContext.isWriteOrAdminSensitive()
        );
    }

    private void emitEntityReplaySuggestion(
            Map<String, AttackSuggestion> deduplicated,
            ObservedItem base,
            EntitySwapTarget swapTarget,
            SignalSet signals,
            MethodContext methodContext,
            String chainPath,
            ContextPair pair
    ) {
        if (!swapTarget.present()) {
            return;
        }
        // Relax: allow entity replay when tenantReplayable even without chain evidence
        if (!signals.chainConnected() && !signals.tenantReplayable()) {
            return;
        }
        if (!signals.idsReusedAcrossContexts() && !signals.tenantReplayable() && !signals.responsesExposeTenantObjects()) {
            return;
        }

        String mutated = mutateUsingSwapTarget(base, swapTarget);
        if (mutated.equals(base.httpRequestRaw())) {
            return;
        }

        createAndPut(
                deduplicated,
                base,
                swapTarget.newValue(),
                "BOLA / IDOR Entity Replay",
                "Entity replay using response-derived ID on " + base.methodName(),
                composeAttackPath(base.methodName(), chainPath, "replay response ID:" + swapTarget.fieldKey()),
                reasonFor("ID reused from prior responses is accepted in a new context (classic BOLA/IDOR pattern).", signals),
                "Reuses real IDs extracted from captured responses; request shape remains unchanged.",
                "Server should bind object ownership to current tenant/user context.",
                "Foreign object is returned or modified using replayed response ID.",
                "Unauthorized object access and cross-account data exposure.",
                evidenceFor(base, signals, methodContext, chainPath, pair),
                mutated,
                signals,
                true,
                methodContext.isWriteOrAdminSensitive()
        );
    }

    private void createAndPut(
            Map<String, AttackSuggestion> deduplicated,
            ObservedItem base,
            String entityKey,
            String category,
            String title,
            String attackPath,
            String reason,
            String observation,
            String expected,
            String ifVulnerable,
            String impact,
            String evidence,
            String repeaterRequest,
            SignalSet signals,
            boolean mutated,
            boolean stateChangeRisk
    ) {
        String dedupKey = base.methodName() + "|" + defaultIfBlank(entityKey, category);

        int confidenceScore = confidenceScore(signals, mutated, stateChangeRisk);
        int effectivenessScore = effectivenessScore(signals, mutated, stateChangeRisk, !defaultIfBlank(entityKey, "").isBlank());
        int priority = Math.min(100, (confidenceScore * 65 + effectivenessScore * 35) / 100);

        AttackSuggestion.Confidence confidence = confidenceScore >= 80
                ? AttackSuggestion.Confidence.HIGH
                : (confidenceScore >= 55 ? AttackSuggestion.Confidence.MEDIUM : AttackSuggestion.Confidence.LOW);

        AttackSuggestion.Verdict verdict = confidenceScore >= 55
                ? AttackSuggestion.Verdict.LIKELY_VULNERABILITY
                : AttackSuggestion.Verdict.LIKELY_SAFE;

        AttackSuggestion suggestion = new AttackSuggestion(
                suggestionId(dedupKey + "|" + category + "|" + title),
                category,
                title,
                priority,
                SecurityFinding.RiskLevel.fromScore(priority),
                confidence,
                verdict,
                defaultIfBlank(base.methodName(), "(multiple)"),
                attackPath,
                observation,
                reason,
                repeaterRequest,
                expected,
                ifVulnerable,
                impact,
                evidence,
                base.host(),
                confidenceScore,
                effectivenessScore,
                repeaterRequest
        );

        AttackSuggestion existing = deduplicated.get(dedupKey);
        if (existing == null || suggestion.priorityScore() > existing.priorityScore()) {
            deduplicated.put(dedupKey, suggestion);
        }
    }

    private String mutateUsingSwapTarget(ObservedItem base, EntitySwapTarget swapTarget) {
        if (swapTarget == null || !swapTarget.present()) {
            return base.httpRequestRaw();
        }

        String mutated = RepeaterRequestMutator.mutateFirstMatchingKeyValueInParams(
                base.httpRequestRaw(),
                base.rpcContext().callIndex(),
                swapTarget.fieldKey(),
                swapTarget.oldValue(),
                swapTarget.newValue()
        );

        if (!mutated.equals(base.httpRequestRaw())) {
            return mutated;
        }

        return RepeaterRequestMutator.mutateFirstMatchingValueInParams(
                base.httpRequestRaw(),
                base.rpcContext().callIndex(),
                swapTarget.oldValue(),
                swapTarget.newValue()
        );
    }

    private String composeAttackPath(String methodName, String chainPath, String mutationLabel) {
        String chain = chainPath == null || chainPath.isBlank() ? methodName : chainPath;
        if (chain.equals(methodName)) {
            return methodName + " -> " + mutationLabel;
        }
        return chain + " | test=" + methodName + " -> " + mutationLabel;
    }

    private int confidenceScore(SignalSet signals, boolean mutated, boolean stateChangeRisk) {
        int score = 20;
        if (signals.authDifferenceDetected()) score += 18;
        if (signals.responseRichnessMismatch()) score += 14;
        if (signals.idsReusedAcrossContexts()) score += 12;
        if (signals.tenantReplayable()) score += 10;
        if (signals.tenantOrDatabaseVisible()) score += 10;
        if (signals.lowPrivWriteSucceeded()) score += 16;
        if (signals.batchMixPrivilege()) score += 8;
        if (signals.wrapperWriteReachable()) score += 8;
        if (signals.responsesExposeTenantObjects()) score += 8;
        if (signals.roleDifferenceSeen()) score += 8;
        if (signals.chainConnected()) score += 8;
        if (signals.methodRiskScore() >= 75) score += 6;
        if (mutated) score += 4;
        if (stateChangeRisk) score += 4;
        return Math.min(100, score);
    }

    private int effectivenessScore(SignalSet signals, boolean mutated, boolean stateChangeRisk, boolean hasRealEntity) {
        int score = 44;
        if (mutated) score += 16;
        if (hasRealEntity) score += 12;
        if (signals.authPairAvailable()) score += 8;
        if (signals.responseRichnessMismatch()) score += 8;
        if (signals.chainConnected()) score += 8;
        if (signals.tenantReplayable()) score += 6;
        if (stateChangeRisk) score += 6;
        if (signals.chainCount() > 0) score += 4;
        if (signals.methodRiskScore() >= 75) score += 6;
        return Math.min(100, score);
    }

    private SignalSet buildSignals(
            List<ObservedItem> items,
            ContextPair pair,
            int methodRisk,
            int chainEdgeCount,
            int chainCount,
            MethodContext methodContext,
            boolean methodInChainPath
    ) {
        boolean authDiff = false;
        boolean responseRichnessMismatch = false;
        boolean idsReused = false;
        boolean tenantVisible = false;
        boolean tenantReplayable = false;
        boolean lowWriteSucceeded = false;
        boolean batchMix = false;
        boolean wrapperWriteReachable = false;
        boolean responseTenantExposure = false;
        boolean roleDifferenceSeen = false;

        if (pair != null && pair.highContextItem() != null && pair.lowContextItem() != null) {
            authDiff = pair.highContextItem().responseSnapshot().objectCount() != pair.lowContextItem().responseSnapshot().objectCount()
                    || !Objects.equals(pair.highContextItem().responseSnapshot().statusCode(), pair.lowContextItem().responseSnapshot().statusCode())
                    || pair.highContextItem().responseSnapshot().hasError() != pair.lowContextItem().responseSnapshot().hasError();

            responseRichnessMismatch = pair.highContextItem().responseSnapshot().fieldCount()
                    != pair.lowContextItem().responseSnapshot().fieldCount()
                    || Math.abs(pair.highContextItem().responseSnapshot().bodyLength()
                    - pair.lowContextItem().responseSnapshot().bodyLength()) > 64;

            Set<String> intersection = new HashSet<>(pair.highContextItem().entityContext().allValues());
            intersection.retainAll(pair.lowContextItem().entityContext().allValues());
            idsReused = !intersection.isEmpty();

            Set<String> highTenant = new HashSet<>(pair.highContextItem().tenantContext().tenantValues());
            Set<String> lowTenant = new HashSet<>(pair.lowContextItem().tenantContext().tenantValues());
            highTenant.removeAll(lowTenant);
            tenantReplayable = !highTenant.isEmpty();

            // Cross-database detection: different databases = strong cross-tenant signal
            String highDb = pair.highContextItem().authContext().database();
            String lowDb = pair.lowContextItem().authContext().database();
            boolean crossDatabase = !highDb.isBlank() && !lowDb.isBlank()
                    && !highDb.equals("unknown-db") && !lowDb.equals("unknown-db")
                    && !highDb.equals(lowDb);
            if (crossDatabase) {
                tenantReplayable = true;
                // Cross-database implies auth difference even if response shapes are same
                authDiff = true;
            }

            // Cross-user detection: different users in same database = privilege escalation vector
            String highUser = pair.highContextItem().authContext().userName();
            String lowUser = pair.lowContextItem().authContext().userName();
            boolean crossUser = !highUser.isBlank() && !lowUser.isBlank()
                    && !highUser.equals("unknown-user") && !lowUser.equals("unknown-user")
                    && !highUser.equals(lowUser);
            if (crossUser && !crossDatabase) {
                tenantReplayable = true;
            }

            roleDifferenceSeen = pair.highContextItem().authContext().role() != pair.lowContextItem().authContext().role();
        }

        for (ObservedItem item : items) {
            tenantVisible = tenantVisible
                    || !item.tenantContext().database().isBlank()
                    || !item.tenantContext().sessionId().isBlank()
                    || !item.tenantContext().userName().isBlank();

            if (item.authContext().role() == RoleType.LOW_PRIV
                    && methodContext.isWriteOrAdminSensitive()
                    && item.responseSnapshot().isSuccess()
                    && !item.responseSnapshot().hasError()) {
                lowWriteSucceeded = true;
            }

            batchMix = batchMix || item.rpcContext().batchRequest() || methodContext.wrapper();
            if ((item.rpcContext().batchRequest() || methodContext.wrapper())
                    && (!item.rpcContext().nestedMethods().isEmpty() || methodContext.isWriteOrAdminSensitive())) {
                wrapperWriteReachable = true;
            }
            responseTenantExposure = responseTenantExposure || !item.entityContext().tenantLinkedValues().isEmpty();
        }

        boolean chainConnected = chainEdgeCount > 0 || chainCount > 0 || methodInChainPath;
        int strongSignals = 0;
        if (authDiff) strongSignals++;
        if (responseRichnessMismatch) strongSignals++;
        if (idsReused) strongSignals++;
        if (tenantReplayable) strongSignals++;
        if (lowWriteSucceeded) strongSignals++;
        if (wrapperWriteReachable) strongSignals++;
        if (responseTenantExposure) strongSignals++;

        return new SignalSet(
                pair != null,
                authDiff,
                responseRichnessMismatch,
                idsReused,
                tenantVisible,
                tenantReplayable,
                lowWriteSucceeded,
                batchMix,
                wrapperWriteReachable,
                responseTenantExposure,
                roleDifferenceSeen,
                chainConnected,
                strongSignals,
                methodRisk,
                chainEdgeCount,
                chainCount
        );
    }

    private ContextPair selectContextPair(List<ObservedItem> items) {
        Map<String, List<ObservedItem>> contexts = new LinkedHashMap<>();
        for (ObservedItem item : items) {
            String key = item.authContext().contextKey();
            contexts.computeIfAbsent(key, ignored -> new ArrayList<>()).add(item);
        }

        if (contexts.size() < 2) {
            return null;
        }

        ObservedItem high = null;
        ObservedItem low = null;

        for (List<ObservedItem> contextItems : contexts.values()) {
            if (contextItems.isEmpty()) {
                continue;
            }
            ObservedItem candidate = contextItems.get(contextItems.size() - 1);
            if (high == null || roleRank(candidate.authContext().role()) > roleRank(high.authContext().role())) {
                high = candidate;
            }
            if (low == null || roleRank(candidate.authContext().role()) < roleRank(low.authContext().role())) {
                low = candidate;
            }
        }

        if (high == null || low == null) {
            return null;
        }

        // If role-based selection resolved to the same context (e.g. both UNKNOWN),
        // prefer a cross-database pair — this is the primary signal for cross-tenant testing
        if (high.authContext().contextKey().equals(low.authContext().contextKey())) {
            // Try to find two items from different databases first
            ContextPair crossDbPair = findCrossDatabasePair(contexts);
            if (crossDbPair != null) {
                return crossDbPair;
            }

            // Fall back to any two distinct contexts
            List<ObservedItem> flat = new ArrayList<>();
            for (List<ObservedItem> contextItems : contexts.values()) {
                flat.addAll(contextItems);
            }
            flat.sort(Comparator.comparing(ObservedItem::timestamp));
            if (flat.size() < 2) {
                return null;
            }
            high = flat.get(flat.size() - 1);
            low = flat.get(flat.size() - 2);
        }

        return new ContextPair(high, low);
    }

    private ContextPair findCrossDatabasePair(Map<String, List<ObservedItem>> contexts) {
        List<ObservedItem> representatives = new ArrayList<>();
        for (List<ObservedItem> contextItems : contexts.values()) {
            if (!contextItems.isEmpty()) {
                representatives.add(contextItems.get(contextItems.size() - 1));
            }
        }

        // Find two items from different databases
        for (int i = 0; i < representatives.size(); i++) {
            for (int j = i + 1; j < representatives.size(); j++) {
                ObservedItem a = representatives.get(i);
                ObservedItem b = representatives.get(j);
                String dbA = a.authContext().database();
                String dbB = b.authContext().database();
                if (!dbA.isBlank() && !dbB.isBlank()
                        && !dbA.equals("unknown-db") && !dbB.equals("unknown-db")
                        && !dbA.equals(dbB)) {
                    // Return the one with higher role rank as "high"
                    return roleRank(a.authContext().role()) >= roleRank(b.authContext().role())
                            ? new ContextPair(a, b)
                            : new ContextPair(b, a);
                }
            }
        }

        // Also find two items from same database but different users
        for (int i = 0; i < representatives.size(); i++) {
            for (int j = i + 1; j < representatives.size(); j++) {
                ObservedItem a = representatives.get(i);
                ObservedItem b = representatives.get(j);
                String userA = a.authContext().userName();
                String userB = b.authContext().userName();
                if (!userA.isBlank() && !userB.isBlank()
                        && !userA.equals("unknown-user") && !userB.equals("unknown-user")
                        && !userA.equals(userB)) {
                    return roleRank(a.authContext().role()) >= roleRank(b.authContext().role())
                            ? new ContextPair(a, b)
                            : new ContextPair(b, a);
                }
            }
        }

        return null;
    }

    private EntitySwapTarget selectEntitySwapTarget(List<ObservedItem> items, ObservedItem high, ObservedItem base) {
        Map<String, String> baseRequestIds = base.entityContext().requestIds();
        if (baseRequestIds.isEmpty()) {
            return EntitySwapTarget.empty();
        }

        if (high != null) {
            EntitySwapTarget highResponseCandidate = selectMatchingSwapByKey(
                    baseRequestIds,
                    high.entityContext().responseIds(),
                    base.entityContext().allValues()
            );
            if (highResponseCandidate.present()) {
                return highResponseCandidate;
            }

            EntitySwapTarget highRequestCandidate = selectMatchingSwapByKey(
                    baseRequestIds,
                    high.entityContext().requestIds(),
                    base.entityContext().allValues()
            );
            if (highRequestCandidate.present()) {
                return highRequestCandidate;
            }
        }

        Set<String> responseEntities = new LinkedHashSet<>();
        for (ObservedItem item : items) {
            responseEntities.addAll(item.entityContext().responseValues());
        }

        for (Map.Entry<String, String> requestEntry : baseRequestIds.entrySet()) {
            String key = requestEntry.getKey();
            String oldValue = requestEntry.getValue();
            if (oldValue == null || oldValue.isBlank()) {
                continue;
            }

            for (String candidate : responseEntities) {
                if (candidate == null || candidate.isBlank()) {
                    continue;
                }
                if (candidate.equals(oldValue)) {
                    continue;
                }
                if (base.entityContext().allValues().contains(candidate)) {
                    continue;
                }
                return new EntitySwapTarget(key, oldValue, candidate);
            }
        }

        return EntitySwapTarget.empty();
    }

    private EntitySwapTarget selectMatchingSwapByKey(
            Map<String, String> baseRequestIds,
            Map<String, String> foreignIds,
            List<String> baseAllValues
    ) {
        for (Map.Entry<String, String> foreignEntry : foreignIds.entrySet()) {
            String key = foreignEntry.getKey();
            String foreignValue = foreignEntry.getValue();
            if (key == null || key.isBlank() || foreignValue == null || foreignValue.isBlank()) {
                continue;
            }

            String currentValue = baseRequestIds.get(key);
            if (currentValue == null || currentValue.isBlank()) {
                continue;
            }
            if (currentValue.equals(foreignValue)) {
                continue;
            }
            if (baseAllValues.contains(foreignValue)) {
                continue;
            }

            return new EntitySwapTarget(key, currentValue, foreignValue);
        }

        return EntitySwapTarget.empty();
    }

    private List<CallView> parseCallViews(String requestBody) {
        JsonNode root = parseJson(requestBody);
        if (root == null) {
            return List.of();
        }

        List<CallView> calls = new ArrayList<>();
        if (root instanceof ObjectNode objectNode) {
            CallView call = toCallView(0, objectNode, false);
            if (call != null) {
                calls.add(call);
            }
            return calls;
        }

        if (!root.isArray()) {
            return List.of();
        }

        for (int i = 0; i < root.size(); i++) {
            JsonNode child = root.get(i);
            if (child instanceof ObjectNode objectNode) {
                CallView call = toCallView(i, objectNode, true);
                if (call != null) {
                    calls.add(call);
                }
            }
        }

        return calls;
    }

    private CallView toCallView(int callIndex, ObjectNode callNode, boolean batch) {
        JsonNode methodNode = callNode.get("method");
        if (methodNode == null || methodNode.isNull()) {
            return null;
        }

        String method = methodNode.isTextual() ? methodNode.asText("") : methodNode.toString();
        if (method.isBlank()) {
            return null;
        }

        JsonNode params = callNode.path("params");
        String paramsMode;
        if (params.isMissingNode()) {
            paramsMode = "missing";
        } else if (params.isNull()) {
            paramsMode = "null";
        } else if (params.isObject()) {
            paramsMode = "named";
        } else if (params.isArray()) {
            paramsMode = "positional";
        } else {
            paramsMode = JsonShapeUtil.topLevelType(params);
        }

        boolean notification = !callNode.has("id") || callNode.path("id").isNull();
        String rpcVersion = callNode.path("jsonrpc").asText("2.0");
        String typeName = findTypeName(params, 0);
        List<String> nestedMethods = findNestedMethods(method, params);

        return new CallView(callIndex, method, typeName, rpcVersion, batch, notification, paramsMode, nestedMethods, callNode, params);
    }

    private String findTypeName(JsonNode node, int depth) {
        if (node == null || node.isNull() || node.isMissingNode() || depth > 7) {
            return "";
        }

        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields.next();
                String key = entry.getKey().toLowerCase(Locale.ROOT);
                if ("typename".equals(key) || "type".equals(key) || "entitytype".equals(key)) {
                    String value = entry.getValue().asText("").trim();
                    if (!value.isBlank()) {
                        return value;
                    }
                }
            }

            fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields.next();
                String nested = findTypeName(entry.getValue(), depth + 1);
                if (!nested.isBlank()) {
                    return nested;
                }
            }
            return "";
        }

        if (node.isArray()) {
            for (int i = 0; i < Math.min(node.size(), 6); i++) {
                String nested = findTypeName(node.get(i), depth + 1);
                if (!nested.isBlank()) {
                    return nested;
                }
            }
        }

        return "";
    }

    private List<String> findNestedMethods(String method, JsonNode params) {
        if (method == null || method.isBlank()) {
            return List.of();
        }

        boolean wrapper = "executemulticall".equalsIgnoreCase(method) || method.toLowerCase(Locale.ROOT).contains("multicall");
        if (!wrapper && params != null && params.isObject()) {
            boolean hasHints = false;
            Iterator<String> names = params.fieldNames();
            while (names.hasNext()) {
                String key = names.next().toLowerCase(Locale.ROOT);
                if ("calls".equals(key) || "requests".equals(key) || "operations".equals(key) || "methods".equals(key)) {
                    hasHints = true;
                    break;
                }
            }
            if (!hasHints) {
                return List.of();
            }
        }

        LinkedHashSet<String> nested = new LinkedHashSet<>();
        collectNestedMethods(params, nested, 0);
        nested.remove(method);
        return List.copyOf(nested);
    }

    private void collectNestedMethods(JsonNode node, Set<String> out, int depth) {
        if (node == null || node.isNull() || node.isMissingNode() || depth > 8) {
            return;
        }

        if (node.isObject()) {
            JsonNode methodNode = node.get("method");
            if (methodNode != null && !methodNode.isNull()) {
                String method = methodNode.isTextual() ? methodNode.asText("") : methodNode.toString();
                if (!method.isBlank()) {
                    out.add(method);
                }
            }
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                collectNestedMethods(fields.next().getValue(), out, depth + 1);
            }
            return;
        }

        if (node.isArray()) {
            for (JsonNode item : node) {
                collectNestedMethods(item, out, depth + 1);
            }
        }
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

    private ResponseSnapshot summarizeResponse(Integer statusCode, JsonNode responseNode, String rawBody) {
        int bodyLength = rawBody == null ? 0 : rawBody.length();
        if (responseNode == null) {
            boolean error = rawBody != null && rawBody.toLowerCase(Locale.ROOT).contains("error");
            return new ResponseSnapshot(statusCode, 0, 0, bodyLength, error,
                    statusCode != null && statusCode >= 200 && statusCode < 300);
        }

        JsonNode resultNode = responseNode;
        if (responseNode.isObject()) {
            JsonNode result = responseNode.path("result");
            if (!result.isMissingNode() && !result.isNull()) {
                resultNode = result;
            }
        }

        int objectCount = estimateObjectCount(resultNode);
        int fieldCount = estimateFieldCount(resultNode, 0, 4, 80);
        boolean hasError = false;
        if (responseNode.isObject()) {
            JsonNode errorNode = responseNode.path("error");
            hasError = !errorNode.isMissingNode() && !errorNode.isNull();
        }

        return new ResponseSnapshot(
                statusCode,
                objectCount,
                fieldCount,
                bodyLength,
                hasError,
                statusCode != null && statusCode >= 200 && statusCode < 300
        );
    }

    private int estimateObjectCount(JsonNode node) {
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

    private int estimateFieldCount(JsonNode node, int depth, int maxDepth, int maxFields) {
        if (node == null || node.isNull() || node.isMissingNode() || depth > maxDepth || maxFields <= 0) {
            return 0;
        }

        if (node.isObject()) {
            int count = 0;
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext() && count < maxFields) {
                Map.Entry<String, JsonNode> entry = fields.next();
                count++;
                count += estimateFieldCount(entry.getValue(), depth + 1, maxDepth, maxFields - count);
            }
            return Math.min(count, maxFields);
        }

        if (node.isArray()) {
            int count = 1;
            int maxItems = Math.min(node.size(), 3);
            for (int i = 0; i < maxItems && count < maxFields; i++) {
                count += estimateFieldCount(node.get(i), depth + 1, maxDepth, maxFields - count);
            }
            return Math.min(count, maxFields);
        }

        return 1;
    }

    private TenantSnapshot buildTenantSnapshot(JsonNode paramsNode, JsonNode responseNode, AuthContextStore.AuthContext auth) {
        Set<String> tenantValues = new LinkedHashSet<>();
        collectTenantValues(paramsNode, tenantValues, 0);
        collectTenantValues(responseNode, tenantValues, 0);

        return new TenantSnapshot(
                fallbackValue(findFirstByKey(paramsNode, Set.of("database", "db", "databaseName")), auth.database()),
                fallbackValue(findFirstByKey(paramsNode, Set.of("sessionId", "session", "sid")), auth.sessionId()),
                fallbackValue(findFirstByKey(paramsNode, Set.of("userName", "username", "user")), auth.userName()),
                List.copyOf(tenantValues)
        );
    }

    private EntitySnapshot buildEntitySnapshot(JsonNode paramsNode, JsonNode responseNode, AuthContextStore.AuthContext auth) {
        Map<String, String> ids = new LinkedHashMap<>();
        Map<String, String> requestIds = new LinkedHashMap<>();
        Map<String, String> responseIds = new LinkedHashMap<>();
        Set<String> allValues = new LinkedHashSet<>();
        Set<String> responseValues = new LinkedHashSet<>();
        Set<String> tenantLinked = new LinkedHashSet<>();

        collectEntityValues(paramsNode, ids, requestIds, allValues, tenantLinked, false, 0);
        collectEntityValues(responseNode, ids, responseIds, allValues, tenantLinked, true, 0);
        collectDirectCredential(auth, ids, requestIds, allValues, tenantLinked);

        for (Map.Entry<String, String> entry : ids.entrySet()) {
            if (isTenantLinkedKey(entry.getKey())) {
                tenantLinked.add(entry.getValue());
            }
        }

        collectResponseEntityValues(responseNode, responseValues, 0);

        return new EntitySnapshot(
                ids,
            requestIds,
            responseIds,
                List.copyOf(allValues),
                List.copyOf(responseValues),
                List.copyOf(tenantLinked)
        );
    }

    private void collectDirectCredential(
            AuthContextStore.AuthContext auth,
            Map<String, String> ids,
            Map<String, String> requestIds,
            Set<String> allValues,
            Set<String> tenantLinked
    ) {
        putIfPresent(ids, requestIds, allValues, tenantLinked, "database", auth.database(), true);
        putIfPresent(ids, requestIds, allValues, tenantLinked, "sessionId", auth.sessionId(), true);
        putIfPresent(ids, requestIds, allValues, tenantLinked, "userName", auth.userName(), true);
    }

    private void collectEntityValues(
            JsonNode node,
            Map<String, String> ids,
            Map<String, String> sourceIds,
            Set<String> allValues,
            Set<String> tenantLinked,
            boolean response,
            int depth
    ) {
        if (node == null || node.isNull() || node.isMissingNode() || depth > 8) {
            return;
        }

        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields.next();
                String key = entry.getKey();
                JsonNode value = entry.getValue();
                if (value != null && value.isValueNode()) {
                    String normalized = normalizeEntityValue(value);
                    if (!normalized.isBlank() && isEntityKey(key)) {
                        ids.putIfAbsent(key, normalized);
                        sourceIds.putIfAbsent(key, normalized);
                        allValues.add(normalized);
                        if (isTenantLinkedKey(key)) {
                            tenantLinked.add(normalized);
                        }
                    }
                }
                collectEntityValues(value, ids, sourceIds, allValues, tenantLinked, response, depth + 1);
            }
            return;
        }

        if (node.isArray()) {
            for (JsonNode item : node) {
                collectEntityValues(item, ids, sourceIds, allValues, tenantLinked, response, depth + 1);
            }
        }
    }

    private void collectResponseEntityValues(JsonNode node, Set<String> responseValues, int depth) {
        if (node == null || node.isNull() || node.isMissingNode() || depth > 8) {
            return;
        }

        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields.next();
                if (entry.getValue().isValueNode() && isEntityKey(entry.getKey())) {
                    String value = normalizeEntityValue(entry.getValue());
                    if (!value.isBlank()) {
                        responseValues.add(value);
                    }
                }
                collectResponseEntityValues(entry.getValue(), responseValues, depth + 1);
            }
            return;
        }

        if (node.isArray()) {
            for (JsonNode item : node) {
                collectResponseEntityValues(item, responseValues, depth + 1);
            }
        }
    }

    private MethodClassification classifyMethod(
            CallView call,
            ResponseSnapshot responseSnapshot,
            TenantSnapshot tenant,
            EntitySnapshot entity
    ) {
        boolean wrapper = call.batchRequest() || !call.nestedMethods().isEmpty();
        boolean notificationCapable = call.notificationRequest() || call.callNode().has("id");
        boolean hasRequestEntities = !entity.requestIds().isEmpty();
        boolean responseRich = responseSnapshot.objectCount() > 0 || responseSnapshot.fieldCount() > 2;

        boolean writeLike = !wrapper
                && hasRequestEntities
                && responseSnapshot.isSuccess()
                && !responseSnapshot.hasError()
                && responseSnapshot.objectCount() <= 1;

        boolean metaTelemetry = !wrapper
                && !hasRequestEntities
                && !responseRich
                && tenant.tenantValues().isEmpty()
                && !responseSnapshot.hasError();

        MethodMode mode = wrapper
                ? MethodMode.WRAPPER
                : (writeLike
                ? MethodMode.WRITE
                : (responseRich
                ? MethodMode.READ
                : (metaTelemetry ? MethodMode.META_TELEMETRY : MethodMode.UNKNOWN)));

        boolean adminSensitive = !entity.tenantLinkedValues().isEmpty()
                || !tenant.tenantValues().isEmpty()
                || (mode == MethodMode.WRITE && responseSnapshot.isSuccess());

        return new MethodClassification(mode, adminSensitive, wrapper, notificationCapable, metaTelemetry);
    }

    private MethodContext reclassifyMethodContext(List<ObservedItem> items, int methodRisk, ContextPair pair) {
        if (items == null || items.isEmpty()) {
            return new MethodContext(MethodMode.UNKNOWN, false, false, false, false, "");
        }

        boolean wrapperObserved = false;
        boolean notificationObserved = false;
        boolean requestEntitiesObserved = false;
        boolean responseRichObserved = false;
        boolean tenantAware = false;
        boolean lowPrivSuccess = false;
        boolean writeLike = false;
        boolean metaTelemetryCandidate = true;
        String typeName = "";

        for (ObservedItem item : items) {
            if (typeName.isBlank() && item.typeName() != null && !item.typeName().isBlank()) {
                typeName = item.typeName();
            }

            boolean hasRequestEntities = !item.entityContext().requestIds().isEmpty();
            boolean responseRich = item.responseSnapshot().objectCount() > 0 || item.responseSnapshot().fieldCount() > 2;

            wrapperObserved = wrapperObserved
                    || item.rpcContext().batchRequest()
                    || item.methodContext().wrapper()
                    || !item.rpcContext().nestedMethods().isEmpty();
                boolean requestContainsJsonRpcId = item.httpRequestRaw() != null
                    && item.httpRequestRaw().contains("\"id\"");
                notificationObserved = notificationObserved
                    || item.rpcContext().notificationRequest()
                    || requestContainsJsonRpcId;
            requestEntitiesObserved = requestEntitiesObserved || hasRequestEntities;
            responseRichObserved = responseRichObserved || responseRich;

            tenantAware = tenantAware
                    || !item.tenantContext().tenantValues().isEmpty()
                    || !item.entityContext().tenantLinkedValues().isEmpty();

            if (item.authContext().role() == RoleType.LOW_PRIV
                    && item.responseSnapshot().isSuccess()
                    && !item.responseSnapshot().hasError()
                    && hasRequestEntities) {
                lowPrivSuccess = true;
            }

            if (item.responseSnapshot().isSuccess()
                    && !item.responseSnapshot().hasError()
                    && hasRequestEntities
                    && item.responseSnapshot().objectCount() <= 1) {
                writeLike = true;
            }

            if (hasRequestEntities || responseRich || tenantAware || item.responseSnapshot().hasError()) {
                metaTelemetryCandidate = false;
            }
        }

        boolean roleDifference = pair != null
                && pair.highContextItem() != null
                && pair.lowContextItem() != null
                && pair.highContextItem().authContext().role() != pair.lowContextItem().authContext().role();

        if (wrapperObserved && requestEntitiesObserved && (tenantAware || lowPrivSuccess)) {
            writeLike = true;
        }

        MethodMode mode = wrapperObserved
                ? MethodMode.WRAPPER
                : (writeLike
                ? MethodMode.WRITE
                : (responseRichObserved
                ? MethodMode.READ
                : (metaTelemetryCandidate ? MethodMode.META_TELEMETRY : MethodMode.UNKNOWN)));

        boolean adminSensitive = tenantAware
                || roleDifference
                || methodRisk >= 70
                || (mode == MethodMode.WRITE && lowPrivSuccess);

        return new MethodContext(
                mode,
                adminSensitive,
                wrapperObserved,
                notificationObserved,
                mode == MethodMode.META_TELEMETRY,
                typeName
        );
    }

    private Map<String, Integer> buildChainEdgeCounts(WorkflowGraphService.WorkflowGraphSnapshot workflowSnapshot) {
        Map<String, Integer> counts = new HashMap<>();
        for (WorkflowGraphService.EdgeView edge : workflowSnapshot.edges()) {
            counts.merge(edge.sourceMethod(), 1, Integer::sum);
            counts.merge(edge.targetMethod(), 1, Integer::sum);
        }
        return counts;
    }

    private Map<String, Integer> buildChainCounts(WorkflowGraphService.WorkflowGraphSnapshot workflowSnapshot) {
        Map<String, Integer> counts = new HashMap<>();
        for (WorkflowGraphService.ChainView chain : workflowSnapshot.chains()) {
            for (String method : chain.methodSequence()) {
                counts.merge(method, 1, Integer::sum);
            }
        }
        return counts;
    }

    private Map<String, String> buildPreferredChainPaths(WorkflowGraphService.WorkflowGraphSnapshot workflowSnapshot) {
        Map<String, ChainChoice> choices = new HashMap<>();
        for (WorkflowGraphService.ChainView chain : workflowSnapshot.chains()) {
            for (String method : chain.methodSequence()) {
                ChainChoice current = choices.get(method);
                if (current == null || chain.score() > current.score()) {
                    choices.put(method, new ChainChoice(chain.path(), chain.score()));
                }
            }
        }

        Map<String, String> result = new HashMap<>();
        for (Map.Entry<String, ChainChoice> entry : choices.entrySet()) {
            result.put(entry.getKey(), entry.getValue().path());
        }
        return result;
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

    private static boolean isEntityKey(String key) {
        if (key == null || key.isBlank()) {
            return false;
        }
        String lowered = key.toLowerCase(Locale.ROOT);
        return lowered.equals("id")
                || lowered.endsWith("id")
                || lowered.contains("_id")
                || lowered.contains("device")
                || lowered.contains("user")
                || lowered.contains("group")
                || lowered.contains("report")
                || lowered.contains("schedule")
                || lowered.contains("rule")
                || lowered.contains("database")
                || lowered.equals("db")
                || lowered.contains("session")
                || lowered.contains("tenant");
    }

    private static boolean isTenantLinkedKey(String key) {
        if (key == null || key.isBlank()) {
            return false;
        }
        String lowered = key.toLowerCase(Locale.ROOT);
        if (TENANT_KEYS.contains(lowered)) {
            return true;
        }
        return lowered.contains("tenant")
                || lowered.contains("database")
                || lowered.contains("group")
                || lowered.contains("company");
    }

    private String normalizeEntityValue(JsonNode node) {
        if (node == null || node.isNull()) {
            return "";
        }
        String value = node.asText("").trim();
        if (value.isBlank()) {
            return "";
        }
        if (value.length() > 120) {
            return value.substring(0, 120);
        }
        return value;
    }

    private void collectTenantValues(JsonNode node, Set<String> out, int depth) {
        if (node == null || node.isNull() || node.isMissingNode() || depth > 8) {
            return;
        }

        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields.next();
                if (isTenantLinkedKey(entry.getKey()) && entry.getValue().isValueNode()) {
                    String value = normalizeEntityValue(entry.getValue());
                    if (!value.isBlank()) {
                        out.add(value);
                    }
                }
                collectTenantValues(entry.getValue(), out, depth + 1);
            }
            return;
        }

        if (node.isArray()) {
            for (JsonNode item : node) {
                collectTenantValues(item, out, depth + 1);
            }
        }
    }

    private String findFirstByKey(JsonNode node, Set<String> keys) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            return "";
        }

        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields.next();
                if (keys.contains(entry.getKey().toLowerCase(Locale.ROOT))) {
                    String value = normalizeEntityValue(entry.getValue());
                    if (!value.isBlank()) {
                        return value;
                    }
                }
                String nested = findFirstByKey(entry.getValue(), keys);
                if (!nested.isBlank()) {
                    return nested;
                }
            }
            return "";
        }

        if (node.isArray()) {
            for (JsonNode item : node) {
                String nested = findFirstByKey(item, keys);
                if (!nested.isBlank()) {
                    return nested;
                }
            }
        }

        return "";
    }

    private static void putIfPresent(
            Map<String, String> ids,
            Map<String, String> requestIds,
            Set<String> allValues,
            Set<String> tenantLinked,
            String key,
            String value,
            boolean tenant
    ) {
        if (value == null || value.isBlank()) {
            return;
        }
        ids.putIfAbsent(key, value);
        requestIds.putIfAbsent(key, value);
        allValues.add(value);
        if (tenant) {
            tenantLinked.add(value);
        }
    }

    private String reasonFor(String baseReason, SignalSet signals) {
        StringBuilder reason = new StringBuilder(baseReason);
        reason.append(" Signals: ");
        List<String> signalText = new ArrayList<>();
        if (signals.authDifferenceDetected()) signalText.add("auth/response differential");
        if (signals.responseRichnessMismatch()) signalText.add("response richness mismatch");
        if (signals.idsReusedAcrossContexts()) signalText.add("ID reuse across contexts");
        if (signals.tenantReplayable()) signalText.add("tenant/database value replayable");
        if (signals.tenantOrDatabaseVisible()) signalText.add("tenant/database values visible");
        if (signals.roleDifferenceSeen()) signalText.add("explicit role difference observed");
        if (signals.lowPrivWriteSucceeded()) signalText.add("low-priv write success observed");
        if (signals.batchMixPrivilege()) signalText.add("batch/multicall path");
        if (signals.wrapperWriteReachable()) signalText.add("wrapper reaches write-like path");
        if (signals.responsesExposeTenantObjects()) signalText.add("tenant-linked object exposure");
        if (signals.chainConnected()) signalText.add("connected workflow chain evidence");
        if (signalText.isEmpty()) signalText.add("captured request-shape mutation");
        reason.append(String.join(", ", signalText));
        return reason.toString();
    }

    private String evidenceFor(ObservedItem base, SignalSet signals, MethodContext methodContext, String chainPath) {
        return evidenceFor(base, signals, methodContext, chainPath, null);
    }

    private String evidenceFor(ObservedItem base, SignalSet signals, MethodContext methodContext, String chainPath, ContextPair pair) {
        StringBuilder evidence = new StringBuilder();
        evidence.append("host=").append(base.host())
                .append(", method=").append(base.methodName())
                .append(", contextKey=").append(base.authContext().contextKey())
                .append(", rpcVersion=").append(base.rpcContext().rpcVersion())
                .append(", batch=").append(base.rpcContext().batchRequest())
                .append(", notification=").append(base.rpcContext().notificationRequest())
                .append(", paramsMode=").append(base.rpcContext().paramsMode())
                .append(", methodMode=").append(methodContext.mode().name())
                .append(", adminSensitive=").append(methodContext.adminSensitive())
                .append(", database=").append(base.authContext().database())
                .append(", sessionId=").append(shortValue(base.authContext().sessionId()))
                .append(", userName=").append(base.authContext().userName())
                .append(", role=").append(base.authContext().role().displayName())
                .append(", ids=").append(String.join(",", firstValues(base.entityContext().allValues(), 8)))
                .append(", authDiff=").append(signals.authDifferenceDetected())
                .append(", richnessDiff=").append(signals.responseRichnessMismatch())
                .append(", chainEdges=").append(signals.chainEdgeCount())
                .append(", chainCount=").append(signals.chainCount())
                .append(", chainPath=").append(defaultIfBlank(chainPath, base.methodName()));

        // Include both involved contexts for actionable cross-tenant/cross-user evidence
        if (pair != null && pair.highContextItem() != null && pair.lowContextItem() != null) {
            ObservedItem highItem = pair.highContextItem();
            ObservedItem lowItem = pair.lowContextItem();
            evidence.append(" | INVOLVED CONTEXTS:")
                    .append(" [HIGH] db=").append(highItem.authContext().database())
                    .append(", user=").append(highItem.authContext().userName())
                    .append(", role=").append(highItem.authContext().role().displayName())
                    .append(", session=").append(shortValue(highItem.authContext().sessionId()))
                    .append(" [LOW] db=").append(lowItem.authContext().database())
                    .append(", user=").append(lowItem.authContext().userName())
                    .append(", role=").append(lowItem.authContext().role().displayName())
                    .append(", session=").append(shortValue(lowItem.authContext().sessionId()));
        }

        return evidence.toString();
    }

    private void logObservation(ObservedItem item) {
        logging.logToOutput("[MyGeotab][rpc] host=" + item.host()
                + " method=" + item.methodName()
                + " nestedMethods=" + item.rpcContext().nestedMethods()
                + " rpcVersion=" + item.rpcContext().rpcVersion()
                + " batch=" + item.rpcContext().batchRequest()
                + " notification=" + item.rpcContext().notificationRequest()
                + " tenantDatabase=" + item.tenantContext().database()
                + " sessionId=" + shortValue(item.tenantContext().sessionId())
                + " userName=" + item.tenantContext().userName()
                + " role=" + item.authContext().role().displayName()
                + " contextKey=" + item.authContext().contextKey()
                + " methodMode=" + item.methodContext().mode().name()
                + " ids=" + firstValues(item.entityContext().allValues(), 6));
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

    private static String fallbackValue(String preferred, String fallback) {
        return preferred == null || preferred.isBlank() ? safe(fallback) : preferred;
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }

    private static String defaultIfBlank(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }

    private static String shortValue(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        return value.length() <= 24 ? value : value.substring(0, 24) + "...";
    }

    private static String firstValues(List<String> values, int max) {
        if (values == null || values.isEmpty()) {
            return "";
        }
        List<String> out = new ArrayList<>();
        for (int i = 0; i < Math.min(max, values.size()); i++) {
            out.add(values.get(i));
        }
        if (values.size() > max) {
            out.add("+" + (values.size() - max));
        }
        return String.join("|", out);
    }

    private static int roleRank(RoleType roleType) {
        if (roleType == null) {
            return 1;
        }
        return switch (roleType) {
            case ADMIN -> 3;
            case UNKNOWN -> 2;
            case LOW_PRIV -> 1;
        };
    }

    private record ChainChoice(String path, long score) {
    }

    private record EntitySwapTarget(String fieldKey, String oldValue, String newValue) {
        private static EntitySwapTarget empty() {
            return new EntitySwapTarget("", "", "");
        }

        private boolean present() {
            return fieldKey != null && !fieldKey.isBlank()
                    && oldValue != null && !oldValue.isBlank()
                    && newValue != null && !newValue.isBlank();
        }
    }

    private record CallView(
            int callIndex,
            String methodName,
            String typeName,
            String rpcVersion,
            boolean batchRequest,
            boolean notificationRequest,
            String paramsMode,
            List<String> nestedMethods,
            ObjectNode callNode,
            JsonNode paramsNode
    ) {
    }

    private record RpcContext(
            String rpcVersion,
            boolean batchRequest,
            boolean notificationRequest,
            String paramsMode,
            List<String> nestedMethods,
            int callIndex
    ) {
    }

    private record AuthSnapshot(
            String contextKey,
            String database,
            String sessionId,
            String userName,
            RoleType role
    ) {
    }

    private record TenantSnapshot(
            String database,
            String sessionId,
            String userName,
            List<String> tenantValues
    ) {
    }

    private record MethodContext(
            MethodMode mode,
            boolean adminSensitive,
            boolean wrapper,
            boolean notificationCapable,
            boolean metaTelemetry,
            String typeName
    ) {
        boolean isWriteOrAdminSensitive() {
            return mode == MethodMode.WRITE || adminSensitive;
        }
    }

    private record MethodClassification(
            MethodMode mode,
            boolean adminSensitive,
            boolean wrapper,
            boolean notificationCapable,
            boolean metaTelemetry
    ) {
    }

    private enum MethodMode {
        READ,
        WRITE,
        WRAPPER,
        META_TELEMETRY,
        UNKNOWN
    }

    private record EntitySnapshot(
            Map<String, String> ids,
            Map<String, String> requestIds,
            Map<String, String> responseIds,
            List<String> allValues,
            List<String> responseValues,
            List<String> tenantLinkedValues
    ) {
    }

    private record ResponseSnapshot(
            Integer statusCode,
            int objectCount,
            int fieldCount,
            int bodyLength,
            boolean hasError,
            boolean success
    ) {
        boolean isSuccess() {
            return success;
        }
    }

    private record ObservedItem(
            String observationId,
            String recordId,
            Instant timestamp,
            String host,
            String methodName,
            String typeName,
            int callIndex,
            String httpRequestRaw,
            String httpResponseRaw,
            RpcContext rpcContext,
            AuthSnapshot authContext,
            TenantSnapshot tenantContext,
            MethodContext methodContext,
            EntitySnapshot entityContext,
            ResponseSnapshot responseSnapshot
    ) {
    }

    private record ContextPair(ObservedItem highContextItem, ObservedItem lowContextItem) {
    }

    private record SignalSet(
            boolean authPairAvailable,
            boolean authDifferenceDetected,
            boolean responseRichnessMismatch,
            boolean idsReusedAcrossContexts,
            boolean tenantOrDatabaseVisible,
            boolean tenantReplayable,
            boolean lowPrivWriteSucceeded,
            boolean batchMixPrivilege,
            boolean wrapperWriteReachable,
            boolean responsesExposeTenantObjects,
            boolean roleDifferenceSeen,
            boolean chainConnected,
            int strongSignalCount,
            int methodRiskScore,
            int chainEdgeCount,
            int chainCount
    ) {
        boolean provenSignal() {
            // Allow through if we have a cross-database/cross-user pair with actionable signals
            if (tenantReplayable && authPairAvailable) {
                return true;
            }
            if (!chainConnected && !authPairAvailable) {
                return false;
            }
            return strongSignalCount >= MIN_STRONG_SIGNALS_FOR_SUGGESTION;
        }
    }
}
