import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class AttackExecutionService {
    private static final Pattern TRAILING_NUMBER_PATTERN = Pattern.compile("^(.*?)(\\d+)$");
    private static final Pattern ATTACK_PATH_CONTEXT_PATTERN = Pattern.compile("->\\s*(.*?)\\s*=>\\s*(.*?)\\s*->");

    private final ObjectMapper objectMapper;
    private final AuthContextStore authContextStore;
    private final EntityStoreService entityStoreService;
    private final JsonRpcIndex index;
    private final Logging logging;
    private final ReplayClient replayClient;

    private volatile boolean safeMode = true;
    private volatile int maxRequestsPerFinding = 8;

    private final Map<String, AttackExecutionFinding> latestBySuggestionId = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, ReplayOutcome> replayCache = new ConcurrentHashMap<>();

    public AttackExecutionService(
            ObjectMapper objectMapper,
            AuthContextStore authContextStore,
            EntityStoreService entityStoreService,
            JsonRpcIndex index,
            Logging logging,
            ReplayClient replayClient
    ) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
        this.authContextStore = Objects.requireNonNull(authContextStore, "authContextStore must not be null");
        this.entityStoreService = Objects.requireNonNull(entityStoreService, "entityStoreService must not be null");
        this.index = Objects.requireNonNull(index, "index must not be null");
        this.logging = Objects.requireNonNull(logging, "logging must not be null");
        this.replayClient = Objects.requireNonNull(replayClient, "replayClient must not be null");
    }

    public static AttackExecutionService create(
            MontoyaApi api,
            ObjectMapper objectMapper,
            AuthContextStore authContextStore,
            EntityStoreService entityStoreService,
            JsonRpcIndex index
    ) {
        Objects.requireNonNull(api, "api must not be null");
        ReplayClient client = (host, port, secure, rawRequest) -> {
            HttpRequest request = HttpRequest.httpRequest(HttpService.httpService(host, port, secure), rawRequest);
            HttpResponse response = api.http().sendRequest(request).response();
            if (response == null) {
                return new ReplayResponse(null, "", "");
            }
            return new ReplayResponse((int) response.statusCode(), defaultIfBlank(response.bodyToString(), ""), defaultIfBlank(response.toString(), ""));
        };
        return new AttackExecutionService(objectMapper, authContextStore, entityStoreService, index, api.logging(), client);
    }

    public void setSafeMode(boolean safeMode) {
        this.safeMode = safeMode;
    }

    public boolean isSafeMode() {
        return safeMode;
    }

    public void setMaxRequestsPerFinding(int maxRequestsPerFinding) {
        if (maxRequestsPerFinding < 1) {
            this.maxRequestsPerFinding = 1;
            return;
        }
        if (maxRequestsPerFinding > 10) {
            this.maxRequestsPerFinding = 10;
            return;
        }
        this.maxRequestsPerFinding = maxRequestsPerFinding;
    }

    public int maxRequestsPerFinding() {
        return maxRequestsPerFinding;
    }

    public Optional<AttackExecutionFinding> snapshotFinding(String suggestionId) {
        return Optional.ofNullable(latestBySuggestionId.get(suggestionId));
    }

    public Map<String, AttackExecutionFinding> snapshotFindings() {
        return Map.copyOf(latestBySuggestionId);
    }

    public Optional<AttackExecutionFinding> executeForSuggestion(AttackSuggestion suggestion) {
        if (suggestion == null) {
            return Optional.empty();
        }

        AttackBudget budget = new AttackBudget(maxRequestsPerFinding);
        List<AttackExecutionFinding> candidates = new ArrayList<>();

        AttackContexts contexts = resolveContexts(suggestion);
        if (!contexts.isComplete()) {
            logging.logToOutput("[LogicHunter][ATTACK] Context resolution failed for suggestion=" + suggestion.suggestionId());
            return Optional.of(buildRejectedFinding(suggestion, contexts, "Unresolved source or target context; attack execution skipped."));
        }

        TemplateRequest template = resolveTemplateRequest(suggestion, contexts.targetKey());
        if (template == null || template.rawRequest().isBlank()) {
            logging.logToOutput("[LogicHunter][ATTACK] Missing template request for suggestion=" + suggestion.suggestionId());
            return Optional.empty();
        }
        if (!hasSufficientAuthMaterial(template.rawRequest())) {
            logging.logToOutput("[LogicHunter][ATTACK] Incomplete auth material for suggestion=" + suggestion.suggestionId());
            return Optional.of(buildRejectedFinding(suggestion, contexts, "Incomplete authentication data in captured request; replay skipped."));
        }

        candidates.addAll(testCrossTenant(suggestion, template, contexts, budget));
        candidates.addAll(validateIdor(suggestion, template, contexts, budget));
        candidates.addAll(enumerateIds(suggestion, template, contexts, budget));

        if (isWriteLikeMethod(suggestion.method()) && !safeMode) {
            AttackExecutionFinding writeFinding = testWriteOperation(suggestion, template, contexts, budget);
            if (writeFinding != null) {
                candidates.add(writeFinding);
            }
        }

        if (isMultiCallMethod(suggestion.method(), template.rawRequest())) {
            AttackExecutionFinding multiCallFinding = testMultiCallExploit(suggestion, template, contexts, budget);
            if (multiCallFinding != null) {
                candidates.add(multiCallFinding);
            }
        }

        AttackExecutionFinding selected = selectBest(candidates);
        if (selected != null) {
            latestBySuggestionId.put(suggestion.suggestionId(), selected);
            logging.logToOutput("[LogicHunter][ATTACK] suggestion=" + suggestion.suggestionId()
                    + " confirmed=" + selected.confirmed()
                    + " severity=" + selected.severity().displayName()
                    + " classification=" + selected.responseClassification());
            return Optional.of(selected);
        }

        AttackExecutionFinding rejected = buildRejectedFinding(suggestion, contexts, "No exploitable behavior observed within replay budget.");
        latestBySuggestionId.put(suggestion.suggestionId(), rejected);
        return Optional.of(rejected);
    }

    public List<AttackExecutionFinding> enumerateIds(
            AttackSuggestion suggestion,
            TemplateRequest template,
            AttackContexts contexts,
            AttackBudget budget
    ) {
        String anchorId = defaultIfBlank(suggestion.entityId(), "");
        if (anchorId.isBlank()) {
            return List.of();
        }

        Matcher matcher = TRAILING_NUMBER_PATTERN.matcher(anchorId);
        if (!matcher.matches()) {
            return List.of();
        }

        String prefix = matcher.group(1);
        int observed;
        try {
            observed = Integer.parseInt(matcher.group(2));
        } catch (NumberFormatException ignored) {
            return List.of();
        }

        int start = Math.max(1, observed - 5);
        int end = safeMode ? Math.min(100, observed + 5) : Math.min(300, observed + 20);

        LinkedHashSet<Integer> numbers = new LinkedHashSet<>();
        for (int i = start; i <= end; i++) {
            numbers.add(i);
        }
        for (int step : List.of(2, 5, 10, 20)) {
            numbers.add(Math.max(1, observed - step));
            numbers.add(observed + step);
        }

        Set<String> knownEntityIds = new LinkedHashSet<>();
        for (EntityStoreService.ExtractedEntity entity : entityStoreService.snapshotExtractedEntities()) {
            knownEntityIds.add(defaultIfBlank(entity.entityId(), ""));
        }

        List<AttackExecutionFinding> findings = new ArrayList<>();
        for (int i : numbers) {
            if (!budget.hasRemaining()) {
                break;
            }
            String candidateId = prefix + i;
            if (candidateId.equals(anchorId)) {
                continue;
            }

            String mutated = RepeaterRequestMutator.mutateFirstMatchingKeyValueInParams(template.rawRequest(), 0, "id", anchorId, candidateId);
            if (mutated.equals(template.rawRequest())) {
                mutated = RepeaterRequestMutator.mutateFirstMatchingValueInParams(template.rawRequest(), 0, anchorId, candidateId);
            }
            if (mutated.equals(template.rawRequest())) {
                mutated = RepeaterRequestMutator.mutateFirstMatchingId(mutated, 0, candidateId);
            }
            if (mutated.equals(template.rawRequest())) {
                continue;
            }

            ReplayOutcome replay = replayRequest(mutated, template.target(), suggestion.method(), budget);
            if (!replay.executed()) {
                continue;
            }

            if (!"success_with_data".equals(replay.classification())) {
                continue;
            }

            boolean newObject = !knownEntityIds.contains(candidateId);
            String summary = newObject
                    ? "Predictable ID enumeration returned previously unseen object: " + candidateId
                    : "Predictable ID enumeration returned data for observed object: " + candidateId;

            AttackExecutionFinding finding = new AttackExecutionFinding(
                    suggestion.suggestionId() + "|enum|" + candidateId,
                    "ID_ENUMERATION",
                    SecurityFinding.RiskLevel.MEDIUM,
                    true,
                    defaultIfBlank(suggestion.method(), "Get"),
                    candidateId,
                    contexts.sourceKey(),
                    contexts.targetKey(),
                    contexts.sourceRole(),
                    contexts.targetRole(),
                    mutated,
                    replay.classification(),
                    "Extract observed ID pattern " + prefix + "N and replay small bounded range against captured endpoint.",
                    summary,
                    Instant.now()
            );
            findings.add(finding);
        }

        return findings;
    }

    public List<AttackExecutionFinding> testCrossTenant(
            AttackSuggestion suggestion,
            TemplateRequest template,
            AttackContexts contexts,
            AttackBudget budget
    ) {
        if (contexts.targetContext() == null) {
            return List.of();
        }

        String currentDb = defaultIfBlank(contexts.targetContext().database(), "");
        if (currentDb.isBlank()) {
            return List.of();
        }

        LinkedHashSet<String> candidateDatabases = new LinkedHashSet<>();
        for (AuthContextStore.SessionView view : authContextStore.snapshotSessions()) {
            String db = defaultIfBlank(view.database(), "");
            if (!db.isBlank() && !db.equalsIgnoreCase(currentDb)) {
                candidateDatabases.add(db);
            }
        }
        if (!safeMode && !currentDb.isBlank()) {
            candidateDatabases.add(currentDb + "-alt");
        }

        if (candidateDatabases.isEmpty()) {
            return List.of();
        }

        ReplayOutcome baseline = replayRequest(template.rawRequest(), template.target(), suggestion.method(), budget);
        if (!baseline.executed()) {
            return List.of();
        }

        List<AttackExecutionFinding> findings = new ArrayList<>();
        for (String candidateDb : candidateDatabases) {
            if (!budget.hasRemaining()) {
                break;
            }

            String mutated = RepeaterRequestMutator.swapDatabaseInBody(template.rawRequest(), 0, candidateDb);
            if (mutated.equals(template.rawRequest())) {
                continue;
            }
            ReplayOutcome replay = replayRequest(mutated, template.target(), suggestion.method(), budget);
            if (!replay.executed()) {
                continue;
            }

            if ("success_with_data".equals(replay.classification()) && isLeakComparedToBaseline(baseline, replay)) {
                String summary = "Cross-tenant data leakage: request with database='" + candidateDb
                        + "' returned data from a foreign tenant boundary.";
                findings.add(new AttackExecutionFinding(
                        suggestion.suggestionId() + "|xtenant|" + candidateDb,
                        "CROSS_TENANT",
                        SecurityFinding.RiskLevel.CRITICAL,
                        true,
                        defaultIfBlank(suggestion.method(), "Get"),
                        defaultIfBlank(suggestion.entityId(), ""),
                        contexts.sourceKey(),
                        contexts.targetKey(),
                        contexts.sourceRole(),
                        contexts.targetRole(),
                        mutated,
                        replay.classification(),
                        "Swap credentials.database to known tenant values and compare result size/object IDs against baseline.",
                        summary,
                        Instant.now()
                ));
            }
        }

        return findings;
    }

    public List<AttackExecutionFinding> validateIdor(
            AttackSuggestion suggestion,
            TemplateRequest template,
            AttackContexts contexts,
            AttackBudget budget
    ) {
        String entityId = defaultIfBlank(suggestion.entityId(), "");
        if (entityId.isBlank()) {
            return List.of();
        }

        TemplateRequest sourceTemplate = resolveTemplateRequest(suggestion, contexts.sourceKey());
        if (sourceTemplate == null || sourceTemplate.rawRequest().isBlank()) {
            return List.of();
        }

        String ownerPayload = injectContextCredentials(sourceTemplate.rawRequest(), contexts.sourceContext());
        ownerPayload = RepeaterRequestMutator.mutateFirstMatchingValueInParams(ownerPayload, 0, entityId, entityId);
        ReplayOutcome owner = replayRequest(ownerPayload, sourceTemplate.target(), suggestion.method(), budget);
        if (!owner.executed()) {
            return List.of();
        }

        String baselinePayload = injectContextCredentials(template.rawRequest(), contexts.targetContext());
        ReplayOutcome baseline = replayRequest(baselinePayload, template.target(), suggestion.method(), budget);
        if (!baseline.executed()) {
            return List.of();
        }

        String replayPayload = injectContextCredentials(template.rawRequest(), contexts.targetContext());
        replayPayload = RepeaterRequestMutator.mutateFirstMatchingValueInParams(replayPayload, 0, entityId, entityId);
        ReplayOutcome replay = replayRequest(replayPayload, template.target(), suggestion.method(), budget);
        if (!replay.executed()) {
            return List.of();
        }

        if (!isUnauthorizedExposure(owner, baseline, replay, entityId)) {
            return List.of();
        }

        if (!"success_with_data".equals(replay.classification())) {
            return List.of();
        }

        SecurityFinding.RiskLevel severity = isWriteLikeMethod(suggestion.method())
                ? SecurityFinding.RiskLevel.CRITICAL
                : SecurityFinding.RiskLevel.HIGH;

        String category = isWriteLikeMethod(suggestion.method()) ? "WRITE_IDOR" : "IDOR";
        String chain = "Use entity ID extracted from privileged flow and replay with target low-privileged credentials.";
        String summary = isWriteLikeMethod(suggestion.method())
                ? "Unauthorized write behavior succeeded with foreign entity ID."
                : "Unauthorized object access succeeded with foreign entity ID.";

        AttackExecutionFinding finding = new AttackExecutionFinding(
                suggestion.suggestionId() + "|idor|" + entityId,
                category,
                severity,
                true,
                defaultIfBlank(suggestion.method(), "Get"),
                entityId,
                contexts.sourceKey(),
                contexts.targetKey(),
                contexts.sourceRole(),
                contexts.targetRole(),
                replayPayload,
                replay.classification(),
                chain,
                summary,
                Instant.now()
        );

        return List.of(finding);
    }

    public AttackExecutionFinding testWriteOperation(
            AttackSuggestion suggestion,
            TemplateRequest template,
            AttackContexts contexts,
            AttackBudget budget
    ) {
        if (safeMode || isDestructiveMethod(suggestion.method())) {
            return null;
        }

        String entityId = defaultIfBlank(suggestion.entityId(), "");
        String mutated = entityId.isBlank()
                ? template.rawRequest()
                : RepeaterRequestMutator.mutateFirstMatchingValueInParams(template.rawRequest(), 0, entityId, entityId);
        if (mutated.equals(template.rawRequest())) {
            mutated = RepeaterRequestMutator.mutateFirstMatchingId(template.rawRequest(), 0, entityId);
        }

        if (contexts.targetContext() != null) {
            mutated = injectContextCredentials(mutated, contexts.targetContext());
        }

        ReplayOutcome before = replayRequest(template.rawRequest(), template.target(), suggestion.method(), budget);
        ReplayOutcome replay = replayRequest(mutated, template.target(), suggestion.method(), budget);
        ReplayOutcome after = replayRequest(template.rawRequest(), template.target(), suggestion.method(), budget);
        if (!replay.executed()) {
            return null;
        }

        if (!isWriteSideEffectObserved(before, replay, after)) {
            return null;
        }

        return new AttackExecutionFinding(
                suggestion.suggestionId() + "|write|" + entityId,
                "WRITE_OPERATION",
                SecurityFinding.RiskLevel.CRITICAL,
                true,
                defaultIfBlank(suggestion.method(), "Set"),
                entityId,
                contexts.sourceKey(),
                contexts.targetKey(),
                contexts.sourceRole(),
                contexts.targetRole(),
                mutated,
                replay.classification(),
                "Extract ID from read call then inject into write request under LOW_PRIV credentials.",
                "Write operation accepted foreign entity identifier under low-privileged context.",
                Instant.now()
        );
    }

    public AttackExecutionFinding testMultiCallExploit(
            AttackSuggestion suggestion,
            TemplateRequest template,
            AttackContexts contexts,
            AttackBudget budget
    ) {
        String mutated = template.rawRequest();
        String entityId = defaultIfBlank(suggestion.entityId(), "");
        if (!entityId.isBlank()) {
            mutated = RepeaterRequestMutator.mutateFirstMatchingValueInParams(mutated, 0, entityId, entityId);
        }

        if (contexts.targetContext() != null) {
            mutated = injectContextCredentials(mutated, contexts.targetContext());
        }

        List<String> variants = buildMultiCallVariants(mutated, entityId);
        ReplayOutcome bestReplay = ReplayOutcome.notExecuted("no_variant");
        for (String variant : variants) {
            if (!budget.hasRemaining()) {
                break;
            }
            ReplayOutcome replay = replayRequest(variant, template.target(), suggestion.method(), budget);
            if (!replay.executed()) {
                continue;
            }
            if ("success_with_data".equals(replay.classification())) {
                bestReplay = replay;
                mutated = variant;
                break;
            }
            bestReplay = replay;
        }

        if (!bestReplay.executed() || !"success_with_data".equals(bestReplay.classification())) {
            return null;
        }

        return new AttackExecutionFinding(
                suggestion.suggestionId() + "|multicall|" + entityId,
                "MULTICALL_EXPLOIT",
                SecurityFinding.RiskLevel.CRITICAL,
                true,
                defaultIfBlank(suggestion.method(), "ExecuteMultiCall"),
                entityId,
                contexts.sourceKey(),
                contexts.targetKey(),
                contexts.sourceRole(),
                contexts.targetRole(),
                mutated,
                bestReplay.classification(),
                "Replay ExecuteMultiCall chain with foreign ID/type values and detect hidden write or data-return side effects.",
                "ExecuteMultiCall chain returned data with unauthorized chained context.",
                Instant.now()
        );
    }

    public ReplayOutcome replayRequest(ReplayRequest plan) {
        if (plan == null) {
            return ReplayOutcome.notExecuted("missing_plan");
        }
        String host = defaultIfBlank(plan.host(), "").trim();
        int port = 443;
        boolean secure = true;
        int colon = host.lastIndexOf(':');
        if (colon > 0 && colon < host.length() - 1) {
            try {
                port = Integer.parseInt(host.substring(colon + 1).trim());
                secure = port != 80;
                host = host.substring(0, colon).trim();
            } catch (NumberFormatException ignored) {
                // keep defaults
            }
        }
        return replayRequest(plan.rawRequest(), new ReplayTarget(host, port, secure), plan.method(), plan.budget());
    }

    public static String classifyResponse(String responseBody, Integer statusCode) {
        if (responseBody == null || responseBody.isBlank()) {
            return "unknown";
        }

        ObjectMapper mapper = new ObjectMapper();
        JsonNode root;
        try {
            root = mapper.readTree(responseBody);
        } catch (Exception ignored) {
            return "unknown";
        }

        if (root == null || (!root.isObject() && !root.isArray())) {
            return "unknown";
        }

        if (root.isArray()) {
            if (root.isEmpty()) {
                return "success_empty";
            }
            root = root.get(0);
            if (root == null || !root.isObject()) {
                return "unknown";
            }
        }

        JsonNode error = root.path("error");
        if (!error.isMissingNode() && !error.isNull()) {
            String message = (error.path("message").asText("") + " " + error.path("data").asText(""))
                    .toLowerCase(Locale.ROOT);
            int code = error.path("code").asInt(0);
            if (message.contains("permission")
                    || message.contains("unauthor")
                    || message.contains("forbidden")
                    || message.contains("invaliduser")
                    || code == 401
                    || code == 403) {
                return "permission_error";
            }
            if (message.contains("validation")
                    || message.contains("invalid")
                    || message.contains("required")
                    || message.contains("malformed")
                    || (statusCode != null && statusCode == 400)) {
                return "validation_error";
            }
            return "unknown";
        }

        JsonNode result = root.path("result");
        if (result.isMissingNode()) {
            return "unknown";
        }
        if (result.isArray()) {
            return result.size() == 0 ? "success_empty" : "success_with_data";
        }
        if (result.isObject()) {
            return result.size() == 0 ? "success_empty" : "success_with_data";
        }
        if (result.isTextual()) {
            return result.asText("").isBlank() ? "success_empty" : "success_with_data";
        }
        if (result.isBoolean() || result.isNumber() || result.isNull()) {
            return result.isNull() ? "success_empty" : "success_with_data";
        }
        return "unknown";
    }

    private ReplayOutcome replayRequest(String rawRequest, ReplayTarget target, String method, AttackBudget budget) {
        if (rawRequest == null || rawRequest.isBlank()) {
            return ReplayOutcome.notExecuted("missing_request");
        }
        if (target == null || target.host() == null || target.host().isBlank() || !MyGeotabScope.isAllowedHost(target.host())) {
            return ReplayOutcome.notExecuted("host_not_allowed");
        }

        String replayKey = replayCacheKey(rawRequest, target, method);
        ReplayOutcome cached = replayCache.get(replayKey);
        if (cached != null) {
            return cached;
        }

        if (!budget.tryConsume()) {
            return ReplayOutcome.notExecuted("budget_exhausted");
        }

        try {
            ReplayResponse response = replayClient.send(target.host(), target.port(), target.secure(), rawRequest);
            String classification = classifyResponse(response.body(), response.statusCode());
            ReplayOutcome outcome = new ReplayOutcome(true, classification, response.body(), response.statusCode(), "");
            replayCache.putIfAbsent(replayKey, outcome);
            return outcome;
        } catch (Exception ex) {
            logging.logToError("[LogicHunter][ATTACK] replay failed method=" + defaultIfBlank(method, "unknown"), ex);
            return ReplayOutcome.notExecuted("replay_error");
        }
    }

    private TemplateRequest resolveTemplateRequest(AttackSuggestion suggestion, String contextKey) {
        String methodKey = defaultIfBlank(suggestion.method(), "") + ":" + defaultIfBlank(suggestion.typeName(), "Unknown");
        Optional<JsonRpcIndex.MethodDetails> details = index.snapshotMethodDetails(methodKey);
        if (details.isEmpty()) {
            return null;
        }

        for (JsonRpcRecord record : details.get().sampleRawRecords()) {
            if (record == null || record.request() == null) {
                continue;
            }
            String recordContext = authContextStore.contextKeyForRecord(record.recordId());
            if (!defaultIfBlank(recordContext, "").equals(defaultIfBlank(contextKey, ""))) {
                continue;
            }

            String raw = normalizeRawRequest(defaultIfBlank(record.request().rawHttpText(), ""));
            if (raw.isBlank()) {
                continue;
            }

            ReplayTarget target = deriveReplayTarget(raw, record.request().url(), suggestion.host());
            if (target == null) {
                continue;
            }
            return new TemplateRequest(raw, target);
        }

        return null;
    }

    private AttackContexts resolveContexts(AttackSuggestion suggestion) {
        Map<String, AuthContextStore.SessionView> byContextKey = new LinkedHashMap<>();
        for (AuthContextStore.SessionView view : authContextStore.snapshotSessions()) {
            byContextKey.put(defaultIfBlank(view.contextKey(), ""), view);
        }

        String sourceKey = "";
        String targetKey = defaultIfBlank(suggestion.sessionId(), "");

        Matcher matcher = ATTACK_PATH_CONTEXT_PATTERN.matcher(defaultIfBlank(suggestion.attackPath(), ""));
        if (matcher.find()) {
            sourceKey = defaultIfBlank(matcher.group(1), "").trim();
            if (targetKey.isBlank()) {
                targetKey = defaultIfBlank(matcher.group(2), "").trim();
            }
        }

        if (targetKey.isBlank() || !byContextKey.containsKey(targetKey)) {
            return new AttackContexts("", "", RoleType.UNKNOWN, RoleType.UNKNOWN, null, null);
        }
        if (sourceKey.isBlank() || !byContextKey.containsKey(sourceKey)) {
            return new AttackContexts("", "", RoleType.UNKNOWN, RoleType.UNKNOWN, null, null);
        }

        AuthContextStore.SessionView source = byContextKey.get(sourceKey);
        AuthContextStore.SessionView target = byContextKey.get(targetKey);

        RoleType sourceRole = source == null ? RoleType.UNKNOWN : source.role();
        RoleType targetRole = target == null ? RoleType.UNKNOWN : target.role();

        return new AttackContexts(sourceKey, targetKey, sourceRole, targetRole, source, target);
    }

    private String injectContextCredentials(String rawRequest, AuthContextStore.SessionView context) {
        String mutated = rawRequest;
        mutated = RepeaterRequestMutator.mutateCredentialField(mutated, 0, "database", defaultIfBlank(context.database(), ""));
        mutated = RepeaterRequestMutator.mutateCredentialField(mutated, 0, "sessionId", defaultIfBlank(context.sessionId(), ""));
        mutated = RepeaterRequestMutator.mutateCredentialField(mutated, 0, "userName", defaultIfBlank(context.userName(), ""));
        return mutated;
    }

    private boolean hasSufficientAuthMaterial(String rawRequest) {
        if (rawRequest == null || rawRequest.isBlank()) {
            return false;
        }
        String normalized = normalizeRawRequest(rawRequest);
        String lowered = normalized.toLowerCase(Locale.ROOT);
        boolean hasHeaderAuth = lowered.contains("\nhost:") && (lowered.contains("\ncookie:") || lowered.contains("\nauthorization:"));
        boolean hasBodyAuth = lowered.contains("\"credentials\"") && lowered.contains("\"sessionid\"");
        return hasHeaderAuth || hasBodyAuth;
    }

    private boolean isUnauthorizedExposure(ReplayOutcome owner, ReplayOutcome baseline, ReplayOutcome replay, String entityId) {
        if (!"success_with_data".equals(replay.classification())) {
            return false;
        }

        JsonNode replayJson = parseJson(replay.responseBody());
        JsonNode baselineJson = parseJson(baseline.responseBody());
        JsonNode ownerJson = parseJson(owner.responseBody());
        if (replayJson == null || baselineJson == null || ownerJson == null) {
            return false;
        }

        Set<String> replayIds = collectIds(replayJson, new LinkedHashSet<>(), 0);
        Set<String> baselineIds = collectIds(baselineJson, new LinkedHashSet<>(), 0);
        Set<String> ownerIds = collectIds(ownerJson, new LinkedHashSet<>(), 0);

        if (!entityId.isBlank() && replayIds.contains(entityId) && !baselineIds.contains(entityId)) {
            return true;
        }

        Set<String> sensitiveReplay = collectSensitiveFields(replayJson, new LinkedHashSet<>(), 0);
        Set<String> sensitiveBaseline = collectSensitiveFields(baselineJson, new LinkedHashSet<>(), 0);
        sensitiveReplay.removeAll(sensitiveBaseline);
        if (!sensitiveReplay.isEmpty()) {
            return true;
        }

        return !ownerIds.isEmpty() && replayIds.stream().anyMatch(id -> ownerIds.contains(id) && !baselineIds.contains(id));
    }

    private boolean isWriteSideEffectObserved(ReplayOutcome before, ReplayOutcome replay, ReplayOutcome after) {
        if (!replay.executed()) {
            return false;
        }
        if (!("success_with_data".equals(replay.classification()) || "success_empty".equals(replay.classification()))) {
            return false;
        }

        JsonNode beforeJson = parseJson(before.responseBody());
        JsonNode afterJson = parseJson(after.responseBody());
        if (beforeJson == null || afterJson == null) {
            return !defaultIfBlank(before.responseBody(), "").equals(defaultIfBlank(after.responseBody(), ""));
        }
        return !beforeJson.equals(afterJson);
    }

    private List<String> buildMultiCallVariants(String rawRequest, String entityId) {
        List<String> variants = new ArrayList<>();
        variants.add(rawRequest);

        String normalized = normalizeRawRequest(rawRequest);
        int split = normalized.indexOf("\r\n\r\n");
        if (split < 0) {
            split = normalized.indexOf("\n\n");
        }
        if (split < 0) {
            return variants;
        }

        String body = normalized.substring(split + (normalized.contains("\r\n\r\n") ? 4 : 2));
        JsonNode root = parseJson(body);
        if (root == null || !root.isObject()) {
            return variants;
        }

        JsonNode calls = root.path("params").path("calls");
        if (!calls.isArray()) {
            calls = root.path("params").path("requests");
        }
        if (!calls.isArray()) {
            calls = root.path("params").path("operations");
        }
        if (!calls.isArray()) {
            return variants;
        }

        for (int i = 0; i < calls.size(); i++) {
            String candidate = RepeaterRequestMutator.mutateFirstMatchingValueInParams(rawRequest, 0, entityId, entityId + "_mc" + i);
            if (!candidate.equals(rawRequest)) {
                variants.add(candidate);
            }
        }
        return variants;
    }

    private Set<String> collectSensitiveFields(JsonNode node, Set<String> out, int depth) {
        if (node == null || node.isNull() || node.isMissingNode() || depth > 8) {
            return out;
        }
        if (node.isObject()) {
            node.fields().forEachRemaining(entry -> {
                String key = defaultIfBlank(entry.getKey(), "").toLowerCase(Locale.ROOT);
                JsonNode value = entry.getValue();
                if ((key.contains("tenant") || key.contains("database") || key.contains("user") || key.contains("account") || key.contains("group") || key.contains("policy"))
                        && value != null
                        && value.isValueNode()) {
                    out.add(key + "=" + defaultIfBlank(value.asText(""), ""));
                }
                collectSensitiveFields(value, out, depth + 1);
            });
            return out;
        }
        if (node.isArray()) {
            for (JsonNode child : node) {
                collectSensitiveFields(child, out, depth + 1);
            }
        }
        return out;
    }

    private ReplayTarget deriveReplayTarget(String rawRequest, String requestUrl, String suggestionHost) {
        String hostHeader = extractHostFromRawRequest(rawRequest);
        int portFromHost = extractPortFromRawRequestHost(rawRequest);
        if (!hostHeader.isBlank()) {
            return new ReplayTarget(hostHeader, portFromHost > 0 ? portFromHost : 443, portFromHost != 80);
        }

        String url = defaultIfBlank(requestUrl, "");
        if (!url.isBlank()) {
            try {
                URI uri = URI.create(url);
                String host = defaultIfBlank(uri.getHost(), "");
                if (!host.isBlank()) {
                    boolean secure = "https".equalsIgnoreCase(uri.getScheme());
                    int port = uri.getPort() > 0 ? uri.getPort() : (secure ? 443 : 80);
                    return new ReplayTarget(host, port, secure);
                }
            } catch (Exception ignored) {
                // no-op
            }
        }

        String fallbackHost = defaultIfBlank(suggestionHost, "");
        if (!fallbackHost.isBlank()) {
            return new ReplayTarget(fallbackHost, 443, true);
        }
        return null;
    }

    private static int extractPortFromRawRequestHost(String rawRequest) {
        if (rawRequest == null || rawRequest.isBlank()) {
            return -1;
        }
        String normalized = rawRequest.replace("\\r\\n", "\r\n");
        String[] lines = normalized.split("\\r?\\n");
        for (String line : lines) {
            if (line == null || line.isBlank()) {
                break;
            }
            if (!line.toLowerCase(Locale.ROOT).startsWith("host:")) {
                continue;
            }
            String hostPort = line.substring(line.indexOf(':') + 1).trim();
            int colon = hostPort.lastIndexOf(':');
            if (colon > 0 && colon < hostPort.length() - 1) {
                try {
                    return Integer.parseInt(hostPort.substring(colon + 1).trim());
                } catch (NumberFormatException ignored) {
                    return -1;
                }
            }
            return -1;
        }
        return -1;
    }

    private String replayCacheKey(String rawRequest, ReplayTarget target, String method) {
        return defaultIfBlank(method, "") + "|" + target.host() + "|" + target.port() + "|" + target.secure() + "|" + Integer.toHexString(defaultIfBlank(rawRequest, "").hashCode());
    }

    private boolean isLeakComparedToBaseline(ReplayOutcome baseline, ReplayOutcome candidate) {
        if (!"success_with_data".equals(candidate.classification())) {
            return false;
        }

        JsonNode base = parseJson(baseline.responseBody());
        JsonNode mutated = parseJson(candidate.responseBody());
        if (base == null || mutated == null) {
            return candidate.responseBody().length() > baseline.responseBody().length() + 40;
        }

        int baseCount = countResultNodes(base);
        int candidateCount = countResultNodes(mutated);
        if (candidateCount > baseCount) {
            return true;
        }

        Set<String> baselineIds = collectIds(base, new LinkedHashSet<>(), 0);
        Set<String> candidateIds = collectIds(mutated, new LinkedHashSet<>(), 0);
        candidateIds.removeAll(baselineIds);
        return !candidateIds.isEmpty();
    }

    private AttackExecutionFinding selectBest(List<AttackExecutionFinding> findings) {
        if (findings.isEmpty()) {
            return null;
        }

        List<AttackExecutionFinding> sorted = new ArrayList<>(findings);
        sorted.sort(Comparator
                .comparing(AttackExecutionFinding::confirmed).reversed()
                .thenComparing((AttackExecutionFinding item) -> item.severity().ordinal(), Comparator.reverseOrder())
                .thenComparing(AttackExecutionFinding::category));
        return sorted.get(0);
    }

    private AttackExecutionFinding buildRejectedFinding(AttackSuggestion suggestion, AttackContexts contexts, String reason) {
        return new AttackExecutionFinding(
                suggestion.suggestionId() + "|rejected",
                "VALIDATION",
                SecurityFinding.RiskLevel.LOW,
                false,
                defaultIfBlank(suggestion.method(), "Get"),
                defaultIfBlank(suggestion.entityId(), ""),
                contexts.sourceKey(),
                contexts.targetKey(),
                contexts.sourceRole(),
                contexts.targetRole(),
                "",
                "unknown",
                "Replay budget exhausted or no unauthorized response observed.",
                reason,
                Instant.now()
        );
    }

    private static String extractHostFromRawRequest(String rawRequest) {
        if (rawRequest == null || rawRequest.isBlank()) {
            return "";
        }

        String normalized = rawRequest.replace("\\r\\n", "\r\n");
        String[] lines = normalized.split("\\r?\\n");
        for (String line : lines) {
            if (line == null || line.isBlank()) {
                break;
            }
            if (!line.toLowerCase(Locale.ROOT).startsWith("host:")) {
                continue;
            }
            String hostPort = line.substring(line.indexOf(':') + 1).trim();
            int colon = hostPort.indexOf(':');
            return colon > 0 ? hostPort.substring(0, colon).trim() : hostPort;
        }
        return "";
    }

    private static String normalizeRawRequest(String raw) {
        if (raw == null || raw.isBlank()) {
            return "";
        }
        return raw.contains("\\r\\n") && !raw.contains("\r\n")
                ? raw.replace("\\r\\n", "\r\n")
                : raw;
    }

    private static boolean isMultiCallMethod(String method, String requestBody) {
        String loweredMethod = defaultIfBlank(method, "").toLowerCase(Locale.ROOT);
        if (loweredMethod.contains("multicall")) {
            return true;
        }
        return defaultIfBlank(requestBody, "").toLowerCase(Locale.ROOT).contains("executemulticall");
    }

    private static boolean isWriteLikeMethod(String method) {
        String lowered = defaultIfBlank(method, "").toLowerCase(Locale.ROOT);
        return lowered.startsWith("set")
                || lowered.startsWith("update")
                || lowered.startsWith("delete")
                || lowered.startsWith("add")
                || lowered.startsWith("remove")
                || lowered.contains("write")
                || lowered.contains("save")
                || lowered.contains("execute");
    }

    private static boolean isDestructiveMethod(String method) {
        String lowered = defaultIfBlank(method, "").toLowerCase(Locale.ROOT);
        return lowered.startsWith("delete")
                || lowered.startsWith("remove")
                || lowered.contains("purge")
                || lowered.contains("drop");
    }

    private JsonNode parseJson(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return objectMapper.readTree(value);
        } catch (Exception ignored) {
            return null;
        }
    }

    private int countResultNodes(JsonNode node) {
        JsonNode result = node.path("result");
        if (result.isArray()) {
            return result.size();
        }
        if (result.isObject()) {
            return result.size();
        }
        if (!result.isMissingNode() && !result.isNull()) {
            return 1;
        }
        return 0;
    }

    private Set<String> collectIds(JsonNode node, Set<String> out, int depth) {
        if (node == null || node.isNull() || node.isMissingNode() || depth > 8) {
            return out;
        }

        if (node.isObject()) {
            node.fields().forEachRemaining(entry -> {
                String key = defaultIfBlank(entry.getKey(), "").toLowerCase(Locale.ROOT);
                JsonNode value = entry.getValue();
                if (("id".equals(key) || key.endsWith("id") || key.contains("_id")) && value != null && value.isValueNode()) {
                    String id = defaultIfBlank(value.asText(""), "").trim();
                    if (!id.isBlank()) {
                        out.add(id);
                    }
                }
                collectIds(value, out, depth + 1);
            });
            return out;
        }

        if (node.isArray()) {
            for (JsonNode child : node) {
                collectIds(child, out, depth + 1);
            }
        }

        return out;
    }

    private static String defaultIfBlank(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }

    public interface ReplayClient {
        ReplayResponse send(String host, int port, boolean secure, String rawRequest);
    }

    public record ReplayRequest(String rawRequest, String host, String method, AttackBudget budget) {
    }

    private record TemplateRequest(String rawRequest, ReplayTarget target) {
    }

    private record ReplayTarget(String host, int port, boolean secure) {
    }

    public record ReplayResponse(Integer statusCode, String body, String rawResponse) {
    }

    public record ReplayOutcome(boolean executed, String classification, String responseBody, Integer statusCode, String reason) {
        public static ReplayOutcome notExecuted(String reason) {
            return new ReplayOutcome(false, "unknown", "", null, reason);
        }
    }

    public static final class AttackBudget {
        private int remaining;

        public AttackBudget(int total) {
            this.remaining = Math.max(0, total);
        }

        public synchronized boolean hasRemaining() {
            return remaining > 0;
        }

        public synchronized boolean tryConsume() {
            if (remaining <= 0) {
                return false;
            }
            remaining--;
            return true;
        }

        public synchronized int remaining() {
            return remaining;
        }
    }

    public record AttackContexts(
            String sourceKey,
            String targetKey,
            RoleType sourceRole,
            RoleType targetRole,
            AuthContextStore.SessionView sourceContext,
            AuthContextStore.SessionView targetContext
    ) {
        private boolean isComplete() {
            return sourceContext != null
                && targetContext != null
                && sourceKey != null
                && targetKey != null
                && !sourceKey.isBlank()
                && !targetKey.isBlank();
        }
    }
}
