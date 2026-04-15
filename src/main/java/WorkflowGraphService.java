import burp.api.montoya.logging.Logging;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.nio.charset.StandardCharsets;
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
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

public final class WorkflowGraphService implements AutoCloseable {
    private static final int MAX_VALUE_INDEX_SIZE = 20_000;
    private static final int MAX_PRODUCERS_PER_VALUE = 24;
    private static final int MAX_PRODUCER_MATCHES_PER_REQUEST_VALUE = 8;
    private static final int MAX_RECENT_RECORDS = 1_800;
    private static final int MAX_EDGE_SAMPLES = 12;

    private static final int MAX_CHAIN_DEPTH = 4;
    private static final int MAX_CHAIN_BRANCHING = 4;
    private static final int MAX_CHAIN_RESULTS = 40;

    private static final long NOTIFY_INTERVAL_MILLIS = 500L;

    private static final Pattern UUID_PATTERN = Pattern.compile("(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$");
    private static final Pattern EMAIL_PATTERN = Pattern.compile("(?i)^[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}$");
    private static final Pattern URL_PATTERN = Pattern.compile("(?i)^https?://");

    private static final List<String> SENSITIVE_TERMS = List.of(
            "admin", "security", "permission", "tenant", "billing", "order",
            "account", "token", "session", "export", "report", "device"
    );

    private final ObjectMapper objectMapper;
    private final Logging logging;
    private final AuthContextStore authContextStore;

    private final ExecutorService analyzerExecutor = Executors.newSingleThreadExecutor(
            runnable -> new Thread(runnable, "jsonrpc-workflow-graph")
    );
    private final List<Runnable> updateListeners = new CopyOnWriteArrayList<>();
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final AtomicLong lastUiNotificationEpochMillis = new AtomicLong(0L);

    private final Object stateLock = new Object();
    private final Map<String, MethodNodeState> methodStates = new HashMap<>();
    private final Map<String, WorkflowEdgeState> edgeStates = new HashMap<>();
    private final LinkedHashMap<String, ArrayDeque<ProducerObservation>> responseProducersByValue;
    private final LinkedHashMap<String, JsonRpcRecord> recentRecords;
    private Map<String, ChainCandidate> lastChainCandidates = new HashMap<>();

    public WorkflowGraphService(ObjectMapper objectMapper, Logging logging) {
        this(objectMapper, logging, null);
    }

    public WorkflowGraphService(ObjectMapper objectMapper, Logging logging, AuthContextStore authContextStore) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
        this.logging = Objects.requireNonNull(logging, "logging must not be null");
        this.authContextStore = authContextStore;

        this.responseProducersByValue = new LinkedHashMap<>(256, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, ArrayDeque<ProducerObservation>> eldest) {
                return size() > MAX_VALUE_INDEX_SIZE;
            }
        };

        this.recentRecords = new LinkedHashMap<>(256, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, JsonRpcRecord> eldest) {
                return size() > MAX_RECENT_RECORDS;
            }
        };
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
                logging.logToError("Workflow graph analysis failed while processing record.", ex);
            }
        });
    }

    void ingestRecordSync(JsonRpcRecord rawRecord, JsonRpcNormalizedRecord normalizedRecord) {
        if (rawRecord == null || normalizedRecord == null) {
            return;
        }

        String contextKey = authContextStore == null
                ? contextKeyFromRecord(rawRecord)
                : authContextStore.observeRecord(rawRecord, normalizedRecord.methodName()).contextKey();

        List<ValueOccurrence> requestValues = attachRecordId(
            extractValueOccurrences(rawRecord.request().bodyText(), PayloadOrigin.REQUEST),
            rawRecord.recordId()
        );
        List<ValueOccurrence> responseValues = attachRecordId(
            extractValueOccurrences(rawRecord.response().bodyText(), PayloadOrigin.RESPONSE),
            rawRecord.recordId()
        );

        synchronized (stateLock) {
            MethodNodeState methodState = methodStates.computeIfAbsent(normalizedRecord.methodName(), MethodNodeState::new);
            methodState.observe(normalizedRecord.timestamp(), requestValues, responseValues, contextKey);

            recentRecords.put(rawRecord.recordId(), rawRecord);

            for (ValueOccurrence requestOccurrence : requestValues) {
                ArrayDeque<ProducerObservation> producers = responseProducersByValue.get(requestOccurrence.canonicalValue);
                if (producers == null || producers.isEmpty()) {
                    continue;
                }

                int matched = 0;
                Iterator<ProducerObservation> iterator = producers.descendingIterator();
                while (iterator.hasNext()) {
                    ProducerObservation producer = iterator.next();
                    if (producer.recordId.equals(rawRecord.recordId())) {
                        continue;
                    }

                        String edgeId = edgeId(producer.methodName, producer.contextKey, normalizedRecord.methodName(), contextKey);
                    WorkflowEdgeState edge = edgeStates.computeIfAbsent(
                            edgeId,
                            ignored -> new WorkflowEdgeState(
                                producer.methodName,
                                producer.contextKey,
                                normalizedRecord.methodName(),
                                contextKey
                            )
                    );
                    edge.observe(producer, requestOccurrence, rawRecord.timestamp());

                    matched++;
                    if (matched >= MAX_PRODUCER_MATCHES_PER_REQUEST_VALUE) {
                        break;
                    }
                }
            }

            for (ValueOccurrence responseOccurrence : responseValues) {
                ArrayDeque<ProducerObservation> queue = responseProducersByValue.computeIfAbsent(
                        responseOccurrence.canonicalValue,
                        ignored -> new ArrayDeque<>()
                );
                queue.addLast(new ProducerObservation(
                        normalizedRecord.methodName(),
                    contextKey,
                        rawRecord.recordId(),
                        responseOccurrence.path,
                        responseOccurrence.keyName,
                        responseOccurrence.entityTag,
                        responseOccurrence.preview,
                        rawRecord.timestamp()
                ));

                while (queue.size() > MAX_PRODUCERS_PER_VALUE) {
                    queue.removeFirst();
                }
            }
        }
    }

    public WorkflowGraphSnapshot snapshot() {
        synchronized (stateLock) {
            SnapshotComputation computation = computeSnapshot();
            lastChainCandidates = computation.chainCandidatesById;
            return computation.snapshot;
        }
    }

    public ObjectNode buildChainExportBundle(String chainId) {
        synchronized (stateLock) {
            if (lastChainCandidates.isEmpty()) {
                SnapshotComputation computation = computeSnapshot();
                lastChainCandidates = computation.chainCandidatesById;
            }

            ChainCandidate chain = lastChainCandidates.get(chainId);
            if (chain == null) {
                throw new IllegalArgumentException("Unknown chain ID: " + chainId);
            }

            ObjectNode root = objectMapper.createObjectNode();
            root.put("generatedAt", Instant.now().toString());
            root.put("mode", "manual-only");
            root.put("chainId", chain.chainId);
            root.put("chainPath", chain.path);
            root.put("score", chain.score);
            root.put("steps", chain.steps());
            root.put("highlights", chain.highlights);
            root.put("rationale", chain.rationale);
            root.put("note", "Passive workflow correlation only. This export does not send any requests.");

            ArrayNode methodArray = objectMapper.createArrayNode();
            for (String method : chain.methods) {
                methodArray.add(method);
            }
            root.set("methods", methodArray);

            ArrayNode edgeArray = objectMapper.createArrayNode();
            for (String edgeId : chain.edgeIds) {
                WorkflowEdgeState edge = edgeStates.get(edgeId);
                if (edge == null) {
                    continue;
                }

                ObjectNode edgeNode = objectMapper.createObjectNode();
                edgeNode.put("edgeId", edgeId);
                edgeNode.put("sourceMethod", edge.sourceMethod);
                edgeNode.put("sourceContext", edge.sourceContext);
                edgeNode.put("targetMethod", edge.targetMethod);
                edgeNode.put("targetContext", edge.targetContext);
                edgeNode.put("correlations", edge.correlationCount);
                edgeNode.put("entityHighlights", edge.entityHighlights());
                edgeNode.put("sharedValues", String.join(", ", edge.sharedValueExamples));
                edgeNode.put("linkagePaths", String.join(", ", edge.pathLinkExamples));
                edgeNode.put("firstSeen", edge.firstSeen == null ? "" : edge.firstSeen.toString());
                edgeNode.put("lastSeen", edge.lastSeen == null ? "" : edge.lastSeen.toString());

                ArrayNode sampleArray = objectMapper.createArrayNode();
                for (EdgeSample sample : edge.samples) {
                    ObjectNode sampleNode = objectMapper.createObjectNode();
                    sampleNode.put("timestamp", sample.timestamp.toString());
                    sampleNode.put("sharedValue", sample.sharedValuePreview);
                    sampleNode.put("entityTag", sample.entityTag.displayName);
                    sampleNode.put("producerResponsePath", sample.producerPath);
                    sampleNode.put("consumerRequestPath", sample.consumerPath);

                    JsonRpcRecord sourceRecord = recentRecords.get(sample.producerRecordId);
                    JsonRpcRecord targetRecord = recentRecords.get(sample.consumerRecordId);

                    sampleNode.set("sourceRecord", recordToExport(sourceRecord, sample.producerRecordId));
                    sampleNode.set("targetRecord", recordToExport(targetRecord, sample.consumerRecordId));
                    sampleArray.add(sampleNode);
                }
                edgeNode.set("samples", sampleArray);

                edgeArray.add(edgeNode);
            }
            root.set("edges", edgeArray);

            ArrayNode reviewHints = objectMapper.createArrayNode();
            reviewHints.add("Check whether identifiers from earlier responses are accepted without ownership validation in later methods.");
            reviewHints.add("Review whether tenant/user/account IDs can be swapped across contexts in this chain.");
            reviewHints.add("Inspect privileged-looking endpoints in the chain for missing role checks.");
            reviewHints.add("Validate server trust boundaries when client-supplied IDs appear to drive backend object access.");
            root.set("reviewHints", reviewHints);

            return root;
        }
    }

    public void clear() {
        synchronized (stateLock) {
            methodStates.clear();
            edgeStates.clear();
            responseProducersByValue.clear();
            recentRecords.clear();
            lastChainCandidates = new HashMap<>();
        }
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

    private SnapshotComputation computeSnapshot() {
        Map<String, Integer> inDegrees = new HashMap<>();
        Map<String, Integer> outDegrees = new HashMap<>();
        Map<String, Long> weightedConnections = new HashMap<>();
        long totalCorrelations = 0;

        for (WorkflowEdgeState edge : edgeStates.values()) {
            outDegrees.merge(edge.sourceMethod, 1, Integer::sum);
            inDegrees.merge(edge.targetMethod, 1, Integer::sum);
            weightedConnections.merge(edge.sourceMethod, edge.correlationCount, Long::sum);
            weightedConnections.merge(edge.targetMethod, edge.correlationCount, Long::sum);
            totalCorrelations += edge.correlationCount;
        }

        List<MethodNodeView> allNodes = new ArrayList<>();
        for (MethodNodeState state : methodStates.values()) {
            int inDegree = inDegrees.getOrDefault(state.methodName, 0);
            int outDegree = outDegrees.getOrDefault(state.methodName, 0);
            long weighted = weightedConnections.getOrDefault(state.methodName, 0L);

            boolean entryPoint = (inDegree == 0 && outDegree > 0) || (inDegree <= 1 && outDegree >= 2);
            boolean privileged = state.sensitiveName || state.entityTags.contains(EntityTag.TENANT_ID)
                    || state.entityTags.contains(EntityTag.ACCOUNT_ID)
                    || state.entityTags.contains(EntityTag.USER_ID);

            allNodes.add(new MethodNodeView(
                    state.methodName,
                    state.observations,
                    inDegree,
                    outDegree,
                    weighted,
                    entryPoint,
                    privileged,
                    summarizeEntityTags(state.entityTags),
                    state.contextKeys.size(),
                    state.firstSeen,
                    state.lastSeen
            ));
        }

        allNodes.sort(Comparator
                .comparingLong(MethodNodeView::weightedConnections).reversed()
                .thenComparingInt(MethodNodeView::outDegree).reversed()
                .thenComparing(MethodNodeView::methodName, String.CASE_INSENSITIVE_ORDER));

        List<MethodNodeView> topConnected = allNodes.size() <= 20
                ? List.copyOf(allNodes)
                : List.copyOf(allNodes.subList(0, 20));

        List<EdgeView> edgeViews = new ArrayList<>();
        for (Map.Entry<String, WorkflowEdgeState> entry : edgeStates.entrySet()) {
            WorkflowEdgeState edge = entry.getValue();
            edgeViews.add(new EdgeView(
                    entry.getKey(),
                    edge.sourceMethod,
                    edge.sourceContext,
                    edge.targetMethod,
                    edge.targetContext,
                    edge.correlationCount,
                    edge.entityHighlights(),
                    String.join(", ", edge.sharedValueExamples),
                    String.join(", ", edge.pathLinkExamples),
                    edge.firstSeen,
                    edge.lastSeen
            ));
        }

        edgeViews.sort(Comparator
                .comparingLong(EdgeView::correlations).reversed()
                .thenComparing(EdgeView::lastSeen, Comparator.nullsLast(Comparator.reverseOrder()))
                .thenComparing(EdgeView::sourceMethod, String.CASE_INSENSITIVE_ORDER)
                .thenComparing(EdgeView::targetMethod, String.CASE_INSENSITIVE_ORDER));

        ChainComputation chainComputation = buildChains(allNodes);

        WorkflowGraphSnapshot snapshot = new WorkflowGraphSnapshot(
                methodStates.size(),
                edgeStates.size(),
                totalCorrelations,
                topConnected,
                edgeViews,
                chainComputation.chainViews
        );

        return new SnapshotComputation(snapshot, chainComputation.chainsById);
    }

    private ChainComputation buildChains(List<MethodNodeView> sortedNodes) {
        Map<String, List<WorkflowEdgeState>> outgoing = new HashMap<>();
        for (WorkflowEdgeState edge : edgeStates.values()) {
            outgoing.computeIfAbsent(edge.sourceMethod, ignored -> new ArrayList<>()).add(edge);
        }

        for (List<WorkflowEdgeState> list : outgoing.values()) {
            list.sort(Comparator.comparingLong(WorkflowEdgeState::scoreWeight).reversed());
        }

        List<String> starts = new ArrayList<>();
        for (MethodNodeView node : sortedNodes) {
            if (node.entryPoint()) {
                starts.add(node.methodName());
            }
        }

        if (starts.isEmpty()) {
            for (int i = 0; i < Math.min(8, sortedNodes.size()); i++) {
                starts.add(sortedNodes.get(i).methodName());
            }
        }

        Map<String, ChainCandidate> deduplicated = new LinkedHashMap<>();

        for (String start : starts) {
            List<String> methods = new ArrayList<>();
            methods.add(start);
            dfsChains(start, null, outgoing, methods, new ArrayList<>(), 0L, new TreeSet<>(), new TreeSet<>(), deduplicated);
        }

        List<ChainCandidate> chains = new ArrayList<>(deduplicated.values());
        chains.sort(Comparator
                .comparingLong(ChainCandidate::score).reversed()
                .thenComparingInt(ChainCandidate::steps).reversed()
                .thenComparing(ChainCandidate::path, String.CASE_INSENSITIVE_ORDER));

        if (chains.size() > MAX_CHAIN_RESULTS) {
            chains = new ArrayList<>(chains.subList(0, MAX_CHAIN_RESULTS));
        }

        Map<String, ChainCandidate> byId = new HashMap<>();
        List<ChainView> views = new ArrayList<>();

        for (ChainCandidate chain : chains) {
            byId.put(chain.chainId, chain);
            views.add(new ChainView(
                    chain.chainId,
                    chain.path,
                    chain.steps(),
                    chain.score,
                    chain.highlights,
                    chain.rationale,
                    List.copyOf(chain.methods),
                    List.copyOf(chain.edgeIds)
            ));
        }

        return new ChainComputation(byId, views);
    }

    private void dfsChains(
            String current,
            String currentContext,
            Map<String, List<WorkflowEdgeState>> outgoing,
            List<String> methods,
            List<String> edgeIds,
            long score,
            Set<EntityTag> highlights,
            Set<String> visitedContextNodes,
            Map<String, ChainCandidate> deduplicated
    ) {
        if (!edgeIds.isEmpty()) {
            String path = buildContextAwarePath(methods, edgeIds);
            String key = String.join("||", edgeIds);
            String chainId = shortHash(key + "|" + score);
            ChainCandidate candidate = new ChainCandidate(
                    chainId,
                    path,
                    new ArrayList<>(methods),
                    new ArrayList<>(edgeIds),
                    score,
                    summarizeEntityTags(highlights),
                    "Values observed in earlier responses are reused by subsequent requests across this chain."
            );

            ChainCandidate previous = deduplicated.get(key);
            if (previous == null || previous.score < candidate.score) {
                deduplicated.put(key, candidate);
            }
        }

        if (edgeIds.size() >= MAX_CHAIN_DEPTH) {
            return;
        }

        List<WorkflowEdgeState> nextEdges = outgoing.getOrDefault(current, List.of());
        int branchCount = 0;

        for (WorkflowEdgeState edge : nextEdges) {
            if (currentContext != null && !currentContext.equals(edge.sourceContext)) {
                continue;
            }

            String targetContextNode = edge.targetMethod + "|" + edge.targetContext;
            if (visitedContextNodes.contains(targetContextNode)) {
                continue;
            }

            branchCount++;
            if (branchCount > MAX_CHAIN_BRANCHING) {
                break;
            }

            methods.add(edge.targetMethod);
            String nextEdgeId = edgeId(edge.sourceMethod, edge.sourceContext, edge.targetMethod, edge.targetContext);
            edgeIds.add(nextEdgeId);
            visitedContextNodes.add(targetContextNode);

            Set<EntityTag> nextHighlights = new TreeSet<>(highlights);
            nextHighlights.addAll(edge.entityTagCounts.keySet());

            long nextScore = score + edge.scoreWeight();
            dfsChains(edge.targetMethod, edge.targetContext, outgoing, methods, edgeIds, nextScore, nextHighlights,
                    visitedContextNodes, deduplicated);

            methods.remove(methods.size() - 1);
            edgeIds.remove(edgeIds.size() - 1);
            visitedContextNodes.remove(targetContextNode);
        }
    }

    private String buildContextAwarePath(List<String> methods, List<String> edgeIds) {
        if (edgeIds.isEmpty()) {
            return String.join(" -> ", methods);
        }

        WorkflowEdgeState firstEdge = edgeStates.get(edgeIds.get(0));
        if (firstEdge == null) {
            return String.join(" -> ", methods);
        }

        StringBuilder builder = new StringBuilder();
        builder.append(firstEdge.sourceMethod).append(" [").append(firstEdge.sourceContext).append("]");
        for (String edgeId : edgeIds) {
            WorkflowEdgeState edge = edgeStates.get(edgeId);
            if (edge == null) {
                continue;
            }
            builder.append(" -> ").append(edge.targetMethod).append(" [").append(edge.targetContext).append("]");
        }

        return builder.toString();
    }

    private ObjectNode recordToExport(JsonRpcRecord record, String recordIdFallback) {
        ObjectNode node = objectMapper.createObjectNode();
        if (record == null) {
            node.put("recordId", recordIdFallback == null ? "" : recordIdFallback);
            node.put("available", false);
            return node;
        }

        node.put("recordId", record.recordId());
        node.put("available", true);
        node.put("timestamp", record.timestamp().toString());
        node.put("tool", record.toolName());

        ObjectNode requestNode = objectMapper.createObjectNode();
        requestNode.put("url", record.request().url());
        requestNode.put("httpMethod", record.request().httpMethod());
        requestNode.put("rawHttp", truncate(record.request().rawHttpText(), 12_000));
        requestNode.put("body", truncate(record.request().bodyText(), 8_000));
        node.set("request", requestNode);

        ObjectNode responseNode = objectMapper.createObjectNode();
        responseNode.put("present", record.response().present());
        responseNode.put("status", record.response().statusCode() == null ? -1 : record.response().statusCode());
        responseNode.put("rawHttp", truncate(record.response().rawHttpText(), 12_000));
        responseNode.put("body", truncate(record.response().bodyText(), 8_000));
        node.set("response", responseNode);

        return node;
    }

    private List<ValueOccurrence> extractValueOccurrences(String jsonBody, PayloadOrigin origin) {
        if (jsonBody == null || jsonBody.isBlank()) {
            return List.of();
        }

        final JsonNode root;
        try {
            root = objectMapper.readTree(jsonBody);
        } catch (Exception ignored) {
            return List.of();
        }

        List<ValueOccurrence> result = new ArrayList<>();
        visitNode(root, "$", "", origin, result);
        return result;
    }

    private static List<ValueOccurrence> attachRecordId(List<ValueOccurrence> occurrences, String recordId) {
        if (occurrences.isEmpty()) {
            return occurrences;
        }

        List<ValueOccurrence> withIds = new ArrayList<>(occurrences.size());
        for (ValueOccurrence occurrence : occurrences) {
            withIds.add(occurrence.withRecordId(recordId));
        }
        return withIds;
    }

    private void visitNode(JsonNode node, String path, String keyName, PayloadOrigin origin, List<ValueOccurrence> out) {
        if (node == null) {
            return;
        }

        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                String childKey = field.getKey();
                JsonNode child = field.getValue();
                String childPath = "$".equals(path) ? "$." + childKey : path + "." + childKey;

                addOccurrenceIfCandidate(child, childPath, childKey, origin, out);
                visitNode(child, childPath, childKey, origin, out);
            }
            return;
        }

        if (node.isArray()) {
            for (int i = 0; i < node.size(); i++) {
                JsonNode child = node.get(i);
                String childPath = path + "[" + i + "]";
                String arrayKeyName = keyName.isBlank() ? "array" : keyName + "[]";

                addOccurrenceIfCandidate(child, childPath, arrayKeyName, origin, out);
                visitNode(child, childPath, arrayKeyName, origin, out);
            }
        }
    }

    private void addOccurrenceIfCandidate(
            JsonNode node,
            String path,
            String keyName,
            PayloadOrigin origin,
            List<ValueOccurrence> out
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
            String canonical = canonicalizeScalar(node, keyName, path, origin);
            if (canonical == null) {
                return;
            }
            EntityTag entityTag = classifyEntityTag(keyName, path, canonical);
            out.add(new ValueOccurrence(canonical, preview(canonical), path, keyName, entityTag));
            return;
        }

        if ((node.isObject() || node.isArray()) && shouldTrackObjectReference(keyName, node)) {
            String serialized = node.toString();
            String canonical = "objref:" + shortHash(serialized);
            out.add(new ValueOccurrence(canonical, "object-ref:" + shortHash(serialized), path, keyName, EntityTag.OBJECT_REFERENCE));
        }
    }

    private String canonicalizeScalar(JsonNode node, String keyName, String path, PayloadOrigin origin) {
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

        String loweredKey = keyName == null ? "" : keyName.toLowerCase(Locale.ROOT);
        boolean idLikeKey = isIdLikeKey(loweredKey);

        if (!idLikeKey && raw.length() < 4 && !looksNumeric(raw)) {
            return null;
        }

        if (!idLikeKey && raw.contains(" ") && !URL_PATTERN.matcher(raw).find() && !EMAIL_PATTERN.matcher(raw).find()) {
            return null;
        }

        String canonical = raw;
        if (EMAIL_PATTERN.matcher(canonical).matches()) {
            canonical = canonical.toLowerCase(Locale.ROOT);
        }

        if (canonical.length() > 200) {
            canonical = "hash:" + shortHash(canonical);
        }

        if (!idLikeKey && !looksStructuredIdentifier(canonical) && origin == PayloadOrigin.REQUEST && path.endsWith(".name")) {
            return null;
        }

        return canonical;
    }

    private boolean shouldTrackObjectReference(String keyName, JsonNode node) {
        if (keyName == null || keyName.isBlank()) {
            return false;
        }

        String lowered = keyName.toLowerCase(Locale.ROOT);
        boolean referenceHint = lowered.contains("ref") || lowered.contains("object") || lowered.contains("item");
        if (!referenceHint) {
            return false;
        }

        if (node.isObject()) {
            return node.size() > 0 && node.size() <= 12;
        }
        if (node.isArray()) {
            return node.size() > 0 && node.size() <= 8;
        }
        return false;
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

    private static boolean looksNumeric(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (!(Character.isDigit(c) || c == '-' || c == '.')) {
                return false;
            }
        }
        return !value.isBlank();
    }

    private static boolean looksStructuredIdentifier(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }

        if (UUID_PATTERN.matcher(value).matches()) {
            return true;
        }

        if (value.length() >= 8 && value.chars().allMatch(c -> Character.isLetterOrDigit(c) || c == '-' || c == '_' || c == ':')) {
            return true;
        }

        return value.contains("-") || value.contains("_") || value.contains(":") || value.contains("/");
    }

    private static EntityTag classifyEntityTag(String keyName, String path, String value) {
        String lowered = keyName == null ? "" : keyName.toLowerCase(Locale.ROOT);

        if (lowered.contains("tenant") || lowered.contains("organization") || lowered.contains("org")) {
            return EntityTag.TENANT_ID;
        }
        if (lowered.contains("user") || lowered.contains("email") || lowered.contains("login")) {
            return EntityTag.USER_ID;
        }
        if (lowered.contains("report")) {
            return EntityTag.REPORT_ID;
        }
        if (lowered.contains("device")) {
            return EntityTag.DEVICE_ID;
        }
        if (lowered.contains("order")) {
            return EntityTag.ORDER_ID;
        }
        if (lowered.contains("account") || lowered.contains("billing") || lowered.contains("customer")) {
            return EntityTag.ACCOUNT_ID;
        }
        if (lowered.contains("ref") || lowered.contains("object")) {
            return EntityTag.OBJECT_REFERENCE;
        }
        if (isIdLikeKey(lowered) || path.endsWith(".id") || path.contains("_id")) {
            return EntityTag.ENTITY_ID;
        }

        if (looksStructuredIdentifier(value)) {
            return EntityTag.ENTITY_ID;
        }

        return EntityTag.OTHER;
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
                logging.logToError("Workflow graph listener failed.", ex);
            }
        }
    }

    private static String edgeId(String sourceMethod, String sourceContext, String targetMethod, String targetContext) {
        return sourceMethod + " [" + sourceContext + "] -> " + targetMethod + " [" + targetContext + "]";
    }

    private static String contextKeyFromRecord(JsonRpcRecord rawRecord) {
        if (rawRecord == null || rawRecord.request() == null) {
            return "unknown-context";
        }

        String host = MyGeotabScope.extractHost(rawRecord.request().url());
        String cookieFingerprint = "none";
        for (String header : rawRecord.request().headers()) {
            if (header != null && header.toLowerCase(Locale.ROOT).startsWith("cookie:")) {
                cookieFingerprint = shortHash(header);
                break;
            }
        }

        return "host=" + (host == null || host.isBlank() ? "unknown" : host)
                + "|cookie=" + cookieFingerprint;
    }

    private static String summarizeEntityTags(Set<EntityTag> entityTags) {
        List<String> labels = new ArrayList<>();
        for (EntityTag tag : entityTags) {
            if (tag == EntityTag.OTHER) {
                continue;
            }
            labels.add(tag.displayName);
        }

        if (labels.isEmpty()) {
            return "(none)";
        }
        labels.sort(String::compareTo);
        return String.join(", ", labels);
    }

    private static String preview(String canonical) {
        if (canonical == null || canonical.isBlank()) {
            return "";
        }
        return canonical.length() <= 72 ? canonical : canonical.substring(0, 72) + "...";
    }

    private static String truncate(String value, int maxChars) {
        if (value == null) {
            return "";
        }
        if (value.length() <= maxChars) {
            return value;
        }
        return value.substring(0, maxChars) + "\n... [truncated]";
    }

    private static String shortHash(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < 8; i++) {
                builder.append(String.format("%02x", hash[i]));
            }
            return builder.toString();
        } catch (Exception ignored) {
            return Integer.toHexString(input.hashCode());
        }
    }

    private enum PayloadOrigin {
        REQUEST,
        RESPONSE
    }

    private enum EntityTag {
        ENTITY_ID("Entity ID"),
        TENANT_ID("Tenant ID"),
        USER_ID("User ID"),
        REPORT_ID("Report ID"),
        DEVICE_ID("Device ID"),
        ORDER_ID("Order ID"),
        ACCOUNT_ID("Account ID"),
        OBJECT_REFERENCE("Object Ref"),
        OTHER("Other");

        private final String displayName;

        EntityTag(String displayName) {
            this.displayName = displayName;
        }
    }

    private static final class MethodNodeState {
        private final String methodName;
        private long observations;
        private Instant firstSeen;
        private Instant lastSeen;
        private final Set<String> contextKeys = new TreeSet<>();
        private final Set<EntityTag> entityTags = new TreeSet<>(Comparator.comparing(Enum::name));
        private final boolean sensitiveName;

        private MethodNodeState(String methodName) {
            this.methodName = methodName;
            String lowered = methodName.toLowerCase(Locale.ROOT);
            boolean sensitive = false;
            for (String term : SENSITIVE_TERMS) {
                if (lowered.contains(term)) {
                    sensitive = true;
                    break;
                }
            }
            this.sensitiveName = sensitive;
        }

        private void observe(
                Instant timestamp,
                List<ValueOccurrence> requestValues,
                List<ValueOccurrence> responseValues,
                String contextKey
        ) {
            observations++;
            if (firstSeen == null || timestamp.isBefore(firstSeen)) {
                firstSeen = timestamp;
            }
            if (lastSeen == null || timestamp.isAfter(lastSeen)) {
                lastSeen = timestamp;
            }

            if (contextKey != null && !contextKey.isBlank()) {
                contextKeys.add(contextKey);
            }

            for (ValueOccurrence occurrence : requestValues) {
                entityTags.add(occurrence.entityTag);
            }
            for (ValueOccurrence occurrence : responseValues) {
                entityTags.add(occurrence.entityTag);
            }
        }
    }

    private static final class WorkflowEdgeState {
        private final String sourceMethod;
        private final String sourceContext;
        private final String targetMethod;
        private final String targetContext;

        private long correlationCount;
        private Instant firstSeen;
        private Instant lastSeen;

        private final Map<EntityTag, Integer> entityTagCounts = new TreeMap<>(Comparator.comparing(Enum::name));
        private final LinkedHashSetLimited<String> sharedValueExamples = new LinkedHashSetLimited<>(8);
        private final LinkedHashSetLimited<String> pathLinkExamples = new LinkedHashSetLimited<>(10);
        private final ArrayDeque<EdgeSample> samples = new ArrayDeque<>();

        private WorkflowEdgeState(String sourceMethod, String sourceContext, String targetMethod, String targetContext) {
            this.sourceMethod = sourceMethod;
            this.sourceContext = sourceContext;
            this.targetMethod = targetMethod;
            this.targetContext = targetContext;
        }

        private void observe(ProducerObservation producer, ValueOccurrence consumer, Instant timestamp) {
            correlationCount++;
            if (firstSeen == null || timestamp.isBefore(firstSeen)) {
                firstSeen = timestamp;
            }
            if (lastSeen == null || timestamp.isAfter(lastSeen)) {
                lastSeen = timestamp;
            }

            entityTagCounts.merge(consumer.entityTag, 1, Integer::sum);
            sharedValueExamples.add(producer.preview + " => " + consumer.preview);
            pathLinkExamples.add(producer.path + " -> " + consumer.path);

            samples.addLast(new EdgeSample(
                    producer.recordId,
                    consumer.recordId,
                    producer.path,
                    consumer.path,
                    consumer.preview,
                    consumer.entityTag,
                    timestamp
            ));
            while (samples.size() > MAX_EDGE_SAMPLES) {
                samples.removeFirst();
            }
        }

        private long scoreWeight() {
            long weight = correlationCount;
            for (Map.Entry<EntityTag, Integer> entry : entityTagCounts.entrySet()) {
                if (entry.getKey() == EntityTag.OTHER) {
                    continue;
                }
                weight += Math.min(entry.getValue(), 5);
            }
            return weight;
        }

        private String entityHighlights() {
            List<String> rows = new ArrayList<>();
            for (Map.Entry<EntityTag, Integer> entry : entityTagCounts.entrySet()) {
                if (entry.getKey() == EntityTag.OTHER) {
                    continue;
                }
                rows.add(entry.getKey().displayName + " x" + entry.getValue());
            }
            return rows.isEmpty() ? "(none)" : String.join(", ", rows);
        }
    }

    private record ProducerObservation(
            String methodName,
            String contextKey,
            String recordId,
            String path,
            String keyName,
            EntityTag entityTag,
            String preview,
            Instant timestamp
    ) {
    }

    private record ValueOccurrence(
            String canonicalValue,
            String preview,
            String path,
            String keyName,
            EntityTag entityTag,
            String recordId
    ) {
        private ValueOccurrence(String canonicalValue, String preview, String path, String keyName, EntityTag entityTag) {
            this(canonicalValue, preview, path, keyName, entityTag, "");
        }

        private ValueOccurrence withRecordId(String recordId) {
            return new ValueOccurrence(canonicalValue, preview, path, keyName, entityTag, recordId == null ? "" : recordId);
        }
    }

    private record EdgeSample(
            String producerRecordId,
            String consumerRecordId,
            String producerPath,
            String consumerPath,
            String sharedValuePreview,
            EntityTag entityTag,
            Instant timestamp
    ) {
    }

    private record ChainCandidate(
            String chainId,
            String path,
            List<String> methods,
            List<String> edgeIds,
            long score,
            String highlights,
            String rationale
    ) {
        private int steps() {
            return edgeIds.size();
        }
    }

    private record SnapshotComputation(
            WorkflowGraphSnapshot snapshot,
            Map<String, ChainCandidate> chainCandidatesById
    ) {
    }

    private record ChainComputation(
            Map<String, ChainCandidate> chainsById,
            List<ChainView> chainViews
    ) {
    }

    private static final class LinkedHashSetLimited<T> extends java.util.LinkedHashSet<T> {
        private final int maxSize;

        private LinkedHashSetLimited(int maxSize) {
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

    public record WorkflowGraphSnapshot(
            int totalMethods,
            int totalEdges,
            long totalCorrelations,
            List<MethodNodeView> topConnectedMethods,
            List<EdgeView> edges,
            List<ChainView> chains
    ) {
    }

    public record MethodNodeView(
            String methodName,
            long observations,
            int inDegree,
            int outDegree,
            long weightedConnections,
            boolean entryPoint,
            boolean privilegedEndpoint,
            String entityHighlights,
            int contextGroups,
            Instant firstSeen,
            Instant lastSeen
    ) {
    }

    public record EdgeView(
            String edgeId,
            String sourceMethod,
            String sourceContext,
            String targetMethod,
            String targetContext,
            long correlations,
            String entityHighlights,
            String sharedValues,
            String linkagePaths,
            Instant firstSeen,
            Instant lastSeen
    ) {
    }

    public record ChainView(
            String chainId,
            String path,
            int steps,
            long score,
            String highlights,
            String rationale,
            List<String> methodSequence,
            List<String> edgeIds
    ) {
    }
}
