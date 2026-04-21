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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;

public final class JsonRpcIndex {
    private static final int SAMPLE_LIMIT = 5;
    private static final int CONTEXT_TIMELINE_LIMIT = 120;
    private static final String UNKNOWN_CONTEXT = "unknown-session";

    // Method store key: method + ":" + typeName
    private final ConcurrentMap<String, MethodAggregate> methods = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, ContextAggregate> contexts = new ConcurrentHashMap<>();
    private final AtomicLong totalRecordCount = new AtomicLong();
    private final ObjectMapper hashingMapper = new ObjectMapper();

    public void addRecord(JsonRpcNormalizedRecord normalized, JsonRpcRecord rawRecord) {
        addRecord(normalized, rawRecord, UNKNOWN_CONTEXT);
    }

    public void addRecord(JsonRpcNormalizedRecord normalized, JsonRpcRecord rawRecord, String contextKey) {
        if (normalized == null || rawRecord == null) {
            return;
        }

        String resolvedContextKey = contextKey == null || contextKey.isBlank() ? UNKNOWN_CONTEXT : contextKey;
        String method = defaultIfBlank(normalized.methodName(), "UnknownMethod");
        String typeName = defaultIfBlank(normalized.typeName(), "Unknown");
        String methodStoreKey = method + ":" + typeName;

        methods.computeIfAbsent(methodStoreKey, ignored -> new MethodAggregate(methodStoreKey, method, typeName))
                .update(normalized, rawRecord, resolvedContextKey, hashResponse(rawRecord.response().bodyText()),
                        comparableRequestFingerprint(rawRecord.request().bodyText()));

        contexts.computeIfAbsent(resolvedContextKey, ContextAggregate::new)
                .update(normalized, rawRecord, methodStoreKey);

        totalRecordCount.incrementAndGet();
    }

    public List<MethodStoreView> snapshotMethodStoreViews() {
        List<MethodStoreView> out = new ArrayList<>();
        for (MethodAggregate aggregate : methods.values()) {
            out.add(aggregate.toMethodStoreView());
        }
        out.sort(Comparator.comparing(MethodStoreView::key, String.CASE_INSENSITIVE_ORDER));
        return out;
    }

    public List<ContextRow> snapshotContextRows() {
        List<ContextRow> rows = new ArrayList<>();
        for (ContextAggregate aggregate : contexts.values()) {
            rows.add(aggregate.toRow());
        }

        rows.sort(Comparator
                .comparingLong(ContextRow::count).reversed()
                .thenComparing(ContextRow::contextKey, String.CASE_INSENSITIVE_ORDER));
        return rows;
    }

    public List<ContextTimelineEntry> snapshotContextTimeline(String contextKey) {
        if (contextKey == null || contextKey.isBlank()) {
            return List.of();
        }
        ContextAggregate aggregate = contexts.get(contextKey);
        return aggregate == null ? List.of() : aggregate.toTimeline();
    }

    public List<MethodRow> snapshotMethodRows() {
        List<MethodRow> rows = new ArrayList<>();
        for (MethodAggregate aggregate : methods.values()) {
            rows.add(aggregate.toRow());
        }

        rows.sort(Comparator
                .comparingLong(MethodRow::count).reversed()
                .thenComparing(MethodRow::methodName, String.CASE_INSENSITIVE_ORDER));
        return rows;
    }

    public Optional<MethodDetails> snapshotMethodDetails(String methodNameOrKey) {
        if (methodNameOrKey == null || methodNameOrKey.isBlank()) {
            return Optional.empty();
        }

        MethodAggregate exact = methods.get(methodNameOrKey);
        if (exact != null) {
            return Optional.of(exact.toDetails());
        }

        MethodAggregate byMethod = null;
        for (MethodAggregate aggregate : methods.values()) {
            if (!aggregate.method.equals(methodNameOrKey)) {
                continue;
            }
            if (byMethod == null || aggregate.totalCount > byMethod.totalCount) {
                byMethod = aggregate;
            }
        }

        return byMethod == null ? Optional.empty() : Optional.of(byMethod.toDetails());
    }

    public Stats snapshotStats() {
        long totalRecords = totalRecordCount.get();
        int distinctMethods = methods.size();
        long withEmptyParams = 0;
        long seenOnce = 0;
        long withMultipleVariants = 0;
        long withLargeResponses = 0;

        for (MethodAggregate aggregate : methods.values()) {
            MethodRow row = aggregate.toRow();
            if (row.hasEmptyParams()) {
                withEmptyParams++;
            }
            if (row.count() == 1) {
                seenOnce++;
            }
            if (row.uniqueVariants() > 1) {
                withMultipleVariants++;
            }
            if (row.hasLargeResponses()) {
                withLargeResponses++;
            }
        }

        return new Stats(totalRecords, distinctMethods, withEmptyParams, seenOnce, withMultipleVariants, withLargeResponses);
    }

    public void clear() {
        methods.clear();
        contexts.clear();
        totalRecordCount.set(0);
    }

    private String hashResponse(String responseBody) {
        String normalized = normalizeJsonForHash(responseBody);
        return sha256Hex(normalized);
    }

    private String normalizeJsonForHash(String raw) {
        if (raw == null || raw.isBlank()) {
            return "";
        }

        try {
            JsonNode node = hashingMapper.readTree(raw);
            return canonicalize(node);
        } catch (Exception ignored) {
            return raw.trim();
        }
    }

    private static String canonicalize(JsonNode node) {
        if (node == null || node.isNull()) {
            return "null";
        }

        if (node.isObject()) {
            List<String> names = new ArrayList<>();
            node.fieldNames().forEachRemaining(names::add);
            names.sort(String::compareTo);

            StringBuilder builder = new StringBuilder();
            builder.append('{');
            boolean first = true;
            for (String name : names) {
                if (!first) {
                    builder.append(',');
                }
                first = false;
                builder.append('"').append(name).append('"').append(':').append(canonicalize(node.get(name)));
            }
            builder.append('}');
            return builder.toString();
        }

        if (node.isArray()) {
            StringBuilder builder = new StringBuilder();
            builder.append('[');
            for (int i = 0; i < node.size(); i++) {
                if (i > 0) {
                    builder.append(',');
                }
                builder.append(canonicalize(node.get(i)));
            }
            builder.append(']');
            return builder.toString();
        }

        return node.toString();
    }

    private static String comparableRequestFingerprint(String requestBody) {
        if (requestBody == null || requestBody.isBlank()) {
            return "";
        }

        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode root = mapper.readTree(requestBody);
            JsonNode target = root;
            if (root.isObject()) {
                JsonNode params = root.path("params");
                if (params.isObject()) {
                    ObjectNodeLike sanitized = sanitizeParams(params);
                    return sanitized.asCanonical();
                }
            }
            return canonicalize(target);
        } catch (Exception ignored) {
            return requestBody.trim();
        }
    }

    private static ObjectNodeLike sanitizeParams(JsonNode params) {
        Map<String, String> canonical = new HashMap<>();
        Iterator<Map.Entry<String, JsonNode>> fields = params.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            String key = entry.getKey() == null ? "" : entry.getKey().toLowerCase(Locale.ROOT);
            if ("credentials".equals(key)) {
                continue;
            }
            canonical.put(entry.getKey(), canonicalize(entry.getValue()));
        }
        return new ObjectNodeLike(canonical);
    }

    private static String sha256Hex(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest((value == null ? "" : value).getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder();
            for (byte b : hash) {
                builder.append(String.format("%02x", b));
            }
            return builder.toString();
        } catch (Exception ignored) {
            return Integer.toHexString((value == null ? "" : value).hashCode());
        }
    }

    private static String defaultIfBlank(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }

    private static final class MethodAggregate {
        private final String key;
        private final String method;
        private final String typeName;

        private long totalCount;
        private long rawRecordsCount;
        private Instant firstSeen;
        private Instant lastSeen;
        private boolean hasEmptyParams;
        private boolean hasLargeResponses;

        private String lastRequest = "";
        private String lastResponse = "";

        private final Set<String> seenInSessions = new LinkedHashSet<>();
        private final Set<String> responseHashes = new LinkedHashSet<>();
        private final Set<String> uniqueEndpoints = new LinkedHashSet<>();
        private final Set<String> uniqueParamShapes = new LinkedHashSet<>();
        private final Set<String> parameterKeyUnion = new TreeSet<>();
        private final Set<String> paramKeySets = new LinkedHashSet<>();
        private final Map<String, MethodContextStats> perContextStats = new HashMap<>();
        private final Map<String, SessionSnapshot> sessionSnapshots = new LinkedHashMap<>();

        private final Map<String, VariantAggregate> variants = new HashMap<>();
        private final ArrayDeque<JsonRpcRecord> sampleRawRecords = new ArrayDeque<>();
        private final ArrayDeque<JsonRpcNormalizedRecord> sampleNormalizedRecords = new ArrayDeque<>();

        private MethodAggregate(String key, String method, String typeName) {
            this.key = key;
            this.method = method;
            this.typeName = typeName;
        }

        synchronized void update(
                JsonRpcNormalizedRecord normalized,
                JsonRpcRecord rawRecord,
                String contextKey,
                String responseHash,
                String comparableRequest
        ) {
            totalCount++;
            rawRecordsCount++;

            if (firstSeen == null || normalized.timestamp().isBefore(firstSeen)) {
                firstSeen = normalized.timestamp();
            }
            if (lastSeen == null || normalized.timestamp().isAfter(lastSeen)) {
                lastSeen = normalized.timestamp();
            }

            seenInSessions.add(contextKey);
            responseHashes.add(responseHash);

            uniqueEndpoints.add(defaultIfBlank(normalized.url(), ""));
            uniqueParamShapes.add(defaultIfBlank(normalized.paramShapeSignature(), ""));
            parameterKeyUnion.addAll(normalized.parameterKeys());
            paramKeySets.add(String.join(",", normalized.parameterKeys()));

            if (normalized.emptyParams()) {
                hasEmptyParams = true;
            }
            if (normalized.largeResponse()) {
                hasLargeResponses = true;
            }

            lastRequest = rawRecord.request().bodyText() == null ? "" : rawRecord.request().bodyText();
            lastResponse = rawRecord.response().bodyText() == null ? "" : rawRecord.response().bodyText();

            perContextStats.computeIfAbsent(contextKey, MethodContextStats::new)
                    .observe(normalized, responseHash);

            sessionSnapshots.put(contextKey, new SessionSnapshot(
                    contextKey,
                    comparableRequest,
                    lastRequest,
                    lastResponse,
                    responseHash,
                    normalized.responseStatus(),
                    normalized.timestamp()
            ));

            VariantAggregate variant = variants.computeIfAbsent(
                    responseHash,
                    variantHash -> new VariantAggregate(
                            variantHash,
                            normalized.paramShapeSignature(),
                            normalized.responseShapeSignature()
                    )
            );
            variant.update(normalized);

            addSample(sampleRawRecords, rawRecord);
            addSample(sampleNormalizedRecords, normalized);
        }

        synchronized MethodStoreView toMethodStoreView() {
            return new MethodStoreView(
                    key,
                    method,
                    typeName,
                    List.copyOf(seenInSessions),
                    List.copyOf(responseHashes),
                    lastRequest,
                    lastResponse,
                    List.copyOf(sessionSnapshots.values())
            );
        }

        synchronized MethodRow toRow() {
            String paramKeySummary = parameterKeyUnion.isEmpty() ? "(none)" : String.join(", ", parameterKeyUnion);
            return new MethodRow(
                    key,
                    totalCount,
                    paramKeySummary,
                    variants.size(),
                    firstSeen,
                    lastSeen,
                    hasEmptyParams,
                    hasLargeResponses,
                    uniqueParamShapes.size(),
                    uniqueEndpoints.size(),
                    rawRecordsCount
            );
        }

        synchronized MethodDetails toDetails() {
            MethodRow row = toRow();
            List<VariantSummary> variantSummaries = new ArrayList<>();
            for (VariantAggregate variant : variants.values()) {
                variantSummaries.add(variant.toSummary());
            }
            variantSummaries.sort(Comparator.comparingLong(VariantSummary::count).reversed());

            List<MethodContextSummary> contextSummaries = new ArrayList<>();
            for (MethodContextStats stats : perContextStats.values()) {
                contextSummaries.add(stats.toSummary());
            }
            contextSummaries.sort(Comparator.comparingLong(MethodContextSummary::count).reversed());

            List<JsonRpcRecord> sampleRaw = List.copyOf(sampleRawRecords);
            List<JsonRpcNormalizedRecord> sampleNormalized = List.copyOf(sampleNormalizedRecords);

            return new MethodDetails(
                    row,
                    List.copyOf(variantSummaries),
                    List.copyOf(contextSummaries),
                    List.copyOf(uniqueEndpoints),
                    List.copyOf(paramKeySets),
                    sampleRaw,
                    sampleNormalized
            );
        }

        private static <T> void addSample(ArrayDeque<T> deque, T value) {
            if (deque.size() >= SAMPLE_LIMIT) {
                deque.removeFirst();
            }
            deque.addLast(value);
        }

        private static final class MethodContextStats {
            private final String contextKey;
            private long count;
            private Instant firstSeen;
            private Instant lastSeen;
            private final Set<Integer> responseStatuses = new TreeSet<>();
            private final Set<String> responseShapes = new TreeSet<>();

            private MethodContextStats(String contextKey) {
                this.contextKey = contextKey;
            }

            private void observe(JsonRpcNormalizedRecord normalized, String responseHash) {
                count++;
                if (firstSeen == null || normalized.timestamp().isBefore(firstSeen)) {
                    firstSeen = normalized.timestamp();
                }
                if (lastSeen == null || normalized.timestamp().isAfter(lastSeen)) {
                    lastSeen = normalized.timestamp();
                }

                if (normalized.responseStatus() != null) {
                    responseStatuses.add(normalized.responseStatus());
                }
                if (responseHash != null && !responseHash.isBlank()) {
                    responseShapes.add(responseHash);
                }
            }

            private MethodContextSummary toSummary() {
                return new MethodContextSummary(
                        contextKey,
                        count,
                        firstSeen,
                        lastSeen,
                        List.copyOf(responseStatuses),
                        List.copyOf(responseShapes)
                );
            }
        }
    }

    private static final class VariantAggregate {
        private final String signature;
        private final String paramShape;
        private final String responseShape;

        private long count;
        private boolean hasEmptyParams;
        private int maxResponseBodySize;
        private final Set<String> parameterKeys = new TreeSet<>();

        private VariantAggregate(String signature, String paramShape, String responseShape) {
            this.signature = signature;
            this.paramShape = paramShape;
            this.responseShape = responseShape;
        }

        synchronized void update(JsonRpcNormalizedRecord record) {
            count++;
            parameterKeys.addAll(record.parameterKeys());
            hasEmptyParams = hasEmptyParams || record.emptyParams();
            maxResponseBodySize = Math.max(maxResponseBodySize, record.responseBodySize());
        }

        synchronized VariantSummary toSummary() {
            return new VariantSummary(
                    signature,
                    count,
                    parameterKeys.isEmpty() ? "(none)" : String.join(", ", parameterKeys),
                    paramShape,
                    responseShape,
                    hasEmptyParams,
                    maxResponseBodySize
            );
        }
    }

    public record MethodStoreView(
            String key,
            String method,
            String typeName,
            List<String> seenInSessions,
            List<String> responseHashes,
            String lastRequest,
            String lastResponse,
            List<SessionSnapshot> sessionSnapshots
    ) {
    }

    public record SessionSnapshot(
            String sessionId,
            String comparableRequestFingerprint,
            String lastRequest,
            String lastResponse,
            String responseHash,
            Integer responseStatus,
            Instant lastSeen
    ) {
    }

    public record MethodRow(
            String methodName,
            long count,
            String paramKeys,
            int uniqueVariants,
            Instant firstSeen,
            Instant lastSeen,
            boolean hasEmptyParams,
            boolean hasLargeResponses,
            int uniqueParamShapes,
            int uniqueEndpoints,
            long rawRecordsCount
    ) {
        public boolean isRare() {
            return count <= 1;
        }
    }

    public record VariantSummary(
            String signature,
            long count,
            String parameterKeys,
            String paramShape,
            String responseShape,
            boolean hasEmptyParams,
            int maxResponseBodySize
    ) {
    }

    public record MethodDetails(
            MethodRow row,
            List<VariantSummary> variants,
            List<MethodContextSummary> contextSummaries,
            List<String> uniqueEndpoints,
            List<String> paramKeySets,
            List<JsonRpcRecord> sampleRawRecords,
            List<JsonRpcNormalizedRecord> sampleNormalizedRecords
    ) {
        public JsonRpcRecord primaryRawRecord() {
            return sampleRawRecords.isEmpty() ? null : sampleRawRecords.get(sampleRawRecords.size() - 1);
        }

        public JsonRpcNormalizedRecord primaryNormalizedRecord() {
            return sampleNormalizedRecords.isEmpty() ? null : sampleNormalizedRecords.get(sampleNormalizedRecords.size() - 1);
        }

        public ObjectNode toMetadataJson(ObjectMapper mapper) {
            ObjectNode root = mapper.createObjectNode();
            root.put("methodName", row.methodName());
            root.put("totalCount", row.count());
            root.put("uniqueVariants", row.uniqueVariants());
            root.put("uniqueParamShapes", row.uniqueParamShapes());
            root.put("uniqueEndpoints", row.uniqueEndpoints());
            root.put("rawRecordsCount", row.rawRecordsCount());
            root.put("firstSeen", row.firstSeen() == null ? "" : row.firstSeen().toString());
            root.put("lastSeen", row.lastSeen() == null ? "" : row.lastSeen().toString());
            root.put("hasEmptyParams", row.hasEmptyParams());
            root.put("hasLargeResponses", row.hasLargeResponses());

            ArrayNode endpointArray = mapper.createArrayNode();
            for (String endpoint : uniqueEndpoints) {
                endpointArray.add(endpoint);
            }
            root.set("uniqueEndpointsList", endpointArray);

            ArrayNode paramKeySetArray = mapper.createArrayNode();
            for (String keySet : paramKeySets) {
                paramKeySetArray.add(keySet);
            }
            root.set("paramKeySets", paramKeySetArray);

            ArrayNode variantArray = mapper.createArrayNode();
            for (VariantSummary variant : variants) {
                ObjectNode variantNode = mapper.createObjectNode();
                variantNode.put("signature", variant.signature());
                variantNode.put("count", variant.count());
                variantNode.put("parameterKeys", variant.parameterKeys());
                variantNode.put("paramShape", variant.paramShape());
                variantNode.put("responseShape", variant.responseShape());
                variantNode.put("hasEmptyParams", variant.hasEmptyParams());
                variantNode.put("maxResponseBodySize", variant.maxResponseBodySize());
                variantArray.add(variantNode);
            }
            root.set("variants", variantArray);

            ArrayNode contextArray = mapper.createArrayNode();
            for (MethodContextSummary summary : contextSummaries) {
                ObjectNode contextNode = mapper.createObjectNode();
                contextNode.put("contextKey", summary.contextKey());
                contextNode.put("count", summary.count());
                contextNode.put("firstSeen", summary.firstSeen() == null ? "" : summary.firstSeen().toString());
                contextNode.put("lastSeen", summary.lastSeen() == null ? "" : summary.lastSeen().toString());

                ArrayNode statuses = mapper.createArrayNode();
                for (Integer status : summary.responseStatuses()) {
                    statuses.add(status);
                }
                contextNode.set("responseStatuses", statuses);

                ArrayNode shapes = mapper.createArrayNode();
                for (String shape : summary.responseShapes()) {
                    shapes.add(shape);
                }
                contextNode.set("responseShapes", shapes);

                contextArray.add(contextNode);
            }
            root.set("contexts", contextArray);

            return root;
        }
    }

    public record MethodContextSummary(
            String contextKey,
            long count,
            Instant firstSeen,
            Instant lastSeen,
            List<Integer> responseStatuses,
            List<String> responseShapes
    ) {
    }

    public record ContextRow(
            String contextKey,
            long count,
            int distinctMethods,
            Instant firstSeen,
            Instant lastSeen
    ) {
    }

    public record ContextTimelineEntry(
            Instant timestamp,
            String recordId,
            String methodName,
            Integer responseStatus,
            String url
    ) {
    }

    private static final class ContextAggregate {
        private final String contextKey;
        private long count;
        private Instant firstSeen;
        private Instant lastSeen;
        private final Map<String, Long> methodCounts = new HashMap<>();
        private final ArrayDeque<ContextTimelineEntry> timeline = new ArrayDeque<>();

        private ContextAggregate(String contextKey) {
            this.contextKey = contextKey;
        }

        synchronized void update(JsonRpcNormalizedRecord normalized, JsonRpcRecord rawRecord, String methodStoreKey) {
            count++;
            if (firstSeen == null || normalized.timestamp().isBefore(firstSeen)) {
                firstSeen = normalized.timestamp();
            }
            if (lastSeen == null || normalized.timestamp().isAfter(lastSeen)) {
                lastSeen = normalized.timestamp();
            }

            methodCounts.merge(methodStoreKey, 1L, Long::sum);
            timeline.addLast(new ContextTimelineEntry(
                    normalized.timestamp(),
                    rawRecord.recordId() == null ? "" : rawRecord.recordId(),
                    methodStoreKey,
                    normalized.responseStatus(),
                    normalized.url()
            ));
            while (timeline.size() > CONTEXT_TIMELINE_LIMIT) {
                timeline.removeFirst();
            }
        }

        synchronized ContextRow toRow() {
            return new ContextRow(
                    contextKey,
                    count,
                    methodCounts.size(),
                    firstSeen,
                    lastSeen
            );
        }

        synchronized List<ContextTimelineEntry> toTimeline() {
            return List.copyOf(timeline);
        }
    }

    public record Stats(
            long totalRecords,
            int distinctMethods,
            long methodsWithEmptyParams,
            long methodsSeenOnce,
            long methodsWithMultipleVariants,
            long methodsWithLargeResponses
    ) {
    }

    private record ObjectNodeLike(Map<String, String> values) {
        private String asCanonical() {
            List<String> keys = new ArrayList<>(values.keySet());
            keys.sort(String::compareTo);
            StringBuilder builder = new StringBuilder();
            builder.append('{');
            boolean first = true;
            for (String key : keys) {
                if (!first) {
                    builder.append(',');
                }
                first = false;
                builder.append('"').append(key).append('"').append(':').append(values.get(key));
            }
            builder.append('}');
            return builder.toString();
        }
    }
}
