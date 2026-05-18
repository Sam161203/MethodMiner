package com.methodminer.burp;

import com.methodminer.core.events.EventBus;
import com.methodminer.core.events.ObservationEvent;
import com.methodminer.core.events.SessionChangedEvent;
import com.methodminer.core.events.SurfaceChangedEvent;
import com.methodminer.core.model.ApiSurface;
import com.methodminer.core.model.SessionProfile;
import com.methodminer.core.model.DataType;
import com.methodminer.core.model.DataTypeKind;
import com.methodminer.core.model.Endpoint;
import com.methodminer.core.model.Observation;
import com.methodminer.core.model.Operation;
import com.methodminer.core.model.OperationKind;
import com.methodminer.core.model.Parameter;
import com.methodminer.core.model.Service;
import com.methodminer.core.repository.SurfaceRepository;
import com.methodminer.protocol.DetectionResult;
import com.methodminer.protocol.HttpExchange;
import com.methodminer.protocol.ProtocolDetector;
import com.methodminer.protocol.ProtocolKind;
import com.methodminer.protocol.graphql.GraphQlProtocolAnalyzer;
import com.methodminer.protocol.jsonrpc.JsonRpcProtocolAnalyzer;
import com.methodminer.session.SessionExtractor;
import com.methodminer.session.SessionFingerprint;
import com.methodminer.session.SessionRepository;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Passive ingestion entry point for the new Method Miner architecture.
 */
public final class TrafficIngestor {
    private final ProtocolDetector protocolDetector;
    private final JsonRpcProtocolAnalyzer jsonRpcProtocolAnalyzer;
    private final GraphQlProtocolAnalyzer graphQlProtocolAnalyzer;
    private final SurfaceRepository surfaceRepository;
    private final EventBus eventBus;
    private final SessionExtractor sessionExtractor;   // nullable for backward compat
    private final SessionRepository sessionRepository; // nullable for backward compat
    private final Object updateLock = new Object();

    public TrafficIngestor(
            ProtocolDetector protocolDetector,
            JsonRpcProtocolAnalyzer jsonRpcProtocolAnalyzer,
            GraphQlProtocolAnalyzer graphQlProtocolAnalyzer,
            SurfaceRepository surfaceRepository,
            EventBus eventBus
    ) {
        this(protocolDetector, jsonRpcProtocolAnalyzer, graphQlProtocolAnalyzer,
                surfaceRepository, eventBus, null, null);
    }

    public TrafficIngestor(
            ProtocolDetector protocolDetector,
            JsonRpcProtocolAnalyzer jsonRpcProtocolAnalyzer,
            GraphQlProtocolAnalyzer graphQlProtocolAnalyzer,
            SurfaceRepository surfaceRepository,
            EventBus eventBus,
            SessionExtractor sessionExtractor,
            SessionRepository sessionRepository
    ) {
        this.protocolDetector = Objects.requireNonNull(protocolDetector, "protocolDetector");
        this.jsonRpcProtocolAnalyzer = Objects.requireNonNull(jsonRpcProtocolAnalyzer, "jsonRpcProtocolAnalyzer");
        this.graphQlProtocolAnalyzer = Objects.requireNonNull(graphQlProtocolAnalyzer, "graphQlProtocolAnalyzer");
        this.surfaceRepository = Objects.requireNonNull(surfaceRepository, "surfaceRepository");
        this.eventBus = Objects.requireNonNull(eventBus, "eventBus");
        this.sessionExtractor = sessionExtractor;   // may be null
        this.sessionRepository = sessionRepository; // may be null
    }

    /**
     * Ingest a pre-normalized HTTP exchange and emit placeholder observations based only on protocol detection.
     */
    public void ingest(HttpExchange exchange) {
        Objects.requireNonNull(exchange, "exchange");

        DetectionResult detection;
        try {
            detection = Objects.requireNonNull(protocolDetector.detect(exchange), "detection");
        } catch (RuntimeException ex) {
            return;
        }

        if (detection.kind() == ProtocolKind.UNKNOWN) {
            return;
        }

        // Session extraction — runs for every recognized exchange
        Optional<UUID> sessionProfileId = extractSession(exchange);

        if (detection.kind() == ProtocolKind.JSON_RPC) {
            ingestJsonRpc(exchange, detection, sessionProfileId);
            return;
        }

        if (detection.kind() == ProtocolKind.GRAPHQL) {
            ingestGraphQl(exchange, detection, sessionProfileId);
            return;
        }

        Instant now = Instant.now();
        IngestionArtifacts artifacts;
        try {
            artifacts = buildArtifacts(exchange, detection, now);
        } catch (RuntimeException ex) {
            return;
        }

        ApiSurface updatedSurface;
        synchronized (updateLock) {
            ApiSurface current = surfaceRepository.snapshot();
            updatedSurface = applyArtifacts(current, artifacts, now);
            surfaceRepository.replace(updatedSurface);
        }

        eventBus.publish(new ObservationEvent(artifacts.observation));
        eventBus.publish(new SurfaceChangedEvent(updatedSurface));
    }

    private void ingestJsonRpc(HttpExchange exchange, DetectionResult detection, Optional<UUID> sessionProfileId) {
        Instant now = Instant.now();

        List<JsonRpcProtocolAnalyzer.AnalysisResult> results;
        try {
            results = jsonRpcProtocolAnalyzer.analyze(exchange, detection);
        } catch (RuntimeException ex) {
            results = List.of();
        }

        if (results.isEmpty()) {
            IngestionArtifacts fallback;
            try {
                fallback = buildArtifacts(exchange, detection, now);
            } catch (RuntimeException ex) {
                return;
            }

            ApiSurface updatedSurface;
            synchronized (updateLock) {
                ApiSurface current = surfaceRepository.snapshot();
                updatedSurface = applyArtifacts(current, fallback, now);
                surfaceRepository.replace(updatedSurface);
            }

            eventBus.publish(new ObservationEvent(fallback.observation));
            eventBus.publish(new SurfaceChangedEvent(updatedSurface));
            return;
        }

        ApiSurface updatedSurface;
        synchronized (updateLock) {
            ApiSurface current = surfaceRepository.snapshot();
            updatedSurface = applyJsonRpcResults(current, results, now);
            surfaceRepository.replace(updatedSurface);
        }

        for (JsonRpcProtocolAnalyzer.AnalysisResult result : results) {
            eventBus.publish(new ObservationEvent(result.observation()));
        }
        eventBus.publish(new SurfaceChangedEvent(updatedSurface));
    }

    private void ingestGraphQl(HttpExchange exchange, DetectionResult detection, Optional<UUID> sessionProfileId) {
        Instant now = Instant.now();

        List<GraphQlProtocolAnalyzer.AnalysisResult> results;
        try {
            results = graphQlProtocolAnalyzer.analyze(exchange, detection);
        } catch (RuntimeException ex) {
            results = List.of();
        }

        if (results.isEmpty()) {
            IngestionArtifacts fallback;
            try {
                fallback = buildArtifacts(exchange, detection, now);
            } catch (RuntimeException ex) {
                return;
            }

            ApiSurface updatedSurface;
            synchronized (updateLock) {
                ApiSurface current = surfaceRepository.snapshot();
                updatedSurface = applyArtifacts(current, fallback, now);
                surfaceRepository.replace(updatedSurface);
            }

            eventBus.publish(new ObservationEvent(fallback.observation));
            eventBus.publish(new SurfaceChangedEvent(updatedSurface));
            return;
        }

        ApiSurface updatedSurface;
        synchronized (updateLock) {
            ApiSurface current = surfaceRepository.snapshot();
            updatedSurface = applyGraphQlResults(current, results, now);
            surfaceRepository.replace(updatedSurface);
        }

        for (GraphQlProtocolAnalyzer.AnalysisResult result : results) {
            eventBus.publish(new ObservationEvent(result.observation()));
        }
        eventBus.publish(new SurfaceChangedEvent(updatedSurface));
    }

    private static ApiSurface applyGraphQlResults(
            ApiSurface current,
            List<GraphQlProtocolAnalyzer.AnalysisResult> results,
            Instant now
    ) {
        List<Service> nextServices = current.services();
        List<Observation> nextObservations = new ArrayList<>(current.observations());

        for (GraphQlProtocolAnalyzer.AnalysisResult result : results) {
            nextServices = upsertService(nextServices, result.service(), result.endpoint(), result.operation());
            nextObservations.add(result.observation());
        }

        return new ApiSurface(
                current.id(),
                current.projectName(),
                nextServices,
                List.copyOf(nextObservations),
                current.sessionProfiles(),
                current.relationships(),
                current.riskSignals(),
                current.recommendations(),
                current.attackChains(),
                current.createdAt(),
                now
        );
    }

    private static ApiSurface applyJsonRpcResults(
            ApiSurface current,
            List<JsonRpcProtocolAnalyzer.AnalysisResult> results,
            Instant now
    ) {
        List<Service> nextServices = current.services();
        List<Observation> nextObservations = new ArrayList<>(current.observations());

        for (JsonRpcProtocolAnalyzer.AnalysisResult result : results) {
            nextServices = upsertService(nextServices, result.service(), result.endpoint(), result.operation());
            nextObservations.add(result.observation());
        }

        return new ApiSurface(
                current.id(),
                current.projectName(),
                nextServices,
                List.copyOf(nextObservations),
                current.sessionProfiles(),
                current.relationships(),
                current.riskSignals(),
                current.recommendations(),
                current.attackChains(),
                current.createdAt(),
                now
        );
    }

    private static IngestionArtifacts buildArtifacts(HttpExchange exchange, DetectionResult detection, Instant now) {
        String host = normalizeHost(exchange.uri().getHost());
        String scheme = exchange.uri().getScheme() == null ? "" : exchange.uri().getScheme().toLowerCase(Locale.ROOT);
        int port = effectivePort(scheme, exchange.uri().getPort());
        String path = normalizePath(exchange.uri().getPath());
        String httpMethod = exchange.method() == null ? "" : exchange.method().trim().toUpperCase(Locale.ROOT);

        String serviceKey = scheme + "://" + host + ":" + port;
        UUID serviceId = stableId("service", serviceKey);
        UUID endpointId = stableId("endpoint", serviceKey + "|" + httpMethod + "|" + path + "|" + detection.kind());

        String operationName = resolveOperationName(exchange, detection, path);
        UUID operationId = stableId("operation", endpointId + "|" + operationName);
        OperationKind operationKind = mapOperationKind(detection.kind());

        Set<String> contentTypes = extractContentTypes(exchange.requestHeaders());

        Operation operation = new Operation(
                operationId,
                detection.kind(),
                operationName,
                operationKind,
                List.of(),
                Optional.empty(),
                Optional.empty()
        );

        Endpoint endpoint = new Endpoint(
                endpointId,
                detection.kind(),
                httpMethod,
                path,
                contentTypes,
                List.of(operation)
        );

        Service service = new Service(
                serviceId,
                host.isBlank() ? "(unknown host)" : host,
                host,
                "",
                List.of(endpoint)
        );

        Map<String, String> attributes = new HashMap<>();
        attributes.put("exchangeId", exchange.id().toString());
        attributes.put("host", host);
        attributes.put("path", path);
        attributes.put("httpMethod", httpMethod);
        attributes.put("responseStatusCode", String.valueOf(exchange.responseStatusCode()));
        attributes.put("confidence", String.valueOf(detection.confidence()));
        if (!detection.reason().isBlank()) {
            attributes.put("detectionReason", detection.reason());
        }
        attributes.putAll(detection.attributes());

        Observation observation = new Observation(
                UUID.randomUUID(),
                detection.kind(),
                serviceId,
                endpointId,
                operationId,
                Optional.empty(),
                now,
                attributes,
                Optional.of(httpMethod + " " + path),
                Optional.of(String.valueOf(exchange.responseStatusCode()))
        );

        return new IngestionArtifacts(service, endpoint, operation, observation);
    }

    private static ApiSurface applyArtifacts(ApiSurface current, IngestionArtifacts artifacts, Instant now) {
        List<Service> nextServices = upsertService(current.services(), artifacts.service, artifacts.endpoint, artifacts.operation);

        List<Observation> nextObservations = new ArrayList<>(current.observations());
        nextObservations.add(artifacts.observation);

        return new ApiSurface(
                current.id(),
                current.projectName(),
                nextServices,
                List.copyOf(nextObservations),
                current.sessionProfiles(),
                current.relationships(),
                current.riskSignals(),
                current.recommendations(),
                current.attackChains(),
                current.createdAt(),
                now
        );
    }

    private static List<Service> upsertService(List<Service> services, Service service, Endpoint endpoint, Operation operation) {
        List<Service> updated = new ArrayList<>(services);
        for (int i = 0; i < updated.size(); i++) {
            Service existing = updated.get(i);
            if (!existing.id().equals(service.id())) {
                continue;
            }

            List<Endpoint> nextEndpoints = upsertEndpoint(existing.endpoints(), endpoint, operation);
            updated.set(i, new Service(existing.id(), existing.name(), existing.host(), existing.basePath(), nextEndpoints));
            return List.copyOf(updated);
        }

        updated.add(service);
        return List.copyOf(updated);
    }

    private static List<Endpoint> upsertEndpoint(List<Endpoint> endpoints, Endpoint endpoint, Operation operation) {
        List<Endpoint> updated = new ArrayList<>(endpoints);
        for (int i = 0; i < updated.size(); i++) {
            Endpoint existing = updated.get(i);
            if (!existing.id().equals(endpoint.id())) {
                continue;
            }

            Set<String> mergedContentTypes = new HashSet<>(existing.contentTypes());
            mergedContentTypes.addAll(endpoint.contentTypes());

            List<Operation> nextOperations = upsertOperation(existing.operations(), operation);
            updated.set(i, new Endpoint(existing.id(), existing.protocolKind(), existing.httpMethod(), existing.path(), mergedContentTypes, nextOperations));
            return List.copyOf(updated);
        }

        updated.add(endpoint);
        return List.copyOf(updated);
    }

    private static List<Operation> upsertOperation(List<Operation> operations, Operation operation) {
        List<Operation> updated = new ArrayList<>(operations);
        for (int i = 0; i < updated.size(); i++) {
            Operation existing = updated.get(i);
            if (!existing.id().equals(operation.id())) {
                continue;
            }

            Operation merged = mergeOperation(existing, operation);
            if (merged.equals(existing)) {
                return operations;
            }
            updated.set(i, merged);
            return List.copyOf(updated);
        }

        updated.add(operation);
        return List.copyOf(updated);
    }

    private static Operation mergeOperation(Operation existing, Operation incoming) {
        OperationKind kind = existing.kind() != OperationKind.UNKNOWN ? existing.kind() : incoming.kind();
        String name = (existing.name() == null || existing.name().isBlank()) ? incoming.name() : existing.name();

        List<Parameter> mergedParameters = mergeParameters(existing.parameters(), incoming.parameters());
        Optional<DataType> mergedRequestType = mergeOptionalDataType(existing.requestType(), incoming.requestType());
        Optional<DataType> mergedResponseType = mergeOptionalDataType(existing.responseType(), incoming.responseType());

        return new Operation(
                existing.id(),
                existing.protocolKind(),
                name,
                kind,
                mergedParameters,
                mergedRequestType,
                mergedResponseType
        );
    }

    private static List<Parameter> mergeParameters(List<Parameter> existing, List<Parameter> incoming) {
        if (incoming == null || incoming.isEmpty()) {
            return existing;
        }
        if (existing == null || existing.isEmpty()) {
            return incoming;
        }

        Map<UUID, Parameter> byId = new HashMap<>();
        List<UUID> orderedIds = new ArrayList<>();
        for (Parameter parameter : existing) {
            if (parameter == null) {
                continue;
            }
            byId.put(parameter.id(), parameter);
            orderedIds.add(parameter.id());
        }

        for (Parameter parameter : incoming) {
            if (parameter == null) {
                continue;
            }
            Parameter previous = byId.get(parameter.id());
            if (previous == null) {
                byId.put(parameter.id(), parameter);
                orderedIds.add(parameter.id());
                continue;
            }

            DataType mergedType = mergeDataType(previous.dataType(), parameter.dataType(), 0);
            if (!mergedType.equals(previous.dataType())) {
                byId.put(previous.id(), new Parameter(
                        previous.id(),
                        previous.name(),
                        previous.path(),
                        previous.source(),
                        previous.required(),
                        mergedType,
                        previous.sensitive() || parameter.sensitive(),
                        previous.examples()
                ));
            }
        }

        List<Parameter> merged = new ArrayList<>(orderedIds.size());
        for (UUID id : orderedIds) {
            Parameter parameter = byId.get(id);
            if (parameter != null) {
                merged.add(parameter);
            }
        }
        return List.copyOf(merged);
    }

    private static Optional<DataType> mergeOptionalDataType(Optional<DataType> existing, Optional<DataType> incoming) {
        Optional<DataType> safeExisting = existing == null ? Optional.empty() : existing;
        Optional<DataType> safeIncoming = incoming == null ? Optional.empty() : incoming;

        if (safeExisting.isEmpty()) {
            return safeIncoming;
        }
        if (safeIncoming.isEmpty()) {
            return safeExisting;
        }

        return Optional.of(mergeDataType(safeExisting.get(), safeIncoming.get(), 0));
    }

    private static DataType mergeDataType(DataType existing, DataType incoming, int depth) {
        if (existing == null) {
            return incoming;
        }
        if (incoming == null) {
            return existing;
        }

        if (existing.kind() == DataTypeKind.UNKNOWN && incoming.kind() != DataTypeKind.UNKNOWN) {
            return incoming;
        }
        if (incoming.kind() == DataTypeKind.UNKNOWN) {
            return existing;
        }

        if (depth >= 6) {
            return existing;
        }

        if (existing.kind() != incoming.kind()) {
            if (existing.kind() == DataTypeKind.UNION) {
                return mergeUnion(existing, incoming);
            }
            if (incoming.kind() == DataTypeKind.UNION) {
                return mergeUnion(incoming, existing);
            }
            return existing;
        }

        return switch (existing.kind()) {
            case OBJECT -> mergeObject(existing, incoming, depth);
            case ARRAY -> mergeArray(existing, incoming, depth);
            case UNION -> mergeUnion(existing, incoming);
            default -> existing;
        };
    }

    private static DataType mergeObject(DataType existing, DataType incoming, int depth) {
        Map<String, DataType> fields = new HashMap<>(existing.fields());
        for (var entry : incoming.fields().entrySet()) {
            String key = entry.getKey();
            DataType inc = entry.getValue();
            if (key == null || key.isBlank() || inc == null) {
                continue;
            }
            DataType prev = fields.get(key);
            fields.put(key, prev == null ? inc : mergeDataType(prev, inc, depth + 1));
        }

        return new DataType(
                existing.id(),
                existing.name(),
                existing.kind(),
                existing.confidence(),
                Map.copyOf(fields),
                existing.elementType(),
                existing.variants(),
                existing.enumValues(),
                existing.examples()
        );
    }

    private static DataType mergeArray(DataType existing, DataType incoming, int depth) {
        Optional<DataType> mergedElement = mergeOptionalDataType(existing.elementType(), incoming.elementType());
        return new DataType(
                existing.id(),
                existing.name(),
                existing.kind(),
                existing.confidence(),
                existing.fields(),
                mergedElement,
                existing.variants(),
                existing.enumValues(),
                existing.examples()
        );
    }

    private static DataType mergeUnion(DataType unionType, DataType other) {
        if (unionType == null) {
            return other;
        }
        if (other == null) {
            return unionType;
        }

        List<DataType> variants = new ArrayList<>(unionType.variants());
        if (other.kind() == DataTypeKind.UNION) {
            for (DataType candidate : other.variants()) {
                addVariantIfMissing(variants, candidate);
            }
        } else {
            addVariantIfMissing(variants, other);
        }

        return new DataType(
                unionType.id(),
                unionType.name(),
                DataTypeKind.UNION,
                unionType.confidence(),
                unionType.fields(),
                unionType.elementType(),
                List.copyOf(variants),
                unionType.enumValues(),
                unionType.examples()
        );
    }

    private static void addVariantIfMissing(List<DataType> variants, DataType candidate) {
        if (candidate == null) {
            return;
        }
        for (DataType variant : variants) {
            if (variant != null && variant.id().equals(candidate.id())) {
                return;
            }
        }
        variants.add(candidate);
    }

    private static String resolveOperationName(HttpExchange exchange, DetectionResult detection, String fallbackPath) {
        Map<String, String> attributes = detection.attributes();
        String name = attributes.getOrDefault("operationName", "").trim();
        if (name.isBlank()) {
            name = attributes.getOrDefault("methodName", "").trim();
        }
        if (name.isBlank()) {
            name = attributes.getOrDefault("operation", "").trim();
        }
        if (!name.isBlank()) {
            return name;
        }

        String path = fallbackPath == null ? "" : fallbackPath;
        if (!path.isBlank()) {
            return detection.kind() + "@" + path;
        }

        String uri = exchange.uri() == null ? "" : exchange.uri().toString();
        if (!uri.isBlank()) {
            return detection.kind() + "@" + uri;
        }

        return detection.kind() + "@unknown";
    }

    private static OperationKind mapOperationKind(ProtocolKind kind) {
        return switch (kind) {
            case JSON_RPC -> OperationKind.METHOD;
            case GRAPHQL -> OperationKind.QUERY;
            default -> OperationKind.UNKNOWN;
        };
    }

    private static Set<String> extractContentTypes(Map<String, List<String>> headers) {
        if (headers == null || headers.isEmpty()) {
            return Set.of();
        }

        for (var entry : headers.entrySet()) {
            if (entry.getKey() == null) {
                continue;
            }
            if (!"content-type".equalsIgnoreCase(entry.getKey())) {
                continue;
            }

            Set<String> types = new HashSet<>();
            for (String value : entry.getValue()) {
                if (value == null || value.isBlank()) {
                    continue;
                }
                String normalized = value.trim();
                int semi = normalized.indexOf(';');
                if (semi >= 0) {
                    normalized = normalized.substring(0, semi).trim();
                }
                if (!normalized.isBlank()) {
                    types.add(normalized);
                }
            }
            return Set.copyOf(types);
        }

        return Set.of();
    }

    private static int effectivePort(String scheme, int port) {
        if (port > 0) {
            return port;
        }
        return switch (scheme) {
            case "https" -> 443;
            case "http" -> 80;
            default -> 0;
        };
    }

    private static String normalizeHost(String host) {
        if (host == null) {
            return "";
        }
        return host.trim().toLowerCase(Locale.ROOT);
    }

    private static String normalizePath(String path) {
        if (path == null || path.isBlank()) {
            return "/";
        }
        String trimmed = path.trim();
        return trimmed.startsWith("/") ? trimmed : "/" + trimmed;
    }

    private static UUID stableId(String namespace, String key) {
        String value = (namespace == null ? "" : namespace) + ":" + (key == null ? "" : key);
        return UUID.nameUUIDFromBytes(value.getBytes(StandardCharsets.UTF_8));
    }

    private record IngestionArtifacts(Service service, Endpoint endpoint, Operation operation, Observation observation) {
    }

    /**
     * Extract a session fingerprint from the exchange and upsert into the repository.
     * Returns the session profile ID if session support is configured, otherwise empty.
     */
    private Optional<UUID> extractSession(HttpExchange exchange) {
        if (sessionExtractor == null || sessionRepository == null) {
            return Optional.empty();
        }
        try {
            SessionFingerprint fingerprint = sessionExtractor.extract(exchange);
            if (fingerprint.isEmpty()) {
                return Optional.empty();
            }
            SessionProfile profile = sessionRepository.upsert(fingerprint, exchange.observedAt());
            eventBus.publish(new SessionChangedEvent(profile));
            return Optional.of(profile.id());
        } catch (RuntimeException ex) {
            return Optional.empty();
        }
    }
}
