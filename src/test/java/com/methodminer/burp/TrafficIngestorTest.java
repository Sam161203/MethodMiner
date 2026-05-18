package com.methodminer.burp;

import com.methodminer.core.events.ObservationEvent;
import com.methodminer.core.events.SessionChangedEvent;
import com.methodminer.core.events.SimpleEventBus;
import com.methodminer.core.events.SurfaceChangedEvent;
import com.methodminer.core.model.ApiSurface;
import com.methodminer.core.model.DataTypeKind;
import com.methodminer.core.model.Operation;
import com.methodminer.core.repository.InMemorySurfaceRepository;
import com.methodminer.protocol.CompositeProtocolDetector;
import com.methodminer.protocol.DetectionResult;
import com.methodminer.protocol.HttpExchange;
import com.methodminer.protocol.ProtocolDetector;
import com.methodminer.protocol.ProtocolKind;
import com.methodminer.protocol.jsonrpc.JsonRpcProtocolAnalyzer;
import com.methodminer.protocol.jsonrpc.JsonRpcProtocolDetector;
import com.methodminer.protocol.graphql.GraphQlProtocolAnalyzer;
import com.methodminer.protocol.graphql.GraphQlProtocolDetector;
import com.methodminer.session.InMemorySessionRepository;
import com.methodminer.session.SessionExtractor;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.*;

class TrafficIngestorTest {

    @Test
    void ingestsNonUnknownDetectionAndPublishesEvents() {
        ProtocolDetector detector = exchange -> DetectionResult.detected(ProtocolKind.JSON_RPC, 1.0, "unit-test");
        InMemorySurfaceRepository repository = new InMemorySurfaceRepository("demo");
        SimpleEventBus bus = new SimpleEventBus();
        JsonRpcProtocolAnalyzer analyzer = new JsonRpcProtocolAnalyzer(new ObjectMapper());

        List<ObservationEvent> observationEvents = new CopyOnWriteArrayList<>();
        List<SurfaceChangedEvent> surfaceChangedEvents = new CopyOnWriteArrayList<>();
        bus.subscribe(ObservationEvent.class, event -> observationEvents.add(event));
        bus.subscribe(SurfaceChangedEvent.class, event -> surfaceChangedEvents.add(event));

        TrafficIngestor ingestor = new TrafficIngestor(detector, analyzer, new GraphQlProtocolAnalyzer(new ObjectMapper()), repository, bus);
        ingestor.ingest(sampleExchange());

        ApiSurface snapshot = repository.snapshot();
        assertEquals(1, snapshot.observations().size());
        assertEquals(1, snapshot.services().size());

        assertEquals(1, observationEvents.size());
        assertEquals(1, surfaceChangedEvents.size());
    }

    @Test
    void ignoresUnknownDetections() {
        ProtocolDetector detector = exchange -> DetectionResult.unknown("nope");
        InMemorySurfaceRepository repository = new InMemorySurfaceRepository("demo");
        SimpleEventBus bus = new SimpleEventBus();
        JsonRpcProtocolAnalyzer analyzer = new JsonRpcProtocolAnalyzer(new ObjectMapper());

        List<ObservationEvent> observationEvents = new CopyOnWriteArrayList<>();
        bus.subscribe(ObservationEvent.class, event -> observationEvents.add(event));

        TrafficIngestor ingestor = new TrafficIngestor(detector, analyzer, new GraphQlProtocolAnalyzer(new ObjectMapper()), repository, bus);
        ingestor.ingest(sampleExchange());

        assertEquals(0, repository.snapshot().observations().size());
        assertEquals(0, observationEvents.size());
    }

    @Test
    void ingestsJsonRpcAndPopulatesOperationParametersAndTypes() {
        ObjectMapper mapper = new ObjectMapper();
        ProtocolDetector detector = new CompositeProtocolDetector(List.of(new JsonRpcProtocolDetector(mapper)));
        JsonRpcProtocolAnalyzer analyzer = new JsonRpcProtocolAnalyzer(mapper);

        InMemorySurfaceRepository repository = new InMemorySurfaceRepository("demo");
        SimpleEventBus bus = new SimpleEventBus();

        TrafficIngestor ingestor = new TrafficIngestor(detector, analyzer, new GraphQlProtocolAnalyzer(mapper), repository, bus);
        ingestor.ingest(jsonRpcExchange(
            "{\"jsonrpc\":\"2.0\",\"method\":\"user.get\",\"params\":{\"id\":123},\"id\":1}",
            "{\"jsonrpc\":\"2.0\",\"result\":{\"name\":\"Alice\"},\"id\":1}"
        ));

        ApiSurface snapshot = repository.snapshot();
        assertEquals(1, snapshot.services().size());
        assertEquals(1, snapshot.observations().size());

        Operation operation = snapshot.services().get(0).endpoints().get(0).operations().get(0);
        assertEquals("user.get", operation.name());
        assertEquals(1, operation.parameters().size());
        assertEquals("id", operation.parameters().get(0).name());
        assertTrue(operation.requestType().isPresent());
        assertEquals(DataTypeKind.OBJECT, operation.requestType().get().kind());
        assertTrue(operation.responseType().isPresent());
        assertEquals(DataTypeKind.OBJECT, operation.responseType().get().kind());
    }

    @Test
    void mergesNewJsonRpcParametersAcrossMultipleObservations() {
        ObjectMapper mapper = new ObjectMapper();
        ProtocolDetector detector = new CompositeProtocolDetector(List.of(new JsonRpcProtocolDetector(mapper)));
        JsonRpcProtocolAnalyzer analyzer = new JsonRpcProtocolAnalyzer(mapper);

        InMemorySurfaceRepository repository = new InMemorySurfaceRepository("demo");
        SimpleEventBus bus = new SimpleEventBus();

        TrafficIngestor ingestor = new TrafficIngestor(detector, analyzer, new GraphQlProtocolAnalyzer(mapper), repository, bus);
        ingestor.ingest(jsonRpcExchange(
            "{\"jsonrpc\":\"2.0\",\"method\":\"user.get\",\"params\":{\"id\":123},\"id\":1}",
            "{\"jsonrpc\":\"2.0\",\"result\":{\"name\":\"Alice\"},\"id\":1}"
        ));
        ingestor.ingest(jsonRpcExchange(
            "{\"jsonrpc\":\"2.0\",\"method\":\"user.get\",\"params\":{\"id\":123,\"verbose\":true},\"id\":2}",
            "{\"jsonrpc\":\"2.0\",\"result\":{\"name\":\"Alice\",\"details\":{\"country\":\"X\"}},\"id\":2}"
        ));

        Operation operation = repository.snapshot().services().get(0).endpoints().get(0).operations().get(0);
        assertEquals(2, operation.parameters().size());
        assertTrue(operation.requestType().isPresent());
        assertTrue(operation.requestType().get().fields().containsKey("id"));
        assertTrue(operation.requestType().get().fields().containsKey("verbose"));
    }

    @Test
    void ingestsGraphQlAndPopulatesSurface() {
        ObjectMapper mapper = new ObjectMapper();
        ProtocolDetector detector = new CompositeProtocolDetector(List.of(
            new JsonRpcProtocolDetector(mapper),
            new GraphQlProtocolDetector(mapper)
        ));
        JsonRpcProtocolAnalyzer jsonRpcAnalyzer = new JsonRpcProtocolAnalyzer(mapper);
        GraphQlProtocolAnalyzer graphQlAnalyzer = new GraphQlProtocolAnalyzer(mapper);

        InMemorySurfaceRepository repository = new InMemorySurfaceRepository("demo");
        SimpleEventBus bus = new SimpleEventBus();

        List<ObservationEvent> observationEvents = new CopyOnWriteArrayList<>();
        bus.subscribe(ObservationEvent.class, event -> observationEvents.add(event));

        TrafficIngestor ingestor = new TrafficIngestor(detector, jsonRpcAnalyzer, graphQlAnalyzer, repository, bus);
        ingestor.ingest(graphqlExchange(
            "{\"query\":\"query GetUser($id: ID!) { user(id: $id) { name email } }\","
                + "\"operationName\":\"GetUser\","
                + "\"variables\":{\"id\":\"abc-123\"}}"
        ));

        ApiSurface snapshot = repository.snapshot();
        assertEquals(1, snapshot.services().size());
        assertEquals(1, snapshot.observations().size());
        assertEquals(1, observationEvents.size());

        Operation operation = snapshot.services().get(0).endpoints().get(0).operations().get(0);
        assertEquals(ProtocolKind.GRAPHQL, operation.protocolKind());
        assertTrue(operation.name().contains("GetUser"));
        assertTrue(operation.responseType().isPresent());
    }

    @Test
    void sessionExtractionPopulatesSessionProfileId() {
        ObjectMapper mapper = new ObjectMapper();
        ProtocolDetector detector = new CompositeProtocolDetector(List.of(new JsonRpcProtocolDetector(mapper)));
        JsonRpcProtocolAnalyzer analyzer = new JsonRpcProtocolAnalyzer(mapper);
        GraphQlProtocolAnalyzer graphQlAnalyzer = new GraphQlProtocolAnalyzer(mapper);

        InMemorySurfaceRepository repository = new InMemorySurfaceRepository("demo");
        SimpleEventBus bus = new SimpleEventBus();
        SessionExtractor sessionExtractor = new SessionExtractor(mapper);
        InMemorySessionRepository sessionRepository = new InMemorySessionRepository();

        List<SessionChangedEvent> sessionEvents = new CopyOnWriteArrayList<>();
        bus.subscribe(SessionChangedEvent.class, event -> sessionEvents.add(event));

        TrafficIngestor ingestor = new TrafficIngestor(
                detector, analyzer, graphQlAnalyzer, repository, bus,
                sessionExtractor, sessionRepository
        );

        // Ingest a JSON-RPC request with credentials
        ingestor.ingest(jsonRpcExchange(
            "{\"jsonrpc\":\"2.0\",\"method\":\"Get\",\"params\":{\"typeName\":\"Device\","
                + "\"credentials\":{\"database\":\"test_db\",\"userName\":\"admin@test.com\","
                + "\"sessionId\":\"sess-123\"}},\"id\":1}",
            "{\"jsonrpc\":\"2.0\",\"result\":{},\"id\":1}"
        ));

        // Verify session was created
        assertFalse(sessionRepository.snapshot().isEmpty(), "Session repository should have a profile");
        assertEquals(1, sessionEvents.size(), "Should have published a SessionChangedEvent");
        assertEquals("admin@test.com", sessionRepository.snapshot().get(0).username());
        assertEquals("test_db", sessionRepository.snapshot().get(0).database());
    }

    // ---- Helpers ----------------------------------------------------------

    private static HttpExchange sampleExchange() {
        return new HttpExchange(
                UUID.randomUUID(),
                URI.create("https://example.test/rpc"),
                "POST",
                Map.of("Content-Type", List.of("application/json")),
                Optional.of("{}"),
                200,
                Map.of(),
                Optional.empty(),
                Instant.now()
        );
    }

    private static HttpExchange jsonRpcExchange(String requestBody, String responseBody) {
        return new HttpExchange(
                UUID.randomUUID(),
                URI.create("https://example.test/rpc"),
                "POST",
                Map.of("Content-Type", List.of("application/json")),
                Optional.of(requestBody),
                200,
                Map.of("Content-Type", List.of("application/json")),
                Optional.ofNullable(responseBody),
                Instant.parse("2026-01-01T00:00:00Z")
        );
    }

    private static HttpExchange graphqlExchange(String requestBody) {
        return new HttpExchange(
                UUID.randomUUID(),
                URI.create("https://api.example.com/graphql"),
                "POST",
                Map.of("Content-Type", List.of("application/json")),
                Optional.of(requestBody),
                200,
                Map.of("Content-Type", List.of("application/json")),
                Optional.of("{\"data\":{\"user\":{\"name\":\"Alice\",\"email\":\"a@test.com\"}}}"),
                Instant.parse("2026-01-01T00:00:00Z")
        );
    }
}
