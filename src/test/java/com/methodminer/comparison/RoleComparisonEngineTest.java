package com.methodminer.comparison;

import com.methodminer.core.model.*;
import com.methodminer.core.repository.InMemorySurfaceRepository;
import com.methodminer.protocol.ProtocolKind;
import com.methodminer.session.InMemorySessionRepository;
import com.methodminer.session.SessionFingerprint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive tests for {@link RoleComparisonEngine}.
 */
class RoleComparisonEngineTest {

    private InMemorySurfaceRepository surfaceRepo;
    private InMemorySessionRepository sessionRepo;
    private RoleComparisonEngine engine;

    @BeforeEach
    void setUp() {
        surfaceRepo = new InMemorySurfaceRepository("test");
        sessionRepo = new InMemorySessionRepository();
        engine = new RoleComparisonEngine(surfaceRepo, sessionRepo);
    }

    // ---- Classification Tests -----------------------------------------------

    @Test
    void emptyObservationsReturnsEmptyResult() {
        RoleComparisonResult result = engine.compare();
        assertEquals(0, result.totalOperations());
        assertEquals(0, result.totalSessions());
        assertTrue(result.operationCoverages().isEmpty());
    }

    @Test
    void adminOnlyClassification() {
        UUID adminSessionId = createSession("admin-host", "Bearer", "token-admin", "admin@test.com", Role.ADMIN);
        UUID opId = UUID.randomUUID();

        addSurfaceWithOperation(opId, "DeleteDevice", ProtocolKind.JSON_RPC);
        addObservation(opId, adminSessionId, ProtocolKind.JSON_RPC);

        RoleComparisonResult result = engine.compare();
        assertEquals(1, result.totalOperations());
        assertEquals(1, result.operationCoverages().size());
        assertEquals(CoverageStatus.ADMIN_ONLY, result.operationCoverages().get(0).status());
        assertEquals(1, result.operationCoverages().get(0).adminSessionCount());
        assertEquals(0, result.operationCoverages().get(0).lowPrivSessionCount());
    }

    @Test
    void lowPrivOnlyClassification() {
        UUID lowPrivSessionId = createSession("host", "Bearer", "token-low", "user@test.com", Role.LOW_PRIV);
        UUID opId = UUID.randomUUID();

        addSurfaceWithOperation(opId, "GetCurrentUser", ProtocolKind.GRAPHQL);
        addObservation(opId, lowPrivSessionId, ProtocolKind.GRAPHQL);

        RoleComparisonResult result = engine.compare();
        assertEquals(CoverageStatus.LOW_PRIV_ONLY, result.operationCoverages().get(0).status());
        assertEquals(0, result.operationCoverages().get(0).adminSessionCount());
        assertEquals(1, result.operationCoverages().get(0).lowPrivSessionCount());
    }

    @Test
    void bothClassification() {
        UUID adminSessionId = createSession("host", "Bearer", "tok-admin", "admin@test.com", Role.ADMIN);
        UUID lowPrivSessionId = createSession("host", "Bearer", "tok-low", "user@test.com", Role.LOW_PRIV);
        UUID opId = UUID.randomUUID();

        addSurfaceWithOperation(opId, "GetUser", ProtocolKind.JSON_RPC);
        addObservation(opId, adminSessionId, ProtocolKind.JSON_RPC);
        addObservation(opId, lowPrivSessionId, ProtocolKind.JSON_RPC);

        RoleComparisonResult result = engine.compare();
        assertEquals(CoverageStatus.BOTH, result.operationCoverages().get(0).status());
        assertEquals(1, result.operationCoverages().get(0).adminSessionCount());
        assertEquals(1, result.operationCoverages().get(0).lowPrivSessionCount());
    }

    @Test
    void unlabeledClassification() {
        UUID unknownSessionId = createSession("host", "Cookie", "tok-unknown", "", Role.UNKNOWN);
        UUID opId = UUID.randomUUID();

        addSurfaceWithOperation(opId, "ListItems", ProtocolKind.JSON_RPC);
        addObservation(opId, unknownSessionId, ProtocolKind.JSON_RPC);

        RoleComparisonResult result = engine.compare();
        assertEquals(CoverageStatus.UNLABELED, result.operationCoverages().get(0).status());
        assertEquals(1, result.operationCoverages().get(0).unlabeledSessionCount());
    }

    @Test
    void unknownWhenNoSessionId() {
        UUID opId = UUID.randomUUID();
        addSurfaceWithOperation(opId, "Ping", ProtocolKind.JSON_RPC);
        addObservation(opId, null, ProtocolKind.JSON_RPC); // No session

        RoleComparisonResult result = engine.compare();
        assertEquals(1, result.totalOperations());
    }

    // ---- Multiple Operations ------------------------------------------------

    @Test
    void multipleOperationsClassifiedIndependently() {
        UUID adminSession = createSession("host", "Bearer", "admin-tok", "admin@t.com", Role.ADMIN);
        UUID lowPrivSession = createSession("host", "Bearer", "low-tok", "user@t.com", Role.LOW_PRIV);

        UUID opAdmin = UUID.randomUUID();
        UUID opBoth = UUID.randomUUID();
        UUID opLow = UUID.randomUUID();

        addSurfaceWithOperations(List.of(
                new OpSpec(opAdmin, "AdminOnly", ProtocolKind.JSON_RPC),
                new OpSpec(opBoth, "SharedOp", ProtocolKind.JSON_RPC),
                new OpSpec(opLow, "LowPrivOnly", ProtocolKind.JSON_RPC)
        ));

        addObservation(opAdmin, adminSession, ProtocolKind.JSON_RPC);
        addObservation(opBoth, adminSession, ProtocolKind.JSON_RPC);
        addObservation(opBoth, lowPrivSession, ProtocolKind.JSON_RPC);
        addObservation(opLow, lowPrivSession, ProtocolKind.JSON_RPC);

        RoleComparisonResult result = engine.compare();
        assertEquals(3, result.totalOperations());

        Map<String, CoverageStatus> statusByOp = new HashMap<>();
        for (OperationRoleCoverage c : result.operationCoverages()) {
            statusByOp.put(c.operationName(), c.status());
        }
        assertEquals(CoverageStatus.ADMIN_ONLY, statusByOp.get("AdminOnly"));
        assertEquals(CoverageStatus.BOTH, statusByOp.get("SharedOp"));
        assertEquals(CoverageStatus.LOW_PRIV_ONLY, statusByOp.get("LowPrivOnly"));
    }

    // ---- Sort Order ---------------------------------------------------------

    @Test
    void resultsSortedByStatusThenName() {
        UUID adminSession = createSession("host", "Bearer", "admin-t", "a@t.com", Role.ADMIN);
        UUID lowSession = createSession("host", "Bearer", "low-t", "l@t.com", Role.LOW_PRIV);

        UUID op1 = UUID.randomUUID();
        UUID op2 = UUID.randomUUID();
        UUID op3 = UUID.randomUUID();

        addSurfaceWithOperations(List.of(
                new OpSpec(op1, "ZetaShared", ProtocolKind.JSON_RPC),
                new OpSpec(op2, "AlphaAdmin", ProtocolKind.JSON_RPC),
                new OpSpec(op3, "BetaLow", ProtocolKind.JSON_RPC)
        ));

        addObservation(op1, adminSession, ProtocolKind.JSON_RPC);
        addObservation(op1, lowSession, ProtocolKind.JSON_RPC);
        addObservation(op2, adminSession, ProtocolKind.JSON_RPC);
        addObservation(op3, lowSession, ProtocolKind.JSON_RPC);

        RoleComparisonResult result = engine.compare();
        List<String> names = result.operationCoverages().stream()
                .map(OperationRoleCoverage::operationName).toList();

        // ADMIN_ONLY first, then BOTH, then LOW_PRIV_ONLY
        assertEquals("AlphaAdmin", names.get(0));
        assertEquals("ZetaShared", names.get(1));
        assertEquals("BetaLow", names.get(2));
    }

    // ---- Summary Counts -----------------------------------------------------

    @Test
    void summaryCountsAreAccurate() {
        UUID adminSession = createSession("host", "Bearer", "atk", "a@t.com", Role.ADMIN);
        UUID lowSession = createSession("host", "Bearer", "ltk", "l@t.com", Role.LOW_PRIV);

        UUID op1 = UUID.randomUUID();
        UUID op2 = UUID.randomUUID();

        addSurfaceWithOperations(List.of(
                new OpSpec(op1, "Op1", ProtocolKind.JSON_RPC),
                new OpSpec(op2, "Op2", ProtocolKind.JSON_RPC)
        ));
        addObservation(op1, adminSession, ProtocolKind.JSON_RPC);
        addObservation(op2, adminSession, ProtocolKind.JSON_RPC);
        addObservation(op2, lowSession, ProtocolKind.JSON_RPC);

        RoleComparisonResult result = engine.compare();
        assertEquals(1, result.countsByStatus().getOrDefault(CoverageStatus.ADMIN_ONLY, 0));
        assertEquals(1, result.countsByStatus().getOrDefault(CoverageStatus.BOTH, 0));
    }

    // ---- Parameter Coverage -------------------------------------------------

    @Test
    void parameterNamesExtractedFromAttributes() {
        UUID adminSession = createSession("host", "Bearer", "ptk", "a@t.com", Role.ADMIN);
        UUID opId = UUID.randomUUID();

        addSurfaceWithOperation(opId, "GetDevice", ProtocolKind.JSON_RPC);
        addObservation(opId, adminSession, ProtocolKind.JSON_RPC,
                Map.of("parameterNames", "id,typeName,verbose"));

        RoleComparisonResult result = engine.compare();
        OperationRoleCoverage cov = result.operationCoverages().get(0);
        assertTrue(cov.parameterNames().contains("id"));
        assertTrue(cov.parameterNames().contains("typeName"));
        assertTrue(cov.parameterNames().contains("verbose"));
        assertEquals(3, cov.parameterCoverage().size());
    }

    @Test
    void parameterCoverageDetectsDifferences() {
        UUID adminSession = createSession("host", "Bearer", "atk", "a@t.com", Role.ADMIN);
        UUID lowSession = createSession("host", "Bearer", "ltk", "l@t.com", Role.LOW_PRIV);
        UUID opId = UUID.randomUUID();

        addSurfaceWithOperation(opId, "Search", ProtocolKind.JSON_RPC);
        addObservation(opId, adminSession, ProtocolKind.JSON_RPC,
                Map.of("parameterNames", "query,adminFlag"));
        addObservation(opId, lowSession, ProtocolKind.JSON_RPC,
                Map.of("parameterNames", "query"));

        RoleComparisonResult result = engine.compare();
        OperationRoleCoverage cov = result.operationCoverages().get(0);
        assertEquals(CoverageStatus.BOTH, cov.status());

        Map<String, CoverageStatus> paramStatuses = new HashMap<>();
        for (ParameterRoleCoverage p : cov.parameterCoverage()) {
            paramStatuses.put(p.name(), p.status());
        }
        assertEquals(CoverageStatus.ADMIN_ONLY, paramStatuses.get("adminFlag"));
        assertEquals(CoverageStatus.BOTH, paramStatuses.get("query"));
    }

    // ---- Role Change Recomputation ------------------------------------------

    @Test
    void roleChangeAltersComparison() {
        UUID sessionId = createSession("host", "Bearer", "tok-1", "user@t.com", Role.UNKNOWN);
        UUID opId = UUID.randomUUID();

        addSurfaceWithOperation(opId, "TestOp", ProtocolKind.JSON_RPC);
        addObservation(opId, sessionId, ProtocolKind.JSON_RPC);

        // Before labeling → UNLABELED
        RoleComparisonResult before = engine.compare();
        assertEquals(CoverageStatus.UNLABELED, before.operationCoverages().get(0).status());

        // After labeling → ADMIN_ONLY
        sessionRepo.setRole(sessionId, Role.ADMIN);
        RoleComparisonResult after = engine.compare();
        assertEquals(CoverageStatus.ADMIN_ONLY, after.operationCoverages().get(0).status());
    }

    // ---- Static Classification Method ----------------------------------------

    @Test
    void classifyStatusLogic() {
        assertEquals(CoverageStatus.BOTH, RoleComparisonEngine.classifyStatus(1, 1, 0));
        assertEquals(CoverageStatus.ADMIN_ONLY, RoleComparisonEngine.classifyStatus(1, 0, 0));
        assertEquals(CoverageStatus.LOW_PRIV_ONLY, RoleComparisonEngine.classifyStatus(0, 1, 0));
        assertEquals(CoverageStatus.UNLABELED, RoleComparisonEngine.classifyStatus(0, 0, 1));
        assertEquals(CoverageStatus.UNKNOWN, RoleComparisonEngine.classifyStatus(0, 0, 0));
        // BOTH takes precedence even with unlabeled
        assertEquals(CoverageStatus.BOTH, RoleComparisonEngine.classifyStatus(1, 1, 5));
        // ADMIN takes precedence over unlabeled
        assertEquals(CoverageStatus.ADMIN_ONLY, RoleComparisonEngine.classifyStatus(2, 0, 3));
    }

    // ---- Session Count Accuracy ---------------------------------------------

    @Test
    void sessionCountAccuracy() {
        // Same session, multiple observations → should count session once
        UUID adminSession = createSession("host", "Bearer", "one-tok", "a@t.com", Role.ADMIN);
        UUID opId = UUID.randomUUID();

        addSurfaceWithOperation(opId, "MultiCall", ProtocolKind.JSON_RPC);
        addObservation(opId, adminSession, ProtocolKind.JSON_RPC);
        addObservation(opId, adminSession, ProtocolKind.JSON_RPC); // duplicate
        addObservation(opId, adminSession, ProtocolKind.JSON_RPC); // triplicate

        RoleComparisonResult result = engine.compare();
        assertEquals(1, result.operationCoverages().get(0).adminSessionCount(),
                "Same session should be counted once, not per-observation");
    }

    // ---- Cross-Protocol Operations ------------------------------------------

    @Test
    void mixedProtocolsTrackedSeparately() {
        UUID adminSession = createSession("host", "Bearer", "xtk", "a@t.com", Role.ADMIN);
        UUID rpcOp = UUID.randomUUID();
        UUID gqlOp = UUID.randomUUID();

        addSurfaceWithOperations(List.of(
                new OpSpec(rpcOp, "GetDevice", ProtocolKind.JSON_RPC),
                new OpSpec(gqlOp, "query GetUser", ProtocolKind.GRAPHQL)
        ));
        addObservation(rpcOp, adminSession, ProtocolKind.JSON_RPC);
        addObservation(gqlOp, adminSession, ProtocolKind.GRAPHQL);

        RoleComparisonResult result = engine.compare();
        assertEquals(2, result.totalOperations());
        for (OperationRoleCoverage c : result.operationCoverages()) {
            assertEquals(CoverageStatus.ADMIN_ONLY, c.status());
        }
    }

    // ---- Helpers ------------------------------------------------------------

    private UUID createSession(String host, String mechanism, String tokenHash,
                               String username, Role role) {
        SessionFingerprint fp = new SessionFingerprint(
                host, mechanism, tokenHash, username, "",
                Set.of(), Set.of(), Map.of());
        SessionProfile profile = sessionRepo.upsert(fp, Instant.now());
        if (role != Role.UNKNOWN) {
            sessionRepo.setRole(profile.id(), role);
        }
        return profile.id();
    }

    private void addSurfaceWithOperation(UUID opId, String opName, ProtocolKind kind) {
        addSurfaceWithOperations(List.of(new OpSpec(opId, opName, kind)));
    }

    private void addSurfaceWithOperations(List<OpSpec> specs) {
        ApiSurface current = surfaceRepo.snapshot();
        List<Service> services = new ArrayList<>(current.services());
        List<Operation> operations = new ArrayList<>();
        for (OpSpec spec : specs) {
            operations.add(new Operation(spec.id, spec.kind, spec.name,
                    OperationKind.QUERY, List.of(), Optional.empty(), Optional.empty()));
        }

        UUID serviceId = UUID.randomUUID();
        UUID endpointId = UUID.randomUUID();
        Endpoint endpoint = new Endpoint(endpointId, specs.get(0).kind, "POST", "/rpc",
                Set.of("application/json"), operations);
        Service service = new Service(serviceId, "test-service", "test-host.com", "", List.of(endpoint));
        services.add(service);

        Instant now = Instant.now();
        surfaceRepo.replace(new ApiSurface(
                current.id(), current.projectName(), services,
                current.observations(), current.sessionProfiles(),
                current.relationships(), current.riskSignals(),
                current.recommendations(), current.attackChains(),
                current.createdAt(), now
        ));
    }

    private void addObservation(UUID opId, UUID sessionId, ProtocolKind kind) {
        addObservation(opId, sessionId, kind, Map.of());
    }

    private void addObservation(UUID opId, UUID sessionId, ProtocolKind kind,
                                Map<String, String> extraAttributes) {
        ApiSurface current = surfaceRepo.snapshot();
        List<Observation> observations = new ArrayList<>(current.observations());

        Map<String, String> attrs = new HashMap<>(extraAttributes);
        Observation obs = new Observation(
                UUID.randomUUID(), kind,
                UUID.randomUUID(), UUID.randomUUID(), opId,
                sessionId != null ? Optional.of(sessionId) : Optional.empty(),
                Instant.now(), attrs,
                Optional.empty(), Optional.empty()
        );
        observations.add(obs);

        Instant now = Instant.now();
        surfaceRepo.replace(new ApiSurface(
                current.id(), current.projectName(), current.services(),
                observations, current.sessionProfiles(),
                current.relationships(), current.riskSignals(),
                current.recommendations(), current.attackChains(),
                current.createdAt(), now
        ));
    }

    private record OpSpec(UUID id, String name, ProtocolKind kind) {}
}
