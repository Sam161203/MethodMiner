package com.methodminer.payload;

import com.methodminer.comparison.CoverageStatus;
import com.methodminer.core.model.*;
import com.methodminer.core.repository.InMemorySurfaceRepository;
import com.methodminer.protocol.ProtocolKind;
import com.methodminer.risk.*;
import com.methodminer.session.InMemorySessionRepository;
import com.methodminer.session.SessionFingerprint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive tests for {@link PayloadAssembler}.
 */
class PayloadAssemblerTest {

    private InMemorySurfaceRepository surfaceRepo;
    private InMemorySessionRepository sessionRepo;
    private PayloadAssembler assembler;

    @BeforeEach
    void setUp() {
        surfaceRepo = new InMemorySurfaceRepository("test");
        sessionRepo = new InMemorySessionRepository();
        assembler = new PayloadAssembler(surfaceRepo, sessionRepo);
    }

    // ---- Empty Input --------------------------------------------------------

    @Test
    void nullInputReturnsEmpty() {
        PayloadAssemblyResult result = assembler.assemble(null);
        assertEquals(0, result.totalCandidates());
    }

    @Test
    void emptySignalsReturnsEmpty() {
        PayloadAssemblyResult result = assembler.assemble(RiskSignalResult.EMPTY);
        assertEquals(0, result.totalCandidates());
    }

    // ---- JSON-RPC Body Construction -----------------------------------------

    @Test
    void jsonRpcBodyContainsMethodAndParams() {
        com.methodminer.risk.RiskSignal signal = buildSignal("DeleteDevice",
                ProtocolKind.JSON_RPC, RiskSignalCategory.ADMIN_ONLY_DELETE,
                CoverageStatus.ADMIN_ONLY, Set.of("id", "typeName"));

        String body = PayloadAssembler.buildJsonRpcBody(signal);
        assertTrue(body.contains("\"jsonrpc\": \"2.0\""));
        assertTrue(body.contains("\"method\": \"DeleteDevice\""));
        assertTrue(body.contains("\"id\""));
        assertTrue(body.contains("\"typeName\""));
        assertTrue(body.contains("<TARGET_ENTITY_ID>"));
    }

    @Test
    void jsonRpcBodyWithNoParams() {
        com.methodminer.risk.RiskSignal signal = buildSignal("Ping",
                ProtocolKind.JSON_RPC, RiskSignalCategory.PRIVILEGED_OPERATION,
                CoverageStatus.ADMIN_ONLY, Set.of());

        String body = PayloadAssembler.buildJsonRpcBody(signal);
        assertTrue(body.contains("\"method\": \"Ping\""));
        assertTrue(body.contains("\"params\": {"));
    }

    // ---- GraphQL Body Construction ------------------------------------------

    @Test
    void graphQlMutationBodyIsCorrect() {
        com.methodminer.risk.RiskSignal signal = buildSignal("mutation UpdateBilling",
                ProtocolKind.GRAPHQL, RiskSignalCategory.GRAPHQL_MUTATION_PRIVILEGE,
                CoverageStatus.ADMIN_ONLY, Set.of("amount", "userId"));

        String body = PayloadAssembler.buildGraphQlBody(signal);
        assertTrue(body.contains("mutation UpdateBilling"));
        assertTrue(body.contains("$amount: String"));
        assertTrue(body.contains("$userId: String"));
        assertTrue(body.contains("\"variables\""));
    }

    @Test
    void graphQlQueryBodyIsCorrect() {
        com.methodminer.risk.RiskSignal signal = buildSignal("query GetUsers",
                ProtocolKind.GRAPHQL, RiskSignalCategory.ENUMERATION_CANDIDATE,
                CoverageStatus.BOTH, Set.of());

        String body = PayloadAssembler.buildGraphQlBody(signal);
        assertTrue(body.contains("query GetUsers"));
    }

    // ---- Type Mapping -------------------------------------------------------

    @Test
    void typeMapping() {
        assertEquals(PayloadCandidateType.ROLE_REPLAY,
                PayloadAssembler.mapSignalToType(buildSignal("X", ProtocolKind.JSON_RPC,
                        RiskSignalCategory.ADMIN_ONLY_DELETE, CoverageStatus.ADMIN_ONLY, Set.of())));
        assertEquals(PayloadCandidateType.ROLE_REPLAY,
                PayloadAssembler.mapSignalToType(buildSignal("X", ProtocolKind.JSON_RPC,
                        RiskSignalCategory.PRIVILEGED_OPERATION, CoverageStatus.ADMIN_ONLY, Set.of())));
        assertEquals(PayloadCandidateType.PARAMETER_INJECTION,
                PayloadAssembler.mapSignalToType(buildSignal("X", ProtocolKind.JSON_RPC,
                        RiskSignalCategory.PARAMETER_EXPOSURE_DIFFERENCE, CoverageStatus.BOTH, Set.of())));
        assertEquals(PayloadCandidateType.GRAPHQL_MUTATION_REPLAY,
                PayloadAssembler.mapSignalToType(buildSignal("X", ProtocolKind.GRAPHQL,
                        RiskSignalCategory.GRAPHQL_MUTATION_PRIVILEGE, CoverageStatus.ADMIN_ONLY, Set.of())));
        assertEquals(PayloadCandidateType.BATCH_CHAIN_REPLAY,
                PayloadAssembler.mapSignalToType(buildSignal("X", ProtocolKind.JSON_RPC,
                        RiskSignalCategory.BATCH_CHAIN_CANDIDATE, CoverageStatus.BOTH, Set.of())));
        assertEquals(PayloadCandidateType.ENUMERATION_REPLAY,
                PayloadAssembler.mapSignalToType(buildSignal("X", ProtocolKind.JSON_RPC,
                        RiskSignalCategory.ENUMERATION_CANDIDATE, CoverageStatus.BOTH, Set.of())));
    }

    // ---- Placeholder Generation ---------------------------------------------

    @Test
    void placeholderUsedWhenNoLowPrivSession() {
        com.methodminer.risk.RiskSignal signal = buildSignal("DeleteDevice",
                ProtocolKind.JSON_RPC, RiskSignalCategory.ADMIN_ONLY_DELETE,
                CoverageStatus.ADMIN_ONLY, Set.of("id"));

        PayloadAssemblyResult result = assembler.assemble(wrapSignal(signal));
        assertFalse(result.candidates().isEmpty());

        PayloadCandidate candidate = result.candidates().get(0);
        assertTrue(candidate.fullHttpRequest().contains("<LOW_PRIV_AUTH_TOKEN>"));
        assertTrue(candidate.curlCommand().contains("<LOW_PRIV_AUTH_TOKEN>"));
    }

    @Test
    void lowPrivSessionUsedWhenAvailable() {
        // Create a LOW_PRIV session
        SessionFingerprint fp = new SessionFingerprint(
                "host.com", "Bearer", "hash-low", "user@test.com", "",
                Set.of(), Set.of("Authorization"), Map.of());
        SessionProfile profile = sessionRepo.upsert(fp, Instant.now());
        sessionRepo.setRole(profile.id(), Role.LOW_PRIV);

        com.methodminer.risk.RiskSignal signal = buildSignal("DeleteDevice",
                ProtocolKind.JSON_RPC, RiskSignalCategory.ADMIN_ONLY_DELETE,
                CoverageStatus.ADMIN_ONLY, Set.of("id"));

        PayloadAssemblyResult result = assembler.assemble(wrapSignal(signal));
        PayloadCandidate candidate = result.candidates().get(0);

        // Should use the Bearer mechanism from the session
        assertTrue(candidate.fullHttpRequest().contains("Bearer"));
    }

    // ---- Cookie Substitution ------------------------------------------------

    @Test
    void cookieSubstitutionWithLowPrivSession() {
        SessionFingerprint fp = new SessionFingerprint(
                "host.com", "", "", "", "",
                Set.of("session_id", "csrf_token"), Set.of(), Map.of());
        SessionProfile profile = sessionRepo.upsert(fp, Instant.now());
        sessionRepo.setRole(profile.id(), Role.LOW_PRIV);

        com.methodminer.risk.RiskSignal signal = buildSignal("GetData",
                ProtocolKind.JSON_RPC, RiskSignalCategory.PRIVILEGED_OPERATION,
                CoverageStatus.ADMIN_ONLY, Set.of());

        PayloadAssemblyResult result = assembler.assemble(wrapSignal(signal));
        PayloadCandidate candidate = result.candidates().get(0);
        assertTrue(candidate.fullHttpRequest().contains("Cookie:"));
    }

    // ---- cURL Command -------------------------------------------------------

    @Test
    void curlCommandIsValid() {
        com.methodminer.risk.RiskSignal signal = buildSignal("GetUser",
                ProtocolKind.JSON_RPC, RiskSignalCategory.ENUMERATION_CANDIDATE,
                CoverageStatus.BOTH, Set.of("userId"));

        PayloadAssemblyResult result = assembler.assemble(wrapSignal(signal));
        PayloadCandidate candidate = result.candidates().get(0);

        assertTrue(candidate.curlCommand().startsWith("curl -X POST"));
        assertTrue(candidate.curlCommand().contains("Content-Type: application/json"));
        assertTrue(candidate.curlCommand().contains("-d '"));
    }

    // ---- ADMIN_TEMPLATE Generation ------------------------------------------

    @Test
    void adminOnlyGeneratesAdminTemplate() {
        com.methodminer.risk.RiskSignal signal = buildSignal("DeleteDevice",
                ProtocolKind.JSON_RPC, RiskSignalCategory.ADMIN_ONLY_DELETE,
                CoverageStatus.ADMIN_ONLY, Set.of("id"));

        PayloadAssemblyResult result = assembler.assemble(wrapSignal(signal));

        // Should have both ROLE_REPLAY and ADMIN_TEMPLATE
        long replayCount = result.candidates().stream()
                .filter(c -> c.candidateType() == PayloadCandidateType.ROLE_REPLAY).count();
        long templateCount = result.candidates().stream()
                .filter(c -> c.candidateType() == PayloadCandidateType.ADMIN_TEMPLATE).count();
        assertTrue(replayCount >= 1, "Should have at least one ROLE_REPLAY");
        assertTrue(templateCount >= 1, "Should have at least one ADMIN_TEMPLATE");
    }

    @Test
    void adminTemplateHasLowerScore() {
        com.methodminer.risk.RiskSignal signal = buildSignal("DeleteDevice",
                ProtocolKind.JSON_RPC, RiskSignalCategory.ADMIN_ONLY_DELETE,
                CoverageStatus.ADMIN_ONLY, Set.of("id"));

        PayloadAssemblyResult result = assembler.assemble(wrapSignal(signal));

        PayloadCandidate replay = result.candidates().stream()
                .filter(c -> c.candidateType() == PayloadCandidateType.ROLE_REPLAY).findFirst().orElseThrow();
        PayloadCandidate template = result.candidates().stream()
                .filter(c -> c.candidateType() == PayloadCandidateType.ADMIN_TEMPLATE).findFirst().orElseThrow();

        assertTrue(replay.score() > template.score(),
                "ADMIN_TEMPLATE should score lower than ROLE_REPLAY");
    }

    // ---- Sort Order ---------------------------------------------------------

    @Test
    void candidatesSortedByDescendingScore() {
        com.methodminer.risk.RiskSignal s1 = buildSignal("DeleteDevice",
                ProtocolKind.JSON_RPC, RiskSignalCategory.ADMIN_ONLY_DELETE,
                CoverageStatus.ADMIN_ONLY, Set.of("id"), 95);
        com.methodminer.risk.RiskSignal s2 = buildSignal("GetUser",
                ProtocolKind.JSON_RPC, RiskSignalCategory.ENUMERATION_CANDIDATE,
                CoverageStatus.BOTH, Set.of(), 50);

        RiskSignalResult signals = new RiskSignalResult(Instant.now(), 2,
                List.of(s1, s2), Map.of(), Map.of());
        PayloadAssemblyResult result = assembler.assemble(signals);

        for (int i = 0; i < result.candidates().size() - 1; i++) {
            assertTrue(result.candidates().get(i).score() >= result.candidates().get(i + 1).score());
        }
    }

    // ---- Summary Counts -----------------------------------------------------

    @Test
    void summaryCountsAreAccurate() {
        com.methodminer.risk.RiskSignal signal = buildSignal("DeleteDevice",
                ProtocolKind.JSON_RPC, RiskSignalCategory.ADMIN_ONLY_DELETE,
                CoverageStatus.ADMIN_ONLY, Set.of());

        PayloadAssemblyResult result = assembler.assemble(wrapSignal(signal));
        int total = result.countsByType().values().stream().mapToInt(Integer::intValue).sum();
        assertEquals(result.totalCandidates(), total);
    }

    // ---- Candidate Fields ---------------------------------------------------

    @Test
    void candidateHasAllRequiredFields() {
        com.methodminer.risk.RiskSignal signal = buildSignal("UpdateRole",
                ProtocolKind.JSON_RPC, RiskSignalCategory.ADMIN_ONLY_MUTATION,
                CoverageStatus.ADMIN_ONLY, Set.of("roleId", "userId"));

        PayloadAssemblyResult result = assembler.assemble(wrapSignal(signal));
        PayloadCandidate c = result.candidates().get(0);

        assertNotNull(c.id());
        assertNotNull(c.timestamp());
        assertNotNull(c.riskSignalId());
        assertNotNull(c.candidateType());
        assertFalse(c.title().isBlank());
        assertFalse(c.summary().isBlank());
        assertFalse(c.rawBody().isBlank());
        assertFalse(c.fullHttpRequest().isBlank());
        assertFalse(c.curlCommand().isBlank());
        assertFalse(c.variables().isEmpty());
        assertFalse(c.recommendedStep().isBlank());
        assertEquals("LOW_PRIV", c.requiredRole());
    }

    // ---- Variables ----------------------------------------------------------

    @Test
    void variablesIncludeAuthAndParams() {
        com.methodminer.risk.RiskSignal signal = buildSignal("GetDevice",
                ProtocolKind.JSON_RPC, RiskSignalCategory.PRIVILEGED_OPERATION,
                CoverageStatus.ADMIN_ONLY, Set.of("deviceId", "typeName"));

        PayloadAssemblyResult result = assembler.assemble(wrapSignal(signal));
        PayloadCandidate c = result.candidates().get(0);

        assertTrue(c.variables().size() >= 3); // authToken + 2 params
        assertTrue(c.variables().stream().anyMatch(v -> v.name().equals("authToken")));
        assertTrue(c.variables().stream().anyMatch(v -> v.name().equals("deviceId")));
        assertTrue(c.variables().stream().anyMatch(v -> v.name().equals("typeName")));
    }

    // ---- Helpers ------------------------------------------------------------

    private static com.methodminer.risk.RiskSignal buildSignal(String opName, ProtocolKind kind,
                                                                RiskSignalCategory cat,
                                                                CoverageStatus coverage,
                                                                Set<String> params) {
        return buildSignal(opName, kind, cat, coverage, params, 80);
    }

    private static com.methodminer.risk.RiskSignal buildSignal(String opName, ProtocolKind kind,
                                                                RiskSignalCategory cat,
                                                                CoverageStatus coverage,
                                                                Set<String> params, int score) {
        return new com.methodminer.risk.RiskSignal(
                UUID.randomUUID(), Instant.now(), cat,
                "Test: " + opName, "Test summary for " + opName,
                kind, "test-host.com", "/rpc", opName,
                RiskSeverity.HIGH, RiskConfidence.HIGH, score,
                List.of("Coverage: " + coverage), "Test recommendation",
                params, coverage
        );
    }

    private static RiskSignalResult wrapSignal(com.methodminer.risk.RiskSignal signal) {
        return new RiskSignalResult(Instant.now(), 1, List.of(signal), Map.of(), Map.of());
    }
}
