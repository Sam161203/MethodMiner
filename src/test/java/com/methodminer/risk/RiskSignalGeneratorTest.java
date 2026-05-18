package com.methodminer.risk;

import com.methodminer.comparison.CoverageStatus;
import com.methodminer.comparison.OperationRoleCoverage;
import com.methodminer.comparison.ParameterRoleCoverage;
import com.methodminer.comparison.RoleComparisonResult;
import com.methodminer.protocol.ProtocolKind;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive tests for {@link RiskSignalGenerator}.
 */
class RiskSignalGeneratorTest {

    private RiskSignalGenerator generator;

    @BeforeEach
    void setUp() {
        generator = new RiskSignalGenerator();
    }

    // ---- Empty/Null Input ----------------------------------------------------

    @Test
    void nullComparisonReturnsEmpty() {
        RiskSignalResult result = generator.generate(null);
        assertEquals(0, result.totalSignals());
        assertTrue(result.signals().isEmpty());
    }

    @Test
    void emptyComparisonReturnsEmpty() {
        RiskSignalResult result = generator.generate(RoleComparisonResult.EMPTY);
        assertEquals(0, result.totalSignals());
    }

    // ---- ADMIN_ONLY Classification ------------------------------------------

    @Test
    void adminOnlyDeleteGeneratesAdminOnlyDeleteSignal() {
        OperationRoleCoverage cov = coverage("DeleteDevice", CoverageStatus.ADMIN_ONLY,
                ProtocolKind.JSON_RPC, 2, 0, 0);

        RiskSignalResult result = generate(cov);
        assertTrue(result.totalSignals() > 0);

        RiskSignal signal = findByCategory(result, RiskSignalCategory.ADMIN_ONLY_DELETE);
        assertNotNull(signal, "Should generate ADMIN_ONLY_DELETE signal for DeleteDevice");
        assertTrue(signal.score() >= 60, "Delete + admin-only should score high");
        assertEquals(CoverageStatus.ADMIN_ONLY, signal.coverageStatus());
    }

    @Test
    void adminOnlyMutationGeneratesAdminOnlyMutationSignal() {
        OperationRoleCoverage cov = coverage("UpdateBilling", CoverageStatus.ADMIN_ONLY,
                ProtocolKind.JSON_RPC, 1, 0, 0);

        RiskSignalResult result = generate(cov);
        RiskSignal signal = findByCategory(result, RiskSignalCategory.ADMIN_ONLY_MUTATION);
        assertNotNull(signal, "Should generate ADMIN_ONLY_MUTATION for UpdateBilling");
        assertTrue(signal.score() >= 55);
    }

    @Test
    void adminOnlyGenericGeneratesPrivilegedOperationSignal() {
        OperationRoleCoverage cov = coverage("ViewAuditLog", CoverageStatus.ADMIN_ONLY,
                ProtocolKind.JSON_RPC, 1, 0, 0);

        RiskSignalResult result = generate(cov);
        RiskSignal signal = findByCategory(result, RiskSignalCategory.PRIVILEGED_OPERATION);
        assertNotNull(signal, "Should generate PRIVILEGED_OPERATION for ViewAuditLog");
        assertEquals(CoverageStatus.ADMIN_ONLY, signal.coverageStatus());
    }

    // ---- GraphQL Mutations --------------------------------------------------

    @Test
    void graphQlMutationGeneratesGraphQlMutationPrivilegeSignal() {
        OperationRoleCoverage cov = coverage("mutation UpdateBilling", CoverageStatus.ADMIN_ONLY,
                ProtocolKind.GRAPHQL, 1, 0, 0);

        RiskSignalResult result = generate(cov);
        RiskSignal signal = findByCategory(result, RiskSignalCategory.GRAPHQL_MUTATION_PRIVILEGE);
        assertNotNull(signal, "Should generate GRAPHQL_MUTATION_PRIVILEGE");
        assertTrue(signal.score() >= 60);
    }

    // ---- Shared Sensitive Operations ----------------------------------------

    @Test
    void sharedSensitiveOperationGeneratesSignal() {
        OperationRoleCoverage cov = coverage("GetUserPermissions", CoverageStatus.BOTH,
                ProtocolKind.JSON_RPC, 2, 3, 0);

        RiskSignalResult result = generate(cov);
        RiskSignal signal = findByCategory(result, RiskSignalCategory.SHARED_SENSITIVE_OPERATION);
        assertNotNull(signal, "Should generate SHARED_SENSITIVE_OPERATION for sensitive shared op");
    }

    // ---- Parameter Differences ----------------------------------------------

    @Test
    void parameterDifferenceGeneratesSignal() {
        List<ParameterRoleCoverage> paramCovs = List.of(
                new ParameterRoleCoverage("query", CoverageStatus.BOTH, Map.of()),
                new ParameterRoleCoverage("adminFlag", CoverageStatus.ADMIN_ONLY, Map.of())
        );
        OperationRoleCoverage cov = new OperationRoleCoverage(
                UUID.randomUUID(), ProtocolKind.JSON_RPC, "host.com", "/rpc",
                "Search", CoverageStatus.BOTH, 1, 1, 0,
                Set.of("query", "adminFlag"), paramCovs
        );

        RiskSignalResult result = generate(cov);
        RiskSignal signal = findByCategory(result, RiskSignalCategory.PARAMETER_EXPOSURE_DIFFERENCE);
        assertNotNull(signal, "Should generate PARAMETER_EXPOSURE_DIFFERENCE");
        assertTrue(signal.summary().contains("adminFlag"));
    }

    // ---- Batch Chain --------------------------------------------------------

    @Test
    void batchChainCandidateGeneratesSignal() {
        OperationRoleCoverage cov = coverage("ExecuteMultiCall", CoverageStatus.BOTH,
                ProtocolKind.JSON_RPC, 2, 2, 0);

        RiskSignalResult result = generate(cov);
        RiskSignal signal = findByCategory(result, RiskSignalCategory.BATCH_CHAIN_CANDIDATE);
        assertNotNull(signal, "Should generate BATCH_CHAIN_CANDIDATE for ExecuteMultiCall");
    }

    // ---- Enumeration --------------------------------------------------------

    @Test
    void enumerationCandidateGeneratesSignal() {
        OperationRoleCoverage cov = coverage("GetUser", CoverageStatus.BOTH,
                ProtocolKind.JSON_RPC, 1, 1, 0);

        RiskSignalResult result = generate(cov);
        RiskSignal signal = findByCategory(result, RiskSignalCategory.ENUMERATION_CANDIDATE);
        assertNotNull(signal, "Should generate ENUMERATION_CANDIDATE for GetUser");
    }

    @Test
    void searchPatternGeneratesEnumerationSignal() {
        OperationRoleCoverage cov = coverage("SearchDevices", CoverageStatus.ADMIN_ONLY,
                ProtocolKind.JSON_RPC, 1, 0, 0);

        RiskSignalResult result = generate(cov);
        RiskSignal signal = findByCategory(result, RiskSignalCategory.ENUMERATION_CANDIDATE);
        assertNotNull(signal, "Should generate ENUMERATION_CANDIDATE for SearchDevices");
    }

    // ---- Score Computation --------------------------------------------------

    @Test
    void scoreComputationFactors() {
        // Admin-only + destructive + sensitive = 40 + 20 + 10 = 70
        int score = RiskSignalGenerator.computeScore(true, false, true, false, true, false, false);
        assertEquals(70, score);

        // Admin-only + graphql mutation + destructive = 40 + 20 + 20 = 80
        int score2 = RiskSignalGenerator.computeScore(true, true, true, false, false, false, false);
        assertEquals(80, score2);

        // All factors = capped at 100
        int maxScore = RiskSignalGenerator.computeScore(true, true, true, true, true, true, true);
        assertEquals(100, maxScore);

        // No factors = 0
        int zeroScore = RiskSignalGenerator.computeScore(false, false, false, false, false, false, false);
        assertEquals(0, zeroScore);
    }

    // ---- Severity Mapping ---------------------------------------------------

    @Test
    void severityMapping() {
        assertEquals(RiskSeverity.CRITICAL, RiskSignalGenerator.mapSeverity(95));
        assertEquals(RiskSeverity.CRITICAL, RiskSignalGenerator.mapSeverity(80));
        assertEquals(RiskSeverity.HIGH, RiskSignalGenerator.mapSeverity(79));
        assertEquals(RiskSeverity.HIGH, RiskSignalGenerator.mapSeverity(60));
        assertEquals(RiskSeverity.MEDIUM, RiskSignalGenerator.mapSeverity(59));
        assertEquals(RiskSeverity.MEDIUM, RiskSignalGenerator.mapSeverity(35));
        assertEquals(RiskSeverity.LOW, RiskSignalGenerator.mapSeverity(34));
        assertEquals(RiskSeverity.LOW, RiskSignalGenerator.mapSeverity(0));
    }

    // ---- Confidence Mapping -------------------------------------------------

    @Test
    void confidenceMapping() {
        assertEquals(RiskConfidence.HIGH, RiskSignalGenerator.mapConfidence(3));
        assertEquals(RiskConfidence.HIGH, RiskSignalGenerator.mapConfidence(5));
        assertEquals(RiskConfidence.MEDIUM, RiskSignalGenerator.mapConfidence(2));
        assertEquals(RiskConfidence.LOW, RiskSignalGenerator.mapConfidence(1));
        assertEquals(RiskConfidence.LOW, RiskSignalGenerator.mapConfidence(0));
    }

    // ---- Sort Order ---------------------------------------------------------

    @Test
    void signalsSortedByDescendingScore() {
        RoleComparisonResult comparison = new RoleComparisonResult(
                Instant.now(), 3, 3, List.of(
                coverage("GetUser", CoverageStatus.BOTH, ProtocolKind.JSON_RPC, 1, 1, 0),
                coverage("DeleteDevice", CoverageStatus.ADMIN_ONLY, ProtocolKind.JSON_RPC, 1, 0, 0),
                coverage("Ping", CoverageStatus.UNLABELED, ProtocolKind.JSON_RPC, 0, 0, 1)
        ), Map.of());

        RiskSignalResult result = generator.generate(comparison);
        if (result.signals().size() >= 2) {
            for (int i = 0; i < result.signals().size() - 1; i++) {
                assertTrue(result.signals().get(i).score() >= result.signals().get(i + 1).score(),
                        "Signals should be sorted by descending score");
            }
        }
    }

    // ---- Deterministic Output -----------------------------------------------

    @Test
    void outputIsDeterministic() {
        OperationRoleCoverage cov = coverage("DeleteUser", CoverageStatus.ADMIN_ONLY,
                ProtocolKind.JSON_RPC, 1, 0, 0);
        RoleComparisonResult comparison = new RoleComparisonResult(
                Instant.now(), 1, 1, List.of(cov), Map.of());

        RiskSignalResult r1 = generator.generate(comparison);
        RiskSignalResult r2 = generator.generate(comparison);

        assertEquals(r1.totalSignals(), r2.totalSignals());
        for (int i = 0; i < r1.signals().size(); i++) {
            assertEquals(r1.signals().get(i).category(), r2.signals().get(i).category());
            assertEquals(r1.signals().get(i).score(), r2.signals().get(i).score());
            assertEquals(r1.signals().get(i).severity(), r2.signals().get(i).severity());
            assertEquals(r1.signals().get(i).operationName(), r2.signals().get(i).operationName());
        }
    }

    // ---- Summary Counts -----------------------------------------------------

    @Test
    void summaryCountsAreAccurate() {
        RoleComparisonResult comparison = new RoleComparisonResult(
                Instant.now(), 2, 2, List.of(
                coverage("DeleteDevice", CoverageStatus.ADMIN_ONLY, ProtocolKind.JSON_RPC, 1, 0, 0),
                coverage("GetUser", CoverageStatus.BOTH, ProtocolKind.JSON_RPC, 1, 1, 0)
        ), Map.of());

        RiskSignalResult result = generator.generate(comparison);
        int totalFromCounts = result.countsBySeverity().values().stream().mapToInt(Integer::intValue).sum();
        assertEquals(result.totalSignals(), totalFromCounts);
    }

    // ---- No Signal for UNLABELED/UNKNOWN ------------------------------------

    @Test
    void unlabeledOnlyDoesNotGeneratePrivilegedSignal() {
        OperationRoleCoverage cov = coverage("SomeOp", CoverageStatus.UNLABELED,
                ProtocolKind.JSON_RPC, 0, 0, 3);

        RiskSignalResult result = generate(cov);
        assertNull(findByCategory(result, RiskSignalCategory.PRIVILEGED_OPERATION),
                "UNLABELED ops should not generate PRIVILEGED_OPERATION signals");
    }

    // ---- Signal Has Required Fields -----------------------------------------

    @Test
    void signalContainsAllRequiredFields() {
        OperationRoleCoverage cov = coverage("DeleteDevice", CoverageStatus.ADMIN_ONLY,
                ProtocolKind.JSON_RPC, 1, 0, 0);
        RiskSignalResult result = generate(cov);
        RiskSignal signal = result.signals().get(0);

        assertNotNull(signal.id());
        assertNotNull(signal.timestamp());
        assertNotNull(signal.category());
        assertFalse(signal.title().isBlank());
        assertFalse(signal.summary().isBlank());
        assertNotNull(signal.protocolKind());
        assertNotNull(signal.severity());
        assertNotNull(signal.confidence());
        assertTrue(signal.score() >= 0 && signal.score() <= 100);
        assertFalse(signal.evidenceRefs().isEmpty());
        assertFalse(signal.recommendedAction().isBlank());
        assertNotNull(signal.coverageStatus());
    }

    // ---- Helpers ------------------------------------------------------------

    private RiskSignalResult generate(OperationRoleCoverage cov) {
        RoleComparisonResult comparison = new RoleComparisonResult(
                Instant.now(), 1, 1, List.of(cov), Map.of());
        return generator.generate(comparison);
    }

    private static OperationRoleCoverage coverage(String name, CoverageStatus status,
                                                   ProtocolKind kind, int admin, int lowPriv,
                                                   int unlabeled) {
        return new OperationRoleCoverage(
                UUID.randomUUID(), kind, "test-host.com", "/rpc", name,
                status, admin, lowPriv, unlabeled, Set.of(), List.of()
        );
    }

    private static RiskSignal findByCategory(RiskSignalResult result, RiskSignalCategory category) {
        return result.signals().stream()
                .filter(s -> s.category() == category)
                .findFirst().orElse(null);
    }
}
