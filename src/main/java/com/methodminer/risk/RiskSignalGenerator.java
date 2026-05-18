package com.methodminer.risk;

import com.methodminer.comparison.CoverageStatus;
import com.methodminer.comparison.OperationRoleCoverage;
import com.methodminer.comparison.ParameterRoleCoverage;
import com.methodminer.comparison.RoleComparisonResult;
import com.methodminer.protocol.ProtocolKind;

import java.time.Instant;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Deterministic, passive analysis engine that converts {@link RoleComparisonResult}
 * into prioritized {@link RiskSignal} objects.
 *
 * <p>The generator applies a fixed set of heuristic rules to each operation's role
 * coverage data, computing a score (0–100), severity, and confidence for each signal.
 * All outputs are deterministic and explainable.
 *
 * <p>This engine performs no active testing, payload generation, or external requests.
 */
public final class RiskSignalGenerator {

    // ---- Keyword patterns (case-insensitive) --------------------------------

    private static final Pattern DESTRUCTIVE_KEYWORDS = Pattern.compile(
            "(?i)(Delete|Remove|Destroy|Purge|Wipe|Revoke|Terminate|Disable)");

    private static final Pattern MUTATION_KEYWORDS = Pattern.compile(
            "(?i)(Update|Set|Create|Add|Assign|Grant|Invite|Modify|Patch|Put|Insert|Enable)");

    private static final Pattern SENSITIVE_KEYWORDS = Pattern.compile(
            "(?i)(Billing|Payment|Security|User|Role|Permission|Admin|Config|Secret|Token|Password|" +
            "Export|Import|Credential|Key|Privilege|Tenant|Account|License|Audit|Policy|Access)");

    private static final Pattern ENUMERATION_KEYWORDS = Pattern.compile(
            "(?i)(^Get|^List|^Search|^Find|^Fetch|^Query|^GetCountOf|^Count|^Lookup|^Browse)");

    private static final Pattern BATCH_KEYWORDS = Pattern.compile(
            "(?i)(ExecuteMultiCall|Batch|Multi|BulkOperation)");

    private static final Pattern GRAPHQL_MUTATION = Pattern.compile(
            "(?i)^mutation\\s");

    // ---- Score factors ------------------------------------------------------

    private static final int SCORE_ADMIN_ONLY = 40;
    private static final int SCORE_GRAPHQL_MUTATION = 20;
    private static final int SCORE_DESTRUCTIVE = 20;
    private static final int SCORE_MUTATION = 15;
    private static final int SCORE_SENSITIVE = 10;
    private static final int SCORE_PARAM_DIFF = 15;
    private static final int SCORE_BATCH = 15;
    private static final int SCORE_ENUMERATION = 10;

    /**
     * Generate risk signals from role comparison data.
     *
     * @param comparison the role comparison result
     * @return an immutable result containing all generated signals, sorted by descending score
     */
    public RiskSignalResult generate(RoleComparisonResult comparison) {
        if (comparison == null || comparison.operationCoverages().isEmpty()) {
            return RiskSignalResult.EMPTY;
        }

        Instant now = Instant.now();
        List<RiskSignal> signals = new ArrayList<>();

        for (OperationRoleCoverage cov : comparison.operationCoverages()) {
            signals.addAll(analyzeOperation(cov, now));
        }

        // Sort by score descending, then by operation name
        signals.sort(Comparator
                .<RiskSignal>comparingInt(s -> -s.score())
                .thenComparing(RiskSignal::operationName));

        // Summary counts
        Map<RiskSeverity, Integer> bySeverity = new EnumMap<>(RiskSeverity.class);
        Map<RiskSignalCategory, Integer> byCategory = new EnumMap<>(RiskSignalCategory.class);
        for (RiskSignal s : signals) {
            bySeverity.merge(s.severity(), 1, Integer::sum);
            byCategory.merge(s.category(), 1, Integer::sum);
        }

        return new RiskSignalResult(now, signals.size(), List.copyOf(signals),
                Map.copyOf(bySeverity), Map.copyOf(byCategory));
    }

    // ---- Per-operation analysis ----------------------------------------------

    private List<RiskSignal> analyzeOperation(OperationRoleCoverage cov, Instant now) {
        List<RiskSignal> signals = new ArrayList<>();
        String name = cov.operationName();
        CoverageStatus status = cov.status();

        boolean isDestructive = DESTRUCTIVE_KEYWORDS.matcher(name).find();
        boolean isMutation = MUTATION_KEYWORDS.matcher(name).find();
        boolean isSensitive = SENSITIVE_KEYWORDS.matcher(name).find();
        boolean isEnumeration = ENUMERATION_KEYWORDS.matcher(name).find();
        boolean isBatch = BATCH_KEYWORDS.matcher(name).find();
        boolean isGraphQlMutation = cov.protocolKind() == ProtocolKind.GRAPHQL &&
                GRAPHQL_MUTATION.matcher(name).find();

        // 1. ADMIN_ONLY operations
        if (status == CoverageStatus.ADMIN_ONLY) {
            if (isDestructive) {
                signals.add(buildSignal(cov, now, RiskSignalCategory.ADMIN_ONLY_DELETE,
                        "Admin-only destructive operation: " + name,
                        buildAdminDeleteSummary(cov),
                        computeScore(true, isGraphQlMutation, true, false, false, false, false),
                        "Attempt this operation with LOW_PRIV session credentials. " +
                                "If it succeeds, this is a privilege escalation vulnerability.",
                        countIndicators(true, isGraphQlMutation, true, isSensitive, false, false, false)));
            } else if (isGraphQlMutation) {
                signals.add(buildSignal(cov, now, RiskSignalCategory.GRAPHQL_MUTATION_PRIVILEGE,
                        "Admin-only GraphQL mutation: " + name,
                        buildGraphQlMutationSummary(cov),
                        computeScore(true, true, false, isMutation, isSensitive, false, false),
                        "Replay this GraphQL mutation with LOW_PRIV session. " +
                                "Check if the server enforces authorization at the resolver level.",
                        countIndicators(true, true, false, isSensitive, false, false, false)));
            } else if (isMutation) {
                signals.add(buildSignal(cov, now, RiskSignalCategory.ADMIN_ONLY_MUTATION,
                        "Admin-only mutation: " + name,
                        buildAdminMutationSummary(cov),
                        computeScore(true, false, false, true, isSensitive, false, false),
                        "Test this mutation with LOW_PRIV credentials. " +
                                "Verify server-side authorization enforcement.",
                        countIndicators(true, false, false, isSensitive, false, false, false)));
            } else {
                signals.add(buildSignal(cov, now, RiskSignalCategory.PRIVILEGED_OPERATION,
                        "Privileged operation: " + name,
                        buildPrivilegedSummary(cov),
                        computeScore(true, false, false, false, isSensitive, false, false),
                        "Attempt this operation with LOW_PRIV session. " +
                                "Verify if access control is enforced.",
                        countIndicators(true, false, false, isSensitive, false, false, false)));
            }
        }

        // 2. BOTH — shared sensitive operations
        if (status == CoverageStatus.BOTH && isSensitive) {
            signals.add(buildSignal(cov, now, RiskSignalCategory.SHARED_SENSITIVE_OPERATION,
                    "Shared sensitive operation: " + name,
                    buildSharedSensitiveSummary(cov),
                    computeSharedScore(isSensitive, isDestructive, isMutation),
                    "Compare response content between ADMIN and LOW_PRIV. " +
                            "Look for data exposure differences (IDOR, horizontal privilege escalation).",
                    countIndicators(false, false, isDestructive, isSensitive, false, false, false)));
        }

        // 3. Parameter differences
        if (status == CoverageStatus.BOTH || status == CoverageStatus.ADMIN_ONLY) {
            List<ParameterRoleCoverage> adminOnlyParams = cov.parameterCoverage().stream()
                    .filter(p -> p.status() == CoverageStatus.ADMIN_ONLY)
                    .toList();
            if (!adminOnlyParams.isEmpty()) {
                signals.add(buildSignal(cov, now, RiskSignalCategory.PARAMETER_EXPOSURE_DIFFERENCE,
                        "Admin-only parameters in: " + name,
                        buildParamDiffSummary(cov, adminOnlyParams),
                        computeScore(status == CoverageStatus.ADMIN_ONLY, false, false, false,
                                isSensitive, true, false),
                        "Add the admin-only parameters to a LOW_PRIV request. " +
                                "If the server processes them, this is a mass-assignment or BOLA vector.",
                        countIndicators(status == CoverageStatus.ADMIN_ONLY, false, false,
                                isSensitive, true, false, false)));
            }
        }

        // 4. Batch/multi-call candidates
        if (isBatch) {
            signals.add(buildSignal(cov, now, RiskSignalCategory.BATCH_CHAIN_CANDIDATE,
                    "Batch chain candidate: " + name,
                    buildBatchSummary(cov),
                    computeScore(status == CoverageStatus.ADMIN_ONLY, false, false, false,
                            false, false, true),
                    "Craft a batch call that chains a privileged operation inside a LOW_PRIV request. " +
                            "Test if batch processing bypasses per-operation authorization.",
                    countIndicators(status == CoverageStatus.ADMIN_ONLY, false, false, false,
                            false, true, false)));
        }

        // 5. Enumeration candidates
        if (isEnumeration && (status == CoverageStatus.BOTH || status == CoverageStatus.ADMIN_ONLY)) {
            signals.add(buildSignal(cov, now, RiskSignalCategory.ENUMERATION_CANDIDATE,
                    "Enumeration candidate: " + name,
                    buildEnumerationSummary(cov),
                    computeScore(status == CoverageStatus.ADMIN_ONLY, false, false, false,
                            false, false, false) + SCORE_ENUMERATION,
                    "Iterate over ID ranges or entity identifiers with LOW_PRIV session. " +
                            "Check if the response leaks data belonging to other users/tenants.",
                    countIndicators(status == CoverageStatus.ADMIN_ONLY, false, false, false,
                            false, false, true)));
        }

        return signals;
    }

    // ---- Score computation --------------------------------------------------

    static int computeScore(boolean adminOnly, boolean graphQlMutation, boolean destructive,
                            boolean mutation, boolean sensitive, boolean paramDiff, boolean batch) {
        int score = 0;
        if (adminOnly) score += SCORE_ADMIN_ONLY;
        if (graphQlMutation) score += SCORE_GRAPHQL_MUTATION;
        if (destructive) score += SCORE_DESTRUCTIVE;
        if (mutation) score += SCORE_MUTATION;
        if (sensitive) score += SCORE_SENSITIVE;
        if (paramDiff) score += SCORE_PARAM_DIFF;
        if (batch) score += SCORE_BATCH;
        return Math.min(100, score);
    }

    private static int computeSharedScore(boolean sensitive, boolean destructive, boolean mutation) {
        int score = 10; // base for shared
        if (sensitive) score += SCORE_SENSITIVE;
        if (destructive) score += SCORE_DESTRUCTIVE;
        if (mutation) score += SCORE_MUTATION;
        return Math.min(100, score);
    }

    // ---- Severity mapping ---------------------------------------------------

    static RiskSeverity mapSeverity(int score) {
        if (score >= 80) return RiskSeverity.CRITICAL;
        if (score >= 60) return RiskSeverity.HIGH;
        if (score >= 35) return RiskSeverity.MEDIUM;
        return RiskSeverity.LOW;
    }

    // ---- Confidence mapping -------------------------------------------------

    static RiskConfidence mapConfidence(int indicatorCount) {
        if (indicatorCount >= 3) return RiskConfidence.HIGH;
        if (indicatorCount >= 2) return RiskConfidence.MEDIUM;
        return RiskConfidence.LOW;
    }

    private static int countIndicators(boolean adminOnly, boolean graphQlMutation,
                                        boolean destructive, boolean sensitive,
                                        boolean paramDiff, boolean batch, boolean enumeration) {
        int count = 0;
        if (adminOnly) count++;
        if (graphQlMutation) count++;
        if (destructive) count++;
        if (sensitive) count++;
        if (paramDiff) count++;
        if (batch) count++;
        if (enumeration) count++;
        return count;
    }

    // ---- Signal builder -----------------------------------------------------

    private static RiskSignal buildSignal(OperationRoleCoverage cov, Instant now,
                                           RiskSignalCategory category, String title,
                                           String summary, int rawScore,
                                           String recommendedAction, int indicatorCount) {
        int score = Math.min(100, rawScore);
        return new RiskSignal(
                UUID.randomUUID(),
                now,
                category,
                title,
                summary,
                cov.protocolKind(),
                cov.host(),
                cov.endpointPath(),
                cov.operationName(),
                mapSeverity(score),
                mapConfidence(indicatorCount),
                score,
                buildEvidenceRefs(cov),
                recommendedAction,
                cov.parameterNames(),
                cov.status()
        );
    }

    // ---- Evidence references ------------------------------------------------

    private static List<String> buildEvidenceRefs(OperationRoleCoverage cov) {
        List<String> refs = new ArrayList<>();
        refs.add("Coverage: " + cov.status().name());
        refs.add("Admin sessions: " + cov.adminSessionCount());
        refs.add("Low-priv sessions: " + cov.lowPrivSessionCount());
        refs.add("Unlabeled sessions: " + cov.unlabeledSessionCount());
        if (!cov.parameterNames().isEmpty()) {
            refs.add("Parameters: " + String.join(", ", cov.parameterNames()));
        }
        return refs;
    }

    // ---- Summary builders ---------------------------------------------------

    private static String buildAdminDeleteSummary(OperationRoleCoverage cov) {
        return String.format(
                "The destructive operation '%s' was observed in %d ADMIN session(s) but never in LOW_PRIV. " +
                "This is a high-priority target for privilege escalation testing. " +
                "If a LOW_PRIV user can invoke this operation, it constitutes a critical authorization bypass.",
                cov.operationName(), cov.adminSessionCount());
    }

    private static String buildGraphQlMutationSummary(OperationRoleCoverage cov) {
        return String.format(
                "The GraphQL mutation '%s' was observed only in ADMIN sessions (%d). " +
                "GraphQL resolvers may lack independent authorization checks. " +
                "Test by replaying the mutation query with LOW_PRIV session credentials.",
                cov.operationName(), cov.adminSessionCount());
    }

    private static String buildAdminMutationSummary(OperationRoleCoverage cov) {
        return String.format(
                "The mutation operation '%s' was observed in %d ADMIN session(s) only. " +
                "State-changing operations restricted to privileged users are prime targets " +
                "for access control testing.",
                cov.operationName(), cov.adminSessionCount());
    }

    private static String buildPrivilegedSummary(OperationRoleCoverage cov) {
        return String.format(
                "The operation '%s' was observed in %d ADMIN session(s) and 0 LOW_PRIV sessions. " +
                "This operation may be missing from the LOW_PRIV UI but still accessible server-side.",
                cov.operationName(), cov.adminSessionCount());
    }

    private static String buildSharedSensitiveSummary(OperationRoleCoverage cov) {
        return String.format(
                "The sensitive operation '%s' is accessible to both ADMIN (%d) and LOW_PRIV (%d) sessions. " +
                "Compare response payloads between roles for data exposure differences (IDOR/BOLA).",
                cov.operationName(), cov.adminSessionCount(), cov.lowPrivSessionCount());
    }

    private static String buildParamDiffSummary(OperationRoleCoverage cov,
                                                 List<ParameterRoleCoverage> adminOnlyParams) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("The operation '%s' has %d parameter(s) observed only in ADMIN sessions: ",
                cov.operationName(), adminOnlyParams.size()));
        adminOnlyParams.forEach(p -> sb.append(p.name()).append(", "));
        sb.setLength(sb.length() - 2);
        sb.append(". These may be mass-assignment or authorization bypass vectors.");
        return sb.toString();
    }

    private static String buildBatchSummary(OperationRoleCoverage cov) {
        return String.format(
                "The batch operation '%s' supports multi-call chaining. " +
                "Privileged operations embedded inside batch requests may bypass per-operation authorization. " +
                "Observed in %d ADMIN, %d LOW_PRIV, %d unlabeled session(s).",
                cov.operationName(), cov.adminSessionCount(), cov.lowPrivSessionCount(),
                cov.unlabeledSessionCount());
    }

    private static String buildEnumerationSummary(OperationRoleCoverage cov) {
        return String.format(
                "The operation '%s' follows a data retrieval pattern suitable for enumeration testing. " +
                "Test with varying entity IDs to check for IDOR/horizontal privilege escalation. " +
                "Observed in %d ADMIN, %d LOW_PRIV session(s).",
                cov.operationName(), cov.adminSessionCount(), cov.lowPrivSessionCount());
    }
}
