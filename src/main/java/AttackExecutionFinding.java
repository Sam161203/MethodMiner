import java.time.Instant;

public record AttackExecutionFinding(
        String findingId,
        String category,
        SecurityFinding.RiskLevel severity,
        boolean confirmed,
        String method,
        String entityId,
        String sourceContext,
        String targetContext,
        RoleType sourceRole,
        RoleType targetRole,
        String payloadUsed,
        String responseClassification,
        String exploitChain,
        String summary,
        Instant executedAt
) {
}
