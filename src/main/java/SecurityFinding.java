import java.time.Instant;

public record SecurityFinding(
        String findingId,
        String method,
        int riskScore,
        RiskLevel riskLevel,
        String trigger,
        String whyFlagged,
        Instant firstSeen,
        Instant lastSeen,
        boolean exported,
        boolean reviewed
) {
    public String riskDisplay() {
        return riskLevel.displayName() + " (" + riskScore + ")";
    }

    public SecurityFinding withReviewed(boolean nextReviewed) {
        return new SecurityFinding(
                findingId,
                method,
                riskScore,
                riskLevel,
                trigger,
                whyFlagged,
                firstSeen,
                lastSeen,
                exported,
                nextReviewed
        );
    }

    public SecurityFinding withExported(boolean nextExported) {
        return new SecurityFinding(
                findingId,
                method,
                riskScore,
                riskLevel,
                trigger,
                whyFlagged,
                firstSeen,
                lastSeen,
                nextExported,
                reviewed
        );
    }

    public enum RiskLevel {
        LOW("Low"),
        MEDIUM("Medium"),
        HIGH("High"),
        CRITICAL("Critical");

        private final String displayName;

        RiskLevel(String displayName) {
            this.displayName = displayName;
        }

        public String displayName() {
            return displayName;
        }

        public static RiskLevel fromScore(int score) {
            if (score >= 80) {
                return CRITICAL;
            }
            if (score >= 60) {
                return HIGH;
            }
            if (score >= 35) {
                return MEDIUM;
            }
            return LOW;
        }
    }
}
