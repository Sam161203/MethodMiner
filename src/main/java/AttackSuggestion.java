public record AttackSuggestion(
        String suggestionId,
        String category,
        String findingTitle,
        int priorityScore,
        SecurityFinding.RiskLevel priorityLevel,
        Confidence confidence,
        Verdict verdict,
        String primaryMethod,
        String attackPath,
        String observation,
        String whySuspicious,
        String exploitPayload,
        String expectedResult,
        String ifVulnerable,
        String impact,
        String evidence,
        String host,
        int confidenceScore,
        int effectivenessScore,
        String repeaterRequest,
        String findingType,
        String findingConfidence,
        String sessionId,
        String entityId,
        String method,
        String typeName,
        String adminResponse,
        String lowPrivResponse,
        String payload,
        String bugcrowdMarkdown
) {
    public String priorityDisplay() {
        return priorityLevel.displayName() + " (" + priorityScore + ")";
    }

    public String confidenceDisplay() {
        return confidence.name();
    }

    public String verdictDisplay() {
        return switch (verdict) {
            case LIKELY_VULNERABILITY -> "Likely vulnerability";
            case LIKELY_SAFE -> "Likely safe behavior";
        };
    }

    public String toFormattedFinding() {
        if (bugcrowdMarkdown != null && !bugcrowdMarkdown.isBlank()) {
            return bugcrowdMarkdown;
        }

        StringBuilder builder = new StringBuilder();
        builder.append(findingTitle).append("\n\n");
        builder.append("Target host:\n");
        builder.append("* ").append(host == null ? "" : host).append("\n\n");

        builder.append("Method and path:\n");
        builder.append("* ").append(primaryMethod).append(" | ").append(attackPath).append("\n\n");

        builder.append("Scores:\n");
        builder.append("* Confidence score: ").append(confidenceScore).append("/100\n");
        builder.append("* Effectiveness score: ").append(effectivenessScore).append("/100\n");
        builder.append("* Priority: ").append(priorityDisplay()).append("\n\n");

        builder.append("Observation:\n");
        builder.append("* ").append(observation).append("\n\n");

        builder.append("Why this is suspicious:\n");
        builder.append("* ").append(whySuspicious).append("\n\n");

        builder.append("Exploit test:\n");
        builder.append("* TEST THIS EXACT REPEATER REQUEST:\n");
        builder.append(repeaterRequest == null || repeaterRequest.isBlank() ? exploitPayload : repeaterRequest).append("\n\n");

        builder.append("Expected result:\n");
        builder.append("* ").append(expectedResult).append("\n\n");

        builder.append("If vulnerable:\n");
        builder.append("* ").append(ifVulnerable).append("\n\n");

        builder.append("Impact:\n");
        builder.append("* ").append(impact).append("\n\n");

        builder.append("Confidence:\n");
        builder.append("* ").append(confidenceDisplay()).append(" (score ").append(confidenceScore).append(")\n\n");

        builder.append("Decision:\n");
        builder.append("* ").append(verdictDisplay()).append(" (" + priorityDisplay() + ")").append("\n\n");

        builder.append("Evidence:\n");
        builder.append("* ").append(evidence);
        return builder.toString();
    }

    public String effectivePayload() {
        if (payload != null && !payload.isBlank()) {
            return payload;
        }
        if (exploitPayload != null && !exploitPayload.isBlank()) {
            return exploitPayload;
        }
        return repeaterRequest == null ? "" : repeaterRequest;
    }

    public enum Confidence {
        LOW,
        MEDIUM,
        HIGH
    }

    public enum Verdict {
        LIKELY_VULNERABILITY,
        LIKELY_SAFE
    }
}
