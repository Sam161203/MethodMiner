package com.methodminer.export;

import java.util.Objects;

/**
 * Configuration options for intelligence export.
 *
 * @param includeSessions       include session profile data
 * @param includeComparisons    include role comparison results
 * @param includeRiskSignals    include ranked risk signals
 * @param includePayloads       include assembled payloads
 * @param includeSchemaSummary  include API schema summary
 * @param includeTimestamps     include observation timestamps
 * @param redactPlaceholders    replace placeholder tokens with "[REDACTED]"
 * @param projectName           project name for file prefixing
 */
public record ExportOptions(
        boolean includeSessions,
        boolean includeComparisons,
        boolean includeRiskSignals,
        boolean includePayloads,
        boolean includeSchemaSummary,
        boolean includeTimestamps,
        boolean redactPlaceholders,
        String projectName
) {
    /** Default options: include everything, no redaction. */
    public static final ExportOptions DEFAULTS = new ExportOptions(
            true, true, true, true, true, true, false, "methodminer");

    public ExportOptions {
        projectName = Objects.requireNonNullElse(projectName, "methodminer");
        if (projectName.isBlank()) projectName = "methodminer";
    }
}
