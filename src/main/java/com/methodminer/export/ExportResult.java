package com.methodminer.export;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * Immutable result of an intelligence export operation.
 *
 * @param exportedAt    when the export was generated
 * @param artifacts     list of generated artifacts
 * @param totalBytes    total bytes across all artifacts
 * @param summary       human-readable summary of what was exported
 */
public record ExportResult(
        Instant exportedAt,
        List<ExportArtifact> artifacts,
        long totalBytes,
        String summary
) {
    public static final ExportResult EMPTY = new ExportResult(
            Instant.EPOCH, List.of(), 0, "No data to export.");

    public ExportResult {
        exportedAt = Objects.requireNonNull(exportedAt, "exportedAt");
        artifacts = List.copyOf(Objects.requireNonNullElse(artifacts, List.of()));
        summary = Objects.requireNonNullElse(summary, "");
    }
}
