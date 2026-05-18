package com.methodminer.export;

import java.util.Objects;

/**
 * A single export artifact containing generated content.
 *
 * @param fileName    deterministic file name (e.g. "methodminer-report.md")
 * @param format      export format
 * @param mimeType    MIME type
 * @param content     generated content as a string
 * @param sizeBytes   content size in bytes (UTF-8)
 * @param description human-readable description of this artifact
 */
public record ExportArtifact(
        String fileName,
        ExportFormat format,
        String mimeType,
        String content,
        long sizeBytes,
        String description
) {
    public ExportArtifact {
        fileName = Objects.requireNonNull(fileName, "fileName");
        format = Objects.requireNonNull(format, "format");
        mimeType = Objects.requireNonNullElse(mimeType, format.mimeType());
        content = Objects.requireNonNullElse(content, "");
        description = Objects.requireNonNullElse(description, "");
    }

    /** Create an artifact with auto-computed size. */
    public static ExportArtifact of(String fileName, ExportFormat format, String content,
                                     String description) {
        long size = content != null ? content.getBytes(java.nio.charset.StandardCharsets.UTF_8).length : 0;
        return new ExportArtifact(fileName, format, format.mimeType(), content, size, description);
    }
}
