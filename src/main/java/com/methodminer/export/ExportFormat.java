package com.methodminer.export;

/**
 * Supported export formats.
 */
public enum ExportFormat {
    MARKDOWN("md", "text/markdown"),
    JSON("json", "application/json"),
    JSONL("jsonl", "application/x-ndjson"),
    CSV("csv", "text/csv");

    private final String extension;
    private final String mimeType;

    ExportFormat(String extension, String mimeType) {
        this.extension = extension;
        this.mimeType = mimeType;
    }

    public String extension() { return extension; }
    public String mimeType() { return mimeType; }
}
