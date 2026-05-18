package com.methodminer.export;

import com.methodminer.comparison.OperationRoleCoverage;
import com.methodminer.comparison.RoleComparisonResult;
import com.methodminer.core.model.ApiSurface;
import com.methodminer.core.model.SessionProfile;
import com.methodminer.payload.PayloadAssemblyResult;
import com.methodminer.payload.PayloadCandidate;
import com.methodminer.risk.RiskSignal;
import com.methodminer.risk.RiskSignalResult;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Deterministic, passive intelligence export engine.
 *
 * <p>Serializes Method Miner intelligence into Markdown, JSON, JSONL, and CSV.
 * Never includes raw authentication secrets. All output is reproducible.
 */
public final class IntelligenceExporter {

    private static final DateTimeFormatter TS_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneOffset.UTC);

    /**
     * Generate export artifacts from the current intelligence state.
     */
    public ExportResult export(ApiSurface surface,
                                List<SessionProfile> sessions,
                                RoleComparisonResult comparison,
                                RiskSignalResult signals,
                                PayloadAssemblyResult payloads,
                                ExportOptions options) {
        Objects.requireNonNull(options, "options");

        Instant now = Instant.now();
        List<ExportArtifact> artifacts = new ArrayList<>();
        String prefix = options.projectName();

        // Always generate Markdown report
        artifacts.add(generateMarkdownReport(surface, sessions, comparison, signals, payloads, options, prefix));

        // JSON export
        if (options.includeRiskSignals() && signals != null && !signals.signals().isEmpty()) {
            artifacts.add(generateJsonSignals(signals, prefix));
        }

        // JSONL export
        if (options.includeRiskSignals() && signals != null && !signals.signals().isEmpty()) {
            artifacts.add(generateJsonlSignals(signals, prefix));
        }

        // CSV export
        if (options.includeRiskSignals() && signals != null && !signals.signals().isEmpty()) {
            artifacts.add(generateCsvSignals(signals, prefix));
        }

        // Payloads JSONL
        if (options.includePayloads() && payloads != null && !payloads.candidates().isEmpty()) {
            artifacts.add(generateJsonlPayloads(payloads, prefix));
        }

        // Sessions CSV
        if (options.includeSessions() && sessions != null && !sessions.isEmpty()) {
            artifacts.add(generateCsvSessions(sessions, prefix));
        }

        long totalBytes = artifacts.stream().mapToLong(ExportArtifact::sizeBytes).sum();
        String summary = buildSummary(artifacts, totalBytes);

        return new ExportResult(now, List.copyOf(artifacts), totalBytes, summary);
    }

    // ---- Markdown Report ----------------------------------------------------

    private ExportArtifact generateMarkdownReport(ApiSurface surface,
                                                   List<SessionProfile> sessions,
                                                   RoleComparisonResult comparison,
                                                   RiskSignalResult signals,
                                                   PayloadAssemblyResult payloads,
                                                   ExportOptions options,
                                                   String prefix) {
        StringBuilder md = new StringBuilder();
        md.append("# Method Miner Intelligence Report\n\n");
        md.append("**Generated**: ").append(TS_FMT.format(Instant.now())).append(" UTC\n\n");

        // Executive summary
        md.append("## Executive Summary\n\n");
        md.append(buildExecutiveSummary(surface, sessions, comparison, signals, payloads));
        md.append("\n");

        // Schema summary
        if (options.includeSchemaSummary() && surface != null) {
            int endpointCount = surface.services().stream().mapToInt(s -> s.endpoints().size()).sum();
            int operationCount = surface.services().stream()
                    .flatMap(s -> s.endpoints().stream())
                    .mapToInt(ep -> ep.operations().size()).sum();
            md.append("## API Surface\n\n");
            md.append("| Metric | Value |\n");
            md.append("|--------|-------|\n");
            md.append("| Services | ").append(surface.services().size()).append(" |\n");
            md.append("| Endpoints | ").append(endpointCount).append(" |\n");
            md.append("| Operations | ").append(operationCount).append(" |\n");
            md.append("| Observations | ").append(surface.observations().size()).append(" |\n\n");
        }

        // Sessions
        if (options.includeSessions() && sessions != null && !sessions.isEmpty()) {
            md.append("## Session Profiles\n\n");
            md.append("| Host | Username | Role | Mechanism | Requests | First Seen | Last Seen |\n");
            md.append("|------|----------|------|-----------|----------|------------|----------|\n");
            for (SessionProfile sp : sessions) {
                md.append("| ").append(sp.host());
                md.append(" | ").append(sp.username().isBlank() ? "-" : sp.username());
                md.append(" | **").append(sp.role()).append("**");
                md.append(" | ").append(String.join(", ", sp.authMechanisms()));
                md.append(" | ").append(sp.requestCount());
                md.append(" | ").append(options.includeTimestamps() ? TS_FMT.format(sp.firstSeen()) : "-");
                md.append(" | ").append(options.includeTimestamps() ? TS_FMT.format(sp.lastSeen()) : "-");
                md.append(" |\n");
            }
            md.append("\n");
        }

        // Role comparison
        if (options.includeComparisons() && comparison != null
                && !comparison.operationCoverages().isEmpty()) {
            md.append("## Role Comparison\n\n");
            md.append("| Operation | Protocol | Coverage | Admin | Low-Priv | Parameters |\n");
            md.append("|-----------|----------|----------|-------|----------|------------|\n");
            for (OperationRoleCoverage orc : comparison.operationCoverages()) {
                md.append("| ").append(orc.operationName());
                md.append(" | ").append(orc.protocolKind());
                md.append(" | **").append(orc.status()).append("**");
                md.append(" | ").append(orc.adminSessionCount());
                md.append(" | ").append(orc.lowPrivSessionCount());
                md.append(" | ").append(orc.parameterNames().size());
                md.append(" |\n");
            }
            md.append("\n");
            if (!comparison.countsByStatus().isEmpty()) {
                md.append("**Coverage Summary**: ");
                comparison.countsByStatus().forEach((status, count) ->
                        md.append(status).append(": ").append(count).append("  "));
                md.append("\n\n");
            }
        }

        // Risk signals
        if (options.includeRiskSignals() && signals != null && !signals.signals().isEmpty()) {
            md.append("## Risk Signals\n\n");
            md.append("| # | Score | Severity | Category | Operation | Protocol | Coverage |\n");
            md.append("|---|-------|----------|----------|-----------|----------|----------|\n");
            int i = 1;
            for (RiskSignal s : signals.signals()) {
                md.append("| ").append(i++);
                md.append(" | **").append(s.score()).append("**");
                md.append(" | ").append(s.severity());
                md.append(" | ").append(s.category());
                md.append(" | ").append(s.operationName());
                md.append(" | ").append(s.protocolKind());
                md.append(" | ").append(s.coverageStatus());
                md.append(" |\n");
            }
            md.append("\n");
            if (!signals.countsBySeverity().isEmpty()) {
                md.append("**Severity Summary**: ");
                signals.countsBySeverity().forEach((sev, count) ->
                        md.append(sev).append(": ").append(count).append("  "));
                md.append("\n\n");
            }

            // Signal details
            md.append("### Signal Details\n\n");
            for (RiskSignal s : signals.signals()) {
                md.append("#### ").append(s.title()).append("\n\n");
                md.append("- **Score**: ").append(s.score()).append("/100\n");
                md.append("- **Severity**: ").append(s.severity()).append("\n");
                md.append("- **Confidence**: ").append(s.confidence()).append("\n");
                md.append("- **Category**: ").append(s.category()).append("\n");
                md.append("- **Operation**: ").append(s.operationName()).append("\n");
                md.append("- **Protocol**: ").append(s.protocolKind()).append("\n");
                md.append("- **Host**: ").append(s.host()).append("\n");
                md.append("- **Coverage**: ").append(s.coverageStatus()).append("\n\n");
                md.append(s.summary()).append("\n\n");
                md.append("**Recommended Action**: ").append(s.recommendedAction()).append("\n\n");
                md.append("---\n\n");
            }
        }

        // Payloads
        if (options.includePayloads() && payloads != null && !payloads.candidates().isEmpty()) {
            md.append("## Payloads\n\n");
            int idx = 1;
            for (PayloadCandidate c : payloads.candidates()) {
                md.append("### ").append(idx++).append(". ").append(c.title()).append("\n\n");
                md.append("- **Type**: ").append(c.candidateType()).append("\n");
                md.append("- **Score**: ").append(c.score()).append("\n");
                md.append("- **Protocol**: ").append(c.protocolKind()).append("\n");
                md.append("- **Required Role**: ").append(c.requiredRole()).append("\n\n");
                md.append(c.summary()).append("\n\n");

                String body = options.redactPlaceholders() ? redact(c.rawBody()) : c.rawBody();
                md.append("**Request Body**:\n```json\n").append(body).append("\n```\n\n");

                String curl = options.redactPlaceholders() ? redact(c.curlCommand()) : c.curlCommand();
                md.append("**cURL**:\n```bash\n").append(curl).append("\n```\n\n");

                md.append("**Recommended Step**:\n").append(c.recommendedStep()).append("\n\n");
                md.append("---\n\n");
            }
        }

        md.append("---\n*Generated by Method Miner — Passive API Security Intelligence*\n");

        return ExportArtifact.of(prefix + "-report.md", ExportFormat.MARKDOWN,
                md.toString(), "Comprehensive Markdown intelligence report");
    }

    // ---- JSON Export --------------------------------------------------------

    private ExportArtifact generateJsonSignals(RiskSignalResult signals, String prefix) {
        StringBuilder json = new StringBuilder();
        json.append("[\n");
        List<RiskSignal> list = signals.signals();
        for (int i = 0; i < list.size(); i++) {
            json.append(signalToJson(list.get(i)));
            if (i < list.size() - 1) json.append(",");
            json.append("\n");
        }
        json.append("]");
        return ExportArtifact.of(prefix + "-risk-signals.json", ExportFormat.JSON,
                json.toString(), "Risk signals in JSON array format");
    }

    // ---- JSONL Export -------------------------------------------------------

    private ExportArtifact generateJsonlSignals(RiskSignalResult signals, String prefix) {
        StringBuilder jsonl = new StringBuilder();
        for (RiskSignal s : signals.signals()) {
            jsonl.append(signalToJsonCompact(s)).append("\n");
        }
        return ExportArtifact.of(prefix + "-risk-signals.jsonl", ExportFormat.JSONL,
                jsonl.toString(), "Risk signals in JSONL format (one per line)");
    }

    private ExportArtifact generateJsonlPayloads(PayloadAssemblyResult payloads, String prefix) {
        StringBuilder jsonl = new StringBuilder();
        for (PayloadCandidate c : payloads.candidates()) {
            jsonl.append(payloadToJsonCompact(c)).append("\n");
        }
        return ExportArtifact.of(prefix + "-payloads.jsonl", ExportFormat.JSONL,
                jsonl.toString(), "Payload candidates in JSONL format (one per line)");
    }

    // ---- CSV Export ---------------------------------------------------------

    private ExportArtifact generateCsvSignals(RiskSignalResult signals, String prefix) {
        StringBuilder csv = new StringBuilder();
        csv.append("Score,Severity,Confidence,Category,Operation,Protocol,Host,Endpoint,Coverage,Summary\n");
        for (RiskSignal s : signals.signals()) {
            csv.append(s.score()).append(",");
            csv.append(s.severity()).append(",");
            csv.append(s.confidence()).append(",");
            csv.append(csvEscape(s.category().name())).append(",");
            csv.append(csvEscape(s.operationName())).append(",");
            csv.append(s.protocolKind()).append(",");
            csv.append(csvEscape(s.host())).append(",");
            csv.append(csvEscape(s.endpointPath())).append(",");
            csv.append(s.coverageStatus()).append(",");
            csv.append(csvEscape(s.summary()));
            csv.append("\n");
        }
        return ExportArtifact.of(prefix + "-risk-signals.csv", ExportFormat.CSV,
                csv.toString(), "Risk signals in CSV format");
    }

    private ExportArtifact generateCsvSessions(List<SessionProfile> sessions, String prefix) {
        StringBuilder csv = new StringBuilder();
        csv.append("Host,Username,Role,Mechanisms,CookieNames,RequestCount,Confidence\n");
        for (SessionProfile sp : sessions) {
            csv.append(csvEscape(sp.host())).append(",");
            csv.append(csvEscape(sp.username())).append(",");
            csv.append(sp.role()).append(",");
            csv.append(csvEscape(String.join(";", sp.authMechanisms()))).append(",");
            csv.append(csvEscape(String.join(";", sp.cookieNames()))).append(",");
            csv.append(sp.requestCount()).append(",");
            csv.append(sp.confidence());
            csv.append("\n");
        }
        return ExportArtifact.of(prefix + "-sessions.csv", ExportFormat.CSV,
                csv.toString(), "Session profiles in CSV format");
    }

    // ---- JSON Helpers -------------------------------------------------------

    private static String signalToJson(RiskSignal s) {
        return "  {\n" +
                "    \"score\": " + s.score() + ",\n" +
                "    \"severity\": \"" + s.severity() + "\",\n" +
                "    \"confidence\": \"" + s.confidence() + "\",\n" +
                "    \"category\": \"" + s.category() + "\",\n" +
                "    \"operation\": \"" + jsonEscape(s.operationName()) + "\",\n" +
                "    \"protocol\": \"" + s.protocolKind() + "\",\n" +
                "    \"host\": \"" + jsonEscape(s.host()) + "\",\n" +
                "    \"endpoint\": \"" + jsonEscape(s.endpointPath()) + "\",\n" +
                "    \"coverage\": \"" + s.coverageStatus() + "\",\n" +
                "    \"title\": \"" + jsonEscape(s.title()) + "\",\n" +
                "    \"summary\": \"" + jsonEscape(s.summary()) + "\",\n" +
                "    \"recommendedAction\": \"" + jsonEscape(s.recommendedAction()) + "\",\n" +
                "    \"parameters\": [" + s.parameters().stream()
                        .sorted().map(p -> "\"" + jsonEscape(p) + "\"")
                        .collect(Collectors.joining(", ")) + "]\n" +
                "  }";
    }

    private static String signalToJsonCompact(RiskSignal s) {
        return "{\"score\":" + s.score() +
                ",\"severity\":\"" + s.severity() + "\"" +
                ",\"category\":\"" + s.category() + "\"" +
                ",\"operation\":\"" + jsonEscape(s.operationName()) + "\"" +
                ",\"protocol\":\"" + s.protocolKind() + "\"" +
                ",\"host\":\"" + jsonEscape(s.host()) + "\"" +
                ",\"coverage\":\"" + s.coverageStatus() + "\"" +
                ",\"title\":\"" + jsonEscape(s.title()) + "\"}";
    }

    private static String payloadToJsonCompact(PayloadCandidate c) {
        return "{\"score\":" + c.score() +
                ",\"type\":\"" + c.candidateType() + "\"" +
                ",\"operation\":\"" + jsonEscape(c.operationName()) + "\"" +
                ",\"protocol\":\"" + c.protocolKind() + "\"" +
                ",\"role\":\"" + c.requiredRole() + "\"" +
                ",\"title\":\"" + jsonEscape(c.title()) + "\"" +
                ",\"body\":\"" + jsonEscape(c.rawBody()) + "\"" +
                ",\"curl\":\"" + jsonEscape(c.curlCommand()) + "\"}";
    }

    // ---- Utility Methods ----------------------------------------------------

    private static String buildExecutiveSummary(ApiSurface surface,
                                                 List<SessionProfile> sessions,
                                                 RoleComparisonResult comparison,
                                                 RiskSignalResult signals,
                                                 PayloadAssemblyResult payloads) {
        StringBuilder sb = new StringBuilder();
        sb.append("This report summarizes passive API security intelligence collected by Method Miner.\n\n");

        sb.append("| Category | Count |\n");
        sb.append("|----------|-------|\n");
        int operationCount = surface != null
                ? surface.services().stream().flatMap(s -> s.endpoints().stream())
                        .mapToInt(ep -> ep.operations().size()).sum()
                : 0;
        sb.append("| API Operations | ").append(operationCount).append(" |\n");
        sb.append("| Observations | ").append(surface != null ? surface.observations().size() : 0).append(" |\n");
        sb.append("| Sessions | ").append(sessions != null ? sessions.size() : 0).append(" |\n");
        sb.append("| Compared Operations | ").append(comparison != null ? comparison.totalOperations() : 0).append(" |\n");
        sb.append("| Risk Signals | ").append(signals != null ? signals.totalSignals() : 0).append(" |\n");
        sb.append("| Payload Candidates | ").append(payloads != null ? payloads.totalCandidates() : 0).append(" |\n");

        return sb.toString();
    }

    private static String buildSummary(List<ExportArtifact> artifacts, long totalBytes) {
        return String.format("Generated %d artifacts (%s total): %s",
                artifacts.size(),
                formatBytes(totalBytes),
                artifacts.stream().map(ExportArtifact::fileName)
                        .collect(Collectors.joining(", ")));
    }

    static String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        return String.format("%.1f MB", bytes / (1024.0 * 1024.0));
    }

    static String csvEscape(String value) {
        if (value == null) return "";
        if (value.contains(",") || value.contains("\"") || value.contains("\n")) {
            return "\"" + value.replace("\"", "\"\"") + "\"";
        }
        return value;
    }

    static String jsonEscape(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private static String redact(String text) {
        if (text == null) return "";
        return text.replaceAll("<[A-Z_]+>", "[REDACTED]");
    }
}
