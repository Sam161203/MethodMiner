package com.methodminer.payload;

import com.methodminer.comparison.CoverageStatus;
import com.methodminer.core.model.ApiSurface;
import com.methodminer.core.model.Observation;
import com.methodminer.core.model.Role;
import com.methodminer.core.model.SessionProfile;
import com.methodminer.core.repository.SurfaceRepository;
import com.methodminer.protocol.ProtocolKind;
import com.methodminer.risk.RiskSignal;
import com.methodminer.risk.RiskSignalResult;
import com.methodminer.session.SessionRepository;

import java.time.Instant;
import java.util.*;

/**
 * Deterministic, passive payload assembly engine.
 *
 * <p>Converts each {@link RiskSignal} into one or more {@link PayloadCandidate} objects
 * containing ready-to-use request bodies, full HTTP requests, and cURL commands.
 *
 * <p>Uses real observation data and session profiles to construct realistic payloads.
 * When LOW_PRIV session data is unavailable, generates clearly-marked placeholders.
 *
 * <p>This engine sends no traffic and makes no external requests.
 */
public final class PayloadAssembler {

    private static final String PLACEHOLDER_SESSION = "<LOW_PRIV_SESSION_ID>";
    private static final String PLACEHOLDER_AUTH = "<LOW_PRIV_AUTH_TOKEN>";
    private static final String PLACEHOLDER_COOKIE = "<LOW_PRIV_COOKIE>";
    private static final String PLACEHOLDER_ENTITY = "<TARGET_ENTITY_ID>";

    private final SurfaceRepository surfaceRepository;
    private final SessionRepository sessionRepository;

    public PayloadAssembler(SurfaceRepository surfaceRepository, SessionRepository sessionRepository) {
        this.surfaceRepository = Objects.requireNonNull(surfaceRepository, "surfaceRepository");
        this.sessionRepository = Objects.requireNonNull(sessionRepository, "sessionRepository");
    }

    /**
     * Assemble payload candidates from risk signals.
     *
     * @param signalResult the risk signal result to process
     * @return an immutable result containing all assembled candidates, sorted by descending score
     */
    public PayloadAssemblyResult assemble(RiskSignalResult signalResult) {
        if (signalResult == null || signalResult.signals().isEmpty()) {
            return PayloadAssemblyResult.EMPTY;
        }

        Instant now = Instant.now();
        ApiSurface surface = surfaceRepository.snapshot();
        SessionContext ctx = resolveSessionContext();

        List<PayloadCandidate> candidates = new ArrayList<>();

        for (RiskSignal signal : signalResult.signals()) {
            Observation bestObs = findBestObservation(signal, surface);
            candidates.addAll(assembleCandidates(signal, bestObs, ctx, now));
        }

        // Sort by descending score, then operation name
        candidates.sort(Comparator
                .<PayloadCandidate>comparingInt(c -> -c.score())
                .thenComparing(PayloadCandidate::operationName));

        // Summary counts
        Map<PayloadCandidateType, Integer> counts = new EnumMap<>(PayloadCandidateType.class);
        for (PayloadCandidate c : candidates) {
            counts.merge(c.candidateType(), 1, Integer::sum);
        }

        return new PayloadAssemblyResult(now, candidates.size(), List.copyOf(candidates),
                Map.copyOf(counts));
    }

    // ---- Candidate Assembly -------------------------------------------------

    private List<PayloadCandidate> assembleCandidates(RiskSignal signal, Observation obs,
                                                       SessionContext ctx, Instant now) {
        List<PayloadCandidate> candidates = new ArrayList<>();

        PayloadCandidateType type = mapSignalToType(signal);
        String body = buildBody(signal, obs);
        List<PayloadVariable> variables = buildVariables(signal, ctx);
        String httpRequest = buildHttpRequest(signal, body, ctx);
        String curl = buildCurlCommand(signal, body, ctx);

        candidates.add(new PayloadCandidate(
                UUID.randomUUID(), now, signal.id(), type,
                signal.protocolKind(), signal.host(), signal.endpointPath(),
                "POST", signal.operationName(),
                buildTitle(signal, type),
                buildSummary(signal, type),
                body, httpRequest, curl, variables,
                "LOW_PRIV",
                buildRecommendedStep(signal, type),
                signal.confidence(),
                signal.score()
        ));

        // For ADMIN_ONLY ops, also generate an ADMIN_TEMPLATE for reference
        if (signal.coverageStatus() == CoverageStatus.ADMIN_ONLY) {
            String adminBody = buildAdminTemplateBody(signal, obs);
            String adminHttp = buildAdminHttpRequest(signal, adminBody);
            String adminCurl = buildAdminCurlCommand(signal, adminBody);

            candidates.add(new PayloadCandidate(
                    UUID.randomUUID(), now, signal.id(),
                    PayloadCandidateType.ADMIN_TEMPLATE,
                    signal.protocolKind(), signal.host(), signal.endpointPath(),
                    "POST", signal.operationName(),
                    "Admin template: " + signal.operationName(),
                    "Original ADMIN request template for reference. Compare with the LOW_PRIV replay.",
                    adminBody, adminHttp, adminCurl, List.of(),
                    "ADMIN",
                    "Use this as reference to compare against the LOW_PRIV replay response.",
                    signal.confidence(),
                    Math.max(0, signal.score() - 10) // Slightly lower than the replay
            ));
        }

        return candidates;
    }

    // ---- Type Mapping -------------------------------------------------------

    static PayloadCandidateType mapSignalToType(RiskSignal signal) {
        return switch (signal.category()) {
            case ADMIN_ONLY_DELETE, ADMIN_ONLY_MUTATION, PRIVILEGED_OPERATION ->
                    PayloadCandidateType.ROLE_REPLAY;
            case PARAMETER_EXPOSURE_DIFFERENCE ->
                    PayloadCandidateType.PARAMETER_INJECTION;
            case GRAPHQL_MUTATION_PRIVILEGE ->
                    PayloadCandidateType.GRAPHQL_MUTATION_REPLAY;
            case BATCH_CHAIN_CANDIDATE ->
                    PayloadCandidateType.BATCH_CHAIN_REPLAY;
            case ENUMERATION_CANDIDATE ->
                    PayloadCandidateType.ENUMERATION_REPLAY;
            case SHARED_SENSITIVE_OPERATION ->
                    PayloadCandidateType.ROLE_REPLAY;
        };
    }

    // ---- Body Construction --------------------------------------------------

    private static String buildBody(RiskSignal signal, Observation obs) {
        // Use observation request summary if available
        if (obs != null && obs.requestSummary().isPresent()) {
            return obs.requestSummary().get();
        }

        // Construct from signal data
        return switch (signal.protocolKind()) {
            case JSON_RPC -> buildJsonRpcBody(signal);
            case GRAPHQL -> buildGraphQlBody(signal);
            default -> buildGenericBody(signal);
        };
    }

    static String buildJsonRpcBody(RiskSignal signal) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"jsonrpc\": \"2.0\",\n");
        sb.append("  \"method\": \"").append(escapeJson(signal.operationName())).append("\",\n");

        // Build params with observed parameters
        sb.append("  \"params\": {\n");
        if (!signal.parameters().isEmpty()) {
            List<String> sortedParams = signal.parameters().stream().sorted().toList();
            for (int i = 0; i < sortedParams.size(); i++) {
                String param = sortedParams.get(i);
                sb.append("    \"").append(escapeJson(param)).append("\": ")
                        .append("\"").append(PLACEHOLDER_ENTITY).append("\"");
                if (i < sortedParams.size() - 1) sb.append(",");
                sb.append("\n");
            }
        }
        sb.append("  },\n");

        sb.append("  \"id\": 1\n");
        sb.append("}");
        return sb.toString();
    }

    static String buildGraphQlBody(RiskSignal signal) {
        StringBuilder sb = new StringBuilder();
        String opName = signal.operationName();
        boolean isMutation = opName.toLowerCase().startsWith("mutation ");
        String cleanName = isMutation ? opName.substring("mutation ".length()).trim() : opName;

        sb.append("{\n");
        sb.append("  \"query\": \"");
        if (isMutation) {
            sb.append("mutation ").append(escapeJson(cleanName));
        } else {
            sb.append("query ").append(escapeJson(cleanName));
        }

        // Add variable definitions if parameters exist
        if (!signal.parameters().isEmpty()) {
            sb.append("(");
            List<String> sortedParams = signal.parameters().stream().sorted().toList();
            for (int i = 0; i < sortedParams.size(); i++) {
                sb.append("$").append(sortedParams.get(i)).append(": String");
                if (i < sortedParams.size() - 1) sb.append(", ");
            }
            sb.append(")");
        }

        sb.append(" { ... }\",\n");

        // Variables
        sb.append("  \"variables\": {\n");
        if (!signal.parameters().isEmpty()) {
            List<String> sortedParams = signal.parameters().stream().sorted().toList();
            for (int i = 0; i < sortedParams.size(); i++) {
                sb.append("    \"").append(escapeJson(sortedParams.get(i))).append("\": ")
                        .append("\"").append(PLACEHOLDER_ENTITY).append("\"");
                if (i < sortedParams.size() - 1) sb.append(",");
                sb.append("\n");
            }
        }
        sb.append("  }\n");
        sb.append("}");
        return sb.toString();
    }

    private static String buildGenericBody(RiskSignal signal) {
        return "{ \"operation\": \"" + escapeJson(signal.operationName()) + "\" }";
    }

    private static String buildAdminTemplateBody(RiskSignal signal, Observation obs) {
        if (obs != null && obs.requestSummary().isPresent()) {
            return obs.requestSummary().get();
        }
        return buildBody(signal, obs);
    }

    // ---- HTTP Request Construction ------------------------------------------

    private static String buildHttpRequest(RiskSignal signal, String body, SessionContext ctx) {
        StringBuilder sb = new StringBuilder();
        String path = signal.endpointPath().isEmpty() ? "/" : signal.endpointPath();
        String host = signal.host().isEmpty() ? "target-host" : signal.host();

        sb.append("POST ").append(path).append(" HTTP/1.1\r\n");
        sb.append("Host: ").append(host).append("\r\n");

        // Content type
        sb.append("Content-Type: application/json\r\n");

        // Auth header — use LOW_PRIV session data if available
        if (ctx.lowPrivAuthHeader != null) {
            sb.append("Authorization: ").append(ctx.lowPrivAuthHeader).append("\r\n");
        } else {
            sb.append("Authorization: Bearer ").append(PLACEHOLDER_AUTH).append("\r\n");
        }

        // Cookie header
        if (ctx.lowPrivCookie != null) {
            sb.append("Cookie: ").append(ctx.lowPrivCookie).append("\r\n");
        }

        sb.append("Content-Length: ").append(body.length()).append("\r\n");
        sb.append("\r\n");
        sb.append(body);

        return sb.toString();
    }

    private static String buildAdminHttpRequest(RiskSignal signal, String body) {
        StringBuilder sb = new StringBuilder();
        String path = signal.endpointPath().isEmpty() ? "/" : signal.endpointPath();
        String host = signal.host().isEmpty() ? "target-host" : signal.host();

        sb.append("POST ").append(path).append(" HTTP/1.1\r\n");
        sb.append("Host: ").append(host).append("\r\n");
        sb.append("Content-Type: application/json\r\n");
        sb.append("Authorization: Bearer <ADMIN_AUTH_TOKEN>\r\n");
        sb.append("Content-Length: ").append(body.length()).append("\r\n");
        sb.append("\r\n");
        sb.append(body);

        return sb.toString();
    }

    // ---- cURL Command Construction ------------------------------------------

    private static String buildCurlCommand(RiskSignal signal, String body, SessionContext ctx) {
        StringBuilder sb = new StringBuilder();
        String host = signal.host().isEmpty() ? "target-host" : signal.host();
        String path = signal.endpointPath().isEmpty() ? "/" : signal.endpointPath();
        String scheme = "https";

        sb.append("curl -X POST \\\n");
        sb.append("  '").append(scheme).append("://").append(host).append(path).append("' \\\n");
        sb.append("  -H 'Content-Type: application/json' \\\n");

        if (ctx.lowPrivAuthHeader != null) {
            sb.append("  -H 'Authorization: ").append(ctx.lowPrivAuthHeader).append("' \\\n");
        } else {
            sb.append("  -H 'Authorization: Bearer ").append(PLACEHOLDER_AUTH).append("' \\\n");
        }

        if (ctx.lowPrivCookie != null) {
            sb.append("  -H 'Cookie: ").append(ctx.lowPrivCookie).append("' \\\n");
        }

        // Escape single quotes in body for shell
        String escapedBody = body.replace("'", "'\\''");
        sb.append("  -d '").append(escapedBody).append("'");

        return sb.toString();
    }

    private static String buildAdminCurlCommand(RiskSignal signal, String body) {
        StringBuilder sb = new StringBuilder();
        String host = signal.host().isEmpty() ? "target-host" : signal.host();
        String path = signal.endpointPath().isEmpty() ? "/" : signal.endpointPath();

        sb.append("curl -X POST \\\n");
        sb.append("  'https://").append(host).append(path).append("' \\\n");
        sb.append("  -H 'Content-Type: application/json' \\\n");
        sb.append("  -H 'Authorization: Bearer <ADMIN_AUTH_TOKEN>' \\\n");
        String escapedBody = body.replace("'", "'\\''");
        sb.append("  -d '").append(escapedBody).append("'");

        return sb.toString();
    }

    // ---- Variable Construction -----------------------------------------------

    private static List<PayloadVariable> buildVariables(RiskSignal signal, SessionContext ctx) {
        List<PayloadVariable> vars = new ArrayList<>();

        // Session/auth variable
        if (ctx.lowPrivAuthHeader != null) {
            vars.add(new PayloadVariable(
                    "authToken", ctx.lowPrivAuthHeader,
                    "LOW_PRIV session authentication token",
                    "LOW_PRIV", ctx.lowPrivAuthHeader));
        } else {
            vars.add(new PayloadVariable(
                    "authToken", PLACEHOLDER_AUTH,
                    "Replace with a valid LOW_PRIV session token",
                    "LOW_PRIV", ""));
        }

        // Parameter variables
        for (String param : signal.parameters().stream().sorted().toList()) {
            vars.add(new PayloadVariable(
                    param, PLACEHOLDER_ENTITY,
                    "Entity ID or value for '" + param + "'. Use a real value from observed traffic.",
                    "ADMIN", ""));
        }

        return List.copyOf(vars);
    }

    // ---- Title/Summary/Step Builders ----------------------------------------

    private static String buildTitle(RiskSignal signal, PayloadCandidateType type) {
        return switch (type) {
            case ROLE_REPLAY -> "Replay " + signal.operationName() + " with LOW_PRIV";
            case PARAMETER_INJECTION -> "Inject admin params into " + signal.operationName();
            case GRAPHQL_MUTATION_REPLAY -> "Replay GraphQL mutation " + signal.operationName();
            case BATCH_CHAIN_REPLAY -> "Chain via " + signal.operationName();
            case ENUMERATION_REPLAY -> "Enumerate " + signal.operationName();
            case ADMIN_TEMPLATE -> "Admin template: " + signal.operationName();
        };
    }

    private static String buildSummary(RiskSignal signal, PayloadCandidateType type) {
        return switch (type) {
            case ROLE_REPLAY -> String.format(
                    "Replay the %s operation '%s' using LOW_PRIV credentials. " +
                    "This operation was observed only in ADMIN sessions. " +
                    "If the server processes it, this is a privilege escalation vulnerability.",
                    signal.protocolKind(), signal.operationName());
            case PARAMETER_INJECTION -> String.format(
                    "Inject admin-only parameters into the '%s' operation using LOW_PRIV credentials. " +
                    "Parameters: %s. If processed, this is a mass-assignment or BOLA vector.",
                    signal.operationName(), String.join(", ", signal.parameters()));
            case GRAPHQL_MUTATION_REPLAY -> String.format(
                    "Replay the GraphQL mutation '%s' with LOW_PRIV session credentials. " +
                    "GraphQL resolvers may not enforce authorization independently.",
                    signal.operationName());
            case BATCH_CHAIN_REPLAY -> String.format(
                    "Chain the '%s' batch operation with a privileged sub-call using LOW_PRIV credentials. " +
                    "Test if batch processing bypasses per-operation authorization.",
                    signal.operationName());
            case ENUMERATION_REPLAY -> String.format(
                    "Enumerate entity IDs through '%s' using LOW_PRIV credentials. " +
                    "Iterate over ID ranges to check for IDOR/horizontal privilege escalation.",
                    signal.operationName());
            case ADMIN_TEMPLATE ->
                    "Admin request template for reference comparison.";
        };
    }

    private static String buildRecommendedStep(RiskSignal signal, PayloadCandidateType type) {
        return switch (type) {
            case ROLE_REPLAY -> "1. Copy the request to Burp Repeater.\n" +
                    "2. Replace auth credentials with LOW_PRIV session.\n" +
                    "3. Send and compare response to the ADMIN version.\n" +
                    "4. If successful, report as privilege escalation.";
            case PARAMETER_INJECTION -> "1. Copy the request to Burp Repeater.\n" +
                    "2. Add the admin-only parameters to a LOW_PRIV request.\n" +
                    "3. If the server processes them, report as mass-assignment.";
            case GRAPHQL_MUTATION_REPLAY -> "1. Copy the GraphQL mutation to Repeater.\n" +
                    "2. Use LOW_PRIV Authorization header.\n" +
                    "3. If mutation succeeds, report as broken authorization.";
            case BATCH_CHAIN_REPLAY -> "1. Copy the batch request to Repeater.\n" +
                    "2. Insert a privileged operation as a sub-call.\n" +
                    "3. Use LOW_PRIV credentials.\n" +
                    "4. If the sub-call succeeds, report as batch bypass.";
            case ENUMERATION_REPLAY -> "1. Copy the request to Burp Intruder.\n" +
                    "2. Mark entity ID fields as injection points.\n" +
                    "3. Iterate over sequential or known IDs.\n" +
                    "4. Analyze responses for data leakage.";
            case ADMIN_TEMPLATE -> "Use as reference to compare with LOW_PRIV replay results.";
        };
    }

    // ---- Observation Lookup -------------------------------------------------

    private static Observation findBestObservation(RiskSignal signal, ApiSurface surface) {
        // Find the most recent observation matching this signal's operation
        Observation best = null;
        for (Observation obs : surface.observations()) {
            if (obs.protocolKind() == signal.protocolKind()) {
                // Check if operation name matches via attributes
                String obsMethod = obs.attributes().getOrDefault("method",
                        obs.attributes().getOrDefault("operationName", ""));
                if (obsMethod.equals(signal.operationName())) {
                    if (best == null || obs.observedAt().isAfter(best.observedAt())) {
                        best = obs;
                    }
                }
            }
        }
        return best;
    }

    // ---- Session Context Resolution -----------------------------------------

    private SessionContext resolveSessionContext() {
        List<SessionProfile> sessions = sessionRepository.snapshot();

        String lowPrivAuth = null;
        String lowPrivCookie = null;

        // Find the first LOW_PRIV session with auth data
        for (SessionProfile sp : sessions) {
            if (sp.role() == Role.LOW_PRIV) {
                // Use auth mechanism info to construct header pattern
                if (!sp.authMechanisms().isEmpty()) {
                    String mechanism = sp.authMechanisms().iterator().next();
                    // We only have fingerprints, not raw tokens — use descriptive placeholder
                    lowPrivAuth = mechanism + " " + PLACEHOLDER_SESSION;
                }
                if (!sp.cookieNames().isEmpty()) {
                    StringBuilder cookieSb = new StringBuilder();
                    for (String name : sp.cookieNames()) {
                        if (!cookieSb.isEmpty()) cookieSb.append("; ");
                        cookieSb.append(name).append("=").append(PLACEHOLDER_COOKIE);
                    }
                    lowPrivCookie = cookieSb.toString();
                }
                if (lowPrivAuth != null || lowPrivCookie != null) break;
            }
        }

        return new SessionContext(lowPrivAuth, lowPrivCookie);
    }

    // ---- Utilities ----------------------------------------------------------

    private static String escapeJson(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private record SessionContext(String lowPrivAuthHeader, String lowPrivCookie) {}
}
