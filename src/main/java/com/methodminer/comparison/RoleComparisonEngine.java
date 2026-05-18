package com.methodminer.comparison;

import com.methodminer.core.model.*;
import com.methodminer.core.repository.SurfaceRepository;
import com.methodminer.protocol.ProtocolKind;
import com.methodminer.session.SessionRepository;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Passive analysis engine that compares API surface observations across session roles.
 *
 * <p>Reads all observations and session profiles, groups by operation, and computes
 * {@link CoverageStatus} for each. Produces deterministic, immutable
 * {@link RoleComparisonResult} objects.
 *
 * <p>This engine performs no vulnerability scoring — it only computes structured
 * comparison data that future recommendation engines can consume.
 */
public final class RoleComparisonEngine {

    private final SurfaceRepository surfaceRepository;
    private final SessionRepository sessionRepository;

    public RoleComparisonEngine(SurfaceRepository surfaceRepository, SessionRepository sessionRepository) {
        this.surfaceRepository = Objects.requireNonNull(surfaceRepository, "surfaceRepository");
        this.sessionRepository = Objects.requireNonNull(sessionRepository, "sessionRepository");
    }

    /**
     * Compute a role comparison across all observed operations and session profiles.
     *
     * @return an immutable comparison result
     */
    public RoleComparisonResult compare() {
        ApiSurface surface = surfaceRepository.snapshot();
        List<SessionProfile> sessions = sessionRepository.snapshot();

        if (surface.observations().isEmpty()) {
            return RoleComparisonResult.EMPTY;
        }

        // Build session role lookup: sessionProfileId → Role
        Map<UUID, Role> sessionRoles = new HashMap<>();
        for (SessionProfile sp : sessions) {
            sessionRoles.put(sp.id(), sp.role());
        }

        // Build operation metadata lookup: operationId → OperationMeta
        Map<UUID, OperationMeta> operationMetaMap = buildOperationMetaMap(surface);

        // Group observations by operationId, collecting per-role session sets
        Map<UUID, OperationAccumulator> accumulators = new LinkedHashMap<>();
        for (Observation obs : surface.observations()) {
            OperationAccumulator acc = accumulators.computeIfAbsent(
                    obs.operationId(), id -> new OperationAccumulator());

            Role role = resolveRole(obs, sessionRoles);
            acc.addObservation(role, obs);
        }

        // Build coverage entries
        List<OperationRoleCoverage> coverages = new ArrayList<>();
        for (var entry : accumulators.entrySet()) {
            UUID opId = entry.getKey();
            OperationAccumulator acc = entry.getValue();
            OperationMeta meta = operationMetaMap.getOrDefault(opId, OperationMeta.UNKNOWN);

            CoverageStatus status = classifyStatus(
                    acc.adminSessions.size(), acc.lowPrivSessions.size(), acc.unlabeledSessions.size());

            List<ParameterRoleCoverage> paramCoverages = buildParameterCoverages(acc, meta);

            coverages.add(new OperationRoleCoverage(
                    opId,
                    meta.protocolKind,
                    meta.host,
                    meta.endpointPath,
                    meta.operationName,
                    status,
                    acc.adminSessions.size(),
                    acc.lowPrivSessions.size(),
                    acc.unlabeledSessions.size(),
                    Set.copyOf(acc.allParameterNames),
                    paramCoverages
            ));
        }

        // Sort: ADMIN_ONLY first, then BOTH, then LOW_PRIV_ONLY, then rest
        coverages.sort(Comparator
                .<OperationRoleCoverage, Integer>comparing(c -> statusSortOrder(c.status()))
                .thenComparing(OperationRoleCoverage::operationName));

        // Summary counts
        Map<CoverageStatus, Integer> counts = new EnumMap<>(CoverageStatus.class);
        for (OperationRoleCoverage c : coverages) {
            counts.merge(c.status(), 1, Integer::sum);
        }

        return new RoleComparisonResult(
                Instant.now(),
                sessions.size(),
                coverages.size(),
                List.copyOf(coverages),
                Map.copyOf(counts)
        );
    }

    // ---- Status classification -------------------------------------------

    static CoverageStatus classifyStatus(int adminCount, int lowPrivCount, int unlabeledCount) {
        boolean hasAdmin = adminCount > 0;
        boolean hasLowPriv = lowPrivCount > 0;
        boolean hasUnlabeled = unlabeledCount > 0;

        if (hasAdmin && hasLowPriv) return CoverageStatus.BOTH;
        if (hasAdmin) return CoverageStatus.ADMIN_ONLY;
        if (hasLowPriv) return CoverageStatus.LOW_PRIV_ONLY;
        if (hasUnlabeled) return CoverageStatus.UNLABELED;
        return CoverageStatus.UNKNOWN;
    }

    // ---- Operation metadata lookup ----------------------------------------

    private static Map<UUID, OperationMeta> buildOperationMetaMap(ApiSurface surface) {
        Map<UUID, OperationMeta> map = new HashMap<>();
        for (Service service : surface.services()) {
            for (Endpoint endpoint : service.endpoints()) {
                for (Operation operation : endpoint.operations()) {
                    map.put(operation.id(), new OperationMeta(
                            operation.protocolKind(),
                            service.host(),
                            endpoint.path(),
                            operation.name(),
                            operation.parameters().stream()
                                    .map(Parameter::name)
                                    .collect(Collectors.toSet())
                    ));
                }
            }
        }
        return map;
    }

    // ---- Role resolution --------------------------------------------------

    private static Role resolveRole(Observation obs, Map<UUID, Role> sessionRoles) {
        if (obs.sessionProfileId().isEmpty()) return Role.UNKNOWN;
        UUID sessionId = obs.sessionProfileId().get();
        return sessionRoles.getOrDefault(sessionId, Role.UNKNOWN);
    }

    // ---- Parameter coverage -----------------------------------------------

    private static List<ParameterRoleCoverage> buildParameterCoverages(
            OperationAccumulator acc, OperationMeta meta) {
        if (acc.allParameterNames.isEmpty()) return List.of();

        List<ParameterRoleCoverage> result = new ArrayList<>();
        for (String paramName : acc.allParameterNames) {
            boolean inAdmin = acc.adminParameterNames.contains(paramName);
            boolean inLowPriv = acc.lowPrivParameterNames.contains(paramName);
            boolean inUnlabeled = acc.unlabeledParameterNames.contains(paramName);

            CoverageStatus paramStatus = classifyStatus(
                    inAdmin ? 1 : 0, inLowPriv ? 1 : 0, inUnlabeled ? 1 : 0);

            Map<String, Set<String>> typesByRole = new LinkedHashMap<>();
            if (inAdmin) typesByRole.put("ADMIN", acc.adminParameterTypes.getOrDefault(paramName, Set.of()));
            if (inLowPriv) typesByRole.put("LOW_PRIV", acc.lowPrivParameterTypes.getOrDefault(paramName, Set.of()));
            if (inUnlabeled) typesByRole.put("UNLABELED", acc.unlabeledParameterTypes.getOrDefault(paramName, Set.of()));

            result.add(new ParameterRoleCoverage(paramName, paramStatus, typesByRole));
        }

        result.sort(Comparator.comparing(ParameterRoleCoverage::name));
        return List.copyOf(result);
    }

    // ---- Sort order -------------------------------------------------------

    private static int statusSortOrder(CoverageStatus status) {
        return switch (status) {
            case ADMIN_ONLY -> 0;
            case BOTH -> 1;
            case LOW_PRIV_ONLY -> 2;
            case UNLABELED -> 3;
            case UNKNOWN -> 4;
        };
    }

    // ---- Internal accumulator ---------------------------------------------

    private static final class OperationAccumulator {
        final Set<UUID> adminSessions = new LinkedHashSet<>();
        final Set<UUID> lowPrivSessions = new LinkedHashSet<>();
        final Set<UUID> unlabeledSessions = new LinkedHashSet<>();
        final Set<String> allParameterNames = new LinkedHashSet<>();
        final Set<String> adminParameterNames = new LinkedHashSet<>();
        final Set<String> lowPrivParameterNames = new LinkedHashSet<>();
        final Set<String> unlabeledParameterNames = new LinkedHashSet<>();
        final Map<String, Set<String>> adminParameterTypes = new LinkedHashMap<>();
        final Map<String, Set<String>> lowPrivParameterTypes = new LinkedHashMap<>();
        final Map<String, Set<String>> unlabeledParameterTypes = new LinkedHashMap<>();

        void addObservation(Role role, Observation obs) {
            UUID sessionId = obs.sessionProfileId().orElse(null);

            switch (role) {
                case ADMIN -> {
                    if (sessionId != null) adminSessions.add(sessionId);
                    collectParams(obs, adminParameterNames, adminParameterTypes);
                }
                case LOW_PRIV -> {
                    if (sessionId != null) lowPrivSessions.add(sessionId);
                    collectParams(obs, lowPrivParameterNames, lowPrivParameterTypes);
                }
                default -> {
                    if (sessionId != null) unlabeledSessions.add(sessionId);
                    collectParams(obs, unlabeledParameterNames, unlabeledParameterTypes);
                }
            }
        }

        private void collectParams(Observation obs, Set<String> names, Map<String, Set<String>> types) {
            // Extract parameter info from observation attributes
            for (var entry : obs.attributes().entrySet()) {
                String key = entry.getKey();
                if (key.startsWith("param.")) {
                    String paramName = key.substring("param.".length());
                    names.add(paramName);
                    allParameterNames.add(paramName);
                    types.computeIfAbsent(paramName, k -> new LinkedHashSet<>()).add(entry.getValue());
                }
            }
            // Also check for parameter names stored as a comma-separated attribute
            String paramList = obs.attributes().get("parameterNames");
            if (paramList != null && !paramList.isBlank()) {
                for (String p : paramList.split(",")) {
                    String trimmed = p.trim();
                    if (!trimmed.isBlank()) {
                        names.add(trimmed);
                        allParameterNames.add(trimmed);
                    }
                }
            }
        }
    }

    private record OperationMeta(
            ProtocolKind protocolKind, String host, String endpointPath,
            String operationName, Set<String> parameterNames
    ) {
        static final OperationMeta UNKNOWN = new OperationMeta(
                ProtocolKind.UNKNOWN, "", "", "(unknown)", Set.of());
    }
}
