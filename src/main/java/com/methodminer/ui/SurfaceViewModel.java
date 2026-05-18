package com.methodminer.ui;

import com.methodminer.core.model.ApiSurface;
import com.methodminer.core.model.Endpoint;
import com.methodminer.core.model.Observation;
import com.methodminer.core.model.Operation;
import com.methodminer.core.model.Parameter;
import com.methodminer.core.model.Service;

import javax.swing.tree.DefaultMutableTreeNode;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * View-model utilities for rendering an {@link ApiSurface} in the UI.
 */
public final class SurfaceViewModel {
    private static final String NO_SELECTION_SCHEMA = "Select an operation to view its schema.";
    private static final String NO_SELECTION_EVIDENCE = "Select an operation to view evidence.";

    private final TreeNodeFactory treeNodeFactory;
    private final int maxEvidenceItems;

    public SurfaceViewModel(TreeNodeFactory treeNodeFactory) {
        this(treeNodeFactory, 5);
    }

    public SurfaceViewModel(TreeNodeFactory treeNodeFactory, int maxEvidenceItems) {
        this.treeNodeFactory = Objects.requireNonNull(treeNodeFactory, "treeNodeFactory");
        this.maxEvidenceItems = Math.max(1, maxEvidenceItems);
    }

    public DefaultMutableTreeNode buildNavigationTree(ApiSurface surface) {
        return treeNodeFactory.build(surface);
    }

    public String renderSchema(ApiSurface surface, TreeNodeFactory.TreeNodeData operationNode) {
        OperationContext context = findOperationContext(surface, operationNode);
        if (context == null) {
            return NO_SELECTION_SCHEMA;
        }

        String namespace = namespaceOf(context.operation.name());
        long observationCount = context.observations.size();

        StringBuilder out = new StringBuilder(512);
        out.append("Operation: ").append(context.operation.name()).append('\n');
        out.append("Protocol: ").append(TreeNodeFactory.formatProtocolKind(context.operation.protocolKind())).append('\n');
        out.append("Namespace: ").append(namespace.isBlank() ? "(none)" : namespace).append('\n');
        out.append("Observations: ").append(observationCount).append('\n');
        out.append('\n');

        out.append("Parameters").append('\n');
        if (context.operation.parameters().isEmpty()) {
            out.append("(none)\n");
            return out.toString();
        }

        for (Parameter parameter : context.operation.parameters()) {
            out.append("- ")
                    .append(parameter.name())
                    .append(" : ")
                    .append(TreeNodeFactory.formatDataType(parameter.dataType()))
                    .append('\n');
        }

        return out.toString();
    }

    public String renderEvidence(ApiSurface surface, TreeNodeFactory.TreeNodeData operationNode) {
        OperationContext context = findOperationContext(surface, operationNode);
        if (context == null) {
            return NO_SELECTION_EVIDENCE;
        }

        String host = safe(context.service.host(), "(unknown host)");
        String endpointUrl = host + safe(context.endpoint.path(), "/");

        StringBuilder out = new StringBuilder(1024);
        out.append("Endpoint: ")
                .append(safe(context.endpoint.httpMethod(), ""))
                .append(" ")
                .append(endpointUrl)
                .append('\n');
        out.append("Operation: ").append(context.operation.name()).append('\n');
        out.append('\n');

        if (context.observations.isEmpty()) {
            out.append("No observations yet.\n");
            return out.toString();
        }

        List<Observation> samples = mostRecent(context.observations, maxEvidenceItems);
        out.append("Observations (most recent ").append(samples.size()).append(")\n");

        for (Observation observation : samples) {
            Map<String, String> attrs = observation.attributes();
            String status = attrs.getOrDefault("responseStatusCode", "");
            out.append("- ")
                    .append(formatInstant(observation.observedAt()))
                    .append(status.isBlank() ? "" : " status=" + status)
                    .append('\n');

            String request = observation.requestSummary().orElse("");
            if (!request.isBlank()) {
                out.append("  request: ").append(request).append('\n');
            }

            String response = observation.responseSummary().orElse("");
            if (!response.isBlank()) {
                out.append("  response: ").append(response).append('\n');
            }
        }

        return out.toString();
    }

    private static List<Observation> mostRecent(List<Observation> observations, int max) {
        List<Observation> copy = new ArrayList<>(observations);
        copy.sort(Comparator.comparing(Observation::observedAt).reversed());
        return copy.subList(0, Math.min(copy.size(), max));
    }

    private static String formatInstant(Instant instant) {
        return instant == null ? "" : instant.toString();
    }

    private static OperationContext findOperationContext(ApiSurface surface, TreeNodeFactory.TreeNodeData operationNode) {
        if (surface == null || operationNode == null || operationNode.kind() != TreeNodeFactory.NodeKind.OPERATION) {
            return null;
        }

        UUID serviceId = operationNode.serviceId();
        UUID endpointId = operationNode.endpointId();
        UUID operationId = operationNode.operationId();
        if (serviceId == null || endpointId == null || operationId == null) {
            return null;
        }

        Service service = null;
        Endpoint endpoint = null;
        Operation operation = null;

        for (Service candidateService : surface.services()) {
            if (!serviceId.equals(candidateService.id())) {
                continue;
            }
            service = candidateService;
            for (Endpoint candidateEndpoint : candidateService.endpoints()) {
                if (!endpointId.equals(candidateEndpoint.id())) {
                    continue;
                }
                endpoint = candidateEndpoint;
                for (Operation candidateOperation : candidateEndpoint.operations()) {
                    if (operationId.equals(candidateOperation.id())) {
                        operation = candidateOperation;
                        break;
                    }
                }
                break;
            }
            break;
        }

        if (service == null || endpoint == null || operation == null) {
            return null;
        }

        List<Observation> observations = new ArrayList<>();
        for (Observation observation : surface.observations()) {
            if (operationId.equals(observation.operationId())) {
                observations.add(observation);
            }
        }

        return new OperationContext(service, endpoint, operation, observations);
    }

    private static String namespaceOf(String operationName) {
        String name = safe(operationName, "");
        int dot = name.indexOf('.');
        int slash = name.indexOf('/');
        int separator = chooseSeparatorIndex(dot, slash);
        if (separator <= 0) {
            return "";
        }
        return name.substring(0, separator);
    }

    private static int chooseSeparatorIndex(int dot, int slash) {
        if (dot < 0) {
            return slash;
        }
        if (slash < 0) {
            return dot;
        }
        return Math.min(dot, slash);
    }

    private static String safe(String value, String fallback) {
        if (value == null) {
            return fallback;
        }
        String trimmed = value.trim();
        return trimmed.isBlank() ? fallback : trimmed;
    }

    private record OperationContext(Service service, Endpoint endpoint, Operation operation, List<Observation> observations) {
    }
}
