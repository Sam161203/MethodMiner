package com.methodminer.ui;

import com.methodminer.core.model.ApiSurface;
import com.methodminer.core.model.DataType;
import com.methodminer.core.model.DataTypeKind;
import com.methodminer.core.model.Endpoint;
import com.methodminer.core.model.Operation;
import com.methodminer.core.model.Parameter;
import com.methodminer.core.model.Service;
import com.methodminer.protocol.ProtocolKind;

import javax.swing.tree.DefaultMutableTreeNode;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Converts {@link ApiSurface} into Swing tree nodes.
 */
public final class TreeNodeFactory {

    public enum NodeKind {
        ROOT,
        PROTOCOL,
        SERVICE,
        ENDPOINT,
        OPERATION,
        PARAMETER
    }

    /**
     * Small user object used for each tree node. {@link #toString()} returns the label.
     */
    public static final class TreeNodeData {
        private final NodeKind kind;
        private final String label;
        private final ProtocolKind protocolKind;
        private final UUID serviceId;
        private final UUID endpointId;
        private final UUID operationId;
        private final UUID parameterId;

        private TreeNodeData(
                NodeKind kind,
                String label,
                ProtocolKind protocolKind,
                UUID serviceId,
                UUID endpointId,
                UUID operationId,
                UUID parameterId
        ) {
            this.kind = Objects.requireNonNull(kind, "kind");
            this.label = Objects.requireNonNull(label, "label");
            this.protocolKind = protocolKind;
            this.serviceId = serviceId;
            this.endpointId = endpointId;
            this.operationId = operationId;
            this.parameterId = parameterId;
        }

        public NodeKind kind() {
            return kind;
        }

        public String label() {
            return label;
        }

        public ProtocolKind protocolKind() {
            return protocolKind;
        }

        public UUID serviceId() {
            return serviceId;
        }

        public UUID endpointId() {
            return endpointId;
        }

        public UUID operationId() {
            return operationId;
        }

        public UUID parameterId() {
            return parameterId;
        }

        @Override
        public String toString() {
            return label;
        }
    }

    public DefaultMutableTreeNode build(ApiSurface surface) {
        DefaultMutableTreeNode root = new DefaultMutableTreeNode(new TreeNodeData(
                NodeKind.ROOT,
                "Services",
                null,
                null,
                null,
                null,
                null
        ));

        if (surface == null || surface.services().isEmpty()) {
            root.add(new DefaultMutableTreeNode("(no data yet)"));
            return root;
        }

        Set<ProtocolKind> presentProtocols = presentProtocols(surface);
        if (presentProtocols.isEmpty()) {
            root.add(new DefaultMutableTreeNode("(no protocol endpoints yet)"));
            return root;
        }

        for (ProtocolKind protocolKind : orderedProtocols(presentProtocols)) {
            DefaultMutableTreeNode protocolNode = new DefaultMutableTreeNode(new TreeNodeData(
                    NodeKind.PROTOCOL,
                    formatProtocolKind(protocolKind),
                    protocolKind,
                    null,
                    null,
                    null,
                    null
            ));

            List<Service> services = new ArrayList<>(surface.services());
            services.sort(Comparator.comparing(TreeNodeFactory::serviceLabel, String.CASE_INSENSITIVE_ORDER));

            for (Service service : services) {
                List<Endpoint> endpoints = endpointsForProtocol(service, protocolKind);
                if (endpoints.isEmpty()) {
                    continue;
                }

                DefaultMutableTreeNode serviceNode = new DefaultMutableTreeNode(new TreeNodeData(
                        NodeKind.SERVICE,
                        serviceLabel(service),
                        protocolKind,
                        service.id(),
                        null,
                        null,
                        null
                ));

                for (Endpoint endpoint : endpoints) {
                    DefaultMutableTreeNode endpointNode = new DefaultMutableTreeNode(new TreeNodeData(
                            NodeKind.ENDPOINT,
                            endpointLabel(endpoint),
                            protocolKind,
                            service.id(),
                            endpoint.id(),
                            null,
                            null
                    ));

                    List<Operation> operations = new ArrayList<>(endpoint.operations());
                    operations.sort(Comparator.comparing(Operation::name, String.CASE_INSENSITIVE_ORDER));
                    for (Operation operation : operations) {
                        DefaultMutableTreeNode operationNode = new DefaultMutableTreeNode(new TreeNodeData(
                                NodeKind.OPERATION,
                                safeLabel(operation.name(), "(unnamed operation)"),
                                protocolKind,
                                service.id(),
                                endpoint.id(),
                                operation.id(),
                                null
                        ));

                        for (Parameter parameter : operation.parameters()) {
                            String paramLabel = safeLabel(parameter.name(), "(unnamed)") + " : " + formatDataType(parameter.dataType());
                            operationNode.add(new DefaultMutableTreeNode(new TreeNodeData(
                                    NodeKind.PARAMETER,
                                    paramLabel,
                                    protocolKind,
                                    service.id(),
                                    endpoint.id(),
                                    operation.id(),
                                    parameter.id()
                            )));
                        }

                        endpointNode.add(operationNode);
                    }

                    serviceNode.add(endpointNode);
                }

                protocolNode.add(serviceNode);
            }

            if (protocolNode.getChildCount() > 0) {
                root.add(protocolNode);
            }
        }

        if (root.getChildCount() == 0) {
            root.add(new DefaultMutableTreeNode("(no data yet)"));
        }

        return root;
    }

    public static String formatProtocolKind(ProtocolKind kind) {
        if (kind == null) {
            return "Unknown";
        }
        return switch (kind) {
            case JSON_RPC -> "JSON-RPC";
            case GRAPHQL -> "GraphQL";
            case UNKNOWN -> "Unknown";
        };
    }

    public static String formatDataType(DataType type) {
        if (type == null) {
            return "unknown";
        }

        DataTypeKind kind = type.kind();
        if (kind == null) {
            return "unknown";
        }

        return switch (kind) {
            case UNKNOWN -> "unknown";
            case SCALAR -> scalarLabel(type);
            case OBJECT -> "object";
            case ARRAY -> formatArray(type.elementType());
            case ENUM -> "enum";
            case UNION -> "union";
            case INPUT_OBJECT -> "input";
        };
    }

    private static String scalarLabel(DataType type) {
        String name = type.name() == null ? "" : type.name().trim().toLowerCase();
        return switch (name) {
            case "string", "boolean", "integer", "number", "null" -> name;
            default -> "scalar";
        };
    }

    private static String formatArray(Optional<DataType> elementType) {
        if (elementType == null || elementType.isEmpty()) {
            return "array";
        }
        return "array<" + formatDataType(elementType.get()) + ">";
    }

    private static Set<ProtocolKind> presentProtocols(ApiSurface surface) {
        EnumSet<ProtocolKind> protocols = EnumSet.noneOf(ProtocolKind.class);
        for (Service service : surface.services()) {
            for (Endpoint endpoint : service.endpoints()) {
                if (endpoint.protocolKind() != ProtocolKind.UNKNOWN) {
                    protocols.add(endpoint.protocolKind());
                }
            }
        }
        return protocols;
    }

    private static List<ProtocolKind> orderedProtocols(Set<ProtocolKind> present) {
        List<ProtocolKind> ordered = new ArrayList<>();
        for (ProtocolKind kind : ProtocolKind.values()) {
            if (present.contains(kind) && kind != ProtocolKind.UNKNOWN) {
                ordered.add(kind);
            }
        }
        return List.copyOf(ordered);
    }

    private static List<Endpoint> endpointsForProtocol(Service service, ProtocolKind protocolKind) {
        List<Endpoint> endpoints = new ArrayList<>();
        for (Endpoint endpoint : service.endpoints()) {
            if (endpoint.protocolKind() == protocolKind) {
                endpoints.add(endpoint);
            }
        }

        endpoints.sort(Comparator
                .comparing(Endpoint::httpMethod, String.CASE_INSENSITIVE_ORDER)
                .thenComparing(Endpoint::path, String.CASE_INSENSITIVE_ORDER)
        );
        return List.copyOf(endpoints);
    }

    private static String serviceLabel(Service service) {
        if (service == null) {
            return "(unknown service)";
        }
        String host = service.host() == null ? "" : service.host().trim();
        if (!host.isBlank()) {
            return host;
        }
        String name = service.name() == null ? "" : service.name().trim();
        if (!name.isBlank()) {
            return name;
        }
        return "(unknown host)";
    }

    private static String endpointLabel(Endpoint endpoint) {
        if (endpoint == null) {
            return "(unknown endpoint)";
        }
        String method = safeLabel(endpoint.httpMethod(), "");
        String path = safeLabel(endpoint.path(), "/");
        if (method.isBlank()) {
            return path;
        }
        return method + " " + path;
    }

    private static String safeLabel(String value, String fallback) {
        if (value == null) {
            return fallback;
        }
        String trimmed = value.trim();
        return trimmed.isBlank() ? fallback : trimmed;
    }
}
