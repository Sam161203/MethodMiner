package com.methodminer.ui;

import com.methodminer.core.model.ApiSurface;
import com.methodminer.core.model.ConfidenceLevel;
import com.methodminer.core.model.DataType;
import com.methodminer.core.model.DataTypeKind;
import com.methodminer.core.model.Endpoint;
import com.methodminer.core.model.Observation;
import com.methodminer.core.model.Operation;
import com.methodminer.core.model.OperationKind;
import com.methodminer.core.model.Parameter;
import com.methodminer.core.model.ParameterSource;
import com.methodminer.core.model.Service;
import com.methodminer.protocol.ProtocolKind;
import org.junit.jupiter.api.Test;

import javax.swing.tree.DefaultMutableTreeNode;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SurfaceViewModelTest {

    @Test
    void buildsNavigationTreeServicesEndpointsOperationsParameters() {
        ApiSurface surface = sampleSurface();
        SurfaceViewModel viewModel = new SurfaceViewModel(new TreeNodeFactory());

        DefaultMutableTreeNode root = viewModel.buildNavigationTree(surface);

        assertEquals("Services", root.getUserObject().toString());
        assertEquals(1, root.getChildCount());

        DefaultMutableTreeNode protocol = (DefaultMutableTreeNode) root.getChildAt(0);
        assertEquals("JSON-RPC", protocol.getUserObject().toString());

        DefaultMutableTreeNode service = (DefaultMutableTreeNode) protocol.getChildAt(0);
        assertEquals("gateway.api.axis.com", service.getUserObject().toString());

        DefaultMutableTreeNode endpoint = (DefaultMutableTreeNode) service.getChildAt(0);
        assertEquals("POST /rpc", endpoint.getUserObject().toString());

        DefaultMutableTreeNode operation = (DefaultMutableTreeNode) endpoint.getChildAt(0);
        assertEquals("user.getProfile", operation.getUserObject().toString());

        DefaultMutableTreeNode param1 = (DefaultMutableTreeNode) operation.getChildAt(0);
        assertEquals("userId : string", param1.getUserObject().toString());

        DefaultMutableTreeNode param2 = (DefaultMutableTreeNode) operation.getChildAt(1);
        assertEquals("includeRoles : boolean", param2.getUserObject().toString());
    }

    @Test
    void rendersSchemaWithNamespaceParamsAndObservationCount() {
        ApiSurface surface = sampleSurface();
        SurfaceViewModel viewModel = new SurfaceViewModel(new TreeNodeFactory());
        DefaultMutableTreeNode root = viewModel.buildNavigationTree(surface);
        TreeNodeFactory.TreeNodeData opNode = findOperationNodeData(root);
        assertNotNull(opNode);

        String schema = viewModel.renderSchema(surface, opNode);
        assertTrue(schema.contains("Operation: user.getProfile"));
        assertTrue(schema.contains("Protocol: JSON-RPC"));
        assertTrue(schema.contains("Namespace: user"));
        assertTrue(schema.contains("Observations: 1"));
        assertTrue(schema.contains("userId : string"));
        assertTrue(schema.contains("includeRoles : boolean"));
    }

    @Test
    void rendersEvidenceWithEndpointAndSampleSummaries() {
        ApiSurface surface = sampleSurface();
        SurfaceViewModel viewModel = new SurfaceViewModel(new TreeNodeFactory());
        DefaultMutableTreeNode root = viewModel.buildNavigationTree(surface);
        TreeNodeFactory.TreeNodeData opNode = findOperationNodeData(root);
        assertNotNull(opNode);

        String evidence = viewModel.renderEvidence(surface, opNode);
        assertTrue(evidence.contains("Endpoint: POST gateway.api.axis.com/rpc"));
        assertTrue(evidence.contains("Operation: user.getProfile"));
        assertTrue(evidence.contains("request:"));
        assertTrue(evidence.contains("response:"));
        assertTrue(evidence.contains("status=200"));
    }

    @Test
    void safeRenderersHandleNullSelection() {
        ApiSurface surface = sampleSurface();
        SurfaceViewModel viewModel = new SurfaceViewModel(new TreeNodeFactory());

        assertTrue(viewModel.renderSchema(surface, null).contains("Select an operation"));
        assertTrue(viewModel.renderEvidence(surface, null).contains("Select an operation"));
    }

    private static TreeNodeFactory.TreeNodeData findOperationNodeData(DefaultMutableTreeNode root) {
        DefaultMutableTreeNode protocol = (DefaultMutableTreeNode) root.getChildAt(0);
        DefaultMutableTreeNode service = (DefaultMutableTreeNode) protocol.getChildAt(0);
        DefaultMutableTreeNode endpoint = (DefaultMutableTreeNode) service.getChildAt(0);
        DefaultMutableTreeNode operation = (DefaultMutableTreeNode) endpoint.getChildAt(0);
        Object userObject = operation.getUserObject();
        return (TreeNodeFactory.TreeNodeData) userObject;
    }

    private static ApiSurface sampleSurface() {
        UUID serviceId = UUID.randomUUID();
        UUID endpointId = UUID.randomUUID();
        UUID operationId = UUID.randomUUID();

        DataType userIdType = new DataType(
                UUID.randomUUID(),
                "string",
                DataTypeKind.SCALAR,
                ConfidenceLevel.LOW,
                Map.of(),
                Optional.empty(),
                List.of(),
                List.of(),
                List.of()
        );
        DataType includeRolesType = new DataType(
                UUID.randomUUID(),
                "boolean",
                DataTypeKind.SCALAR,
                ConfidenceLevel.LOW,
                Map.of(),
                Optional.empty(),
                List.of(),
                List.of(),
                List.of()
        );

        Parameter userId = new Parameter(
                UUID.randomUUID(),
                "userId",
                "$.params.userId",
                ParameterSource.JSON_RPC_PARAM,
                false,
                userIdType,
                false,
                List.of()
        );
        Parameter includeRoles = new Parameter(
                UUID.randomUUID(),
                "includeRoles",
                "$.params.includeRoles",
                ParameterSource.JSON_RPC_PARAM,
                false,
                includeRolesType,
                false,
                List.of()
        );

        Operation operation = new Operation(
                operationId,
                ProtocolKind.JSON_RPC,
                "user.getProfile",
                OperationKind.METHOD,
                List.of(userId, includeRoles),
                Optional.empty(),
                Optional.empty()
        );

        Endpoint endpoint = new Endpoint(
                endpointId,
                ProtocolKind.JSON_RPC,
                "POST",
                "/rpc",
                Set.of("application/json"),
                List.of(operation)
        );

        Service service = new Service(
                serviceId,
                "gateway.api.axis.com",
                "gateway.api.axis.com",
                "",
                List.of(endpoint)
        );

        Observation observation = new Observation(
                UUID.randomUUID(),
                ProtocolKind.JSON_RPC,
                serviceId,
                endpointId,
                operationId,
                Optional.empty(),
                Instant.parse("2026-05-17T00:00:00Z"),
                Map.of(
                        "host", "gateway.api.axis.com",
                        "path", "/rpc",
                        "httpMethod", "POST",
                        "responseStatusCode", "200"
                ),
                Optional.of("user.getProfile(named:userId,includeRoles)"),
                Optional.of("status=200 result object{name:string,...}")
        );

        Instant now = Instant.parse("2026-05-17T00:00:00Z");
        return new ApiSurface(
                UUID.randomUUID(),
                "demo",
                List.of(service),
                List.of(observation),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                now,
                now
        );
    }
}
