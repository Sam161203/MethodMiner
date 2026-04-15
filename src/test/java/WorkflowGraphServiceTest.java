import burp.api.montoya.logging.Logging;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WorkflowGraphServiceTest {
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final JsonRpcParser parser = new JsonRpcParser(objectMapper, 1024);

    @Test
    void infersMethodTransitionsFromSharedResponseToRequestValues() throws Exception {
        try (WorkflowGraphService service = new WorkflowGraphService(objectMapper, new NoopLogging())) {
            JsonRpcRecord first = createRecord(
                    "user.lookup",
                    "{\"params\":{\"email\":\"alice@example.test\"}}",
                    "{\"result\":{\"userId\":\"u-100\",\"tenantId\":\"t-1\"}}"
            );
            JsonRpcRecord second = createRecord(
                    "report.fetch",
                    "{\"params\":{\"userId\":\"u-100\"}}",
                    "{\"result\":{\"reportId\":\"r-77\",\"ownerUserId\":\"u-100\"}}"
            );
            JsonRpcRecord third = createRecord(
                    "admin.exportReport",
                    "{\"params\":{\"reportId\":\"r-77\",\"tenantId\":\"t-1\"}}",
                    "{\"result\":{\"exportId\":\"x-1\"}}"
            );

            JsonRpcNormalizedRecord firstNorm = parser.normalize(first);
            JsonRpcNormalizedRecord secondNorm = parser.normalize(second);
            JsonRpcNormalizedRecord thirdNorm = parser.normalize(third);

            service.ingestRecordSync(first, firstNorm);
            service.ingestRecordSync(second, secondNorm);
            service.ingestRecordSync(third, thirdNorm);

            WorkflowGraphService.WorkflowGraphSnapshot snapshot = service.snapshot();
            assertFalse(snapshot.edges().isEmpty());

            WorkflowGraphService.EdgeView edgeOne = edge(snapshot, "user.lookup", "report.fetch");
            WorkflowGraphService.EdgeView edgeTwo = edge(snapshot, "report.fetch", "admin.exportReport");
            assertNotNull(edgeOne);
            assertNotNull(edgeTwo);
            assertTrue(edgeOne.correlations() >= 1);
            assertTrue(edgeTwo.correlations() >= 1);

            WorkflowGraphService.MethodNodeView entry = node(snapshot, "user.lookup");
            WorkflowGraphService.MethodNodeView privileged = node(snapshot, "admin.exportReport");
            assertNotNull(entry);
            assertNotNull(privileged);
            assertTrue(entry.entryPoint());
            assertTrue(privileged.privilegedEndpoint());

            assertFalse(snapshot.chains().isEmpty());
            WorkflowGraphService.ChainView chain = snapshot.chains().get(0);
            ObjectNode export = service.buildChainExportBundle(chain.chainId());
            assertEquals("manual-only", export.path("mode").asText());
            ArrayNode edges = (ArrayNode) export.path("edges");
            assertTrue(edges.size() >= 1);
        }
    }

    @Test
    void doesNotChainAcrossMismatchedIntermediateContexts() throws Exception {
        try (WorkflowGraphService service = new WorkflowGraphService(objectMapper, new NoopLogging())) {
            JsonRpcRecord first = createRecord(
                "seed.lookup",
                "sid-a",
                "{\"params\":{\"lookup\":\"alpha\"}}",
                "{\"result\":{\"userId\":\"u-1\"}}"
            );

            JsonRpcRecord second = createRecord(
                "report.fetch",
                "sid-b",
                "{\"params\":{\"userId\":\"u-1\"}}",
                "{\"result\":{\"reportId\":\"r-1\"}}"
            );

            JsonRpcRecord third = createRecord(
                "report.fetch",
                "sid-a",
                "{\"params\":{\"userId\":\"u-2\"}}",
                "{\"result\":{\"reportId\":\"r-2\"}}"
            );

            JsonRpcRecord fourth = createRecord(
                "report.export",
                "sid-a",
                "{\"params\":{\"reportId\":\"r-2\"}}",
                "{\"result\":{\"exportId\":\"x-1\"}}"
            );

            service.ingestRecordSync(first, parser.normalize(first));
            service.ingestRecordSync(second, parser.normalize(second));
            service.ingestRecordSync(third, parser.normalize(third));
            service.ingestRecordSync(fourth, parser.normalize(fourth));

            WorkflowGraphService.WorkflowGraphSnapshot snapshot = service.snapshot();

            WorkflowGraphService.EdgeView seedToFetch = edge(snapshot, "seed.lookup", "report.fetch");
            WorkflowGraphService.EdgeView fetchToExport = edge(snapshot, "report.fetch", "report.export");
            assertNotNull(seedToFetch);
            assertNotNull(fetchToExport);
            assertNotEquals(
                seedToFetch.targetContext(),
                fetchToExport.sourceContext(),
                "Test precondition should use different report.fetch contexts"
            );

            boolean foundBadChain = snapshot.chains().stream()
                .anyMatch(chain -> chain.edgeIds().contains(seedToFetch.edgeId())
                    && chain.edgeIds().contains(fetchToExport.edgeId()));

            assertFalse(foundBadChain,
                "Chain traversal must not jump from report.fetch in sid-b context to report.export in sid-a context");
        }
    }

    private WorkflowGraphService.EdgeView edge(
            WorkflowGraphService.WorkflowGraphSnapshot snapshot,
            String source,
            String target
    ) {
        for (WorkflowGraphService.EdgeView edge : snapshot.edges()) {
            if (source.equals(edge.sourceMethod()) && target.equals(edge.targetMethod())) {
                return edge;
            }
        }
        return null;
    }

    private WorkflowGraphService.MethodNodeView node(
            WorkflowGraphService.WorkflowGraphSnapshot snapshot,
            String method
    ) {
        for (WorkflowGraphService.MethodNodeView node : snapshot.topConnectedMethods()) {
            if (method.equals(node.methodName())) {
                return node;
            }
        }
        return null;
    }

    private JsonRpcRecord createRecord(String method, String paramsSuffix, String responseBody) {
        return createRecord(method, "sid-default", paramsSuffix, responseBody);
        }

        private JsonRpcRecord createRecord(String method, String sessionId, String paramsSuffix, String responseBody) {
        String requestBody = "{\"jsonrpc\":\"2.0\",\"method\":\"" + method + "\"," + paramsSuffix.substring(1);

        String rawRequest = "POST /rpc HTTP/1.1\\r\\n"
                + "Host: example.test\\r\\n"
                + "Content-Type: application/json\\r\\n"
            + "Cookie: sessionId=" + sessionId + "\\r\\n"
                + "\\r\\n"
                + requestBody;

        JsonRpcRecord.RequestData requestData = JsonRpcRecord.RequestData.fromCaptured(
                "https://example.test/rpc",
                "POST",
            List.of("Host: example.test", "Content-Type: application/json", "Cookie: sessionId=" + sessionId),
                requestBody,
                requestBody.getBytes(StandardCharsets.UTF_8),
                rawRequest,
                rawRequest.getBytes(StandardCharsets.UTF_8)
        );

        String responseRaw = "HTTP/1.1 200 OK\\r\\n"
                + "Content-Type: application/json\\r\\n"
                + "\\r\\n"
                + responseBody;

        JsonRpcRecord.ResponseData responseData = JsonRpcRecord.ResponseData.fromCaptured(
                200,
                List.of("Content-Type: application/json"),
                responseBody,
                responseBody.getBytes(StandardCharsets.UTF_8),
                responseRaw,
                responseRaw.getBytes(StandardCharsets.UTF_8)
        );

        return new JsonRpcRecord(
                null,
                1,
                Instant.now(),
                "Proxy",
                requestData,
                responseData
        );
    }

    private static final class NoopLogging implements Logging {
        @Override
        public java.io.PrintStream output() {
            return System.out;
        }

        @Override
        public java.io.PrintStream error() {
            return System.err;
        }

        @Override
        public void logToOutput(String message) {
        }

        @Override
        public void logToOutput(Object object) {
        }

        @Override
        public void logToError(String message) {
        }

        @Override
        public void logToError(String message, Throwable cause) {
        }

        @Override
        public void logToError(Throwable cause) {
        }

        @Override
        public void raiseDebugEvent(String message) {
        }

        @Override
        public void raiseInfoEvent(String message) {
        }

        @Override
        public void raiseErrorEvent(String message) {
        }

        @Override
        public void raiseCriticalEvent(String message) {
        }
    }
}
