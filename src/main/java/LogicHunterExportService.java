import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public final class LogicHunterExportService {
    private final ObjectMapper objectMapper;
    private final AuthContextStore authContextStore;
    private final JsonRpcIndex index;
    private final SecurityAnalyzerService securityAnalyzer;
    private final EntityStoreService entityStoreService;
    private final AttackSuggestionService attackSuggestionService;
    private final WorkflowGraphService workflowGraphService;

    public LogicHunterExportService(
            ObjectMapper objectMapper,
            AuthContextStore authContextStore,
            JsonRpcIndex index,
            SecurityAnalyzerService securityAnalyzer,
            EntityStoreService entityStoreService,
            AttackSuggestionService attackSuggestionService,
            WorkflowGraphService workflowGraphService
    ) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
        this.authContextStore = Objects.requireNonNull(authContextStore, "authContextStore must not be null");
        this.index = Objects.requireNonNull(index, "index must not be null");
        this.securityAnalyzer = Objects.requireNonNull(securityAnalyzer, "securityAnalyzer must not be null");
        this.entityStoreService = Objects.requireNonNull(entityStoreService, "entityStoreService must not be null");
        this.attackSuggestionService = Objects.requireNonNull(attackSuggestionService, "attackSuggestionService must not be null");
        this.workflowGraphService = Objects.requireNonNull(workflowGraphService, "workflowGraphService must not be null");
    }

    public ObjectNode buildFullExport() {
        ObjectNode root = objectMapper.createObjectNode();
        root.put("exportedAt", Instant.now().toString());

        root.set("authContexts", exportAuthContexts());
        root.set("methods", exportMethods(null));
        root.set("entities", exportEntities(null));
        root.set("findings", exportFindings(null));
        root.set("attackSuggestions", exportAttackSuggestions(null));
        root.set("workflowChains", exportWorkflowChains(null));

        return root;
    }

    public ObjectNode buildMethodExport(String methodName) {
        ObjectNode root = objectMapper.createObjectNode();
        root.put("exportedAt", Instant.now().toString());
        root.put("method", methodName == null ? "" : methodName);

        root.set("authContexts", exportAuthContexts());
        root.set("methods", exportMethods(methodName));
        root.set("entities", exportEntities(methodName));
        root.set("findings", exportFindings(methodName));
        root.set("attackSuggestions", exportAttackSuggestions(methodName));
        root.set("workflowChains", exportWorkflowChains(methodName));

        return root;
    }

    private ArrayNode exportAuthContexts() {
        ArrayNode contexts = objectMapper.createArrayNode();
        for (AuthContextStore.AuthContext context : authContextStore.snapshotContexts()) {
            ObjectNode node = objectMapper.createObjectNode();
            node.put("database", safe(context.database()));
            node.put("userName", safe(context.userName()));
            node.put("sessionId", safe(context.sessionId()));
            node.put("role", context.role() == null ? RoleType.UNKNOWN.displayName() : context.role().displayName());
            node.put("contextKey", safe(context.contextKey()));
            node.put("authorization", safe(context.rawAuthorizationHeader()));
            node.put("cookie", safe(context.rawCookieHeader()));
            node.put("lastSeenUrl", safe(context.lastSeenUrl()));
            contexts.add(node);
        }
        return contexts;
    }

    private ArrayNode exportMethods(String focusMethod) {
        ArrayNode methods = objectMapper.createArrayNode();
        for (JsonRpcIndex.MethodRow row : index.snapshotMethodRows()) {
            if (focusMethod != null && !focusMethod.isBlank() && !focusMethod.equals(row.methodName())) {
                continue;
            }

            ObjectNode node = objectMapper.createObjectNode();
            node.put("methodName", row.methodName());
            node.put("paramKeys", row.paramKeys());
            node.put("count", row.count());
            node.put("uniqueVariants", row.uniqueVariants());
            node.put("firstSeen", row.firstSeen() == null ? "" : row.firstSeen().toString());
            node.put("lastSeen", row.lastSeen() == null ? "" : row.lastSeen().toString());
            node.put("role", authContextStore.roleForMethod(row.methodName()).displayName());

            ArrayNode samples = objectMapper.createArrayNode();
            index.snapshotMethodDetails(row.methodName()).ifPresent(details -> {
                for (JsonRpcRecord sample : details.sampleRawRecords()) {
                    ObjectNode sampleNode = objectMapper.createObjectNode();
                    sampleNode.put("recordId", sample.recordId());
                    sampleNode.put("timestamp", sample.timestamp() == null ? "" : sample.timestamp().toString());
                    sampleNode.put("url", safe(sample.request().url()));
                    sampleNode.put("httpMethod", safe(sample.request().httpMethod()));
                    sampleNode.put("requestBody", safe(sample.request().bodyText()));
                    sampleNode.put("responseStatus", sample.response().statusCode() == null ? -1 : sample.response().statusCode());
                    sampleNode.put("responseBody", safe(sample.response().bodyText()));
                    sampleNode.put("role", authContextStore.roleForRecordId(sample.recordId()).displayName());
                    samples.add(sampleNode);
                }
            });
            node.set("sampleRequests", samples);

            methods.add(node);
        }
        return methods;
    }

    private ArrayNode exportEntities(String focusMethod) {
        ArrayNode entities = objectMapper.createArrayNode();
        for (EntityStoreService.EntityRow row : entityStoreService.snapshotRows()) {
            EntityStoreService.EntityDetails details = entityStoreService.snapshotEntityDetails(row.entityKey()).orElse(null);
            if (details == null) {
                continue;
            }

            if (focusMethod != null && !focusMethod.isBlank() && !details.methods().contains(focusMethod)) {
                continue;
            }

            ObjectNode node = objectMapper.createObjectNode();
            node.put("entityId", row.entityKey());
            node.put("displayValue", row.preview());
            node.put("entityType", row.entityType().displayName());
            node.put("risk", row.riskDisplay());

            ArrayNode methods = objectMapper.createArrayNode();
            for (String method : details.methods()) {
                methods.add(method);
            }
            node.set("seenInMethods", methods);

            ArrayNode samples = objectMapper.createArrayNode();
            for (String sample : details.samples()) {
                samples.add(sample);
            }
            node.set("sampleValues", samples);

            entities.add(node);
        }
        return entities;
    }

    private ArrayNode exportFindings(String focusMethod) {
        ArrayNode findings = objectMapper.createArrayNode();

        for (SecurityFinding finding : securityAnalyzer.snapshotFindings()) {
            if (focusMethod != null && !focusMethod.isBlank() && !focusMethod.equals(finding.method())) {
                continue;
            }

            ObjectNode node = objectMapper.createObjectNode();
            node.put("id", finding.findingId());
            node.put("method", finding.method());
            node.put("trigger", finding.trigger());
            node.put("riskScore", finding.riskScore());
            node.put("risk", finding.riskDisplay());
            node.put("whyFlagged", finding.whyFlagged());
            node.put("firstSeen", finding.firstSeen() == null ? "" : finding.firstSeen().toString());
            node.put("lastSeen", finding.lastSeen() == null ? "" : finding.lastSeen().toString());
            node.put("reviewed", finding.reviewed());
            node.put("exported", finding.exported());
            findings.add(node);
        }

        return findings;
    }

    private ArrayNode exportAttackSuggestions(String focusMethod) {
        ArrayNode suggestions = objectMapper.createArrayNode();
        for (AttackSuggestion suggestion : attackSuggestionService.snapshotSuggestions()) {
            if (focusMethod != null && !focusMethod.isBlank()) {
                boolean matchesMethod = focusMethod.equals(suggestion.primaryMethod())
                        || safe(suggestion.attackPath()).contains(focusMethod);
                if (!matchesMethod) {
                    continue;
                }
            }

            ObjectNode node = objectMapper.createObjectNode();
            node.put("id", suggestion.suggestionId());
            node.put("category", suggestion.category());
            node.put("title", suggestion.findingTitle());
            node.put("host", suggestion.host());
            node.put("method", suggestion.primaryMethod());
            node.put("priority", suggestion.priorityDisplay());
            node.put("confidence", suggestion.confidenceDisplay());
            node.put("confidenceScore", suggestion.confidenceScore());
            node.put("effectivenessScore", suggestion.effectivenessScore());
            node.put("decision", suggestion.verdictDisplay());
            node.put("primaryMethod", suggestion.primaryMethod());
            node.put("attackPath", suggestion.attackPath());
            node.put("observation", suggestion.observation());
            node.put("whySuspicious", suggestion.whySuspicious());
            node.put("exploitPayload", suggestion.exploitPayload());
            node.put("repeaterRequest", suggestion.repeaterRequest());
            node.put("expectedResult", suggestion.expectedResult());
            node.put("ifVulnerable", suggestion.ifVulnerable());
            node.put("impact", suggestion.impact());
            node.put("evidence", suggestion.evidence());
            node.put("formattedFinding", suggestion.toFormattedFinding());

            // Include full request context for copy-paste
            try {
                String curlCommand = CopyablePayloadBuilder.buildCurlForSuggestion(suggestion, authContextStore, index);
                node.put("curlCommand", curlCommand);
                String rawHttpRequest = CopyablePayloadBuilder.buildHttpRequest(suggestion, authContextStore, index);
                node.put("rawHttpRequest", rawHttpRequest);
            } catch (Exception ignored) {
                // CopyablePayloadBuilder may fail if no auth context captured yet.
            }

            suggestions.add(node);
        }
        return suggestions;
    }

    private ArrayNode exportWorkflowChains(String focusMethod) {
        ArrayNode chains = objectMapper.createArrayNode();
        WorkflowGraphService.WorkflowGraphSnapshot snapshot = workflowGraphService.snapshot();
        for (WorkflowGraphService.ChainView chain : snapshot.chains()) {
            if (focusMethod != null && !focusMethod.isBlank()) {
                List<String> sequence = chain.methodSequence() == null ? List.of() : chain.methodSequence();
                if (!sequence.contains(focusMethod)) {
                    continue;
                }
            }

            ObjectNode node = objectMapper.createObjectNode();
            node.put("chainId", chain.chainId());
            node.put("path", chain.path());
            node.put("steps", chain.steps());
            node.put("score", chain.score());
            node.put("entityFlow", chain.highlights());
            node.put("rationale", chain.rationale());

            ArrayNode sequenceArray = objectMapper.createArrayNode();
            for (String method : nullSafe(chain.methodSequence())) {
                sequenceArray.add(method);
            }
            node.set("methodSequence", sequenceArray);

            chains.add(node);
        }
        return chains;
    }

    private static List<String> nullSafe(List<String> values) {
        if (values == null) {
            return List.of();
        }
        return new ArrayList<>(values);
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }
}
