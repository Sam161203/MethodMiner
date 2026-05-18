# Method Miner Industrial Redesign Report

Date: 2026-05-16

## 1. Executive Summary

Method Miner currently implements a passive JSON-RPC analysis pipeline with useful foundations: Montoya HTTP capture, JSON-RPC normalization, in-memory indexing, entity extraction, workflow correlation, session tagging, exports, Repeater payload generation, and unit tests. The project is not yet an industrial-grade InQL-style extension. It is a JSON-RPC-only product (formerly named "LogicHunter" in code and UI), with no GraphQL support, no protocol-agnostic domain model, no durable project-scoped persistence, and a large amount of analyzer/UI logic concentrated in very large classes.

The recommended strategy is a modular rewrite, not a full rewrite. Keep the proven parsing utilities, JSON shape inference ideas, basic entity extraction heuristics, table models, tests, and Montoya integration learnings. Replace the default-package monolith with a package-oriented architecture centered on a protocol-agnostic `ApiSurface` model, event pipeline, durable store, and pluggable protocol analyzers for GraphQL and JSON-RPC.

The biggest product correction is to separate passive evidence generation from active testing. The current code includes `AttackExecutionService`, which sends HTTP requests through Montoya. That contradicts the stated passive design and should move behind an explicit, disabled-by-default "active validation lab" capability, or be removed from the MVP.

Reference direction:
- InQL: https://github.com/doyensec/inql
- Clairvoyance: https://github.com/nikitastupin/clairvoyance

## 2. Current Codebase Analysis

### Repository Structure

The repo is a compact Gradle Java 21 Burp extension:

- `build.gradle.kts`: Java plugin, Montoya API `2026.2`, Jackson Databind, JUnit 5.
- `src/main/java`: all production classes in the default package.
- `src/test/java`: focused JUnit tests for parser, index, auth context, entity store, workflow graph, mutator, security analyzer, and suggestion engine.
- `docs`: Burp/Montoya/BApp development notes.

There are no Java packages, no module boundaries, no service interfaces, and no resource layer beyond JSONL files.

### How It Works Today

1. `Extension` wires everything manually, registers two suite tabs, registers `JsonRpcCollector`, then warms the in-memory index from disk.
2. `JsonRpcCollector` listens to Montoya HTTP events, stores pending requests by message id, pairs them with responses, filters to POST and configured hosts, probes JSON, requires body credentials, persists raw/normalized JSONL, and notifies downstream services.
3. `JsonRpcParser` accepts JSON-RPC objects or arrays, extracts `method`, `params`, batch metadata, parameter keys, response shape signatures, and multicall nested methods.
4. `JsonRpcIndex` aggregates method/type variants, response hashes, session snapshots, method stats, and a small sample buffer.
5. `AuthContextStore` extracts sessions only from JSON-RPC body `params.credentials.sessionId/database/userName`, maps records and methods to contexts, and lets users mark roles.
6. `SecurityAnalyzerService`, `EntityStoreService`, `WorkflowGraphService`, and `AttackSuggestionService` subscribe to records and recompute findings, entities, value-flow edges, chains, and attack suggestions.
7. `DashboardTab` and `AttackPlannerTab` show tables and text areas for methods, sessions, entities, suggestions, payloads, evidence, and chains.
8. `StorageManager` writes JSONL logs to `%USERPROFILE%/jsonrpc-logs` or a configured folder.

### Important Current References

- Extension wiring and listener graph: `src/main/java/Extension.java` lines 32-105.
- Collector pipeline: `src/main/java/JsonRpcCollector.java` lines 173-329.
- Parser requires non-null `params`: `src/main/java/JsonRpcParser.java` lines 227-247.
- Session extraction is body-credential-specific: `src/main/java/AuthContextStore.java` lines 509-530.
- Active replay exists: `src/main/java/AttackExecutionService.java` lines 69 and 110.
- Active UI controls exist: `src/main/java/AttackPlannerTab.java` lines 125-151.
- JSONL persistence stores full request/response text: `src/main/java/JsonRpcRecord.java` lines 108-131 and `src/main/java/StorageManager.java` lines 84-96.

## 3. Technical Debt Assessment

### Architecture Debt

- Default package for all classes prevents clear ownership and makes growth painful.
- `Extension` is a service locator and manual dependency graph.
- Analyzers directly depend on concrete services instead of domain interfaces.
- Current model is JSON-RPC-first; GraphQL would be bolted on rather than integrated.
- Old tabs still exist (`JsonRpcTab`, `SecurityAnalysisTab`, `WorkflowGraphTab`, `EntityStoreTab`, `AttackSuggestionsTab`) even though only two tabs are registered.

### Class Size and Coupling

The biggest hotspots are too large for maintainable evolution:

- `AttackSuggestionService`: about 104 KB, combines observation storage, detector orchestration, scoring, payload creation, report text, and diff evidence.
- `SecurityAnalyzerService`: about 82 KB, combines response schema analysis, risk scoring, sample rendering, export bundle generation, and auth comparison.
- `AttackExecutionService`: about 46 KB, combines replay targeting, payload mutation, validation, and response classification.
- `AttackPlannerTab`: about 39 KB, combines table UI, payload actions, active validation, diff rendering, Repeater, export, and workflow display.
- `WorkflowGraphService`: about 46 KB, combines indexing, graph calculation, chain generation, and export.

### Threading and Performance Debt

- Many services use one `newSingleThreadExecutor`; each record is fanned out to multiple queues, causing duplicated parsing and duplicated auth lookup.
- `WorkflowGraphService.ingestRecordSync` calls `authContextStore.observeRecord`, which mutates session state again instead of using a non-mutating lookup.
- Full suggestion recomputation snapshots indexes and workflow graph repeatedly. It is throttled, but not incremental.
- Swing tables render large text and large row models directly; there is no pagination or virtualized model.
- JSON bodies are repeatedly parsed in parser, auth store, entity extractor, workflow graph, security analyzer, and suggestion engine.

### Thread-Safety Concerns

- Mixed use of `ConcurrentHashMap`, synchronized aggregate methods, and shared mutable state is workable but hard to reason about.
- UI update listeners can be invoked frequently from analyzer threads and then queued to Swing; this is safe in places, but the event model is ad hoc.
- `AuthContextStore.SessionState` fields are mutated inside `ConcurrentHashMap.compute`, but snapshots read state without an object-level lock.

### Persistence Limitations

- Persistence is append-only JSONL outside the Burp project by default.
- There is no schema versioning, migration, compaction, encryption, or per-project namespace.
- Raw request/response body and raw HTTP are persisted. This conflicts with the requirement that raw Authorization/Cookie headers remain memory-only. The current `JsonRpcRecord` model can persist headers and raw HTTP.
- Role tags, reviewed/exported flags, UI preferences, settings, and computed caches are not durably modeled as first-class project state.

### UI Problems

- The UI is reduced to two registered tabs, but each tab still has nested sub-tabs and dense action bars.
- UI uses plain Swing tables/text areas rather than a navigable API tree and schema/graph-centric experience.
- Active validation buttons are highly visible, which conflicts with passive-first expectations.
- There is no unified left navigation, no protocol tree, no first-class session comparison view, no settings dialog, and no syntax highlighting component.
- Color choices are hard-coded and not fully theme-aware.

## 4. Gap Analysis

| Area | Current | Target | Gap |
| --- | --- | --- | --- |
| Protocols | JSON-RPC only | GraphQL and JSON-RPC | Major |
| Detection | POST + JSON-RPC method + body credentials | Proxy history and Site Map, GraphQL endpoint detection, JSON-RPC detection | Major |
| Schema | JSON shape signatures | GraphQL SDL, JSON-RPC schema-like model | Major |
| Session | MyGeotab-style body credentials | Cookies, Authorization, API keys, custom headers, body fields, GraphQL variables | Major |
| Model | Method aggregates and records | Protocol-agnostic `ApiSurface` domain model | Major |
| Relationships | Value equality response -> request | Identifier semantics, namespace, CRUD, sessions, response/input mapping | Partial |
| Recommendations | Heuristic detectors, many generated suggestions | Low-noise evidence-weighted recommendations | Partial |
| UI | Two table-heavy tabs | Single InQL-style professional tab | Major |
| Persistence | JSONL logs | Versioned project store and cache | Major |
| Performance | Multiple parse/recompute paths | Incremental analysis, cached observations, lazy graph | Partial |
| Testing | Good unit tests for current services | Unit, integration, UI, benchmarks, regression corpus | Partial |

## 5. Reuse vs Rewrite

### Reuse

- Montoya registration and unload lifecycle concepts from `Extension`.
- `JsonRpcParser` logic for JSON-RPC batch/multicall normalization, after generalizing nullable params and protocol detection.
- `JsonShapeUtil` and response shape signature ideas.
- `RepeaterRequestMutator`, after moving it into a passive payload builder module and adding strong tests.
- `WorkflowGraphService` value-flow concept, but not the current monolithic implementation.
- Entity extraction heuristics for id-like fields, but behind typed extractors.
- Existing JUnit tests as regression seeds.

### Rewrite

- Package structure and service boundaries.
- Domain model.
- Session detection and profile management.
- Recommendation engine.
- Persistence layer.
- GraphQL analyzer.
- UI.
- Settings system.
- Active replay integration.

## 6. Recommended Refactoring Strategy

Use a modular rewrite with compatibility adapters.

Do not full-rewrite the repo from scratch. The current implementation has working tests and useful heuristics. But do not incrementally refactor inside the default-package monolith either; it will leave GraphQL and unified modeling as afterthoughts.

Plan:

1. Create new packages and a protocol-agnostic domain model.
2. Add a new passive event bus and repository layer beside existing code.
3. Port JSON-RPC detection/parser into `protocol.jsonrpc`.
4. Implement GraphQL detection/parser in `protocol.graphql`.
5. Build new analyzers against `ApiSurface`.
6. Build a new single-tab UI against query/view-model interfaces.
7. Deprecate old tabs/services once feature parity exists.
8. Keep old tests, add new protocol and recommendation tests, then delete legacy code.

## 7. Final System Architecture

```
Montoya capture
  -> TrafficIngestor
  -> ProtocolDetector
  -> ObservationNormalizer
  -> EventBus
  -> SurfaceRepository
  -> IncrementalAnalyzers
  -> ViewModels
  -> Single Method Miner UI
```

Core principles:

- Capture is always fast and non-blocking.
- Raw traffic is separated from sanitized observations.
- Protocol analyzers are plugins.
- Recommendations require evidence, not just suspicious names.
- UI reads snapshots and view models, never analyzer internals.
- Active validation is optional, explicit, rate-limited, and separated.

## 8. Package Structure

Recommended Java packages:

```text
com.methodminer
  Extension
  burp
    MontoyaLifecycle
    TrafficIngestor
    RepeaterSender
    SiteMapScanner
  core.model
    ApiSurface, Service, Endpoint, Operation, Parameter, DataType
    SessionProfile, Relationship, Observation, RiskSignal
    AttackRecommendation, AttackChain
  core.events
    ObservationEvent, SurfaceChangedEvent, EventBus
  core.analysis
    RelationshipAnalyzer, RiskScorer, RecommendationEngine
  core.session
    SessionDetector, SessionProfileStore, AuthMaterialVault
  protocol
    ProtocolDetector, ProtocolAnalyzer, ProtocolKind
  protocol.jsonrpc
    JsonRpcDetector, JsonRpcParser, JsonRpcSchemaInferer
  protocol.graphql
    GraphQlDetector, GraphQlParser, IntrospectionRunner
    ClairvoyanceDiscoveryAdapter, JsGraphQlExtractor
  persistence
    ProjectStore, JsonStore, CacheStore, Migration
  ui
    MethodMinerTab, SurfaceTreePanel, SchemaPanel, EvidencePanel
    RecommendationPanel, SessionComparePanel, SettingsDialog
  settings
    SettingsStore, GraphQlSettings, JsonRpcSettings, RiskSettings
  export
    SdlExporter, JsonRpcSchemaExporter, ModelExporter, RecommendationExporter
```

## 9. Class Design

Key interfaces:

```java
interface ProtocolDetector {
    DetectionResult detect(HttpExchange exchange);
}

interface ProtocolAnalyzer {
    List<Observation> normalize(HttpExchange exchange, DetectionResult detection);
}

interface IncrementalAnalyzer {
    AnalysisDelta analyze(Observation observation, SurfaceRepository repo);
}

interface SurfaceRepository {
    void upsertObservation(Observation observation);
    ApiSurface snapshot(SurfaceQuery query);
}

interface RecommendationRule {
    List<RiskSignal> evaluate(Operation operation, EvidenceContext evidence);
}
```

Keep analyzers pure where possible. Burp APIs should be isolated to `burp.*`.

## 10. Unified Data Model

Use stable IDs so data can be merged across captures:

- `ApiSurface`: project root, services, sessions, global findings.
- `Service`: host/base path/protocol grouping.
- `Endpoint`: URL, method, content types, protocol kind.
- `Operation`: GraphQL query/mutation/subscription or JSON-RPC method.
- `Parameter`: name/path, source, required/optional, observed values, sensitivity.
- `DataType`: scalar/object/array/enum/union/input object, confidence, examples.
- `SessionProfile`: display name, auth fingerprints, role, observed boundaries.
- `Relationship`: producer, consumer, entity path, confidence, samples.
- `Observation`: one normalized request/response fact with sanitized evidence.
- `RiskSignal`: atomic signal with score contribution and evidence pointer.
- `AttackRecommendation`: vulnerability type, severity, confidence, payload, evidence.
- `AttackChain`: ordered operations plus relationship and auth evidence.

## 11. Protocol Detection Logic

### GraphQL

Detect when any of these are true:

- POST JSON body has `query` string and optional `variables` or `operationName`.
- GET request has `query` parameter containing GraphQL syntax.
- Content type or path hints: `/graphql`, `/gql`, `application/graphql`.
- Response has `data` or GraphQL-shaped `errors`.
- JavaScript contains GraphQL documents or persisted query hashes.

### JSON-RPC

Detect when:

- Body is an object or array of objects.
- Object contains `method`.
- `jsonrpc` is `2.0` when present.
- `params` may be missing, null, object, array, or scalar.
- `id` may be missing for notifications.

Current parser should be relaxed because JSON-RPC permits requests without `params`.

## 12. Session-Aware Architecture

Replace `AuthContextStore` with:

- `AuthMaterialExtractor`: extracts Cookie, Authorization, API keys, custom headers, body auth, GraphQL variables.
- `AuthFingerprint`: hashes sensitive auth values for durable storage.
- `AuthMaterialVault`: in-memory only raw auth material for copy/send-to-Repeater.
- `SessionProfileStore`: persisted profile metadata, names, roles, confidence, aliases.
- `SessionComparator`: aligns equivalent operations across profiles.

Session profile fields:

```java
record SessionProfile(
    UUID id,
    String name,
    Role role,
    Set<AuthFingerprint> fingerprints,
    Set<String> hosts,
    Instant firstSeen,
    Instant lastSeen,
    ProfileConfidence confidence
) {}
```

## 13. Schema Extraction Strategies

### GraphQL

1. Passive parse captured operations into AST.
2. Merge operation fields, variables, arguments, fragments, aliases, and return paths.
3. Run introspection only when enabled and explicitly allowed.
4. If introspection is disabled:
   - JavaScript extraction for embedded operations and fragments.
   - Wordlist discovery with delay/concurrency/rate-limit controls.
   - Clairvoyance-style error-based reconstruction.
5. Merge sources into a confidence-scored schema graph.
6. Export SDL with source annotations.

### JSON-RPC

1. Group by endpoint, namespace, method, and params mode.
2. Infer params from named objects, positional arrays, and observed scalar paths.
3. Infer return schemas from result/error bodies.
4. Derive namespace tree from `.` and `/` separators.
5. Detect common discovery operations (`system.listMethods`, `rpc.discover`, `system.describe`) as optional active checks only.
6. Export a JSON-RPC schema-like document.

## 14. Relationship Inference Algorithms

Score relationships with additive evidence:

- Shared identifier: +25
- Response field name matches later input parameter: +20
- Namespace/CRUD pattern: +15
- Observed temporal order: +10
- Cross-session ownership mismatch potential: +20
- Multiple samples: +min(15, samples * 3)
- Same endpoint/service: +5

Relationship examples:

- `user.listUsers -> user.getUser -> user.updateUser`
- `order.listOrders -> order.getOrder -> order.cancelOrder`
- `admin.getRoles -> admin.assignRole`

Use lazy calculation for expensive graph views. Store inverted indexes by value fingerprint, field path, entity type, and operation id.

## 15. Risk Scoring Formulas

Recommendation score should be evidence-first:

```text
score =
  verbRisk
  + identifierRisk
  + sensitiveDataRisk
  + relationshipRisk
  + sessionBoundaryRisk
  + responseDiffRisk
  + sampleConsistencyRisk
  - noisePenalty
```

Suggested weights:

- Dangerous verb: get/list +10, update/assign/reset +25, delete/transfer +30.
- Identifier parameter: +20, tenant/account/user id +30.
- Sensitive response fields: +10 to +30.
- Relationship chain to write operation: +20.
- Admin-only or profile-specific observation: +25.
- Same request shape, different response across profiles: +30.
- Repeated consistent samples: +5 to +20.
- Error-only or single weak heuristic: -20.
- Known low-value method or UI telemetry: -30.

Confidence:

- High: at least two independent evidence classes, including session or relationship evidence.
- Medium: strong method/entity evidence but missing cross-session proof.
- Low: naming heuristic only; hide by default.

## 16. Recommendation Engine Design

Use rule modules:

- `BrokenAccessControlRule`
- `BolaRule`
- `PrivilegeEscalationRule`
- `MassAssignmentRule`
- `SensitiveDataExposureRule`
- `BusinessLogicWorkflowRule`
- `GraphQlIntrospectionExposureRule`
- `GraphQlMutationRiskRule`
- `JsonRpcDiscoveryExposureRule`

Each recommendation must include:

- Vulnerability type.
- Why it is interesting.
- Related operations and chains.
- Confidence score and severity.
- Evidence snippets with record ids.
- Ready-to-copy payload.
- Send to Repeater action.
- Suppression and reviewed state.

Default UI should show only Medium and High confidence.

## 17. UI/UX Architecture

Build one Burp tab named `Method Miner`.

Layout:

1. Toolbar: scope, protocol filter, session selector, search, export, settings.
2. Left navigation tree: Services -> Endpoints -> Operations -> Params/Types.
3. Center panel: schema view or relationship graph.
4. Right/bottom evidence panel: request/response examples, variables, params.
5. Recommendations panel: ranked findings with confidence filters.
6. Settings dialog.

Use:

- `JSplitPane` for stable panes.
- `JTree` or tree-table for navigation.
- `RSyntaxTextArea` or similar syntax component if dependencies are allowed; otherwise custom styled text.
- `SwingWorker` and immutable view snapshots.
- Theme-aware colors from Burp/Swing UI defaults.
- Virtualized/paginated table models for large projects.

## 18. Settings Architecture

Persist typed settings:

- GraphQL introspection enabled/disabled.
- Discovery mode: passive only, JS extraction, wordlist, error-based.
- Discovery controls: delay, concurrency, retries, jitter, rate-limit handling.
- Wordlist paths.
- JSON-RPC discovery methods enabled/disabled.
- Session detection header/body rules.
- Risk thresholds and hidden categories.
- Persistence location, retention, raw traffic policy.
- UI preferences.

Settings should be versioned and project-scoped.

## 19. Persistence and Caching Design

Recommended store:

- `project-state.json`: settings, schema version, profiles, reviewed flags.
- `observations.jsonl`: sanitized normalized observations.
- `raw-vault`: optional encrypted/local-only raw request references, disabled or memory-only by default.
- `cache`: derived indexes by protocol, operation, entity, relationship.

Do not persist raw Authorization/Cookie headers unless the user explicitly enables encrypted storage. Persist only fingerprints by default.

Use schema migrations:

```java
interface Migration {
    int fromVersion();
    int toVersion();
    void migrate(ProjectStore store);
}
```

## 20. Performance Optimization Plan

- Parse each HTTP exchange once into `ParsedExchange`.
- Publish immutable observations to analyzers.
- Deduplicate by method, endpoint, request shape, response shape, session fingerprint.
- Batch UI notifications.
- Use bounded worker pools for CPU analysis and separate queues for optional active discovery.
- Keep relationship graph lazy and cache by `surfaceVersion`.
- Cap stored samples per operation, but retain enough representative examples.
- Avoid full recomputation on each record; use deltas.
- Add backpressure when Burp projects are huge.

## 21. Testing Strategy

### Unit Tests

- Protocol detectors.
- GraphQL AST parsing and SDL merge.
- JSON-RPC parser edge cases.
- Session extractor rules.
- Risk scorer formulas.
- Relationship scoring.
- Payload builder redaction.

### Integration Tests

- Synthetic Burp HTTP exchanges through full passive pipeline.
- Multi-session BOLA scenarios.
- GraphQL introspection enabled/disabled scenarios.
- JSON-RPC batch and notification scenarios.

### UI Tests

- Swing smoke tests for tree navigation, selection, filtering, export, settings.
- Large model rendering tests.

### Performance Benchmarks

- 10K, 100K, and 1M observations.
- Large GraphQL schemas.
- Large JSON-RPC response bodies.
- Cold start and warm project load.

### Regression Corpus

- Realistic anonymized fixtures for bug bounty workflows.
- Known false positives.
- Known vulnerable patterns.

## 22. MVP Roadmap

1. Rename product/UI to Method Miner.
2. Add packages and core domain model.
3. Build new passive `TrafficIngestor` and `ProtocolDetector`.
4. Port JSON-RPC parsing into new model.
5. Add basic GraphQL passive detection and operation parsing.
6. Build `SessionProfileStore` with header/body/variable extraction.
7. Implement unified surface tree UI.
8. Implement schema exports: GraphQL SDL from passive operations and JSON-RPC schema JSON.
9. Implement evidence-driven recommendation engine with low-noise defaults.
10. Add project-scoped settings and sanitized persistence.

## 23. Advanced Roadmap

- GraphQL introspection runner.
- Clairvoyance-style error-based reconstruction.
- JavaScript GraphQL document extraction.
- Wordlist discovery with responsible controls.
- Relationship graph visualization.
- Session comparison matrix.
- Repeater integration with raw in-memory auth vault.
- Finding suppression, notes, and triage state.
- BApp Store hardening.
- Optional active validation lab with clear consent and rate limits.

## 24. Additional Industrial-Grade Suggestions

- Make passive mode the default and safest product identity.
- Treat recommendations as triage items, not scanner findings.
- Add a "why this was hidden" low-confidence drawer for transparency.
- Add per-program scope controls to avoid collecting unrelated traffic.
- Add redaction previews before export.
- Add project import/export for collaboration without raw secrets.
- Add architecture decision records in `docs/adr`.
- Add CI with build, tests, static checks, and dependency review.
- Add a fixture generator for anonymized traffic.
- Add BApp Store readiness checks before release.

## Final Recommendation

Proceed with a modular rewrite. Keep the working JSON-RPC learnings and tests, but move them into a new architecture instead of stretching the current default-package monolith. A full rewrite would waste useful parser/analyzer knowledge; an incremental refactor would trap GraphQL, sessions, persistence, and UI inside assumptions that were built for a narrower MyGeotab-style JSON-RPC workflow.
