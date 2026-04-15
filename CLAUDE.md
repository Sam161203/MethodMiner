# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Architecture

LogicHunter is a passive Burp Suite extension for JSON-RPC business-logic vulnerability discovery.

- **Main Entry Point**: `src/main/java/Extension.java` - implements `BurpExtension`, wires all services and registers 2 UI tabs
- **Build System**: Gradle with Kotlin DSL, Java 21 compatibility
- **Dependencies**: Montoya API 2025.10 (compile-only), Jackson for JSON, no other runtime dependencies
- **Threading**: All analysis runs on background `ExecutorService` threads; UI updates are queued via `SwingUtilities.invokeLater`

## Core Services

| Service | Purpose |
|---------|---------|
| `JsonRpcCollector` | HTTP handler that intercepts, parses, and stores JSON-RPC traffic |
| `AuthContextStore` | Tracks session/user context with full raw headers (Authorization, Cookie) |
| `SecurityAnalyzerService` | Compares admin vs. low-priv responses for access-control gaps |
| `WorkflowGraphService` | Builds method-to-method value-flow correlations |
| `EntityStoreService` | Extracts and tracks entity IDs, tokens, tenant references |
| `AttackSuggestionService` | Heuristic engine that generates prioritized exploit suggestions |
| `CopyablePayloadBuilder` | Assembles copy-paste-ready payloads with real captured session data |
| `LogicHunterExportService` | JSON export with full auth context, cURL commands, raw HTTP requests |

## UI Layout (2 tabs)

| Tab | Components |
|-----|------------|
| **Dashboard** (`DashboardTab`) | Methods table + Traffic / Entities / Sessions sub-tabs |
| **Attack Planner** (`AttackPlannerTab`) | Suggestions table + Payload / Evidence / Chains sub-tabs |

## Key Design Constraints

1. **Strictly passive** — no traffic replay, no fuzzing, no external calls
2. **Full headers in memory only** — raw Authorization/Cookie headers are used for payload assembly but NOT persisted to JSONL disk logs
3. **Real values over placeholders** — `CopyablePayloadBuilder` resolves actual captured entity IDs and session tokens instead of generic `<foreign_id>` placeholders
4. **Non-blocking** — all ingestion and analysis runs on background threads

## Key Development Commands

```bash
./gradlew build    # Build and test the extension
./gradlew jar      # Create the extension JAR file
./gradlew clean    # Clean build artifacts
```

The built JAR file will be in `build/libs/` and can be loaded directly into Burp Suite.

## Extension Loading in Burp

1. Build the JAR using `./gradlew jar`
2. In Burp: Extensions > Installed > Add > Select the JAR file
3. For quick reloading during development: Ctrl/⌘ + click the Loaded checkbox

## Documentation Structure

- See @docs/bapp-store-requirements.md for BApp Store submission requirements
- See @docs/montoya-api-examples.md for code patterns and extension structure
- See @docs/development-best-practices.md for development guidelines
- See @docs/resources.md for external documentation and links