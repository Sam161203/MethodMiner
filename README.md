# LogicHunter (Burp Suite Montoya Extension)

LogicHunter is a passive Burp Suite extension for JSON-RPC traffic analysis focused on business-logic, access-control, and workflow abuse discovery.

## Why LogicHunter?

Bug bounty hunters regularly test JSON-RPC APIs for broken access control: log in as admin, capture requests, log in as low-privilege user, capture requests, then compare. LogicHunter automates the tedious analysis part:

- **Passively captures** all JSON-RPC traffic (zero interference with your workflow).
- **Differentiates admin vs. low-priv sessions** to surface access-control gaps.
- **Generates ready-to-use exploit payloads** with your *actual* captured session tokens, cookies, and entity IDs — no manual placeholder substitution.
- **One-click copy** of cURL commands, raw HTTP requests, and auth headers directly to clipboard.

## Safety Model

LogicHunter is intentionally passive and analyst-driven:

- Capture and analysis only.
- No automatic traffic replay.
- No auto-fuzzing, brute force, or request flooding.
- No calls to external services.
- Manual export bundles for Repeater-driven verification.

## MyGeotab Scope (Hard Filter)

This build is tuned for the MyGeotab Bugcrowd program and only processes traffic for:

- bugcrowd5.geotab.com
- bugcrowd6.geotab.com
- bugcrowd7.geotab.com
- bugcrowd8.geotab.com
- bugcrowd9.geotab.com
- bugcrowd10.geotab.com
- bugcrowd11.geotab.com

Traffic outside this host set is ignored by capture, replay, and suggestion generation.

Focused signal categories:

- Cross-tenant / cross-database access
- BOLA / IDOR object replay
- Privilege escalation
- Unauthorized state changes
- Method-level authorization bypass

Suppressed families:

- JSONP, CORS
- Add-ins, messages, audit-log only issues
- UI-only findings
- Password complexity checks
- DoS/rate-limit checks

## Quick Start

1. Build and load the extension (see [Build and Test](#build-and-test)).
2. **Browse as Admin**: Navigate the target app normally. LogicHunter captures all JSON-RPC traffic.
3. **Mark Admin session**: In the **Dashboard** tab, select a method and click **★ Mark ADMIN**.
4. **Browse as Low-Priv user**: Log out, log in as a low-privilege user, repeat browsing.
5. **Mark Low-Priv session**: Select a method from the new session and click **☆ Mark LOW_PRIV**.
6. Switch to the **Attack Planner** tab — findings are auto-generated with your real session data.
7. Click **📋 Copy cURL** or **📋 Copy Payload** to get ready-to-paste exploit commands.

## JSON-RPC Detection

A request is processed when all conditions are met:

1. HTTP method is POST.
2. Body parses as JSON.
3. Top-level JSON object contains a non-empty method field.

Malformed JSON is logged safely to the error stream and never crashes the extension.

## Data Retention

Raw and normalized JSONL logs are stored in this priority order:

1. D:\tools\jsonrpc-logs
2. %USERPROFILE%\jsonrpc-logs (fallback)
3. %TEMP%\jsonrpc-logs (emergency fallback)

Files:

- jsonrpc-raw.jsonl
- jsonrpc-normalized.jsonl
- jsonrpc-errors.jsonl

On startup, raw records are replayed to rebuild in-memory analytics.

## Burp Tabs

LogicHunter adds two focused tabs:

- **LogicHunter - Dashboard**
- **LogicHunter - Attack Planner**

### LogicHunter - Dashboard

Consolidated view merging Methods, Entities, and Auth Sessions:

- **Traffic sub-tab**: Method-centric traffic inventory with search + filters. Variant signatures, key summaries, and sample request/response inspection.
- **Entities sub-tab**: Per-method entity view showing extracted IDs, tokens, tenant references. Tracks cross-method and cross-context reuse with risk scoring.
- **Sessions sub-tab**: All detected auth sessions with captured Authorization headers, Cookie values, and last-seen URLs. Displays role assignments at a glance.

Controls:
- **★ Mark ADMIN / ☆ Mark LOW_PRIV / Clear Role**: Assign privilege levels to sessions.
- **Export All**: Full JSON export of all captured data.
- **Clear / Reset**: Wipe in-memory data and truncate JSONL files.

### LogicHunter - Attack Planner

Consolidated view merging Findings, Attack Suggestions, and Workflow Chains:

- **Payload sub-tab**: Copy-paste-ready exploit payloads with your actual captured session tokens. Includes:
  - Full HTTP request context (URL, headers, body)
  - cURL commands for both ADMIN and LOW_PRIV sessions
  - One-click copy buttons for payloads, cURL, raw HTTP, and auth headers
- **Evidence sub-tab**: Detailed finding analysis with admin vs. low-priv response comparison, observation details, and impact assessment.
- **Chains sub-tab**: Workflow chains showing method-to-method value flows relevant to the selected finding.

Finding categories:
- Auth differentials (admin receives data, low-priv receives nothing)
- Auth bypass correlations (role-based response discrepancies)
- Multicall mixed-privilege and cross-tenant abuse
- Entity-centric IDOR/BOLA targeting maps
- Chained workflow attack paths
- Response anomaly security signals

Every finding includes:
- Exact exploit payload with real session data
- cURL command (ready to paste into terminal)
- Expected secure outcome
- Vulnerable outcome signature
- Impact statement and confidence level

## Payload Context

LogicHunter payloads are context-aware. Instead of generic placeholders like `<foreign_entity_id>`, payloads include:

- **Real Authorization headers** captured from your browsing sessions
- **Real Cookie values** from your browser
- **Real entity IDs** extracted from traffic (preferring cross-context reusable values)
- **Real target URLs** observed in captured requests

Example payload output:
```
=== TARGET ===
POST https://target.com/jsonrpc

=== HEADERS (LOW_PRIV session — use these to test) ===
Content-Type: application/json
Cookie: session_id=abc123def456
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...

=== BODY ===
{
  "jsonrpc": "2.0",
  "method": "GetUserProfile",
  "params": { "userId": "admin-user-uuid-here" },
  "id": "lh-manual-test"
}

=== cURL (LOW_PRIV — test this) ===
curl -X POST 'https://target.com/jsonrpc' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: session_id=abc123def456' \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIs...' \
  -d '{"jsonrpc":"2.0","method":"GetUserProfile","params":{"userId":"admin-user-uuid-here"},"id":"lh-manual-test"}'
```

## Export Format

Exports include full request context for every finding:

- Auth contexts with raw headers (Authorization, Cookie, last URL)
- cURL commands and raw HTTP requests per suggestion
- Full request/response data for both vulnerable and safe findings
- Formatted findings for bug bounty report templates

## Build and Test

Requirements:

- JDK 21+

Commands:

```bash
./gradlew build
./gradlew jar
```

Windows:

```powershell
gradlew.bat build
gradlew.bat jar
```

Jar output:

- build/libs/logic-hunter.jar

## Load into Burp

1. Open Burp Extensions > Installed.
2. Click Add.
3. Select build/libs/logic-hunter.jar.
4. Verify both LogicHunter tabs load (Dashboard + Attack Planner).

## Test Fixtures

Fixture files used by parser tests:

- src/test/resources/fixtures/jsonrpc-request-basic.json
- src/test/resources/fixtures/jsonrpc-response-basic.json
