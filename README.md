# Method Miner

Method Miner is a passive :contentReference[oaicite:0]{index=0} extension built with the Montoya API for analyzing API traffic and generating actionable intelligence for business logic and access control testing.

It automatically discovers and correlates:

- JSON-RPC APIs
- GraphQL APIs
- Authentication sessions
- Role differences (ADMIN vs LOW_PRIV)
- Privilege boundaries
- High-risk operations
- Repeater-ready payload templates

Method Miner is designed to accelerate manual bug hunting for vulnerabilities such as IDOR/BOLA, broken access control, privilege escalation, cross-tenant access, and workflow abuse.

---

## 🚧 Project Status

> Method Miner is actively under development.

The core architecture and passive analysis pipeline are stable, and the extension is fully usable for real-world API reconnaissance. However, several intelligence features are still being refined.

### Stable Components

- Passive JSON-RPC and GraphQL traffic capture
- Session discovery and role labeling
- Schema extraction and evidence correlation
- Role comparison (ADMIN vs LOW_PRIV)
- Risk signal generation
- Payload assembly
- Export system (Markdown, JSON, JSONL, CSV)
- Project lifecycle management
- Unified Burp UI

### Areas Under Active Improvement

- Risk scoring and prioritization logic
- Attack suggestion quality
- Payload generation accuracy
- Cross-operation correlation
- Business logic chain detection
- Heuristic tuning to reduce false positives

### Current Recommendation

Method Miner should be used as a **security research assistant** rather than a fully automated vulnerability finder.

It excels at:

- Organizing large API surfaces
- Highlighting privilege differences
- Generating testing hypotheses
- Preparing Repeater-ready payloads

Final vulnerability validation and exploitation remain manual and analyst-driven.

### Contributions Welcome

Feedback, bug reports, and pull requests are highly encouraged. Contributions are especially welcome in:

- Improved detection heuristics
- Better risk prioritization
- Additional protocol support (REST, gRPC-Web)
- UI refinements
- Test coverage expansion
- Documentation

---

## 🎯 Purpose

Modern APIs often expose hundreds of operations across multiple protocols. Manually identifying privilege differences and attack paths is time-consuming.

A typical manual workflow requires:

1. Logging in as a low-privileged user
2. Capturing application behavior
3. Logging in as an administrator
4. Repeating the same workflow
5. Comparing requests manually
6. Building payloads in Repeater

Method Miner automates the analysis layer by transforming captured traffic into structured intelligence.

---

## ⚙️ Core Capabilities

### Protocol Detection

- Passive JSON-RPC detection and schema extraction
- Passive GraphQL detection and operation parsing
- Protocol-agnostic ingestion pipeline

### Session Intelligence

- Automatic session fingerprinting
- Cookie and authentication metadata extraction
- Role labeling (ADMIN, LOW_PRIV, UNKNOWN)
- Cross-session comparison

### Role Comparison

- Detect operations observed only under privileged roles
- Parameter-level coverage analysis
- Highlight likely access control gaps

### Risk Signals

Generate prioritized testing hypotheses for:

- IDOR / BOLA
- Privilege escalation
- Cross-tenant access
- Workflow abuse
- Batch chaining via `ExecuteMultiCall`
- Sensitive data exposure

### Payload Assembly

Create copy-ready templates for:

- JSON request bodies
- Raw HTTP requests
- cURL commands
- Multi-step reproduction workflows

### Intelligence Export

Export findings in:

- Markdown
- JSON
- JSONL
- CSV

---

## 🔐 Typical Workflow

1. Launch Burp Suite
2. Load Method Miner
3. Authenticate as LOW_PRIV
4. Browse the target application
5. Mark the discovered session as LOW_PRIV
6. Authenticate as ADMIN
7. Browse the same application areas
8. Mark the discovered session as ADMIN
9. Review:
   - Risk Signals
   - Payloads
   - Comparison
   - Sessions
10. Export actionable intelligence

---

## 🧠 What It Helps Identify

- IDOR / BOLA
- Broken Access Control
- Privilege Escalation
- Cross-Tenant Data Access
- Workflow Chaining Vulnerabilities
- ExecuteMultiCall Abuse
- Hidden Administrative Operations
- Sensitive GraphQL Queries and Mutations

---

## 🛡️ Safety Model

Method Miner is strictly passive.

### It Does

- Observe Burp traffic
- Build schemas and relationships
- Compare roles
- Generate testing payloads
- Export structured intelligence

### It Does Not

- Send active requests
- Fuzz parameters
- Brute force operations
- Modify traffic
- Exploit vulnerabilities automatically

All exploitation remains under analyst control using Burp Repeater.

---

## 🏗️ Architecture Overview

```text
Burp Traffic
    ↓
BurpTrafficBridge
    ↓
TrafficIngestor
    ↓
CompositeProtocolDetector
    ↓
Protocol Analyzers (JSON-RPC / GraphQL)
    ↓
Surface Repository
    ↓
Session Extraction
    ↓
Role Comparison
    ↓
Risk Signal Generation
    ↓
Payload Assembly
    ↓
Export Engine
