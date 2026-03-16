# CyberSentry Full Build Plan

## 1) Product Goal
Build CyberSentry into a production-ready autonomous security remediation platform that:
- Detects vulnerabilities across codebases
- Scans authorized website URLs for web-layer security risks
- Reasons about root causes and blast radius
- Runs multi-agent remediation debate
- Generates safe patch candidates
- Requires human approval before apply
- Exposes fully transparent thought traces and audit artifacts

## 2) Scope Definition
In scope:
- CLI-first core engine
- Web UI as a first-class product surface (not optional)
- Scanner orchestration and finding normalization
- Authorized URL scanning mode (DAST-lite)
- Triage, clustering, prioritization, confidence scoring
- Multi-agent debate and judge ranking
- Patch diff generation and approval gate
- Reporting (JSON/Markdown/SARIF)
- Realtime thought trace API + web console
- CI/CD integration and policy controls

Out of scope for initial production:
- Autonomous patch apply without approval
- Self-hosted model training
- Binary and mobile reverse engineering
- Unauthorized scanning of third-party websites (must require explicit ownership/permission acknowledgement)

## 3) Target Architecture
Layers:
1. Interface layer
- CLI (primary)
- Web console (primary for business users)
- CI plugin hooks

2. Orchestration layer
- ReAct loop engine
- Task planner and replanner
- Run state manager

3. Analysis layer
- Semgrep adapter
- Bandit adapter
- Dependency audit adapter
- Custom AST rules engine
- Web scanner pipeline (HTTP checks, header checks, crawler, optional authenticated checks)

4. Reasoning layer
- Debate orchestrator (Red, Blue, Auditor)
- Judge scorer and ranker
- Prompt templates + guardrails

5. Remediation layer
- Patch strategy generator
- Diff renderer
- Approval workflow

6. Observability layer
- Event stream and thought trace timeline
- Structured run artifacts
- Metrics and error telemetry

7. Policy and safety layer
- Prompt injection filter
- Path traversal and command restrictions
- Secret redaction and policy checks
- Safe web scanning guardrails (target allowlist, rate limits, robots awareness, explicit legal acknowledgement)

## 4) Repository and Code Layout
Recommended structure:

```text
cyber_sentry/
  src/
    cyber_sentry_cli/
      __init__.py
      main.py
      commands/
        init.py
        doctor.py
        scan.py
        triage.py
        debate.py
        patch.py
        report.py
        trace.py
      core/
        orchestrator.py
        run_state.py
        models.py
        events.py
      scanners/
        base.py
        semgrep.py
        bandit.py
        deps.py
        ast_rules.py
      reasoning/
        debate_engine.py
        judge.py
        prompts.py
      remediation/
        generator.py
        diff.py
        approval.py
      policy/
        guardrails.py
        risk_policy.py
      storage/
        artifacts.py
        repository.py
      output/
        terminal.py
        json_export.py
        sarif_export.py
      integrations/
        openrouter.py
        github_actions.py
      api/
        app.py
        ws.py
  tests/
    unit/
    integration/
    e2e/
  docs/
    architecture.md
    threat-model.md
    operations.md
  .cybersentry/
    policies/
```

## 5) Delivery Roadmap (16 Weeks)

### Phase 0 (Week 1): Foundation
Objectives:
- Initialize project standards and development workflow
- Establish baseline package, typing, linting, and test tooling

Deliverables:
- Python project scaffold and dependency management
- CLI entrypoint and command groups
- Basic logging and config loader
- UI scaffold (React/Next.js) with shared design tokens and auth-ready shell

Definition of done:
- `cs --help` works
- CI checks pass for lint, type-check, and unit smoke tests

### Phase 1 (Weeks 2-4): Scan and Triage Core
Objectives:
- Implement scanner adapters and normalized finding model
- Build triage and clustering pipeline

Deliverables:
- `cs scan <target>` with Semgrep and Bandit
- Canonical finding schema and severity mapping
- `cs triage <run-id>` with dedupe, cluster, prioritize
- `cs webscan <url>` skeleton command with URL validation and run artifact model

Definition of done:
- Supports medium-size repos locally
- Produces deterministic JSON artifacts per run
- Shows top risks in terminal summary

### Phase 2 (Weeks 5-7): Debate and Judging
Objectives:
- Build multi-agent debate engine and score outputs
- Add confidence and rationale generation

Deliverables:
- `cs debate <finding-id>` command
- Red/Blue/Auditor proposal generation
- Judge scoring rubric and ranked outputs
- UI findings detail page with debate timeline and scorecards

Definition of done:
- 3-round debate flow works in local deterministic mode
- Optional LLM mode via OpenRouter feature flag
- Debate transcript stored and replayable

### Phase 3 (Weeks 8-9): Patch and Approval Flow
Objectives:
- Generate patch candidates and enforce safety gates

Deliverables:
- `cs patch <finding-id> --dry-run`
- Diff generation with file-level impact summary
- Approval gate with explicit confirmation workflow
- UI approval center for patch review and decision logging

Definition of done:
- No apply by default
- All patch proposals include rationale, risks, and rollback note

### Phase 4 (Weeks 10-11): Reports and Trace UX
Objectives:
- Improve explainability and reporting quality

Deliverables:
- `cs report <run-id> --format json|md|sarif`
- `cs trace <run-id>` timeline replay in terminal
- Metrics summary (counts, MTTR estimate, risk distribution)
- Web dashboard with live run status, severity trends, and export actions

Definition of done:
- Reports are CI-consumable
- Trace data is complete and human-readable

### Phase 5 (Weeks 12-13): API and Realtime Console
Objectives:
- Add FastAPI and WebSocket event streaming for live observability

Deliverables:
- `/runs`, `/findings`, `/debates`, `/patches` APIs
- WebSocket event stream for thought trace
- Production UI dashboard (operations + executive views)
- `/webscan` API for URL-targeted scans

Definition of done:
- CLI and UI reflect same event stream and run artifacts
- Realtime updates during active run

### Phase 6 (Weeks 14-15): CI Integrations and Hardening
Objectives:
- Integrate with common development workflows and secure boundaries

Deliverables:
- GitHub Actions integration mode
- Policy enforcement options (block on critical)
- Guardrails for injection, secrets, and path traversal
- Web scanning safeguards: max depth, request budget, timeout, rate limiting, allowlist policies

Definition of done:
- CI pipeline usage documented with examples
- Security tests pass for key threat scenarios

### Phase 7 (Week 16): Launch Readiness
Objectives:
- Stabilize, benchmark, and package for release

Deliverables:
- Release candidate package
- Migration docs and runbooks
- Demo script and benchmark report
- Hosted deployment blueprint (SaaS) + self-hosted reference deployment

Definition of done:
- Stable on reference repos
- Known issues documented
- Launch checklist completed

## 6) Functional Requirements
Core requirements:
- Deterministic run IDs and artifact storage
- Unified finding schema across scanners
- Unified finding schema for code scan + web URL scan outputs
- Critical/high escalation rules into debate
- Judge ranking with clear scoring dimensions
- Human approval as mandatory for apply action
- Exportable reports for engineering and compliance
- UI workflows for scan launch, finding triage, debate review, and report export

Performance requirements:
- Scan feedback under 2 minutes for small repos (<50k LOC)
- Debate completion under 30 seconds in local mode
- WebSocket update latency below 500 ms average on local network
- URL scan first-pass summary under 90 seconds for small sites (<200 pages)

Reliability requirements:
- Retries on scanner subprocess failures
- Partial-failure tolerance with clear degraded-mode reporting
- Idempotent reruns with preserved previous artifacts
- Graceful degradation when website blocks crawling or WAF limits requests

## 7) Non-Functional Requirements
Security:
- Tool output sanitization before model prompts
- Secret detection and redaction in logs and traces
- Command execution sandbox policy
- Web scan legal/safety controls: only authorized targets, signed acknowledgement, optional target verification token

Compliance readiness:
- Immutable run history metadata
- Audit-friendly event chronology
- Mapping tags for OWASP/CWE categories

Maintainability:
- Strong type hints and dataclass/pydantic models
- Clear plugin interfaces for scanners and LLM providers
- Versioned config and artifact schema

## 8) Data Model Plan
Primary entities:
- Run
- Finding
- Cluster
- WebTarget
- HttpRequestSample
- WebEvidence
- DebateSession
- Proposal
- JudgeScore
- PatchCandidate
- ApprovalDecision
- Event

Versioning:
- `schema_version` included in every artifact
- Migration utility for backward compatibility

## 9) Scoring and Prioritization Design
Risk score formula (initial):

$$Risk = SeverityWeight \times Confidence \times ExposureFactor \times Reachability$$

Example starting weights:
- Critical: 1.00
- High: 0.75
- Medium: 0.45
- Low: 0.20

Judge rubric dimensions:
- Security effectiveness
- Implementation safety
- Maintainability impact
- Compliance alignment
- Effort estimate

## 10) Testing Strategy
Test layers:
1. Unit tests
- Parser, scoring, clustering, prompt building, guardrails

2. Integration tests
- Scanner subprocess adapters
- Orchestrator flows and artifact writer

3. End-to-end tests
- Golden repos with known vulnerabilities
- Full `scan -> triage -> debate -> patch -> report` flow
- Full `webscan -> triage -> report` flow against local intentionally vulnerable test app

4. Security tests
- Prompt injection payloads
- Path traversal payloads
- Secret leakage checks
- Web safety checks (rate-limit handling, robots policy behavior, allowlist enforcement)

Quality gates:
- Minimum 80% coverage for core modules
- No critical lint/type errors
- Must pass golden-scenario snapshots

## 11) DevOps and Release Plan
Build and release:
- Semantic versioning for CLI
- Automated release notes from tagged commits
- Package publish pipeline

Environment strategy:
- Local developer mode
- Staging with integration tests
- Production with monitored telemetry
- Production deployment modes:
- Managed SaaS deployment (default)
- Self-hosted deployment (regulated environments)

Observability:
- Structured logs
- Error categories and retry counters
- Run duration and command success metrics

## 12) Team Plan and Ownership
Suggested roles:
- Tech lead: architecture and orchestrator
- Security engineer: policies, scanners, threat model
- ML engineer: debate prompts and scoring strategy
- Full-stack engineer: API and web console
- QA engineer: test harness and golden suites

Operating cadence:
- Weekly milestone demo
- Daily async update (risk, progress, blockers)
- Bi-weekly architecture review

## 13) Risk Register and Mitigation
Risk: scanner output inconsistency
- Mitigation: strict adapter contracts and contract tests

Risk: LLM non-determinism
- Mitigation: deterministic fallback mode and scoring normalization

Risk: unsafe patch recommendations
- Mitigation: policy checks plus mandatory human approval

Risk: demo instability
- Mitigation: offline debate mode and fixture repositories

Risk: scope creep
- Mitigation: freeze MVP scope by end of Phase 1

## 14) Demo and GTM Readiness Plan
Demo package:
- One vulnerable sample repo
- One enterprise-like medium repo
- Predefined command script for 5-minute and 10-minute demos

Go-to-market readiness artifacts:
- One-page value proposition
- Competitive comparison matrix
- Security and compliance explainer

## 15) Immediate Next 10 Tasks (Execution Order)
1. Set up Python project metadata and CLI entrypoint
2. Implement config loader and run artifact directories
3. Implement finding schema and severity normalization
4. Add Semgrep adapter and JSON parser
5. Add Bandit adapter and JSON parser
6. Build scan orchestrator command
7. Build triage clustering and prioritization command
8. Implement local deterministic debate engine
9. Add judge scoring and ranked output
10. Implement patch diff generation and approval gate

## 16) Exit Criteria for "Full Build Complete"
CyberSentry is considered fully built for v1 when:
- CLI supports end-to-end remediation flow
- Debate and judge produce ranked explainable outputs
- Patch is generated safely with approval gate
- Reports are exportable in engineering and compliance formats
- API/WebSocket trace is usable in a lightweight dashboard
- CI integration can run and enforce policy thresholds
- Documentation and runbooks are complete for onboarding
