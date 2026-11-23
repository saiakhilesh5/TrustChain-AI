# TrustChain-AI — Software Supply Chain Guardian

**Know What You Build. Trust What You Ship.**

An agentic AI system that continuously analyzes a software supply chain to identify
dependency risks, vulnerabilities, and suspicious changes before they impact applications.

Built for the Bosch Global Software Technologies (BGSW) hackathon, November 2026.

---

## What it does

TrustChain-AI implements the full **Discover → Detect → Analyze → Remediate → Validate**
workflow:

1. **Discover** — parse package manifests and lockfiles, identify direct and transitive
   dependencies, component names, versions and origins.
2. **Build the supply chain view** — generate a CycloneDX SBOM, build the dependency
   graph, inspect container images and CI/CD workflows.
3. **Detect vulnerabilities** — correlate components with known CVEs, capture severity
   and fixes, and trace vulnerable transitive dependencies back to their root.
4. **Detect suspicious changes** — typosquats, unexpected dependency changes, unpinned
   CI actions, `:latest` container tags, unsafe install scripts.
5. **Present evidence** — every finding carries its component, dependency path,
   supporting evidence, and initial risk level — with a strict separation between
   **verified evidence** (tool-derived) and **AI inference** (agent reasoning).

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Agent Layer (Claude)                     │
│                                                              │
│  Orchestrator ── plans, routes, aggregates, enforces gates   │
│    ├── Discovery Agent        (components + origins)         │
│    ├── Graph Agent            (dependency paths)             │
│    ├── Vulnerability Analyst  (CVE correlation)              │
│    ├── Anomaly Investigator   (supply-chain anomalies)       │
│    └── Day 2: Prioritizer / Remediation / Validation         │
└───────────────────────────┬─────────────────────────────────┘
                            │ tool calls
┌───────────────────────────▼─────────────────────────────────┐
│                    Tool Layer (deterministic)                 │
│  manifest parsers · SBOM (CycloneDX) · CVE scanners (OSV)   │
│  git diff/log mining · graph builder · build/test runner     │
└───────────────────────────┬─────────────────────────────────┘
                            │ findings + evidence refs
┌───────────────────────────▼─────────────────────────────────┐
│              Evidence Store (append-only ledger)              │
│  every finding → file paths, line numbers, scan output,      │
│  commit SHAs; verified vs. inferred clearly separated        │
└───────────────────────────┬─────────────────────────────────┘
                            ▼
              Guardian Report (HTML + JSON)
              + Human Approval Gate (Day 2)
```

**Design principle:** deterministic tools produce facts; agents only reason and explain.
Every claim must carry a pointer to verifiable evidence. Agents cannot merge, deploy,
or release anything — remediation requires human approval by construction.

## Repository strategy

| Repo | Role | Why |
|------|------|-----|
| [strapi/strapi](https://github.com/strapi/strapi) | **Validation** | Huge npm dependency tree; its dependabot / CVE-fix commit history is ground truth — we rewind to pre-fix commits and measure whether the Guardian detects the issue (precision/recall). |
| [ROBOTIS-GIT/turtlebot3](https://github.com/ROBOTIS-GIT/turtlebot3) | **Prediction** | A completely different ecosystem (ROS `package.xml` manifests). Running the *same* agent, unchanged, on it demonstrates generality; findings are novel and framed as pending human review. |

## Setup

Requirements: Python 3.10+, git, Node.js (only if scanning npm-based samples).

```bash
git clone https://github.com/saiakhilesh5/TrustChain-AI.git
cd TrustChain-AI

python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
# source .venv/bin/activate

pip install -r requirements.txt

# Fetch the sample repositories (clones into samples/, gitignored)
python scripts/fetch_samples.py
```

### Configuration

Agents use the Anthropic API. Set your key:

```bash
# Windows (PowerShell)
$env:ANTHROPIC_API_KEY = "sk-ant-..."

# Linux/macOS
export ANTHROPIC_API_KEY="sk-ant-..."
```

The key is read from the environment only — never stored, never committed.

## Usage

```bash
# Scan a repository's software supply chain (Day 1 pipeline)
python -m trustchain scan --target samples/strapi --output outputs/strapi

# Generate the dependency graph visualization
python -m trustchain graph --target samples/strapi --output outputs/strapi

# Produce the Guardian report (HTML + JSON)
python -m trustchain report --run outputs/strapi
```

## Project layout

```
TrustChain-AI/
├── trustchain/
│   ├── discovery/   # manifest + lockfile parsers, component inventory
│   ├── graph/       # dependency graph building + visualization
│   ├── scan/        # CVE correlation (OSV), path tracing
│   ├── anomaly/     # typosquats, CI pinning, image tags, diff anomalies
│   ├── agents/      # Claude orchestrator + subagents
│   ├── evidence/    # append-only evidence ledger
│   └── report/      # HTML + JSON Guardian report
├── scripts/         # sample fetch, validation harness
├── samples/         # cloned sample repos (gitignored)
├── outputs/         # scan results, reports (gitignored)
└── tests/
```

## Responsible AI & security

- Deterministic tools (not the LLM) produce component lists, CVE matches and diffs.
- Findings separate `verified` evidence from `inferred` reasoning, with confidence.
- No auto-merge, deploy or release: remediation proposals require human approval.
- All scanning is local, against cloned public repositories, inside this sandbox.
- Secrets are read from the environment only and never committed.

## Milestones

- [x] M0 — Project scaffold, architecture, setup docs
- [x] M1 — Manifest parsers + component inventory
- [ ] M2 — CycloneDX SBOM + dependency graph
- [x] M3 — CVE scan + transitive path tracing
- [x] M4 — Anomaly detection (CI, images, diffs, typosquats)
- [x] M5 — Claude agent layer + evidence store + Guardian report
- [ ] M6 — Validation harness (Strapi history) + prediction run (TurtleBot3)
- [ ] Day 2 — Prioritizer, remediation, validation agents
