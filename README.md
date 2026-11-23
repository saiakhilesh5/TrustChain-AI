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
│                    Agent Layer (Gemini)                       │
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
| [strapi/strapi](https://github.com/strapi/strapi) | **Validation + demo target** | Huge npm dependency tree (3000+ components); its dependabot / CVE-fix commit history is ground truth — we rewind to pre-fix commits and measure whether the Guardian detects the issue (precision/recall). |

## How validation works

The harness mines dependabot `bump X from A to B` commits from Strapi's history:

1. **Ground truth** — OSV is asked whether version A is affected and version B is fixed. If advisories disappear across the bump, the commit is a confirmed security fix.
2. **Rewind** — a git worktree is checked out at the commit's parent (the pre-fix snapshot).
3. **Run the Guardian** on that snapshot.
4. **Score** — did it flag the known-vulnerable component and advisory? Did the dependency-diff detector catch the version change?

Results are written to `outputs/<name>/validation_report.json` with per-commit cases and
aggregate recall. This answers the inevitable judge question — *"how do you know the agent
isn't making things up?"* — with a measurable, reproducible number.

**Validation results (12 dependabot commits, 6 confirmed security fixes):**

| Capability | Result |
|------------|--------|
| Vulnerability detection on pre-fix snapshots | 6/6 detected — recall **1.00** |
| Dependency version-change detection | 11/12 detected — recall **0.917** |

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

Agents use the **Gemini API** with multi-key rotation. Copy the template and paste your keys:

```bash
cp .env.example .env
# then edit .env:
#   GEMINI_API_KEY_1=AIza...
#   GEMINI_API_KEY_2=AIza...
#   ... up to 6 keys
```

When one key hits its rate limit (HTTP 429), the client automatically rotates to the next
key and retries. The model can be overridden with `TRUSTCHAIN_MODEL` (default
`gemini-3.8-flash`).

`.env` is gitignored — keys are never stored in git, and a run without keys still works
via `--no-ai` (tools-only report).

## Usage

```bash
# Scan a repository's software supply chain (Day 1 pipeline):
# manifests -> inventory -> CycloneDX SBOM -> OSV CVEs -> anomalies
python -m trustchain scan --target samples/strapi --output outputs/strapi

# Generate the interactive dependency graph (vulnerable components highlighted)
python -m trustchain graph --target samples/strapi --output outputs/strapi

# Produce the Guardian report (HTML + JSON) with Gemini agent analysis
# (fill .env with Gemini keys, or pass --no-ai for a tools-only report)
python -m trustchain report --run outputs/strapi

# Retrospective validation: mine dependency-bump commits, rewind to
# pre-fix snapshots, and score the Guardian against known fixes
python -m trustchain validate --target samples/strapi --output outputs/strapi-validation
```

### Web UI

Paste any GitHub repository URL and watch the Day 1 checklist fill in, browse findings,
and explore the interactive dependency graph — all in the browser:

```bash
python -m trustchain serve        # opens http://127.0.0.1:5000
```

### Deploy (Render)

The repo ships a [render.yaml](render.yaml) blueprint (free tier, waitress server,
`/api/health` health check):

1. Render dashboard → **New +** → **Blueprint** → select this repository.
2. When prompted, fill in the secret values for `GEMINI_API_KEY_1` … `GEMINI_API_KEY_6`.
3. **Apply** — the service builds with `pip install -r requirements.txt` and starts
   `waitress-serve --call --port=$PORT trustchain.web.app:create_app`.

Note: free-tier instances sleep after ~15 min idle and their disk is ephemeral — scan
results live for the lifetime of the instance. The UI polls every 2s during a scan,
which keeps the instance awake while a pipeline is running.

## Project layout

```
TrustChain-AI/
├── trustchain/
│   ├── discovery/   # manifest + lockfile parsers, component inventory
│   ├── graph/       # dependency graph building + visualization
│   ├── scan/        # CVE correlation (OSV), path tracing
│   ├── anomaly/     # typosquats, CI pinning, image tags, diff anomalies
│   ├── agents/      # Gemini agents (multi-key rotation) + orchestrator
│   ├── evidence/    # append-only evidence ledger
│   ├── web/         # Flask API + single-page web UI
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
- [x] M2 — CycloneDX SBOM + dependency graph
- [x] M3 — CVE scan + transitive path tracing
- [x] M4 — Anomaly detection (CI, images, diffs, typosquats)
- [x] M5 — Gemini agent layer + evidence store + Guardian report
- [x] M6 — Validation harness (Strapi history)
- [x] M7 — Gemini multi-key rotation + .env configuration
- [x] M8 — Web UI: scan by URL, Day 1 checklist, findings, graph
- [ ] Day 2 — Prioritizer, remediation, validation agents
