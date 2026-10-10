<div align="center">

```
  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
```

# 🛡️ SENTINEL Sovereign Core v3.0
### *The Sovereign, Evidence-Driven Security & Privacy Verification Runtime*

[![Release Tests](https://img.shields.io/badge/Acceptance%20Suite-79%2F79%20Passing-10b981?style=for-the-badge&logo=checkmarx&logoColor=white)]()
[![Privacy Shield](https://img.shields.io/badge/Privacy%20Shield-8%2F8%20Passing-3b82f6?style=for-the-badge&logo=pytest&logoColor=white)]()
[![Attestation](https://img.shields.io/badge/Attestation-Ed25519%20%2B%20HMAC--SHA256-8b5cf6?style=for-the-badge&logo=gnupg&logoColor=white)]()
[![Zero-NAND RAM](https://img.shields.io/badge/Storage-Zero--NAND%20%2Fdev%2Fshm-f59e0b?style=for-the-badge&logo=linux&logoColor=white)]()
[![License](https://img.shields.io/badge/License-Apache%202.0-64748b?style=for-the-badge&logo=apache&logoColor=white)]()

<p align="center">
  <b>SENTINEL</b> is an enterprise-grade, fail-closed security and privacy runtime designed for mission-critical enterprise environments and sovereign AI pipelines.<br/>
  It eliminates silent scanner omissions by compiling security evaluations into deterministic <b>Security Intermediate Representations (SIR)</b>, generating <b>Counterfactual Remediation Plans</b>, and signing outputs with <b>Ed25519 cryptographic attestations</b>.
</p>

---

[📖 Executive Summary](#-executive-summary) •
[🏛️ System Architecture](#-system-architecture--subsystem-deep-dive) •
[🔒 The 8 Sovereign Invariants](#-the-8-sovereign-invariants) •
[🎛️ The 5 Core Modules](#-the-5-core-product-modules) •
[🧩 Browser Extension Bridge](#-ai-guardian-manifest-v3-browser-extension) •
[🚀 Quickstart](#-quickstart--installation) •
[🛠️ Supervisor CLI](#-master-supervisor-orchestrator-mainpy) •
[📡 Complete API Reference](#-complete-rest--two-phase-sse-api-reference) •
[🧪 Verification Gates](#-formal-verification-gates--calibration-lab) •
[🛡️ Threat Model](#-threat-model--security-perimeter)

---

</div>

## 📖 Executive Summary

### The Fundamental Flaw in Traditional Security Scanners
Most existing security tools and compliance pipelines operate on a **fail-open** assumption:
$$\text{Verdict} = \begin{cases} \text{BLOCK}, & \text{if } \text{KnownThreatFound}(D) \\ \text{ALLOW}, & \text{otherwise} \end{cases}$$

When an underlying analyzer runs out of memory, encounters an unsupported container format, suffers a network timeout, or simply isn't installed, the exception is caught, discarded, and the system reports **"0 Threats Detected"**. This silent omission is a catastrophic attack vector in modern enterprise software supply chains and generative AI ingestion pipelines.

### The SENTINEL Sovereign Guarantee
SENTINEL redesigns security evaluation around **Epistemic Honesty** and **Formal Coverage Fusion**:
$$\text{Verdict} = \begin{cases} \text{BLOCK}, & \text{if } \exists f \in \text{Findings} \text{ s.t. } \text{Severity}(f) \ge \text{CRITICAL} \\ \text{REVIEW\_REQUIRED}, & \text{if } \exists a \in \text{Analyzers} \text{ s.t. } \text{State}(a) \in \{\text{FAILED}, \text{UNAVAILABLE}\} \\ \text{ALLOW}, & \text{if } \forall a \in \text{ApplicableAnalyzers}, \text{State}(a) = \text{COMPLETED} \land \text{Findings} = \emptyset \end{cases}$$

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ ❌ TRADITIONAL SCANNERS (Silent Omission / False Clean)                                │
│ Container Bomb / Missing Plugin ──► Uncaught Error Swallowed ──► "Clean Scan" (0 Flaws)│
└────────────────────────────────────────────────────────────────────────────────────────┘
                                            VS
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ ✅ SENTINEL SOVEREIGN CORE (Fail-Closed Multi-Scanner Fusion)                          │
│ Container Bomb / Missing Plugin ──► Explicit Coverage Gap ──► Verdict: REVIEW_REQUIRED │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔒 The 8 Sovereign Invariants

Every subsystem and analyzer in SENTINEL strictly adheres to 8 mathematically verifiable invariants:

| # | Invariant | Formal Definition & Guarantee |
|---|---|---|
| **1** | **Fail-Closed Verdict Fusion** | An evaluation is **never** granted an `ALLOW` verdict if any applicable analyzer failed, was killed due to limits, or was unconfigured. |
| **2** | **Epistemic Status Differentiation** | Analyzers must explicitly return one of five typed states: `completed`, `finding`, `failed`, `unavailable`, or `not_applicable`. |
| **3** | **Zero-NAND Ephemeral RAM Vault** | Untrusted payload bytes live strictly in volatile memory (`/dev/shm` tmpfs on Linux, isolated memory buffers cross-platform). Paths are sandboxed and unlinked immediately post-scan. |
| **4** | **Differential Perception Engine** | Isolates divergence between human visual rendering and LLM token stream extraction: $\Delta_{\text{Perception}} = \text{Extract}_{\text{Tokenizer}}(D) \setminus \text{Render}_{\text{Visual}}(D)$. Traps micro-fonts, opacity-0 text, and invisible prompt injections. |
| **5** | **Transactional Twin Redaction** | Redactions execute on isolated memory twins. The derivative file is parsed from scratch and verified for **0.00% sensitive residue** before issuing a single-use download token. |
| **6** | **Cryptographic Attestation** | Assessment reports are compiled to SARIF v2.1 and signed using an asymmetric Ed25519 keypair and local machine-root HMAC-SHA256 for non-repudiation and tamper detection. |
| **7** | **Deterministic SIR & Evidence DAG** | Evidence is compiled into a content-minimized Directed Acyclic Graph (DAG) with a deterministic SHA-256 canonical representation digest. |
| **8** | **Counterfactual Action Planner** | Inverts the blocker dependency graph to output the minimal, topologically sorted sequence of user actions required to achieve an `ALLOW` state. |

---

## 🏛️ System Architecture & Subsystem Deep Dive

SENTINEL is composed of decoupled, highly isolated micro-runtimes coordinated through typed IPC and a master process supervisor:

```mermaid
flowchart TD
    subgraph ClientSpace ["User & Integration Layer"]
        UI["🖥️ React + Vite Web Workbench\n(Port 5173)\n• Threat Inspector\n• Privacy Shield\n• Differential Perception\n• Time Machine & Attestation\n• Two-Phase SSE Live Stream"]
        Ext["🧩 AI Guardian Extension\n(Manifest V3)\n• Prompt Interceptor\n• Attachment Gating\n• Origin-Bound HMAC Bridge"]
    end

    subgraph SupervisorSpace ["Supervisor & Lifecycle Orchestrator (main.py)"]
        Supervisor["⚙️ Master Process Supervisor\n• Process Health Probes\n• Signal Handler (SIGINT/SIGTERM)\n• Subsystem Lifecycle Manager"]
    end

    subgraph CoreSpace ["SENTINEL Core Engine (Node.js / Express - Port 5001)"]
        Gateway["📡 REST & Two-Phase SSE API Gateway"]
        Vault["⚡ Zero-NAND Ephemeral Storage Tier\n• Linux /dev/shm tmpfs (Mode 0700)\n• In-Memory Buffer Fallback\n• Immediate Unlink Scrubber"]
        Worker["🛡️ Sandboxed Archive Worker\n• Bubblewrap (bwrap) / prlimit\n• 3-Tier Nested Archive Recursion\n• Decompression Bomb Ratio Guards (10:1)"]
        SIRCompiler["📊 Security Intermediate Representation (SIR)\n• Typed Graph Structure\n• Artifacts, Analyzers, Findings, Gaps"]
        DAGGen["🔗 Deterministic Evidence DAG\n• Canonical JSON Serialization\n• SHA-256 Digest Minimization"]
        Planner["🧠 Counterfactual Dependency Planner\n• Blocker Tree Inversion\n• Topologically Sorted Actions"]
        STM["⏳ Security Time Machine\n• SQLite Immutable Evaluation Ledger\n• Epistemic Diff Engine (Additions/Removals)\n• Machine-Root HMAC & Ed25519 Keypair"]
    end

    subgraph PrivacySpace ["Privacy Shield Service (Python FastAPI - Port 8000)"]
        FastAPI["🚀 FastAPI Microservice"]
        Sanitizer["🛡️ Unicode & Bidi Sanitizer\n• Zero-Width Stripper\n• RLO Directional Override Trap"]
        Presidio["🔍 Presidio NLP Engine\n• spaCy Named Entity Recognition\n• PII / Credentials / Financial Rules"]
        Redactor["✂️ Surgical Multi-Format Redactor\n• PDF Vector & Annotations Masking\n• DOCX Run-Level Replacement\n• Image Bounding-Box Overlay"]
        ResidueGate["🔬 Fresh Derivative Residue Gate\n• Re-Extraction of Output Bytes\n• 0% Residual Sensitive Value Check\n• Expiring Single-Use Download Tokens"]
    end

    UI -- "REST / Two-Phase SSE Stream" --> Gateway
    Ext -- "Authenticated HMAC Requests" --> Gateway
    Gateway <--> Vault
    Gateway --> Worker
    Gateway --> SIRCompiler --> DAGGen --> Planner
    Gateway <--> STM
    Gateway -- "HMAC-Authenticated IPC" --> FastAPI
    FastAPI --> Sanitizer --> Presidio --> Redactor --> ResidueGate
    Supervisor --> CoreSpace
    Supervisor --> PrivacySpace
    Supervisor --> ClientSpace
```

---

## 🎛️ The 5 Core Product Modules

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   SENTINEL CORE MODULE MATRIX                                          │
├──────────────────────┬──────────────────────┬──────────────────────┬───────────────────────────────────┤
│ 1. Threat Inspector  │ 2. Privacy Shield    │ 3. Content Integrity │ 4. Code & Toolchain Auditor       │
├──────────────────────┼──────────────────────┼──────────────────────┼───────────────────────────────────┤
│ • Magic-Byte Match   │ • Presidio NLP Engine│ • Differential Visual│ • AST Static Heuristics           │
│ • Deep ZIP Recursion │ • Multi-Format Redact│   Disparity Analyzer │ • Local Semgrep Engine Bridge     │
│ • Static PE Disasm   │ • 0% Residue Gate    │ • Steganography Trap │ • Gitleaks High-Entropy Secrets   │
│ • OOXML / Macro Trap │ • Single-Use Tokens  │ • Prompt Injections  │ • OSV Vulnerability Scanner       │
├──────────────────────┴──────────────────────┴──────────────────────┴───────────────────────────────────┤
│                                5. Fix & Verify (Time Machine & Planner)                                │
│   • Epistemic Diff Comparison     • Counterfactual Action Steps     • Ed25519 Signed SARIF Attestations│
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 1. Threat Inspector & Deep Container Armor
- **Magic-Byte Binary Identification**: Ignores deceptive file extensions; categorizes binaries strictly by raw file signatures.
- **Deep Recursive Container Unpacker**: Traverses nested archives up to 3 levels deep. Enforces a **10:1 decompression ratio limit**, maximum 2,000 members, 16MB central directory limit, and 50MB total extracted size limit inside ephemeral memory vaults.
- **Static Executable (PE/EXE) Disassembly**: Parses PE32/PE32+ headers, sections, export tables, import address tables (IAT), compiler fingerprints, and Shannon section entropy without executing code.
- **OOXML & Document Structure Armor**: Parses Word (`.docx`), Excel (`.xlsx`), and PowerPoint (`.pptx`) archives for embedded VBA macros, dynamic DDE commands, and external relationship endpoints.

### 2. Privacy Shield & Surgical Redaction
- **Presidio NLP Recognition**: Multi-lingual named entity recognition detecting PII, Social Security Numbers, Credit Cards, IBANs, Passwords, API Keys, and Custom Regex Patterns.
- **Unicode & Bidi Armor**: Identifies and neutralizes zero-width spaces, right-to-left override attacks (RLO `\u202E`), and homoglyph substitution spoofing.
- **Multi-Format Redactor**: Executes vector overlays on PDFs, run-level XML text replacement on DOCX, pixel-precise bounding-box masking on images, and string redactions on plaintext.
- **Fresh Derivative Residue Gate**: Re-extracts text from the newly rendered document and verifies **zero residual leakage** of original sensitive values before generating a single-use download token.

### 3. Content Integrity & Differential Perception
- **Human vs LLM Disparity Isolation**: Extracts document layers to detect content crafted to be invisible to human readers (opacity 0, 1pt micro-fonts, white-on-white text, off-canvas coordinates) but ingested by LLM tokenizers.
- **Stealth Prompt Injection Defense**: Traps delimiters, system role directives (`[INST]`, `<system>`), and jailbreak payloads embedded in document margins.

### 4. Code Auditor & Offline Toolchain Engine
- **Static AST Heuristics**: Analyzes source code for hardcoded secrets, weak cryptographic primitives, unsafe TLS configurations, and dangerous shell execution calls without executing code.
- **Local Toolchain Bridge**: Connects directly to local binaries of `semgrep`, `gitleaks`, and `osv-scanner` without transmitting source code to external servers.

### 5. Fix & Verify (Security Time Machine & Counterfactual Planner)
- **Security Time Machine**: Evaluates assessment history for the exact same artifact hash over time, computing epistemic diffs (new vulnerabilities, resolved findings, and ruleset version drifts).
- **Counterfactual Action Planner**: Inverts the finding dependency graph to generate an ordered, minimal checklist required to transition an artifact from `BLOCKED` to `ALLOW`.
- **Cryptographic SARIF Attestation**: Exports SARIF v2.1 reports containing embedded Ed25519 signatures and machine-root HMAC-SHA256 digests for verifiable non-repudiation.

---

## 🧩 AI Guardian: Manifest V3 Browser Extension

The included Manifest V3 browser extension operates natively inside Chromium browsers (Chrome, Brave, Edge), intercepting prompts and document attachments inside AI portals (ChatGPT, Claude, Gemini) **before** they leave your workstation.

```
                              AI GUARDIAN INTERCEPTION WORKFLOW
  ┌─────────────────┐       Prompt / File       ┌────────────────────────┐       403 / Blocked       ┌─────────────────┐
  │ User Submits    │ ────────────────────────► │ AI Guardian Content    │ ────────────────────────► │ Send Intercepted│
  │ Prompt / Upload │                           │ Script (Manifest V3)   │                           │ Prompt Review   │
  └─────────────────┘                           └────────────────────────┘                           └─────────────────┘
                                                             │
                                                             ▼ Authenticated IPC (Token + Origin Bound)
                                                ┌────────────────────────┐
                                                │  SENTINEL Core Gateway │
                                                │      (Port 5001)       │
                                                └────────────────────────┘
                                                             │
                                                             ▼ Verified Clean / Redacted
                                                ┌────────────────────────┐
                                                │ Release Payload to LLM │
                                                └────────────────────────┘
```

### Pairing Setup in 60 Seconds:
1. Open Chrome/Brave and navigate to `chrome://extensions`.
2. Toggle **Developer Mode** (top right) $\rightarrow$ Click **Load Unpacked**.
3. Select the [`browser-extension/`](file:///home/hdd/hackathons/kiet/sentinel-stage19-full/browser-extension) directory.
4. Copy your Extension Origin (`chrome-extension://<id>`).
5. Configure `.env`:
   ```env
   SENTINEL_EXTENSION_ORIGIN=chrome-extension://<your-extension-id>
   SENTINEL_EXTENSION_TOKEN=your-random-32-char-secret-token-here
   ```
6. Open the extension options dialog in your browser, enter `http://127.0.0.1:5001` and your token.

---

## 🚀 Quickstart & Installation

### System Prerequisites
- **Python 3.11+** (`uv` recommended)
- **Node.js 18+** & `npm`
- **Linux / macOS / Windows** (Linux enables native `/dev/shm` tmpfs RAM vaulting and `bwrap` sandboxing)

```bash
# 1. Clone the repository
git clone https://github.com/Aviralgit1212/SENTINEL.git
cd SENTINEL

# 2. Setup Python environment using uv
uv venv
source .venv/bin/activate
uv pip install -r privacy-service/requirements.txt -r python-analyzers/requirements.txt

# 3. Install Node.js dependencies
cd server && npm ci && cd ..
cd client && npm ci && cd ..

# 4. Initialize environment configuration
cp .env.example .env

# 5. Launch the full platform
python main.py
```

### Access URLs:
- **Web Workbench UI:** `http://localhost:5173`
- **Core Security REST API:** `http://127.0.0.1:5001`
- **Privacy Shield Engine:** `http://127.0.0.1:8000`

---

## 🛠️ Master Supervisor Orchestrator (`main.py`)

SENTINEL is managed by a unified Python orchestrator that handles microservice lifecycles, health probing, cross-platform environments, and atomic teardowns:

```bash
# Launch full production stack (FastAPI + Node Core API + React Client)
python main.py

# Launch in development mode with live hot-reloading
python main.py --dev

# Launch backend microservices only (Headless mode)
python main.py --server-only

# Run the complete release acceptance test suite (8 PyTest + 79 Node tests)
python main.py --test

# Run the 5,000-case archive mutation fuzzer
python main.py --fuzz

# Run the analyzer trust & calibration lab
python main.py --calibrate

# Probe the health of running background daemons
python main.py --health
```

---

## ⚙️ Environment Configuration (`.env`)

| Variable | Default Value | Purpose | Security Implication |
|---|---|---|---|
| `SENTINEL_PORT` | `5001` | Core Security API port | Bind to `127.0.0.1` to prevent external network access |
| `HOST` | `127.0.0.1` | Network interface binding | Prevents DNS rebinding and LAN exposure |
| `PRIVACY_PORT` | `8000` | FastAPI Privacy Shield port | Local microservice port |
| `PRIVACY_SERVICE_URL` | `http://127.0.0.1:8000` | IPC bridge URL | Used by Node API to dispatch privacy scans |
| `SENTINEL_VAULT_TIER` | `ram` | `ram` (`/dev/shm`) or `secure_temp` | In `ram` mode, payloads never touch permanent NAND |
| `SENTINEL_SIGNING_KEY_PATH` | `./server/data/sentinel-signing.key` | Machine HMAC root key path | Key created with mode `0600` |
| `SENTINEL_EXTENSION_ORIGIN` | `chrome-extension://...` | Authorized extension origin | Enforces strict CORS and origin verification |
| `SENTINEL_EXTENSION_TOKEN` | *32+ char secret* | Extension pairing token | Unauthenticated requests return `403 Forbidden` |
| `SENTINEL_SEMGREP_CONFIG` | `auto` | Semgrep local ruleset path | Offline rule verification |

---

## 📡 Complete REST & Two-Phase SSE API Reference

### 1. Two-Phase Real-Time Scan Stream
`POST /api/v3/scan-stream`  
**Content-Type:** `multipart/form-data` (Field: `file`)

Streams real-time diagnostic and execution events:
```bash
curl -N -F "file=@document.pdf" http://127.0.0.1:5001/api/v3/scan-stream
```

**Stream Lifecycle Events:**
```json
// 1. Intake Acknowledged
event: intake_ack
data: {"scanId":"sc_1892a","sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","size":1048576,"storageTier":"ram"}

// 2. SIR Compiled
event: sir_compiled
data: {"graph":{"nodes":[{"id":"art_1","type":"artifact"},{"id":"an_pdf","type":"analyzer"}],"edges":[]}}

// 3. Security Finding Emitted
event: finding
data: {"id":"fnd_1","category":"differential-perception","severity":"HIGH","title":"Hidden prompt injection in PDF stream"}

// 4. Counterfactual Plan Emitted
event: counterfactual_plan
data: {"targetVerdict":"allow","actions":[{"step":1,"action":"strip-invisible-text","impact":"resolves_fnd_1"}]}

// 5. Complete Report with Attestation
event: complete
data: {"verdict":"review_required","sarifDoc":{...},"attestation":{"algorithm":"Ed25519","signature":"..."}}
```

### 2. Standard Multipart File Inspection
`POST /api/scans` (Multipart `file`)
```bash
curl -F "file=@package.zip" http://127.0.0.1:5001/api/scans
```

### 3. Content-Minimized Evidence DAG
`GET /api/scans/:scanId/evidence`
```bash
curl http://127.0.0.1:5001/api/scans/<scan_id>/evidence
```

### 4. Privacy Text Inspection & Redaction
`POST /api/privacy/scan-text`
```bash
curl -X POST http://127.0.0.1:5001/api/privacy/scan-text \
  -H "Content-Type: application/json" \
  -d '{"text": "Confidential: User Alice (alice@company.com) with SSN 000-12-3456"}'
```

### 5. Ed25519 & HMAC SARIF Receipt Verification
`POST /api/attestations/verify`
```bash
curl -X POST http://127.0.0.1:5001/api/attestations/verify \
  -H "Content-Type: application/json" \
  -d '{"sarif": {...}, "algorithm": "Ed25519"}'
```

---

## 🧪 Formal Verification Gates & Calibration Lab

SENTINEL enforces 8 rigorous release acceptance gates tested across 87 automated tests:

| Gate | Target Subsystem | Test Count | Status |
|---|---|---|---|
| **Gate 01** | Zero-NAND Ephemeral RAM Vault & Storage Isolation | 7 Tests | ✅ Pass |
| **Gate 02** | Deep Archive Armor & 5,000-Case Mutation Fuzzer | 8 Tests | ✅ Pass |
| **Gate 03** | Presidio NLP & Fresh Derivative Residue Gate | 14 Tests | ✅ Pass |
| **Gate 04** | Differential Perception & Tokenizer Disparity Engine | 5 Tests | ✅ Pass |
| **Gate 05** | Security Intermediate Representation (SIR) & Evidence DAG | 6 Tests | ✅ Pass |
| **Gate 06** | Counterfactual Action Planner & Blocker Graph | 4 Tests | ✅ Pass |
| **Gate 07** | Cryptographic Attestation (Ed25519 & Machine HMAC) | 6 Tests | ✅ Pass |
| **Gate 08** | AI Guardian Extension Bridge & Origin-Bound Handshake | 5 Tests | ✅ Pass |

Run the complete test harness:
```bash
python main.py --test
```

---

## 🛡️ Threat Model & Security Perimeter

### Formally Guaranteed Security Boundaries:
- **Zero Silent Failures**: Missing, crashed, or unconfigured analyzers always force `REVIEW_REQUIRED`.
- **Ephemeral Payload Processing**: Artifact bytes exist only in `/dev/shm` tmpfs and are securely scrubbed from memory after processing.
- **Tamper Evidence**: SARIF exports signed with Ed25519 and HMAC roots detect any post-scan modification.
- **Cryptographic Residue Prevention**: Derivative documents are re-parsed to confirm that zero unmasked tokens remain.

### Explicit Non-Goals:
- **Dynamic Binary Sandboxing**: SENTINEL performs deep static disassembly; it does not execute untrusted binaries.
- **Cloud Telemetry**: SENTINEL is 100% sovereign; no document bytes or hashes are transmitted to external third-party cloud services.

---

<div align="center">
  <b>SENTINEL Sovereign Core v3.0 — Precision Security for Sovereign Enterprise Data.</b><br/>
  <sub>Developed for mission-critical security, privacy-first computing, and verifiable AI safety.</sub>
</div>
