# ARGUS — Insider Threat Range (Purple Team)

A self-contained security lab that **simulates insider data-exfiltration, detects it with
Sigma rules mapped to MITRE ATT&CK, and triages the alerts with a locally-run,
prompt-injection-hardened AI assistant.** Built to run on a laptop — no cloud, no SIEM.

> **Status:** active learning / portfolio project. This is a deliberately small, clean
> slice built to demonstrate the concepts end-to-end — not a production-scale system.

---

## Why this project

Most security portfolios pick red **or** blue. ARGUS is **purple** — it runs the insider
attacks *and* detects them — and it addresses where the field actually is in 2026:
autonomous AI agents as attackers, and AI tools weaponized for data exfiltration via
prompt injection. Every scenario is modeled on a real, documented 2026 incident
(see [`THREAT-MODEL.md`](THREAT-MODEL.md)).

## The full loop, on one laptop

```
 raw log event  ->  Sigma rule fires  ->  AI triage copilot classifies  ->  verdict
 (endpoint)         (detection-as-code)   (local LLM, injection-hardened)
```

## What's inside

| Folder / file | What it is |
|---|---|
| `ai_triage/triage.py` | AI alert-triage copilot — local LLM (Ollama) returns a structured verdict (classification, severity, true/false positive, reasoning, MITRE IDs). Mock fallback so it always runs. |
| `ai_triage/harden.py` | Prompt-injection defense: detects injected instructions, computes a hard-facts risk floor, and never lets the model clear a real exfil. |
| `ai_triage/demo_injection.py` | Before/after demo — watch the raw copilot get tricked, then the hardened one catch it. |
| `detections/sigma_rules/` | Real Sigma detection rules (USB exfil, legal-hold tampering). |
| `detections/run_detections.py` | Local Sigma engine; `--triage` pipes each hit into the AI copilot. |
| `detections/sample_logs/` | Labeled test events (malicious + benign). |
| `PROJECT-BLUEPRINT.md` | Full plan and how it maps to target job descriptions. |
| `THREAT-MODEL.md` | Each scenario tied to a real 2026 incident. |

## Quick start

```bash
# 1) Detections (no dependencies beyond PyYAML, which ships with Anaconda)
cd detections
python3 run_detections.py

# 2) AI triage — runs offline in mock mode immediately
cd ../ai_triage
python3 triage.py --all --mock

# 3) AI triage with a real local model
#    install Ollama (https://ollama.com), then:
ollama pull llama3.2:3b
python3 triage.py --all

# 4) The prompt-injection before/after demo
python3 demo_injection.py            # or add --mock to run offline

# 5) The full pipeline: log -> rule -> AI verdict
cd ../detections
python3 run_detections.py --triage   # add --mock to run offline
```

## Techniques covered (MITRE ATT&CK)
- **T1052.001** Exfiltration over USB
- **T1567** Exfiltration to web service / cloud
- **T1070 / T1565** Legal-hold tampering / data manipulation
- **T1530** Collection of sensitive data
- Prompt injection against the AI tool itself (OWASP LLM01), with mitigation

## Roadmap
- Velocity detection for the rogue-AI-agent scenario (one identity, hundreds of reads in seconds)
- Auto-generated incident reports from triaged alerts
- MITRE ATT&CK coverage matrix
- Wire detections to real Windows Event Logs (EVTX)

---

*Author: Yuri Son. Built as a hands-on lab to study insider-threat detection and
AI-assisted triage.*
