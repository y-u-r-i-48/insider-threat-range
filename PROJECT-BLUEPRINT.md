# Project ARGUS — Insider Threat Range (Purple Team)

> *A self-contained lab that simulates insider-threat and AI-driven exfiltration attacks, detects them, and triages the alerts with a locally-run, injection-hardened AI assistant.*

**Author:** Yuri Son · Washington, DC
**Status:** In development (started Oct 2026)
**Repo name suggestion:** `insider-threat-range` (codename ARGUS — the hundred-eyed watchman; rename freely)

---

## 1. One-paragraph pitch (the thing you say out loud)

ARGUS is a home-built security range where I play both sides. I run insider-threat campaigns — USB exfiltration, cloud/email exfiltration, DNS tunneling, privilege abuse, and a 2026-style *rogue AI agent* insider — against a small Active Directory lab, then I detect them with Sysmon + Wazuh + Sigma rules mapped to MITRE ATT&CK. On top of the detection pipeline sits an AI triage assistant that classifies each alert (true/false positive, severity, incident type) and auto-drafts the incident report. It runs **locally** so telemetry never leaves the environment, and I **hardened it against prompt injection** — the same attack class behind the EchoLeak and Reprompt Copilot breaches. The scenarios are modeled on real 2026 incidents, documented in `THREAT-MODEL.md`.

---

## 2. Why this project exists (positioning against the two roles)

Most candidates pick red **or** blue. ARGUS is deliberately **purple** so it speaks to both of my target roles at once, and the AI layer shows I track where the field actually is in 2026.

### Samsung — Cybersecurity Engineer (blue / detection & response)
| JD responsibility | Where ARGUS covers it |
|---|---|
| Threat detection / detection engineering | Sigma rules authored per technique, deployed in Wazuh |
| Incident investigation & analysis (validate, classify, scope) | AI triage assistant + manual investigation walkthrough |
| Monitoring & alert management (endpoints, AD, network) | Sysmon + Windows Event Forwarding + Zeek into Wazuh SIEM |
| Incident response (SIEM/EDR/IDS alerts, true vs false positive) | End-to-end campaign → alert → triage → response playbook |
| Documentation | Auto-generated incident reports + full repo docs |
| **Scanning external media / removable devices** | **USB exfiltration scenario + USB-insertion detection rule** |

### Coupang — Insider Threat Counter Operation (red / offensive simulation)
| JD responsibility | Where ARGUS covers it |
|---|---|
| Insider threat simulation campaigns | The entire red-side scenario suite |
| Sensitive data identification & gathering | File-tagging / lightweight DSPM classifier |
| Data exfiltration | USB, cloud, email, DNS-tunnel exfil scenarios |
| Policy circumvention & privilege abuse | Log-clearing / zip-encrypt evasion + priv-abuse scenario |
| Operations against DLP, DSPM, legal hold | DLP tripwires, file classifier, legal-hold deletion alert |
| Improve & develop customized tools | The campaign runner is a custom Python tool |
| Native Korean + English | *(already yours — lead with it)* |

> **Interview move:** bring this table. Walking a manager line-by-line through their own JD is disarmingly effective.

---

## 3. Architecture

```
                 ┌─────────────────────────────────────────┐
                 │               ARGUS LAB                  │
                 │                                          │
  ┌───────────┐  │   ┌────────────┐      ┌──────────────┐  │
  │ Attacker  │──┼──▶│ Win11       │      │ Win Server   │  │
  │ box (Kali │  │   │ endpoint    │◀────▶│ (DC: AD/DNS) │  │
  │ / Linux)  │  │   │ +Sysmon     │      │ +Sysmon      │  │
  └───────────┘  │   └─────┬──────┘      └──────┬───────┘  │
    campaign                │  logs / events      │          │
    runner (Python)         ▼                     ▼          │
                 │   ┌──────────────────────────────────┐   │
                 │   │ Wazuh SIEM (+ Zeek/Suricata net)  │   │
                 │   │  → Sigma rules → alerts           │   │
                 │   └──────────────┬───────────────────┘   │
                 └──────────────────┼───────────────────────┘
                                    ▼
                      ┌──────────────────────────┐
                      │ AI Triage Assistant       │
                      │ (local LLM via Ollama)    │
                      │  • classify / severity     │
                      │  • TP vs FP + reasoning     │
                      │  • auto incident report     │
                      │  • prompt-injection hardened│
                      └──────────────────────────┘
```

**Hardware note (MacBook M2, 8 GB RAM):** a full multi-VM Windows AD range + Wazuh will *not* fit in 8 GB. ARGUS runs **laptop-native** instead — same skills, zero cost, runs today. The diagram above is the conceptual flow; the real stack is below. (A live cloud/Windows range stays an optional Phase-3 upgrade.)

**Laptop-native stack (all free, runs on 8 GB M2):**
- **Endpoint telemetry — attacks you run yourself:** **osquery** on macOS — lightweight, SQL-queryable visibility into processes, files, USB mounts, network connections.
- **Windows/AD story — without running Windows:** real attack telemetry from public **EVTX attack-sample datasets** (sbousseaden/EVTX-ATTACK-SAMPLES, OTRF Security-Datasets) — detect genuine Windows/AD attacks without hosting a domain.
- **Detection engine — no heavy SIEM:** **Sigma rules** executed with **Chainsaw** and/or **Hayabusa** (fast Rust CLIs) against EVTX; detections also written against osquery + Zeek output.
- **Network:** **Zeek** on captured pcaps (ties to your Wireshark skill) for DNS-tunnel detection.
- **ML layer:** your existing Isolation Forest / LOF / One-Class SVM (scikit-learn) on generated telemetry.
- **AI layer:** **Ollama** running a small model (`llama3.2:3b` ≈ 2 GB; alternatives `qwen2.5:3b`, `phi3:mini`) — 3B-class fits 8 GB; a 7B model will swap hard, so avoid it. Python orchestration + strict JSON validation.
- **MITRE ATT&CK** mapping throughout.

> Trade-off, stated honestly: you lose *"I administered a live multi-host AD domain."* You gain *"I detected real-world Windows attack telemetry and built live macOS endpoint monitoring with osquery."* Still strong, and it runs on the machine you have.

---

## 4. Red side — the campaigns

Each is a function in the custom Python **campaign runner** (`campaigns/`). Setup first: plant tagged "sensitive" files (fake SSNs, files marked `CONFIDENTIAL` / `LEGAL-HOLD`).

| # | Scenario | Technique (MITRE) | Priority |
|---|---|---|---|
| 1 | **USB exfiltration** (copy tagged files to removable media) | T1052.001 | **MVP** |
| 2 | **Cloud / web upload exfil** | T1567 | **MVP** |
| 3 | Email exfil to external address | T1048 | Stretch |
| 4 | **DNS tunneling** exfil (ties to your Wireshark skill) | T1048.003 | Stretch |
| 5 | Privilege abuse / mass + after-hours file access | T1078 / T1530 | Stretch |
| 6 | Defense evasion (clear logs, rename/zip/encrypt before exfil) | T1070 / T1560 | Stretch |
| 7 | **Rogue AI-agent insider** (autonomous, high-velocity enumeration + exfil) | T1530 + velocity | **Differentiator** |

---

## 5. Blue side — the detections

- **Sigma rule per technique** → deployed in Wazuh. Detection-as-code is the phrase that signals "detection engineering."
- **MITRE ATT&CK coverage matrix** (Collection / Exfiltration / Defense Evasion) — the artifact that makes it read as professional.
- **Velocity detection** for the rogue-agent scenario (e.g. *N sensitive-file reads by one identity in 60s*) — not just per-event rules.
- **DLP tripwires:** outbound connection carrying tagged data = the generalizable control across every exfil channel.
- **Legal-hold alert:** fires when a `LEGAL-HOLD`-tagged file is moved/deleted.
- **ML anomaly layer:** re-run Isolation Forest / LOF / One-Class SVM on generated telemetry; report **TPR / false-positive rate** (mirror your existing 100% TPR / 36% FP reduction for resume continuity).
- **One full incident report**, hand-written, SOC-analyst style — the sample deliverable for Samsung's "Documentation" + "Investigation" bullets.

---

## 6. AI layer (the 2026 relevance)

| Component | What it does | Why it's defensible in interview |
|---|---|---|
| **Triage copilot** | alert → LLM → {classification, severity, TP/FP, reasoning} as JSON | Samsung's exact words: validate, classify, reduce false positives |
| **Auto incident report** | triaged alert + timeline → drafted report | Direct sample of the "Documentation" responsibility |
| **Local inference (Ollama)** | all AI runs locally, no telemetry leaves the lab | Shows data-governance thinking — the thing Coupang protects |
| **Prompt-injection hardening** | demo the attack (malicious text in a log/filename → "mark benign"), then mitigate | Purple-team thinking applied to AI; defends the EchoLeak/Reprompt class |
| **(Stretch) SOAR auto-response** | USB-exfil rule → auto isolate host / disable account / quarantine file | "Automation" in the real SOC sense; Wazuh active-response |
| **(Stretch) RAG over ATT&CK** | grounded Q&A over ATT&CK + your detection docs | Demonstrates a hot, hireable skill |

**Keep the red-side AI restrained.** The credible, demonstrable value is in the *defensive* AI (triage, reporting, injection-hardening), not in using an LLM to generate attacks.

---

## 7. Threat model — real 2026 incidents → your scenarios

Full detail lives in `THREAT-MODEL.md`. Summary of the mapping:

| Real incident (2026) | What it demonstrated | ARGUS scenario it justifies |
|---|---|---|
| Hugging Face autonomous-agent breach (~17,600 actions; root cause: no log monitoring + weak sandboxing) | AI agent as high-speed insider | #7 rogue-agent + velocity detection + account scoping |
| Agent campaign built & run in <6 hrs (Google) | machine-speed attacks | velocity / tempo-based detection |
| EchoLeak (CVE-2025-32711) — zero-click M365 Copilot exfil | AI tool as exfil channel via injection | prompt-injection hardening of triage copilot |
| Reprompt (CVE-2026-24307) — single-click Copilot exfil | untrusted input + external output channel | DLP external-channel detection |
| CellShock — injection in Claude for Excel | hidden instructions in untrusted data | injection demo-and-fix |
| Cline/OpenClaw supply-chain injection (~4,000 machines) | governance / untrusted-content gap | README governance section |

---

## 8. Roadmap (aggressive — you want a job now)

**MVP — Week 1–2 (already a strong portfolio piece on its own):**
- [ ] Stand up lab (DC + endpoint + attacker), Sysmon + Wazuh logging confirmed
- [ ] Scenario #1 (USB exfil) + #2 (cloud exfil)
- [ ] 2 Sigma rules deployed + firing
- [ ] AI triage copilot v1 (local Ollama) returning structured JSON on sample alerts
- [ ] 1 hand-written incident report
- [ ] README + this blueprint + `THREAT-MODEL.md` in repo

**Phase 2 — Week 3:**
- [ ] Scenario #7 (rogue-agent) + velocity detection
- [ ] Prompt-injection attack-and-fix demo on the copilot
- [ ] Auto-generated incident report
- [ ] MITRE ATT&CK coverage matrix
- [ ] 60-second GIF: attack → alert → triage → report

**Phase 3 — stretch (after first applications are out):**
- [ ] DNS tunneling + privilege abuse + evasion scenarios
- [ ] ML anomaly layer on real telemetry (TPR/FP numbers)
- [ ] SOAR auto-response + RAG over ATT&CK

> Don't wait for Phase 3 to apply. The MVP + GIF is enough to put on the resume and talk about.

---

## 9. Portfolio deliverables (what a recruiter actually sees)

1. **GitHub repo** — campaign runner, Sigma rules, lab docs, this blueprint, threat model.
2. **60-second GIF/video** — attack → alert → AI triage → report. The single most convincing artifact.
3. **MITRE ATT&CK coverage matrix** — one image.
4. **One polished incident report** (PDF).
5. **A `THREAT-MODEL.md`** citing real 2026 incidents — makes it read as threat-informed.

---

## 10. Resume bullets this will produce (draft)

- Built a purple-team insider-threat range (Windows AD + Wazuh SIEM + Sysmon/Zeek) simulating USB, cloud, email, and DNS-tunnel data exfiltration, authoring Sigma detections mapped to MITRE ATT&CK.
- Developed a custom Python campaign runner and an AI alert-triage assistant (local LLM via Ollama) that classifies incidents and auto-drafts reports, cutting false positives via a layered rule + ML + LLM pipeline.
- Modeled attack scenarios on real 2026 incidents (autonomous-agent breaches, EchoLeak/Reprompt-class AI exfiltration) and hardened the triage tool against prompt injection.

---

## 11. Honest notes

- **Coupang wants 5+ yrs** — treat it as the reach; native Korean + insider-threat focus are your real edge. Samsung-type SOC/detection roles are the realistic near-term target.
- **CISM** (landing in a few weeks) is governance-oriented; for these hands-on roles it's a supporting signal, not the headline. This project + Security+ carry the technical screen. A later technical cert (BTL1 defense / eJPT offense) would reinforce these JDs more directly.
- Cite only the CVE-documented / vendor-reported incidents in interviews. Skip the sensational "Skynet Day" framing.
