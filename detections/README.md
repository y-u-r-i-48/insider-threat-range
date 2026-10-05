# detections — Sigma rules + local runner (blue team)

The blue-team half of ARGUS. Real **Sigma rules** (the portable detection-as-code
format SOC teams write) plus a lightweight local runner so the whole thing works on
the laptop with no SIEM. The red-side campaigns generate events; these detections
catch them.

## What's here
```
detections/
├── run_detections.py              # local Sigma engine (needs PyYAML)
├── sigma_rules/
│   ├── usb_exfil.yml              # CONFIDENTIAL/LEGAL-HOLD file -> removable media
│   └── legal_hold_tamper.yml      # delete/move/rename of a LEGAL-HOLD file
└── sample_logs/
    └── endpoint_events.jsonl      # 6 events: 3 malicious, 3 benign
```

## Run it
```bash
cd detections
python3 run_detections.py                 # fire the rules at the sample logs
python3 run_detections.py --triage --mock # also run each hit through the AI copilot (offline)
python3 run_detections.py --triage        # ...using the real local LLM
```
> `--triage` expects the `ai_triage/` folder to sit next to `detections/`
> (that's how the project is laid out). Needs PyYAML — ships with Anaconda;
> otherwise `pip install pyyaml`.

## What a good run shows
Scanning 6 events fires **3** detections and correctly stays silent on the other 3
(a non-tagged file to USB, a normal local read, an authorized local backup). That
"correct silence" is the difference between a real detection and a noisy one.

With `--triage`, each fired detection flows straight into the hardened AI copilot —
so you can demo the full SOC pipeline end to end: **raw log -> Sigma rule -> AI triage verdict.**

## JD coverage
- **Samsung** — detection engineering (Sigma), monitoring/alerting, and the
  removable-media duty (the USB rule is a direct hit).
- **Coupang** — legal-hold is named in the JD; `legal_hold_tamper.yml` detects
  tampering with data under hold.

## How to talk about it
- *"I write detections as Sigma so they're portable to any SIEM, and I validate them
  against labelled logs — checking they fire on the true positives and stay silent on
  the benign events."*
- *"My detection pipeline hands each hit to an AI triage copilot, so a raw log event
  becomes a classified, severity-rated verdict automatically."*

## Next rules to add (roadmap)
- Cloud/web exfil to file-sharing hosts (T1567).
- DNS-tunnel exfil via Zeek logs (T1048.003).
- Velocity rule: one identity reading N+ sensitive files in 60s (the rogue-AI-agent
  scenario from THREAT-MODEL.md).
