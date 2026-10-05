#!/usr/bin/env python3
"""
ARGUS — Sigma Detection Runner
==============================

Applies Sigma rules (sigma_rules/*.yml) to a log file of JSON events
(one JSON object per line) and prints which events fired which rule.

This is the blue-team half of ARGUS: the red-side campaigns generate events,
these detections catch them. The rules are real Sigma YAML (the portable
detection-as-code format SOC teams use); this runner is a lightweight local
engine so the whole thing runs on the laptop with no SIEM.

Supported Sigma subset (enough for ARGUS rules):
  - detection blocks with field matches
  - value lists (OR), and |contains / |endswith / |startswith modifiers
  - condition: a boolean over block names, e.g.
        "selection"              |  "selection and not filter"  |  "a or b"

Usage:
    python3 run_detections.py
    python3 run_detections.py --logs sample_logs/endpoint_events.jsonl
    python3 run_detections.py --triage          # also triage each hit with the AI copilot
    python3 run_detections.py --triage --mock    # ...offline

Needs PyYAML (ships with Anaconda/conda). If missing:  pip install pyyaml
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("This runner needs PyYAML. Install it with:  pip install pyyaml",
          file=sys.stderr)
    raise SystemExit(1)


# --- Matching a single selection block --------------------------------------
def _match_value(event_val, expected) -> bool:
    """One field's expected value(s) against the event value."""
    if isinstance(expected, list):
        return any(_match_value(event_val, e) for e in expected)
    if event_val is None:
        return False
    return str(event_val).strip().lower() == str(expected).strip().lower()


def _match_field(event: dict, key: str, expected) -> bool:
    """Handle Sigma field modifiers like field|contains, field|endswith."""
    if "|" in key:
        field, mod = key.split("|", 1)
        val = str(event.get(field, "") or "").lower()
        exps = expected if isinstance(expected, list) else [expected]
        exps = [str(e).lower() for e in exps]
        if mod == "contains":
            return any(e in val for e in exps)
        if mod == "endswith":
            return any(val.endswith(e) for e in exps)
        if mod == "startswith":
            return any(val.startswith(e) for e in exps)
        return False
    return _match_value(event.get(key), expected)


def _match_block(event: dict, block: dict) -> bool:
    """A selection block matches only if ALL its field conditions match (AND)."""
    return all(_match_field(event, k, v) for k, v in block.items())


# --- Evaluating the condition over named blocks -----------------------------
_ALLOWED_TOKENS = {"and", "or", "not", "(", ")", "True", "False"}


def _eval_condition(condition: str, block_results: dict) -> bool:
    """Turn 'selection and not filter' into a safe boolean evaluation."""
    expr_tokens = []
    for tok in condition.replace("(", " ( ").replace(")", " ) ").split():
        if tok in ("and", "or", "not", "(", ")"):
            expr_tokens.append(tok)
        elif tok in block_results:
            expr_tokens.append("True" if block_results[tok] else "False")
        else:
            # Unknown token — fail closed rather than guess.
            raise ValueError(f"unsupported token in condition: {tok!r}")
    expr = " ".join(expr_tokens)
    # expr now contains only True/False/and/or/not/parentheses — safe to eval.
    if set(expr.split()) - _ALLOWED_TOKENS:
        raise ValueError(f"refusing to evaluate condition: {expr!r}")
    return bool(eval(expr))  # noqa: S307 - sanitized to booleans + operators


# --- Rule loading + evaluation ----------------------------------------------
def load_rules(rules_dir: Path) -> list[dict]:
    rules = []
    for p in sorted(rules_dir.glob("*.yml")) + sorted(rules_dir.glob("*.yaml")):
        with p.open(encoding="utf-8") as f:
            rule = yaml.safe_load(f)
        rule["_file"] = p.name
        rules.append(rule)
    return rules


def evaluate(rule: dict, event: dict) -> bool:
    detection = rule.get("detection", {})
    condition = detection.get("condition", "")
    blocks = {name: _match_block(event, blk)
              for name, blk in detection.items() if name != "condition"}
    try:
        return _eval_condition(condition, blocks)
    except ValueError as e:
        print(f"  [!] {rule.get('_file')}: {e}", file=sys.stderr)
        return False


def event_to_alert(rule: dict, event: dict, n: int) -> dict:
    """Shape a fired detection into the alert format the triage copilot expects."""
    return {
        "alert_id": f"DET-{n:04d}",
        "detected_at": event.get("timestamp"),
        "rule": {
            "title": rule.get("title"),
            "id": rule.get("id"),
            "level": rule.get("level"),
            "mitre": [t.split(".", 1)[-1].upper()
                      for t in rule.get("tags", []) if t.startswith("attack.t")],
        },
        "host": {"name": event.get("host")},
        "identity": {"user": event.get("user")},
        "event": event,
    }


# --- Main --------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="ARGUS Sigma detection runner")
    ap.add_argument("--rules", default="sigma_rules")
    ap.add_argument("--logs", default="sample_logs/endpoint_events.jsonl")
    ap.add_argument("--triage", action="store_true",
                    help="send each fired detection to the AI triage copilot")
    ap.add_argument("--mock", action="store_true",
                    help="triage offline (implies --triage)")
    args = ap.parse_args()
    if args.mock:
        args.triage = True

    here = Path(__file__).parent
    rules = load_rules(here / args.rules)
    log_path = here / args.logs if not Path(args.logs).is_absolute() else Path(args.logs)

    print(f"Loaded {len(rules)} Sigma rule(s). Scanning {log_path.name} ...\n")

    hits = 0
    scanned = 0
    with log_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            scanned += 1
            event = json.loads(line)
            for rule in rules:
                if evaluate(rule, event):
                    hits += 1
                    print(f"[FIRED] {rule['level'].upper():<8} {rule['title']}")
                    print(f"        rule : {rule['_file']}  ({rule.get('id')})")
                    print(f"        when : {event.get('timestamp')}  on {event.get('host')}")
                    print(f"        who  : {event.get('user')}  "
                          f"{event.get('action')}  {event.get('target_file')}")
                    if event.get("destination_type") == "removable":
                        print(f"        dest : {event.get('destination')} (removable)")
                    if args.triage:
                        _triage_hit(here, rule, event, hits, args)
                    print()

    print("-" * 60)
    print(f"Scanned {scanned} events, {hits} detection(s) fired across "
          f"{len(rules)} rule(s).")
    return 0


def _triage_hit(here: Path, rule: dict, event: dict, n: int, args) -> None:
    """Bridge: hand a fired detection to the AI triage copilot (if available)."""
    sys.path.insert(0, str(here.parent / "ai_triage"))
    try:
        from triage import triage_alert
    except ImportError:
        print("        (triage copilot not found next to detections/ — skipping)")
        return
    alert = event_to_alert(rule, event, n)
    v = triage_alert(alert, model="llama3.2:3b", use_mock=args.mock, harden=True)
    print(f"        TRIAGE: {v['verdict']} / {v['severity']} / {v['classification']}"
          f"  [{v['_engine']}]")


if __name__ == "__main__":
    raise SystemExit(main())
