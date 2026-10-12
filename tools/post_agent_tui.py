#!/usr/bin/env python3
"""Post-agent evidence review TUI.

A formatted number is not a measurement. This tool separates agent-reported
results from raw observations and flags missing metrology/provenance fields.
It uses only the Python standard library and never executes packet content.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from pathlib import Path
from typing import Any

REQUIRED_OBSERVATION_FIELDS = (
    "id", "value", "unit", "observed_at", "method", "instrument",
    "source", "raw_value",
)
RECOMMENDED_OBSERVATION_FIELDS = (
    "calibration", "uncertainty", "replicate_id", "operator_or_automation",
)
VALID_STATES = {"PASS", "REVIEW_REQUIRED", "FAIL"}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_hash(value: Any) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    return sha256_bytes(data)


def _is_finite_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value))


def review_observation(obs: Any) -> dict[str, Any]:
    """Assess auditability, not scientific truth."""
    if not isinstance(obs, dict):
        return {"state": "FAIL", "id": None, "issues": ["observation must be a JSON object"]}
    issues: list[str] = []
    missing = [key for key in REQUIRED_OBSERVATION_FIELDS if key not in obs or obs[key] in (None, "")]
    if missing:
        issues.append("missing required fields: " + ", ".join(missing))
    if "value" in obs and not _is_finite_number(obs["value"]):
        issues.append("value must be a finite numeric value")
    if "raw_value" in obs and obs["raw_value"] in (None, ""):
        issues.append("raw_value must preserve the original instrument/source value")
    if "source_sha256" in obs:
        digest = obs.get("source_sha256")
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest.lower()):
            issues.append("source_sha256 must be a 64-character SHA-256 hex digest")
    else:
        issues.append("missing source_sha256: raw source bytes are not content-addressed")
    recommended_missing = [key for key in RECOMMENDED_OBSERVATION_FIELDS if key not in obs or obs[key] in (None, "")]
    if recommended_missing:
        issues.append("recommended metadata absent: " + ", ".join(recommended_missing))
    state = "FAIL" if any(x.startswith("missing required") or x.startswith("value must") or x.startswith("observation must") for x in issues) else ("REVIEW_REQUIRED" if issues else "PASS")
    return {"state": state, "id": obs.get("id"), "issues": issues, "observation_sha256": canonical_hash(obs)}


def review_packet(packet: Any) -> dict[str, Any]:
    if not isinstance(packet, dict):
        raise ValueError("packet root must be a JSON object")
    observations = packet.get("raw_observations", [])
    if not isinstance(observations, list):
        raise ValueError("raw_observations must be an array")
    results = [review_observation(obs) for obs in observations]
    ids = [r.get("id") for r in results if r.get("id") is not None]
    duplicates = sorted({x for x in ids if ids.count(x) > 1})
    issues: list[str] = []
    if not observations:
        issues.append("no raw observations supplied; reported metrics cannot be independently checked")
    if duplicates:
        issues.append("duplicate observation IDs: " + ", ".join(map(str, duplicates)))
    metric_results = packet.get("reported_results", [])
    if not isinstance(metric_results, list):
        raise ValueError("reported_results must be an array")
    raw_pass = bool(results) and all(r["state"] == "PASS" for r in results) and not duplicates
    state = "PASS" if raw_pass and not issues else ("FAIL" if any(r["state"] == "FAIL" for r in results) else "REVIEW_REQUIRED")
    return {
        "schema_version": 1,
        "review_type": "post_agent_measurement_audit",
        "packet_id": packet.get("packet_id", "UNNAMED"),
        "state": state,
        "important_limit": "Auditability checks do not establish scientific validity or truth.",
        "packet_sha256": canonical_hash(packet),
        "reported_result_count": len(metric_results),
        "raw_observation_count": len(observations),
        "observations": results,
        "issues": issues,
    }


def _short(value: Any, width: int = 64) -> str:
    text = str(value).replace("\n", " ")
    return text if len(text) <= width else text[: width - 1] + "…"


def render(packet: dict[str, Any], audit: dict[str, Any]) -> str:
    lines = [
        "EVEZ / POST-AGENT REVIEW",
        "=" * 72,
        f"Packet: {_short(audit['packet_id'])}",
        f"Audit state: {audit['state']}",
        f"Packet SHA-256: {audit['packet_sha256']}",
        f"Reported results: {audit['reported_result_count']} | Raw observations: {audit['raw_observation_count']}",
        "",
        "REPORTED RESULTS (claims are not raw observations)",
        "-" * 72,
    ]
    for item in packet.get("reported_results", []):
        if not isinstance(item, dict):
            lines.append(f"- malformed result: {_short(item)}")
            continue
        lines.append(f"- {_short(item.get('name', item.get('id', 'unnamed')))} = {_short(item.get('value', 'MISSING'))} {_short(item.get('unit', ''))}")
        if item.get("precision") is not None:
            lines.append(f"  printed precision: {item['precision']} (formatting only; not a validity test)")
        if item.get("observation_ids"):
            lines.append(f"  linked observations: {', '.join(map(str, item['observation_ids']))}")
        else:
            lines.append("  linked observations: NONE")
    lines += ["", "RAW OBSERVATIONS", "-" * 72]
    obs_results = audit["observations"]
    raw = packet.get("raw_observations", [])
    if not raw:
        lines.append("NO RAW OBSERVATIONS PROVIDED.")
    for obs, result in zip(raw, obs_results):
        lines.append(f"[{result['state']}] observation={_short(result.get('id', 'UNNAMED'))} sha256={result.get('observation_sha256', '')}")
        if isinstance(obs, dict):
            for key in ("raw_value", "value", "unit", "observed_at", "method", "instrument", "calibration", "uncertainty", "replicate_id", "source", "source_sha256"):
                if key in obs:
                    lines.append(f"  {key}: {_short(obs[key])}")
        for issue in result["issues"]:
            lines.append(f"  ! {issue}")
    lines += ["", "REVIEW FLAGS", "-" * 72]
    if not audit["issues"] and all(x["state"] == "PASS" for x in obs_results):
        lines.append("No schema-level auditability flags. Independent scientific review is still required.")
    else:
        lines.extend("- " + x for x in audit["issues"])
        for obs in obs_results:
            lines.extend(f"- observation {obs.get('id')}: {issue}" for issue in obs["issues"])
    lines += [
        "",
        "Interpretation: three decimal places are display precision, not measurement validity.",
        "Check raw source, method, calibration, units, uncertainty, replication, and provenance.",
        "This TUI does not infer truth, execute tools, or approve agent actions.",
    ]
    return "\n".join(lines)


def load_packet(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    if len(raw) > 20 * 1024 * 1024:
        raise ValueError("packet exceeds 20 MiB safety limit")
    packet = json.loads(raw.decode("utf-8"), parse_constant=lambda x: (_ for _ in ()).throw(ValueError(f"invalid JSON constant: {x}")))
    if not isinstance(packet, dict):
        raise ValueError("packet root must be a JSON object")
    return packet


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet", type=Path, help="JSON packet exported by an agent")
    parser.add_argument("--json", action="store_true", help="emit machine-readable audit JSON")
    parser.add_argument("--write-audit", type=Path, help="write audit result to a JSON file")
    args = parser.parse_args(argv)
    try:
        packet = load_packet(args.packet)
        audit = review_packet(packet)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        print(f"review error: {exc}", file=sys.stderr)
        return 2
    if args.write_audit:
        args.write_audit.write_text(json.dumps(audit, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(audit, indent=2, sort_keys=True) if args.json else render(packet, audit))
    return 0 if audit["state"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
