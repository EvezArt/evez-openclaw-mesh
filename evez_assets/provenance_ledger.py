"""Small append-only provenance ledger for EVEZ asset transformations.

This is a local reference implementation. It is not a substitute for signed
identity, access controls, durable storage, or an external trusted timestamp.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any


def canonical_json(value: Any) -> bytes:
    # Deterministic subset for Python JSON values. For cross-language canonical
    # JSON, replace this with a standards-compliant RFC 8785 JCS implementation.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_file(path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while chunk := stream.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


class ProvenanceLedger:
    """Append-only JSONL ledger; each event commits to the prior event hash."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _last_hash(self) -> str | None:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return None
        with self.path.open("rb") as stream:
            last = None
            for line in stream:
                if line.strip():
                    last = line
        if last is None:
            return None
        return json.loads(last)["event_hash"]

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        if "event_hash" in event or "previous_hash" in event:
            raise ValueError("Ledger-owned hash fields cannot be supplied by callers")
        record = dict(event)
        record["previous_hash"] = self._last_hash()
        record["event_hash"] = sha256_bytes(canonical_json(record))
        line = canonical_json(record) + b"\n"
        # O_APPEND prevents ordinary writes from overwriting prior events.
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            with os.fdopen(fd, "ab", closefd=False) as stream:
                stream.write(line)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(fd)
        return record

    def verify(self) -> dict[str, Any]:
        previous = None
        count = 0
        if not self.path.exists():
            return {"valid": True, "events": 0, "head_hash": None}
        with self.path.open("rb") as stream:
            for number, line in enumerate(stream, start=1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    return {"valid": False, "events": count, "line": number, "reason": "invalid_json"}
                supplied_hash = record.pop("event_hash", None)
                if record.get("previous_hash") != previous:
                    return {"valid": False, "events": count, "line": number, "reason": "previous_hash_mismatch"}
                expected_hash = sha256_bytes(canonical_json(record))
                if supplied_hash != expected_hash:
                    return {"valid": False, "events": count, "line": number, "reason": "event_hash_mismatch"}
                previous = supplied_hash
                count += 1
        return {"valid": True, "events": count, "head_hash": previous}


def transformation_event(
    *,
    inputs: list[dict[str, str]],
    outputs: list[dict[str, str]],
    tool_name: str,
    tool_version: str,
    parameters: dict[str, Any],
    status: str,
    run_id: str,
    policy_decision: str,
) -> dict[str, Any]:
    """Build an explicit provenance edge; input/output entries require id+sha256."""
    if not inputs:
        raise ValueError("A transformation must declare at least one input asset")
    for group_name, group in (("inputs", inputs), ("outputs", outputs)):
        for asset in group:
            if not asset.get("asset_id") or not asset.get("sha256"):
                raise ValueError(f"Every {group_name} asset requires asset_id and sha256")
    return {
        "event_type": "TRANSFORMATION_RECORDED",
        "run_id": run_id,
        "inputs": inputs,
        "outputs": outputs,
        "tool": {"name": tool_name, "version": tool_version},
        "parameters": parameters,
        "status": status,
        "policy_decision": policy_decision,
    }
