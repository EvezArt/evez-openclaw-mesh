import json
from pathlib import Path

import pytest

from evez_assets.provenance_ledger import ProvenanceLedger, transformation_event, hash_file


def test_ledger_appends_and_verifies_chain(tmp_path: Path):
    ledger = ProvenanceLedger(tmp_path / "events.jsonl")
    first = ledger.append({"event_type": "ASSET_CAPTURED", "asset_id": "a1", "sha256": "abc"})
    second = ledger.append({"event_type": "TRANSFORMATION_RECORDED", "run_id": "r1"})
    assert first["previous_hash"] is None
    assert second["previous_hash"] == first["event_hash"]
    assert ledger.verify()["valid"] is True
    assert ledger.verify()["events"] == 2


def test_ledger_detects_payload_tampering(tmp_path: Path):
    path = tmp_path / "events.jsonl"
    ledger = ProvenanceLedger(path)
    ledger.append({"event_type": "ASSET_CAPTURED", "asset_id": "a1"})
    row = json.loads(path.read_text())
    row["asset_id"] = "rewritten"
    path.write_text(json.dumps(row) + "\n")
    result = ledger.verify()
    assert result["valid"] is False
    assert result["reason"] == "event_hash_mismatch"


def test_caller_cannot_set_chain_fields(tmp_path: Path):
    ledger = ProvenanceLedger(tmp_path / "events.jsonl")
    with pytest.raises(ValueError):
        ledger.append({"event_type": "FAKE", "event_hash": "chosen"})


def test_transformation_requires_provenance_assets():
    with pytest.raises(ValueError):
        transformation_event(
            inputs=[], outputs=[], tool_name="x", tool_version="1",
            parameters={}, status="success", run_id="r", policy_decision="allow"
        )


def test_transformation_requires_hashes():
    with pytest.raises(ValueError):
        transformation_event(
            inputs=[{"asset_id": "source"}], outputs=[],
            tool_name="x", tool_version="1", parameters={},
            status="success", run_id="r", policy_decision="allow"
        )


def test_hash_file(tmp_path: Path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"prima materia")
    assert hash_file(source) == "e2a43e71f2c70e4d2bdb7e4d4b87e5e2d6d91d0f8bb6c2f78b7e3e3f2d9b1a4e"
