# Post-Agent Review TUI

The post-agent review TUI is a read-only review surface for agent-produced result packets. It separates **reported results** from **raw observations** and checks whether observations carry enough provenance and metrology metadata to be independently inspected.

## Run

```bash
python tools/post_agent_tui.py examples/post-agent-measurement-packet.json
python tools/post_agent_tui.py examples/post-agent-measurement-packet.json --json
python tools/post_agent_tui.py examples/post-agent-measurement-packet.json --write-audit review.json
python -m unittest discover -s tests -p 'test_post_agent_tui.py' -v
```

Exit codes: `0` means schema-level auditability checks pass; `1` means review flags or missing evidence; `2` means the packet could not be read or parsed. PASS is not scientific validation.

## Packet contract

- `reported_results`: agent claims or derived outputs, with optional linked observation IDs.
- `raw_observations`: original values plus unit, timestamp, method, instrument, source, and source SHA-256.
- Calibration, uncertainty, replicate ID, and operator/automation are recommended fields and will be flagged when absent.
- Packet and per-observation canonical JSON hashes are emitted for audit references.

Example:

```json
{
  "packet_id": "demo-001",
  "reported_results": [
    {"name": "ratio_r", "value": 0.5, "unit": "ratio", "precision": 3, "observation_ids": ["obs-001"]}
  ],
  "raw_observations": [
    {
      "id": "obs-001",
      "value": 0.5,
      "unit": "ratio",
      "observed_at": "2026-10-12T08:00:00Z",
      "method": "documented computation",
      "instrument": "python-stdlib",
      "source": "fixtures/raw-input.json",
      "raw_value": "{\"a\": 1, \"b\": 1}",
      "source_sha256": "REPLACE_WITH_REAL_64_CHARACTER_SHA256",
      "calibration": "not-applicable: deterministic arithmetic fixture",
      "uncertainty": "not applicable to exact arithmetic; input uncertainty not supplied",
      "replicate_id": "run-001",
      "operator_or_automation": "fixture"
    }
  ]
}
```

The example hash is a placeholder, not a valid digest. Replace it with the hash of the actual raw source bytes before expecting a clean review.

## Review semantics

- Missing raw observations never pass merely because a reported result has three decimal places.
- Missing required metadata or non-finite values fail the schema-level check.
- Missing recommended metadata, missing source hashes, or malformed source hashes require review.
- Duplicate observation IDs are flagged.
- Content hashes establish identity/integrity of the bytes that were hashed; they do not establish that the source is authentic, calibrated, representative, or true.
- The tool does not execute packet content, invoke agent tools, approve actions, or infer truth.

An independent reviewer should inspect the actual raw source bytes, collection method, instrument/calibration record, units, uncertainty model, replicate structure, transforms, and the link between each reported result and its source observations. A formatted decimal is presentation, not metrology.
