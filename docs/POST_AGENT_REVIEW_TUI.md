# Post-Agent Review Tools

## Easiest option: browser reviewer

Open [`tools/post-agent-review.html`](../tools/post-agent-review.html) in a modern browser. Paste JSON or load a local JSON file, then choose **Review evidence**. It runs locally in the browser tab and does not upload the packet. Browser SHA-256 verification uses Web Crypto, so use localhost or HTTPS if opening directly from a file does not expose the API. The HTML reviewer displays bounded raw-source previews and can export the audit JSON. Its packet digest is computed over the browser's parsed JSON serialization; it is not a byte-for-byte hash of the original packet file.

The command-line reviewer remains available below.

## Command-line reviewer

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
- `raw_observations`: original values plus unit, timestamp, method, instrument, source, source SHA-256, and the actual source bytes in `source_content` (UTF-8 text) or `source_bytes_base64` (arbitrary bytes).
- Exactly one of `source_content` or `source_bytes_base64` should be supplied for a source to pass the byte-integrity check. The TUI computes SHA-256 over those exact bytes and compares it with `source_sha256`; a valid-looking 64-character digest by itself is not enough.
- Calibration, uncertainty, replicate ID, and operator/automation are recommended fields and will be flagged when absent.
- Each reported result must link to existing observation IDs. Missing or dangling links are review flags.
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
      "raw_value": "a=1;b=2",
      "source_content": "a=1;b=2",
      "source_sha256": "REPLACE_WITH_SHA256_OF_EXACT_UTF8_SOURCE_CONTENT",
      "calibration": "not-applicable: deterministic arithmetic fixture",
      "uncertainty": "not applicable to exact arithmetic; input uncertainty not supplied",
      "replicate_id": "run-001",
      "operator_or_automation": "fixture"
    }
  ]
}
```

The example hash is a placeholder, not a valid digest. Compute it from the exact UTF-8 bytes of `source_content` (or decode `source_bytes_base64` and hash those bytes). The digest must match exactly for the source-byte integrity check to pass.

## Review semantics

- Missing raw observations never pass merely because a reported result has three decimal places.
- Missing required metadata or non-finite values fail the schema-level check.
- Missing recommended metadata or missing source bytes require review.
- Malformed hashes, mismatches between declared and computed source hashes, and malformed base64 fail the corresponding observation.
- Duplicate observation IDs and missing/dangling result-to-observation links are flagged.
- Content hashes establish identity/integrity of the bytes that were hashed; they do not establish that the source is authentic, calibrated, representative, or true.
- The tool does not execute packet content, invoke agent tools, approve actions, or infer truth.

An independent reviewer should inspect the actual raw source bytes, collection method, instrument/calibration record, units, uncertainty model, replicate structure, transforms, and the link between each reported result and its source observations. A formatted decimal is presentation, not metrology.
