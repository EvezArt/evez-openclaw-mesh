"""Minimal local-first EVEZ asset-ingest and compound-runner harness.

Usage:
  python -m evez_assets.compound_runner ingest ./input --store ./evez-store
  python -m evez_assets.compound_runner verify --store ./evez-store
  python -m evez_assets.compound_runner tui --store ./evez-store

This starter records original files and their digests. It does not execute untrusted
files or call external models. Media extraction plugins can be attached as separate,
versioned transformation workers.
"""
from __future__ import annotations

import argparse
import json
import mimetypes
import shutil
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from evez_assets.provenance_ledger import ProvenanceLedger, hash_file


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def ingest(source: Path, store: Path) -> int:
    if not source.exists():
        raise FileNotFoundError(source)
    asset_dir = store / "assets"
    asset_dir.mkdir(parents=True, exist_ok=True)
    ledger = ProvenanceLedger(store / "ledger.jsonl")
    files = [source] if source.is_file() else sorted(p for p in source.rglob("*") if p.is_file())
    count = 0
    for path in files:
        digest = hash_file(path)
        asset_id = "asset-" + digest[:20]
        destination = asset_dir / digest
        if not destination.exists():
            shutil.copyfile(path, destination)
        # Verify copied bytes before recording the asset as captured.
        if hash_file(destination) != digest:
            raise IOError(f"Digest mismatch after copying: {path}")
        mime, _ = mimetypes.guess_type(path.name)
        record = {
            "event_type": "ASSET_CAPTURED",
            "asset_id": asset_id,
            "sha256": digest,
            "original_name": path.name,
            "relative_source": str(path),
            "mime_type": mime or "application/octet-stream",
            "size_bytes": path.stat().st_size,
            "captured_at": utc_now(),
            "storage_path": str(destination),
        }
        ledger.append(record)
        count += 1
        print(f"CAPTURED {asset_id} {digest} {path.name}")
    print(f"RESULT assets_captured={count} ledger={store / 'ledger.jsonl'}")
    return count


def show_tui(store: Path) -> None:
    """A dependency-free terminal dashboard with an inspectable status snapshot."""
    ledger_path = store / "ledger.jsonl"
    ledger = ProvenanceLedger(ledger_path)
    verification = ledger.verify()
    rows = []
    if ledger_path.exists():
        for line in ledger_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rows.append(json.loads(line))
    captured = sum(row.get("event_type") == "ASSET_CAPTURED" for row in rows)
    transforms = sum(row.get("event_type") == "TRANSFORMATION_RECORDED" for row in rows)
    print("=" * 68)
    print("EVEZ / PHENOMENOLOGY OPERATIONS")
    print("=" * 68)
    print(f"Store:          {store.resolve()}")
    print(f"Ledger events:  {verification.get('events', 0)}")
    print(f"Captured assets:{captured:>5}")
    print(f"Transformations:{transforms:>5}")
    print(f"Chain verified: {'YES' if verification['valid'] else 'NO'}")
    print(f"Ledger head:    {verification.get('head_hash') or 'EMPTY'}")
    if not verification["valid"]:
        print(f"Integrity fault: line={verification.get('line')} reason={verification.get('reason')}")
    print("-" * 68)
    print("Recent events:")
    for row in rows[-12:]:
        print(f"  {row.get('event_type', 'UNKNOWN'):28} {row.get('asset_id', row.get('run_id', ''))}")
    print("-" * 68)
    print("Controls: ingest <path> | verify | tui")
    print("This TUI is read-only; it does not approve or execute external actions.")
    print("=" * 68)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    ingest_parser = sub.add_parser("ingest")
    ingest_parser.add_argument("source", type=Path)
    ingest_parser.add_argument("--store", type=Path, default=Path("./evez-store"))
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("--store", type=Path, default=Path("./evez-store"))
    tui_parser = sub.add_parser("tui")
    tui_parser.add_argument("--store", type=Path, default=Path("./evez-store"))
    args = parser.parse_args(argv)
    if args.command == "ingest":
        ingest(args.source, args.store)
        return 0
    if args.command == "verify":
        result = ProvenanceLedger(args.store / "ledger.jsonl").verify()
        print(json.dumps(result, indent=2))
        return 0 if result["valid"] else 2
    if args.command == "tui":
        show_tui(args.store)
        result = ProvenanceLedger(args.store / "ledger.jsonl").verify()
        return 0 if result["valid"] else 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
