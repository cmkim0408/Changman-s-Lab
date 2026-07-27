#!/usr/bin/env python3
"""Hash-lock R4 before any target-outcome reveal."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PACKAGE = ROOT.parent
R3 = PACKAGE / "23_CACL_VPC_UCI_CENSUS_BATCH"
REGISTERED_IDS = [75, 327, 572]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> None:
    files = [
        ROOT / "R4_PROTOCOL.md",
        ROOT / "requirements-lock.txt",
        ROOT / "config" / "r4_contract.json",
        ROOT / "code" / "cacl_oc_engine.py",
        ROOT / "code" / "freeze_r4_lock.py",
        ROOT / "receipts" / "R4_PRE_REVEAL_BATCH.json",
        R3 / "receipts" / "R3_SOURCE_STOP_AUDIT.json",
    ]
    for dataset_id in REGISTERED_IDS:
        output = ROOT / "registered_census" / f"uci_{dataset_id}"
        files.extend(
            [
                output / "SOURCE_FREEZE_RECEIPT.json",
                output / "FROZEN_POLICY.joblib",
                output / "SEALED_TARGET_ACTIONS.npz",
            ]
        )
    payload = {
        "schema": "cacl-oc-r4-local-lock-v1",
        "status": "R4_LOCKED_PENDING_EXTERNAL_TIMESTAMP",
        "target_outcome_reveal_permitted": False,
        "registered_ids": REGISTERED_IDS,
        "source_routes": {"75": "ACT", "327": "ACT", "572": "ABSTAIN"},
        "files": {
            str(path.relative_to(PACKAGE)).replace("\\", "/"): {
                "bytes": path.stat().st_size,
                "sha256": sha256(path),
            }
            for path in files
        },
    }
    output = ROOT / "receipts" / "R4_LOCAL_LOCK.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(payload["status"])
    print(f"receipt_sha256={sha256(output)}")


if __name__ == "__main__":
    main()
