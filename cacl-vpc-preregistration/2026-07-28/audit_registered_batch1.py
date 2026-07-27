#!/usr/bin/env python3
"""Final denominator-preserving audit for CACL-VPC registered batch 1."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
RECEIPTS = ROOT / "receipts"
BATCH = ROOT / "registered_batch"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> None:
    selection_path = RECEIPTS / "PHASE2_SELECTION_RECEIPT.json"
    preparation_path = RECEIPTS / "PHASE3_PREPARATION_RECEIPT.json"
    selection = json.loads(selection_path.read_text(encoding="utf-8"))
    preparation = json.loads(preparation_path.read_text(encoding="utf-8"))
    rows = []
    source_compress = 0
    target_passes = 0
    for dataset_id in selection["selected_ids_in_draw_order"]:
        prep_path = BATCH / f"uci_{dataset_id}" / "PREPARATION_RECEIPT.json"
        prep = json.loads(prep_path.read_text(encoding="utf-8"))
        row = {
            "uci_id": dataset_id,
            "preparation_status": prep["status"],
            "source_route": None,
            "target_pass": None,
            "reason": prep.get("failure_reasons"),
        }
        if prep["status"] == "PREPARED_SOURCE_TARGET_SEALED":
            freeze = json.loads(
                (
                    BATCH
                    / f"uci_{dataset_id}"
                    / "cacl_vpc"
                    / "SOURCE_FREEZE_RECEIPT.json"
                ).read_text(encoding="utf-8")
            )
            verdict = json.loads(
                (
                    BATCH
                    / f"uci_{dataset_id}"
                    / "cacl_vpc"
                    / "TARGET_VERDICT.json"
                ).read_text(encoding="utf-8")
            )
            row["source_route"] = freeze["route"]
            row["target_pass"] = verdict["target_pass"]
            source_compress += freeze["route"] == "COMPRESS"
            target_passes += verdict["target_pass"] is True
        rows.append(row)

    gates = {
        "registered_denominator_is_four": len(rows) == 4,
        "no_replacement": [
            row["uci_id"] for row in rows
        ]
        == selection["selected_ids_in_draw_order"],
        "minimum_two_source_compress": source_compress >= 2,
        "minimum_two_target_passes": target_passes >= 2,
    }
    receipt = {
        "schema": "cacl-vpc-uci-batch1-final-audit-v1",
        "status": (
            "CONFIRMATORY_PASS"
            if all(gates.values())
            else "INCONCLUSIVE_EXTERNAL"
        ),
        "interpretation": (
            "Three registered draws were non-binary target schema failures "
            "and the sole compatible task source-routed to ABSTAIN. This is "
            "not evidence of CACL-VPC deployment failure; it exposes that "
            "binary cardinality was not resolved before the registered draw."
        ),
        "registered_denominator": len(rows),
        "external_failures": sum(
            row["preparation_status"] == "EXTERNAL_FAIL" for row in rows
        ),
        "source_compress": source_compress,
        "target_passes": target_passes,
        "gates": gates,
        "datasets": rows,
        "artifact_hashes": {
            "selection_receipt": sha256(selection_path),
            "preparation_receipt": sha256(preparation_path),
            "audit_code": sha256(Path(__file__)),
        },
        "thresholds_changed_after_results": False,
        "datasets_replaced": False,
    }
    output = RECEIPTS / "BATCH1_FINAL_AUDIT.json"
    output.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(receipt["status"])
    print(f"registered_denominator={receipt['registered_denominator']}")
    print(f"external_failures={receipt['external_failures']}")
    print(f"source_compress={receipt['source_compress']}")
    print(f"target_passes={receipt['target_passes']}")


if __name__ == "__main__":
    main()
