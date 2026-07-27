#!/usr/bin/env python3
"""Bind the campaign-record search for prior instance access before Stage A."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from integrity import (
    NEW_IDS,
    PACKAGE,
    RECEIPTS,
    exclusive_write_json,
    read_json,
    sha256,
    validate_r4_2_invalidation_provenance,
    validate_r4_3_invalidation_provenance,
)


R1_SELECTION = (
    PACKAGE
    / "21_CACL_VPC_UCI_CLOSED_BATCH"
    / "receipts"
    / "PHASE2_SELECTION_RECEIPT.json"
)
R1_PREPARATION = (
    PACKAGE
    / "21_CACL_VPC_UCI_CLOSED_BATCH"
    / "receipts"
    / "PHASE3_PREPARATION_RECEIPT.json"
)
R1_FINAL = (
    PACKAGE
    / "21_CACL_VPC_UCI_CLOSED_BATCH"
    / "receipts"
    / "BATCH1_FINAL_AUDIT.json"
)
R2_LOCK = (
    PACKAGE
    / "22_CACL_VPC_UCI_BINARY_VERIFIED_BATCH"
    / "receipts"
    / "R2_LOCAL_LOCK.json"
)
R2_CODE = (
    PACKAGE
    / "22_CACL_VPC_UCI_BINARY_VERIFIED_BATCH"
    / "code"
    / "r2_binary_verify_select.py"
)
R2_LEDGER = (
    PACKAGE
    / "22_CACL_VPC_UCI_BINARY_VERIFIED_BATCH"
    / "registry_snapshot"
    / "R2_BINARY_VERIFIED_ELIGIBILITY.csv"
)
R2_SELECTION = (
    PACKAGE
    / "22_CACL_VPC_UCI_BINARY_VERIFIED_BATCH"
    / "receipts"
    / "R2_SELECTION_RECEIPT.json"
)


def relative(path: Path) -> str:
    return str(path.relative_to(PACKAGE)).replace("\\", "/")


def record(path: Path) -> dict[str, Any]:
    return {
        "relative_path": relative(path),
        "bytes": path.stat().st_size,
        "sha256": sha256(path),
    }


def candidate_path_hits() -> list[str]:
    hits: list[str] = []
    tokens = tuple(
        token
        for dataset_id in NEW_IDS
        for token in (f"uci_{dataset_id}", f"uci-{dataset_id}")
    )
    for path in PACKAGE.rglob("*"):
        if path.is_file():
            relative_path = relative(path)
            if any(token in relative_path.lower() for token in tokens):
                hits.append(relative_path)
    return sorted(hits)


def main() -> None:
    output = RECEIPTS / "R4_4_PRIOR_ACCESS_AUDIT_V2.json"
    if output.exists():
        raise FileExistsError(f"write-once access audit exists: {output}")

    r1_selection = read_json(R1_SELECTION)
    r1_preparation = read_json(R1_PREPARATION)
    r1_final = read_json(R1_FINAL)
    r1_selected = [
        int(value)
        for value in r1_selection["selected_ids_in_draw_order"]
    ]
    r1_prepared = [
        int(row["uci_id"]) for row in r1_preparation["datasets"]
    ]
    r1_audited = [
        int(row["uci_id"]) for row in r1_final["datasets"]
    ]

    r2_lock = read_json(R2_LOCK)
    r2_selection = read_json(R2_SELECTION)
    with R2_LEDGER.open("r", encoding="utf-8-sig", newline="") as handle:
        r2_rows = list(csv.DictReader(handle))
    r2_fetched = [int(row["uci_id"]) for row in r2_rows]

    allowed_path_hits = sorted(
        [
            (
                f"21_CACL_VPC_UCI_CLOSED_BATCH/registry_snapshot/"
                f"metadata/uci_{dataset_id}.json"
            )
            for dataset_id in NEW_IDS
        ]
        + [
            (
                f"22_CACL_VPC_UCI_BINARY_VERIFIED_BATCH/"
                f"registry_snapshot/metadata/uci_{dataset_id}.json"
            )
            for dataset_id in NEW_IDS
        ]
        + [
            (
                "28_CACL_OC_UCI_EXPANDED_R4_4/registration/"
                "uci_942_official_taxonomy.json"
            )
        ]
    )
    observed_path_hits = candidate_path_hits()
    candidate_set = set(NEW_IDS)
    r4_2 = validate_r4_2_invalidation_provenance()
    r4_3 = validate_r4_3_invalidation_provenance()
    checks = {
        "r1_selection_exact": (
            r1_selection.get("schema")
            == "cacl-vpc-uci-phase2-selection-v1"
            and r1_selection.get("status") == "REGISTERED_BATCH_SELECTED"
            and r1_selected == [146, 31, 80, 365]
            and r1_selection.get("replacement_permitted") is False
        ),
        "r1_preparation_exact": (
            r1_preparation.get("schema")
            == "cacl-vpc-uci-registered-batch-preparation-v1"
            and r1_prepared == r1_selected
            and r1_preparation.get("selection_receipt_sha256")
            == sha256(R1_SELECTION)
        ),
        "r1_final_exact": (
            r1_final.get("schema")
            == "cacl-vpc-uci-batch1-final-audit-v1"
            and r1_audited == r1_selected
            and r1_final.get("datasets_replaced") is False
            and r1_final.get("artifact_hashes", {}).get(
                "selection_receipt"
            )
            == sha256(R1_SELECTION)
            and r1_final.get("artifact_hashes", {}).get(
                "preparation_receipt"
            )
            == sha256(R1_PREPARATION)
        ),
        "r1_candidate_intersection_empty": (
            not candidate_set.intersection(r1_selected)
            and not candidate_set.intersection(r1_prepared)
            and not candidate_set.intersection(r1_audited)
        ),
        "r2_lock_binds_fetch_code": (
            r2_lock.get("schema") == "cacl-vpc-uci-r2-local-lock-v1"
            and r2_lock.get("files", {})
            .get(relative(R2_CODE), {})
            .get("sha256")
            == sha256(R2_CODE)
        ),
        "r2_selection_binds_code_and_ledger": (
            r2_selection.get("schema") == "cacl-vpc-uci-r2-selection-v1"
            and r2_selection.get("code_sha256") == sha256(R2_CODE)
            and r2_selection.get("artifacts", {}).get(
                "binary_verified_ledger"
            )
            == sha256(R2_LEDGER)
            and r2_selection.get("replacement_permitted") is False
        ),
        "r2_fetched_denominator_exact": (
            r2_fetched == [75, 107, 327, 572]
        ),
        "r2_candidate_intersection_empty": (
            not candidate_set.intersection(r2_fetched)
        ),
        "r4_2_prior_failure_provenance_exact": r4_2["passes"],
        "r4_3_prior_failure_provenance_exact": (
            r4_3["passes"]
            and read_json(
                PACKAGE
                / "27_CACL_OC_UCI_EXPANDED_R4_3"
                / "receipts"
                / "R4_3_STAGE_A_DATA_ELIGIBILITY_INVALIDATION.json"
            ).get("uci967_instance_data_read_reached")
            is False
        ),
        "candidate_path_hits_metadata_or_registration_only": (
            observed_path_hits == allowed_path_hits
        ),
    }
    if not all(checks.values()):
        failed = [name for name, value in checks.items() if not value]
        raise RuntimeError(
            "prior-access audit failed: " + ", ".join(failed)
        )

    payload = {
        "schema": "cacl-oc-r4.4-prior-access-audit-v2",
        "status": "NO_INSTANCE_TRACE_FOUND_IN_AUDITED_CAMPAIGN_PATHS",
        "candidate_ids": NEW_IDS,
        "claim_boundary": (
            "This is a reproducible search of recorded campaign paths and "
            "candidate-ID filenames in the shared package. It is not proof "
            "of absolute non-access, independent custody, or the absence "
            "of unrecorded access outside the audited workspace."
        ),
        "checks": checks,
        "passes": True,
        "r1_selected_and_prepared_ids": r1_selected,
        "r2_instance_fetch_ledger_ids": r2_fetched,
        "candidate_path_hits": observed_path_hits,
        "allowed_metadata_or_registration_paths": allowed_path_hits,
        "evidence": {
            "r1_selection": record(R1_SELECTION),
            "r1_preparation": record(R1_PREPARATION),
            "r1_final": record(R1_FINAL),
            "r2_lock": record(R2_LOCK),
            "r2_fetch_code": record(R2_CODE),
            "r2_verified_ledger": record(R2_LEDGER),
            "r2_selection": record(R2_SELECTION),
        },
        "r4_2_invalidation_lock_sha256": r4_2["lock_sha256"],
        "r4_2_invalidation_ack_sha256": r4_2["ack_sha256"],
        "r4_3_invalidation_lock_sha256": r4_3["lock_sha256"],
        "r4_3_invalidation_ack_sha256": r4_3["ack_sha256"],
    }
    exclusive_write_json(output, payload)
    print(payload["status"])


if __name__ == "__main__":
    main()
