#!/usr/bin/env python3
"""Freeze the R4.5 metadata screen and recorded-workspace access census."""

from __future__ import annotations

import csv
import json
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
    validate_r4_4_invalidation_provenance,
)


R1 = PACKAGE / "21_CACL_VPC_UCI_CLOSED_BATCH"
R2 = PACKAGE / "22_CACL_VPC_UCI_BINARY_VERIFIED_BATCH"
R1_SELECTION = R1 / "receipts" / "PHASE2_SELECTION_RECEIPT.json"
R1_PREPARATION = R1 / "receipts" / "PHASE3_PREPARATION_RECEIPT.json"
R1_FINAL = R1 / "receipts" / "BATCH1_FINAL_AUDIT.json"
R2_LOCK = R2 / "receipts" / "R2_LOCAL_LOCK.json"
R2_CODE = R2 / "code" / "r2_binary_verify_select.py"
R2_LEDGER = (
    R2
    / "registry_snapshot"
    / "R2_BINARY_VERIFIED_ELIGIBILITY.csv"
)
R2_SELECTION = R2 / "receipts" / "R2_SELECTION_RECEIPT.json"
METADATA = R2 / "registry_snapshot" / "metadata"


def relative(path: Path) -> str:
    return str(path.relative_to(PACKAGE)).replace("\\", "/")


def record(path: Path) -> dict[str, Any]:
    return {
        "relative_path": relative(path),
        "bytes": path.stat().st_size,
        "sha256": sha256(path),
    }


def candidate_path_hits() -> list[str]:
    tokens = tuple(
        token
        for dataset_id in NEW_IDS
        for token in (f"uci_{dataset_id}", f"uci-{dataset_id}")
    )
    hits: list[str] = []
    for path in PACKAGE.rglob("*"):
        if path.is_file():
            candidate = relative(path)
            if any(token in candidate.lower() for token in tokens):
                hits.append(candidate)
    return sorted(hits)


def metadata_screen_row(path: Path) -> dict[str, Any]:
    envelope = read_json(path)
    metadata = envelope.get("data", {})
    variables = metadata.get("variables")
    variables = variables if isinstance(variables, list) else []
    features = [
        value for value in variables if value.get("role") == "Feature"
    ]
    targets = [
        value for value in variables if value.get("role") == "Target"
    ]
    dataset_id = int(metadata.get("uci_id", -1))
    gates = {
        "metadata_status_200": envelope.get("status") == 200,
        "classification_task": (
            "Classification" in (metadata.get("tasks") or [])
        ),
        "single_metadata_binary_target": (
            len(targets) == 1 and targets[0].get("type") == "Binary"
        ),
        "features_20_to_500": (
            20 <= int(metadata.get("num_features") or 0) <= 500
        ),
        "rows_4000_to_100000": (
            4000 <= int(metadata.get("num_instances") or 0) <= 100000
        ),
        "all_predictors_numeric": (
            bool(features)
            and all(
                value.get("type")
                in {"Binary", "Integer", "Continuous", "Real"}
                for value in features
            )
        ),
        "metadata_declares_no_missing": (
            str(metadata.get("has_missing_values")).lower() == "no"
            and all(
                str(value.get("missing_values")).lower() == "no"
                for value in features + targets
            )
        ),
        "exact_official_static_csv": (
            metadata.get("data_url")
            == (
                "https://archive.ics.uci.edu/static/public/"
                f"{dataset_id}/data.csv"
            )
        ),
    }
    return {
        "uci_id": dataset_id,
        "name": metadata.get("name"),
        "metadata": record(path),
        "gates": gates,
        "eligible": all(gates.values()),
    }


def main() -> None:
    access_output = RECEIPTS / "R4_5_PRIOR_ACCESS_AUDIT.json"
    screen_output = RECEIPTS / "R4_5_METADATA_SCREEN.json"
    if access_output.exists() or screen_output.exists():
        raise FileExistsError("write-once R4.5 audit receipt exists")

    metadata_paths = sorted(
        METADATA.glob("uci_*.json"),
        key=lambda path: int(path.stem.split("_")[1]),
    )
    screen_rows = [metadata_screen_row(path) for path in metadata_paths]
    eligible_ids = [
        int(row["uci_id"]) for row in screen_rows if row["eligible"]
    ]
    if len(screen_rows) != 208 or eligible_ids != [94, 350]:
        raise RuntimeError(
            "frozen 208-metadata screen denominator or result changed"
        )

    prior_instance_evidence = {
        "94": record(
            PACKAGE
            / "14_CACL_THREE_CYCLE_EXTENSION"
            / "closing_spambase"
            / "source_data"
            / "uci_94_spambase.zip"
        ),
        "350": record(
            PACKAGE
            / "13_CACL_1_0_CONSOLIDATION"
            / "operational_final"
            / "source_data"
            / "uci_350_credit_default.zip"
        ),
    }
    screen_receipt = {
        "schema": "cacl-oc-r4.5-frozen-metadata-screen-v1",
        "status": "NO_ADDITIONAL_UNTOUCHED_TASK_FROM_FROZEN_SCREEN",
        "screen_denominator": len(screen_rows),
        "screen_rule": {
            "task": "Classification",
            "target": "exactly one metadata Binary target",
            "features": "20 to 500 inclusive; all Binary/Integer/Continuous/Real",
            "rows": "4000 to 100000 inclusive",
            "missingness": "dataset, feature and target metadata all no",
            "transport": "exact official HTTPS static CSV URL",
        },
        "rows": screen_rows,
        "metadata_eligible_ids": eligible_ids,
        "eligible_ids_with_recorded_instance_artifacts": [94, 350],
        "additional_selected_ids": [],
        "carry_forward_outside_screen": {
            "uci_id": 967,
            "reason": (
                "pre-registered in R4.2-R4.4; R4.4 preprocessing is "
                "unchanged and all three invalidation chains record no "
                "UCI967 instance access"
            ),
        },
        "prior_instance_evidence": prior_instance_evidence,
        "claim_boundary": (
            "The screen is exhaustive only for the frozen 208-file "
            "metadata snapshot and the exact declared rule."
        ),
    }
    exclusive_write_json(screen_output, screen_receipt)

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
        r2_fetched = [
            int(row["uci_id"]) for row in csv.DictReader(handle)
        ]

    observed_hits = candidate_path_hits()
    allowed_hits = [
        "21_CACL_VPC_UCI_CLOSED_BATCH/registry_snapshot/metadata/uci_967.json",
        "22_CACL_VPC_UCI_BINARY_VERIFIED_BATCH/registry_snapshot/metadata/uci_967.json",
    ]
    r4_2 = validate_r4_2_invalidation_provenance()
    r4_3 = validate_r4_3_invalidation_provenance()
    r4_4 = validate_r4_4_invalidation_provenance()
    candidate_set = set(NEW_IDS)
    checks = {
        "new_ids_exact": NEW_IDS == [967],
        "r1_selection_exact": (
            r1_selection.get("schema")
            == "cacl-vpc-uci-phase2-selection-v1"
            and r1_selected == [146, 31, 80, 365]
            and r1_prepared == r1_selected
            and r1_audited == r1_selected
        ),
        "r1_candidate_intersection_empty": (
            not candidate_set.intersection(r1_selected)
        ),
        "r2_lock_binds_fetch_code": (
            r2_lock.get("schema") == "cacl-vpc-uci-r2-local-lock-v1"
            and r2_lock.get("files", {})
            .get(relative(R2_CODE), {})
            .get("sha256")
            == sha256(R2_CODE)
        ),
        "r2_selection_binds_code_and_ledger": (
            r2_selection.get("schema")
            == "cacl-vpc-uci-r2-selection-v1"
            and r2_selection.get("code_sha256") == sha256(R2_CODE)
            and r2_selection.get("artifacts", {}).get(
                "binary_verified_ledger"
            )
            == sha256(R2_LEDGER)
        ),
        "r2_fetched_denominator_exact": (
            r2_fetched == [75, 107, 327, 572]
        ),
        "r2_candidate_intersection_empty": (
            not candidate_set.intersection(r2_fetched)
        ),
        "r4_2_no_uci967_access": r4_2["passes"],
        "r4_3_no_uci967_access": r4_3["passes"],
        "r4_4_no_uci967_access": r4_4["passes"],
        "candidate_path_hits_metadata_only": (
            observed_hits == allowed_hits
        ),
    }
    if not all(checks.values()):
        failed = [key for key, value in checks.items() if not value]
        raise RuntimeError(
            "R4.5 prior-access audit failed: " + ", ".join(failed)
        )

    receipt = {
        "schema": "cacl-oc-r4.5-prior-access-audit-v1",
        "status": "NO_RECORDED_UCI967_INSTANCE_TRACE_FOUND",
        "candidate_ids": NEW_IDS,
        "checks": checks,
        "passes": True,
        "r1_selected_prepared_audited_ids": r1_selected,
        "r2_instance_fetch_ledger_ids": r2_fetched,
        "candidate_path_hits": observed_hits,
        "allowed_metadata_paths": allowed_hits,
        "metadata_screen": record(screen_output),
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
        "r4_3_invalidation_lock_sha256": r4_3["lock_sha256"],
        "r4_4_invalidation_lock_sha256": r4_4["lock_sha256"],
        "claim_boundary": (
            "This is a reproducible census of recorded paths and locked "
            "campaign receipts. It is not proof of absolute non-access, "
            "independent custody, or unrecorded activity outside the "
            "shared workspace."
        ),
    }
    exclusive_write_json(access_output, receipt)
    print(receipt["status"])


if __name__ == "__main__":
    main()
