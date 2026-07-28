#!/usr/bin/env python3
"""Create the write-once R4.5 Stage-B lock before target reveal."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from integrity import (
    CAMPAIGN_IDS,
    DESCRIPTIVE_IDS,
    HISTORICAL_NON_EVALUATED_IDS,
    INFERENTIAL_IDS,
    NEW_IDS,
    PACKAGE,
    RECEIPTS,
    REGISTERED_IDS,
    ROOT,
    dataset_root,
    exclusive_write_json,
    expected_outcome_binding,
    read_json,
    required_final_paths,
    sha256,
)


TEXT_SUFFIXES = {".json", ".md", ".py", ".txt"}


def file_record(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(path)
    return {"bytes": path.stat().st_size, "sha256": sha256(path)}


def relative(path: Path) -> str:
    return str(path.relative_to(PACKAGE)).replace("\\", "/")


def main() -> None:
    output = RECEIPTS / "R4_5_LOCAL_LOCK.json"
    if output.exists():
        raise FileExistsError(f"write-once lock already exists: {output}")

    config = read_json(ROOT / "config" / "r4_5_contract.json")
    if (
        config.get("registered_ids") != REGISTERED_IDS
        or config.get("inferential_ids") != INFERENTIAL_IDS
        or config.get("descriptive_ids") != DESCRIPTIVE_IDS
        or config.get("campaign_ids") != CAMPAIGN_IDS
        or config.get("historical_non_evaluated_ids")
        != HISTORICAL_NON_EVALUATED_IDS
    ):
        raise RuntimeError("R4.5 config denominator/role mismatch")

    batch_path = RECEIPTS / "R4_5_PRE_REVEAL_BATCH.json"
    batch = read_json(batch_path)
    if (
        batch.get("status") != "R4_5_PRE_REVEAL_ROUTES_FROZEN"
        or batch.get("campaign_denominator") != CAMPAIGN_IDS
        or batch.get("historical_non_evaluated_denominator")
        != HISTORICAL_NON_EVALUATED_IDS
        or batch.get("registered_denominator") != REGISTERED_IDS
        or batch.get("inferential_denominator") != INFERENTIAL_IDS
        or batch.get("descriptive_denominator") != DESCRIPTIVE_IDS
        or batch.get("target_outcomes_semantically_opened") is not False
    ):
        raise RuntimeError("pre-reveal batch contract mismatch")

    files = required_final_paths()
    if len({relative(path) for path in files}) != len(files):
        raise RuntimeError("required_final_paths contains duplicates")

    routes: dict[str, str] = {}
    bindings: dict[str, dict[str, Any]] = {}
    for dataset_id in REGISTERED_IDS:
        prepared_dataset = dataset_root(dataset_id)
        frozen_dataset = (
            ROOT / "registered_census" / f"uci_{dataset_id}"
        )
        preparation_path = (
            prepared_dataset / "PREPARATION_RECEIPT.json"
        )
        source_receipt_path = (
            frozen_dataset / "SOURCE_FREEZE_RECEIPT.json"
        )
        frozen_path = frozen_dataset / "FROZEN_POLICY.joblib"
        actions_path = frozen_dataset / "SEALED_TARGET_ACTIONS.npz"
        if preparation_path not in files:
            raise RuntimeError(
                f"preparation receipt missing from required paths: {dataset_id}"
            )

        receipt = read_json(source_receipt_path)
        route = str(receipt.get("route"))
        expected_routes = (
            {"DESCRIPTIVE_REPLAY"}
            if dataset_id in DESCRIPTIVE_IDS
            else {"ACT", "ABSTAIN"}
        )
        if (
            receipt.get("dataset_id") != dataset_id
            or route not in expected_routes
            or receipt.get("target_outcomes_semantically_opened")
            is not False
            or receipt.get("frozen_policy_sha256")
            != sha256(frozen_path)
            or receipt.get("sealed_target_actions_sha256")
            != sha256(actions_path)
        ):
            raise RuntimeError(
                f"source freeze receipt mismatch: {dataset_id}"
            )
        binding = expected_outcome_binding(dataset_id)
        if receipt.get("target_outcome_binding_from_preparation") != binding:
            raise RuntimeError(
                f"target outcome binding mismatch: {dataset_id}"
            )
        routes[str(dataset_id)] = route
        bindings[str(dataset_id)] = binding

    inferential_act_count = sum(
        routes[str(dataset_id)] == "ACT"
        for dataset_id in INFERENTIAL_IDS
    )
    new_source_act_count = sum(
        routes[str(dataset_id)] == "ACT" for dataset_id in NEW_IDS
    )
    if (
        batch.get("routes") != routes
        or batch.get("inferential_source_act_count")
        != inferential_act_count
        or batch.get("new_source_act_count") != new_source_act_count
    ):
        raise RuntimeError("batch routes are not derived-file consistent")
    minimum_source_act = int(config["minimum_source_act"])
    minimum_new_source_act = int(config["minimum_new_source_act"])
    if inferential_act_count < minimum_source_act:
        raise RuntimeError(
            "R4.5 pre-reveal viability failed: "
            f"{inferential_act_count} inferential ACT routes, "
            f"minimum {minimum_source_act}; lock and reveal refused"
        )
    if new_source_act_count < minimum_new_source_act:
        raise RuntimeError(
            "R4.5 pre-reveal new-data viability failed: "
            f"{new_source_act_count} new ACT routes, "
            f"minimum {minimum_new_source_act}; lock and reveal refused"
        )

    file_records = {relative(path): file_record(path) for path in files}
    public_text_paths = sorted(
        [
            relative(path)
            for path in files
            if path.suffix.lower() in TEXT_SUFFIXES
        ]
        + [relative(output)]
    )

    payload = {
        "schema": "cacl-oc-r4.5-local-lock-v1",
        "status": "R4_5_LOCKED_PENDING_EXTERNAL_TIMESTAMP",
        "target_outcome_reveal_permitted": False,
        "campaign_ids": CAMPAIGN_IDS,
        "historical_non_evaluated_ids": HISTORICAL_NON_EVALUATED_IDS,
        "registered_ids": REGISTERED_IDS,
        "inferential_ids": INFERENTIAL_IDS,
        "descriptive_ids": DESCRIPTIVE_IDS,
        "source_routes": routes,
        "inferential_source_act_count": inferential_act_count,
        "new_source_act_count": new_source_act_count,
        "minimum_source_act": minimum_source_act,
        "minimum_new_source_act": minimum_new_source_act,
        "target_outcome_bindings": bindings,
        "files": file_records,
        "public_text_paths": public_text_paths,
    }
    exclusive_write_json(output, payload)
    print(payload["status"])
    print(f"receipt_sha256={sha256(output)}")


if __name__ == "__main__":
    main()
