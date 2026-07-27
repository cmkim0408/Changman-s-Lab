#!/usr/bin/env python3
"""Shared write-once, snapshot and hash-chain checks for CACL-OC R4.2."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import numpy as np


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PACKAGE = ROOT.parent
R3 = PACKAGE / "23_CACL_VPC_UCI_CENSUS_BATCH"
RECEIPTS = ROOT / "receipts"
REGISTERED_IDS = [75, 327, 572, 855, 967]
INFERENTIAL_IDS = [327, 572, 855, 967]
DESCRIPTIVE_IDS = [75]
NEW_IDS = [855, 967]
REPOSITORY = "cmkim0408/Changman-s-Lab"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def exclusive_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def _safe_package_path(relative: str) -> Path:
    candidate = (PACKAGE / relative).resolve()
    package = PACKAGE.resolve()
    if candidate != package and package not in candidate.parents:
        raise RuntimeError(f"lock path escapes package: {relative}")
    return candidate


def dataset_root(dataset_id: int) -> Path:
    if int(dataset_id) in NEW_IDS:
        return ROOT / "prepared_census" / f"uci_{dataset_id}"
    return R3 / "registered_census" / f"uci_{dataset_id}"


def preparation_receipt(dataset_id: int) -> dict[str, Any]:
    path = dataset_root(dataset_id) / "PREPARATION_RECEIPT.json"
    receipt = read_json(path)
    observed_id = receipt.get("uci_id")
    if observed_id != int(dataset_id):
        raise RuntimeError(f"preparation receipt ID mismatch: {dataset_id}")
    return receipt


def expected_artifact(dataset_id: int, name: str) -> dict[str, Any]:
    receipt = preparation_receipt(dataset_id)
    artifact = receipt["artifacts"][name]
    path = dataset_root(dataset_id) / name
    return {
        "relative_path": str(path.relative_to(PACKAGE)).replace("\\", "/"),
        "bytes": int(artifact["bytes"]),
        "sha256": str(artifact["sha256"]),
    }


def expected_outcome_binding(dataset_id: int) -> dict[str, Any]:
    return expected_artifact(dataset_id, "target_outcomes.npz")


def load_verified_npz_snapshot(
    expected: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, np.ndarray]]:
    """Hash and decode the exact same byte snapshot, closing check/use races."""

    path = _safe_package_path(str(expected["relative_path"]))
    payload = path.read_bytes()
    actual = {
        "relative_path": str(expected["relative_path"]),
        "bytes": len(payload),
        "sha256": sha256_bytes(payload),
    }
    if actual != expected:
        raise RuntimeError(
            f"artifact snapshot identity mismatch: {expected['relative_path']}"
        )
    with np.load(BytesIO(payload), allow_pickle=False) as archive:
        arrays = {name: np.asarray(archive[name]).copy() for name in archive.files}
    return actual, arrays


def load_verified_target_snapshot(
    dataset_id: int,
) -> tuple[dict[str, Any], dict[str, np.ndarray]]:
    lock = read_json(RECEIPTS / "R4_2_LOCAL_LOCK.json")
    expected = lock["target_outcome_bindings"][str(dataset_id)]
    if expected != expected_outcome_binding(dataset_id):
        raise RuntimeError(
            f"target binding differs from preparation receipt: {dataset_id}"
        )
    return load_verified_npz_snapshot(expected)


def load_verified_feature_snapshot(
    dataset_id: int,
) -> tuple[dict[str, Any], dict[str, np.ndarray]]:
    return load_verified_npz_snapshot(
        expected_artifact(dataset_id, "target_features.npz")
    )


def stage_a_required_paths() -> list[Path]:
    return [
        ROOT / "R4_2_STAGE_A_REGISTRATION.md",
        ROOT / "R4_2_PROTOCOL.md",
        ROOT / "requirements-lock.txt",
        ROOT / "config" / "r4_2_contract.json",
        ROOT / "code" / "integrity.py",
        ROOT / "code" / "prepare_r4_2_new_data.py",
        ROOT / "code" / "freeze_r4_2_stage_a_lock.py",
        ROOT / "code" / "verify_r4_2_stage_a_timestamp.py",
        ROOT / "code" / "create_r4_2_public_ack.py",
        ROOT / "code" / "cacl_oc_engine.py",
        ROOT / "code" / "freeze_r4_2_lock.py",
        ROOT / "code" / "verify_r4_2_timestamp.py",
        ROOT / "code" / "audit_r4_2_final.py",
    ]


def _valid_utc_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return (
        parsed.tzinfo is not None
        and parsed.utcoffset() == timedelta(0)
        and parsed <= datetime.now(timezone.utc)
    )


def _ack_checks(
    ack: dict[str, Any],
    lock_path: Path,
    *,
    schema: str,
    expected_public_count: int,
    unopened_field: str,
) -> dict[str, bool]:
    lock = read_json(lock_path)
    verified = ack.get("verified_remote_files", {})
    public_paths = lock.get("public_text_paths", [])
    remote_prefix = str(ack.get("remote_path_prefix", "")).rstrip("/")
    remote_evidence_exact = (
        isinstance(verified, dict)
        and bool(remote_prefix)
        and set(verified) == set(public_paths)
        and all(
            isinstance(verified.get(relative), dict)
            and verified[relative].get("remote_path")
            == f"{remote_prefix}/{relative}"
            and verified[relative].get("bytes")
            == _safe_package_path(relative).stat().st_size
            and verified[relative].get("sha256")
            == sha256(_safe_package_path(relative))
            for relative in public_paths
        )
    )
    url = str(ack.get("public_url", ""))
    parsed = urlparse(url)
    commit_sha = str(ack.get("public_commit_sha", ""))
    expected_url = (
        f"https://github.com/{REPOSITORY}/commit/{commit_sha}"
    )
    lock_hash = sha256(lock_path)
    return {
        "ack_schema": ack.get("schema") == schema,
        "strict_remote_exact_true": (
            ack.get("remote_files_exactly_match_local") is True
        ),
        f"strict_{unopened_field}_true": (
            ack.get(unopened_field) is True
        ),
        "ack_created_by_network_fetch": (
            ack.get("ack_created_by_network_fetch") is True
        ),
        "verifier_did_not_decode_target_outcomes": (
            ack.get(
                "target_outcomes_semantically_decoded_by_this_verifier"
            )
            is False
        ),
        "verified_remote_file_evidence_exact": remote_evidence_exact,
        "commit_sha_format": bool(
            re.fullmatch(r"[0-9a-f]{40}", commit_sha)
        ),
        "canonical_commit_url": (
            parsed.scheme == "https"
            and parsed.netloc == "github.com"
            and url == expected_url
        ),
        "valid_utc_timestamp": _valid_utc_timestamp(
            ack.get("public_timestamp_utc")
        ),
        "local_lock_hash": ack.get("local_lock_sha256") == lock_hash,
        "remote_lock_hash": ack.get("remote_lock_sha256") == lock_hash,
        "remote_file_count_exact": (
            ack.get("remote_file_count") == expected_public_count
        ),
    }


def _rehash_locked_files(
    lock: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for relative, expected in lock.get("files", {}).items():
        path = _safe_package_path(relative)
        exists = path.is_file()
        actual_bytes = path.stat().st_size if exists else None
        actual_sha = sha256(path) if exists else None
        row = {
            "exists": exists,
            "bytes_match": (
                exists and actual_bytes == int(expected["bytes"])
            ),
            "sha256_match": (
                exists and actual_sha == str(expected["sha256"])
            ),
            "actual_bytes": actual_bytes,
            "actual_sha256": actual_sha,
        }
        row["passes"] = bool(
            row["exists"]
            and row["bytes_match"]
            and row["sha256_match"]
        )
        rows[relative] = row
    return rows


def validate_stage_a_ack_and_lock() -> dict[str, Any]:
    lock_path = RECEIPTS / "R4_2_STAGE_A_LOCAL_LOCK.json"
    ack_path = RECEIPTS / "R4_2_STAGE_A_TIMESTAMP_ACK.json"
    if not lock_path.is_file() or not ack_path.is_file():
        raise RuntimeError("R4.2 Stage-A lock or ACK is absent")
    lock = read_json(lock_path)
    ack = read_json(ack_path)
    expected_public_count = len(lock.get("public_text_paths", []))
    checks = _ack_checks(
        ack,
        lock_path,
        schema="cacl-oc-r4.2-stage-a-timestamp-ack-v1",
        expected_public_count=expected_public_count,
        unopened_field="new_instance_data_unopened_at_timestamp",
    )
    checks.update(
        {
            "lock_schema": (
                lock.get("schema")
                == "cacl-oc-r4.2-stage-a-local-lock-v1"
            ),
            "lock_status": (
                lock.get("status")
                == "R4_2_STAGE_A_LOCKED_BEFORE_NEW_DATA_ACCESS"
            ),
            "new_ids_exact": lock.get("new_registered_ids") == NEW_IDS,
            "new_data_not_downloaded": (
                lock.get("new_data_downloaded") is False
            ),
            "required_file_keyset_exact": (
                set(lock.get("files", {}))
                == {
                    str(path.relative_to(PACKAGE)).replace("\\", "/")
                    for path in stage_a_required_paths()
                }
            ),
            "public_paths_exact": (
                set(lock.get("public_text_paths", []))
                == set(lock.get("files", {}))
                | {
                    str(lock_path.relative_to(PACKAGE)).replace(
                        "\\", "/"
                    )
                }
            ),
        }
    )
    file_checks = _rehash_locked_files(lock)
    checks["all_locked_files_current"] = bool(
        file_checks and all(row["passes"] for row in file_checks.values())
    )
    result = {
        "checks": checks,
        "file_checks": file_checks,
        "passes": all(checks.values()),
        "lock_sha256": sha256(lock_path),
        "ack_sha256": sha256(ack_path),
        "public_commit_sha": str(ack.get("public_commit_sha", "")),
    }
    if not result["passes"]:
        failed = [name for name, value in checks.items() if not value]
        raise RuntimeError(
            "R4.2 Stage-A authorization failed: " + ", ".join(failed)
        )
    return result


def required_final_paths() -> list[Path]:
    paths = [
        ROOT / "R4_2_PROTOCOL.md",
        ROOT / "R4_2_STAGE_A_REGISTRATION.md",
        ROOT / "requirements-lock.txt",
        ROOT / "config" / "r4_2_contract.json",
        ROOT / "code" / "integrity.py",
        ROOT / "code" / "prepare_r4_2_new_data.py",
        ROOT / "code" / "freeze_r4_2_stage_a_lock.py",
        ROOT / "code" / "verify_r4_2_stage_a_timestamp.py",
        ROOT / "code" / "create_r4_2_public_ack.py",
        ROOT / "code" / "cacl_oc_engine.py",
        ROOT / "code" / "freeze_r4_2_lock.py",
        ROOT / "code" / "verify_r4_2_timestamp.py",
        ROOT / "code" / "audit_r4_2_final.py",
        RECEIPTS / "R4_2_STAGE_A_LOCAL_LOCK.json",
        RECEIPTS / "R4_2_STAGE_A_TIMESTAMP_ACK.json",
        RECEIPTS / "R4_2_STAGE_A_TIMESTAMP_VERIFICATION.json",
        RECEIPTS / "R4_2_NEW_DATA_PREPARATION.json",
        RECEIPTS / "R4_2_PRE_REVEAL_BATCH.json",
        R3 / "receipts" / "R3_PREPARATION_RECEIPT.json",
        R3 / "receipts" / "R3_SOURCE_STOP_AUDIT.json",
        PACKAGE
        / "24_CACL_OC_UCI_TARGET_UNTOUCHED"
        / "R4_STATIC_AUDIT_INVALIDATION.md",
        PACKAGE
        / "24_CACL_OC_UCI_TARGET_UNTOUCHED"
        / "receipts"
        / "R4_PRE_REVEAL_INVALIDATION.json",
    ]
    for dataset_id in REGISTERED_IDS:
        paths.extend(
            [
                dataset_root(dataset_id) / "PREPARATION_RECEIPT.json",
                ROOT
                / "registered_census"
                / f"uci_{dataset_id}"
                / "SOURCE_FREEZE_RECEIPT.json",
                ROOT
                / "registered_census"
                / f"uci_{dataset_id}"
                / "FROZEN_POLICY.joblib",
                ROOT
                / "registered_census"
                / f"uci_{dataset_id}"
                / "SEALED_TARGET_ACTIONS.npz",
            ]
        )
    return paths


def validate_ack_and_lock() -> dict[str, Any]:
    """Recompute the complete Stage-B chain; never trust a status field."""

    stage_a = validate_stage_a_ack_and_lock()
    stage_a_verification = read_json(
        RECEIPTS / "R4_2_STAGE_A_TIMESTAMP_VERIFICATION.json"
    )
    preparation_batch = read_json(
        RECEIPTS / "R4_2_NEW_DATA_PREPARATION.json"
    )
    lock_path = RECEIPTS / "R4_2_LOCAL_LOCK.json"
    ack_path = RECEIPTS / "R4_2_EXTERNAL_TIMESTAMP_ACK.json"
    if not lock_path.is_file() or not ack_path.is_file():
        raise RuntimeError("R4.2 Stage-B lock or ACK is absent")
    lock = read_json(lock_path)
    ack = read_json(ack_path)
    config = read_json(ROOT / "config" / "r4_2_contract.json")
    batch = read_json(RECEIPTS / "R4_2_PRE_REVEAL_BATCH.json")
    expected_public_count = len(lock.get("public_text_paths", []))
    checks = _ack_checks(
        ack,
        lock_path,
        schema="cacl-oc-r4.2-timestamp-ack-v1",
        expected_public_count=expected_public_count,
        unopened_field=(
            "target_outcomes_not_semantically_decoded_by_scientific_"
            "engine_at_timestamp"
        ),
    )
    checks.update(
        {
            "stage_a_verification_exact": (
                stage_a_verification.get("schema")
                == "cacl-oc-r4.2-stage-a-verification-v1"
                and stage_a_verification.get("status")
                == "R4_2_STAGE_A_DATA_ACCESS_AUTHORIZED"
                and stage_a_verification.get("lock_sha256")
                == stage_a["lock_sha256"]
                and stage_a_verification.get("ack_sha256")
                == stage_a["ack_sha256"]
                and stage_a_verification.get("public_commit_sha")
                == stage_a["public_commit_sha"]
                and stage_a_verification.get(
                    "all_locked_files_current"
                )
                is True
                and stage_a_verification.get(
                    "new_data_access_permitted_after_receipt"
                )
                is True
            ),
            "new_preparation_batch_exact": (
                preparation_batch.get("schema")
                == "cacl-oc-r4.2-new-data-preparation-batch-v1"
                and preparation_batch.get("status")
                == "R4_2_NEW_DATA_PREPARATION_COMPLETE"
                and preparation_batch.get("registered_ids") == NEW_IDS
                and preparation_batch.get("datasets_replaced") is False
                and preparation_batch.get("target_summaries_emitted")
                is False
                and preparation_batch.get("model_fitted") is False
                and [
                    row.get("uci_id")
                    for row in preparation_batch.get("datasets", [])
                ]
                == NEW_IDS
                and all(
                    row
                    == preparation_receipt(int(row["uci_id"]))
                    for row in preparation_batch.get("datasets", [])
                )
            ),
            "lock_schema": (
                lock.get("schema") == "cacl-oc-r4.2-local-lock-v1"
            ),
            "lock_status": (
                lock.get("status")
                == "R4_2_LOCKED_PENDING_EXTERNAL_TIMESTAMP"
            ),
            "registered_ids_exact": (
                lock.get("registered_ids") == REGISTERED_IDS
                == config.get("registered_ids")
            ),
            "inferential_ids_exact": (
                lock.get("inferential_ids") == INFERENTIAL_IDS
                == config.get("inferential_ids")
            ),
            "descriptive_ids_exact": (
                lock.get("descriptive_ids") == DESCRIPTIVE_IDS
                == config.get("descriptive_ids")
            ),
            "reveal_flag_false": (
                lock.get("target_outcome_reveal_permitted") is False
            ),
            "required_file_keyset_exact": (
                set(lock.get("files", {}))
                == {
                    str(path.relative_to(PACKAGE)).replace("\\", "/")
                    for path in required_final_paths()
                }
            ),
            "public_paths_include_lock": (
                str(lock_path.relative_to(PACKAGE)).replace("\\", "/")
                in lock.get("public_text_paths", [])
            ),
        }
    )
    expected_public_paths = {
        relative
        for relative in lock.get("files", {})
        if Path(relative).suffix.lower()
        in {".json", ".md", ".py", ".txt"}
    } | {
        str(lock_path.relative_to(PACKAGE)).replace("\\", "/")
    }
    checks["public_text_paths_exact"] = (
        set(lock.get("public_text_paths", []))
        == expected_public_paths
    )

    routes: dict[str, str] = {}
    for dataset_id in REGISTERED_IDS:
        receipt = read_json(
            ROOT
            / "registered_census"
            / f"uci_{dataset_id}"
            / "SOURCE_FREEZE_RECEIPT.json"
        )
        routes[str(dataset_id)] = str(receipt["route"])
    inferential_act_count = sum(
        routes[str(dataset_id)] == "ACT"
        for dataset_id in INFERENTIAL_IDS
    )
    new_source_act_count = sum(
        routes[str(dataset_id)] == "ACT"
        for dataset_id in NEW_IDS
    )
    checks.update(
        {
            "routes_derived_exact": (
                lock.get("source_routes") == routes
                == batch.get("routes")
            ),
            "inferential_act_count_derived_exact": (
                lock.get("inferential_source_act_count")
                == inferential_act_count
                == batch.get("inferential_source_act_count")
            ),
            "new_act_count_derived_exact": (
                lock.get("new_source_act_count")
                == new_source_act_count
                == batch.get("new_source_act_count")
            ),
            "pre_reveal_viability": (
                inferential_act_count
                >= int(config["minimum_source_act"])
            ),
            "new_pre_reveal_viability": (
                new_source_act_count
                >= int(config["minimum_new_source_act"])
            ),
        }
    )

    file_checks = _rehash_locked_files(lock)
    checks["all_locked_files_current"] = bool(
        file_checks and all(row["passes"] for row in file_checks.values())
    )
    binding_checks: dict[str, dict[str, Any]] = {}
    for dataset_id in REGISTERED_IDS:
        expected = expected_outcome_binding(dataset_id)
        locked = lock.get("target_outcome_bindings", {}).get(
            str(dataset_id)
        )
        path = _safe_package_path(expected["relative_path"])
        row = {
            "lock_matches_preparation_receipt": locked == expected,
            "path_exists": path.is_file(),
            "bytes_match_without_semantic_load": (
                path.is_file()
                and path.stat().st_size == int(expected["bytes"])
            ),
            "sha256_match_without_semantic_load": (
                path.is_file()
                and sha256(path) == str(expected["sha256"])
            ),
        }
        row["passes"] = all(row.values())
        binding_checks[str(dataset_id)] = row
    checks["all_outcome_bindings_committed"] = (
        set(lock.get("target_outcome_bindings", {}))
        == {str(value) for value in REGISTERED_IDS}
        and all(row["passes"] for row in binding_checks.values())
    )

    result = {
        "checks": checks,
        "file_checks": file_checks,
        "outcome_binding_checks": binding_checks,
        "passes": all(checks.values()),
        "lock_sha256": sha256(lock_path),
        "ack_sha256": sha256(ack_path),
        "public_commit_sha": str(ack.get("public_commit_sha", "")),
        "stage_a_lock_sha256": stage_a["lock_sha256"],
        "stage_a_ack_sha256": stage_a["ack_sha256"],
        "stage_a_public_commit_sha": stage_a["public_commit_sha"],
    }
    if not result["passes"]:
        failed = [name for name, value in checks.items() if not value]
        raise RuntimeError(
            "R4.2 Stage-B authorization failed: " + ", ".join(failed)
        )
    return result
