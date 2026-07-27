#!/usr/bin/env python3
"""Shared write-once, snapshot and hash-chain checks for CACL-OC R4.4."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.parse import unquote

import numpy as np


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PACKAGE = ROOT.parent
R3 = PACKAGE / "23_CACL_VPC_UCI_CENSUS_BATCH"
R4_2 = PACKAGE / "26_CACL_OC_UCI_EXPANDED_R4_2"
R4_3 = PACKAGE / "27_CACL_OC_UCI_EXPANDED_R4_3"
RECEIPTS = ROOT / "receipts"
CAMPAIGN_IDS = [75, 327, 572, 855, 367, 891, 942, 967]
REGISTERED_IDS = [75, 327, 572, 367, 891, 942, 967]
INFERENTIAL_IDS = [327, 572, 367, 891, 942, 967]
DESCRIPTIVE_IDS = [75]
ELIGIBILITY_FAILURE_IDS = [855]
NEW_IDS = [367, 891, 942, 967]
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


def _sha256_text(value: Any) -> bool:
    return isinstance(value, str) and bool(
        re.fullmatch(r"[0-9a-f]{64}", value)
    )


def preparation_transport_matches(
    receipt: dict[str, Any], config: dict[str, Any]
) -> bool:
    dataset_id = int(receipt.get("uci_id", -1))
    acquisition = receipt.get("acquisition")
    registered = config.get("transport", {}).get(str(dataset_id))
    if not isinstance(acquisition, dict) or not isinstance(
        registered, dict
    ):
        return False
    if dataset_id not in NEW_IDS:
        return False
    metadata_path = str(
        registered.get("metadata_snapshot_relative_path", "")
    )
    taxonomy_exact = (
        dataset_id != 942
        or (
            registered.get("taxonomy_registration_relative_path")
            == (
                "28_CACL_OC_UCI_EXPANDED_R4_4/registration/"
                "uci_942_official_taxonomy.json"
            )
            and _sha256_text(
                registered.get("taxonomy_registration_sha256")
            )
            and _safe_package_path(
                str(
                    registered.get(
                        "taxonomy_registration_relative_path", ""
                    )
                )
            ).is_file()
            and sha256(
                _safe_package_path(
                    str(
                        registered.get(
                            "taxonomy_registration_relative_path", ""
                        )
                    )
                )
            )
            == registered.get("taxonomy_registration_sha256")
        )
    )
    return (
        set(acquisition)
        == {
            "method",
            "uci_id",
            "url",
            "final_url",
            "metadata_snapshot_relative_path",
            "metadata_snapshot_sha256",
            "csv_bytes",
            "csv_sha256",
        }
        and acquisition.get("method") == "official_uci_static_csv"
        == registered.get("method")
        and acquisition.get("uci_id") == dataset_id
        and acquisition.get("url") == registered.get("url")
        and (
            lambda requested, resolved: (
                resolved.scheme == "https"
                and resolved.netloc.lower() == requested.netloc.lower()
                and unquote(resolved.path) == unquote(requested.path)
                and not resolved.params
                and not resolved.query
                and not resolved.fragment
                and registered.get("redirect_policy")
                == (
                    "https_same_origin_same_decoded_path_no_query_"
                    "fragment"
                )
            )
        )(
            urlparse(str(acquisition.get("url", ""))),
            urlparse(str(acquisition.get("final_url", ""))),
        )
        and acquisition.get("metadata_snapshot_relative_path")
        == metadata_path
        and acquisition.get("metadata_snapshot_sha256")
        == registered.get("metadata_snapshot_sha256")
        and _safe_package_path(metadata_path).is_file()
        and sha256(_safe_package_path(metadata_path))
        == registered.get("metadata_snapshot_sha256")
        and isinstance(acquisition.get("csv_bytes"), int)
        and 0
        < acquisition["csv_bytes"]
        <= int(registered["maximum_csv_bytes"])
        and _sha256_text(acquisition.get("csv_sha256"))
        and taxonomy_exact
    )


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
    # Outcome archives are semantically readable only after both the
    # externally timestamped Stage-B chain and the local one-shot reveal
    # receipt have been validated.  Keeping this guard at the loader closes
    # direct-call paths that bypass the batch evaluator.
    require_target_semantic_load_authorized()
    lock = read_json(RECEIPTS / "R4_4_LOCAL_LOCK.json")
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
        R4_2 / "receipts" / "R4_2_STAGE_A_LOCAL_LOCK.json",
        R4_2 / "receipts" / "R4_2_STAGE_A_TIMESTAMP_ACK.json",
        R4_2
        / "receipts"
        / "R4_2_STAGE_A_TIMESTAMP_VERIFICATION.json",
        R4_2 / "R4_2_TRANSPORT_INVALIDATION.md",
        R4_2
        / "receipts"
        / "R4_2_STAGE_A_TRANSPORT_INVALIDATION.json",
        R4_3 / "receipts" / "R4_3_STAGE_A_LOCAL_LOCK.json",
        R4_3 / "receipts" / "R4_3_STAGE_A_TIMESTAMP_ACK.json",
        R4_3
        / "receipts"
        / "R4_3_STAGE_A_TIMESTAMP_VERIFICATION.json",
        R4_3 / "R4_3_DATA_ELIGIBILITY_INVALIDATION.md",
        R4_3
        / "receipts"
        / "R4_3_STAGE_A_DATA_ELIGIBILITY_INVALIDATION.json",
        *[
            PACKAGE
            / (
                "22_CACL_VPC_UCI_BINARY_VERIFIED_BATCH/"
                f"registry_snapshot/metadata/uci_{dataset_id}.json"
            )
            for dataset_id in NEW_IDS
        ],
        ROOT / "registration" / "uci_942_official_taxonomy.json",
        PACKAGE
        / "21_CACL_VPC_UCI_CLOSED_BATCH"
        / "receipts"
        / "PHASE2_SELECTION_RECEIPT.json",
        PACKAGE
        / "21_CACL_VPC_UCI_CLOSED_BATCH"
        / "receipts"
        / "PHASE3_PREPARATION_RECEIPT.json",
        PACKAGE
        / "21_CACL_VPC_UCI_CLOSED_BATCH"
        / "receipts"
        / "BATCH1_FINAL_AUDIT.json",
        PACKAGE
        / "22_CACL_VPC_UCI_BINARY_VERIFIED_BATCH"
        / "receipts"
        / "R2_LOCAL_LOCK.json",
        PACKAGE
        / "22_CACL_VPC_UCI_BINARY_VERIFIED_BATCH"
        / "code"
        / "r2_binary_verify_select.py",
        PACKAGE
        / "22_CACL_VPC_UCI_BINARY_VERIFIED_BATCH"
        / "registry_snapshot"
        / "R2_BINARY_VERIFIED_ELIGIBILITY.csv",
        PACKAGE
        / "22_CACL_VPC_UCI_BINARY_VERIFIED_BATCH"
        / "receipts"
        / "R2_SELECTION_RECEIPT.json",
        RECEIPTS / "R4_4_PRIOR_ACCESS_AUDIT.json",
        RECEIPTS / "R4_4_PRIOR_ACCESS_AUDIT_V1_INVALIDATION.json",
        RECEIPTS / "R4_4_PRIOR_ACCESS_AUDIT_V2.json",
        ROOT / "R4_4_STAGE_A_REGISTRATION.md",
        ROOT / "R4_4_PROTOCOL.md",
        ROOT / "requirements-lock.txt",
        ROOT / "config" / "r4_4_contract.json",
        ROOT / "code" / "integrity.py",
        ROOT / "code" / "build_r4_4_prior_access_audit.py",
        ROOT / "code" / "prepare_r4_4_new_data.py",
        ROOT / "code" / "freeze_r4_4_stage_a_lock.py",
        ROOT / "code" / "verify_r4_4_stage_a_timestamp.py",
        ROOT / "code" / "create_r4_4_public_ack.py",
        ROOT / "code" / "cacl_oc_engine.py",
        ROOT / "code" / "freeze_r4_4_lock.py",
        ROOT / "code" / "verify_r4_4_timestamp.py",
        ROOT / "code" / "audit_r4_4_final.py",
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


def _current_candidate_path_hits() -> list[str]:
    tokens = tuple(
        token
        for dataset_id in NEW_IDS
        for token in (f"uci_{dataset_id}", f"uci-{dataset_id}")
    )
    hits: list[str] = []
    for path in PACKAGE.rglob("*"):
        if path.is_file():
            relative = str(path.relative_to(PACKAGE)).replace("\\", "/")
            if any(token in relative.lower() for token in tokens):
                hits.append(relative)
    return sorted(hits)


def validate_prior_access_audit(
    *, recompute_current_census: bool = False
) -> dict[str, Any]:
    """Rehash the evidence bound by the pre-instance workspace audit."""

    path = RECEIPTS / "R4_4_PRIOR_ACCESS_AUDIT_V2.json"
    v1_path = RECEIPTS / "R4_4_PRIOR_ACCESS_AUDIT.json"
    invalidation_path = (
        RECEIPTS / "R4_4_PRIOR_ACCESS_AUDIT_V1_INVALIDATION.json"
    )
    if not path.is_file():
        raise RuntimeError("R4.4 prior-access audit is absent")
    audit = read_json(path)
    invalidation = read_json(invalidation_path)
    evidence = audit.get("evidence", {})
    evidence_checks: dict[str, bool] = {}
    if isinstance(evidence, dict):
        for name, expected in evidence.items():
            if not isinstance(expected, dict):
                evidence_checks[str(name)] = False
                continue
            relative = str(expected.get("relative_path", ""))
            candidate = _safe_package_path(relative)
            evidence_checks[str(name)] = (
                candidate.is_file()
                and candidate.stat().st_size == expected.get("bytes")
                and sha256(candidate) == expected.get("sha256")
            )
    checks = {
        "schema": (
            audit.get("schema")
            == "cacl-oc-r4.4-prior-access-audit-v2"
        ),
        "status": (
            audit.get("status")
            == "NO_INSTANCE_TRACE_FOUND_IN_AUDITED_CAMPAIGN_PATHS"
        ),
        "candidate_ids": audit.get("candidate_ids") == NEW_IDS,
        "declared_checks_all_true": (
            isinstance(audit.get("checks"), dict)
            and bool(audit["checks"])
            and all(audit["checks"].values())
            and audit.get("passes") is True
        ),
        "evidence_complete_and_current": (
            bool(evidence_checks) and all(evidence_checks.values())
        ),
        "path_audit_exact": (
            audit.get("candidate_path_hits")
            == audit.get("allowed_metadata_or_registration_paths")
        ),
        "v1_preserved_and_invalidated_exact": (
            v1_path.is_file()
            and v1_path.stat().st_size == 4674
            and sha256(v1_path)
            == (
                "c81042edeb791f74eadc932c066394cdd399c7e54c8e606682"
                "0589c6051fda22"
            )
            and invalidation.get("schema")
            == "cacl-oc-r4.4-prior-access-audit-v1-invalidation-v1"
            and invalidation.get("status")
            == "R4_4_PRIOR_ACCESS_AUDIT_V1_INVALIDATED_BEFORE_STAGE_A"
            and invalidation.get("invalidated_receipt_bytes") == 4674
            and invalidation.get("invalidated_receipt_sha256")
            == sha256(v1_path)
            and invalidation.get("invalidated_receipt")
            == (
                "28_CACL_OC_UCI_EXPANDED_R4_4/receipts/"
                "R4_4_PRIOR_ACCESS_AUDIT.json"
            )
            and invalidation.get("failure_class")
            == "filename_only_workspace_scan"
            and isinstance(invalidation.get("failure_detail"), str)
            and bool(invalidation["failure_detail"].strip())
            and invalidation.get("repair_scope")
            == (
                "replace basename search with full package-relative-path "
                "search and issue a new write-once V2 receipt; preserve V1"
            )
            and invalidation.get(
                "instance_endpoint_opened_before_invalidation"
            )
            is False
            and invalidation.get(
                "instance_data_read_before_invalidation"
            )
            is False
            and invalidation.get(
                "stage_a_lock_created_before_invalidation"
            )
            is False
            and invalidation.get("v1_scientific_evidence_permitted")
            is False
        ),
        "claim_boundary_present": (
            isinstance(audit.get("claim_boundary"), str)
            and "not proof of absolute non-access"
            in audit["claim_boundary"]
        ),
    }
    current_path_hits: list[str] | None = None
    if recompute_current_census:
        current_path_hits = _current_candidate_path_hits()
        checks["current_prelock_path_census_exact"] = (
            current_path_hits == audit.get("candidate_path_hits")
            == audit.get("allowed_metadata_or_registration_paths")
        )
    result = {
        "checks": checks,
        "evidence_checks": evidence_checks,
        "passes": all(checks.values()),
        "sha256": sha256(path),
        "declared_path_hits": audit.get("candidate_path_hits"),
        "current_path_hits": current_path_hits,
    }
    if not result["passes"]:
        failed = [name for name, value in checks.items() if not value]
        raise RuntimeError(
            "R4.4 prior-access audit validation failed: "
            + ", ".join(failed)
        )
    return result


def validate_r4_2_invalidation_provenance() -> dict[str, Any]:
    """Prove that R4.2 was locked, then stopped before instance data."""

    lock_path = R4_2 / "receipts" / "R4_2_STAGE_A_LOCAL_LOCK.json"
    ack_path = R4_2 / "receipts" / "R4_2_STAGE_A_TIMESTAMP_ACK.json"
    verification_path = (
        R4_2 / "receipts" / "R4_2_STAGE_A_TIMESTAMP_VERIFICATION.json"
    )
    invalidation_path = (
        R4_2 / "receipts" / "R4_2_STAGE_A_TRANSPORT_INVALIDATION.json"
    )
    lock = read_json(lock_path)
    ack = read_json(ack_path)
    verification = read_json(verification_path)
    invalidation = read_json(invalidation_path)
    lock_hash = sha256(lock_path)
    ack_hash = sha256(ack_path)
    ack_checks = _ack_checks(
        ack,
        lock_path,
        schema="cacl-oc-r4.2-stage-a-timestamp-ack-v1",
        expected_public_count=len(lock.get("public_text_paths", [])),
        unopened_field="new_instance_data_unopened_at_timestamp",
    )
    locked_file_checks = _rehash_locked_files(lock)
    false_flags = (
        "instance_data_read_reached",
        "prepared_census_created",
        "registered_census_created",
        "scientific_model_fitted",
        "source_route_computed",
        "target_outcome_semantically_decoded",
        "r4_2_scientific_result_permitted",
    )
    checks = {
        "r4_2_lock_schema_status": (
            lock.get("schema")
            == "cacl-oc-r4.2-stage-a-local-lock-v1"
            and lock.get("status")
            == "R4_2_STAGE_A_LOCKED_BEFORE_NEW_DATA_ACCESS"
            and lock.get("new_registered_ids") == [855, 967]
            and lock.get("new_data_downloaded") is False
        ),
        "r4_2_ack_exact": all(ack_checks.values()),
        "r4_2_locked_files_current": bool(
            locked_file_checks
            and all(row["passes"] for row in locked_file_checks.values())
        ),
        "r4_2_verification_exact": (
            verification.get("schema")
            == "cacl-oc-r4.2-stage-a-verification-v1"
            and verification.get("status")
            == "R4_2_STAGE_A_DATA_ACCESS_AUTHORIZED"
            and verification.get("lock_sha256") == lock_hash
            and verification.get("ack_sha256") == ack_hash
            and verification.get("public_commit_sha")
            == ack.get("public_commit_sha")
            and verification.get("all_locked_files_current") is True
            and verification.get(
                "new_data_access_permitted_after_receipt"
            )
            is True
        ),
        "r4_2_invalidation_exact": (
            invalidation.get("schema")
            == "cacl-oc-r4.2-stage-a-transport-invalidation-v1"
            and invalidation.get("status")
            == "R4_2_INVALIDATED_BEFORE_INSTANCE_DATA_ACCESS"
            and invalidation.get("failure_class")
            == "transport_implementation"
            and invalidation.get("dataset_id") == 855
            and invalidation.get("repair_scope_permitted")
            == "official UCI 855 archive transport only"
            and all(invalidation.get(field) is False for field in false_flags)
        ),
        "r4_2_invalidation_bindings_exact": (
            invalidation.get("public_stage_a_commit")
            == ack.get("public_commit_sha")
            and invalidation.get("stage_a_lock_sha256") == lock_hash
        ),
        "r4_2_data_outputs_absent": (
            not (R4_2 / "prepared_census").exists()
            and not (R4_2 / "registered_census").exists()
        ),
    }
    result = {
        "checks": checks,
        "ack_checks": ack_checks,
        "locked_file_checks": locked_file_checks,
        "passes": all(checks.values()),
        "lock_sha256": lock_hash,
        "ack_sha256": ack_hash,
        "public_commit_sha": str(ack.get("public_commit_sha", "")),
    }
    if not result["passes"]:
        failed = [name for name, value in checks.items() if not value]
        raise RuntimeError(
            "R4.2 invalidation provenance failed: " + ", ".join(failed)
        )
    return result


def validate_r4_3_invalidation_provenance() -> dict[str, Any]:
    """Prove R4.3 stopped on UCI855 before preparation and UCI967."""

    lock_path = R4_3 / "receipts" / "R4_3_STAGE_A_LOCAL_LOCK.json"
    ack_path = R4_3 / "receipts" / "R4_3_STAGE_A_TIMESTAMP_ACK.json"
    verification_path = (
        R4_3 / "receipts" / "R4_3_STAGE_A_TIMESTAMP_VERIFICATION.json"
    )
    invalidation_path = (
        R4_3
        / "receipts"
        / "R4_3_STAGE_A_DATA_ELIGIBILITY_INVALIDATION.json"
    )
    lock = read_json(lock_path)
    ack = read_json(ack_path)
    verification = read_json(verification_path)
    invalidation = read_json(invalidation_path)
    lock_hash = sha256(lock_path)
    ack_hash = sha256(ack_path)
    verification_hash = sha256(verification_path)
    ack_checks = _ack_checks(
        ack,
        lock_path,
        schema="cacl-oc-r4.3-stage-a-timestamp-ack-v1",
        expected_public_count=len(lock.get("public_text_paths", [])),
        unopened_field="new_instance_data_unopened_at_timestamp",
    )
    locked_file_checks = _rehash_locked_files(lock)
    checks = {
        "r4_3_lock_schema_status": (
            lock.get("schema")
            == "cacl-oc-r4.3-stage-a-local-lock-v1"
            and lock.get("status")
            == "R4_3_STAGE_A_LOCKED_BEFORE_NEW_DATA_ACCESS"
            and lock.get("new_registered_ids") == [855, 967]
            and lock.get("new_data_downloaded") is False
        ),
        "r4_3_ack_exact": all(ack_checks.values()),
        "r4_3_locked_files_current": bool(
            locked_file_checks
            and all(row["passes"] for row in locked_file_checks.values())
        ),
        "r4_3_verification_exact": (
            verification.get("schema")
            == "cacl-oc-r4.3-stage-a-verification-v1"
            and verification.get("status")
            == "R4_3_STAGE_A_DATA_ACCESS_AUTHORIZED"
            and verification.get("lock_sha256") == lock_hash
            and verification.get("ack_sha256") == ack_hash
            and verification.get("public_commit_sha")
            == ack.get("public_commit_sha")
            and verification.get("all_locked_files_current") is True
            and verification.get(
                "new_data_access_permitted_after_receipt"
            )
            is True
        ),
        "r4_3_invalidation_exact": (
            invalidation.get("schema")
            == "cacl-oc-r4.3-stage-a-data-eligibility-invalidation-v1"
            and invalidation.get("status")
            == "R4_3_INVALIDATED_AFTER_UCI855_ACCESS_BEFORE_PREPARATION"
            and invalidation.get("failure_class")
            == "pre_registered_data_eligibility"
            and invalidation.get("dataset_id") == 855
            and invalidation.get("instance_data_read_reached") is True
            and invalidation.get("target_labels_read_by_preparation_layer")
            is True
            and invalidation.get("uci967_instance_data_read_reached")
            is False
            and invalidation.get("scientific_engine_target_outcome_opened")
            is False
            and invalidation.get("prepared_census_created") is False
            and invalidation.get("registered_census_created") is False
            and invalidation.get("preparation_batch_created") is False
            and invalidation.get("scientific_model_fitted") is False
            and invalidation.get("source_route_computed") is False
            and invalidation.get("target_action_computed") is False
            and invalidation.get("r4_3_retry_permitted") is False
            and invalidation.get("r4_3_scientific_result_permitted")
            is False
        ),
        "r4_3_invalidation_bindings_exact": (
            invalidation.get("public_stage_a_commit")
            == ack.get("public_commit_sha")
            and invalidation.get("stage_a_lock_sha256") == lock_hash
            and invalidation.get("stage_a_ack_sha256") == ack_hash
            and invalidation.get("stage_a_verification_sha256")
            == verification_hash
        ),
        "r4_3_data_outputs_absent": (
            not (R4_3 / "prepared_census").exists()
            and not (R4_3 / "registered_census").exists()
            and not (
                R4_3 / "receipts" / "R4_3_NEW_DATA_PREPARATION.json"
            ).exists()
        ),
    }
    result = {
        "checks": checks,
        "ack_checks": ack_checks,
        "locked_file_checks": locked_file_checks,
        "passes": all(checks.values()),
        "lock_sha256": lock_hash,
        "ack_sha256": ack_hash,
        "public_commit_sha": str(ack.get("public_commit_sha", "")),
    }
    if not result["passes"]:
        failed = [name for name, value in checks.items() if not value]
        raise RuntimeError(
            "R4.3 invalidation provenance failed: " + ", ".join(failed)
        )
    return result


def validate_stage_a_ack_and_lock() -> dict[str, Any]:
    r4_2 = validate_r4_2_invalidation_provenance()
    r4_3 = validate_r4_3_invalidation_provenance()
    prior_access = validate_prior_access_audit()
    lock_path = RECEIPTS / "R4_4_STAGE_A_LOCAL_LOCK.json"
    ack_path = RECEIPTS / "R4_4_STAGE_A_TIMESTAMP_ACK.json"
    if not lock_path.is_file() or not ack_path.is_file():
        raise RuntimeError("R4.4 Stage-A lock or ACK is absent")
    lock = read_json(lock_path)
    ack = read_json(ack_path)
    expected_public_count = len(lock.get("public_text_paths", []))
    checks = _ack_checks(
        ack,
        lock_path,
        schema="cacl-oc-r4.4-stage-a-timestamp-ack-v1",
        expected_public_count=expected_public_count,
        unopened_field="new_instance_data_unopened_at_timestamp",
    )
    checks.update(
        {
            "lock_schema": (
                lock.get("schema")
                == "cacl-oc-r4.4-stage-a-local-lock-v1"
            ),
            "lock_status": (
                lock.get("status")
                == "R4_4_STAGE_A_LOCKED_BEFORE_NEW_DATA_ACCESS"
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
            "r4_2_invalidation_provenance_exact": r4_2["passes"],
            "r4_3_invalidation_provenance_exact": r4_3["passes"],
            "prior_access_audit_exact": prior_access["passes"],
            "prior_access_lock_binding_exact": (
                lock.get("prior_access_audit_sha256")
                == prior_access["sha256"]
                and lock.get("prelock_candidate_path_hits")
                == prior_access["declared_path_hits"]
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
        "r4_2_invalidation_provenance": r4_2,
        "r4_3_invalidation_provenance": r4_3,
        "prior_access_audit": prior_access,
    }
    if not result["passes"]:
        failed = [name for name, value in checks.items() if not value]
        raise RuntimeError(
            "R4.4 Stage-A authorization failed: " + ", ".join(failed)
        )
    return result


def required_final_paths() -> list[Path]:
    paths = [
        *stage_a_required_paths(),
        RECEIPTS / "R4_4_STAGE_A_LOCAL_LOCK.json",
        RECEIPTS / "R4_4_STAGE_A_TIMESTAMP_ACK.json",
        RECEIPTS / "R4_4_STAGE_A_TIMESTAMP_VERIFICATION.json",
        RECEIPTS / "R4_4_NEW_DATA_PREPARATION.json",
        RECEIPTS / "R4_4_PRE_REVEAL_BATCH.json",
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
                dataset_root(dataset_id) / "source.npz",
                dataset_root(dataset_id) / "target_features.npz",
                dataset_root(dataset_id) / "target_outcomes.npz",
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
        if dataset_id in NEW_IDS:
            paths.append(dataset_root(dataset_id) / "raw_official.csv")
    return paths


def validate_ack_and_lock() -> dict[str, Any]:
    """Recompute the complete Stage-B chain; never trust a status field."""

    stage_a = validate_stage_a_ack_and_lock()
    stage_a_verification = read_json(
        RECEIPTS / "R4_4_STAGE_A_TIMESTAMP_VERIFICATION.json"
    )
    preparation_batch = read_json(
        RECEIPTS / "R4_4_NEW_DATA_PREPARATION.json"
    )
    lock_path = RECEIPTS / "R4_4_LOCAL_LOCK.json"
    ack_path = RECEIPTS / "R4_4_EXTERNAL_TIMESTAMP_ACK.json"
    if not lock_path.is_file() or not ack_path.is_file():
        raise RuntimeError("R4.4 Stage-B lock or ACK is absent")
    lock = read_json(lock_path)
    ack = read_json(ack_path)
    config = read_json(ROOT / "config" / "r4_4_contract.json")
    batch = read_json(RECEIPTS / "R4_4_PRE_REVEAL_BATCH.json")
    expected_public_count = len(lock.get("public_text_paths", []))
    checks = _ack_checks(
        ack,
        lock_path,
        schema="cacl-oc-r4.4-timestamp-ack-v1",
        expected_public_count=expected_public_count,
        unopened_field=(
            "target_outcomes_not_semantically_decoded_by_scientific_"
            "engine_at_timestamp"
        ),
    )
    checks.update(
        {
            "prior_invalidation_provenance_exact": (
                stage_a["checks"].get(
                    "r4_2_invalidation_provenance_exact"
                )
                is True
                and stage_a["checks"].get(
                    "r4_3_invalidation_provenance_exact"
                )
                is True
            ),
            "prior_access_audit_exact": (
                stage_a["checks"].get("prior_access_audit_exact")
                is True
            ),
            "stage_a_verification_exact": (
                stage_a_verification.get("schema")
                == "cacl-oc-r4.4-stage-a-verification-v1"
                and stage_a_verification.get("status")
                == "R4_4_STAGE_A_DATA_ACCESS_AUTHORIZED"
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
                == "cacl-oc-r4.4-new-data-preparation-batch-v1"
                and preparation_batch.get("status")
                == "R4_4_NEW_DATA_PREPARATION_COMPLETE"
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
                and all(
                    preparation_transport_matches(row, config)
                    for row in preparation_batch.get("datasets", [])
                )
            ),
            "lock_schema": (
                lock.get("schema") == "cacl-oc-r4.4-local-lock-v1"
            ),
            "lock_status": (
                lock.get("status")
                == "R4_4_LOCKED_PENDING_EXTERNAL_TIMESTAMP"
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
            "campaign_and_eligibility_failures_exact": (
                lock.get("campaign_ids") == CAMPAIGN_IDS
                == config.get("campaign_ids")
                and lock.get("eligibility_failure_ids")
                == ELIGIBILITY_FAILURE_IDS
                == config.get("eligibility_failure_ids")
                and set(REGISTERED_IDS).isdisjoint(
                    ELIGIBILITY_FAILURE_IDS
                )
                and sorted(
                    REGISTERED_IDS + ELIGIBILITY_FAILURE_IDS
                )
                == sorted(CAMPAIGN_IDS)
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
            "pre_reveal_denominators_exact": (
                batch.get("campaign_denominator") == CAMPAIGN_IDS
                and batch.get("eligibility_failure_denominator")
                == ELIGIBILITY_FAILURE_IDS
                and batch.get("registered_denominator")
                == REGISTERED_IDS
                and batch.get("inferential_denominator")
                == INFERENTIAL_IDS
                and batch.get("descriptive_denominator")
                == DESCRIPTIVE_IDS
            ),
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
            "R4.4 Stage-B authorization failed: " + ", ".join(failed)
        )
    return result


def validate_stage_b_timestamp_verification() -> dict[str, Any]:
    """Require the exact verifier receipt, not merely its headline status."""

    chain = validate_ack_and_lock()
    verification_path = (
        RECEIPTS / "R4_4_EXTERNAL_TIMESTAMP_VERIFICATION.json"
    )
    if not verification_path.is_file():
        raise RuntimeError(
            "R4.4 external timestamp verification receipt is absent"
        )
    verification = read_json(verification_path)
    checks = {
        "schema": (
            verification.get("schema")
            == "cacl-oc-r4.4-timestamp-verification-v1"
        ),
        "status": (
            verification.get("status")
            == "R4_4_TARGET_REVEAL_AUTHORIZED"
        ),
        "lock_sha256": (
            verification.get("lock_sha256") == chain["lock_sha256"]
        ),
        "ack_sha256": (
            verification.get("ack_sha256") == chain["ack_sha256"]
        ),
        "public_commit_sha": (
            verification.get("public_commit_sha")
            == chain["public_commit_sha"]
        ),
        "checks_exact": verification.get("checks") == chain["checks"],
        "locked_file_count": (
            verification.get("locked_file_count")
            == len(chain["file_checks"])
        ),
        "all_locked_files_current": (
            verification.get("all_locked_files_current") is True
            and all(
                row["passes"] for row in chain["file_checks"].values()
            )
        ),
        "all_outcome_bindings_committed": (
            verification.get("all_outcome_bindings_committed") is True
            and all(
                row["passes"]
                for row in chain["outcome_binding_checks"].values()
            )
        ),
        "semantic_load_explicitly_permitted": (
            verification.get(
                "target_outcome_semantic_load_permitted_after_receipt"
            )
            is True
        ),
    }
    if not all(checks.values()):
        failed = [name for name, value in checks.items() if not value]
        raise RuntimeError(
            "R4.4 timestamp verification is incomplete: "
            + ", ".join(failed)
        )
    return chain


def require_target_semantic_load_authorized() -> dict[str, Any]:
    """Fail closed unless the exact one-shot reveal has formally started."""

    chain = validate_stage_b_timestamp_verification()
    reveal_path = RECEIPTS / "R4_4_REVEAL_STARTED.json"
    if not reveal_path.is_file():
        raise RuntimeError(
            "R4.4 one-shot reveal-start receipt is absent"
        )
    reveal = read_json(reveal_path)
    checks = {
        "schema": (
            reveal.get("schema") == "cacl-oc-r4.4-reveal-start-v1"
        ),
        "status": (
            reveal.get("status")
            == "R4_4_ONE_SHOT_TARGET_REVEAL_STARTED"
        ),
        "started_utc": _valid_utc_timestamp(reveal.get("started_utc")),
        "campaign_ids": reveal.get("campaign_ids") == CAMPAIGN_IDS,
        "eligibility_failure_ids": (
            reveal.get("eligibility_failure_ids")
            == ELIGIBILITY_FAILURE_IDS
        ),
        "registered_ids": reveal.get("registered_ids") == REGISTERED_IDS,
        "lock_sha256": (
            reveal.get("lock_sha256") == chain["lock_sha256"]
        ),
        "ack_sha256": (
            reveal.get("ack_sha256") == chain["ack_sha256"]
        ),
        "public_commit_sha": (
            reveal.get("public_commit_sha") == chain["public_commit_sha"]
        ),
        "no_prior_semantic_load": (
            reveal.get(
                "target_outcome_semantic_load_before_this_receipt"
            )
            is False
        ),
        "retry_forbidden": reveal.get("retry_permitted") is False,
    }
    if not all(checks.values()):
        failed = [name for name, value in checks.items() if not value]
        raise RuntimeError(
            "R4.4 reveal-start authorization is invalid: "
            + ", ".join(failed)
        )
    return chain
