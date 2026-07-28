#!/usr/bin/env python3
"""Fail-closed V2 pre-reveal amendment for CACL-OC R4.5."""

from __future__ import annotations

import argparse
import importlib
import importlib.util
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote
from urllib.request import Request, urlopen


HERE = Path(__file__).resolve()
ROOT = HERE.parents[1]
PACKAGE = ROOT.parent
V1_ROOT = PACKAGE / "30_CACL_OC_UCI_EXPANDED_R4_5_1_AMENDMENT"
ORIGINAL_ROOT = PACKAGE / "29_CACL_OC_UCI_EXPANDED_R4_5"
ORIGINAL_CODE = ORIGINAL_ROOT / "code"
RECEIPTS = ROOT / "receipts"
REPOSITORY = "cmkim0408/Changman-s-Lab"

if str(ORIGINAL_CODE) not in sys.path:
    sys.path.insert(0, str(ORIGINAL_CODE))

import integrity  # noqa: E402


def load_v1_module() -> Any:
    path = V1_ROOT / "code" / "r4_5_1_amendment.py"
    spec = importlib.util.spec_from_file_location(
        "r4_5_1_rejected_draft_dependency", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load rejected amendment dependency")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = load_v1_module()

LOCK_PATH = RECEIPTS / "R4_5_1_AMENDMENT_V2_LOCAL_LOCK.json"
ACK_PATH = RECEIPTS / "R4_5_1_AMENDMENT_V2_TIMESTAMP_ACK.json"
VERIFICATION_PATH = (
    RECEIPTS / "R4_5_1_AMENDMENT_V2_TIMESTAMP_VERIFICATION.json"
)
FINAL_AUDIT_PATH = RECEIPTS / "R4_5_1_AMENDMENT_V2_FINAL_AUDIT.json"

LOCK_RELATIVE = (
    "31_CACL_OC_UCI_EXPANDED_R4_5_1_AMENDMENT_V2/receipts/"
    "R4_5_1_AMENDMENT_V2_LOCAL_LOCK.json"
)

SOURCE_PATHS = [
    (
        "31_CACL_OC_UCI_EXPANDED_R4_5_1_AMENDMENT_V2/"
        "AMENDMENT_V2_PROTOCOL.md"
    ),
    (
        "31_CACL_OC_UCI_EXPANDED_R4_5_1_AMENDMENT_V2/code/"
        "r4_5_1_amendment_v2.py"
    ),
]

REJECTED_DRAFT_PATHS = [
    (
        "30_CACL_OC_UCI_EXPANDED_R4_5_1_AMENDMENT/"
        "AMENDMENT_PROTOCOL.md"
    ),
    (
        "30_CACL_OC_UCI_EXPANDED_R4_5_1_AMENDMENT/code/"
        "r4_5_1_amendment.py"
    ),
    (
        "30_CACL_OC_UCI_EXPANDED_R4_5_1_AMENDMENT/receipts/"
        "R4_5_1_AMENDMENT_LOCAL_LOCK.json"
    ),
]

PUBLIC_PATHS = (
    SOURCE_PATHS
    + REJECTED_DRAFT_PATHS
    + base.PUBLIC_ORIGINAL_CHAIN_PATHS
    + [LOCK_RELATIVE]
)

EXPECTED_COUNTS = {
    "stage_b_checks": 34,
    "stage_b_locked_files": 82,
    "stage_b_outcome_bindings": 4,
    "authorized_post_stage_a_paths": 8,
}


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        result = json.load(handle)
    if not isinstance(result, dict):
        raise RuntimeError(f"expected JSON object: {path}")
    return result


def write_json_once(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(
        payload, indent=2, sort_keys=True, ensure_ascii=False
    ) + "\n"
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(serialized)


def package_path(relative: str) -> Path:
    candidate = (PACKAGE / relative).resolve()
    if not candidate.is_relative_to(PACKAGE.resolve()):
        raise RuntimeError(f"path escapes package: {relative}")
    return candidate


def artifact(relative: str) -> dict[str, Any]:
    path = package_path(relative)
    return {
        "bytes": path.stat().st_size,
        "sha256": integrity.sha256(path),
    }


def parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise RuntimeError(f"timestamp lacks timezone: {value}")
    return parsed.astimezone(timezone.utc)


def request_bytes(url: str) -> tuple[bytes, str]:
    request = Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "CACL-R4.5.1-amendment-v2",
        },
    )
    with urlopen(request, timeout=60) as response:
        return response.read(), response.geturl()


def commit_metadata(commit_sha: str) -> dict[str, str]:
    if not re.fullmatch(r"[0-9a-f]{40}", commit_sha):
        raise RuntimeError("invalid commit SHA")
    url = f"https://api.github.com/repos/{REPOSITORY}/commits/{commit_sha}"
    payload, final_url = request_bytes(url)
    value = json.loads(payload.decode("utf-8"))
    if value.get("sha") != commit_sha:
        raise RuntimeError("commit API returned a different SHA")
    timestamp = value["commit"]["committer"]["date"]
    parse_utc(timestamp)
    return {
        "sha": commit_sha,
        "timestamp_utc": timestamp,
        "api_final_url": final_url,
    }


def no_reveal_outputs() -> None:
    base.assert_pre_reveal_absence()


def exact_file_map(
    mapping: Any, expected_paths: list[str], label: str
) -> None:
    if not isinstance(mapping, dict) or set(mapping) != set(expected_paths):
        raise RuntimeError(f"{label} keyset is not exact")
    for relative in expected_paths:
        expected = mapping[relative]
        path = package_path(relative)
        if (
            not path.is_file()
            or not isinstance(expected, dict)
            or path.stat().st_size != expected.get("bytes")
            or integrity.sha256(path) != expected.get("sha256")
        ):
            raise RuntimeError(f"{label} rehash failed: {relative}")


def structural_lock_validation(
    *, require_pre_reveal_census: bool
) -> dict[str, Any]:
    lock = read_json(LOCK_PATH)
    header_checks = {
        "schema": (
            lock.get("schema")
            == "cacl-oc-r4.5.1-amendment-v2-lock-v1"
        ),
        "status": (
            lock.get("status")
            == "R4_5_1_AMENDMENT_V2_LOCKED_PRE_REVEAL"
        ),
        "scientific_change_false": lock.get("scientific_change") is False,
        "target_unopened": (
            lock.get("target_outcomes_semantically_opened") is False
        ),
        "draft_rejected": (
            lock.get("rejected_draft_used_for_authorization") is False
        ),
        "failure_fingerprint": (
            lock.get("registered_failure_fingerprint")
            == base.EXPECTED_UNPATCHED_ERROR
        ),
        "historical_paths": (
            lock.get("historical_candidate_paths")
            == base.HISTORICAL_PATHS
        ),
        "authorized_paths": (
            lock.get("authorized_post_stage_a_paths")
            == base.AUTHORIZED_POST_STAGE_A_PATHS
        ),
        "current_paths": (
            lock.get("current_candidate_paths")
            == sorted(
                base.HISTORICAL_PATHS
                + base.AUTHORIZED_POST_STAGE_A_PATHS
            )
        ),
        "stage_b_check_count": (
            lock.get("patched_stage_b_check_count")
            == EXPECTED_COUNTS["stage_b_checks"]
        ),
        "stage_b_file_count": (
            lock.get("patched_stage_b_locked_file_count")
            == EXPECTED_COUNTS["stage_b_locked_files"]
        ),
        "stage_b_binding_count": (
            lock.get("patched_stage_b_outcome_binding_count")
            == EXPECTED_COUNTS["stage_b_outcome_bindings"]
        ),
        "patched_pass": lock.get("patched_stage_b_all_pass") is True,
        "pre_reveal_absent": lock.get("pre_reveal_outputs_absent") is True,
        "public_paths_exact": lock.get("public_text_paths") == PUBLIC_PATHS,
        "stage_a_commit": (
            lock.get("stage_a_public_commit_sha")
            == read_json(
                ORIGINAL_ROOT
                / "receipts"
                / "R4_5_STAGE_A_TIMESTAMP_ACK.json"
            ).get("public_commit_sha")
        ),
        "stage_b_commit": (
            lock.get("stage_b_public_commit_sha")
            == read_json(
                ORIGINAL_ROOT
                / "receipts"
                / "R4_5_EXTERNAL_TIMESTAMP_ACK.json"
            ).get("public_commit_sha")
        ),
        "stage_a_timestamp": (
            lock.get("stage_a_timestamp_utc")
            == read_json(
                ORIGINAL_ROOT
                / "receipts"
                / "R4_5_STAGE_A_TIMESTAMP_ACK.json"
            ).get("public_timestamp_utc")
        ),
        "stage_b_timestamp": (
            lock.get("stage_b_timestamp_utc")
            == read_json(
                ORIGINAL_ROOT
                / "receipts"
                / "R4_5_EXTERNAL_TIMESTAMP_ACK.json"
            ).get("public_timestamp_utc")
        ),
        "draft_lock_hash": (
            lock.get("rejected_draft_lock_sha256")
            == integrity.sha256(base.LOCK_PATH)
        ),
    }
    if not all(header_checks.values()):
        failed = [key for key, value in header_checks.items() if not value]
        raise RuntimeError(
            "V2 lock structure failed: " + ", ".join(failed)
        )

    exact_file_map(lock.get("amendment_files"), SOURCE_PATHS, "V2 source")
    exact_file_map(
        lock.get("rejected_draft_files"),
        REJECTED_DRAFT_PATHS,
        "rejected draft",
    )
    exact_file_map(
        lock.get("critical_original_files"),
        base.CRITICAL_ORIGINAL_PATHS,
        "critical original",
    )

    stored_artifact_checks = lock.get("authorized_artifact_checks")
    if (
        not isinstance(stored_artifact_checks, dict)
        or set(stored_artifact_checks)
        != set(base.AUTHORIZED_POST_STAGE_A_PATHS)
        or not all(
            isinstance(row, dict)
            and set(row)
            == {
                "exists",
                "bound_by_stage_b_lock",
                "bytes_match",
                "sha256_match",
                "passes",
            }
            and all(row.values())
            for row in stored_artifact_checks.values()
        )
    ):
        raise RuntimeError("stored authorized-artifact checks are not exact")

    if require_pre_reveal_census:
        current = base.validate_authorized_current_census()
        if current["authorized_artifact_checks"] != stored_artifact_checks:
            raise RuntimeError("authorized-artifact recheck changed")
    return lock


def remote_file_recheck(
    *,
    commit_sha: str,
    prefix: str,
    paths: list[str],
) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for relative in paths:
        local = package_path(relative).read_bytes()
        remote_path = f"{prefix.rstrip('/')}/{relative}"
        url = (
            f"https://raw.githubusercontent.com/{REPOSITORY}/"
            f"{commit_sha}/{quote(remote_path, safe='/')}"
        )
        payload, final_url = request_bytes(url)
        row = {
            "remote_path": remote_path,
            "bytes": len(payload),
            "sha256": integrity.sha256_bytes(payload),
            "bytes_match": len(payload) == len(local),
            "sha256_match": (
                integrity.sha256_bytes(payload)
                == integrity.sha256_bytes(local)
            ),
            "final_url_https": final_url.startswith("https://"),
        }
        row["passes"] = (
            row["bytes_match"]
            and row["sha256_match"]
            and row["final_url_https"]
        )
        rows[relative] = row
    if set(rows) != set(paths) or not all(
        row["passes"] for row in rows.values()
    ):
        raise RuntimeError("remote amendment byte recheck failed")
    return rows


def strict_ack_validation(
    lock: dict[str, Any], *, network: bool
) -> dict[str, Any]:
    ack = read_json(ACK_PATH)
    verified = ack.get("verified_remote_files")
    prefix = str(ack.get("remote_path_prefix", "")).rstrip("/")
    commit = str(ack.get("public_commit_sha", ""))
    checks = {
        "schema": (
            ack.get("schema")
            == "cacl-oc-r4.5.1-amendment-v2-timestamp-ack-v1"
        ),
        "status": (
            ack.get("status")
            == "R4_5_1_AMENDMENT_V2_PUBLICLY_BYTE_VERIFIED"
        ),
        "commit_format": bool(re.fullmatch(r"[0-9a-f]{40}", commit)),
        "canonical_url": (
            ack.get("public_url")
            == f"https://github.com/{REPOSITORY}/commit/{commit}"
        ),
        "timestamp_valid": bool(parse_utc(str(ack["public_timestamp_utc"]))),
        "lock_hashes": (
            ack.get("local_lock_sha256") == integrity.sha256(LOCK_PATH)
            and ack.get("remote_lock_sha256")
            == integrity.sha256(LOCK_PATH)
        ),
        "remote_exact": (
            ack.get("remote_files_exactly_match_local") is True
        ),
        "target_unopened": (
            ack.get(
                "target_outcomes_semantically_decoded_by_this_verifier"
            )
            is False
        ),
        "count": ack.get("remote_file_count") == len(PUBLIC_PATHS),
        "verified_keyset": (
            isinstance(verified, dict)
            and set(verified) == set(PUBLIC_PATHS)
        ),
        "prefix": bool(prefix) and not prefix.startswith("/"),
    }
    if all(checks.values()):
        for relative in PUBLIC_PATHS:
            row = verified[relative]
            local = package_path(relative)
            checks[f"verified:{relative}"] = (
                isinstance(row, dict)
                and row.get("remote_path")
                == f"{prefix}/{relative}"
                and row.get("bytes") == local.stat().st_size
                and row.get("sha256") == integrity.sha256(local)
            )
    if not all(checks.values()):
        failed = [key for key, value in checks.items() if not value]
        raise RuntimeError("strict ACK failed: " + ", ".join(failed))

    network_rows = None
    commit_live = None
    if network:
        commit_live = commit_metadata(commit)
        if commit_live["timestamp_utc"] != ack["public_timestamp_utc"]:
            raise RuntimeError("live GitHub commit timestamp differs from ACK")
        network_rows = remote_file_recheck(
            commit_sha=commit, prefix=prefix, paths=PUBLIC_PATHS
        )
    return {
        "ack": ack,
        "commit_live": commit_live,
        "network_rows": network_rows,
        "passes": True,
    }


def strict_verification_validation(
    lock: dict[str, Any],
    ack_result: dict[str, Any],
) -> dict[str, Any]:
    value = read_json(VERIFICATION_PATH)
    ack = ack_result["ack"]
    stage_a_ack = read_json(
        ORIGINAL_ROOT / "receipts" / "R4_5_STAGE_A_TIMESTAMP_ACK.json"
    )
    stage_b_ack = read_json(
        ORIGINAL_ROOT / "receipts" / "R4_5_EXTERNAL_TIMESTAMP_ACK.json"
    )
    checks = {
        "schema": (
            value.get("schema")
            == "cacl-oc-r4.5.1-amendment-v2-verification-v1"
        ),
        "status": (
            value.get("status")
            == "R4_5_1_AMENDMENT_V2_AUTHORIZES_TARGET_REVEAL"
        ),
        "lock_hash": (
            value.get("amendment_lock_sha256")
            == integrity.sha256(LOCK_PATH)
        ),
        "ack_hash": (
            value.get("amendment_ack_sha256")
            == integrity.sha256(ACK_PATH)
        ),
        "commit": (
            value.get("amendment_public_commit_sha")
            == ack.get("public_commit_sha")
        ),
        "timestamp": (
            value.get("amendment_public_timestamp_utc")
            == ack.get("public_timestamp_utc")
        ),
        "timestamp_order": (
            value.get("public_timestamp_order_exact") is True
            and parse_utc(stage_a_ack["public_timestamp_utc"])
            < parse_utc(stage_b_ack["public_timestamp_utc"])
            < parse_utc(ack["public_timestamp_utc"])
        ),
        "stage_a_remote": (
            value.get("stage_a_remote_recheck", {}).get("passes") is True
            and value["stage_a_remote_recheck"].get("commit_sha")
            == stage_a_ack["public_commit_sha"]
            and value["stage_a_remote_recheck"].get("timestamp_utc")
            == stage_a_ack["public_timestamp_utc"]
        ),
        "stage_b_remote": (
            value.get("stage_b_remote_recheck", {}).get("passes") is True
            and value["stage_b_remote_recheck"].get("commit_sha")
            == stage_b_ack["public_commit_sha"]
            and value["stage_b_remote_recheck"].get("timestamp_utc")
            == stage_b_ack["public_timestamp_utc"]
        ),
        "amendment_remote": (
            value.get("amendment_remote_recheck_all_pass") is True
            and value.get("amendment_remote_file_count")
            == len(PUBLIC_PATHS)
        ),
        "failure": (
            value.get("unpatched_failure_fingerprint")
            == base.EXPECTED_UNPATCHED_ERROR
        ),
        "census": value.get("authorized_current_census_exact") is True,
        "patched_chain": (
            value.get("patched_stage_b_chain_all_pass") is True
            and value.get("patched_stage_b_check_count")
            == EXPECTED_COUNTS["stage_b_checks"]
            and value.get("patched_stage_b_locked_file_count")
            == EXPECTED_COUNTS["stage_b_locked_files"]
            and value.get("patched_stage_b_outcome_binding_count")
            == EXPECTED_COUNTS["stage_b_outcome_bindings"]
        ),
        "science": value.get("scientific_change") is False,
        "target": value.get("target_outcomes_semantically_opened") is False,
        "pre_reveal": value.get("pre_reveal_outputs_absent") is True,
        "claim": value.get("claim_boundary") == lock.get("claim_boundary"),
    }
    if not all(checks.values()):
        failed = [key for key, passed in checks.items() if not passed]
        raise RuntimeError(
            "strict amendment verification failed: " + ", ".join(failed)
        )
    return value


def freeze() -> None:
    no_reveal_outputs()
    error = base.diagnose_unpatched_failure()
    census = base.validate_authorized_current_census()
    chain = base.validate_patched_stage_b_chain()
    if (
        len(chain["checks"]) != EXPECTED_COUNTS["stage_b_checks"]
        or len(chain["file_checks"])
        != EXPECTED_COUNTS["stage_b_locked_files"]
        or len(chain["outcome_binding_checks"])
        != EXPECTED_COUNTS["stage_b_outcome_bindings"]
    ):
        raise RuntimeError("patched Stage-B counts changed")

    stage_a_ack = read_json(
        ORIGINAL_ROOT / "receipts" / "R4_5_STAGE_A_TIMESTAMP_ACK.json"
    )
    stage_b_ack = read_json(
        ORIGINAL_ROOT / "receipts" / "R4_5_EXTERNAL_TIMESTAMP_ACK.json"
    )
    payload = {
        "schema": "cacl-oc-r4.5.1-amendment-v2-lock-v1",
        "status": "R4_5_1_AMENDMENT_V2_LOCKED_PRE_REVEAL",
        "scientific_change": False,
        "target_outcomes_semantically_opened": False,
        "rejected_draft_used_for_authorization": False,
        "rejected_draft_lock_sha256": integrity.sha256(base.LOCK_PATH),
        "registered_failure_fingerprint": error,
        "historical_candidate_paths": base.HISTORICAL_PATHS,
        "authorized_post_stage_a_paths": (
            base.AUTHORIZED_POST_STAGE_A_PATHS
        ),
        "current_candidate_paths": census["current_paths"],
        "authorized_artifact_checks": census[
            "authorized_artifact_checks"
        ],
        "patched_stage_b_check_count": len(chain["checks"]),
        "patched_stage_b_locked_file_count": len(chain["file_checks"]),
        "patched_stage_b_outcome_binding_count": len(
            chain["outcome_binding_checks"]
        ),
        "patched_stage_b_all_pass": True,
        "stage_a_public_commit_sha": stage_a_ack["public_commit_sha"],
        "stage_b_public_commit_sha": stage_b_ack["public_commit_sha"],
        "stage_a_timestamp_utc": stage_a_ack["public_timestamp_utc"],
        "stage_b_timestamp_utc": stage_b_ack["public_timestamp_utc"],
        "amendment_files": {
            relative: artifact(relative) for relative in SOURCE_PATHS
        },
        "rejected_draft_files": {
            relative: artifact(relative)
            for relative in REJECTED_DRAFT_PATHS
        },
        "critical_original_files": {
            relative: artifact(relative)
            for relative in base.CRITICAL_ORIGINAL_PATHS
        },
        "public_text_paths": PUBLIC_PATHS,
        "pre_reveal_outputs_absent": True,
        "write_once": True,
        "claim_boundary": (
            "Target-outcome-uninformed computational confirmation under "
            "a transparently amended infrastructure validator; not an "
            "unamended run, independent custody, causal, clinical, "
            "wet-lab, prospective physical acquisition, or field-safety "
            "claim."
        ),
    }
    write_json_once(LOCK_PATH, payload)
    print("R4_5_1_AMENDMENT_V2_LOCKED_PRE_REVEAL")
    print(f"lock_sha256={integrity.sha256(LOCK_PATH)}")


def create_ack(commit_sha: str, prefix: str) -> None:
    no_reveal_outputs()
    lock = structural_lock_validation(require_pre_reveal_census=True)
    if (
        not prefix
        or prefix.startswith("/")
        or "\\" in prefix
        or ".." in Path(prefix).parts
    ):
        raise RuntimeError("invalid remote prefix")
    live = commit_metadata(commit_sha)
    rows = remote_file_recheck(
        commit_sha=commit_sha,
        prefix=prefix,
        paths=PUBLIC_PATHS,
    )
    if not (
        parse_utc(lock["stage_b_timestamp_utc"])
        < parse_utc(live["timestamp_utc"])
    ):
        raise RuntimeError("amendment commit is not after Stage B")
    verified = {
        relative: {
            "remote_path": rows[relative]["remote_path"],
            "bytes": rows[relative]["bytes"],
            "sha256": rows[relative]["sha256"],
        }
        for relative in PUBLIC_PATHS
    }
    payload = {
        "schema": "cacl-oc-r4.5.1-amendment-v2-timestamp-ack-v1",
        "status": "R4_5_1_AMENDMENT_V2_PUBLICLY_BYTE_VERIFIED",
        "public_commit_sha": commit_sha,
        "public_timestamp_utc": live["timestamp_utc"],
        "public_url": (
            f"https://github.com/{REPOSITORY}/commit/{commit_sha}"
        ),
        "remote_path_prefix": prefix.rstrip("/"),
        "local_lock_sha256": integrity.sha256(LOCK_PATH),
        "remote_lock_sha256": integrity.sha256(LOCK_PATH),
        "remote_file_count": len(PUBLIC_PATHS),
        "remote_files_exactly_match_local": True,
        "target_outcomes_semantically_decoded_by_this_verifier": False,
        "verified_remote_files": verified,
        "write_once": True,
    }
    write_json_once(ACK_PATH, payload)
    print("R4_5_1_AMENDMENT_V2_PUBLIC_ACK_COMPLETE")
    print(f"ack_sha256={integrity.sha256(ACK_PATH)}")


def verify() -> None:
    no_reveal_outputs()
    lock = structural_lock_validation(require_pre_reveal_census=True)
    ack_result = strict_ack_validation(lock, network=True)
    stage_a = base.original_remote_recheck(
        ORIGINAL_ROOT / "receipts" / "R4_5_STAGE_A_TIMESTAMP_ACK.json"
    )
    stage_b = base.original_remote_recheck(
        ORIGINAL_ROOT / "receipts" / "R4_5_EXTERNAL_TIMESTAMP_ACK.json"
    )
    if not (
        parse_utc(stage_a["timestamp_utc"])
        < parse_utc(stage_b["timestamp_utc"])
        < parse_utc(ack_result["ack"]["public_timestamp_utc"])
    ):
        raise RuntimeError("Stage-A/Stage-B/amendment order failed")
    error = base.diagnose_unpatched_failure()
    census = base.validate_authorized_current_census()
    chain = base.validate_patched_stage_b_chain()
    payload = {
        "schema": "cacl-oc-r4.5.1-amendment-v2-verification-v1",
        "status": "R4_5_1_AMENDMENT_V2_AUTHORIZES_TARGET_REVEAL",
        "amendment_lock_sha256": integrity.sha256(LOCK_PATH),
        "amendment_ack_sha256": integrity.sha256(ACK_PATH),
        "amendment_public_commit_sha": ack_result["ack"][
            "public_commit_sha"
        ],
        "amendment_public_timestamp_utc": ack_result["ack"][
            "public_timestamp_utc"
        ],
        "public_timestamp_order_exact": True,
        "stage_a_remote_recheck": stage_a,
        "stage_b_remote_recheck": stage_b,
        "amendment_remote_recheck_all_pass": True,
        "amendment_remote_file_count": len(
            ack_result["network_rows"]
        ),
        "unpatched_failure_fingerprint": error,
        "authorized_current_census_exact": census["passes"],
        "patched_stage_b_chain_all_pass": chain["passes"],
        "patched_stage_b_check_count": len(chain["checks"]),
        "patched_stage_b_locked_file_count": len(chain["file_checks"]),
        "patched_stage_b_outcome_binding_count": len(
            chain["outcome_binding_checks"]
        ),
        "scientific_change": False,
        "target_outcomes_semantically_opened": False,
        "pre_reveal_outputs_absent": True,
        "claim_boundary": lock["claim_boundary"],
        "write_once": True,
    }
    write_json_once(VERIFICATION_PATH, payload)
    strict_verification_validation(lock, ack_result)
    print("R4_5_1_AMENDMENT_V2_AUTHORIZES_TARGET_REVEAL")


def require_verified(*, network: bool, pre_reveal: bool) -> dict[str, Any]:
    if pre_reveal:
        no_reveal_outputs()
    lock = structural_lock_validation(
        require_pre_reveal_census=pre_reveal
    )
    ack_result = strict_ack_validation(lock, network=network)
    strict_verification_validation(lock, ack_result)
    return lock


def authorize() -> None:
    require_verified(network=True, pre_reveal=True)
    base.validate_authorized_current_census()
    base.install_phase_aware_patch()
    module = importlib.import_module("verify_r4_5_timestamp")
    module.main()
    print("R4_5_1_AMENDMENT_V2_ORIGINAL_VERIFIER_AUTHORIZED")


def evaluate() -> None:
    original_verification = (
        ORIGINAL_ROOT
        / "receipts"
        / "R4_5_EXTERNAL_TIMESTAMP_VERIFICATION.json"
    )
    if not original_verification.is_file():
        raise RuntimeError("original Stage-B verification is absent")
    # The original verification is the only reveal-related file allowed
    # before this one-shot evaluation begins.
    present = [
        path
        for path in base.PRE_REVEAL_ABSENT_PATHS
        if path != original_verification and path.exists()
    ]
    if present:
        raise RuntimeError("evaluation output already exists")
    require_verified(network=True, pre_reveal=False)
    base.validate_authorized_current_census()
    base.install_phase_aware_patch()
    module = importlib.import_module("cacl_oc_engine")
    module.evaluate_all()


def audit() -> None:
    require_verified(network=False, pre_reveal=False)
    base.install_phase_aware_patch()
    module = importlib.import_module("audit_r4_5_final")
    module.main()


def finalize() -> None:
    if FINAL_AUDIT_PATH.exists():
        raise FileExistsError(f"write-once file exists: {FINAL_AUDIT_PATH}")
    lock = require_verified(network=True, pre_reveal=False)
    paths = {
        "original_timestamp_verification": (
            ORIGINAL_ROOT
            / "receipts"
            / "R4_5_EXTERNAL_TIMESTAMP_VERIFICATION.json"
        ),
        "reveal_started": (
            ORIGINAL_ROOT / "receipts" / "R4_5_REVEAL_STARTED.json"
        ),
        "reveal_completed": (
            ORIGINAL_ROOT / "receipts" / "R4_5_REVEAL_COMPLETED.json"
        ),
        "final_verdict": (
            ORIGINAL_ROOT / "receipts" / "R4_5_FINAL_BATCH_VERDICT.json"
        ),
        "original_final_audit": (
            ORIGINAL_ROOT
            / "receipts"
            / "R4_5_FINAL_INTEGRITY_AUDIT.json"
        ),
    }
    if not all(path.is_file() for path in paths.values()):
        missing = [name for name, path in paths.items() if not path.is_file()]
        raise RuntimeError("final amendment artifacts absent: " + ", ".join(missing))
    reveal = read_json(paths["reveal_started"])
    final = read_json(paths["final_verdict"])
    audit_receipt = read_json(paths["original_final_audit"])
    verification = read_json(VERIFICATION_PATH)
    ordering = (
        parse_utc(verification["amendment_public_timestamp_utc"])
        < parse_utc(reveal["started_utc"])
    )
    checks = {
        "timestamp_order": ordering,
        "target_unopened_before_reveal": (
            reveal.get("target_outcome_semantic_load_before_this_receipt")
            is False
        ),
        "retry_forbidden": reveal.get("retry_permitted") is False,
        "original_final_audit_pass": (
            audit_receipt.get("all_checks_pass") is True
        ),
        "final_status_present": isinstance(final.get("status"), str),
        "scientific_change_false": lock.get("scientific_change") is False,
    }
    if not all(checks.values()):
        failed = [name for name, value in checks.items() if not value]
        raise RuntimeError("amendment final audit failed: " + ", ".join(failed))
    payload = {
        "schema": "cacl-oc-r4.5.1-amendment-v2-final-audit-v1",
        "status": "R4_5_1_AMENDMENT_V2_FINAL_AUDIT_PASS",
        "checks": checks,
        "amendment_lock_sha256": integrity.sha256(LOCK_PATH),
        "amendment_ack_sha256": integrity.sha256(ACK_PATH),
        "amendment_verification_sha256": integrity.sha256(
            VERIFICATION_PATH
        ),
        "bound_original_artifacts": {
            name: {
                "relative_path": str(path.relative_to(PACKAGE)).replace(
                    "\\", "/"
                ),
                "bytes": path.stat().st_size,
                "sha256": integrity.sha256(path),
            }
            for name, path in paths.items()
        },
        "final_campaign_status": final["status"],
        "claim_boundary": lock["claim_boundary"],
        "write_once": True,
    }
    write_json_once(FINAL_AUDIT_PATH, payload)
    print("R4_5_1_AMENDMENT_V2_FINAL_AUDIT_PASS")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="mode", required=True)
    commands.add_parser("freeze")
    ack = commands.add_parser("ack")
    ack.add_argument("--commit-sha", required=True)
    ack.add_argument("--remote-prefix", required=True)
    commands.add_parser("verify")
    commands.add_parser("authorize")
    commands.add_parser("evaluate")
    commands.add_parser("audit")
    commands.add_parser("finalize")
    return result


def main() -> None:
    args = parser().parse_args()
    if args.mode == "freeze":
        freeze()
    elif args.mode == "ack":
        create_ack(args.commit_sha, args.remote_prefix)
    elif args.mode == "verify":
        verify()
    elif args.mode == "authorize":
        authorize()
    elif args.mode == "evaluate":
        evaluate()
    elif args.mode == "audit":
        audit()
    elif args.mode == "finalize":
        finalize()
    else:  # pragma: no cover
        raise RuntimeError(f"unsupported command: {args.mode}")


if __name__ == "__main__":
    main()
