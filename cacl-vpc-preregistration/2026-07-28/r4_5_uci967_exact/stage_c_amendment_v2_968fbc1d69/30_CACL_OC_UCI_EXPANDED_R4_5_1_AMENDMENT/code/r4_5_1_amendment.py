#!/usr/bin/env python3
"""Public, pre-reveal infrastructure amendment for CACL-OC R4.5.

This module never changes a frozen R4.5 file.  It corrects only the phase of
one prior-access census check, while replacing that invalid post-access check
with an exact whitelist and Stage-B-lock rehash of the authorized artifacts.
"""

from __future__ import annotations

import argparse
import importlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote
from urllib.request import Request, urlopen


HERE = Path(__file__).resolve()
AMENDMENT_ROOT = HERE.parents[1]
PACKAGE = AMENDMENT_ROOT.parent
ORIGINAL_ROOT = PACKAGE / "29_CACL_OC_UCI_EXPANDED_R4_5"
ORIGINAL_CODE = ORIGINAL_ROOT / "code"
RECEIPTS = AMENDMENT_ROOT / "receipts"
REPOSITORY = "cmkim0408/Changman-s-Lab"

if str(ORIGINAL_CODE) not in sys.path:
    sys.path.insert(0, str(ORIGINAL_CODE))

import integrity  # noqa: E402


LOCK_PATH = RECEIPTS / "R4_5_1_AMENDMENT_LOCAL_LOCK.json"
ACK_PATH = RECEIPTS / "R4_5_1_AMENDMENT_TIMESTAMP_ACK.json"
VERIFICATION_PATH = (
    RECEIPTS / "R4_5_1_AMENDMENT_TIMESTAMP_VERIFICATION.json"
)

EXPECTED_UNPATCHED_ERROR = (
    "R4.5 prior-access audit validation failed: "
    "current_prelock_path_census_exact"
)

HISTORICAL_PATHS = [
    (
        "21_CACL_VPC_UCI_CLOSED_BATCH/registry_snapshot/"
        "metadata/uci_967.json"
    ),
    (
        "22_CACL_VPC_UCI_BINARY_VERIFIED_BATCH/"
        "registry_snapshot/metadata/uci_967.json"
    ),
]

AUTHORIZED_POST_STAGE_A_PATHS = [
    (
        "29_CACL_OC_UCI_EXPANDED_R4_5/prepared_census/uci_967/"
        "PREPARATION_RECEIPT.json"
    ),
    (
        "29_CACL_OC_UCI_EXPANDED_R4_5/prepared_census/uci_967/"
        "raw_official.csv"
    ),
    (
        "29_CACL_OC_UCI_EXPANDED_R4_5/prepared_census/uci_967/"
        "source.npz"
    ),
    (
        "29_CACL_OC_UCI_EXPANDED_R4_5/prepared_census/uci_967/"
        "target_features.npz"
    ),
    (
        "29_CACL_OC_UCI_EXPANDED_R4_5/prepared_census/uci_967/"
        "target_outcomes.npz"
    ),
    (
        "29_CACL_OC_UCI_EXPANDED_R4_5/registered_census/uci_967/"
        "FROZEN_POLICY.joblib"
    ),
    (
        "29_CACL_OC_UCI_EXPANDED_R4_5/registered_census/uci_967/"
        "SEALED_TARGET_ACTIONS.npz"
    ),
    (
        "29_CACL_OC_UCI_EXPANDED_R4_5/registered_census/uci_967/"
        "SOURCE_FREEZE_RECEIPT.json"
    ),
]

CRITICAL_ORIGINAL_PATHS = [
    "29_CACL_OC_UCI_EXPANDED_R4_5/R4_5_PROTOCOL.md",
    "29_CACL_OC_UCI_EXPANDED_R4_5/config/r4_5_contract.json",
    "29_CACL_OC_UCI_EXPANDED_R4_5/code/integrity.py",
    "29_CACL_OC_UCI_EXPANDED_R4_5/code/cacl_oc_engine.py",
    "29_CACL_OC_UCI_EXPANDED_R4_5/code/audit_r4_5_final.py",
    "29_CACL_OC_UCI_EXPANDED_R4_5/code/verify_r4_5_timestamp.py",
    (
        "29_CACL_OC_UCI_EXPANDED_R4_5/receipts/"
        "R4_5_STAGE_A_LOCAL_LOCK.json"
    ),
    (
        "29_CACL_OC_UCI_EXPANDED_R4_5/receipts/"
        "R4_5_STAGE_A_TIMESTAMP_ACK.json"
    ),
    (
        "29_CACL_OC_UCI_EXPANDED_R4_5/receipts/"
        "R4_5_STAGE_A_TIMESTAMP_VERIFICATION.json"
    ),
    (
        "29_CACL_OC_UCI_EXPANDED_R4_5/receipts/"
        "R4_5_LOCAL_LOCK.json"
    ),
    (
        "29_CACL_OC_UCI_EXPANDED_R4_5/receipts/"
        "R4_5_EXTERNAL_TIMESTAMP_ACK.json"
    ),
]

AMENDMENT_SOURCE_PATHS = [
    (
        "30_CACL_OC_UCI_EXPANDED_R4_5_1_AMENDMENT/"
        "AMENDMENT_PROTOCOL.md"
    ),
    (
        "30_CACL_OC_UCI_EXPANDED_R4_5_1_AMENDMENT/code/"
        "r4_5_1_amendment.py"
    ),
]

PUBLIC_ORIGINAL_CHAIN_PATHS = [
    (
        "29_CACL_OC_UCI_EXPANDED_R4_5/receipts/"
        "R4_5_STAGE_A_LOCAL_LOCK.json"
    ),
    (
        "29_CACL_OC_UCI_EXPANDED_R4_5/receipts/"
        "R4_5_STAGE_A_TIMESTAMP_ACK.json"
    ),
    (
        "29_CACL_OC_UCI_EXPANDED_R4_5/receipts/"
        "R4_5_STAGE_A_TIMESTAMP_VERIFICATION.json"
    ),
    (
        "29_CACL_OC_UCI_EXPANDED_R4_5/receipts/"
        "R4_5_LOCAL_LOCK.json"
    ),
    (
        "29_CACL_OC_UCI_EXPANDED_R4_5/receipts/"
        "R4_5_EXTERNAL_TIMESTAMP_ACK.json"
    ),
]

PRE_REVEAL_ABSENT_PATHS = [
    ORIGINAL_ROOT / "receipts" / "R4_5_EXTERNAL_TIMESTAMP_VERIFICATION.json",
    ORIGINAL_ROOT / "receipts" / "R4_5_REVEAL_STARTED.json",
    ORIGINAL_ROOT / "receipts" / "R4_5_REVEAL_COMPLETED.json",
    ORIGINAL_ROOT / "receipts" / "R4_5_FINAL_BATCH_VERDICT.json",
    ORIGINAL_ROOT / "receipts" / "R4_5_FINAL_INTEGRITY_AUDIT.json",
    *[
        ORIGINAL_ROOT
        / "registered_census"
        / f"uci_{dataset_id}"
        / "TARGET_VERDICT.json"
        for dataset_id in (75, 327, 572, 967)
    ],
]


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise RuntimeError(f"expected object: {path}")
    return value


def write_json_once(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(
        payload, indent=2, sort_keys=True, ensure_ascii=False
    ) + "\n"
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def package_path(relative: str) -> Path:
    candidate = (PACKAGE / relative).resolve()
    if not candidate.is_relative_to(PACKAGE.resolve()):
        raise RuntimeError(f"path escapes package: {relative}")
    return candidate


def artifact(path: Path) -> dict[str, Any]:
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
            "User-Agent": "CACL-R4.5.1-amendment",
        },
    )
    with urlopen(request, timeout=60) as response:
        return response.read(), response.geturl()


def assert_pre_reveal_absence() -> None:
    present = [
        str(path.relative_to(PACKAGE))
        for path in PRE_REVEAL_ABSENT_PATHS
        if path.exists()
    ]
    if present:
        raise RuntimeError(
            "pre-reveal amendment attempted after reveal output: "
            + ", ".join(present)
        )


def diagnose_unpatched_failure() -> str:
    try:
        integrity.validate_ack_and_lock()
    except RuntimeError as exc:
        observed = str(exc)
    else:
        raise RuntimeError("registered unpatched failure was not reproduced")
    if observed != EXPECTED_UNPATCHED_ERROR:
        raise RuntimeError(
            "unpatched failure fingerprint changed: " + observed
        )
    return observed


def validate_authorized_current_census() -> dict[str, Any]:
    current = integrity._current_candidate_path_hits()
    expected = sorted(HISTORICAL_PATHS + AUTHORIZED_POST_STAGE_A_PATHS)
    stage_b_lock = read_json(
        ORIGINAL_ROOT / "receipts" / "R4_5_LOCAL_LOCK.json"
    )
    checks: dict[str, bool] = {
        "current_census_exact": current == expected,
        "historical_prefix_exact": (
            read_json(
                ORIGINAL_ROOT
                / "receipts"
                / "R4_5_PRIOR_ACCESS_AUDIT.json"
            ).get("candidate_path_hits")
            == HISTORICAL_PATHS
        ),
    }
    artifact_checks: dict[str, dict[str, Any]] = {}
    for relative in AUTHORIZED_POST_STAGE_A_PATHS:
        path = package_path(relative)
        expected_artifact = stage_b_lock.get("files", {}).get(relative)
        row = {
            "exists": path.is_file(),
            "bound_by_stage_b_lock": isinstance(expected_artifact, dict),
            "bytes_match": (
                path.is_file()
                and isinstance(expected_artifact, dict)
                and path.stat().st_size == expected_artifact.get("bytes")
            ),
            "sha256_match": (
                path.is_file()
                and isinstance(expected_artifact, dict)
                and integrity.sha256(path)
                == expected_artifact.get("sha256")
            ),
        }
        row["passes"] = all(row.values())
        artifact_checks[relative] = row
    checks["all_authorized_artifacts_locked_and_current"] = all(
        row["passes"] for row in artifact_checks.values()
    )
    if not all(checks.values()):
        failed = [name for name, value in checks.items() if not value]
        raise RuntimeError(
            "authorized post-Stage-A census failed: " + ", ".join(failed)
        )
    return {
        "checks": checks,
        "current_paths": current,
        "authorized_artifact_checks": artifact_checks,
        "passes": True,
    }


def install_phase_aware_patch() -> None:
    if getattr(
        integrity.validate_prior_access_audit,
        "_r4_5_1_phase_aware",
        False,
    ):
        return
    original = integrity.validate_prior_access_audit

    def phase_aware_prior_access(
        *, recompute_current_census: bool = False
    ) -> dict[str, Any]:
        # The current post-authorization census is checked separately and
        # exactly against the Stage-B lock.  The historical audit must remain
        # scoped to the public Stage-A snapshot.
        return original(recompute_current_census=False)

    phase_aware_prior_access._r4_5_1_phase_aware = True  # type: ignore[attr-defined]
    phase_aware_prior_access._r4_5_1_original = original  # type: ignore[attr-defined]
    integrity.validate_prior_access_audit = phase_aware_prior_access


def validate_patched_stage_b_chain() -> dict[str, Any]:
    validate_authorized_current_census()
    install_phase_aware_patch()
    chain = integrity.validate_ack_and_lock()
    if not chain.get("passes"):
        raise RuntimeError("patched Stage-B chain did not pass")
    if not all(
        row.get("passes") for row in chain.get("file_checks", {}).values()
    ):
        raise RuntimeError("a Stage-B locked file did not rehash")
    if not all(
        row.get("passes")
        for row in chain.get("outcome_binding_checks", {}).values()
    ):
        raise RuntimeError("an outcome binding did not rehash")
    return chain


def original_remote_recheck(ack_path: Path) -> dict[str, Any]:
    ack = read_json(ack_path)
    commit = str(ack.get("public_commit_sha", ""))
    prefix = str(ack.get("remote_path_prefix", "")).rstrip("/")
    verified = ack.get("verified_remote_files", {})
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise RuntimeError(f"invalid original commit: {ack_path}")
    rows: dict[str, dict[str, Any]] = {}
    for relative, expected in verified.items():
        remote_path = f"{prefix}/{relative}"
        url = (
            f"https://raw.githubusercontent.com/{REPOSITORY}/"
            f"{commit}/{quote(remote_path, safe='/')}"
        )
        payload, final_url = request_bytes(url)
        row = {
            "bytes_match": len(payload) == expected.get("bytes"),
            "sha256_match": (
                integrity.sha256_bytes(payload) == expected.get("sha256")
            ),
            "final_url_https": final_url.startswith("https://"),
        }
        row["passes"] = all(row.values())
        rows[relative] = row
    if (
        not rows
        or set(rows) != set(verified)
        or not all(row["passes"] for row in rows.values())
    ):
        raise RuntimeError(f"original public chain recheck failed: {ack_path}")
    return {
        "commit_sha": commit,
        "timestamp_utc": ack["public_timestamp_utc"],
        "remote_file_count": len(rows),
        "passes": True,
    }


def validate_local_lock() -> dict[str, Any]:
    lock = read_json(LOCK_PATH)
    if (
        lock.get("schema") != "cacl-oc-r4.5.1-amendment-lock-v1"
        or lock.get("status") != "R4_5_1_AMENDMENT_LOCKED_PRE_REVEAL"
        or lock.get("scientific_change") is not False
        or lock.get("target_outcomes_semantically_opened") is not False
    ):
        raise RuntimeError("invalid amendment lock header")
    for section in ("amendment_files", "critical_original_files"):
        for relative, expected in lock.get(section, {}).items():
            path = package_path(relative)
            if (
                not path.is_file()
                or path.stat().st_size != expected.get("bytes")
                or integrity.sha256(path) != expected.get("sha256")
            ):
                raise RuntimeError(
                    f"amendment lock rehash failed: {relative}"
                )
    return lock


def freeze() -> None:
    assert_pre_reveal_absence()
    observed_error = diagnose_unpatched_failure()
    census = validate_authorized_current_census()
    chain = validate_patched_stage_b_chain()

    amendment_files = {
        relative: artifact(package_path(relative))
        for relative in AMENDMENT_SOURCE_PATHS
    }
    critical_original = {
        relative: artifact(package_path(relative))
        for relative in CRITICAL_ORIGINAL_PATHS
    }
    public_paths = (
        AMENDMENT_SOURCE_PATHS
        + PUBLIC_ORIGINAL_CHAIN_PATHS
        + [
            (
                "30_CACL_OC_UCI_EXPANDED_R4_5_1_AMENDMENT/receipts/"
                "R4_5_1_AMENDMENT_LOCAL_LOCK.json"
            )
        ]
    )
    payload = {
        "schema": "cacl-oc-r4.5.1-amendment-lock-v1",
        "status": "R4_5_1_AMENDMENT_LOCKED_PRE_REVEAL",
        "scientific_change": False,
        "target_outcomes_semantically_opened": False,
        "registered_failure_fingerprint": observed_error,
        "correction": (
            "scope the Stage-A path census to the public pre-access "
            "snapshot; replace its invalid post-access replay with an "
            "exact Stage-B-locked authorized-artifact census"
        ),
        "current_candidate_paths": census["current_paths"],
        "historical_candidate_paths": HISTORICAL_PATHS,
        "authorized_post_stage_a_paths": AUTHORIZED_POST_STAGE_A_PATHS,
        "authorized_artifact_checks": census[
            "authorized_artifact_checks"
        ],
        "patched_stage_b_check_count": len(chain["checks"]),
        "patched_stage_b_locked_file_count": len(chain["file_checks"]),
        "patched_stage_b_outcome_binding_count": len(
            chain["outcome_binding_checks"]
        ),
        "patched_stage_b_all_pass": True,
        "stage_a_public_commit_sha": chain["stage_a_public_commit_sha"],
        "stage_b_public_commit_sha": chain["public_commit_sha"],
        "stage_a_timestamp_utc": read_json(
            ORIGINAL_ROOT
            / "receipts"
            / "R4_5_STAGE_A_TIMESTAMP_ACK.json"
        )["public_timestamp_utc"],
        "stage_b_timestamp_utc": read_json(
            ORIGINAL_ROOT
            / "receipts"
            / "R4_5_EXTERNAL_TIMESTAMP_ACK.json"
        )["public_timestamp_utc"],
        "amendment_files": amendment_files,
        "critical_original_files": critical_original,
        "public_text_paths": public_paths,
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
    print("R4_5_1_AMENDMENT_LOCKED_PRE_REVEAL")
    print(f"lock_sha256={integrity.sha256(LOCK_PATH)}")


def create_ack(commit_sha: str, remote_prefix: str) -> None:
    assert_pre_reveal_absence()
    lock = validate_local_lock()
    if not re.fullmatch(r"[0-9a-f]{40}", commit_sha):
        raise RuntimeError("commit SHA must be 40 lowercase hex characters")
    if (
        not remote_prefix
        or remote_prefix.startswith("/")
        or "\\" in remote_prefix
        or ".." in Path(remote_prefix).parts
    ):
        raise RuntimeError("invalid remote prefix")

    commit_url = (
        f"https://api.github.com/repos/{REPOSITORY}/commits/{commit_sha}"
    )
    commit_payload, _ = request_bytes(commit_url)
    commit = json.loads(commit_payload.decode("utf-8"))
    if commit.get("sha") != commit_sha:
        raise RuntimeError("commit API did not return the requested SHA")
    timestamp = commit["commit"]["committer"]["date"]

    rows: dict[str, dict[str, Any]] = {}
    for relative in lock["public_text_paths"]:
        local = package_path(relative).read_bytes()
        remote_path = f"{remote_prefix.rstrip('/')}/{relative}"
        url = (
            f"https://raw.githubusercontent.com/{REPOSITORY}/"
            f"{commit_sha}/{quote(remote_path, safe='/')}"
        )
        remote, final_url = request_bytes(url)
        if remote != local:
            raise RuntimeError(f"remote bytes differ: {relative}")
        rows[relative] = {
            "bytes": len(remote),
            "sha256": integrity.sha256_bytes(remote),
            "remote_path": remote_path,
            "final_url": final_url,
        }

    stage_b_time = parse_utc(str(lock["stage_b_timestamp_utc"]))
    amendment_time = parse_utc(timestamp)
    if not stage_b_time < amendment_time:
        raise RuntimeError("amendment timestamp does not follow Stage B")
    payload = {
        "schema": "cacl-oc-r4.5.1-amendment-timestamp-ack-v1",
        "status": "R4_5_1_AMENDMENT_PUBLICLY_BYTE_VERIFIED",
        "public_commit_sha": commit_sha,
        "public_timestamp_utc": timestamp,
        "public_url": (
            f"https://github.com/{REPOSITORY}/commit/{commit_sha}"
        ),
        "remote_path_prefix": remote_prefix.rstrip("/"),
        "local_lock_sha256": integrity.sha256(LOCK_PATH),
        "remote_lock_sha256": integrity.sha256(LOCK_PATH),
        "remote_file_count": len(rows),
        "remote_files_exactly_match_local": True,
        "target_outcomes_semantically_decoded_by_this_verifier": False,
        "verified_remote_files": rows,
        "write_once": True,
    }
    write_json_once(ACK_PATH, payload)
    print("R4_5_1_AMENDMENT_PUBLIC_ACK_COMPLETE")
    print(f"ack_sha256={integrity.sha256(ACK_PATH)}")


def verify() -> None:
    assert_pre_reveal_absence()
    lock = validate_local_lock()
    ack = read_json(ACK_PATH)
    if (
        ack.get("schema")
        != "cacl-oc-r4.5.1-amendment-timestamp-ack-v1"
        or ack.get("status")
        != "R4_5_1_AMENDMENT_PUBLICLY_BYTE_VERIFIED"
        or ack.get("local_lock_sha256") != integrity.sha256(LOCK_PATH)
        or ack.get("remote_lock_sha256") != integrity.sha256(LOCK_PATH)
        or ack.get("remote_files_exactly_match_local") is not True
        or ack.get(
            "target_outcomes_semantically_decoded_by_this_verifier"
        )
        is not False
    ):
        raise RuntimeError("invalid amendment ACK")

    commit = str(ack["public_commit_sha"])
    prefix = str(ack["remote_path_prefix"]).rstrip("/")
    remote_rows: dict[str, dict[str, Any]] = {}
    for relative in lock["public_text_paths"]:
        local = package_path(relative).read_bytes()
        url = (
            f"https://raw.githubusercontent.com/{REPOSITORY}/"
            f"{commit}/{quote(prefix + '/' + relative, safe='/')}"
        )
        remote, final_url = request_bytes(url)
        row = {
            "bytes_match": len(remote) == len(local),
            "sha256_match": (
                integrity.sha256_bytes(remote)
                == integrity.sha256_bytes(local)
            ),
            "final_url_https": final_url.startswith("https://"),
        }
        row["passes"] = all(row.values())
        remote_rows[relative] = row
    if not all(row["passes"] for row in remote_rows.values()):
        raise RuntimeError("amendment public recheck failed")

    stage_a_remote = original_remote_recheck(
        ORIGINAL_ROOT
        / "receipts"
        / "R4_5_STAGE_A_TIMESTAMP_ACK.json"
    )
    stage_b_remote = original_remote_recheck(
        ORIGINAL_ROOT
        / "receipts"
        / "R4_5_EXTERNAL_TIMESTAMP_ACK.json"
    )
    amendment_time = parse_utc(str(ack["public_timestamp_utc"]))
    if not (
        parse_utc(stage_a_remote["timestamp_utc"])
        < parse_utc(stage_b_remote["timestamp_utc"])
        < amendment_time
    ):
        raise RuntimeError("public timestamp order is invalid")

    observed_error = diagnose_unpatched_failure()
    census = validate_authorized_current_census()
    chain = validate_patched_stage_b_chain()
    payload = {
        "schema": "cacl-oc-r4.5.1-amendment-verification-v1",
        "status": "R4_5_1_AMENDMENT_AUTHORIZES_TARGET_REVEAL",
        "amendment_lock_sha256": integrity.sha256(LOCK_PATH),
        "amendment_ack_sha256": integrity.sha256(ACK_PATH),
        "amendment_public_commit_sha": commit,
        "amendment_public_timestamp_utc": ack[
            "public_timestamp_utc"
        ],
        "public_timestamp_order_exact": True,
        "stage_a_remote_recheck": stage_a_remote,
        "stage_b_remote_recheck": stage_b_remote,
        "amendment_remote_file_count": len(remote_rows),
        "amendment_remote_recheck_all_pass": True,
        "unpatched_failure_fingerprint": observed_error,
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
    print("R4_5_1_AMENDMENT_AUTHORIZES_TARGET_REVEAL")


def require_verified_amendment(*, pre_reveal: bool) -> dict[str, Any]:
    if pre_reveal:
        assert_pre_reveal_absence()
    lock = validate_local_lock()
    ack = read_json(ACK_PATH)
    verification = read_json(VERIFICATION_PATH)
    checks = {
        "verification_schema": (
            verification.get("schema")
            == "cacl-oc-r4.5.1-amendment-verification-v1"
        ),
        "verification_status": (
            verification.get("status")
            == "R4_5_1_AMENDMENT_AUTHORIZES_TARGET_REVEAL"
        ),
        "lock_hash": (
            verification.get("amendment_lock_sha256")
            == integrity.sha256(LOCK_PATH)
        ),
        "ack_hash": (
            verification.get("amendment_ack_sha256")
            == integrity.sha256(ACK_PATH)
        ),
        "commit": (
            verification.get("amendment_public_commit_sha")
            == ack.get("public_commit_sha")
        ),
        "scientific_change_false": (
            verification.get("scientific_change") is False
            and lock.get("scientific_change") is False
        ),
        "target_unopened_at_verification": (
            verification.get("target_outcomes_semantically_opened")
            is False
        ),
    }
    if not all(checks.values()):
        failed = [name for name, value in checks.items() if not value]
        raise RuntimeError(
            "amendment verification is invalid: " + ", ".join(failed)
        )
    return verification


def authorize_original_verifier() -> None:
    require_verified_amendment(pre_reveal=True)
    validate_authorized_current_census()
    install_phase_aware_patch()
    module = importlib.import_module("verify_r4_5_timestamp")
    module.main()
    print("R4_5_1_ORIGINAL_VERIFIER_AUTHORIZED")


def evaluate() -> None:
    require_verified_amendment(pre_reveal=False)
    original_verification = (
        ORIGINAL_ROOT
        / "receipts"
        / "R4_5_EXTERNAL_TIMESTAMP_VERIFICATION.json"
    )
    if not original_verification.is_file():
        raise RuntimeError("original Stage-B verification is absent")
    if any(
        path.exists()
        for path in PRE_REVEAL_ABSENT_PATHS
        if path != original_verification
    ):
        raise RuntimeError("evaluation output already exists")
    validate_authorized_current_census()
    install_phase_aware_patch()
    module = importlib.import_module("cacl_oc_engine")
    module.evaluate_all()


def audit() -> None:
    require_verified_amendment(pre_reveal=False)
    install_phase_aware_patch()
    module = importlib.import_module("audit_r4_5_final")
    module.main()


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    subparsers = result.add_subparsers(dest="mode", required=True)
    subparsers.add_parser("freeze")
    ack_parser = subparsers.add_parser("ack")
    ack_parser.add_argument("--commit-sha", required=True)
    ack_parser.add_argument("--remote-prefix", required=True)
    subparsers.add_parser("verify")
    subparsers.add_parser("authorize")
    subparsers.add_parser("evaluate")
    subparsers.add_parser("audit")
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
        authorize_original_verifier()
    elif args.mode == "evaluate":
        evaluate()
    elif args.mode == "audit":
        audit()
    else:  # pragma: no cover
        raise RuntimeError(f"unsupported mode: {args.mode}")


if __name__ == "__main__":
    main()
