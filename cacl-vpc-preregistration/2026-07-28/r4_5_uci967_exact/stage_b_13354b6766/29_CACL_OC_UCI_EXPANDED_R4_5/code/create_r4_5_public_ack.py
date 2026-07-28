#!/usr/bin/env python3
"""Fetch a public GitHub commit byte-for-byte before writing an R4.5 ACK."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote
from urllib.request import Request, urlopen

from integrity import (
    NEW_IDS,
    PACKAGE,
    RECEIPTS,
    REPOSITORY,
    ROOT,
    exclusive_write_json,
    read_json,
    sha256,
)


def fetch_bytes(url: str) -> bytes:
    request = Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "CACL-R4.5-public-byte-verifier",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urlopen(request, timeout=60) as response:
        return response.read()


def fetch_json(url: str) -> dict[str, Any]:
    return json.loads(fetch_bytes(url).decode("utf-8"))


def safe_local(relative: str) -> Path:
    path = (PACKAGE / relative).resolve()
    package = PACKAGE.resolve()
    if path != package and package not in path.parents:
        raise RuntimeError(f"public path escapes package: {relative}")
    return path


def mode_contract(mode: str) -> dict[str, Any]:
    if mode == "stage-a":
        return {
            "lock": RECEIPTS / "R4_5_STAGE_A_LOCAL_LOCK.json",
            "ack": RECEIPTS / "R4_5_STAGE_A_TIMESTAMP_ACK.json",
            "schema": "cacl-oc-r4.5-stage-a-timestamp-ack-v1",
            "unopened_field": "new_instance_data_unopened_at_timestamp",
        }
    return {
        "lock": RECEIPTS / "R4_5_LOCAL_LOCK.json",
        "ack": RECEIPTS / "R4_5_EXTERNAL_TIMESTAMP_ACK.json",
        "schema": "cacl-oc-r4.5-timestamp-ack-v1",
        "unopened_field": (
            "target_outcomes_not_semantically_decoded_by_scientific_"
            "engine_at_timestamp"
        ),
    }


def verify_preconditions(mode: str) -> None:
    if mode == "stage-a":
        present = [
            ROOT / "prepared_census" / f"uci_{dataset_id}"
            for dataset_id in NEW_IDS
            if (
                ROOT / "prepared_census" / f"uci_{dataset_id}"
            ).exists()
        ]
        if present:
            raise RuntimeError(
                "Stage-A ACK refused after new-data path creation: "
                + ", ".join(map(str, present))
            )
        return
    forbidden = [
        RECEIPTS / "R4_5_REVEAL_STARTED.json",
        RECEIPTS / "R4_5_REVEAL_COMPLETED.json",
        RECEIPTS / "R4_5_FINAL_BATCH_VERDICT.json",
    ]
    if any(path.exists() for path in forbidden):
        raise RuntimeError(
            "Stage-B ACK refused after target semantic reveal began"
        )


def create_ack(mode: str, commit_sha: str, remote_prefix: str) -> Path:
    if not re.fullmatch(r"[0-9a-f]{40}", commit_sha):
        raise RuntimeError("commit SHA must be 40 lowercase hex characters")
    if (
        not remote_prefix
        or remote_prefix.startswith("/")
        or "\\" in remote_prefix
    ):
        raise RuntimeError("remote prefix must be a relative repository path")
    if ".." in Path(remote_prefix).parts:
        raise RuntimeError("remote prefix may not contain '..'")

    contract = mode_contract(mode)
    lock_path: Path = contract["lock"]
    output: Path = contract["ack"]
    if output.exists():
        raise FileExistsError(f"write-once ACK already exists: {output}")
    verify_preconditions(mode)
    lock = read_json(lock_path)
    public_paths = list(lock.get("public_text_paths", []))
    if not public_paths or len(public_paths) != len(set(public_paths)):
        raise RuntimeError("public path list is empty or duplicated")

    api_url = (
        f"https://api.github.com/repos/{REPOSITORY}/commits/{commit_sha}"
    )
    commit = fetch_json(api_url)
    if commit.get("sha") != commit_sha:
        raise RuntimeError("GitHub commit API returned a different SHA")
    committed_utc = str(
        commit.get("commit", {}).get("committer", {}).get("date", "")
    )
    parsed = datetime.fromisoformat(
        committed_utc.replace("Z", "+00:00")
    )
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() != timezone.utc.utcoffset(parsed)
        or parsed > datetime.now(timezone.utc)
    ):
        raise RuntimeError("invalid GitHub UTC commit timestamp")

    verified: dict[str, dict[str, Any]] = {}
    remote_lock_payload: bytes | None = None
    lock_relative = str(lock_path.relative_to(PACKAGE)).replace("\\", "/")
    for relative in public_paths:
        local_path = safe_local(relative)
        local_payload = local_path.read_bytes()
        remote_path = f"{remote_prefix.rstrip('/')}/{relative}"
        raw_url = (
            f"https://raw.githubusercontent.com/{REPOSITORY}/"
            f"{commit_sha}/{quote(remote_path, safe='/')}"
        )
        remote_payload = fetch_bytes(raw_url)
        if remote_payload != local_payload:
            raise RuntimeError(
                f"remote bytes differ from local bytes: {relative}"
            )
        digest = hashlib.sha256(remote_payload).hexdigest()
        verified[relative] = {
            "remote_path": remote_path,
            "bytes": len(remote_payload),
            "sha256": digest,
        }
        if relative == lock_relative:
            remote_lock_payload = remote_payload

    if remote_lock_payload is None:
        raise RuntimeError("public file set did not include the lock itself")
    lock_hash = sha256(lock_path)
    remote_lock_hash = hashlib.sha256(remote_lock_payload).hexdigest()
    if remote_lock_hash != lock_hash:
        raise RuntimeError("remote lock hash mismatch")

    receipt = {
        "schema": contract["schema"],
        "public_url": (
            f"https://github.com/{REPOSITORY}/commit/{commit_sha}"
        ),
        "public_commit_sha": commit_sha,
        "public_timestamp_utc": committed_utc,
        "local_lock_sha256": lock_hash,
        "remote_lock_sha256": remote_lock_hash,
        "remote_file_count": len(verified),
        "remote_files_exactly_match_local": True,
        contract["unopened_field"]: True,
        "remote_path_prefix": remote_prefix.rstrip("/"),
        "commit_api_url": api_url,
        "verified_remote_files": verified,
        "ack_created_by_network_fetch": True,
        "target_outcomes_semantically_decoded_by_this_verifier": False,
    }
    exclusive_write_json(output, receipt)
    return output


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("mode", choices=["stage-a", "stage-b"])
    result.add_argument("--commit-sha", required=True)
    result.add_argument("--remote-prefix", required=True)
    return result


def main() -> None:
    args = parser().parse_args()
    output = create_ack(
        args.mode, args.commit_sha, args.remote_prefix
    )
    print(f"PUBLIC_ACK_BYTE_VERIFIED={output.name}")
    print(f"ack_sha256={sha256(output)}")


if __name__ == "__main__":
    main()
