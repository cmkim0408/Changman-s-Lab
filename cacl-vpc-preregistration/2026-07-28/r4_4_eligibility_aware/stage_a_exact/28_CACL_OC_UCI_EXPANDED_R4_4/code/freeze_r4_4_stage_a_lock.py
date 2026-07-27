#!/usr/bin/env python3
"""Hash-lock R4.4 dataset registration before new-data access."""

from __future__ import annotations

from integrity import (
    NEW_IDS,
    PACKAGE,
    RECEIPTS,
    ROOT,
    exclusive_write_json,
    sha256,
    stage_a_required_paths,
    validate_prior_access_audit,
)


def main() -> None:
    output = RECEIPTS / "R4_4_STAGE_A_LOCAL_LOCK.json"
    if output.exists():
        raise FileExistsError(f"write-once Stage-A lock exists: {output}")
    already_present = [
        ROOT / "prepared_census" / f"uci_{dataset_id}"
        for dataset_id in NEW_IDS
        if (ROOT / "prepared_census" / f"uci_{dataset_id}").exists()
    ]
    if already_present:
        raise RuntimeError(
            "Stage-A lock refused because new instance-level data paths "
            "already exist: " + ", ".join(map(str, already_present))
        )
    prior_access = validate_prior_access_audit(
        recompute_current_census=True
    )
    files = stage_a_required_paths()
    relative_files = [
        str(path.relative_to(PACKAGE)).replace("\\", "/")
        for path in files
    ]
    lock_relative = str(output.relative_to(PACKAGE)).replace("\\", "/")
    payload = {
        "schema": "cacl-oc-r4.4-stage-a-local-lock-v1",
        "status": "R4_4_STAGE_A_LOCKED_BEFORE_NEW_DATA_ACCESS",
        "new_registered_ids": NEW_IDS,
        "new_data_downloaded": False,
        "prior_access_audit_sha256": prior_access["sha256"],
        "prelock_candidate_path_hits": prior_access[
            "current_path_hits"
        ],
        "files": {
            str(path.relative_to(PACKAGE)).replace("\\", "/"): {
                "bytes": path.stat().st_size,
                "sha256": sha256(path),
            }
            for path in files
        },
        "public_text_paths": [*relative_files, lock_relative],
    }
    exclusive_write_json(output, payload)
    print(payload["status"])
    print(f"receipt_sha256={sha256(output)}")


if __name__ == "__main__":
    main()
