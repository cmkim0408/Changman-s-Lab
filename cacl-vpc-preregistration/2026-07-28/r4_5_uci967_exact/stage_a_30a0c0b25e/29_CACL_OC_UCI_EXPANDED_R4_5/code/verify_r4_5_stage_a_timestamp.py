#!/usr/bin/env python3
"""Verify the public Stage-A registration before new-data access."""

from __future__ import annotations

from integrity import (
    RECEIPTS,
    exclusive_write_json,
    validate_stage_a_ack_and_lock,
)


def main() -> None:
    output = RECEIPTS / "R4_5_STAGE_A_TIMESTAMP_VERIFICATION.json"
    if output.exists():
        raise FileExistsError(
            f"write-once Stage-A verification exists: {output}"
        )
    chain = validate_stage_a_ack_and_lock()
    receipt = {
        "schema": "cacl-oc-r4.5-stage-a-verification-v1",
        "status": "R4_5_STAGE_A_DATA_ACCESS_AUTHORIZED",
        "lock_sha256": chain["lock_sha256"],
        "ack_sha256": chain["ack_sha256"],
        "public_commit_sha": chain["public_commit_sha"],
        "all_locked_files_current": True,
        "new_data_access_permitted_after_receipt": True,
    }
    exclusive_write_json(output, receipt)
    print(receipt["status"])


if __name__ == "__main__":
    main()
