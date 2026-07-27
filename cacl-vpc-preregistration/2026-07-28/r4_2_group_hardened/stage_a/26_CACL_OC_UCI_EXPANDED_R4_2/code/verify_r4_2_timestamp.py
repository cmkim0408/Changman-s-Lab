#!/usr/bin/env python3
"""Revalidate the public R4.2 timestamp and every locked artifact."""

from __future__ import annotations

from integrity import RECEIPTS, exclusive_write_json, validate_ack_and_lock


def main() -> None:
    output = RECEIPTS / "R4_2_EXTERNAL_TIMESTAMP_VERIFICATION.json"
    if output.exists():
        raise FileExistsError(
            f"write-once verification already exists: {output}"
        )
    chain = validate_ack_and_lock()
    receipt = {
        "schema": "cacl-oc-r4.2-timestamp-verification-v1",
        "status": "R4_2_TARGET_REVEAL_AUTHORIZED",
        "lock_sha256": chain["lock_sha256"],
        "ack_sha256": chain["ack_sha256"],
        "public_commit_sha": chain["public_commit_sha"],
        "checks": chain["checks"],
        "locked_file_count": len(chain["file_checks"]),
        "all_locked_files_current": all(
            row["passes"] for row in chain["file_checks"].values()
        ),
        "all_outcome_bindings_committed": all(
            row["passes"]
            for row in chain["outcome_binding_checks"].values()
        ),
        "target_outcome_semantic_load_permitted_after_receipt": True,
    }
    exclusive_write_json(output, receipt)
    print(receipt["status"])


if __name__ == "__main__":
    main()
