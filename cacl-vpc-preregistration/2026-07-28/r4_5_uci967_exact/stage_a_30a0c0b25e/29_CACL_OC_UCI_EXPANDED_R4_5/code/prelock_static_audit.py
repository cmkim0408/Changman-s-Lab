#!/usr/bin/env python3
"""Write the fail-closed R4.5 audit performed before the Stage-A lock."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import prepare_r4_5_new_data as preparation
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
    _safe_package_path,
    exclusive_write_json,
    read_json,
    sha256,
    validate_prior_access_audit,
    validate_r4_2_invalidation_provenance,
    validate_r4_3_invalidation_provenance,
    validate_r4_4_invalidation_provenance,
)


SCIENTIFIC_FUNCTIONS = [
    "hash_order",
    "exact_feature_group_ids",
    "deterministic_group_representatives",
    "group_disjoint_source_splits",
    "cp_lower",
    "cp_upper",
    "direct_actions",
    "query_actions_masks_and_costs",
    "certificate",
    "feasibility_frontier",
    "tree_model",
    "selection_key",
]


def function_nodes(path: Path) -> dict[str, Any]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def main() -> None:
    output = RECEIPTS / "R4_5_PRELOCK_STATIC_AUDIT_V2.json"
    if output.exists():
        raise FileExistsError(f"write-once prelock audit exists: {output}")
    predecessor = RECEIPTS / "R4_5_PRELOCK_STATIC_AUDIT.json"
    if not predecessor.is_file():
        raise RuntimeError("preserved R4.5 prelock V1 receipt is absent")

    r4_4_engine = (
        PACKAGE
        / "28_CACL_OC_UCI_EXPANDED_R4_4"
        / "code"
        / "cacl_oc_engine.py"
    )
    r4_5_engine = ROOT / "code" / "cacl_oc_engine.py"
    old_nodes = function_nodes(r4_4_engine)
    new_nodes = function_nodes(r4_5_engine)
    ast_checks = {
        name: (
            name in old_nodes
            and name in new_nodes
            and ast.dump(old_nodes[name], include_attributes=False)
            == ast.dump(new_nodes[name], include_attributes=False)
        )
        for name in SCIENTIFIC_FUNCTIONS
    }

    config = read_json(ROOT / "config" / "r4_5_contract.json")
    r4_2 = validate_r4_2_invalidation_provenance()
    r4_3 = validate_r4_3_invalidation_provenance()
    r4_4 = validate_r4_4_invalidation_provenance()
    prior = validate_prior_access_audit(recompute_current_census=True)
    bound_paths = [
        ROOT / "R4_5_STAGE_A_REGISTRATION.md",
        ROOT / "R4_5_PROTOCOL.md",
        ROOT / "requirements-lock.txt",
        ROOT / "config" / "r4_5_contract.json",
        ROOT / "code" / "integrity.py",
        ROOT / "code" / "build_r4_5_prior_access_audit.py",
        ROOT / "code" / "prelock_static_audit.py",
        ROOT / "code" / "prepare_r4_5_new_data.py",
        ROOT / "code" / "freeze_r4_5_stage_a_lock.py",
        ROOT / "code" / "verify_r4_5_stage_a_timestamp.py",
        ROOT / "code" / "create_r4_5_public_ack.py",
        ROOT / "code" / "cacl_oc_engine.py",
        ROOT / "code" / "freeze_r4_5_lock.py",
        ROOT / "code" / "verify_r4_5_timestamp.py",
        ROOT / "code" / "audit_r4_5_final.py",
    ]
    bound_files = {
        str(path.relative_to(PACKAGE)).replace("\\", "/"): {
            "bytes": path.stat().st_size,
            "sha256": sha256(path),
        }
        for path in bound_paths
    }
    predecessor_payload = read_json(predecessor)

    network_called = False

    def forbidden_network(*args: Any, **kwargs: Any) -> Any:
        nonlocal network_called
        network_called = True
        raise AssertionError("network transport reached before Stage A")

    original_urlopen = preparation.urlopen
    preparation.urlopen = forbidden_network
    pre_stage_a_blocked = False
    try:
        preparation.fetch_registered_dataset(967)
    except RuntimeError:
        pre_stage_a_blocked = True
    finally:
        preparation.urlopen = original_urlopen

    path_escape_blocked = False
    try:
        _safe_package_path("../r4_5_escape_test")
    except RuntimeError:
        path_escape_blocked = True

    checks = {
        "denominators_exact": (
            CAMPAIGN_IDS
            == [75, 327, 572, 855, 367, 891, 942, 967]
            and REGISTERED_IDS == [75, 327, 572, 967]
            and INFERENTIAL_IDS == [327, 572, 967]
            and DESCRIPTIVE_IDS == [75]
            and HISTORICAL_NON_EVALUATED_IDS
            == [855, 367, 891, 942]
            and NEW_IDS == [967]
            and config.get("campaign_ids") == CAMPAIGN_IDS
            and config.get("registered_ids") == REGISTERED_IDS
            and config.get("inferential_ids") == INFERENTIAL_IDS
            and config.get("descriptive_ids") == DESCRIPTIVE_IDS
            and config.get("historical_non_evaluated_ids")
            == HISTORICAL_NON_EVALUATED_IDS
        ),
        "r4_4_alpha_retained": (
            config.get("source_alpha")
            == config.get("target_alpha")
            == 0.0008333333333333334
        ),
        "scientific_function_ast_identical": all(ast_checks.values()),
        "r4_2_lineage_valid": r4_2["passes"],
        "r4_3_lineage_valid": r4_3["passes"],
        "r4_4_lineage_valid": r4_4["passes"],
        "prior_access_and_metadata_screen_valid": prior["passes"],
        "predecessor_v1_preserved": (
            predecessor_payload.get("schema")
            == "cacl-oc-r4.5-prelock-static-audit-v1"
            and predecessor_payload.get("status")
            == "R4_5_PRELOCK_STATIC_AUDIT_PASS"
            and all(predecessor_payload.get("checks", {}).values())
        ),
        "all_v2_bound_files_present": (
            len(bound_files) == len(bound_paths)
            and all(path.is_file() for path in bound_paths)
        ),
        "pre_stage_a_transport_blocked_before_network": (
            pre_stage_a_blocked and not network_called
        ),
        "path_escape_blocked": path_escape_blocked,
        "no_r4_5_instance_or_scientific_outputs": (
            not (ROOT / "prepared_census").exists()
            and not (ROOT / "registered_census").exists()
            and not (RECEIPTS / "R4_5_STAGE_A_LOCAL_LOCK.json").exists()
            and not (RECEIPTS / "R4_5_STAGE_A_TIMESTAMP_ACK.json").exists()
            and not (RECEIPTS / "R4_5_REVEAL_STARTED.json").exists()
        ),
    }
    receipt = {
        "schema": "cacl-oc-r4.5-prelock-static-audit-v2",
        "status": (
            "R4_5_PRELOCK_STATIC_AUDIT_PASS"
            if all(checks.values())
            else "R4_5_PRELOCK_STATIC_AUDIT_FAIL"
        ),
        "checks": checks,
        "scientific_function_ast_checks": ast_checks,
        "r4_4_engine_sha256": sha256(r4_4_engine),
        "r4_5_engine_sha256": sha256(r4_5_engine),
        "prior_access_audit_sha256": prior["sha256"],
        "metadata_screen_sha256": prior["screen_sha256"],
        "predecessor_v1": {
            "relative_path": str(
                predecessor.relative_to(PACKAGE)
            ).replace("\\", "/"),
            "bytes": predecessor.stat().st_size,
            "sha256": sha256(predecessor),
        },
        "bound_files": bound_files,
    }
    exclusive_write_json(output, receipt)
    if not all(checks.values()):
        failed = [name for name, value in checks.items() if not value]
        raise RuntimeError("prelock audit failed: " + ", ".join(failed))
    print(receipt["status"])


if __name__ == "__main__":
    main()
