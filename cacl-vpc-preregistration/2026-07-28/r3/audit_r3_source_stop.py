#!/usr/bin/env python3
"""Audit the R3 source-only stop without opening any target outcomes."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import joblib
import numpy as np


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PACKAGE = ROOT.parent
ENGINE_PATH = (
    PACKAGE
    / "21_CACL_VPC_UCI_CLOSED_BATCH"
    / "code"
    / "cacl_vpc_uci_engine.py"
)
REGISTERED_IDS = [75, 327, 572]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_engine():
    spec = importlib.util.spec_from_file_location("cacl_vpc_engine", ENGINE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load frozen engine")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> None:
    engine = load_engine()
    rows = []
    for dataset_id in REGISTERED_IDS:
        dataset_root = ROOT / "registered_census" / f"uci_{dataset_id}"
        output_root = dataset_root / "cacl_vpc"
        source_path = dataset_root / "source.npz"
        frozen_path = output_root / "FROZEN_POLICY.joblib"
        freeze_receipt_path = output_root / "SOURCE_FREEZE_RECEIPT.json"

        source = np.load(source_path, allow_pickle=False)
        y = np.asarray(source["y"], dtype=int)
        row_ids = source["row_ids"]
        frozen = joblib.load(frozen_path)
        freeze_receipt = json.loads(
            freeze_receipt_path.read_text(encoding="utf-8")
        )
        order = engine.hash_order(
            row_ids, "CACL-VPC-UCI-DESIGN-AUDIT-v1"
        )
        design_n = int(np.floor(0.70 * len(order)))
        audit = order[design_n:]
        static_action = int(frozen["static_action"])
        audit_opportunities = int(np.sum(y[audit] != static_action))
        audit_n = len(audit)
        audit_opportunity_rate = audit_opportunities / audit_n

        candidates = frozen["source_audit_candidates"]
        best_relative = max(
            candidates,
            key=lambda item: item["certificate"]["relative_lcb"],
        )
        best_harm = min(
            candidates,
            key=lambda item: item["certificate"]["harm_ucb"],
        )
        best_compression = max(
            candidates,
            key=lambda item: (
                item["certificate"]["average_compression"]
                if item["certificate"]["average_compression"] is not None
                else float("-inf")
            ),
        )
        necessary_opportunity_rate = (
            engine.COVERAGE_FLOOR * (1.0 - engine.HARM_CAP)
        )
        target_verdict = output_root / "TARGET_VERDICT.json"
        rows.append(
            {
                "uci_id": dataset_id,
                "source_units": len(y),
                "source_features": int(source["x"].shape[1]),
                "static_action": static_action,
                "source_opportunity_rate": float(
                    np.mean(y != static_action)
                ),
                "source_audit_units": audit_n,
                "source_audit_opportunities": audit_opportunities,
                "source_audit_opportunity_rate": audit_opportunity_rate,
                "necessary_opportunity_rate_for_fixed_gates": (
                    necessary_opportunity_rate
                ),
                "fixed_coverage_harm_pair_empirically_feasible": (
                    audit_opportunity_rate >= necessary_opportunity_rate
                ),
                "route": frozen["route"],
                "best_relative_candidate": {
                    "budget": best_relative["budget"],
                    "relative_lcb": best_relative["certificate"][
                        "relative_lcb"
                    ],
                    "point_value_fraction": best_relative["certificate"][
                        "point_value_fraction"
                    ],
                },
                "best_harm_candidate": {
                    "budget": best_harm["budget"],
                    "harm_ucb": best_harm["certificate"]["harm_ucb"],
                },
                "best_compression_candidate": {
                    "budget": best_compression["budget"],
                    "average_compression": best_compression["certificate"][
                        "average_compression"
                    ],
                },
                "freeze_receipt_sha256": sha256(freeze_receipt_path),
                "frozen_policy_sha256": sha256(frozen_path),
                "target_outcomes_opened_flag": bool(
                    freeze_receipt["target_outcomes_opened"]
                ),
                "target_verdict_exists": target_verdict.exists(),
            }
        )

    source_compress_count = sum(row["route"] == "COMPRESS" for row in rows)
    target_unopened = all(
        not row["target_outcomes_opened_flag"]
        and not row["target_verdict_exists"]
        for row in rows
    )
    receipt = {
        "schema": "cacl-vpc-r3-source-stop-audit-v1",
        "status": "STRUCTURAL_FAIL_TARGET_UNOPENED",
        "registered_denominator": REGISTERED_IDS,
        "registered_denominator_retained": [
            row["uci_id"] for row in rows
        ]
        == REGISTERED_IDS,
        "source_compress_count": source_compress_count,
        "minimum_source_compress": 2,
        "confirmatory_pass_still_possible": source_compress_count >= 2,
        "target_outcomes_remain_unopened_for_model_evaluation": (
            target_unopened
        ),
        "fixed_gate_necessary_condition": (
            "opportunity_rate >= coverage_floor*(1-harm_cap)"
        ),
        "fixed_gate_necessary_threshold": (
            engine.COVERAGE_FLOOR * (1.0 - engine.HARM_CAP)
        ),
        "interpretation": (
            "R3 cannot pass because no registered source task authorized "
            "COMPRESS. On two tasks, the fixed absolute coverage/harm pair "
            "is itself empirically infeasible; no threshold was changed and "
            "target outcomes were not evaluated."
        ),
        "datasets": rows,
    }
    output = ROOT / "receipts" / "R3_SOURCE_STOP_AUDIT.json"
    output.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(receipt["status"])
    print(
        "source_compress_count="
        f"{receipt['source_compress_count']}/"
        f"{receipt['minimum_source_compress']}"
    )
    print(f"target_unopened={target_unopened}")


if __name__ == "__main__":
    main()
