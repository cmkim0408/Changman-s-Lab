#!/usr/bin/env python3
"""Frozen CACL-OC engine for the R4 UCI census."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from scipy.stats import beta as beta_distribution
from sklearn.impute import SimpleImputer
from sklearn.tree import DecisionTreeClassifier


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PACKAGE = ROOT.parent
R3 = PACKAGE / "23_CACL_VPC_UCI_CENSUS_BATCH"
CONFIG_PATH = ROOT / "config" / "r4_contract.json"
REGISTERED_IDS = [75, 327, 572]


def read_config() -> dict[str, Any]:
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def native(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): native(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [native(item) for item in value]
    if isinstance(value, np.ndarray):
        return value.tolist()
    if isinstance(value, np.generic):
        return value.item()
    return value


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(native(payload), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def hash_order(row_ids: np.ndarray, salt: str) -> np.ndarray:
    return np.asarray(
        sorted(
            range(len(row_ids)),
            key=lambda index: (
                hashlib.sha256(
                    f"{salt}|{row_ids[index]}".encode()
                ).hexdigest(),
                index,
            ),
        ),
        dtype=int,
    )


def cp_lower(successes: int, trials: int, alpha: float) -> float:
    if trials <= 0 or successes <= 0:
        return 0.0
    return float(
        beta_distribution.ppf(alpha, successes, trials - successes + 1)
    )


def cp_upper(events: int, trials: int, alpha: float) -> float:
    if trials <= 0 or events >= trials:
        return 1.0
    return float(
        beta_distribution.ppf(
            1.0 - alpha, events + 1, trials - events
        )
    )


def direct_actions(
    tree: DecisionTreeClassifier,
    x: np.ndarray,
    static_action: int,
    threshold: float,
) -> np.ndarray:
    minority_action = 1 - int(static_action)
    class_index = int(
        np.flatnonzero(tree.classes_ == minority_action)[0]
    )
    probability = tree.predict_proba(x)[:, class_index]
    return np.where(
        probability >= float(threshold),
        minority_action,
        int(static_action),
    ).astype(int)


def path_actions_and_costs(
    tree: DecisionTreeClassifier,
    x: np.ndarray,
    static_action: int,
    threshold: float,
) -> tuple[np.ndarray, np.ndarray]:
    structure = tree.tree_
    minority_action = 1 - int(static_action)
    class_index = int(
        np.flatnonzero(tree.classes_ == minority_action)[0]
    )
    actions = np.empty(len(x), dtype=int)
    costs = np.empty(len(x), dtype=float)
    for row_index, row in enumerate(x):
        node = 0
        measured: set[int] = set()
        while (
            structure.children_left[node]
            != structure.children_right[node]
        ):
            feature = int(structure.feature[node])
            measured.add(feature)
            if row[feature] <= structure.threshold[node]:
                node = int(structure.children_left[node])
            else:
                node = int(structure.children_right[node])
        counts = np.asarray(structure.value[node][0], dtype=float)
        probability = float(counts[class_index] / np.sum(counts))
        actions[row_index] = (
            minority_action
            if probability >= float(threshold)
            else int(static_action)
        )
        costs[row_index] = float(len(measured))
    return actions, costs


def certificate(
    actions: np.ndarray,
    outcomes: np.ndarray,
    static_action: int,
    costs: np.ndarray,
    feature_count: int,
    *,
    alpha: float,
    harm_cap: float,
    recall_floor: float,
    compression_floor: float,
) -> dict[str, Any]:
    actions = np.asarray(actions, dtype=int)
    outcomes = np.asarray(outcomes, dtype=int)
    costs = np.asarray(costs, dtype=float)
    changed = actions != int(static_action)
    opportunity = outcomes != int(static_action)
    helpful = changed & opportunity
    harmful = changed & ~opportunity
    changed_count = int(np.sum(changed))
    opportunity_count = int(np.sum(opportunity))
    helpful_count = int(np.sum(helpful))
    harmful_count = int(np.sum(harmful))

    gain = (
        (actions == outcomes).astype(float)
        - (int(static_action) == outcomes).astype(float)
    )
    widths = 2.0 * changed.astype(float)
    radius = math.sqrt(
        math.log(1.0 / alpha)
        * float(np.sum(widths**2))
        / (2.0 * len(outcomes) ** 2)
    )
    gain_lcb = float(np.mean(gain) - radius)
    harm_ucb = cp_upper(harmful_count, changed_count, alpha)
    recall_lcb = cp_lower(
        helpful_count, opportunity_count, alpha
    )
    mean_queries = float(np.mean(costs))
    compression = (
        float(feature_count / mean_queries)
        if mean_queries > 0.0
        else None
    )
    gates = {
        "positive_gain_lcb": gain_lcb > 0.0,
        "harm_ucb_at_most_cap": harm_ucb <= harm_cap,
        "opportunity_recall_lcb_at_least_floor": (
            recall_lcb >= recall_floor
        ),
        "average_compression_at_least_floor": bool(
            compression is not None
            and compression >= compression_floor
        ),
    }
    return {
        "units": len(outcomes),
        "alpha": alpha,
        "static_action": int(static_action),
        "mean_gain": float(np.mean(gain)),
        "gain_lcb": gain_lcb,
        "gain_radius": radius,
        "changed_actions": changed_count,
        "opportunities": opportunity_count,
        "helpful_changes": helpful_count,
        "harmful_changes": harmful_count,
        "changed_action_rate": float(np.mean(changed)),
        "opportunity_rate": float(np.mean(opportunity)),
        "opportunity_recall": (
            float(helpful_count / opportunity_count)
            if opportunity_count
            else 0.0
        ),
        "opportunity_recall_lcb": recall_lcb,
        "changed_action_harm_rate": (
            float(harmful_count / changed_count)
            if changed_count
            else 1.0
        ),
        "changed_action_harm_ucb": harm_ucb,
        "mean_queries": mean_queries,
        "worst_case_queries": int(np.max(costs)) if len(costs) else 0,
        "feature_count": int(feature_count),
        "average_compression": compression,
        "harm_cap": harm_cap,
        "opportunity_recall_floor": recall_floor,
        "compression_floor": compression_floor,
        "gates": gates,
        "passes": all(gates.values()),
    }


def feasibility_frontier(
    outcomes: np.ndarray,
    static_action: int,
    *,
    old_coverage_floor: float = 0.20,
    harm_cap: float = 0.20,
) -> dict[str, Any]:
    outcomes = np.asarray(outcomes, dtype=int)
    opportunities = int(np.sum(outcomes != int(static_action)))
    units = len(outcomes)
    opportunity_rate = opportunities / units
    necessary_rate = old_coverage_floor * (1.0 - harm_cap)
    maximum_coverage = min(
        1.0, opportunity_rate / (1.0 - harm_cap)
    )
    minimum_changed = int(math.ceil(old_coverage_floor * units))
    minimum_harm_count = max(0, minimum_changed - opportunities)
    minimum_point_harm = (
        minimum_harm_count / minimum_changed
        if minimum_changed
        else 0.0
    )
    return {
        "units": units,
        "opportunities": opportunities,
        "opportunity_rate": opportunity_rate,
        "old_absolute_coverage_floor": old_coverage_floor,
        "harm_cap": harm_cap,
        "necessary_opportunity_rate": necessary_rate,
        "oracle_maximum_coverage_under_harm_cap": maximum_coverage,
        "minimum_harm_count_at_old_coverage_floor": (
            minimum_harm_count
        ),
        "minimum_point_harm_at_old_coverage_floor": (
            minimum_point_harm
        ),
        "old_gate_pair_structurally_feasible": (
            opportunity_rate >= necessary_rate
        ),
    }


def tree_model(depth: int, leaf: int) -> DecisionTreeClassifier:
    return DecisionTreeClassifier(
        max_depth=int(depth),
        min_samples_leaf=int(leaf),
        class_weight="balanced",
        criterion="log_loss",
        random_state=2304102,
    )


def selection_key(row: dict[str, Any]) -> tuple[Any, ...]:
    cert = row["calibration_certificate"]
    return (
        cert["gain_lcb"],
        cert["mean_gain"],
        -cert["mean_queries"],
        -row["depth"],
        -row["minimum_leaf_size"],
        -row["threshold"],
    )


def freeze_one(dataset_id: int) -> dict[str, Any]:
    config = read_config()
    dataset_root = (
        R3 / "registered_census" / f"uci_{dataset_id}"
    )
    output_root = ROOT / "registered_census" / f"uci_{dataset_id}"
    output_root.mkdir(parents=True, exist_ok=True)

    source_path = dataset_root / "source.npz"
    target_features_path = dataset_root / "target_features.npz"
    target_outcomes_path = dataset_root / "target_outcomes.npz"
    source = np.load(source_path, allow_pickle=False)
    target_features = np.load(
        target_features_path, allow_pickle=False
    )
    x = np.asarray(source["x"], dtype=float)
    y = np.asarray(source["y"], dtype=int)
    row_ids = source["row_ids"]
    target_x = np.asarray(target_features["x"], dtype=float)
    target_row_ids = target_features["row_ids"]
    if set(np.unique(y)) != {0, 1}:
        raise RuntimeError("R4 requires a binary source task")

    order = hash_order(row_ids, config["split_salt"])
    train_end = int(np.floor(config["source_split"][0] * len(order)))
    calibration_end = int(
        np.floor(
            (
                config["source_split"][0]
                + config["source_split"][1]
            )
            * len(order)
        )
    )
    train = order[:train_end]
    calibration = order[train_end:calibration_end]
    audit = order[calibration_end:]
    imputer = SimpleImputer(strategy="median").fit(x[train])
    transformed = imputer.transform(x)
    transformed_target = imputer.transform(target_x)
    static_action = int(
        np.argmax(np.bincount(y[train], minlength=2))
    )

    all_candidates: list[dict[str, Any]] = []
    fitted_models: dict[tuple[int, int], DecisionTreeClassifier] = {}
    for depth in config["tree_depths"]:
        for leaf in config["minimum_leaf_sizes"]:
            fitted = tree_model(depth, leaf).fit(
                transformed[train], y[train]
            )
            fitted_models[(int(depth), int(leaf))] = fitted
            for threshold in config["threshold_grid"]:
                actions, costs = path_actions_and_costs(
                    fitted,
                    transformed[calibration],
                    static_action,
                    float(threshold),
                )
                direct = direct_actions(
                    fitted,
                    transformed[calibration],
                    static_action,
                    float(threshold),
                )
                agreement = float(np.mean(actions == direct))
                if agreement != 1.0:
                    raise RuntimeError(
                        "calibration direct/path action mismatch"
                    )
                cert = certificate(
                    actions,
                    y[calibration],
                    static_action,
                    costs,
                    x.shape[1],
                    alpha=config["source_alpha"],
                    harm_cap=config["selection_harm_ucb_cap"],
                    recall_floor=config[
                        "opportunity_recall_lcb_floor"
                    ],
                    compression_floor=config[
                        "average_compression_floor"
                    ],
                )
                all_candidates.append(
                    {
                        "depth": int(depth),
                        "minimum_leaf_size": int(leaf),
                        "threshold": float(threshold),
                        "direct_path_action_agreement": agreement,
                        "calibration_certificate": cert,
                    }
                )

    eligible = [
        row
        for row in all_candidates
        if row["calibration_certificate"]["passes"]
    ]
    selected = max(eligible, key=selection_key) if eligible else None
    diagnostic = max(all_candidates, key=selection_key)
    deployed_choice = selected if selected is not None else diagnostic
    tree = fitted_models[
        (
            int(deployed_choice["depth"]),
            int(deployed_choice["minimum_leaf_size"]),
        )
    ]
    threshold = float(deployed_choice["threshold"])

    audit_actions, audit_costs = path_actions_and_costs(
        tree, transformed[audit], static_action, threshold
    )
    audit_direct = direct_actions(
        tree, transformed[audit], static_action, threshold
    )
    audit_agreement = float(np.mean(audit_actions == audit_direct))
    source_audit_certificate = certificate(
        audit_actions,
        y[audit],
        static_action,
        audit_costs,
        x.shape[1],
        alpha=config["source_alpha"],
        harm_cap=config["scientific_harm_ucb_cap"],
        recall_floor=config["opportunity_recall_lcb_floor"],
        compression_floor=config["average_compression_floor"],
    )
    route = (
        "ACT"
        if selected is not None
        and source_audit_certificate["passes"]
        and audit_agreement
        == config["direct_path_action_agreement"]
        else "ABSTAIN"
    )

    frozen = {
        "schema": "cacl-oc-r4-frozen-policy-v1",
        "dataset_id": int(dataset_id),
        "route": route,
        "static_action": static_action,
        "imputer": imputer,
        "tree": tree,
        "threshold": threshold,
        "selected_was_calibration_eligible": selected is not None,
        "selected_specification": {
            "depth": int(deployed_choice["depth"]),
            "minimum_leaf_size": int(
                deployed_choice["minimum_leaf_size"]
            ),
            "threshold": threshold,
        },
        "calibration_certificate": deployed_choice[
            "calibration_certificate"
        ],
        "source_audit_certificate": source_audit_certificate,
        "source_audit_direct_path_action_agreement": audit_agreement,
        "target_outcomes_opened": False,
    }
    frozen_path = output_root / "FROZEN_POLICY.joblib"
    joblib.dump(frozen, frozen_path, compress=3)

    target_actions, target_costs = path_actions_and_costs(
        tree, transformed_target, static_action, threshold
    )
    target_direct = direct_actions(
        tree, transformed_target, static_action, threshold
    )
    target_agreement = float(
        np.mean(target_actions == target_direct)
    )
    if target_agreement != 1.0:
        raise RuntimeError("target direct/path action mismatch")
    actions_path = output_root / "SEALED_TARGET_ACTIONS.npz"
    np.savez_compressed(
        actions_path,
        row_ids=target_row_ids,
        actions=target_actions,
        costs=target_costs,
    )

    receipt = {
        "schema": "cacl-oc-r4-source-freeze-receipt-v1",
        "status": "SOURCE_POLICY_AND_TARGET_ACTIONS_FROZEN",
        "dataset_id": int(dataset_id),
        "route": route,
        "source_sha256": sha256(source_path),
        "target_features_sha256": sha256(target_features_path),
        "target_outcome_path_recorded_but_not_opened": str(
            target_outcomes_path
        ),
        "target_outcomes_opened": False,
        "frozen_policy_sha256": sha256(frozen_path),
        "sealed_target_actions_sha256": sha256(actions_path),
        "candidate_count": len(all_candidates),
        "eligible_calibration_candidates": len(eligible),
        "selected_specification": frozen["selected_specification"],
        "calibration_certificate": frozen[
            "calibration_certificate"
        ],
        "source_audit_certificate": source_audit_certificate,
        "source_audit_direct_path_action_agreement": (
            audit_agreement
        ),
        "target_direct_path_action_agreement": target_agreement,
        "source_feasibility_frontier": feasibility_frontier(
            y[audit],
            static_action,
            harm_cap=config["scientific_harm_ucb_cap"],
        ),
        "target_units": len(target_actions),
        "target_mean_queries_outcome_blind": float(
            np.mean(target_costs)
        ),
        "target_average_compression_outcome_blind": float(
            x.shape[1] / np.mean(target_costs)
        ),
    }
    receipt_path = output_root / "SOURCE_FREEZE_RECEIPT.json"
    write_json(receipt_path, receipt)
    return receipt


def freeze_all() -> None:
    receipts = [freeze_one(dataset_id) for dataset_id in REGISTERED_IDS]
    batch = {
        "schema": "cacl-oc-r4-pre-reveal-batch-v1",
        "status": "R4_PRE_REVEAL_ROUTES_FROZEN",
        "registered_denominator": REGISTERED_IDS,
        "routes": {
            str(row["dataset_id"]): row["route"] for row in receipts
        },
        "source_act_count": sum(
            row["route"] == "ACT" for row in receipts
        ),
        "target_outcomes_opened": False,
    }
    write_json(ROOT / "receipts" / "R4_PRE_REVEAL_BATCH.json", batch)
    print(batch["status"])
    print(f"source_act_count={batch['source_act_count']}/3")


def verify_timestamp_authorized() -> None:
    path = ROOT / "receipts" / "R4_EXTERNAL_TIMESTAMP_VERIFICATION.json"
    if not path.exists():
        raise RuntimeError("R4 external timestamp verification is absent")
    receipt = json.loads(path.read_text(encoding="utf-8"))
    if receipt.get("status") != "R4_TARGET_REVEAL_AUTHORIZED":
        raise RuntimeError("R4 target reveal is not authorized")


def evaluate_one(dataset_id: int) -> dict[str, Any]:
    config = read_config()
    verify_timestamp_authorized()
    dataset_root = (
        R3 / "registered_census" / f"uci_{dataset_id}"
    )
    output_root = ROOT / "registered_census" / f"uci_{dataset_id}"
    frozen_path = output_root / "FROZEN_POLICY.joblib"
    actions_path = output_root / "SEALED_TARGET_ACTIONS.npz"
    freeze_receipt_path = output_root / "SOURCE_FREEZE_RECEIPT.json"
    freeze_receipt = json.loads(
        freeze_receipt_path.read_text(encoding="utf-8")
    )
    if sha256(frozen_path) != freeze_receipt["frozen_policy_sha256"]:
        raise RuntimeError("frozen policy hash mismatch")
    if (
        sha256(actions_path)
        != freeze_receipt["sealed_target_actions_sha256"]
    ):
        raise RuntimeError("sealed target-action hash mismatch")

    frozen = joblib.load(frozen_path)
    sealed = np.load(actions_path, allow_pickle=False)
    target_outcomes_path = dataset_root / "target_outcomes.npz"
    target = np.load(target_outcomes_path, allow_pickle=False)
    if not np.array_equal(sealed["row_ids"], target["row_ids"]):
        raise RuntimeError("target row identity mismatch")
    cert = certificate(
        sealed["actions"],
        target["y"],
        frozen["static_action"],
        sealed["costs"],
        frozen["imputer"].n_features_in_,
        alpha=config["target_alpha"],
        harm_cap=config["scientific_harm_ucb_cap"],
        recall_floor=config["opportunity_recall_lcb_floor"],
        compression_floor=config["average_compression_floor"],
    )
    route = frozen["route"]
    if route == "ACT":
        verdict = (
            "OPERATIONAL_ACT_PASS"
            if cert["passes"]
            else "FALSE_ACT_FAIL"
        )
    else:
        verdict = (
            "FALSE_ABSTAIN_FAIL"
            if cert["passes"]
            else "OPERATIONAL_ABSTAIN_CORRECT"
        )
    receipt = {
        "schema": "cacl-oc-r4-target-verdict-v1",
        "dataset_id": int(dataset_id),
        "pre_reveal_route": route,
        "verdict": verdict,
        "target_certificate": cert,
        "frozen_policy_sha256": sha256(frozen_path),
        "sealed_target_actions_sha256": sha256(actions_path),
        "target_outcomes_sha256": sha256(target_outcomes_path),
        "source_informed_target_outcome_untouched": True,
        "claim_boundary": (
            "Computational target-outcome-untouched confirmation; not "
            "dataset-level untouched discovery, causal, clinical, wet-lab, "
            "field-safety or independent-human-custody evidence."
        ),
    }
    write_json(output_root / "TARGET_VERDICT.json", receipt)
    return receipt


def evaluate_all() -> None:
    rows = [evaluate_one(dataset_id) for dataset_id in REGISTERED_IDS]
    source_act_count = sum(
        row["pre_reveal_route"] == "ACT" for row in rows
    )
    target_pass_count = sum(
        row["verdict"] == "OPERATIONAL_ACT_PASS" for row in rows
    )
    false_act_count = sum(
        row["verdict"] == "FALSE_ACT_FAIL" for row in rows
    )
    config = read_config()
    gates = {
        "denominator_complete": [
            row["dataset_id"] for row in rows
        ]
        == REGISTERED_IDS,
        "minimum_source_act": (
            source_act_count >= config["minimum_source_act"]
        ),
        "minimum_target_act_pass": (
            target_pass_count >= config["minimum_target_act_pass"]
        ),
        "zero_false_act": false_act_count == 0,
    }
    batch = {
        "schema": "cacl-oc-r4-final-batch-verdict-v1",
        "status": (
            "R4_CONFIRMATORY_PASS"
            if all(gates.values())
            else "R4_CONFIRMATORY_FAIL"
        ),
        "registered_denominator": REGISTERED_IDS,
        "source_act_count": source_act_count,
        "target_act_pass_count": target_pass_count,
        "false_act_count": false_act_count,
        "gates": gates,
        "dataset_verdicts": {
            str(row["dataset_id"]): row["verdict"] for row in rows
        },
    }
    write_json(ROOT / "receipts" / "R4_FINAL_BATCH_VERDICT.json", batch)
    print(batch["status"])
    print(f"target_act_pass_count={target_pass_count}/3")
    print(f"false_act_count={false_act_count}")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument(
        "mode", choices=["freeze-all", "evaluate-all"]
    )
    return result


def main() -> None:
    args = parser().parse_args()
    if args.mode == "freeze-all":
        freeze_all()
    else:
        evaluate_all()


if __name__ == "__main__":
    main()
