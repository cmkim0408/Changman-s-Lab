#!/usr/bin/env python3
"""Frozen CACL-OC R4.4 engine with instrumented path access."""

from __future__ import annotations

import argparse
import hashlib
import math
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from scipy.stats import beta as beta_distribution
from sklearn.impute import SimpleImputer
from sklearn.tree import DecisionTreeClassifier

from integrity import (
    CAMPAIGN_IDS,
    DESCRIPTIVE_IDS,
    ELIGIBILITY_FAILURE_IDS,
    INFERENTIAL_IDS,
    NEW_IDS,
    REGISTERED_IDS,
    ROOT,
    dataset_root,
    exclusive_write_json,
    expected_artifact,
    expected_outcome_binding,
    load_verified_feature_snapshot,
    load_verified_npz_snapshot,
    load_verified_target_snapshot,
    preparation_receipt,
    read_json,
    require_target_semantic_load_authorized,
    sha256,
    validate_stage_b_timestamp_verification,
)


CONFIG_PATH = ROOT / "config" / "r4_4_contract.json"


def read_config() -> dict[str, Any]:
    return read_json(CONFIG_PATH)


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


def write_json_once(path: Path, payload: dict[str, Any]) -> None:
    exclusive_write_json(path, native(payload))


def write_joblib_once(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        joblib.dump(payload, handle, compress=3)


def write_npz_once(path: Path, **arrays: np.ndarray) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        np.savez_compressed(handle, **arrays)


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


def exact_feature_group_ids(x: np.ndarray) -> np.ndarray:
    values = np.ascontiguousarray(np.asarray(x, dtype="<f8"))
    return np.asarray(
        [
            hashlib.sha256(
                b"CACL-OC-R4.2-EXACT-FEATURE-GROUP-v1|" + row.tobytes()
            ).hexdigest()
            for row in values
        ]
    )


def deterministic_group_representatives(
    row_ids: np.ndarray,
    group_ids: np.ndarray,
    salt: str,
) -> np.ndarray:
    """Choose exactly one label-blind representative from every group."""

    row_ids = np.asarray(row_ids)
    group_ids = np.asarray(group_ids).astype(str)
    if len(row_ids) != len(group_ids):
        raise RuntimeError("representative group-ID shape mismatch")
    best: dict[str, tuple[str, int]] = {}
    for index, (row_id, group) in enumerate(
        zip(row_ids, group_ids, strict=True)
    ):
        digest = hashlib.sha256(
            f"{salt}|representative|{group}|{row_id}".encode("utf-8")
        ).hexdigest()
        candidate = (digest, index)
        if group not in best or candidate < best[group]:
            best[group] = candidate
    selected = [value[1] for value in best.values()]
    selected.sort(
        key=lambda index: (
            hashlib.sha256(
                f"{salt}|group-order|{group_ids[index]}".encode(
                    "utf-8"
                )
            ).hexdigest(),
            str(row_ids[index]),
        )
    )
    result = np.asarray(selected, dtype=int)
    if len(set(group_ids[result].tolist())) != len(result):
        raise RuntimeError("representative selection retained a duplicate group")
    return result


def group_disjoint_source_splits(
    row_ids: np.ndarray,
    group_ids: np.ndarray,
    ratios: list[float],
    salt: str,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    if len(ratios) != 3 or not math.isclose(sum(ratios), 1.0):
        raise RuntimeError("source split ratios must sum to one")
    group_ids = np.asarray(group_ids).astype(str)
    if len(group_ids) != len(row_ids):
        raise RuntimeError("source group-ID shape mismatch")
    boundaries = np.cumsum(ratios)
    group_bucket: dict[str, int] = {}
    for group in set(group_ids.tolist()):
        digest = hashlib.sha256(
            f"{salt}|group|{group}".encode("utf-8")
        ).hexdigest()
        fraction = int(digest[:16], 16) / float(2**64)
        group_bucket[group] = (
            0
            if fraction < boundaries[0]
            else 1
            if fraction < boundaries[1]
            else 2
        )
    result: list[np.ndarray] = []
    for bucket in range(3):
        indices = np.asarray(
            [
                index
                for index, group in enumerate(group_ids)
                if group_bucket[group] == bucket
            ],
            dtype=int,
        )
        if not len(indices):
            raise RuntimeError(
                f"group-disjoint source split {bucket} is empty"
            )
        within = hash_order(row_ids[indices], f"{salt}|rows|{bucket}")
        result.append(indices[within])
    group_sets = [set(group_ids[index]) for index in result]
    if (
        group_sets[0] & group_sets[1]
        or group_sets[0] & group_sets[2]
        or group_sets[1] & group_sets[2]
    ):
        raise RuntimeError("source split group overlap")
    return result[0], result[1], result[2]


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
    transformed_x: np.ndarray,
    static_action: int,
    threshold: float,
) -> np.ndarray:
    minority_action = 1 - int(static_action)
    class_index = int(
        np.flatnonzero(tree.classes_ == minority_action)[0]
    )
    probability = tree.predict_proba(transformed_x)[:, class_index]
    return np.where(
        probability >= float(threshold),
        minority_action,
        int(static_action),
    ).astype(int)


def query_actions_masks_and_costs(
    tree: DecisionTreeClassifier,
    raw_x: np.ndarray,
    training_medians: np.ndarray,
    static_action: int,
    threshold: float,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Execute decisions through feature reads made only along tree paths."""

    raw_x = np.asarray(raw_x, dtype=float)
    medians = np.asarray(training_medians, dtype=float)
    if raw_x.ndim != 2 or raw_x.shape[1] != len(medians):
        raise RuntimeError("query executor feature shape mismatch")
    structure = tree.tree_
    minority_action = 1 - int(static_action)
    class_index = int(
        np.flatnonzero(tree.classes_ == minority_action)[0]
    )
    actions = np.empty(len(raw_x), dtype=int)
    query_mask = np.zeros(raw_x.shape, dtype=bool)

    for row_index in range(len(raw_x)):
        node = 0
        while (
            structure.children_left[node]
            != structure.children_right[node]
        ):
            feature = int(structure.feature[node])
            query_mask[row_index, feature] = True
            value = float(raw_x[row_index, feature])
            if np.isnan(value):
                value = float(medians[feature])
            if value <= float(structure.threshold[node]):
                node = int(structure.children_left[node])
            else:
                node = int(structure.children_right[node])
        weights = np.asarray(structure.value[node][0], dtype=float)
        probability = float(weights[class_index] / np.sum(weights))
        actions[row_index] = (
            minority_action
            if probability >= float(threshold)
            else int(static_action)
        )

    costs = np.sum(query_mask, axis=1).astype(float)
    return actions, query_mask, costs


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
        "minimum_harm_count_at_old_coverage_floor": minimum_harm_count,
        "minimum_point_harm_at_old_coverage_floor": minimum_point_harm,
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
    cert = row["calibration_screening_bounds"]
    return (
        cert["gain_lcb"],
        cert["mean_gain"],
        -cert["mean_queries"],
        -row["depth"],
        -row["minimum_leaf_size"],
        -row["threshold"],
    )


def _verify_preparation_inputs(
    dataset_id: int,
    source_path: Path,
    target_features_path: Path,
    target_outcomes_path: Path,
) -> dict[str, Any]:
    preparation = preparation_receipt(dataset_id)
    artifacts = preparation["artifacts"]
    checks = {
        "source_bytes": (
            source_path.stat().st_size
            == int(artifacts["source.npz"]["bytes"])
        ),
        "source_sha256": (
            sha256(source_path)
            == str(artifacts["source.npz"]["sha256"])
        ),
        "target_features_bytes": (
            target_features_path.stat().st_size
            == int(artifacts["target_features.npz"]["bytes"])
        ),
        "target_features_sha256": (
            sha256(target_features_path)
            == str(artifacts["target_features.npz"]["sha256"])
        ),
        "target_outcomes_exists": target_outcomes_path.is_file(),
        "target_outcomes_bytes_without_semantic_load": (
            target_outcomes_path.stat().st_size
            == int(artifacts["target_outcomes.npz"]["bytes"])
        ),
        "target_outcomes_sha256_without_semantic_load": (
            sha256(target_outcomes_path)
            == str(artifacts["target_outcomes.npz"]["sha256"])
        ),
    }
    if not all(checks.values()):
        raise RuntimeError(
            f"preparation identity check failed: {dataset_id}"
        )
    return checks


def freeze_one(dataset_id: int) -> dict[str, Any]:
    config = read_config()
    input_root = dataset_root(dataset_id)
    output_root = ROOT / "registered_census" / f"uci_{dataset_id}"
    if output_root.exists() and any(output_root.iterdir()):
        raise FileExistsError(
            f"write-once freeze output already exists: {output_root}"
        )
    output_root.mkdir(parents=True, exist_ok=True)

    source_path = input_root / "source.npz"
    target_features_path = input_root / "target_features.npz"
    target_outcomes_path = input_root / "target_outcomes.npz"
    identity_checks = _verify_preparation_inputs(
        dataset_id,
        source_path,
        target_features_path,
        target_outcomes_path,
    )
    source_identity, source = load_verified_npz_snapshot(
        expected_artifact(dataset_id, "source.npz")
    )
    target_feature_identity, target_features = (
        load_verified_npz_snapshot(
            expected_artifact(dataset_id, "target_features.npz")
        )
    )
    x = np.asarray(source["x"], dtype=float)
    y = np.asarray(source["y"], dtype=int)
    row_ids = source["row_ids"]
    target_x = np.asarray(target_features["x"], dtype=float)
    target_row_ids = target_features["row_ids"]
    source_group_ids = np.asarray(
        source["group_ids"]
        if "group_ids" in source
        else exact_feature_group_ids(x)
    ).astype(str)
    target_group_ids = np.asarray(
        target_features["group_ids"]
        if "group_ids" in target_features
        else exact_feature_group_ids(target_x)
    ).astype(str)
    if set(np.unique(y)) != {0, 1}:
        raise RuntimeError("R4.4 requires a binary source task")
    if len(x) != len(y) or len(x) != len(row_ids):
        raise RuntimeError("source row shape mismatch")
    if len(target_x) != len(target_row_ids):
        raise RuntimeError("target row shape mismatch")
    if x.shape[1] != target_x.shape[1]:
        raise RuntimeError("source/target feature-count mismatch")
    if len(np.unique(row_ids)) != len(row_ids):
        raise RuntimeError("source row IDs are not unique")
    if len(np.unique(target_row_ids)) != len(target_row_ids):
        raise RuntimeError("target row IDs are not unique")
    if np.intersect1d(row_ids, target_row_ids).size:
        raise RuntimeError("source and target row IDs overlap")
    source_target_group_overlap = len(
        set(source_group_ids.tolist()) & set(target_group_ids.tolist())
    )
    source_archive_units = len(x)
    target_archive_units = len(target_x)
    source_representatives = deterministic_group_representatives(
        row_ids,
        source_group_ids,
        f"{config['split_salt']}|source",
    )
    target_representatives = deterministic_group_representatives(
        target_row_ids,
        target_group_ids,
        f"{config['split_salt']}|target",
    )
    x = x[source_representatives]
    y = y[source_representatives]
    row_ids = row_ids[source_representatives]
    source_group_ids = source_group_ids[source_representatives]
    target_x = target_x[target_representatives]
    target_row_ids = target_row_ids[target_representatives]
    target_group_ids = target_group_ids[target_representatives]

    train, calibration, audit = group_disjoint_source_splits(
        row_ids,
        source_group_ids,
        [float(value) for value in config["source_split"]],
        config["split_salt"],
    )
    imputer = SimpleImputer(strategy="median").fit(x[train])
    if np.any(np.isnan(imputer.statistics_)):
        raise RuntimeError("training split contains an all-missing feature")
    transformed = imputer.transform(x)
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
                actions, masks, costs = query_actions_masks_and_costs(
                    fitted,
                    x[calibration],
                    imputer.statistics_,
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
                mask_cost_agreement = float(
                    np.mean(np.sum(masks, axis=1) == costs)
                )
                if agreement != 1.0 or mask_cost_agreement != 1.0:
                    raise RuntimeError(
                        "calibration executor integrity mismatch"
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
                        "direct_query_action_agreement": agreement,
                        "mask_cost_agreement": mask_cost_agreement,
                        "calibration_screening_bounds": cert,
                    }
                )

    eligible = [
        row
        for row in all_candidates
        if row["calibration_screening_bounds"]["passes"]
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

    audit_actions, audit_masks, audit_costs = (
        query_actions_masks_and_costs(
            tree,
            x[audit],
            imputer.statistics_,
            static_action,
            threshold,
        )
    )
    audit_direct = direct_actions(
        tree, transformed[audit], static_action, threshold
    )
    audit_agreement = float(
        np.mean(audit_actions == audit_direct)
    )
    audit_mask_cost_agreement = float(
        np.mean(np.sum(audit_masks, axis=1) == audit_costs)
    )
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
    candidate_passes_source = (
        selected is not None
        and source_audit_certificate["passes"]
        and audit_agreement
        == config["direct_path_action_agreement"]
        and audit_mask_cost_agreement == 1.0
        and source_target_group_overlap == 0
    )
    candidate_route = (
        "ACT"
        if candidate_passes_source
        else "ABSTAIN"
    )
    route = (
        "DESCRIPTIVE_REPLAY"
        if dataset_id in DESCRIPTIVE_IDS
        else candidate_route
    )

    frozen = {
        "schema": "cacl-oc-r4.4-frozen-policy-v1",
        "dataset_id": int(dataset_id),
        "route": route,
        "candidate_route_before_role_override": candidate_route,
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
        "calibration_screening_bounds": deployed_choice[
            "calibration_screening_bounds"
        ],
        "source_audit_certificate": source_audit_certificate,
        "source_audit_direct_query_action_agreement": audit_agreement,
        "source_audit_mask_cost_agreement": (
            audit_mask_cost_agreement
        ),
        "source_group_count": len(set(source_group_ids.tolist())),
        "source_archive_units": source_archive_units,
        "source_representative_units": len(source_group_ids),
        "source_train_group_count": len(
            set(source_group_ids[train].tolist())
        ),
        "source_calibration_group_count": len(
            set(source_group_ids[calibration].tolist())
        ),
        "source_audit_group_count": len(
            set(source_group_ids[audit].tolist())
        ),
        "source_target_group_overlap": source_target_group_overlap,
        "target_archive_units": target_archive_units,
        "target_representative_units": len(target_group_ids),
        "target_outcomes_opened": False,
    }
    frozen_path = output_root / "FROZEN_POLICY.joblib"
    write_joblib_once(frozen_path, frozen)

    target_actions, target_masks, target_costs = (
        query_actions_masks_and_costs(
            tree,
            target_x,
            imputer.statistics_,
            static_action,
            threshold,
        )
    )
    transformed_target_for_audit_only = imputer.transform(target_x)
    target_direct = direct_actions(
        tree,
        transformed_target_for_audit_only,
        static_action,
        threshold,
    )
    target_agreement = float(
        np.mean(target_actions == target_direct)
    )
    target_mask_cost_agreement = float(
        np.mean(np.sum(target_masks, axis=1) == target_costs)
    )
    if target_agreement != 1.0 or target_mask_cost_agreement != 1.0:
        raise RuntimeError("target executor integrity mismatch")
    if route == "ACT":
        deployed_actions = target_actions.copy()
        deployed_costs = target_costs.copy()
        deployed_query_mask = target_masks.copy()
        dispatch_status = "CANDIDATE_DISPATCHED_AS_ACT"
    else:
        deployed_actions = np.full(
            len(target_actions), static_action, dtype=int
        )
        deployed_costs = np.zeros(len(target_actions), dtype=float)
        deployed_query_mask = np.zeros_like(target_masks, dtype=bool)
        dispatch_status = (
            "STATIC_DESCRIPTIVE_DISPATCHED; candidate retained only "
            "for descriptive replay"
            if route == "DESCRIPTIVE_REPLAY"
            else
            "STATIC_ABSTENTION_DISPATCHED; candidate retained only "
            "for counterfactual abstention audit"
        )
    actions_path = output_root / "SEALED_TARGET_ACTIONS.npz"
    write_npz_once(
        actions_path,
        row_ids=target_row_ids,
        group_ids=target_group_ids,
        candidate_actions=target_actions,
        candidate_costs=target_costs,
        candidate_query_mask=target_masks,
        deployed_actions=deployed_actions,
        deployed_costs=deployed_costs,
        deployed_query_mask=deployed_query_mask,
    )

    binding = expected_outcome_binding(dataset_id)
    receipt = {
        "schema": "cacl-oc-r4.4-source-freeze-receipt-v1",
        "status": "SOURCE_POLICY_AND_QUERY_ACTIONS_FROZEN",
        "dataset_id": int(dataset_id),
        "route": route,
        "candidate_route_before_role_override": candidate_route,
        "preparation_identity_checks": identity_checks,
        "source_snapshot_identity": source_identity,
        "target_feature_snapshot_identity": target_feature_identity,
        "target_outcome_binding_from_preparation": binding,
        "target_outcomes_semantically_opened": False,
        "frozen_policy_sha256": sha256(frozen_path),
        "sealed_target_actions_sha256": sha256(actions_path),
        "candidate_count": len(all_candidates),
        "eligible_calibration_candidates": len(eligible),
        "selected_specification": frozen["selected_specification"],
        "calibration_screening_bounds": frozen[
            "calibration_screening_bounds"
        ],
        "source_audit_certificate": source_audit_certificate,
        "source_audit_direct_query_action_agreement": (
            audit_agreement
        ),
        "source_audit_mask_cost_agreement": (
            audit_mask_cost_agreement
        ),
        "source_group_count": frozen["source_group_count"],
        "source_archive_units": source_archive_units,
        "source_representative_units": len(source_group_ids),
        "source_train_group_count": frozen[
            "source_train_group_count"
        ],
        "source_calibration_group_count": frozen[
            "source_calibration_group_count"
        ],
        "source_audit_group_count": frozen[
            "source_audit_group_count"
        ],
        "source_target_group_overlap": source_target_group_overlap,
        "target_archive_units": target_archive_units,
        "target_representative_units": len(target_group_ids),
        "target_direct_query_action_agreement": target_agreement,
        "target_query_mask_cost_agreement": (
            target_mask_cost_agreement
        ),
        "target_dispatch_status": dispatch_status,
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
        "policy_access_mode": (
            "instrumented tree-path access over a preloaded matrix"
        ),
        "full_feature_target_calculation_role": (
            "audit-only direct/action equivalence; not action generation"
        ),
        "sparse_claim_boundary": (
            "computational query replay, not prospective physical "
            "feature acquisition"
        ),
        "certificate_unit": (
            "one deterministic label-blind representative per registered "
            "group"
        ),
    }
    receipt_path = output_root / "SOURCE_FREEZE_RECEIPT.json"
    write_json_once(receipt_path, receipt)
    return receipt


def freeze_all() -> None:
    batch_path = ROOT / "receipts" / "R4_4_PRE_REVEAL_BATCH.json"
    if batch_path.exists():
        raise FileExistsError(
            f"write-once batch receipt already exists: {batch_path}"
        )
    receipts = [freeze_one(dataset_id) for dataset_id in REGISTERED_IDS]
    inferential_act_count = sum(
        row["route"] == "ACT"
        for row in receipts
        if row["dataset_id"] in INFERENTIAL_IDS
    )
    new_source_act_count = sum(
        row["route"] == "ACT"
        for row in receipts
        if row["dataset_id"] in NEW_IDS
    )
    batch = {
        "schema": "cacl-oc-r4.4-pre-reveal-batch-v1",
        "status": "R4_4_PRE_REVEAL_ROUTES_FROZEN",
        "campaign_denominator": CAMPAIGN_IDS,
        "eligibility_failure_denominator": ELIGIBILITY_FAILURE_IDS,
        "registered_denominator": REGISTERED_IDS,
        "inferential_denominator": INFERENTIAL_IDS,
        "descriptive_denominator": DESCRIPTIVE_IDS,
        "routes": {
            str(row["dataset_id"]): row["route"] for row in receipts
        },
        "inferential_source_act_count": inferential_act_count,
        "new_source_act_count": new_source_act_count,
        "target_outcomes_semantically_opened": False,
        "write_once": True,
        "query_execution": (
            "instrumented tree-path access over preloaded matrices"
        ),
    }
    write_json_once(batch_path, batch)
    print(batch["status"])
    print(
        "inferential_source_act_count="
        f"{batch['inferential_source_act_count']}/"
        f"{len(INFERENTIAL_IDS)}"
    )


def verify_timestamp_authorized() -> dict[str, Any]:
    return validate_stage_b_timestamp_verification()


def evaluate_one(dataset_id: int) -> dict[str, Any]:
    config = read_config()
    require_target_semantic_load_authorized()
    output_root = ROOT / "registered_census" / f"uci_{dataset_id}"
    frozen_path = output_root / "FROZEN_POLICY.joblib"
    actions_path = output_root / "SEALED_TARGET_ACTIONS.npz"
    freeze_receipt_path = output_root / "SOURCE_FREEZE_RECEIPT.json"
    freeze_receipt = read_json(freeze_receipt_path)
    frozen_payload = frozen_path.read_bytes()
    if (
        hashlib.sha256(frozen_payload).hexdigest()
        != freeze_receipt["frozen_policy_sha256"]
    ):
        raise RuntimeError("frozen policy hash mismatch")
    actions_payload = actions_path.read_bytes()
    if (
        hashlib.sha256(actions_payload).hexdigest()
        != freeze_receipt["sealed_target_actions_sha256"]
    ):
        raise RuntimeError("sealed target-action hash mismatch")

    frozen = joblib.load(BytesIO(frozen_payload))
    with np.load(BytesIO(actions_payload), allow_pickle=False) as archive:
        sealed = {
            name: np.asarray(archive[name]).copy()
            for name in archive.files
        }
    source_receipt = freeze_receipt
    batch = read_json(
        ROOT / "receipts" / "R4_4_PRE_REVEAL_BATCH.json"
    )
    if (
        frozen.get("dataset_id") != dataset_id
        or source_receipt.get("dataset_id") != dataset_id
        or frozen.get("route") != source_receipt.get("route")
        or batch["routes"].get(str(dataset_id)) != frozen.get("route")
        or frozen.get("selected_specification")
        != source_receipt.get("selected_specification")
        or frozen.get("static_action")
        != source_receipt["source_audit_certificate"][
            "static_action"
        ]
    ):
        raise RuntimeError("frozen/source/batch policy metadata mismatch")

    feature_identity, target_features = (
        load_verified_feature_snapshot(dataset_id)
    )
    target_feature_x_full = np.asarray(
        target_features["x"], dtype=float
    )
    target_feature_row_ids_full = np.asarray(
        target_features["row_ids"]
    )
    target_feature_group_ids_full = np.asarray(
        target_features["group_ids"]
        if "group_ids" in target_features
        else exact_feature_group_ids(target_feature_x_full)
    ).astype(str)
    target_representatives = deterministic_group_representatives(
        target_feature_row_ids_full,
        target_feature_group_ids_full,
        f"{config['split_salt']}|target",
    )
    target_feature_x = target_feature_x_full[target_representatives]
    target_feature_row_ids = target_feature_row_ids_full[
        target_representatives
    ]
    recomputed_group_ids = target_feature_group_ids_full[
        target_representatives
    ]
    recomputed_actions, recomputed_masks, recomputed_costs = (
        query_actions_masks_and_costs(
            frozen["tree"],
            target_feature_x,
            frozen["imputer"].statistics_,
            frozen["static_action"],
            frozen["threshold"],
        )
    )
    if not (
        np.array_equal(
            target_feature_row_ids, sealed["row_ids"]
        )
        and np.array_equal(
            recomputed_group_ids, sealed["group_ids"].astype(str)
        )
        and np.array_equal(
            recomputed_actions, sealed["candidate_actions"]
        )
        and np.array_equal(
            recomputed_masks, sealed["candidate_query_mask"]
        )
        and np.array_equal(
            recomputed_costs, sealed["candidate_costs"]
        )
    ):
        raise RuntimeError(
            "sealed actions do not match locked-policy recomputation"
        )
    expected_deployed_actions = (
        recomputed_actions
        if frozen["route"] == "ACT"
        else np.full(
            len(recomputed_actions),
            frozen["static_action"],
            dtype=int,
        )
    )
    expected_deployed_costs = (
        recomputed_costs
        if frozen["route"] == "ACT"
        else np.zeros(len(recomputed_costs), dtype=float)
    )
    if not (
        np.array_equal(
            expected_deployed_actions, sealed["deployed_actions"]
        )
        and np.array_equal(
            expected_deployed_costs, sealed["deployed_costs"]
        )
        and np.array_equal(
            (
                recomputed_masks
                if frozen["route"] == "ACT"
                else np.zeros_like(recomputed_masks, dtype=bool)
            ),
            sealed["deployed_query_mask"],
        )
    ):
        raise RuntimeError("sealed dispatched action map mismatch")

    identity, target = load_verified_target_snapshot(dataset_id)
    target_outcome_row_ids_full = np.asarray(target["row_ids"])
    if not np.array_equal(
        target_feature_row_ids_full, target_outcome_row_ids_full
    ):
        raise RuntimeError("full target feature/outcome row identity mismatch")
    target_y = np.asarray(target["y"], dtype=int)[
        target_representatives
    ]
    if not np.array_equal(
        sealed["row_ids"],
        target_outcome_row_ids_full[target_representatives],
    ):
        raise RuntimeError("target row identity mismatch")
    if (
        "group_ids" in target
        and not np.array_equal(
            sealed["group_ids"].astype(str),
            np.asarray(target["group_ids"]).astype(str)[
                target_representatives
            ],
        )
    ):
        raise RuntimeError("target group identity mismatch")
    if not np.array_equal(
        np.sum(sealed["candidate_query_mask"], axis=1),
        sealed["candidate_costs"],
    ):
        raise RuntimeError("sealed query-mask/cost mismatch")
    cert = certificate(
        sealed["candidate_actions"],
        target_y,
        frozen["static_action"],
        sealed["candidate_costs"],
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
    elif route == "DESCRIPTIVE_REPLAY":
        verdict = "DESCRIPTIVE_REPLAY_REPORTED"
    else:
        verdict = (
            "FALSE_ABSTAIN_FAIL"
            if cert["passes"]
            else "OPERATIONAL_ABSTAIN_CORRECT"
        )
    return {
        "schema": "cacl-oc-r4.4-target-verdict-v1",
        "dataset_id": int(dataset_id),
        "pre_reveal_route": route,
        "verdict": verdict,
        "target_certificate": cert,
        "frozen_policy_sha256": sha256(frozen_path),
        "sealed_target_actions_sha256": sha256(actions_path),
        "target_outcome_identity": identity,
        "target_feature_identity": feature_identity,
        "target_outcome_unused_for_policy_route_and_actions": True,
        "target_outcome_usage_qualifier": (
            "The preparation layer decoded labels only to create a "
            "hash-bound outcome archive; policy fitting, routing and "
            "sealed actions did not semantically decode that archive "
            "before the one-shot reveal."
        ),
        "query_mask_cost_agreement": 1.0,
        "claim_boundary": (
            "Externally timestamped, source-informed, target-outcome-"
            "untouched computational confirmation with instrumented "
            "tree-path access replay on finite registered group "
            "representatives over a preloaded matrix; not a raw-row "
            "population guarantee, "
            "independent custody, prospective physical acquisition, "
            "causal, clinical, wet-lab or field-safety evidence."
        ),
    }


def evaluate_all() -> None:
    final_path = ROOT / "receipts" / "R4_4_FINAL_BATCH_VERDICT.json"
    reveal_started = ROOT / "receipts" / "R4_4_REVEAL_STARTED.json"
    reveal_completed = ROOT / "receipts" / "R4_4_REVEAL_COMPLETED.json"
    verdict_paths = [
        ROOT
        / "registered_census"
        / f"uci_{dataset_id}"
        / "TARGET_VERDICT.json"
        for dataset_id in REGISTERED_IDS
    ]
    existing = [
        path
        for path in [
            reveal_started,
            reveal_completed,
            final_path,
            *verdict_paths,
        ]
        if path.exists()
    ]
    if existing:
        raise FileExistsError(
            "write-once target output already exists: "
            + ", ".join(str(path) for path in existing)
        )

    chain = verify_timestamp_authorized()
    write_json_once(
        reveal_started,
        {
            "schema": "cacl-oc-r4.4-reveal-start-v1",
            "status": "R4_4_ONE_SHOT_TARGET_REVEAL_STARTED",
            "started_utc": datetime.now(timezone.utc).isoformat(),
            "campaign_ids": CAMPAIGN_IDS,
            "eligibility_failure_ids": ELIGIBILITY_FAILURE_IDS,
            "registered_ids": REGISTERED_IDS,
            "lock_sha256": chain["lock_sha256"],
            "ack_sha256": chain["ack_sha256"],
            "public_commit_sha": chain["public_commit_sha"],
            "target_outcome_semantic_load_before_this_receipt": False,
            "retry_permitted": False,
        },
    )
    rows = [evaluate_one(dataset_id) for dataset_id in REGISTERED_IDS]
    verify_timestamp_authorized()

    inferential_rows = [
        row for row in rows if row["dataset_id"] in INFERENTIAL_IDS
    ]
    source_act_count = sum(
        row["pre_reveal_route"] == "ACT" for row in inferential_rows
    )
    new_source_act_count = sum(
        row["pre_reveal_route"] == "ACT"
        for row in inferential_rows
        if row["dataset_id"] in NEW_IDS
    )
    target_pass_count = sum(
        row["verdict"] == "OPERATIONAL_ACT_PASS"
        for row in inferential_rows
    )
    new_target_pass_count = sum(
        row["verdict"] == "OPERATIONAL_ACT_PASS"
        for row in inferential_rows
        if row["dataset_id"] in NEW_IDS
    )
    false_act_count = sum(
        row["verdict"] == "FALSE_ACT_FAIL"
        for row in inferential_rows
    )
    config = read_config()
    gates = {
        "denominator_complete": [
            row["dataset_id"] for row in rows
        ]
        == REGISTERED_IDS,
        "inferential_denominator_exact": [
            row["dataset_id"] for row in inferential_rows
        ]
        == INFERENTIAL_IDS,
        "minimum_source_act": (
            source_act_count >= config["minimum_source_act"]
        ),
        "minimum_new_source_act": (
            new_source_act_count >= config["minimum_new_source_act"]
        ),
        "minimum_target_act_pass": (
            target_pass_count >= config["minimum_target_act_pass"]
        ),
        "minimum_new_target_act_pass": (
            new_target_pass_count
            >= config["minimum_new_target_act_pass"]
        ),
        "zero_false_act": false_act_count == 0,
    }
    batch = {
        "schema": "cacl-oc-r4.4-final-batch-verdict-v1",
        "status": (
            "R4_4_CONFIRMATORY_PASS"
            if all(gates.values())
            else "R4_4_CONFIRMATORY_FAIL"
        ),
        "campaign_denominator": CAMPAIGN_IDS,
        "eligibility_failure_denominator": ELIGIBILITY_FAILURE_IDS,
        "registered_denominator": REGISTERED_IDS,
        "inferential_denominator": INFERENTIAL_IDS,
        "descriptive_denominator": DESCRIPTIVE_IDS,
        "inferential_source_act_count": source_act_count,
        "new_source_act_count": new_source_act_count,
        "target_act_pass_count": target_pass_count,
        "new_target_act_pass_count": new_target_pass_count,
        "false_act_count": false_act_count,
        "gates": gates,
        "dataset_verdicts": {
            str(row["dataset_id"]): row["verdict"] for row in rows
        },
    }
    for path, row in zip(verdict_paths, rows, strict=True):
        write_json_once(path, row)
    write_json_once(final_path, batch)
    write_json_once(
        reveal_completed,
        {
            "schema": "cacl-oc-r4.4-reveal-complete-v1",
            "status": "R4_4_ONE_SHOT_TARGET_REVEAL_COMPLETED",
            "completed_utc": datetime.now(timezone.utc).isoformat(),
            "campaign_ids": CAMPAIGN_IDS,
            "eligibility_failure_ids": ELIGIBILITY_FAILURE_IDS,
            "registered_ids": REGISTERED_IDS,
            "final_batch_verdict_sha256": sha256(final_path),
            "verdict_sha256": {
                str(dataset_id): sha256(path)
                for dataset_id, path in zip(
                    REGISTERED_IDS, verdict_paths, strict=True
                )
            },
            "retry_permitted": False,
        },
    )
    print(batch["status"])
    print(
        f"target_act_pass_count={target_pass_count}/"
        f"{len(INFERENTIAL_IDS)}"
    )
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
