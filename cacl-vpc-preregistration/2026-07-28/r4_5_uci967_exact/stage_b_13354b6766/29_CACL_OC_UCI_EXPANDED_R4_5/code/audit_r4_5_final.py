#!/usr/bin/env python3
"""Independent raw-data audit of the complete CACL-OC R4.5 campaign.

The auditor deliberately does not import the scientific engine.  It rebuilds
the selected source model from the verified source snapshot, independently
executes every source and target tree path, recomputes every certificate and
route/verdict gate, and validates the one-shot reveal/hash chain.
"""

from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

import joblib
import numpy as np
import pandas as pd
from scipy.stats import beta as beta_distribution
from sklearn.tree import DecisionTreeClassifier

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
    dataset_root,
    exclusive_write_json,
    expected_artifact,
    expected_outcome_binding,
    load_verified_feature_snapshot,
    load_verified_npz_snapshot,
    load_verified_target_snapshot,
    read_json,
    sha256,
    sha256_bytes,
    validate_ack_and_lock,
)


UCI967_PRIMARY_FEATURES = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "TLDLength",
    "NoOfSubDomain",
    "HasObfuscation",
    "NoOfObfuscatedChar",
    "ObfuscationRatio",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "IsHTTPS",
    "LineOfCode",
    "LargestLineLength",
    "HasTitle",
    "DomainTitleMatchScore",
    "URLTitleMatchScore",
    "HasFavicon",
    "Robots",
    "IsResponsive",
    "NoOfURLRedirect",
    "NoOfSelfRedirect",
    "HasDescription",
    "NoOfPopup",
    "NoOfiFrame",
    "HasExternalFormSubmit",
    "HasSocialNet",
    "HasSubmitButton",
    "HasHiddenFields",
    "HasPasswordField",
    "Bank",
    "Pay",
    "Crypto",
    "HasCopyrightInfo",
    "NoOfImage",
    "NoOfCSS",
    "NoOfJS",
    "NoOfSelfRef",
    "NoOfEmptyRef",
    "NoOfExternalRef",
]
UCI967_EXCLUDED_FEATURES = [
    "URL",
    "Domain",
    "TLD",
    "Title",
    "URLSimilarityIndex",
    "CharContinuationRate",
    "TLDLegitimateProb",
    "URLCharProb",
]
REGISTRATION_SELECTION_SALT = (
    "CACL-OC-R4.2-GROUP-COMPLETE-REGISTRATION-v1"
)
REGISTRATION_SOURCE_TARGET_SALT = (
    "CACL-OC-R4.2-GROUP-SOURCE-TARGET-v1"
)


def independent_name_list_sha256(names: list[str]) -> str:
    """Hash a locked ordered schema without importing preparation code."""

    payload = json.dumps(
        names, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def independent_sha256_text(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and set(value).issubset(set("0123456789abcdef"))
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


def independent_feature_signature_groups(x: np.ndarray) -> np.ndarray:
    """Recreate the locked exact-feature group without engine imports."""

    values = np.ascontiguousarray(np.asarray(x, dtype="<f8"))
    prefix = b"CACL-OC-R4.2-EXACT-FEATURE-GROUP-v1|"
    return np.asarray(
        [
            hashlib.sha256(prefix + row.tobytes()).hexdigest()
            for row in values
        ]
    )


def independent_registration_group_digest(
    group: str, dataset_id: int, salt: str
) -> str:
    return hashlib.sha256(
        f"{salt}|{dataset_id}|{group}".encode("utf-8")
    ).hexdigest()


def independent_group_complete_registration(
    group_ids: np.ndarray, dataset_id: int, cap: int
) -> np.ndarray:
    """Rebuild the pre-registered whole-group row cap."""

    if len(group_ids) <= cap:
        return np.arange(len(group_ids), dtype=int)
    rows_by_group: dict[str, list[int]] = {}
    for index, group in enumerate(np.asarray(group_ids).astype(str)):
        rows_by_group.setdefault(group, []).append(index)
    ordered_groups = sorted(
        rows_by_group,
        key=lambda group: (
            independent_registration_group_digest(
                group,
                dataset_id,
                REGISTRATION_SELECTION_SALT,
            ),
            group,
        ),
    )
    selected: list[np.ndarray] = []
    total = 0
    for group in ordered_groups:
        rows = np.asarray(rows_by_group[group], dtype=int)
        if total + len(rows) <= cap:
            selected.append(rows)
            total += len(rows)
    if not selected:
        raise RuntimeError("independent group-complete cap is empty")
    return np.sort(np.concatenate(selected)).astype(int)


def independent_registration_source_target(
    registered_index: np.ndarray,
    group_ids: np.ndarray,
    dataset_id: int,
) -> tuple[np.ndarray, np.ndarray]:
    registered_groups = np.asarray(group_ids).astype(str)[registered_index]
    source_groups = {
        group
        for group in set(registered_groups.tolist())
        if int(
            independent_registration_group_digest(
                group,
                dataset_id,
                REGISTRATION_SOURCE_TARGET_SALT,
            )[:16],
            16,
        )
        / float(2**64)
        < 0.65
    }
    source_mask = np.asarray(
        [group in source_groups for group in registered_groups]
    )
    source = registered_index[source_mask]
    target = registered_index[~source_mask]
    if not len(source) or not len(target):
        raise RuntimeError("independent source/target split is empty")
    return source, target


def independent_normalized_domain_groups(domain: pd.Series) -> np.ndarray:
    if bool(domain.isna().any()):
        raise RuntimeError("independent Domain grouping found missing data")
    normalized = domain.astype(str).str.strip().str.lower()
    if bool((normalized == "").any()):
        raise RuntimeError("independent Domain grouping found an empty key")
    return np.asarray(
        [
            hashlib.sha256(
                (
                    "CACL-OC-R4.2-NORMALIZED-DOMAIN-v1|" + value
                ).encode("utf-8")
            ).hexdigest()
            for value in normalized
        ]
    )


def independent_new_target_transform(
    dataset_id: int,
    labels: pd.Series,
    config: dict[str, Any],
) -> np.ndarray:
    if bool(labels.isna().any()):
        raise RuntimeError("independent target transform found missing data")
    if dataset_id != 967 or str(dataset_id) not in config["transport"]:
        raise RuntimeError("independent target transform saw unknown task")
    numeric = pd.to_numeric(labels, errors="raise").to_numpy(dtype=float)
    if not bool(np.isfinite(numeric).all()):
        raise RuntimeError(
            "independent numeric target contains non-finite data"
        )
    unique = np.unique(numeric)
    if (
        len(unique) != 2
        or int(np.sum(unique > 0)) != 1
        or int(np.sum(unique <= 0)) != 1
    ):
        raise RuntimeError(
            "independent numeric target is not two-value binary"
        )
    result = (numeric > 0).astype(int)
    if set(result.tolist()) != {0, 1}:
        raise RuntimeError("independent target transform lost one class")
    return result


def independent_group_representatives(
    row_ids: np.ndarray,
    group_ids: np.ndarray,
    salt: str,
) -> np.ndarray:
    """Choose one label-blind row per group without engine imports."""

    row_ids = np.asarray(row_ids)
    group_ids = np.asarray(group_ids).astype(str)
    if len(row_ids) != len(group_ids):
        raise RuntimeError("independent representative shape mismatch")
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
    if (
        len(result) != len(set(group_ids.tolist()))
        or len(set(group_ids[result].tolist())) != len(result)
    ):
        raise RuntimeError(
            "independent representative selection is not one-per-group"
        )
    return result


def independent_group_source_splits(
    row_ids: np.ndarray,
    group_ids: np.ndarray,
    ratios: list[float],
    salt: str,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Independently assign whole groups to train/calibration/audit."""

    if len(ratios) != 3 or not math.isclose(
        sum(ratios), 1.0, rel_tol=0.0, abs_tol=1e-12
    ):
        raise RuntimeError("invalid independent group-split ratios")
    row_ids = np.asarray(row_ids)
    group_ids = np.asarray(group_ids).astype(str)
    if len(row_ids) != len(group_ids):
        raise RuntimeError("independent source group-ID shape mismatch")
    cutoffs = np.cumsum(np.asarray(ratios, dtype=float))
    assigned: dict[str, int] = {}
    for group in set(group_ids.tolist()):
        digest = hashlib.sha256(
            f"{salt}|group|{group}".encode("utf-8")
        ).hexdigest()
        fraction = int(digest[:16], 16) / float(2**64)
        assigned[group] = (
            0
            if fraction < cutoffs[0]
            else 1
            if fraction < cutoffs[1]
            else 2
        )

    partitions: list[np.ndarray] = []
    for bucket in range(3):
        selected = np.asarray(
            [
                index
                for index, group in enumerate(group_ids)
                if assigned[group] == bucket
            ],
            dtype=int,
        )
        if not len(selected):
            raise RuntimeError(
                f"independent group split {bucket} is empty"
            )
        local_order = hash_order(
            row_ids[selected], f"{salt}|rows|{bucket}"
        )
        partitions.append(selected[local_order])
    group_sets = [
        set(group_ids[index].tolist()) for index in partitions
    ]
    if any(
        group_sets[left] & group_sets[right]
        for left, right in ((0, 1), (0, 2), (1, 2))
    ):
        raise RuntimeError("independent source partitions share groups")
    return partitions[0], partitions[1], partitions[2]


def independent_selection_key(row: dict[str, Any]) -> tuple[Any, ...]:
    """Reproduce the preregistered lexicographic model-selection order."""

    certificate = row["calibration_screening_bounds"]
    return (
        certificate["gain_lcb"],
        certificate["mean_gain"],
        -certificate["mean_queries"],
        -row["depth"],
        -row["minimum_leaf_size"],
        -row["threshold"],
    )


def independent_execute(
    tree: DecisionTreeClassifier,
    raw_x: np.ndarray,
    medians: np.ndarray,
    static_action: int,
    threshold: float,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Execute a tree through explicit feature reads, without engine code."""

    raw_x = np.asarray(raw_x, dtype=float)
    medians = np.asarray(medians, dtype=float)
    if raw_x.ndim != 2 or raw_x.shape[1] != len(medians):
        raise RuntimeError("independent executor feature shape mismatch")
    structure = tree.tree_
    minority = 1 - int(static_action)
    class_matches = np.flatnonzero(tree.classes_ == minority)
    if len(class_matches) != 1:
        raise RuntimeError("independent executor class mapping mismatch")
    class_index = int(class_matches[0])
    actions = np.empty(len(raw_x), dtype=int)
    masks = np.zeros(raw_x.shape, dtype=bool)

    for row_index, row in enumerate(raw_x):
        node = 0
        while (
            structure.children_left[node]
            != structure.children_right[node]
        ):
            feature = int(structure.feature[node])
            masks[row_index, feature] = True
            value = float(row[feature])
            if np.isnan(value):
                value = float(medians[feature])
            node = int(
                structure.children_left[node]
                if value <= float(structure.threshold[node])
                else structure.children_right[node]
            )
        weights = np.asarray(structure.value[node][0], dtype=float)
        probability = float(weights[class_index] / np.sum(weights))
        actions[row_index] = (
            minority
            if probability >= float(threshold)
            else int(static_action)
        )
    costs = np.sum(masks, axis=1).astype(float)
    return actions, masks, costs


def independent_direct_actions(
    tree: DecisionTreeClassifier,
    raw_x: np.ndarray,
    medians: np.ndarray,
    static_action: int,
    threshold: float,
) -> np.ndarray:
    """Full-matrix prediction used only as an action-equivalence audit."""

    raw_x = np.asarray(raw_x, dtype=float)
    transformed = np.where(
        np.isnan(raw_x), np.asarray(medians)[None, :], raw_x
    )
    minority = 1 - int(static_action)
    class_index = int(np.flatnonzero(tree.classes_ == minority)[0])
    probability = tree.predict_proba(transformed)[:, class_index]
    return np.where(
        probability >= float(threshold),
        minority,
        int(static_action),
    ).astype(int)


def independent_certificate(
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
    if len(actions) != len(outcomes) or len(costs) != len(outcomes):
        raise RuntimeError("certificate row-count mismatch")
    changed = actions != int(static_action)
    opportunity = outcomes != int(static_action)
    helpful = changed & opportunity
    harmful = changed & ~opportunity
    changed_n = int(np.sum(changed))
    opportunity_n = int(np.sum(opportunity))
    helpful_n = int(np.sum(helpful))
    harmful_n = int(np.sum(harmful))
    gain = (
        (actions == outcomes).astype(float)
        - (int(static_action) == outcomes).astype(float)
    )
    radius = math.sqrt(
        math.log(1.0 / alpha)
        * float(np.sum((2.0 * changed.astype(float)) ** 2))
        / (2.0 * len(outcomes) ** 2)
    )
    mean_queries = float(np.mean(costs))
    compression = (
        float(feature_count / mean_queries)
        if mean_queries > 0.0
        else None
    )
    gain_lcb = float(np.mean(gain) - radius)
    harm_ucb = cp_upper(harmful_n, changed_n, alpha)
    recall_lcb = cp_lower(helpful_n, opportunity_n, alpha)
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
        "changed_actions": changed_n,
        "opportunities": opportunity_n,
        "helpful_changes": helpful_n,
        "harmful_changes": harmful_n,
        "changed_action_rate": float(np.mean(changed)),
        "opportunity_rate": float(np.mean(opportunity)),
        "opportunity_recall": (
            float(helpful_n / opportunity_n) if opportunity_n else 0.0
        ),
        "opportunity_recall_lcb": recall_lcb,
        "changed_action_harm_rate": (
            float(harmful_n / changed_n) if changed_n else 1.0
        ),
        "changed_action_harm_ucb": harm_ucb,
        "mean_queries": mean_queries,
        "worst_case_queries": (
            int(np.max(costs)) if len(costs) else 0
        ),
        "feature_count": int(feature_count),
        "average_compression": compression,
        "harm_cap": harm_cap,
        "opportunity_recall_floor": recall_floor,
        "compression_floor": compression_floor,
        "gates": gates,
        "passes": all(gates.values()),
    }


def independent_feasibility_frontier(
    outcomes: np.ndarray,
    static_action: int,
    *,
    old_coverage_floor: float,
    harm_cap: float,
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


def numerically_equal(left: Any, right: Any) -> bool:
    if isinstance(left, dict) and isinstance(right, dict):
        return set(left) == set(right) and all(
            numerically_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, (list, tuple)) and isinstance(
        right, (list, tuple)
    ):
        return len(left) == len(right) and all(
            numerically_equal(a, b) for a, b in zip(left, right)
        )
    if isinstance(left, (bool, np.bool_)) or isinstance(
        right, (bool, np.bool_)
    ):
        return bool(left) is bool(right)
    if left is None or right is None:
        return left is None and right is None
    if isinstance(left, (int, float, np.number)) and isinstance(
        right, (int, float, np.number)
    ):
        return bool(
            math.isclose(
                float(left),
                float(right),
                rel_tol=1e-12,
                abs_tol=1e-12,
            )
        )
    return left == right


def _read_locked_joblib(
    path: Path, expected_sha256: str
) -> tuple[dict[str, Any], str]:
    payload = path.read_bytes()
    observed = sha256_bytes(payload)
    if observed != expected_sha256:
        raise RuntimeError(f"locked joblib hash mismatch: {path}")
    value = joblib.load(BytesIO(payload))
    if not isinstance(value, dict):
        raise RuntimeError(f"unexpected frozen payload: {path}")
    return value, observed


def _read_locked_npz(
    path: Path, expected_sha256: str
) -> tuple[dict[str, np.ndarray], str]:
    payload = path.read_bytes()
    observed = sha256_bytes(payload)
    if observed != expected_sha256:
        raise RuntimeError(f"locked NPZ hash mismatch: {path}")
    with np.load(BytesIO(payload), allow_pickle=False) as archive:
        arrays = {
            name: np.asarray(archive[name]).copy()
            for name in archive.files
        }
    return arrays, observed


def _tree_equal(
    left: DecisionTreeClassifier, right: DecisionTreeClassifier
) -> bool:
    if not np.array_equal(left.classes_, right.classes_):
        return False
    if left.n_features_in_ != right.n_features_in_:
        return False
    left_tree = left.tree_
    right_tree = right.tree_
    if left_tree.node_count != right_tree.node_count:
        return False
    integer_fields = (
        "children_left",
        "children_right",
        "feature",
        "n_node_samples",
    )
    float_fields = (
        "threshold",
        "impurity",
        "weighted_n_node_samples",
        "value",
    )
    return all(
        np.array_equal(
            getattr(left_tree, name), getattr(right_tree, name)
        )
        for name in integer_fields
    ) and all(
        np.allclose(
            getattr(left_tree, name),
            getattr(right_tree, name),
            rtol=1e-12,
            atol=1e-12,
            equal_nan=True,
        )
        for name in float_fields
    )


def _parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(
        parsed
    ):
        return None
    if parsed > datetime.now(timezone.utc):
        return None
    return parsed


def independent_rebuild_new_preparation(
    dataset_id: int,
    config: dict[str, Any],
    preparation: dict[str, Any],
    source: dict[str, np.ndarray],
    target_features: dict[str, np.ndarray],
    target_outcomes: dict[str, np.ndarray],
) -> dict[str, bool]:
    """Rebuild CSV parsing, transform, cap and split after reveal."""

    registration = config["new_data_registration"][str(dataset_id)]
    transport = config["transport"][str(dataset_id)]
    raw_path = dataset_root(dataset_id) / "raw_official.csv"
    raw_payload = raw_path.read_bytes()
    raw_identity = {
        "bytes": len(raw_payload),
        "sha256": sha256_bytes(raw_payload),
    }
    metadata = read_json(
        PACKAGE / transport["metadata_snapshot_relative_path"]
    )["data"]
    variables = metadata["variables"]
    feature_names = [
        str(row["name"])
        for row in variables
        if row.get("role") == "Feature"
    ]
    target_names = [
        str(row["name"])
        for row in variables
        if row.get("role") == "Target"
    ]
    frame = pd.read_csv(BytesIO(raw_payload))
    if (
        set(frame.columns)
        != {str(row["name"]) for row in variables}
        or len(frame.columns) != len(set(frame.columns))
        or target_names != [transport["target_column"]]
    ):
        raise RuntimeError(
            f"independent raw CSV schema mismatch for {dataset_id}"
        )
    x_frame = frame[feature_names]
    labels = frame[target_names[0]]
    if dataset_id == 967:
        primary_names = UCI967_PRIMARY_FEATURES
        raw_group_ids = independent_normalized_domain_groups(
            x_frame["Domain"]
        )
    else:
        raise RuntimeError("independent new preparation saw unknown task")
    raw_x = (
        x_frame[primary_names]
        .apply(pd.to_numeric, errors="raise")
        .to_numpy(dtype=float)
    )
    raw_y = independent_new_target_transform(
        dataset_id, labels, config
    )
    raw_labels = labels.astype(str).to_numpy(dtype=str)
    registered_index = independent_group_complete_registration(
        raw_group_ids,
        dataset_id,
        int(registration["registered_row_cap"]),
    )
    source_index, target_index = independent_registration_source_target(
        registered_index, raw_group_ids, dataset_id
    )

    source_x = np.asarray(source["x"], dtype=float)
    source_y = np.asarray(source["y"], dtype=int)
    source_rows = np.asarray(source["row_ids"])
    source_groups = np.asarray(source["group_ids"]).astype(str)
    source_raw_labels = np.asarray(source["raw_labels"]).astype(str)
    target_x = np.asarray(target_features["x"], dtype=float)
    target_rows = np.asarray(target_features["row_ids"])
    target_groups = np.asarray(target_features["group_ids"]).astype(str)
    target_y = np.asarray(target_outcomes["y"], dtype=int)
    target_outcome_rows = np.asarray(target_outcomes["row_ids"])
    target_outcome_groups = np.asarray(
        target_outcomes["group_ids"]
    ).astype(str)
    target_raw_labels = np.asarray(
        target_outcomes["raw_labels"]
    ).astype(str)

    checks = {
        "raw_csv_artifact_identity": (
            preparation.get("artifacts", {}).get("raw_official.csv")
            == raw_identity
            and preparation.get("acquisition", {}).get("csv_bytes")
            == raw_identity["bytes"]
            and preparation.get("acquisition", {}).get("csv_sha256")
            == raw_identity["sha256"]
        ),
        "raw_csv_shape_and_schema_rebuilt": (
            x_frame.shape
            == (
                registration["raw_rows"],
                registration["raw_features"],
            )
            and raw_x.shape
            == (
                registration["raw_rows"],
                registration["primary_features"],
            )
            and independent_name_list_sha256(feature_names)
            == registration["raw_feature_name_sha256"]
            and independent_name_list_sha256(primary_names)
            == registration["primary_feature_name_sha256"]
        ),
        "raw_predictor_eligibility_rebuilt": (
            float(np.isnan(raw_x).mean()) <= 0.20
            and not bool(np.any(np.all(np.isnan(raw_x), axis=0)))
            and not bool(np.isinf(raw_x).any())
        ),
        "group_complete_cap_rebuilt": (
            len(registered_index)
            == preparation.get("registered_rows")
            and len(set(raw_group_ids[registered_index].tolist()))
            == preparation.get("registered_groups")
        ),
        "source_archive_rebuilt_from_raw": (
            np.array_equal(
                raw_x[source_index], source_x, equal_nan=True
            )
            and np.array_equal(raw_y[source_index], source_y)
            and np.array_equal(source_index, source_rows)
            and np.array_equal(
                raw_group_ids[source_index].astype(str),
                source_groups,
            )
            and np.array_equal(
                raw_labels[source_index], source_raw_labels
            )
        ),
        "target_feature_archive_rebuilt_from_raw": (
            np.array_equal(
                raw_x[target_index], target_x, equal_nan=True
            )
            and np.array_equal(target_index, target_rows)
            and np.array_equal(
                raw_group_ids[target_index].astype(str),
                target_groups,
            )
        ),
        "target_outcome_archive_rebuilt_from_raw": (
            np.array_equal(raw_y[target_index], target_y)
            and np.array_equal(target_index, target_outcome_rows)
            and np.array_equal(
                raw_group_ids[target_index].astype(str),
                target_outcome_groups,
            )
            and np.array_equal(
                raw_labels[target_index], target_raw_labels
            )
        ),
        "source_target_raw_groups_disjoint": (
            not (
                set(raw_group_ids[source_index].astype(str).tolist())
                & set(raw_group_ids[target_index].astype(str).tolist())
            )
        ),
        "fixed_transform_did_not_fit_target_vocabulary": (
            preparation.get("target_transform_fit_scope")
            == "none_pre_instance_fixed_rule"
            and preparation.get("target_summary_emitted") is False
        ),
        "raw_snapshot_preservation_declared": (
            preparation.get(
                "raw_instance_csv_preserved_for_post_reveal_audit"
            )
            is True
        ),
    }
    return checks


def audit_dataset(
    dataset_id: int,
    config: dict[str, Any],
    pre_reveal: dict[str, Any],
) -> dict[str, Any]:
    """Rebuild one source policy and independently re-score its target."""

    input_root = dataset_root(dataset_id)
    output_root = ROOT / "registered_census" / f"uci_{dataset_id}"
    frozen_path = output_root / "FROZEN_POLICY.joblib"
    actions_path = output_root / "SEALED_TARGET_ACTIONS.npz"
    receipt_path = output_root / "SOURCE_FREEZE_RECEIPT.json"
    verdict_path = output_root / "TARGET_VERDICT.json"
    source_receipt = read_json(receipt_path)
    verdict = read_json(verdict_path)
    frozen, frozen_hash = _read_locked_joblib(
        frozen_path, str(source_receipt["frozen_policy_sha256"])
    )
    sealed, actions_hash = _read_locked_npz(
        actions_path,
        str(source_receipt["sealed_target_actions_sha256"]),
    )

    preparation = read_json(input_root / "PREPARATION_RECEIPT.json")
    source_identity, source = load_verified_npz_snapshot(
        expected_artifact(dataset_id, "source.npz")
    )
    feature_identity, target_features = (
        load_verified_feature_snapshot(dataset_id)
    )
    x = np.asarray(source["x"], dtype=float)
    y = np.asarray(source["y"], dtype=int)
    row_ids = np.asarray(source["row_ids"])
    target_x = np.asarray(target_features["x"], dtype=float)
    target_row_ids = np.asarray(target_features["row_ids"])

    # Group identities and source partitions are reconstructed here rather
    # than imported from the engine.  Legacy datasets are always assigned
    # their exact-feature signatures, even if an unexpected group_ids array
    # is present. UCI 967's normalized-domain key is deliberately excluded
    # from x; its locked group identity is cross-checked across the source,
    # feature, outcome, seal and preparation receipts below.
    source_exact_groups = independent_feature_signature_groups(x)
    target_exact_groups = independent_feature_signature_groups(target_x)
    source_has_group_ids = "group_ids" in source
    target_has_group_ids = "group_ids" in target_features
    source_npz_group_ids = (
        np.asarray(source["group_ids"]).astype(str)
        if source_has_group_ids
        else None
    )
    target_npz_group_ids = (
        np.asarray(target_features["group_ids"]).astype(str)
        if target_has_group_ids
        else None
    )
    if dataset_id in NEW_IDS and not (
        source_has_group_ids and target_has_group_ids
    ):
        raise RuntimeError(
            f"new dataset {dataset_id} is missing registered group IDs"
        )
    if dataset_id == 967:
        source_group_ids = np.asarray(source_npz_group_ids).astype(str)
        target_group_ids = np.asarray(target_npz_group_ids).astype(str)
    else:
        source_group_ids = source_exact_groups
        target_group_ids = target_exact_groups

    source_group_set = set(source_group_ids.tolist())
    target_group_set = set(target_group_ids.tolist())
    source_target_group_overlap = len(
        source_group_set & target_group_set
    )

    source_archive_x = x
    source_archive_y = y
    source_archive_row_ids = row_ids
    source_archive_group_ids = source_group_ids
    target_archive_x = target_x
    target_archive_row_ids = target_row_ids
    target_archive_group_ids = target_group_ids
    source_archive_units = len(source_archive_x)
    target_archive_units = len(target_archive_x)
    source_representatives = independent_group_representatives(
        source_archive_row_ids,
        source_archive_group_ids,
        f"{config['split_salt']}|source",
    )
    target_representatives = independent_group_representatives(
        target_archive_row_ids,
        target_archive_group_ids,
        f"{config['split_salt']}|target",
    )
    x = source_archive_x[source_representatives]
    y = source_archive_y[source_representatives]
    row_ids = source_archive_row_ids[source_representatives]
    source_group_ids = source_archive_group_ids[
        source_representatives
    ]
    target_x = target_archive_x[target_representatives]
    target_row_ids = target_archive_row_ids[target_representatives]
    target_group_ids = target_archive_group_ids[
        target_representatives
    ]

    train, calibration, audit = independent_group_source_splits(
        row_ids,
        source_group_ids,
        [float(value) for value in config["source_split"]],
        str(config["split_salt"]),
    )
    source_split_group_sets = {
        "train": set(source_group_ids[train].tolist()),
        "calibration": set(source_group_ids[calibration].tolist()),
        "audit": set(source_group_ids[audit].tolist()),
    }
    source_split_group_counts = {
        name: len(groups)
        for name, groups in source_split_group_sets.items()
    }
    source_split_group_overlap = {
        "train_calibration": len(
            source_split_group_sets["train"]
            & source_split_group_sets["calibration"]
        ),
        "train_audit": len(
            source_split_group_sets["train"]
            & source_split_group_sets["audit"]
        ),
        "calibration_audit": len(
            source_split_group_sets["calibration"]
            & source_split_group_sets["audit"]
        ),
    }

    new_preparation_checks: dict[str, bool] = {}
    if dataset_id in NEW_IDS:
        registration = config["new_data_registration"][str(dataset_id)]
        expected_excluded = UCI967_EXCLUDED_FEATURES
        mapping = preparation.get("target_mapping")
        missing_fraction = preparation.get("missing_fraction")
        artifacts = preparation.get("artifacts", {})
        source_fraction = preparation.get("source_fraction")
        acquisition = preparation.get("acquisition")
        transport = config["transport"][str(dataset_id)]
        metadata_envelope = read_json(
            PACKAGE / transport["metadata_snapshot_relative_path"]
        )
        metadata = metadata_envelope.get("data", {})
        metadata_variables = metadata.get("variables", [])
        metadata_feature_names = [
            str(row.get("name"))
            for row in metadata_variables
            if row.get("role") == "Feature"
        ]
        metadata_target_names = [
            str(row.get("name"))
            for row in metadata_variables
            if row.get("role") == "Target"
        ]
        new_preparation_checks = {
            "schema_and_status": (
                preparation.get("schema")
                == "cacl-oc-r4.5-new-data-preparation-v1"
                and preparation.get("status")
                == "R4_5_NEW_DATASET_PREPARED"
                and preparation.get("uci_id") == dataset_id
            ),
            "raw_schema_receipt_matches_registration": (
                preparation.get("raw_rows")
                == registration["raw_rows"]
                and preparation.get("registered_row_cap")
                == registration["registered_row_cap"]
                and preparation.get("predictors")
                == registration["primary_features"]
                == x.shape[1]
                == target_x.shape[1]
            ),
            "feature_name_hash_receipts_match_registration": (
                preparation.get("ordered_raw_feature_name_sha256")
                == registration["raw_feature_name_sha256"]
                and preparation.get(
                    "ordered_primary_feature_name_sha256"
                )
                == registration["primary_feature_name_sha256"]
            ),
            "metadata_snapshot_independently_matches_registration": (
                metadata_envelope.get("status") == 200
                and metadata.get("uci_id") == dataset_id
                and metadata.get("num_instances")
                == registration["raw_rows"]
                and metadata.get("num_features")
                == registration["raw_features"]
                and metadata.get("data_url") == transport["url"]
                and metadata_target_names == [transport["target_column"]]
                and independent_name_list_sha256(metadata_feature_names)
                == registration["raw_feature_name_sha256"]
            ),
            "uci967_primary_hash_independently_recomputed": (
                dataset_id != 967
                or independent_name_list_sha256(UCI967_PRIMARY_FEATURES)
                == registration["primary_feature_name_sha256"]
                == preparation.get(
                    "ordered_primary_feature_name_sha256"
                )
            ),
            "feature_partition_receipt_exact": (
                preparation.get("excluded_feature_columns")
                == expected_excluded
                and registration["raw_features"]
                - registration["primary_features"]
                == len(expected_excluded)
            ),
            "group_rule_receipt_exact": (
                preparation.get("group_rule")
                == registration["group_rule"]
            ),
            "transport_receipt_exact": (
                isinstance(acquisition, dict)
                and set(acquisition)
                == {
                    "method",
                    "uci_id",
                    "url",
                    "final_url",
                    "metadata_snapshot_relative_path",
                    "metadata_snapshot_sha256",
                    "csv_bytes",
                    "csv_sha256",
                }
                and acquisition.get("method")
                == transport["method"]
                == "official_uci_static_csv"
                and acquisition.get("uci_id") == dataset_id
                and acquisition.get("url") == transport["url"]
                and (
                    lambda requested, resolved: (
                        resolved.scheme == "https"
                        and resolved.netloc.lower()
                        == requested.netloc.lower()
                        and unquote(resolved.path)
                        == unquote(requested.path)
                        and not resolved.params
                        and not resolved.query
                        and not resolved.fragment
                        and transport.get("redirect_policy")
                        == (
                            "https_same_origin_same_decoded_path_"
                            "no_query_fragment"
                        )
                    )
                )(
                    urlparse(str(acquisition.get("url", ""))),
                    urlparse(str(acquisition.get("final_url", ""))),
                )
                and acquisition.get("metadata_snapshot_relative_path")
                == transport["metadata_snapshot_relative_path"]
                and acquisition.get("metadata_snapshot_sha256")
                == transport["metadata_snapshot_sha256"]
                and sha256(
                    PACKAGE
                    / transport["metadata_snapshot_relative_path"]
                )
                == transport["metadata_snapshot_sha256"]
                and isinstance(acquisition.get("csv_bytes"), int)
                and 0
                < acquisition["csv_bytes"]
                <= transport["maximum_csv_bytes"]
                and independent_sha256_text(
                    acquisition.get("csv_sha256")
                )
            ),
            "new_task_is_locked_uci967": dataset_id == 967,
            "uci967_domain_group_proxy_is_excluded": (
                dataset_id != 967
                or (
                    preparation.get("group_rule")
                    == "normalized_domain"
                    and "Domain" in expected_excluded
                    and "Domain" not in UCI967_PRIMARY_FEATURES
                )
            ),
            "npz_group_arrays_present_and_well_formed": (
                source_has_group_ids
                and target_has_group_ids
                and source_npz_group_ids is not None
                and target_npz_group_ids is not None
                and len(source_npz_group_ids) == source_archive_units
                and len(target_npz_group_ids) == target_archive_units
                and all(source_npz_group_ids.tolist())
                and all(target_npz_group_ids.tolist())
            ),
            "registered_unit_receipts_recomputed": (
                preparation.get("source_units") == source_archive_units
                and preparation.get("target_units")
                == target_archive_units
                and preparation.get("registered_rows")
                == source_archive_units + target_archive_units
                and preparation.get("registered_rows")
                <= registration["registered_row_cap"]
                and preparation.get("registered_rows")
                <= registration["raw_rows"]
                and isinstance(source_fraction, (int, float))
                and math.isclose(
                    float(source_fraction),
                    source_archive_units
                    / (source_archive_units + target_archive_units),
                    rel_tol=0.0,
                    abs_tol=1e-15,
                )
            ),
            "group_count_receipts_recomputed": (
                preparation.get("source_groups")
                == len(source_group_set)
                and preparation.get("target_groups")
                == len(target_group_set)
                and preparation.get("registered_groups")
                == len(source_group_set | target_group_set)
                and preparation.get("source_target_group_overlap")
                == source_target_group_overlap
                == 0
            ),
            "target_mapping_receipt_valid": (
                preparation.get("target_cardinality") == 2
                and isinstance(mapping, dict)
                and mapping
                == {
                    "rule": (
                        "positive_numeric_value_to_1_nonpositive_to_0"
                    ),
                    "mapping_fit_scope": "none_pre_instance_fixed_rule",
                    "observed_target_values_disclosed": False,
                }
            ),
            "target_transform_receipt_exact": (
                preparation.get("target_transform")
                == (
                    "pre-instance fixed numeric positive-to-1, "
                    "nonpositive-to-0 mapping"
                )
                and preparation.get("target_transform_fit_scope")
                == "none_pre_instance_fixed_rule"
                and config.get("target_transforms", {}).get("967")
                == (
                    "pre_instance_fixed_numeric_positive_to_1_"
                    "nonpositive_to_0"
                )
            ),
            "target_transform_registration_exact": (
                preparation.get("target_transform_registration") is None
            ),
            "missingness_receipt_within_locked_bound": (
                isinstance(missing_fraction, (int, float))
                and 0.0 <= float(missing_fraction) <= 0.20
                and (
                    registration["registered_row_cap"]
                    < registration["raw_rows"]
                    or math.isclose(
                        float(missing_fraction),
                        float(
                            np.isnan(
                                np.concatenate(
                                    [source_archive_x, target_archive_x],
                                    axis=0,
                                )
                            ).mean()
                        ),
                        rel_tol=0.0,
                        abs_tol=1e-15,
                    )
                )
            ),
            "outcome_blind_preparation_flags": (
                preparation.get("target_summary_emitted") is False
                and preparation.get("model_fitted") is False
            ),
            "artifact_receipt_names_exact": (
                set(artifacts)
                == {
                    "raw_official.csv",
                    "source.npz",
                    "target_features.npz",
                    "target_outcomes.npz",
                }
            ),
        }

    medians = np.nanmedian(x[train], axis=0)
    transformed_train = np.where(
        np.isnan(x[train]), medians[None, :], x[train]
    )
    static_action = int(
        np.argmax(np.bincount(y[train], minlength=2))
    )

    # Re-run the complete locked search.  Reading the frozen specification
    # and fitting only that tree would verify execution but not whether the
    # preregistered grid and lexicographic rule actually selected it.
    all_calibration_candidates: list[dict[str, Any]] = []
    independently_fitted_trees: dict[
        tuple[int, int], DecisionTreeClassifier
    ] = {}
    for depth_value in config["tree_depths"]:
        for leaf_value in config["minimum_leaf_sizes"]:
            depth = int(depth_value)
            leaf = int(leaf_value)
            candidate_tree = DecisionTreeClassifier(
                max_depth=depth,
                min_samples_leaf=leaf,
                class_weight="balanced",
                criterion="log_loss",
                random_state=2304102,
            ).fit(transformed_train, y[train])
            independently_fitted_trees[(depth, leaf)] = candidate_tree
            for threshold_value in config["threshold_grid"]:
                candidate_threshold = float(threshold_value)
                (
                    candidate_actions,
                    candidate_masks,
                    candidate_costs,
                ) = independent_execute(
                    candidate_tree,
                    x[calibration],
                    medians,
                    static_action,
                    candidate_threshold,
                )
                candidate_direct = independent_direct_actions(
                    candidate_tree,
                    x[calibration],
                    medians,
                    static_action,
                    candidate_threshold,
                )
                candidate_action_agreement = float(
                    np.mean(candidate_actions == candidate_direct)
                )
                candidate_mask_cost_agreement = float(
                    np.mean(
                        np.sum(candidate_masks, axis=1)
                        == candidate_costs
                    )
                )
                if (
                    candidate_action_agreement != 1.0
                    or candidate_mask_cost_agreement != 1.0
                ):
                    raise RuntimeError(
                        "independent full-grid executor mismatch for "
                        f"UCI {dataset_id}, depth={depth}, leaf={leaf}, "
                        f"threshold={candidate_threshold}"
                    )
                candidate_certificate = independent_certificate(
                    candidate_actions,
                    y[calibration],
                    static_action,
                    candidate_costs,
                    x.shape[1],
                    alpha=float(config["source_alpha"]),
                    harm_cap=float(
                        config["selection_harm_ucb_cap"]
                    ),
                    recall_floor=float(
                        config["opportunity_recall_lcb_floor"]
                    ),
                    compression_floor=float(
                        config["average_compression_floor"]
                    ),
                )
                all_calibration_candidates.append(
                    {
                        "depth": depth,
                        "minimum_leaf_size": leaf,
                        "threshold": candidate_threshold,
                        "direct_query_action_agreement": (
                            candidate_action_agreement
                        ),
                        "mask_cost_agreement": (
                            candidate_mask_cost_agreement
                        ),
                        "calibration_screening_bounds": (
                            candidate_certificate
                        ),
                    }
                )

    eligible_calibration_candidates = [
        row
        for row in all_calibration_candidates
        if row["calibration_screening_bounds"]["passes"]
    ]
    independently_selected = (
        max(
            eligible_calibration_candidates,
            key=independent_selection_key,
        )
        if eligible_calibration_candidates
        else None
    )
    independent_diagnostic_fallback = max(
        all_calibration_candidates, key=independent_selection_key
    )
    independent_deployed_choice = (
        independently_selected
        if independently_selected is not None
        else independent_diagnostic_fallback
    )
    specification = {
        "depth": int(independent_deployed_choice["depth"]),
        "minimum_leaf_size": int(
            independent_deployed_choice["minimum_leaf_size"]
        ),
        "threshold": float(independent_deployed_choice["threshold"]),
    }
    rebuilt_tree = independently_fitted_trees[
        (
            specification["depth"],
            specification["minimum_leaf_size"],
        )
    ]
    threshold = float(specification["threshold"])

    calibration_actions, calibration_masks, calibration_costs = (
        independent_execute(
            rebuilt_tree,
            x[calibration],
            medians,
            static_action,
            threshold,
        )
    )
    calibration_direct = independent_direct_actions(
        rebuilt_tree,
        x[calibration],
        medians,
        static_action,
        threshold,
    )
    calibration_certificate = independent_certificate(
        calibration_actions,
        y[calibration],
        static_action,
        calibration_costs,
        x.shape[1],
        alpha=float(config["source_alpha"]),
        harm_cap=float(config["selection_harm_ucb_cap"]),
        recall_floor=float(config["opportunity_recall_lcb_floor"]),
        compression_floor=float(config["average_compression_floor"]),
    )
    calibration_action_agreement = float(
        np.mean(calibration_actions == calibration_direct)
    )
    calibration_mask_cost_agreement = float(
        np.mean(
            np.sum(calibration_masks, axis=1)
            == calibration_costs
        )
    )

    source_actions, source_masks, source_costs = independent_execute(
        rebuilt_tree,
        x[audit],
        medians,
        static_action,
        threshold,
    )
    source_direct = independent_direct_actions(
        rebuilt_tree,
        x[audit],
        medians,
        static_action,
        threshold,
    )
    source_certificate = independent_certificate(
        source_actions,
        y[audit],
        static_action,
        source_costs,
        x.shape[1],
        alpha=float(config["source_alpha"]),
        harm_cap=float(config["scientific_harm_ucb_cap"]),
        recall_floor=float(config["opportunity_recall_lcb_floor"]),
        compression_floor=float(config["average_compression_floor"]),
    )
    source_action_agreement = float(
        np.mean(source_actions == source_direct)
    )
    source_mask_cost_agreement = float(
        np.mean(np.sum(source_masks, axis=1) == source_costs)
    )
    candidate_route = (
        "ACT"
        if calibration_certificate["passes"]
        and source_certificate["passes"]
        and source_action_agreement
        == float(config["direct_path_action_agreement"])
        and source_mask_cost_agreement == 1.0
        and source_target_group_overlap == 0
        else "ABSTAIN"
    )
    expected_route = (
        "DESCRIPTIVE_REPLAY"
        if dataset_id in DESCRIPTIVE_IDS
        else candidate_route
    )
    frontier = independent_feasibility_frontier(
        y[audit],
        static_action,
        old_coverage_floor=0.20,
        harm_cap=float(config["scientific_harm_ucb_cap"]),
    )

    target_actions, target_masks, target_costs = independent_execute(
        rebuilt_tree,
        target_x,
        medians,
        static_action,
        threshold,
    )
    target_direct = independent_direct_actions(
        rebuilt_tree,
        target_x,
        medians,
        static_action,
        threshold,
    )
    pre_outcome_trace_checks = {
        "feature_and_seal_row_ids": np.array_equal(
            target_row_ids, np.asarray(sealed["row_ids"])
        ),
        "feature_and_seal_group_ids": np.array_equal(
            target_group_ids,
            np.asarray(sealed["group_ids"]).astype(str),
        ),
        "candidate_actions": np.array_equal(
            target_actions, sealed["candidate_actions"]
        ),
        "candidate_masks": np.array_equal(
            target_masks, sealed["candidate_query_mask"]
        ),
        "candidate_costs": np.array_equal(
            target_costs, sealed["candidate_costs"]
        ),
        "mask_cost_identity": np.array_equal(
            np.sum(sealed["candidate_query_mask"], axis=1),
            sealed["candidate_costs"],
        ),
        "direct_path_identity": np.array_equal(
            target_actions, target_direct
        ),
    }
    if not all(pre_outcome_trace_checks.values()):
        failed = [
            name
            for name, value in pre_outcome_trace_checks.items()
            if not value
        ]
        raise RuntimeError(
            "pre-outcome target trace audit failed for "
            f"{dataset_id}: {', '.join(failed)}"
        )

    # The outcome snapshot is decoded only after the independent policy trace
    # has reproduced every sealed action, query mask and cost.
    outcome_identity, target = load_verified_target_snapshot(dataset_id)
    target_outcome_row_ids_full = np.asarray(target["row_ids"])
    full_target_row_identity = np.array_equal(
        target_archive_row_ids, target_outcome_row_ids_full
    )
    if not full_target_row_identity:
        raise RuntimeError(
            f"full target feature/outcome row mismatch for {dataset_id}"
        )
    target_y_full = np.asarray(target["y"], dtype=int)
    if len(target_y_full) != target_archive_units:
        raise RuntimeError(
            f"full target outcome denominator mismatch for {dataset_id}"
        )
    target_y = target_y_full[target_representatives]
    target_outcome_has_group_ids = "group_ids" in target
    target_outcome_group_ids_full = (
        np.asarray(target["group_ids"]).astype(str)
        if target_outcome_has_group_ids
        else None
    )
    target_outcome_group_ids = (
        target_outcome_group_ids_full[target_representatives]
        if target_outcome_group_ids_full is not None
        else None
    )
    target_outcome_group_identity = (
        (
            np.array_equal(
                target_outcome_group_ids_full,
                target_archive_group_ids,
            )
            and np.array_equal(
                target_outcome_group_ids, target_group_ids
            )
        )
        if target_outcome_has_group_ids
        else dataset_id not in NEW_IDS
    )
    if dataset_id in NEW_IDS:
        artifacts = preparation["artifacts"]
        raw_path = input_root / "raw_official.csv"
        raw_identity = {
            "bytes": raw_path.stat().st_size,
            "sha256": sha256(raw_path),
        }
        new_preparation_checks[
            "artifact_receipts_match_verified_snapshots"
        ] = all(
            artifacts.get(name)
            == {
                "bytes": int(identity["bytes"]),
                "sha256": str(identity["sha256"]),
            }
            for name, identity in (
                ("source.npz", source_identity),
                ("target_features.npz", feature_identity),
                ("target_outcomes.npz", outcome_identity),
            )
        ) and artifacts.get("raw_official.csv") == raw_identity
        new_preparation_checks[
            "outcome_npz_group_ids_match_feature_registration"
        ] = (
            target_outcome_has_group_ids
            and target_outcome_group_ids_full is not None
            and len(target_outcome_group_ids_full)
            == target_archive_units
            and target_outcome_group_identity
        )
        new_preparation_checks.update(
            independent_rebuild_new_preparation(
                dataset_id,
                config,
                preparation,
                source,
                target_features,
                target,
            )
        )
    target_certificate = independent_certificate(
        target_actions,
        target_y,
        static_action,
        target_costs,
        x.shape[1],
        alpha=float(config["target_alpha"]),
        harm_cap=float(config["scientific_harm_ucb_cap"]),
        recall_floor=float(config["opportunity_recall_lcb_floor"]),
        compression_floor=float(config["average_compression_floor"]),
    )
    expected_verdict = (
        (
            "OPERATIONAL_ACT_PASS"
            if target_certificate["passes"]
            else "FALSE_ACT_FAIL"
        )
        if expected_route == "ACT"
        else (
            "DESCRIPTIVE_REPLAY_REPORTED"
            if expected_route == "DESCRIPTIVE_REPLAY"
            else (
                "FALSE_ABSTAIN_FAIL"
                if target_certificate["passes"]
                else "OPERATIONAL_ABSTAIN_CORRECT"
            )
        )
    )
    expected_deployed_actions = (
        target_actions
        if expected_route == "ACT"
        else np.full(
            len(target_actions), static_action, dtype=int
        )
    )
    expected_deployed_costs = (
        target_costs
        if expected_route == "ACT"
        else np.zeros(len(target_costs), dtype=float)
    )
    expected_deployed_masks = (
        target_masks
        if expected_route == "ACT"
        else np.zeros_like(target_masks, dtype=bool)
    )
    expected_candidate_count = (
        len(config["tree_depths"])
        * len(config["minimum_leaf_sizes"])
        * len(config["threshold_grid"])
    )
    expected_target_compression = float(
        x.shape[1] / np.mean(target_costs)
    )

    source_checks = {
        "dataset_root_current": input_root == dataset_root(dataset_id),
        "source_schema": (
            source_receipt.get("schema")
            == "cacl-oc-r4.5-source-freeze-receipt-v1"
            and frozen.get("schema")
            == "cacl-oc-r4.5-frozen-policy-v1"
        ),
        "dataset_ids_exact": (
            source_receipt.get("dataset_id")
            == frozen.get("dataset_id")
            == dataset_id
        ),
        "source_snapshot_identity": (
            source_identity
            == source_receipt.get("source_snapshot_identity")
        ),
        "feature_snapshot_identity": (
            feature_identity
            == source_receipt.get("target_feature_snapshot_identity")
        ),
        "outcome_binding_exact": (
            source_receipt.get(
                "target_outcome_binding_from_preparation"
            )
            == expected_outcome_binding(dataset_id)
        ),
        "frozen_hash_exact": frozen_hash
        == source_receipt.get("frozen_policy_sha256"),
        "actions_hash_exact": actions_hash
        == source_receipt.get("sealed_target_actions_sha256"),
        "row_shapes_valid": (
            source_archive_x.ndim == 2
            and len(source_archive_x)
            == len(source_archive_y)
            == len(source_archive_row_ids)
            and target_archive_x.ndim == 2
            and len(target_archive_x) == len(target_archive_row_ids)
            and target_archive_x.shape[1]
            == source_archive_x.shape[1]
            and x.ndim == 2
            and len(x) == len(y) == len(row_ids)
            and target_x.ndim == 2
            and len(target_x) == len(target_row_ids)
            and target_x.shape[1] == x.shape[1]
        ),
        "binary_source_task": (
            set(np.unique(source_archive_y).tolist()) == {0, 1}
            and set(np.unique(y).tolist()) == {0, 1}
        ),
        "row_ids_disjoint": (
            len(np.unique(source_archive_row_ids))
            == source_archive_units
            and len(np.unique(target_archive_row_ids))
            == target_archive_units
            and np.intersect1d(
                source_archive_row_ids, target_archive_row_ids
            ).size
            == 0
        ),
        "group_id_shapes_valid": (
            len(source_archive_group_ids) == source_archive_units
            and len(target_archive_group_ids) == target_archive_units
            and len(source_group_ids) == len(x)
            and len(target_group_ids) == len(target_x)
            and all(source_group_ids.tolist())
            and all(target_group_ids.tolist())
        ),
        "representatives_independently_recomputed": (
            len(x) == len(source_group_set)
            and len(target_x) == len(target_group_set)
            and len(np.unique(source_group_ids)) == len(x)
            and len(np.unique(target_group_ids)) == len(target_x)
            and np.array_equal(
                row_ids,
                source_archive_row_ids[source_representatives],
            )
            and np.array_equal(
                target_row_ids,
                target_archive_row_ids[target_representatives],
            )
            and np.array_equal(
                source_group_ids,
                source_archive_group_ids[source_representatives],
            )
            and np.array_equal(
                target_group_ids,
                target_archive_group_ids[target_representatives],
            )
        ),
        "new_npz_group_ids_present": (
            dataset_id not in NEW_IDS
            or (
                source_has_group_ids
                and target_has_group_ids
                and source_npz_group_ids is not None
                and target_npz_group_ids is not None
            )
        ),
        "legacy_group_ids_independently_recomputed": (
            dataset_id in NEW_IDS
            or (
                (
                    not source_has_group_ids
                    or np.array_equal(
                        source_npz_group_ids, source_exact_groups
                    )
                )
                and (
                    not target_has_group_ids
                    or np.array_equal(
                        target_npz_group_ids, target_exact_groups
                    )
                )
                and np.array_equal(
                    source_archive_group_ids, source_exact_groups
                )
                and np.array_equal(
                    target_archive_group_ids, target_exact_groups
                )
            )
        ),
        "split_denominator_exact": (
            len(train) + len(calibration) + len(audit) == len(x)
            and np.array_equal(
                np.sort(np.concatenate([train, calibration, audit])),
                np.arange(len(x), dtype=int),
            )
        ),
        "source_split_groups_disjoint": (
            all(value == 0 for value in source_split_group_overlap.values())
            and (
                source_split_group_sets["train"]
                | source_split_group_sets["calibration"]
                | source_split_group_sets["audit"]
            )
            == source_group_set
        ),
        "source_group_counts_recomputed": (
            frozen.get("source_group_count")
            == source_receipt.get("source_group_count")
            == len(source_group_set)
            and frozen.get("source_train_group_count")
            == source_receipt.get("source_train_group_count")
            == source_split_group_counts["train"]
            and frozen.get("source_calibration_group_count")
            == source_receipt.get("source_calibration_group_count")
            == source_split_group_counts["calibration"]
            and frozen.get("source_audit_group_count")
            == source_receipt.get("source_audit_group_count")
            == source_split_group_counts["audit"]
        ),
        "archive_and_representative_counts_recomputed": (
            frozen.get("source_archive_units")
            == source_receipt.get("source_archive_units")
            == source_archive_units
            and frozen.get("source_representative_units")
            == source_receipt.get("source_representative_units")
            == len(x)
            == len(source_group_set)
            and frozen.get("target_archive_units")
            == source_receipt.get("target_archive_units")
            == target_archive_units
            and frozen.get("target_representative_units")
            == source_receipt.get("target_representative_units")
            == len(target_x)
            == len(target_group_set)
        ),
        "certificate_unit_exact": (
            source_receipt.get("certificate_unit")
            == (
                "one deterministic label-blind representative per "
                "registered group"
            )
        ),
        "source_target_group_overlap_recomputed": (
            frozen.get("source_target_group_overlap")
            == source_receipt.get("source_target_group_overlap")
            == source_target_group_overlap
        ),
        "source_target_overlap_blocks_inferential_act": (
            dataset_id not in INFERENTIAL_IDS
            or source_target_group_overlap == 0
            or candidate_route == "ABSTAIN"
        ),
        "uci327_exact_signature_overlap_blocks_act": (
            dataset_id != 327
            or source_target_group_overlap == 0
            or candidate_route == "ABSTAIN"
        ),
        "new_preparation_receipt_audit": (
            dataset_id not in NEW_IDS
            or (
                bool(new_preparation_checks)
                and all(new_preparation_checks.values())
            )
        ),
        "training_medians_exact": np.allclose(
            medians,
            np.asarray(frozen["imputer"].statistics_, dtype=float),
            rtol=0.0,
            atol=0.0,
            equal_nan=True,
        ),
        "static_action_recomputed": (
            frozen.get("static_action")
            == source_receipt["source_audit_certificate"][
                "static_action"
            ]
            == static_action
        ),
        "specification_exact": (
            specification
            == source_receipt.get("selected_specification")
            == frozen.get("selected_specification")
            and int(specification["depth"]) in config["tree_depths"]
            and int(specification["minimum_leaf_size"])
            in config["minimum_leaf_sizes"]
            and float(specification["threshold"])
            in config["threshold_grid"]
        ),
        "frozen_tree_rebuilt": _tree_equal(
            rebuilt_tree, frozen["tree"]
        ),
        "candidate_count_exact": (
            source_receipt.get("candidate_count")
            == expected_candidate_count
            == len(all_calibration_candidates)
        ),
        "eligible_candidate_count_recomputed": (
            source_receipt.get("eligible_calibration_candidates")
            == len(eligible_calibration_candidates)
        ),
        "selected_eligibility_exact": (
            bool(frozen.get("selected_was_calibration_eligible"))
            == (independently_selected is not None)
            == (
                source_receipt.get(
                    "eligible_calibration_candidates", 0
                )
                > 0
            )
            == bool(calibration_certificate["passes"])
        ),
        "full_grid_selection_or_fallback_recomputed": (
            specification
            == {
                "depth": int(independent_deployed_choice["depth"]),
                "minimum_leaf_size": int(
                    independent_deployed_choice[
                        "minimum_leaf_size"
                    ]
                ),
                "threshold": float(
                    independent_deployed_choice["threshold"]
                ),
            }
            and (
                (
                    independently_selected is not None
                    and independent_deployed_choice
                    is independently_selected
                )
                or (
                    independently_selected is None
                    and independent_deployed_choice
                    is independent_diagnostic_fallback
                )
            )
        ),
        "calibration_certificate_recomputed": (
            numerically_equal(
                calibration_certificate,
                frozen.get("calibration_screening_bounds"),
            )
            and numerically_equal(
                calibration_certificate,
                source_receipt.get("calibration_screening_bounds"),
            )
            and numerically_equal(
                calibration_certificate,
                independent_deployed_choice[
                    "calibration_screening_bounds"
                ],
            )
        ),
        "calibration_executor_exact": (
            calibration_action_agreement == 1.0
            and calibration_mask_cost_agreement == 1.0
        ),
        "source_certificate_recomputed": (
            numerically_equal(
                source_certificate,
                frozen.get("source_audit_certificate"),
            )
            and numerically_equal(
                source_certificate,
                source_receipt.get("source_audit_certificate"),
            )
        ),
        "source_executor_metrics_recomputed": (
            numerically_equal(
                source_action_agreement,
                frozen.get(
                    "source_audit_direct_query_action_agreement"
                ),
            )
            and numerically_equal(
                source_action_agreement,
                source_receipt.get(
                    "source_audit_direct_query_action_agreement"
                ),
            )
            and numerically_equal(
                source_mask_cost_agreement,
                frozen.get("source_audit_mask_cost_agreement"),
            )
            and numerically_equal(
                source_mask_cost_agreement,
                source_receipt.get(
                    "source_audit_mask_cost_agreement"
                ),
            )
        ),
        "candidate_route_recomputed": (
            frozen.get("candidate_route_before_role_override")
            == source_receipt.get(
                "candidate_route_before_role_override"
            )
            == candidate_route
        ),
        "role_route_recomputed": (
            frozen.get("route")
            == source_receipt.get("route")
            == pre_reveal["routes"].get(str(dataset_id))
            == expected_route
        ),
        "descriptive_role_enforced": (
            dataset_id not in DESCRIPTIVE_IDS
            or expected_route == "DESCRIPTIVE_REPLAY"
        ),
        "feasibility_frontier_recomputed": numerically_equal(
            frontier,
            source_receipt.get("source_feasibility_frontier"),
        ),
        "target_outcome_blind_query_metrics_recomputed": (
            source_receipt.get("target_units") == len(target_actions)
            and numerically_equal(
                source_receipt.get(
                    "target_mean_queries_outcome_blind"
                ),
                float(np.mean(target_costs)),
            )
            and numerically_equal(
                source_receipt.get(
                    "target_average_compression_outcome_blind"
                ),
                expected_target_compression,
            )
        ),
        "unopened_flags_exact": (
            source_receipt.get(
                "target_outcomes_semantically_opened"
            )
            is False
            and frozen.get("target_outcomes_opened") is False
        ),
    }

    target_checks = {
        "verdict_schema": (
            verdict.get("schema")
            == "cacl-oc-r4.5-target-verdict-v1"
        ),
        "dataset_and_route_exact": (
            verdict.get("dataset_id") == dataset_id
            and verdict.get("pre_reveal_route") == expected_route
        ),
        "feature_identity_exact": (
            feature_identity == verdict.get("target_feature_identity")
        ),
        "outcome_identity_exact": (
            outcome_identity == verdict.get("target_outcome_identity")
        ),
        "target_row_ids_exact": (
            full_target_row_identity
            and np.array_equal(
                target_row_ids, np.asarray(sealed["row_ids"])
            )
            and np.array_equal(
                target_outcome_row_ids_full[target_representatives],
                np.asarray(sealed["row_ids"]),
            )
        ),
        "target_group_ids_exact": (
            np.array_equal(
                target_group_ids,
                np.asarray(sealed["group_ids"]).astype(str),
            )
            and target_outcome_group_identity
        ),
        "target_representative_denominator_exact": (
            len(target_actions)
            == len(target_y)
            == len(target_representatives)
            == len(target_group_set)
            and target_archive_units
            == len(target_outcome_row_ids_full)
        ),
        "new_target_outcome_group_ids_present": (
            dataset_id not in NEW_IDS or target_outcome_has_group_ids
        ),
        "candidate_actions_recomputed": np.array_equal(
            target_actions, sealed["candidate_actions"]
        ),
        "candidate_masks_recomputed": np.array_equal(
            target_masks, sealed["candidate_query_mask"]
        ),
        "candidate_costs_recomputed": np.array_equal(
            target_costs, sealed["candidate_costs"]
        ),
        "candidate_mask_cost_exact": np.array_equal(
            np.sum(sealed["candidate_query_mask"], axis=1),
            sealed["candidate_costs"],
        ),
        "candidate_direct_path_exact": (
            all(pre_outcome_trace_checks.values())
            and verdict.get("query_mask_cost_agreement") == 1.0
        ),
        "deployed_actions_exact": np.array_equal(
            expected_deployed_actions, sealed["deployed_actions"]
        ),
        "deployed_masks_exact": np.array_equal(
            expected_deployed_masks, sealed["deployed_query_mask"]
        ),
        "deployed_costs_exact": np.array_equal(
            expected_deployed_costs, sealed["deployed_costs"]
        ),
        "deployed_mask_cost_exact": np.array_equal(
            np.sum(sealed["deployed_query_mask"], axis=1),
            sealed["deployed_costs"],
        ),
        "target_certificate_recomputed": numerically_equal(
            target_certificate, verdict.get("target_certificate")
        ),
        "verdict_recomputed": verdict.get("verdict")
        == expected_verdict,
        "artifact_hashes_repeated_in_verdict": (
            verdict.get("frozen_policy_sha256") == frozen_hash
            and verdict.get("sealed_target_actions_sha256")
            == actions_hash
        ),
        "outcome_nonuse_flag_and_qualifier_exact": (
            verdict.get(
                "target_outcome_unused_for_policy_route_and_actions"
            )
            is True
            and verdict.get("target_outcome_usage_qualifier")
            == (
                "The preparation layer decoded labels only to create a "
                "hash-bound outcome archive; policy fitting, routing and "
                "sealed actions did not semantically decode that archive "
                "before the one-shot reveal."
            )
            and verdict.get("claim_boundary")
            == (
                "Externally timestamped, source-informed, target-outcome-"
                "untouched computational confirmation with instrumented "
                "tree-path access replay on finite registered group "
                "representatives over a preloaded matrix; not a raw-row "
                "population guarantee, independent custody, prospective "
                "physical acquisition, causal, clinical, wet-lab or "
                "field-safety evidence."
            )
        ),
    }

    role = str(config["dataset_roles"][str(dataset_id)])
    all_checks = all(source_checks.values()) and all(
        target_checks.values()
    )
    return {
        "dataset_id": dataset_id,
        "role": role,
        "inferential": dataset_id in INFERENTIAL_IDS,
        "descriptive_only": dataset_id in DESCRIPTIVE_IDS,
        "recomputed_route": expected_route,
        "recomputed_verdict": expected_verdict,
        "source_archive_units": source_archive_units,
        "source_representative_units": len(x),
        "target_archive_units": target_archive_units,
        "target_representative_units": len(target_x),
        "source_split_units": {
            "train": len(train),
            "calibration": len(calibration),
            "audit": len(audit),
        },
        "source_group_count": len(source_group_set),
        "source_split_group_counts": source_split_group_counts,
        "source_split_group_overlap": source_split_group_overlap,
        "source_target_group_overlap": source_target_group_overlap,
        "new_preparation_checks": new_preparation_checks,
        "full_grid_search": {
            "candidate_count": len(all_calibration_candidates),
            "eligible_candidate_count": len(
                eligible_calibration_candidates
            ),
            "selection_mode": (
                "ELIGIBLE_MAX"
                if independently_selected is not None
                else "DIAGNOSTIC_FALLBACK"
            ),
            "selected_specification": specification,
        },
        "source_calibration_certificate": calibration_certificate,
        "source_audit_certificate": source_certificate,
        "target_certificate": target_certificate,
        "source_checks": source_checks,
        "target_checks": target_checks,
        "passes": all_checks,
    }


def main() -> None:
    output = RECEIPTS / "R4_5_FINAL_INTEGRITY_AUDIT.json"
    if output.exists():
        raise FileExistsError(f"write-once audit already exists: {output}")

    chain = validate_ack_and_lock()
    config = read_json(ROOT / "config" / "r4_5_contract.json")
    verification = read_json(
        RECEIPTS / "R4_5_EXTERNAL_TIMESTAMP_VERIFICATION.json"
    )
    pre_reveal = read_json(RECEIPTS / "R4_5_PRE_REVEAL_BATCH.json")
    reveal_started_path = RECEIPTS / "R4_5_REVEAL_STARTED.json"
    reveal_completed_path = RECEIPTS / "R4_5_REVEAL_COMPLETED.json"
    final_path = RECEIPTS / "R4_5_FINAL_BATCH_VERDICT.json"
    reveal_started = read_json(reveal_started_path)
    reveal_completed = read_json(reveal_completed_path)
    final = read_json(final_path)
    started_at = _parse_utc(reveal_started.get("started_utc"))
    reveal_start_authorized = (
        reveal_started.get("schema")
        == "cacl-oc-r4.5-reveal-start-v1"
        and reveal_started.get("status")
        == "R4_5_ONE_SHOT_TARGET_REVEAL_STARTED"
        and reveal_started.get("campaign_ids") == CAMPAIGN_IDS
        and reveal_started.get("historical_non_evaluated_ids")
        == HISTORICAL_NON_EVALUATED_IDS
        and reveal_started.get("registered_ids") == REGISTERED_IDS
        and reveal_started.get("lock_sha256") == chain["lock_sha256"]
        and reveal_started.get("ack_sha256") == chain["ack_sha256"]
        and reveal_started.get("public_commit_sha")
        == chain["public_commit_sha"]
        and reveal_started.get(
            "target_outcome_semantic_load_before_this_receipt"
        )
        is False
        and reveal_started.get("retry_permitted") is False
        and started_at is not None
    )
    if not reveal_start_authorized:
        raise RuntimeError(
            "R4.5 reveal-start receipt is invalid; refusing target decode"
        )

    rows = [
        audit_dataset(dataset_id, config, pre_reveal)
        for dataset_id in REGISTERED_IDS
    ]
    inferential_rows = [
        row for row in rows if row["dataset_id"] in INFERENTIAL_IDS
    ]
    descriptive_rows = [
        row for row in rows if row["dataset_id"] in DESCRIPTIVE_IDS
    ]
    new_rows = [
        row for row in rows if row["dataset_id"] in NEW_IDS
    ]
    routes = {
        str(row["dataset_id"]): row["recomputed_route"]
        for row in rows
    }
    dataset_verdicts = {
        str(row["dataset_id"]): row["recomputed_verdict"]
        for row in rows
    }
    inferential_source_act_count = sum(
        row["recomputed_route"] == "ACT"
        for row in inferential_rows
    )
    new_source_act_count = sum(
        row["recomputed_route"] == "ACT" for row in new_rows
    )
    target_act_pass_count = sum(
        row["recomputed_verdict"] == "OPERATIONAL_ACT_PASS"
        for row in inferential_rows
    )
    new_target_act_pass_count = sum(
        row["recomputed_verdict"] == "OPERATIONAL_ACT_PASS"
        for row in new_rows
    )
    false_act_count = sum(
        row["recomputed_verdict"] == "FALSE_ACT_FAIL"
        for row in inferential_rows
    )
    expected_gates = {
        "denominator_complete": [
            row["dataset_id"] for row in rows
        ]
        == REGISTERED_IDS,
        "inferential_denominator_exact": [
            row["dataset_id"] for row in inferential_rows
        ]
        == INFERENTIAL_IDS,
        "minimum_source_act": (
            inferential_source_act_count
            >= int(config["minimum_source_act"])
        ),
        "minimum_new_source_act": (
            new_source_act_count
            >= int(config["minimum_new_source_act"])
        ),
        "minimum_target_act_pass": (
            target_act_pass_count
            >= int(config["minimum_target_act_pass"])
        ),
        "minimum_new_target_act_pass": (
            new_target_act_pass_count
            >= int(config["minimum_new_target_act_pass"])
        ),
        "zero_false_act": false_act_count == 0,
    }
    expected_status = (
        "R4_5_CONFIRMATORY_PASS"
        if all(expected_gates.values())
        else "R4_5_CONFIRMATORY_FAIL"
    )
    completed_at = _parse_utc(reveal_completed.get("completed_utc"))
    verdict_paths = {
        str(dataset_id): (
            ROOT
            / "registered_census"
            / f"uci_{dataset_id}"
            / "TARGET_VERDICT.json"
        )
        for dataset_id in REGISTERED_IDS
    }
    expected_verdict_hashes = {
        key: sha256(path) for key, path in verdict_paths.items()
    }
    stale_prior_outputs = sorted(
        {
            path.name
            for pattern in ("R4_1_*", "R4_2_*", "R4_3_*")
            for path in RECEIPTS.glob(pattern)
        }
    )

    batch_checks = {
        "stage_a_chain_revalidated": (
            bool(chain.get("stage_a_lock_sha256"))
            and bool(chain.get("stage_a_ack_sha256"))
            and bool(chain.get("stage_a_public_commit_sha"))
            and chain["checks"].get(
                "prior_invalidation_provenance_exact"
            )
            is True
            and chain["checks"].get("prior_access_audit_exact") is True
            and chain["checks"].get("stage_a_verification_exact") is True
            and chain["checks"].get("new_preparation_batch_exact") is True
        ),
        "config_denominators_exact": (
            config.get("campaign_ids") == CAMPAIGN_IDS
            and config.get("historical_non_evaluated_ids")
            == HISTORICAL_NON_EVALUATED_IDS
            and config.get("registered_ids") == REGISTERED_IDS
            and config.get("inferential_ids") == INFERENTIAL_IDS
            and config.get("descriptive_ids") == DESCRIPTIVE_IDS
            and set(INFERENTIAL_IDS).isdisjoint(DESCRIPTIVE_IDS)
            and sorted(INFERENTIAL_IDS + DESCRIPTIVE_IDS)
            == sorted(REGISTERED_IDS)
            and sorted(
                REGISTERED_IDS + HISTORICAL_NON_EVALUATED_IDS
            )
            == sorted(CAMPAIGN_IDS)
        ),
        "new_denominator_exact": (
            [row["dataset_id"] for row in new_rows] == NEW_IDS
            and set(NEW_IDS).issubset(INFERENTIAL_IDS)
            and sorted(
                int(value)
                for value in config.get(
                    "new_data_registration", {}
                )
            )
            == NEW_IDS
        ),
        "uci75_descriptive_only": (
            DESCRIPTIVE_IDS == [75]
            and 75 not in INFERENTIAL_IDS
            and len(descriptive_rows) == 1
            and descriptive_rows[0]["recomputed_route"]
            == "DESCRIPTIVE_REPLAY"
            and descriptive_rows[0]["recomputed_verdict"]
            == "DESCRIPTIVE_REPLAY_REPORTED"
        ),
        "pre_reveal_schema_status": (
            pre_reveal.get("schema")
            == "cacl-oc-r4.5-pre-reveal-batch-v1"
            and pre_reveal.get("status")
            == "R4_5_PRE_REVEAL_ROUTES_FROZEN"
            and pre_reveal.get("target_outcomes_semantically_opened")
            is False
            and pre_reveal.get("write_once") is True
        ),
        "pre_reveal_denominators_exact": (
            pre_reveal.get("campaign_denominator") == CAMPAIGN_IDS
            and pre_reveal.get(
                "historical_non_evaluated_denominator"
            )
            == HISTORICAL_NON_EVALUATED_IDS
            and pre_reveal.get("registered_denominator")
            == REGISTERED_IDS
            and pre_reveal.get("inferential_denominator")
            == INFERENTIAL_IDS
            and pre_reveal.get("descriptive_denominator")
            == DESCRIPTIVE_IDS
        ),
        "pre_reveal_routes_and_count_recomputed": (
            pre_reveal.get("routes") == routes
            and pre_reveal.get("inferential_source_act_count")
            == inferential_source_act_count
            and pre_reveal.get("new_source_act_count")
            == new_source_act_count
        ),
        "timestamp_verification_exact": (
            verification.get("schema")
            == "cacl-oc-r4.5-timestamp-verification-v1"
            and verification.get("status")
            == "R4_5_TARGET_REVEAL_AUTHORIZED"
            and verification.get("lock_sha256")
            == chain["lock_sha256"]
            and verification.get("ack_sha256")
            == chain["ack_sha256"]
            and verification.get("public_commit_sha")
            == chain["public_commit_sha"]
            and verification.get("checks") == chain["checks"]
            and verification.get("locked_file_count")
            == len(chain["file_checks"])
            and verification.get("all_locked_files_current") is True
            and verification.get("all_outcome_bindings_committed")
            is True
            and verification.get(
                "target_outcome_semantic_load_permitted_after_receipt"
            )
            is True
        ),
        "reveal_start_write_once_receipt": (
            reveal_start_authorized
        ),
        "reveal_complete_write_once_receipt": (
            reveal_completed.get("schema")
            == "cacl-oc-r4.5-reveal-complete-v1"
            and reveal_completed.get("status")
            == "R4_5_ONE_SHOT_TARGET_REVEAL_COMPLETED"
            and reveal_completed.get("campaign_ids") == CAMPAIGN_IDS
            and reveal_completed.get("historical_non_evaluated_ids")
            == HISTORICAL_NON_EVALUATED_IDS
            and reveal_completed.get("registered_ids")
            == REGISTERED_IDS
            and reveal_completed.get("retry_permitted") is False
            and completed_at is not None
            and (
                started_at is not None
                and completed_at is not None
                and completed_at >= started_at
            )
            and reveal_completed.get("final_batch_verdict_sha256")
            == sha256(final_path)
            and reveal_completed.get("verdict_sha256")
            == expected_verdict_hashes
        ),
        "final_schema": (
            final.get("schema")
            == "cacl-oc-r4.5-final-batch-verdict-v1"
        ),
        "final_denominators_exact": (
            final.get("campaign_denominator") == CAMPAIGN_IDS
            and final.get("historical_non_evaluated_denominator")
            == HISTORICAL_NON_EVALUATED_IDS
            and final.get("registered_denominator") == REGISTERED_IDS
            and final.get("inferential_denominator") == INFERENTIAL_IDS
            and final.get("descriptive_denominator")
            == DESCRIPTIVE_IDS
        ),
        "final_dataset_verdicts_exact": (
            final.get("dataset_verdicts") == dataset_verdicts
        ),
        "final_counts_inferential_only": (
            final.get("inferential_source_act_count")
            == inferential_source_act_count
            and final.get("new_source_act_count")
            == new_source_act_count
            and final.get("target_act_pass_count")
            == target_act_pass_count
            and final.get("new_target_act_pass_count")
            == new_target_act_pass_count
            and final.get("false_act_count") == false_act_count
        ),
        "final_gates_recomputed": final.get("gates")
        == expected_gates,
        "final_status_recomputed": final.get("status")
        == expected_status,
        "no_stale_prior_outputs": not stale_prior_outputs,
    }
    all_dataset_checks = all(row["passes"] for row in rows)
    all_batch_checks = all(batch_checks.values())
    receipt = {
        "schema": "cacl-oc-r4.5-final-integrity-audit-v1",
        "status": (
            "R4_5_FINAL_INTEGRITY_AUDIT_PASS"
            if all_dataset_checks and all_batch_checks
            else "R4_5_FINAL_INTEGRITY_AUDIT_FAIL"
        ),
        "locked_file_count": len(chain["file_checks"]),
        "stage_a_lock_sha256": chain["stage_a_lock_sha256"],
        "stage_a_ack_sha256": chain["stage_a_ack_sha256"],
        "stage_a_public_commit_sha": chain[
            "stage_a_public_commit_sha"
        ],
        "campaign_denominator": CAMPAIGN_IDS,
        "historical_non_evaluated_denominator": (
            HISTORICAL_NON_EVALUATED_IDS
        ),
        "registered_denominator": REGISTERED_IDS,
        "inferential_denominator": INFERENTIAL_IDS,
        "descriptive_denominator": DESCRIPTIVE_IDS,
        "recomputed_inferential_source_act_count": (
            inferential_source_act_count
        ),
        "recomputed_new_source_act_count": new_source_act_count,
        "recomputed_target_act_pass_count": target_act_pass_count,
        "recomputed_new_target_act_pass_count": (
            new_target_act_pass_count
        ),
        "recomputed_false_act_count": false_act_count,
        "recomputed_final_gates": expected_gates,
        "recomputed_final_status": expected_status,
        "dataset_audits": rows,
        "batch_checks": batch_checks,
        "stale_prior_outputs": stale_prior_outputs,
        "all_checks_pass": all_dataset_checks and all_batch_checks,
    }
    exclusive_write_json(output, receipt)
    print(receipt["status"])
    if not receipt["all_checks_pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
