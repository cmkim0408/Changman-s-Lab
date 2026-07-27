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
       …14232 tokens truncated…tity == verdict.get("target_feature_identity")
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
