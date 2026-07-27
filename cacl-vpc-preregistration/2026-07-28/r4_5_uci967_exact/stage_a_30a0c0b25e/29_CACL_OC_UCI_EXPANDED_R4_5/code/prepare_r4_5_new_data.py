#!/usr/bin/env python3
"""Prepare the single R4.5 pre-instance-data UCI task without summaries."""

from __future__ import annotations

import hashlib
import json
from io import BytesIO
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse
from urllib.request import Request, urlopen

import numpy as np
import pandas as pd

from integrity import (
    PACKAGE,
    ROOT,
    exclusive_write_json,
    read_json,
    sha256,
    validate_stage_a_ack_and_lock,
)


NEW_DATASETS = {
    967: {
        "name": "PhiUSIIL Phishing URL (Website)",
        "raw_rows": 235795,
        "raw_features": 54,
        "primary_features": 46,
        "registered_row_cap": 100000,
        "raw_feature_name_sha256": (
            "8f2b32b72319d66b4d42225a0d7279269ee0b0e735928864"
            "46012ca4594f9866"
        ),
        "primary_feature_name_sha256": (
            "54250825298c88f28c5f24430288afa85ac2ab4cf21f630848"
            "217a34ae5fedc4"
        ),
        "group_rule": "normalized_domain",
    },
}
PRIMARY_967 = [
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
EXCLUDED_967 = [
    "URL",
    "Domain",
    "TLD",
    "Title",
    "URLSimilarityIndex",
    "CharContinuationRate",
    "TLDLegitimateProb",
    "URLCharProb",
]
SELECTION_SALT = "CACL-OC-R4.2-GROUP-COMPLETE-REGISTRATION-v1"
SOURCE_TARGET_SALT = "CACL-OC-R4.2-GROUP-SOURCE-TARGET-v1"
REDIRECT_POLICY = (
    "https_same_origin_same_decoded_path_no_query_fragment"
)
TRANSPORT = {
    967: {
        "method": "official_uci_static_csv",
        "url": "https://archive.ics.uci.edu/static/public/967/data.csv",
        "target_column": "label",
        "metadata_snapshot_relative_path": (
            "22_CACL_VPC_UCI_BINARY_VERIFIED_BATCH/registry_snapshot/"
            "metadata/uci_967.json"
        ),
        "metadata_snapshot_sha256": (
            "43c189d8f547752c515b2612fda2a9c3f9578f7f3660c8490d"
            "18767d88fe68a9"
        ),
        "redirect_policy": REDIRECT_POLICY,
        "maximum_csv_bytes": 512 * 1024 * 1024,
    },
}


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


def verify_frozen_registration_config() -> None:
    config = read_json(ROOT / "config" / "r4_5_contract.json")
    if config.get("source_target_group_split") != [0.65, 0.35]:
        raise RuntimeError("source-target group split config mismatch")
    locked = config.get("new_data_registration", {})
    for dataset_id, expected in NEW_DATASETS.items():
        if locked.get(str(dataset_id)) != {
            key: expected[key]
            for key in (
                "raw_rows",
                "raw_features",
                "primary_features",
                "registered_row_cap",
                "group_rule",
                "raw_feature_name_sha256",
                "primary_feature_name_sha256",
            )
        }:
            raise RuntimeError(
                f"UCI {dataset_id}: code/config registration mismatch"
            )
    if config.get("transport") != {
        str(dataset_id): TRANSPORT[dataset_id]
        for dataset_id in NEW_DATASETS
    }:
        raise RuntimeError("code/config transport registration mismatch")
    if config.get("target_transforms") != {
        "967": (
            "pre_instance_fixed_numeric_positive_to_1_nonpositive_to_0"
        ),
    }:
        raise RuntimeError("code/config target transform mismatch")


def require_stage_a_data_access_authorized() -> dict[str, Any]:
    """Fail closed at every transport entry point, not only in ``main``."""

    validation = validate_stage_a_ack_and_lock()
    verification = read_json(
        ROOT / "receipts" / "R4_5_STAGE_A_TIMESTAMP_VERIFICATION.json"
    )
    exact = (
        verification.get("schema")
        == "cacl-oc-r4.5-stage-a-verification-v1"
        and verification.get("status")
        == "R4_5_STAGE_A_DATA_ACCESS_AUTHORIZED"
        and verification.get("lock_sha256")
        == validation["lock_sha256"]
        and verification.get("ack_sha256")
        == validation["ack_sha256"]
        and verification.get("public_commit_sha")
        == validation["public_commit_sha"]
        and verification.get("all_locked_files_current") is True
        and verification.get("new_data_access_permitted_after_receipt")
        is True
    )
    if not exact:
        raise RuntimeError(
            "Stage-A verification is absent or inconsistent"
        )
    return validation


def write_npz_once(path: Path, **arrays: np.ndarray) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        np.savez_compressed(handle, **arrays)


def write_bytes_once(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(payload)


def name_list_sha256(names: list[str]) -> str:
    payload = json.dumps(
        names, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def exact_signature_groups(x: np.ndarray) -> np.ndarray:
    values = np.ascontiguousarray(np.asarray(x, dtype="<f8"))
    return np.asarray(
        [
            hashlib.sha256(
                b"CACL-OC-R4.2-EXACT-FEATURE-GROUP-v1|" + row.tobytes()
            ).hexdigest()
            for row in values
        ]
    )


def normalized_domain_groups(domain: pd.Series) -> np.ndarray:
    if bool(domain.isna().any()):
        raise RuntimeError("UCI 967: missing normalized Domain group")
    normalized = domain.astype(str).str.strip().str.lower()
    if bool((normalized == "").any()):
        raise RuntimeError("UCI 967: empty normalized Domain group")
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


def fixed_numeric_sign_binary_target(
    labels: pd.Series,
) -> tuple[np.ndarray, dict[str, Any]]:
    """Apply a pre-instance fixed sign rule without fitting a vocabulary."""

    numeric = pd.to_numeric(labels, errors="raise").to_numpy(dtype=float)
    if not bool(np.isfinite(numeric).all()):
        raise RuntimeError("numeric target contains a non-finite value")
    unique = np.unique(numeric)
    if (
        len(unique) != 2
        or int(np.sum(unique > 0)) != 1
        or int(np.sum(unique <= 0)) != 1
    ):
        raise RuntimeError(
            "fixed numeric-sign target is not a two-value binary target"
        )
    result = (numeric > 0).astype(int)
    if set(result.tolist()) != {0, 1}:
        raise RuntimeError(
            "fixed numeric-sign target did not produce two classes"
        )
    return result, {
        "rule": "positive_numeric_value_to_1_nonpositive_to_0",
        "mapping_fit_scope": "none_pre_instance_fixed_rule",
        "observed_target_values_disclosed": False,
    }


def group_digest(group: str, dataset_id: int, salt: str) -> str:
    return hashlib.sha256(
        f"{salt}|{dataset_id}|{group}".encode("utf-8")
    ).hexdigest()


def group_complete_registration(
    group_ids: np.ndarray, dataset_id: int, cap: int
) -> np.ndarray:
    if len(group_ids) <= cap:
        return np.arange(len(group_ids), dtype=int)
    row_lists: dict[str, list[int]] = {}
    for index, group in enumerate(group_ids.astype(str)):
        row_lists.setdefault(group, []).append(index)
    unique_groups = sorted(
        row_lists,
        key=lambda group: (
            group_digest(group, dataset_id, SELECTION_SALT),
            group,
        ),
    )
    rows_by_group = {
        group: np.asarray(row_lists[group], dtype=int)
        for group in unique_groups
    }
    selected: list[np.ndarray] = []
    total = 0
    for group in unique_groups:
        rows = rows_by_group[group]
        if total + len(rows) <= cap:
            selected.append(rows)
            total += len(rows)
    if not selected:
        raise RuntimeError(
            f"UCI {dataset_id}: no complete group fits registration cap"
        )
    return np.sort(np.concatenate(selected)).astype(int)


def group_disjoint_source_target(
    registered_index: np.ndarray,
    group_ids: np.ndarray,
    dataset_id: int,
) -> tuple[np.ndarray, np.ndarray]:
    registered_groups = group_ids[registered_index]
    source_groups = {
        group
        for group in set(map(str, registered_groups))
        if int(
            group_digest(group, dataset_id, SOURCE_TARGET_SALT)[:16],
            16,
        )
        / float(2**64)
        < 0.65
    }
    source_mask = np.asarray(
        [str(group) in source_groups for group in registered_groups]
    )
    source = registered_index[source_mask]
    target = registered_index[~source_mask]
    if not len(source) or not len(target):
        raise RuntimeError(
            f"UCI {dataset_id}: group split produced an empty side"
        )
    return source, target


def fetch_registered_dataset(dataset_id: int) -> tuple[
    pd.DataFrame, pd.DataFrame, str, dict[str, Any], bytes
]:
    """Read exactly the public CSV registered in a locked metadata snapshot."""

    require_stage_a_data_access_authorized()
    transport = TRANSPORT[dataset_id]
    metadata_path = (
        PACKAGE / transport["metadata_snapshot_relative_path"]
    )
    if sha256(metadata_path) != transport["metadata_snapshot_sha256"]:
        raise RuntimeError(
            f"UCI {dataset_id}: metadata snapshot hash changed"
        )
    envelope = read_json(metadata_path)
    metadata = envelope.get("data", {})
    if (
        envelope.get("status") != 200
        or metadata.get("uci_id") != dataset_id
        or metadata.get("name") != NEW_DATASETS[dataset_id]["name"]
        or metadata.get("num_instances")
        != NEW_DATASETS[dataset_id]["raw_rows"]
        or metadata.get("num_features")
        != NEW_DATASETS[dataset_id]["raw_features"]
        or metadata.get("data_url") != transport["url"]
    ):
        raise RuntimeError(
            f"UCI {dataset_id}: locked metadata content changed"
        )
    variables = metadata.get("variables")
    if not isinstance(variables, list):
        raise RuntimeError(f"UCI {dataset_id}: variable metadata absent")
    feature_names = [
        str(row["name"]) for row in variables if row.get("role") == "Feature"
    ]
    target_names = [
        str(row["name"]) for row in variables if row.get("role") == "Target"
    ]
    all_names = [str(row["name"]) for row in variables]
    if (
        len(feature_names) != NEW_DATASETS[dataset_id]["raw_features"]
        or target_names != [transport["target_column"]]
        or len(all_names) != len(set(all_names))
    ):
        raise RuntimeError(
            f"UCI {dataset_id}: locked variable roles changed"
        )
    request = Request(
        transport["url"],
        headers={"User-Agent": "CACL-OC-R4.5/1.0"},
    )
    with urlopen(request, timeout=180) as response:
        final_url = str(response.geturl())
        requested = urlparse(transport["url"])
        resolved = urlparse(final_url)
        allowed_final_url = (
            resolved.scheme == "https"
            and resolved.netloc.lower() == requested.netloc.lower()
            and unquote(resolved.path) == unquote(requested.path)
            and not resolved.params
            and not resolved.query
            and not resolved.fragment
        )
        if not allowed_final_url:
            raise RuntimeError(
                f"UCI {dataset_id}: redirect left locked URL identity"
            )
        content_length = response.headers.get("Content-Length")
        maximum = int(transport["maximum_csv_bytes"])
        if content_length is not None and int(content_length) > maximum:
            raise RuntimeError(
                f"UCI {dataset_id}: CSV exceeds locked byte cap"
            )
        csv_bytes = response.read(maximum + 1)
    if len(csv_bytes) > maximum:
        raise RuntimeError(
            f"UCI {dataset_id}: CSV exceeds locked byte cap"
        )
    frame = pd.read_csv(BytesIO(csv_bytes))
    if (
        len(frame.columns) != len(set(frame.columns))
        or set(frame.columns) != set(all_names)
    ):
        raise RuntimeError(
            f"UCI {dataset_id}: full CSV schema changed"
        )
    x_frame = frame[feature_names]
    y_frame = frame[target_names]
    acquisition = {
        "method": "official_uci_static_csv",
        "uci_id": dataset_id,
        "url": transport["url"],
        "final_url": final_url,
        "metadata_snapshot_relative_path": transport[
            "metadata_snapshot_relative_path"
        ],
        "metadata_snapshot_sha256": transport[
            "metadata_snapshot_sha256"
        ],
        "csv_bytes": len(csv_bytes),
        "csv_sha256": hashlib.sha256(csv_bytes).hexdigest(),
    }
    return x_frame, y_frame, str(metadata["name"]), acquisition, csv_bytes


def build_prepared(dataset_id: int) -> dict[str, Any]:
    expected = NEW_DATASETS[dataset_id]

    x_frame, y_frame, observed_name, acquisition, csv_bytes = (
        fetch_registered_dataset(dataset_id)
    )
    observed_feature_names = [str(column) for column in x_frame.columns]
    if (
        name_list_sha256(observed_feature_names)
        != expected["raw_feature_name_sha256"]
    ):
        raise RuntimeError(
            f"UCI {dataset_id}: ordered feature schema changed"
        )
    if dataset_id == 967:
        if (
            set(observed_feature_names)
            != set(PRIMARY_967) | set(EXCLUDED_967)
        ):
            raise RuntimeError("UCI 967: locked feature partition changed")
        primary_names = PRIMARY_967
        group_ids = normalized_domain_groups(x_frame["Domain"])
    else:
        primary_names = observed_feature_names
        group_ids = np.asarray([], dtype=str)
    if name_list_sha256(primary_names) != expected[
        "primary_feature_name_sha256"
    ]:
        raise RuntimeError(
            f"UCI {dataset_id}: primary feature schema changed"
        )
    x_numeric = x_frame[primary_names].apply(
        pd.to_numeric, errors="raise"
    )
    if y_frame.shape[1] != 1:
        raise RuntimeError(f"UCI {dataset_id}: target columns changed")
    if bool(y_frame.isna().any().any()):
        raise RuntimeError(f"UCI {dataset_id}: target contains missing values")
    raw_labels = y_frame.iloc[:, 0]
    labels = raw_labels.astype(str)
    y, mapping = fixed_numeric_sign_binary_target(raw_labels)
    raw_label_array = labels.to_numpy(dtype=str)
    x = x_numeric.to_numpy(dtype=float)
    if x_frame.shape != (
        expected["raw_rows"],
        expected["raw_features"],
    ):
        raise RuntimeError(
            f"UCI {dataset_id}: raw shape changed: {x_frame.shape}"
        )
    if x.shape != (
        expected["raw_rows"],
        expected["primary_features"],
    ):
        raise RuntimeError(
            f"UCI {dataset_id}: numeric shape changed: {x.shape}"
        )
    if float(np.isnan(x).mean()) > 0.20:
        raise RuntimeError(f"UCI {dataset_id}: missingness exceeds 0.20")
    if np.any(np.all(np.isnan(x), axis=0)):
        raise RuntimeError(f"UCI {dataset_id}: all-missing feature")
    if bool(np.isinf(x).any()):
        raise RuntimeError(f"UCI {dataset_id}: infinite predictor value")
    if dataset_id != 967:
        group_ids = exact_signature_groups(x)

    registered_index = group_complete_registration(
        group_ids,
        dataset_id,
        int(expected["registered_row_cap"]),
    )
    source_index, target_index = group_disjoint_source_target(
        registered_index, group_ids, dataset_id
    )
    source_groups = group_ids[source_index]
    target_groups = group_ids[target_index]
    overlap = set(map(str, source_groups)) & set(map(str, target_groups))
    if overlap:
        raise RuntimeError(
            f"UCI {dataset_id}: source-target group overlap"
        )
    receipt = {
        "schema": "cacl-oc-r4.5-new-data-preparation-v1",
        "status": "R4_5_NEW_DATASET_PREPARED",
        "uci_id": dataset_id,
        "registered_name": expected["name"],
        "observed_name": observed_name,
        "acquisition": acquisition,
        "raw_rows": len(x),
        "registered_rows": len(registered_index),
        "registered_row_cap": expected["registered_row_cap"],
        "predictors": x.shape[1],
        "ordered_raw_feature_name_sha256": name_list_sha256(
            observed_feature_names
        ),
        "ordered_primary_feature_name_sha256": name_list_sha256(
            primary_names
        ),
        "excluded_feature_columns": (
            EXCLUDED_967
            if dataset_id == 967
            else []
        ),
        "target_transform": (
            "pre-instance fixed numeric positive-to-1, "
            "nonpositive-to-0 mapping"
        ),
        "target_transform_fit_scope": "none_pre_instance_fixed_rule",
        "target_transform_registration": None,
        "group_rule": expected["group_rule"],
        "registered_groups": len(set(map(str, group_ids[registered_index]))),
        "source_groups": len(set(map(str, source_groups))),
        "target_groups": len(set(map(str, target_groups))),
        "source_target_group_overlap": 0,
        "missing_fraction": float(np.isnan(x).mean()),
        "target_cardinality": 2,
        "target_mapping": mapping,
        "source_units": len(source_index),
        "target_units": len(target_index),
        "source_fraction": float(
            len(source_index) / len(registered_index)
        ),
        "target_summary_emitted": False,
        "raw_instance_csv_preserved_for_post_reveal_audit": True,
        "model_fitted": False,
    }
    return {
        "receipt": receipt,
        "raw_csv_bytes": csv_bytes,
        "arrays": {
            "source.npz": {
                "x": x[source_index],
                "y": y[source_index],
                "raw_labels": raw_label_array[source_index],
                "row_ids": source_index,
                "group_ids": source_groups,
            },
            "target_features.npz": {
                "x": x[target_index],
                "row_ids": target_index,
                "group_ids": target_groups,
            },
            "target_outcomes.npz": {
                "y": y[target_index],
                "raw_labels": raw_label_array[target_index],
                "row_ids": target_index,
                "group_ids": target_groups,
            },
        },
    }


def persist_prepared(plan: dict[str, Any]) -> dict[str, Any]:
    receipt = plan["receipt"]
    dataset_id = int(receipt["uci_id"])
    output = ROOT / "prepared_census" / f"uci_{dataset_id}"
    if output.exists():
        raise FileExistsError(
            f"write-once prepared dataset path exists: {output}"
        )
    output.mkdir(parents=True, exist_ok=False)
    write_bytes_once(output / "raw_official.csv", plan["raw_csv_bytes"])
    for name, arrays in plan["arrays"].items():
        write_npz_once(output / name, **arrays)
    receipt["artifacts"] = {
        name: {
            "bytes": (output / name).stat().st_size,
            "sha256": sha256(output / name),
        }
        for name in ["raw_official.csv", *plan["arrays"]]
    }
    exclusive_write_json(
        output / "PREPARATION_RECEIPT.json", native(receipt)
    )
    return receipt


def main() -> None:
    require_stage_a_data_access_authorized()
    verify_frozen_registration_config()
    output = ROOT / "receipts" / "R4_5_NEW_DATA_PREPARATION.json"
    if output.exists():
        raise FileExistsError(
            f"write-once preparation receipt exists: {output}"
        )
    existing_paths = [
        ROOT / "prepared_census" / f"uci_{dataset_id}"
        for dataset_id in NEW_DATASETS
        if (
            ROOT / "prepared_census" / f"uci_{dataset_id}"
        ).exists()
    ]
    if existing_paths:
        raise FileExistsError(
            "write-once prepared paths already exist: "
            + ", ".join(map(str, existing_paths))
        )
    plans = [
        build_prepared(dataset_id) for dataset_id in NEW_DATASETS
    ]
    rows = [persist_prepared(plan) for plan in plans]
    batch = {
        "schema": "cacl-oc-r4.5-new-data-preparation-batch-v1",
        "status": "R4_5_NEW_DATA_PREPARATION_COMPLETE",
        "registered_ids": list(NEW_DATASETS),
        "datasets_replaced": False,
        "target_summaries_emitted": False,
        "model_fitted": False,
        "datasets": rows,
    }
    exclusive_write_json(output, native(batch))
    print(batch["status"])
    for row in rows:
        print(
            f"uci_{row['uci_id']}:n={row['registered_rows']},"
            f"p={row['predictors']},source={row['source_units']},"
            f"target={row['target_units']}"
        )


if __name__ == "__main__":
    main()
