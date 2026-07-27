#!/usr/bin/env python3
"""Prepare pre-instance-data UCI 855 and 967 without target summaries."""

from __future__ import annotations

import hashlib
import json
from io import BytesIO
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse
from urllib.request import Request, urlopen
from zipfile import BadZipFile, ZipFile

import numpy as np
import pandas as pd
from ucimlrepo import fetch_ucirepo

from integrity import (
    ROOT,
    exclusive_write_json,
    read_json,
    sha256,
    validate_stage_a_ack_and_lock,
)


NEW_DATASETS = {
    855: {
        "name": "TUANDROMD",
        "raw_rows": 4464,
        "raw_features": 241,
        "primary_features": 241,
        "registered_row_cap": 4464,
        "raw_feature_name_sha256": (
            "024ca7f02a42988fd35bb8154d10dd1e1315089cb0d77361bc"
            "da7b9164e0d4d8"
        ),
        "primary_feature_name_sha256": (
            "024ca7f02a42988fd35bb8154d10dd1e1315089cb0d77361bc"
            "da7b9164e0d4d8"
        ),
        "group_rule": "exact_primary_feature_signature",
    },
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
UCI_855_ARCHIVE_URL = (
    "https://archive.ics.uci.edu/static/public/855/"
    "tuandromd%2B%28tezpur%2Buniversity%2Bandroid%2Bmalware%2Bdataset%29.zip"
)
UCI_855_ARCHIVE_MEMBER = "TUANDROMD.csv"
UCI_855_TARGET_COLUMN = "Label"
UCI_855_MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
UCI_855_MAX_CSV_BYTES = 256 * 1024 * 1024


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
    config = read_json(ROOT / "config" / "r4_3_contract.json")
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
        "855": {
            "method": "official_uci_static_zip",
            "url": UCI_855_ARCHIVE_URL,
            "archive_member": UCI_855_ARCHIVE_MEMBER,
            "target_column": UCI_855_TARGET_COLUMN,
            "redirect_policy": (
                "https_same_origin_same_decoded_path_no_query_fragment"
            ),
            "maximum_archive_bytes": UCI_855_MAX_ARCHIVE_BYTES,
            "maximum_csv_bytes": UCI_855_MAX_CSV_BYTES,
        },
        "967": {
            "method": "ucimlrepo_0.0.7_official_api",
        },
    }:
        raise RuntimeError("code/config transport registration mismatch")


def require_stage_a_data_access_authorized() -> dict[str, Any]:
    """Fail closed at every transport entry point, not only in ``main``."""

    validation = validate_stage_a_ack_and_lock()
    verification = read_json(
        ROOT / "receipts" / "R4_3_STAGE_A_TIMESTAMP_VERIFICATION.json"
    )
    exact = (
        verification.get("schema")
        == "cacl-oc-r4.3-stage-a-verification-v1"
        and verification.get("status")
        == "R4_3_STAGE_A_DATA_ACCESS_AUTHORIZED"
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


def fetch_official_uci_855() -> tuple[
    pd.DataFrame, pd.DataFrame, str, dict[str, Any]
]:
    """Read the registered official archive without inspecting it pre-lock."""

    require_stage_a_data_access_authorized()
    request = Request(
        UCI_855_ARCHIVE_URL,
        headers={"User-Agent": "CACL-OC-R4.3/1.0"},
    )
    with urlopen(request, timeout=120) as response:
        final_url = str(response.geturl())
        requested = urlparse(UCI_855_ARCHIVE_URL)
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
                "UCI 855: redirect left the locked official URL identity"
            )
        content_length = response.headers.get("Content-Length")
        if (
            content_length is not None
            and int(content_length) > UCI_855_MAX_ARCHIVE_BYTES
        ):
            raise RuntimeError("UCI 855: archive exceeds locked byte cap")
        archive_bytes = response.read(UCI_855_MAX_ARCHIVE_BYTES + 1)
    if len(archive_bytes) > UCI_855_MAX_ARCHIVE_BYTES:
        raise RuntimeError("UCI 855: archive exceeds locked byte cap")
    try:
        with ZipFile(BytesIO(archive_bytes)) as archive:
            matches = [
                info
                for info in archive.infolist()
                if info.filename == UCI_855_ARCHIVE_MEMBER
                and not info.is_dir()
            ]
            if len(matches) != 1:
                raise RuntimeError(
                    "UCI 855: locked CSV member is absent or duplicated"
                )
            info = matches[0]
            if info.file_size > UCI_855_MAX_CSV_BYTES:
                raise RuntimeError("UCI 855: CSV exceeds locked byte cap")
            csv_bytes = archive.read(info)
    except BadZipFile as exc:
        raise RuntimeError("UCI 855: official payload is not a ZIP") from exc
    if len(csv_bytes) > UCI_855_MAX_CSV_BYTES:
        raise RuntimeError("UCI 855: CSV exceeds locked byte cap")
    frame = pd.read_csv(BytesIO(csv_bytes))
    if list(frame.columns).count(UCI_855_TARGET_COLUMN) != 1:
        raise RuntimeError("UCI 855: locked target column changed")
    if frame.shape[1] != NEW_DATASETS[855]["raw_features"] + 1:
        raise RuntimeError("UCI 855: total CSV column count changed")
    x_frame = frame.drop(columns=[UCI_855_TARGET_COLUMN])
    y_frame = frame[[UCI_855_TARGET_COLUMN]]
    acquisition = {
        "method": "official_uci_static_zip",
        "url": UCI_855_ARCHIVE_URL,
        "final_url": final_url,
        "archive_member": UCI_855_ARCHIVE_MEMBER,
        "target_column": UCI_855_TARGET_COLUMN,
        "archive_bytes": len(archive_bytes),
        "archive_sha256": hashlib.sha256(archive_bytes).hexdigest(),
        "csv_bytes": len(csv_bytes),
        "csv_sha256": hashlib.sha256(csv_bytes).hexdigest(),
    }
    return x_frame, y_frame, "TUANDROMD", acquisition


def fetch_registered_dataset(dataset_id: int) -> tuple[
    pd.DataFrame, pd.DataFrame, str, dict[str, Any]
]:
    require_stage_a_data_access_authorized()
    if dataset_id == 855:
        return fetch_official_uci_855()
    dataset = fetch_ucirepo(id=dataset_id)
    x_frame = dataset.data.features
    y_frame = dataset.data.targets
    if not isinstance(x_frame, pd.DataFrame):
        x_frame = pd.DataFrame(x_frame)
    if not isinstance(y_frame, pd.DataFrame):
        y_frame = pd.DataFrame(y_frame)
    observed_name = str(getattr(dataset.metadata, "name", dataset_id))
    acquisition = {
        "method": "ucimlrepo_0.0.7_official_api",
        "uci_id": dataset_id,
    }
    return x_frame, y_frame, observed_name, acquisition


def build_prepared(dataset_id: int) -> dict[str, Any]:
    expected = NEW_DATASETS[dataset_id]

    x_frame, y_frame, observed_name, acquisition = (
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
    labels = y_frame.iloc[:, 0].astype(str)
    unique = sorted(set(labels))
    if len(unique) != 2:
        raise RuntimeError(f"UCI {dataset_id}: target is not binary")
    mapping = {label: index for index, label in enumerate(unique)}
    y = np.asarray([mapping[label] for label in labels], dtype=int)
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
    if dataset_id == 855:
        finite_values = set(np.unique(x[~np.isnan(x)]).tolist())
        if not finite_values.issubset({0.0, 1.0}):
            raise RuntimeError(
                "UCI 855: a locked binary predictor left {0,1}"
            )
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
        "schema": "cacl-oc-r4.3-new-data-preparation-v1",
        "status": "R4_3_NEW_DATASET_PREPARED",
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
            EXCLUDED_967 if dataset_id == 967 else []
        ),
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
        "model_fitted": False,
    }
    return {
        "receipt": receipt,
        "arrays": {
            "source.npz": {
                "x": x[source_index],
                "y": y[source_index],
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
    for name, arrays in plan["arrays"].items():
        write_npz_once(output / name, **arrays)
    receipt["artifacts"] = {
        name: {
            "bytes": (output / name).stat().st_size,
            "sha256": sha256(output / name),
        }
        for name in plan["arrays"]
    }
    exclusive_write_json(
        output / "PREPARATION_RECEIPT.json", native(receipt)
    )
    return receipt


def main() -> None:
    require_stage_a_data_access_authorized()
    verify_frozen_registration_config()
    output = ROOT / "receipts" / "R4_3_NEW_DATA_PREPARATION.json"
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
        "schema": "cacl-oc-r4.3-new-data-preparation-batch-v1",
        "status": "R4_3_NEW_DATA_PREPARATION_COMPLETE",
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
