#!/usr/bin/env python3
"""Download and mechanically prepare the already registered UCI batch."""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from ucimlrepo import fetch_ucirepo


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
RECEIPTS = ROOT / "receipts"
PREPARED = ROOT / "registered_batch"
SOURCE_FRACTION = 0.65
SALT = "CACL-VPC-UCI-SOURCE-TARGET-v1"


def native(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): native(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [native(item) for item in value]
    if isinstance(value, np.ndarray):
        return native(value.tolist())
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


def metadata_to_dict(metadata: Any) -> dict[str, Any]:
    if hasattr(metadata, "__dict__"):
        return {
            key: metadata_to_dict(value)
            for key, value in vars(metadata).items()
            if not key.startswith("_")
        }
    if isinstance(metadata, dict):
        return {
            str(key): metadata_to_dict(value)
            for key, value in metadata.items()
        }
    if isinstance(metadata, (list, tuple)):
        return [metadata_to_dict(value) for value in metadata]
    if isinstance(metadata, (str, int, float, bool)) or metadata is None:
        return metadata
    return str(metadata)


def target_codes(values: pd.Series) -> tuple[np.ndarray, dict[str, int]]:
    labels = [str(value) for value in values.astype(str)]
    unique = sorted(set(labels))
    mapping = {label: index for index, label in enumerate(unique)}
    return np.asarray([mapping[label] for label in labels], dtype=int), mapping


def row_order(x: np.ndarray, dataset_id: int) -> np.ndarray:
    canonical = np.asarray(x, dtype="<f8")
    keys: list[tuple[str, int]] = []
    prefix = f"{SALT}|{dataset_id}|".encode()
    for index, row in enumerate(canonical):
        normalized = np.where(np.isnan(row), np.float64(np.nan), row)
        digest = hashlib.sha256(prefix + normalized.tobytes()).hexdigest()
        keys.append((digest, index))
    return np.asarray(
        [index for _, index in sorted(keys)],
        dtype=int,
    )


def prepare_one(dataset_id: int) -> dict[str, Any]:
    dataset_dir = PREPARED / f"uci_{dataset_id}"
    dataset_dir.mkdir(parents=True, exist_ok=True)
    result: dict[str, Any] = {
        "uci_id": dataset_id,
        "status": "EXTERNAL_FAIL",
        "replacement_permitted": False,
    }
    try:
        dataset = fetch_ucirepo(id=dataset_id)
        metadata = metadata_to_dict(dataset.metadata)
        write_json(dataset_dir / "FETCHED_METADATA.json", metadata)
        features = dataset.data.features
        targets = dataset.data.targets
        if not isinstance(features, pd.DataFrame):
            features = pd.DataFrame(features)
        if not isinstance(targets, pd.DataFrame):
            targets = pd.DataFrame(targets)
        reasons: list[str] = []
        if targets.shape[1] != 1:
            reasons.append(f"target_columns_{targets.shape[1]}")
        target_cardinality = (
            int(targets.iloc[:, 0].nunique(dropna=True))
            if targets.shape[1] == 1
            else None
        )
        if target_cardinality != 2:
            reasons.append(f"target_cardinality_{target_cardinality}")
        if len(features) < 4000:
            reasons.append(f"rows_{len(features)}")
        if not (32 <= features.shape[1] <= 500):
            reasons.append(f"predictors_{features.shape[1]}")
        numeric = features.apply(pd.to_numeric, errors="coerce")
        introduced_missing = int(
            numeric.isna().sum().sum() - features.isna().sum().sum()
        )
        if introduced_missing > 0:
            reasons.append("non_numeric_values_present")
        missing_fraction = float(numeric.isna().to_numpy().mean())
        if not math.isfinite(missing_fraction) or missing_fraction > 0.20:
            reasons.append(f"missing_fraction_{missing_fraction}")
        if reasons:
            result.update(
                {
                    "name": metadata.get("name"),
                    "failure_reasons": reasons,
                    "rows": len(features),
                    "predictors": features.shape[1],
                    "target_cardinality": target_cardinality,
                    "missing_fraction": missing_fraction,
                }
            )
            write_json(dataset_dir / "PREPARATION_RECEIPT.json", result)
            return result

        x = numeric.to_numpy(dtype=float)
        y, mapping = target_codes(targets.iloc[:, 0])
        order = row_order(x, dataset_id)
        source_n = int(math.floor(SOURCE_FRACTION * len(order)))
        source_index = order[:source_n]
        target_index = order[source_n:]
        np.savez_compressed(
            dataset_dir / "source.npz",
            x=x[source_index],
            y=y[source_index],
            row_ids=source_index,
        )
        np.savez_compressed(
            dataset_dir / "target_features.npz",
            x=x[target_index],
            row_ids=target_index,
        )
        np.savez_compressed(
            dataset_dir / "target_outcomes.npz",
            y=y[target_index],
            row_ids=target_index,
        )
        result.update(
            {
                "status": "PREPARED_SOURCE_TARGET_SEALED",
                "name": metadata.get("name"),
                "rows": len(x),
                "predictors": x.shape[1],
                "target_cardinality": 2,
                "target_mapping": mapping,
                "missing_fraction": missing_fraction,
                "source_units": len(source_index),
                "target_units": len(target_index),
                "license_basis": (
                    "UCI repository dataset page / donation policy CC BY 4.0"
                ),
                "artifacts": {
                    name: {
                        "bytes": (dataset_dir / name).stat().st_size,
                        "sha256": sha256(dataset_dir / name),
                    }
                    for name in (
                        "source.npz",
                        "target_features.npz",
                        "target_outcomes.npz",
                    )
                },
            }
        )
    except Exception as error:
        result["failure_reasons"] = [f"download_or_parse:{error!r}"]
    write_json(dataset_dir / "PREPARATION_RECEIPT.json", result)
    return result


def main() -> None:
    selection = json.loads(
        (RECEIPTS / "PHASE2_SELECTION_RECEIPT.json").read_text(
            encoding="utf-8"
        )
    )
    if selection["status"] != "REGISTERED_BATCH_SELECTED":
        raise RuntimeError("registered batch is not selected")
    PREPARED.mkdir(parents=True, exist_ok=True)
    rows = [
        prepare_one(int(dataset_id))
        for dataset_id in selection["selected_ids_in_draw_order"]
    ]
    summary = {
        "schema": "cacl-vpc-uci-registered-batch-preparation-v1",
        "status": "REGISTERED_BATCH_PREPARATION_COMPLETE",
        "preparation_code_sha256": sha256(Path(__file__)),
        "selection_receipt_sha256": sha256(
            RECEIPTS / "PHASE2_SELECTION_RECEIPT.json"
        ),
        "registered_denominator": len(rows),
        "prepared_count": sum(
            row["status"] == "PREPARED_SOURCE_TARGET_SEALED"
            for row in rows
        ),
        "external_fail_count": sum(
            row["status"] == "EXTERNAL_FAIL" for row in rows
        ),
        "datasets": rows,
    }
    write_json(RECEIPTS / "PHASE3_PREPARATION_RECEIPT.json", summary)
    print(summary["status"])
    print(f"prepared={summary['prepared_count']}")
    print(f"external_fail={summary['external_fail_count']}")
    for row in rows:
        print(
            f"uci_{row['uci_id']}={row['status']}:"
            f"{row.get('failure_reasons', [])}"
        )


if __name__ == "__main__":
    main()
