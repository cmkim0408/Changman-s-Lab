#!/usr/bin/env python3
"""Prepare the three pre-registered R3 census tasks."""

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
DATA_ROOT = ROOT / "registered_census"
REGISTERED_IDS = (75, 327, 572)
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


def order_rows(x: np.ndarray, dataset_id: int) -> np.ndarray:
    values = np.asarray(x, dtype="<f8")
    prefix = f"{SALT}|{dataset_id}|".encode()
    keys = [
        (
            hashlib.sha256(prefix + row.tobytes()).hexdigest(),
            index,
        )
        for index, row in enumerate(values)
    ]
    return np.asarray([index for _, index in sorted(keys)], dtype=int)


def prepare(dataset_id: int) -> dict[str, Any]:
    dataset = fetch_ucirepo(id=dataset_id)
    x_frame = dataset.data.features
    y_frame = dataset.data.targets
    if not isinstance(x_frame, pd.DataFrame):
        x_frame = pd.DataFrame(x_frame)
    if not isinstance(y_frame, pd.DataFrame):
        y_frame = pd.DataFrame(y_frame)
    x_numeric = x_frame.apply(pd.to_numeric, errors="coerce")
    if y_frame.shape[1] != 1:
        raise RuntimeError(f"UCI {dataset_id}: target columns changed")
    labels = y_frame.iloc[:, 0].astype(str)
    unique = sorted(set(labels))
    if len(unique) != 2:
        raise RuntimeError(f"UCI {dataset_id}: target cardinality changed")
    mapping = {label: index for index, label in enumerate(unique)}
    y = np.asarray([mapping[label] for label in labels], dtype=int)
    x = x_numeric.to_numpy(dtype=float)
    missing_fraction = float(np.isnan(x).mean())
    if not (4000 <= len(x) <= 100000):
        raise RuntimeError(f"UCI {dataset_id}: row rule changed")
    if not (20 <= x.shape[1] <= 500):
        raise RuntimeError(f"UCI {dataset_id}: predictor rule changed")
    if missing_fraction > 0.20:
        raise RuntimeError(f"UCI {dataset_id}: missing rule changed")
    order = order_rows(x, dataset_id)
    source_n = int(math.floor(0.65 * len(order)))
    source_index = order[:source_n]
    target_index = order[source_n:]
    dataset_root = DATA_ROOT / f"uci_{dataset_id}"
    dataset_root.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(
        dataset_root / "source.npz",
        x=x[source_index],
        y=y[source_index],
        row_ids=source_index,
    )
    np.savez_compressed(
        dataset_root / "target_features.npz",
        x=x[target_index],
        row_ids=target_index,
    )
    np.savez_compressed(
        dataset_root / "target_outcomes.npz",
        y=y[target_index],
        row_ids=target_index,
    )
    receipt = {
        "uci_id": dataset_id,
        "name": str(getattr(dataset.metadata, "name", dataset_id)),
        "status": "R3_SOURCE_TARGET_PREPARED",
        "rows": len(x),
        "predictors": x.shape[1],
        "missing_fraction": missing_fraction,
        "target_cardinality": 2,
        "target_mapping": mapping,
        "source_units": len(source_index),
        "target_units": len(target_index),
        "artifacts": {
            name: {
                "bytes": (dataset_root / name).stat().st_size,
                "sha256": sha256(dataset_root / name),
            }
            for name in (
                "source.npz",
                "target_features.npz",
                "target_outcomes.npz",
            )
        },
    }
    write_json(dataset_root / "PREPARATION_RECEIPT.json", receipt)
    return receipt


def main() -> None:
    verification = json.loads(
        (RECEIPTS / "R3_EXTERNAL_TIMESTAMP_VERIFICATION.json").read_text(
            encoding="utf-8"
        )
    )
    if verification["status"] != "R3_EXECUTION_AUTHORIZED":
        raise RuntimeError("R3 timestamp is not authorized")
    rows = [prepare(dataset_id) for dataset_id in REGISTERED_IDS]
    receipt = {
        "schema": "cacl-vpc-uci-r3-preparation-v1",
        "status": "R3_CENSUS_PREPARATION_COMPLETE",
        "registered_ids": list(REGISTERED_IDS),
        "datasets_replaced": False,
        "code_sha256": sha256(Path(__file__)),
        "datasets": rows,
    }
    write_json(RECEIPTS / "R3_PREPARATION_RECEIPT.json", receipt)
    print(receipt["status"])
    for row in rows:
        print(
            f"uci_{row['uci_id']}:n={row['rows']},p={row['predictors']},"
            f"source={row['source_units']},target={row['target_units']}"
        )


if __name__ == "__main__":
    main()
