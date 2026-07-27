#!/usr/bin/env python3
"""R2 UCI eligibility custodian and seeded selection."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
import random
import re
import ssl
import time
import urllib.request

import certifi
import pandas as pd
from ucimlrepo import fetch_ucirepo


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PACKAGE = ROOT.parent
BATCH1 = PACKAGE / "21_CACL_VPC_UCI_CLOSED_BATCH"
ORIGINAL_LEDGER = (
    PACKAGE
    / "19_CACL_REVIEWER_RESPONSE_ROUND3"
    / "closed_batch"
    / "EXISTING_DATASET_LEDGER.csv"
)
RECEIPTS = ROOT / "receipts"
SNAPSHOT = ROOT / "registry_snapshot"
METADATA_DIR = SNAPSHOT / "metadata"
LIST_URL = "https://archive.ics.uci.edu/api/datasets/list?filter=python"
DATASET_URL = "https://archive.ics.uci.edu/api/dataset?id={dataset_id}"
NUMERIC_TYPES = {"continuous", "integer", "real"}
DISALLOWED = {
    "image",
    "sequential",
    "text",
    "time-series",
    "time series",
    "graph",
}
SEED = 2302001
BATCH_SIZE = 4


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def normalize_title(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def fetch_json(url: str, attempts: int = 5) -> dict:
    context = ssl.create_default_context(cafile=certifi.where())
    error: Exception | None = None
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(
                url,
                context=context,
                timeout=60,
            ) as response:
                return json.load(response)
        except Exception as current:
            error = current
            time.sleep(0.5 * (attempt + 1))
    raise RuntimeError(f"failed to fetch {url}") from error


def excluded_ids() -> set[int]:
    result: set[int] = set()
    with ORIGINAL_LEDGER.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as handle:
        for row in csv.DictReader(handle):
            if row["registry"].strip().upper() == "UCI":
                result.add(int(row["registry_id"]))
    batch1 = json.loads(
        (BATCH1 / "receipts" / "BATCH1_FINAL_AUDIT.json").read_text(
            encoding="utf-8"
        )
    )
    result.update(int(row["uci_id"]) for row in batch1["datasets"])
    return result


def metadata_filter(
    data: dict,
    excluded: set[int],
    excluded_titles: set[str],
) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    dataset_id = int(data["uci_id"])
    if dataset_id in excluded:
        reasons.append("previously_touched_id")
    if normalize_title(str(data["name"])) in excluded_titles:
        reasons.append("previously_touched_title")
    rows = data.get("num_instances")
    if not isinstance(rows, int) or not (4000 <= rows <= 100000):
        reasons.append("metadata_rows_outside_4000_100000")
    tasks = {str(value).lower() for value in (data.get("tasks") or [])}
    if "classification" not in tasks:
        reasons.append("not_classification")
    characteristics = {
        str(value).lower()
        for value in (data.get("characteristics") or [])
    }
    if characteristics & DISALLOWED:
        reasons.append("disallowed_characteristic")
    if len(data.get("target_col") or []) != 1:
        reasons.append("target_column_count_not_one")
    feature_variables = [
        variable
        for variable in (data.get("variables") or [])
        if str(variable.get("role", "")).lower() == "feature"
    ]
    if not (20 <= len(feature_variables) <= 500):
        reasons.append("metadata_predictors_outside_20_500")
    if any(
        str(variable.get("type", "")).lower() not in NUMERIC_TYPES
        for variable in feature_variables
    ):
        reasons.append("metadata_non_numeric_predictor")
    if not data.get("repository_url") or not data.get("dataset_doi"):
        reasons.append("missing_repository_url_or_doi")
    return not reasons, reasons


def custodian_verify(dataset_id: int, name: str) -> dict:
    row = {
        "uci_id": dataset_id,
        "name": name,
        "fully_eligible": False,
        "actual_rows": None,
        "actual_predictors": None,
        "target_columns": None,
        "target_cardinality": None,
        "missing_fraction": None,
        "reasons": "",
    }
    reasons: list[str] = []
    try:
        dataset = fetch_ucirepo(id=dataset_id)
        features = dataset.data.features
        targets = dataset.data.targets
        if not isinstance(features, pd.DataFrame):
            features = pd.DataFrame(features)
        if not isinstance(targets, pd.DataFrame):
            targets = pd.DataFrame(targets)
        numeric = features.apply(pd.to_numeric, errors="coerce")
        introduced = int(
            numeric.isna().sum().sum() - features.isna().sum().sum()
        )
        missing_fraction = float(numeric.isna().to_numpy().mean())
        target_columns = int(targets.shape[1])
        target_cardinality = (
            int(targets.iloc[:, 0].nunique(dropna=True))
            if target_columns == 1
            else None
        )
        target_missing = (
            int(targets.iloc[:, 0].isna().sum())
            if target_columns == 1
            else None
        )
        row.update(
            {
                "actual_rows": len(features),
                "actual_predictors": features.shape[1],
                "target_columns": target_columns,
                "target_cardinality": target_cardinality,
                "missing_fraction": missing_fraction,
            }
        )
        if not (4000 <= len(features) <= 100000):
            reasons.append("actual_rows_outside_4000_100000")
        if not (20 <= features.shape[1] <= 500):
            reasons.append("actual_predictors_outside_20_500")
        if introduced > 0:
            reasons.append("non_numeric_values_present")
        if missing_fraction > 0.20:
            reasons.append("missing_fraction_above_0_20")
        if target_columns != 1:
            reasons.append("target_column_count_not_one")
        if target_cardinality != 2:
            reasons.append("target_cardinality_not_two")
        if target_missing not in (0, None):
            reasons.append("target_missing_values")
    except Exception as error:
        reasons.append(f"download_or_parse:{error!r}")
    row["reasons"] = "|".join(reasons)
    row["fully_eligible"] = not reasons
    return row


def main() -> None:
    verification = json.loads(
        (RECEIPTS / "R2_EXTERNAL_TIMESTAMP_VERIFICATION.json").read_text(
            encoding="utf-8"
        )
    )
    if verification["status"] != "R2_PHASE2_AUTHORIZED":
        raise RuntimeError("R2 external timestamp is not authorized")
    SNAPSHOT.mkdir(parents=True, exist_ok=True)
    METADATA_DIR.mkdir(parents=True, exist_ok=True)
    registry = fetch_json(LIST_URL)
    list_path = SNAPSHOT / "UCI_PYTHON_REGISTRY_R2.json"
    list_path.write_text(
        json.dumps(registry, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    entries = sorted(registry["data"], key=lambda value: int(value["id"]))
    excluded = excluded_ids()
    excluded_titles = {
        normalize_title(str(entry["name"]))
        for entry in entries
        if int(entry["id"]) in excluded
    }

    metadata_rows: list[dict] = []
    provisional: list[tuple[int, str]] = []
    for entry in entries:
        dataset_id = int(entry["id"])
        try:
            response = fetch_json(
                DATASET_URL.format(dataset_id=dataset_id)
            )
            if response.get("status") != 200:
                raise RuntimeError("metadata status != 200")
            path = METADATA_DIR / f"uci_{dataset_id}.json"
            path.write_text(
                json.dumps(response, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            data = response["data"]
            eligible, reasons = metadata_filter(
                data,
                excluded,
                excluded_titles,
            )
            metadata_rows.append(
                {
                    "uci_id": dataset_id,
                    "name": data["name"],
                    "metadata_eligible": eligible,
                    "reasons": "|".join(reasons),
                }
            )
            if eligible:
                provisional.append((dataset_id, str(data["name"])))
        except Exception as error:
            metadata_rows.append(
                {
                    "uci_id": dataset_id,
                    "name": entry["name"],
                    "metadata_eligible": False,
                    "reasons": f"metadata_fetch:{error!r}",
                }
            )

    with (SNAPSHOT / "R2_METADATA_LEDGER.csv").open(
        "w",
        encoding="utf-8",
        newline="",
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=list(metadata_rows[0]))
        writer.writeheader()
        writer.writerows(metadata_rows)

    verified_rows = [
        custodian_verify(dataset_id, name)
        for dataset_id, name in provisional
    ]
    with (SNAPSHOT / "R2_BINARY_VERIFIED_ELIGIBILITY.csv").open(
        "w",
        encoding="utf-8",
        newline="",
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=list(verified_rows[0]))
        writer.writeheader()
        writer.writerows(verified_rows)
    pool = sorted(
        int(row["uci_id"])
        for row in verified_rows
        if row["fully_eligible"]
    )
    if len(pool) < BATCH_SIZE:
        selected: list[int] = []
        status = "R2_INSUFFICIENT_FULLY_VERIFIED_POOL"
    else:
        selected = random.Random(SEED).sample(pool, BATCH_SIZE)
        status = "R2_REGISTERED_BATCH_SELECTED"

    receipt = {
        "schema": "cacl-vpc-uci-r2-selection-v1",
        "status": status,
        "code_sha256": sha256(Path(__file__)),
        "registry_entries": len(entries),
        "excluded_ids": sorted(excluded),
        "metadata_provisional_count": len(provisional),
        "fully_verified_pool_size": len(pool),
        "fully_verified_pool_ids": pool,
        "selection_implementation": (
            "random.Random(2302001).sample(sorted(pool),4)"
        ),
        "selected_ids_in_draw_order": selected,
        "replacement_permitted": False,
        "eligibility_output_guard_respected": True,
        "artifacts": {
            "registry": sha256(list_path),
            "metadata_ledger": sha256(
                SNAPSHOT / "R2_METADATA_LEDGER.csv"
            ),
            "binary_verified_ledger": sha256(
                SNAPSHOT / "R2_BINARY_VERIFIED_ELIGIBILITY.csv"
            ),
        },
    }
    output = RECEIPTS / "R2_SELECTION_RECEIPT.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(receipt["status"])
    print(f"metadata_provisional={len(provisional)}")
    print(f"fully_verified_pool={len(pool)}")
    print(f"selected={selected}")
    if status != "R2_REGISTERED_BATCH_SELECTED":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
