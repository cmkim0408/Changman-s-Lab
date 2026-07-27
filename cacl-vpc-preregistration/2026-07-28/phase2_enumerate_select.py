#!/usr/bin/env python3
"""Enumerate the post-timestamp UCI registry and select the locked batch."""

from __future__ import annotations

import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
from pathlib import Path
import random
import re
import ssl
import time
import urllib.request

import certifi


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PACKAGE = ROOT.parent
LEDGER = (
    PACKAGE
    / "19_CACL_REVIEWER_RESPONSE_ROUND3"
    / "closed_batch"
    / "EXISTING_DATASET_LEDGER.csv"
)
RECEIPTS = ROOT / "receipts"
SNAPSHOT = ROOT / "registry_snapshot"
METADATA = SNAPSHOT / "metadata"
LIST_URL = "https://archive.ics.uci.edu/api/datasets/list?filter=python"
DATASET_URL = "https://archive.ics.uci.edu/api/dataset?id={dataset_id}"
SEED = 2301001
BATCH_SIZE = 4
NUMERIC_TYPES = {"continuous", "integer", "real"}
DISALLOWED_CHARACTERISTICS = {
    "image",
    "sequential",
    "text",
    "time-series",
    "time series",
    "graph",
}


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
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(
                url,
                context=context,
                timeout=60,
            ) as response:
                return json.load(response)
        except Exception as error:  # preserved as registry metadata failure
            last_error = error
            time.sleep(0.5 * (attempt + 1))
    raise RuntimeError(f"failed after {attempts} attempts: {url}") from last_error


def load_existing_ids() -> set[int]:
    result: set[int] = set()
    with LEDGER.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            if row["registry"].strip().upper() == "UCI":
                result.add(int(row["registry_id"]))
    return result


def preliminary_eligibility(
    data: dict,
    existing_ids: set[int],
    existing_titles: set[str],
) -> tuple[bool, list[str], int]:
    reasons: list[str] = []
    dataset_id = int(data["uci_id"])
    name = str(data["name"])
    if dataset_id in existing_ids:
        reasons.append("existing_registry_id")
    if normalize_title(name) in existing_titles:
        reasons.append("existing_normalized_title")
    rows = data.get("num_instances")
    if not isinstance(rows, int) or rows < 4000:
        reasons.append("rows_below_4000_or_missing")
    tasks = {str(item).lower() for item in (data.get("tasks") or [])}
    if "classification" not in tasks:
        reasons.append("not_registry_classification")
    characteristics = {
        str(item).lower() for item in (data.get("characteristics") or [])
    }
    if characteristics & DISALLOWED_CHARACTERISTICS:
        reasons.append("disallowed_characteristic")
    targets = data.get("target_col") or []
    if len(targets) != 1:
        reasons.append("target_column_count_not_one")
    variables = data.get("variables") or []
    feature_variables = [
        item
        for item in variables
        if str(item.get("role", "")).lower() == "feature"
    ]
    numeric_count = sum(
        str(item.get("type", "")).lower() in NUMERIC_TYPES
        for item in feature_variables
    )
    if not (32 <= numeric_count <= 500):
        reasons.append("numeric_predictor_count_outside_32_500")
    if numeric_count != len(feature_variables):
        reasons.append("non_numeric_predictor_present")
    if not data.get("repository_url") or not data.get("data_url"):
        reasons.append("missing_repository_or_data_url")
    if not data.get("dataset_doi"):
        reasons.append("missing_dataset_doi")
    return not reasons, reasons, numeric_count


def main() -> None:
    verification = json.loads(
        (RECEIPTS / "EXTERNAL_TIMESTAMP_VERIFICATION.json").read_text(
            encoding="utf-8"
        )
    )
    if verification["status"] != "PHASE2_LOCALLY_AUTHORIZED":
        raise RuntimeError("external timestamp is not authorized")

    SNAPSHOT.mkdir(parents=True, exist_ok=True)
    METADATA.mkdir(parents=True, exist_ok=True)
    registry = fetch_json(LIST_URL)
    if registry.get("status") != 200:
        raise RuntimeError("UCI registry list did not return status 200")
    list_path = SNAPSHOT / "UCI_PYTHON_REGISTRY.json"
    list_path.write_text(
        json.dumps(registry, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    entries = sorted(registry["data"], key=lambda item: int(item["id"]))

    metadata_results: dict[int, dict] = {}
    metadata_errors: dict[int, str] = {}

    def retrieve(entry: dict) -> tuple[int, dict]:
        dataset_id = int(entry["id"])
        response = fetch_json(DATASET_URL.format(dataset_id=dataset_id))
        if response.get("status") != 200:
            raise RuntimeError(f"metadata status != 200 for {dataset_id}")
        return dataset_id, response

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(retrieve, entry): entry for entry in entries}
        for future in as_completed(futures):
            entry = futures[future]
            dataset_id = int(entry["id"])
            try:
                returned_id, response = future.result()
                metadata_results[returned_id] = response
                (METADATA / f"uci_{returned_id}.json").write_text(
                    json.dumps(response, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
            except Exception as error:
                metadata_errors[dataset_id] = repr(error)

    existing_ids = load_existing_ids()
    existing_titles = {
        normalize_title(str(entry["name"]))
        for entry in entries
        if int(entry["id"]) in existing_ids
    }
    rows: list[dict] = []
    pool: list[int] = []
    for entry in entries:
        dataset_id = int(entry["id"])
        if dataset_id in metadata_errors:
            rows.append(
                {
                    "uci_id": dataset_id,
                    "name": entry["name"],
                    "preliminary_eligible": False,
                    "numeric_predictors": None,
                    "reasons": "metadata_fetch_failed",
                }
            )
            continue
        data = metadata_results[dataset_id]["data"]
        eligible, reasons, numeric_count = preliminary_eligibility(
            data,
            existing_ids,
            existing_titles,
        )
        rows.append(
            {
                "uci_id": dataset_id,
                "name": data["name"],
                "preliminary_eligible": eligible,
                "numeric_predictors": numeric_count,
                "reasons": "|".join(reasons),
            }
        )
        if eligible:
            pool.append(dataset_id)

    ledger_path = SNAPSHOT / "PRELIMINARY_ELIGIBILITY_LEDGER.csv"
    with ledger_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    if len(pool) < BATCH_SIZE:
        selected: list[int] = []
        status = "INSUFFICIENT_PRELIMINARY_POOL"
    else:
        selected = random.Random(SEED).sample(sorted(pool), BATCH_SIZE)
        status = "REGISTERED_BATCH_SELECTED"

    receipt = {
        "schema": "cacl-vpc-uci-phase2-selection-v1",
        "status": status,
        "external_timestamp_verification_sha256": sha256(
            RECEIPTS / "EXTERNAL_TIMESTAMP_VERIFICATION.json"
        ),
        "enumeration_code_sha256": sha256(Path(__file__)),
        "registry_url": LIST_URL,
        "registry_entries": len(entries),
        "metadata_successes": len(metadata_results),
        "metadata_failures": len(metadata_errors),
        "existing_uci_ids": sorted(existing_ids),
        "preliminary_pool_size": len(pool),
        "preliminary_pool_ids": sorted(pool),
        "selection_implementation": "random.Random(2301001).sample(sorted(pool),4)",
        "selected_ids_in_draw_order": selected,
        "replacement_permitted": False,
        "post_download_incompatibilities": (
            "retained as EXTERNAL_FAIL in the four-dataset denominator"
        ),
        "artifacts": {
            "registry_snapshot_sha256": sha256(list_path),
            "eligibility_ledger_sha256": sha256(ledger_path),
        },
        "metadata_errors": metadata_errors,
    }
    receipt_path = RECEIPTS / "PHASE2_SELECTION_RECEIPT.json"
    receipt_path.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(receipt["status"])
    print(f"registry_entries={receipt['registry_entries']}")
    print(f"preliminary_pool_size={receipt['preliminary_pool_size']}")
    print(f"selected_ids={receipt['selected_ids_in_draw_order']}")
    if status != "REGISTERED_BATCH_SELECTED":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
