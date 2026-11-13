import argparse
import json
from pathlib import Path
from urllib.parse import urlparse

import kagglehub
import pandas as pd

DATASET_REF = "bpali26/popular-websites-across-the-globe"
URL_COLUMN_NAMES = ("url", "website", "domain", "site", "link")


def read_csv_compat(path, **kwargs):
    try:
        return pd.read_csv(path, encoding="utf-8", **kwargs)
    except UnicodeDecodeError:
        return pd.read_csv(path, encoding="latin-1", **kwargs)


def find_source_file(download_path):
    candidates = sorted(Path(download_path).rglob("*.csv"))
    if not candidates:
        raise FileNotFoundError("The downloaded Kaggle dataset did not contain a CSV file.")

    for candidate in candidates:
        columns = {
            str(column).strip().lower().replace(" ", "_")
            for column in read_csv_compat(candidate, nrows=0).columns
        }
        if any(name in columns for name in URL_COLUMN_NAMES):
            return candidate
    raise ValueError("Could not find a URL or domain column in the downloaded dataset.")


def find_url_column(dataset):
    normalized_columns = {
        str(column).strip().lower().replace(" ", "_"): column
        for column in dataset.columns
    }
    for name in URL_COLUMN_NAMES:
        if name in normalized_columns:
            return normalized_columns[name]
    raise ValueError("Could not find a URL or domain column in the dataset.")


def normalize_domain(value):
    raw_value = str(value).strip()
    if not raw_value or raw_value.lower() == "nan":
        return None
    candidate = raw_value if "://" in raw_value else f"https://{raw_value}"
    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    return f"https://{parsed.hostname.lower()}/"


def import_safe_samples(dataset_path, output_path, manifest_path, max_rows):
    source = read_csv_compat(dataset_path)
    url_column = find_url_column(source)
    imported = pd.DataFrame(
        {
            "url": source[url_column].map(normalize_domain),
            "label": "safe",
        }
    ).dropna(subset=["url"])
    imported = imported.drop_duplicates(subset=["url"]).head(max_rows)

    existing = pd.read_csv(output_path) if Path(output_path).exists() else pd.DataFrame(
        columns=["url", "label"]
    )
    merged = pd.concat([existing[["url", "label"]], imported], ignore_index=True)
    merged["url"] = merged["url"].astype("string").str.strip()
    merged["label"] = merged["label"].astype("string").str.strip().str.lower()
    merged = merged.drop_duplicates(subset=["url"], keep="first").reset_index(drop=True)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    merged.to_csv(output_path, index=False)

    manifest = {
        "dataset_ref": DATASET_REF,
        "source_file": Path(dataset_path).name,
        "source_url_column": str(url_column),
        "imported_safe_rows": int(len(imported)),
        "total_rows": int(len(merged)),
        "max_rows": max_rows,
        "warning": "Imported rows are assumed safe because this source is a popular-websites list.",
    }
    Path(manifest_path).parent.mkdir(parents=True, exist_ok=True)
    Path(manifest_path).write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def main():
    parser = argparse.ArgumentParser(description="Import popular websites as safe ML samples.")
    parser.add_argument("--output", default="data/url_dataset.csv")
    parser.add_argument("--manifest", default="data/dataset_manifest.json")
    parser.add_argument("--max-rows", type=int, default=500)
    args = parser.parse_args()
    if args.max_rows < 1:
        raise ValueError("--max-rows must be at least 1.")

    download_path = kagglehub.dataset_download(DATASET_REF)
    source_file = find_source_file(download_path)
    manifest = import_safe_samples(
        source_file,
        args.output,
        args.manifest,
        args.max_rows,
    )
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
