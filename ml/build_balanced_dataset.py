import argparse
import json
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import kagglehub
import pandas as pd

from ml.import_kaggle_dataset import find_source_file, read_csv_compat

POPULAR_DATASET = "bpali26/popular-websites-across-the-globe"
MALICIOUS_DATASET = "sid321axn/malicious-urls-dataset"
MALICIOUS_LABELS = {
    "benign": "safe",
    "phishing": "suspicious",
    "defacement": "dangerous",
    "malware": "dangerous",
}


def normalize_url(value):
    raw_value = str(value).strip()
    if not raw_value or raw_value.lower() == "nan":
        return None
    candidate = raw_value if "://" in raw_value else f"https://{raw_value}"
    try:
        parsed = urlparse(candidate)
        port = parsed.port
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    hostname = parsed.hostname.lower()
    netloc = hostname
    if port:
        netloc = f"{netloc}:{port}"
    return urlunparse((
        "https",
        netloc,
        parsed.path or "/",
        parsed.params,
        parsed.query,
        parsed.fragment,
    ))


def find_column(dataset, names):
    normalized = {
        str(column).strip().lower().replace(" ", "_"): column
        for column in dataset.columns
    }
    for name in names:
        if name in normalized:
            return normalized[name]
    raise ValueError(f"Could not find one of these columns: {', '.join(names)}")


def build_dataset(popular_path, malicious_path, output_path, manifest_path, rows_per_source):
    popular = read_csv_compat(popular_path)
    popular_url_column = find_column(popular, ("url", "website", "domain", "site", "link"))
    popular_rows = pd.DataFrame({
        "url": popular[popular_url_column].map(normalize_url),
        "label": "safe",
        "source": "popular-websites",
    }).dropna(subset=["url"]).drop_duplicates("url")

    malicious = read_csv_compat(malicious_path)
    malicious_url_column = find_column(malicious, ("url", "website", "domain", "site", "link"))
    malicious_type_column = find_column(malicious, ("type", "label", "class", "category"))
    malicious_rows = pd.DataFrame({
        "url": malicious[malicious_url_column].map(normalize_url),
        "source_label": malicious[malicious_type_column].astype("string").str.strip().str.lower(),
        "source": "malicious-urls",
    }).dropna(subset=["url"])
    malicious_rows["label"] = malicious_rows["source_label"].map(MALICIOUS_LABELS)
    malicious_rows = malicious_rows.dropna(subset=["label"]).drop_duplicates("url")

    if len(popular_rows) < rows_per_source or len(malicious_rows) < rows_per_source:
        raise ValueError(f"Each source must contain at least {rows_per_source} valid unique URLs.")

    popular_sample = popular_rows.sample(rows_per_source, random_state=42)
    malicious_sample = malicious_rows.sample(rows_per_source, random_state=42)
    combined = pd.concat(
        [
            popular_sample[["url", "label", "source"]],
            malicious_sample[["url", "label", "source"]],
        ],
        ignore_index=True,
    ).sample(frac=1, random_state=42).reset_index(drop=True)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    combined[["url", "label"]].to_csv(output_path, index=False)

    manifest = {
        "popular_dataset": POPULAR_DATASET,
        "malicious_dataset": MALICIOUS_DATASET,
        "rows_per_source": rows_per_source,
        "total_rows": len(combined),
        "source_counts": combined["source"].value_counts().to_dict(),
        "label_counts": combined["label"].value_counts().to_dict(),
        "malicious_label_mapping": MALICIOUS_LABELS,
    }
    Path(manifest_path).parent.mkdir(parents=True, exist_ok=True)
    Path(manifest_path).write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def main():
    parser = argparse.ArgumentParser(description="Build a balanced two-source URL dataset.")
    parser.add_argument("--output", default="data/url_dataset.csv")
    parser.add_argument("--manifest", default="data/dataset_manifest.json")
    parser.add_argument("--rows-per-source", type=int, default=150)
    args = parser.parse_args()
    if args.rows_per_source < 1:
        raise ValueError("--rows-per-source must be at least 1.")

    popular_path = find_source_file(kagglehub.dataset_download(POPULAR_DATASET))
    malicious_path = find_source_file(kagglehub.dataset_download(MALICIOUS_DATASET))
    print(json.dumps(build_dataset(
        popular_path,
        malicious_path,
        args.output,
        args.manifest,
        args.rows_per_source,
    ), indent=2))


if __name__ == "__main__":
    main()
