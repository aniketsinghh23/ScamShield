from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

LABELS = ("safe", "suspicious", "dangerous")
DATASET_VERSION = "url-baseline-v1"


def load_dataset(path):
    dataset = pd.read_csv(path)
    required_columns = {"url", "label"}
    if not required_columns.issubset(dataset.columns):
        raise ValueError("Dataset must contain url and label columns.")

    dataset = dataset.loc[:, ["url", "label"]].copy()
    dataset["url"] = dataset["url"].astype("string").str.strip()
    dataset["label"] = dataset["label"].astype("string").str.strip().str.lower()
    dataset = dataset[(dataset["url"].notna()) & (dataset["label"].notna())]
    dataset = dataset[(dataset["url"] != "") & (dataset["label"] != "")]

    invalid_labels = sorted(set(dataset["label"]) - set(LABELS))
    if invalid_labels:
        raise ValueError(f"Unsupported labels: {', '.join(invalid_labels)}")

    dataset = dataset.drop_duplicates(subset=["url", "label"]).reset_index(drop=True)
    if dataset["label"].nunique() < len(LABELS):
        raise ValueError("Dataset must contain safe, suspicious, and dangerous labels.")
    if dataset["label"].value_counts().min() < 2:
        raise ValueError("Each label must contain at least two rows.")
    return dataset


def build_pipeline():
    return Pipeline(
        [
            (
                "features",
                TfidfVectorizer(
                    analyzer="char",
                    lowercase=True,
                    ngram_range=(3, 5),
                    min_df=1,
                    sublinear_tf=True,
                ),
            ),
            (
                "classifier",
                LogisticRegression(
                    class_weight="balanced",
                    max_iter=1000,
                    random_state=42,
                ),
            ),
        ]
    )


def save_artifact(model, path, metrics):
    artifact = {
        "dataset_version": DATASET_VERSION,
        "feature_schema": {
            "analyzer": "char",
            "ngram_range": [3, 5],
            "lowercase": True,
        },
        "labels": list(LABELS),
        "metrics": metrics,
        "model": model,
    }
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, path)
    return artifact


def load_artifact(path):
    artifact = joblib.load(path)
    if not isinstance(artifact, dict) or not {"model", "labels", "dataset_version"}.issubset(artifact):
        raise ValueError("Unsupported URL model artifact.")
    if tuple(artifact["labels"]) != LABELS:
        raise ValueError("URL model artifact labels do not match the application.")
    return artifact
