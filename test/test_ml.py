import pandas as pd

from ml.build_balanced_dataset import build_dataset
from ml.import_kaggle_dataset import import_safe_samples
from ml.train_model import train
from ml.url_model import DATASET_VERSION, load_artifact, load_dataset


def test_dataset_has_expected_schema_and_labels():
    dataset = load_dataset("data/url_dataset.csv")

    assert set(dataset.columns) == {"url", "label"}
    assert set(dataset["label"]) == {"safe", "suspicious", "dangerous"}
    assert len(dataset) >= 20


def test_training_writes_valid_versioned_artifact(tmp_path):
    model_path = tmp_path / "url_model.joblib"

    metrics = train("data/url_dataset.csv", model_path)
    artifact = load_artifact(model_path)

    assert artifact["dataset_version"] == DATASET_VERSION
    assert metrics["rows"] == len(load_dataset("data/url_dataset.csv"))
    assert 0 <= metrics["precision_macro"] <= 1
    assert 0 <= metrics["recall_macro"] <= 1
    assert len(artifact["labels"]) == 3


def test_kaggle_import_labels_only_new_rows_as_safe(tmp_path):
    source_path = tmp_path / "websites.csv"
    output_path = tmp_path / "url_dataset.csv"
    manifest_path = tmp_path / "manifest.json"
    pd.DataFrame({"Website": ["Example.COM", "safe.example"]}).to_csv(
        source_path,
        index=False,
        encoding="latin-1",
    )
    pd.DataFrame(
        {
            "url": ["https://danger.example/verify"],
            "label": ["dangerous"],
        }
    ).to_csv(output_path, index=False)

    manifest = import_safe_samples(
        source_path,
        output_path,
        manifest_path,
        max_rows=10,
    )
    merged = pd.read_csv(output_path)

    assert manifest["imported_safe_rows"] == 2
    assert "dangerous" in set(merged["label"])
    assert set(merged["url"]) == {
        "https://danger.example/verify",
        "https://example.com/",
        "https://safe.example/",
    }


def test_balanced_builder_takes_exact_rows_and_maps_labels(tmp_path):
    popular_path = tmp_path / "popular.csv"
    malicious_path = tmp_path / "malicious.csv"
    output_path = tmp_path / "combined.csv"
    manifest_path = tmp_path / "manifest.json"
    pd.DataFrame({"Website": ["safe-one.example", "safe-two.example", "safe-three.example"]}).to_csv(
        popular_path,
        index=False,
    )
    pd.DataFrame(
        {
            "url": [
                "phish.example/login",
                "malware.example/drop",
                "benign.example/",
            ],
            "type": ["phishing", "malware", "benign"],
        }
    ).to_csv(malicious_path, index=False)

    manifest = build_dataset(
        popular_path,
        malicious_path,
        output_path,
        manifest_path,
        rows_per_source=2,
    )
    combined = pd.read_csv(output_path)

    assert manifest["total_rows"] == 4
    assert manifest["source_counts"] == {
        "popular-websites": 2,
        "malicious-urls": 2,
    }
    assert set(combined["label"]) <= {"safe", "suspicious", "dangerous"}
