import argparse
import json
from pathlib import Path

import joblib
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from ml.url_model import build_pipeline, load_dataset, save_artifact


def train(dataset_path, model_path):
    dataset = load_dataset(dataset_path)
    train_urls, test_urls, train_labels, test_labels = train_test_split(
        dataset["url"],
        dataset["label"],
        test_size=0.25,
        random_state=42,
        stratify=dataset["label"],
    )
    model = build_pipeline()
    model.fit(train_urls, train_labels)
    predictions = model.predict(test_urls)
    report = classification_report(
        test_labels,
        predictions,
        labels=["safe", "suspicious", "dangerous"],
        output_dict=True,
        zero_division=0,
    )
    metrics = {
        "rows": int(len(dataset)),
        "train_rows": int(len(train_urls)),
        "test_rows": int(len(test_urls)),
        "precision_macro": report["macro avg"]["precision"],
        "recall_macro": report["macro avg"]["recall"],
        "f1_macro": report["macro avg"]["f1-score"],
        "confusion_matrix": confusion_matrix(
            test_labels,
            predictions,
            labels=["safe", "suspicious", "dangerous"],
        ).tolist(),
    }
    save_artifact(model, model_path, metrics)
    return metrics


def main():
    parser = argparse.ArgumentParser(description="Train the ScamShield URL baseline model.")
    parser.add_argument("--dataset", default="data/url_dataset.csv")
    parser.add_argument("--output", default="models/url_model.joblib")
    args = parser.parse_args()
    metrics = train(args.dataset, args.output)
    metrics_path = Path(args.output).with_suffix(".metrics.json")
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
