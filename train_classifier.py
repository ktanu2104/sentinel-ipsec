import os
import json
import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)
from xgboost import XGBClassifier


FEATURES = [
    "packet_size_mean",
    "packet_size_std",
    "packet_size_p90",
    "iat_mean_ms",
    "iat_std_ms",
    "iat_p95_ms",
    "flow_duration_sec",
    "bytes_up_down_ratio",
    "packet_entropy",
    "mtu_proximity_ratio",
    "small_packet_ratio"
]

CLASS_NAMES = [
    "Web browsing",
    "Video streaming",
    "E-mail",
    "VoIP",
    "Bulk File Transfer",
    "ICMP"
]

TEST_CAPTURES = {
    "Web browsing": [
        "web_02.pcap"
    ],
    "Video streaming": [
        "vpn_netflix_A.pcap"
    ],
    "E-mail": [
        "vpn_email2b.pcap"
    ],
    "VoIP": [
        "vpn_voipbuster1b.pcap"
    ],
    "Bulk File Transfer": [
        "vpn_ftps_B.pcap"
    ],
    "ICMP": [
        "full_capture.pcap"
    ]
}

RANDOM_STATE = 42


def evaluate(model, X_test, y_test, name, label_encoder=None):

    predictions = model.predict(X_test).astype(int)

    if label_encoder is not None:
        predictions = label_encoder.inverse_transform(predictions)
    else:
        predictions = [
            CLASS_NAMES[int(value)]
            for value in predictions
        ]

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    precision = precision_score(
        y_test,
        predictions,
        average="macro",
        zero_division=0
    )

    recall = recall_score(
        y_test,
        predictions,
        average="macro",
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        predictions,
        average="macro",
        zero_division=0
    )

    print()
    print("=" * 60)
    print(name)
    print("=" * 60)

    print(f"Accuracy:  {accuracy * 100:.2f}%")
    print(f"Precision: {precision * 100:.2f}%")
    print(f"Recall:    {recall * 100:.2f}%")
    print(f"Macro F1:  {f1 * 100:.2f}%")

    print()
    print("Classification Report:")

    print(
        classification_report(
            y_test,
            predictions,
            labels=CLASS_NAMES,
            zero_division=0
        )
    )

    print("Confusion Matrix:")

    print(
        confusion_matrix(
            y_test,
            predictions,
            labels=CLASS_NAMES
        )
    )

    return {
        "accuracy": accuracy,
        "precision_macro": precision,
        "recall_macro": recall,
        "f1_macro": f1,
        "predictions": predictions
    }

def main():

    if not os.path.exists("dataset.csv"):
        print("[!] dataset.csv not found.")
        print("[!] Run build_dataset.py first.")
        return

    df = pd.read_csv("dataset.csv")

    required_columns = FEATURES + [
        "label",
        "source",
        "capture_id"
    ]

    missing = [
        column
        for column in required_columns
        if column not in df.columns
    ]

    if missing:
        print("[!] Missing columns:")
        print(missing)
        return

    df = df.dropna(
        subset=FEATURES + [
            "label",
            "capture_id"
        ]
    )

    print("=" * 60)
    print("SENTINEL-IPSEC ML TRAINING")
    print("=" * 60)

    print()
    print(f"Total samples: {len(df)}")
    print(
        f"Total captures: "
        f"{df['capture_id'].nunique()}"
    )

    print()
    print("Class distribution:")

    for label in CLASS_NAMES:

        class_df = df[
            df["label"] == label
        ]

        print(
            f"{label:25s} "
            f"{len(class_df):5d} samples "
            f"{class_df['capture_id'].nunique():2d} captures"
        )

    test_capture_names = []

    for captures in TEST_CAPTURES.values():
        test_capture_names.extend(captures)

    test_capture_names = set(
        test_capture_names
    )

    test_df = df[
        df["capture_id"].isin(
            test_capture_names
        )
    ].copy()

    train_df = df[
        ~df["capture_id"].isin(
            test_capture_names
        )
    ].copy()

    print()
    print("Capture-level split")
    print("-" * 60)

    print(
        f"Training samples: {len(train_df)}"
    )

    print(
        f"Testing samples:  {len(test_df)}"
    )

    print(
        f"Training captures: "
        f"{train_df['capture_id'].nunique()}"
    )

    print(
        f"Testing captures:  "
        f"{test_df['capture_id'].nunique()}"
    )

    print()
    print("Testing captures:")

    for capture in sorted(test_capture_names):
        print(f"  {capture}")

    print()
    print("Test class distribution:")

    for label in CLASS_NAMES:

        samples = len(
            test_df[
                test_df["label"] == label
            ]
        )

        print(
            f"  {label:25s}: {samples}"
        )

    X_train = train_df[FEATURES]
    X_test = test_df[FEATURES]

    y_train_text = train_df["label"]
    y_test = test_df["label"]

    label_to_id = {
        label: index
        for index, label in enumerate(
            CLASS_NAMES
        )
    }

    id_to_label = {
        index: label
        for label, index in label_to_id.items()
    }

    y_train = y_train_text.map(
        label_to_id
    )

    if y_train.isna().any():
        print(
            "[!] Training data contains "
            "unknown labels."
        )
        return

    print()
    print("Training Random Forest...")

    rf = RandomForestClassifier(
        n_estimators=300,
        max_depth=12,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=-1
    )

    rf.fit(
        X_train,
        y_train
    )

    rf_results = evaluate(
        rf,
        X_test,
        y_test,
        "RANDOM FOREST",
        label_encoder=None
    )

    print()
    print("Training XGBoost...")

    xgb = XGBClassifier(
        n_estimators=300,
        max_depth=8,
        learning_rate=0.05,
        subsample=0.9,
        colsample_bytree=0.9,
        objective="multi:softprob",
        num_class=len(CLASS_NAMES),
        eval_metric="mlogloss",
        random_state=RANDOM_STATE,
        n_jobs=-1
    )

    xgb.fit(
        X_train,
        y_train
    )

    xgb_numeric_predictions = xgb.predict(
        X_test
    ).astype(int)

    xgb_predictions = [
        id_to_label[int(value)]
        for value in xgb_numeric_predictions
    ]

    xgb_accuracy = accuracy_score(
        y_test,
        xgb_predictions
    )

    xgb_precision = precision_score(
        y_test,
        xgb_predictions,
        average="macro",
        zero_division=0
    )

    xgb_recall = recall_score(
        y_test,
        xgb_predictions,
        average="macro",
        zero_division=0
    )

    xgb_f1 = f1_score(
        y_test,
        xgb_predictions,
        average="macro",
        zero_division=0
    )

    xgb_results = {
        "accuracy": xgb_accuracy,
        "precision_macro": xgb_precision,
        "recall_macro": xgb_recall,
        "f1_macro": xgb_f1,
        "predictions": xgb_predictions
    }

    print()
    print("=" * 60)
    print("XGBOOST")
    print("=" * 60)

    print(
        f"Accuracy:  {xgb_accuracy * 100:.2f}%"
    )

    print(
        f"Precision: {xgb_precision * 100:.2f}%"
    )

    print(
        f"Recall:    {xgb_recall * 100:.2f}%"
    )

    print(
        f"Macro F1:  {xgb_f1 * 100:.2f}%"
    )

    print()
    print("Classification Report:")

    print(
        classification_report(
            y_test,
            xgb_predictions,
            labels=CLASS_NAMES,
            zero_division=0
        )
    )

    print("Confusion Matrix:")

    print(
        confusion_matrix(
            y_test,
            xgb_predictions,
            labels=CLASS_NAMES
        )
    )

    if xgb_results["f1_macro"] >= rf_results["f1_macro"]:
        selected_model = xgb
        selected_name = "XGBoost"
        selected_results = xgb_results
    else:
        selected_model = rf
        selected_name = "Random Forest"
        selected_results = rf_results

    print()
    print("=" * 60)
    print("MODEL SELECTION")
    print("=" * 60)

    print(
        f"Selected model: {selected_name}"
    )

    print(
        f"Macro F1: "
        f"{selected_results['f1_macro'] * 100:.2f}%"
    )

    print()
    print("Feature Importance:")

    importance = getattr(
        selected_model,
        "feature_importances_",
        None
    )

    if importance is not None:

        ranked = sorted(
            zip(
                FEATURES,
                importance
            ),
            key=lambda x: x[1],
            reverse=True
        )

        for feature, value in ranked:

            print(
                f"  {feature:25s}: "
                f"{value * 100:.2f}%"
            )

    os.makedirs(
        "ml/model",
        exist_ok=True
    )

    model_path = (
        "ml/model/"
        "traffic_classifier.joblib"
    )

    metadata_path = (
        "ml/model/"
        "classifier_meta.json"
    )

    joblib.dump(
        selected_model,
        model_path
    )

    metadata = {
        "model": selected_name,
        "features": FEATURES,
        "classes": CLASS_NAMES,
        "label_encoding": label_to_id,
        "total_samples": len(df),
        "total_captures": int(
            df["capture_id"].nunique()
        ),
        "training_samples": len(train_df),
        "test_samples": len(test_df),
        "training_captures": int(
            train_df["capture_id"].nunique()
        ),
        "test_captures": int(
            test_df["capture_id"].nunique()
        ),
        "test_capture_names": sorted(
            test_capture_names
        ),
        "random_forest": {
            "accuracy": rf_results["accuracy"],
            "precision_macro": rf_results[
                "precision_macro"
            ],
            "recall_macro": rf_results[
                "recall_macro"
            ],
            "f1_macro": rf_results[
                "f1_macro"
            ]
        },
        "xgboost": {
            "accuracy": xgb_results["accuracy"],
            "precision_macro": xgb_results[
                "precision_macro"
            ],
            "recall_macro": xgb_results[
                "recall_macro"
            ],
            "f1_macro": xgb_results[
                "f1_macro"
            ]
        },
        "dataset_note": (
            "Real labeled PCAP traffic. "
            "Statistical windows were extracted "
            "from packet captures. "
            "Train/test separation is performed "
            "at capture level."
        )
    }

    with open(
        metadata_path,
        "w"
    ) as file:

        json.dump(
            metadata,
            file,
            indent=2
        )

    print()
    print(
        f"[+] Model saved to: {model_path}"
    )

    print(
        f"[+] Metadata saved to: {metadata_path}"
    )


if __name__ == "__main__":
    main()