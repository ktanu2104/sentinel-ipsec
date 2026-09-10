import os
import csv
from features import extract_features


DATA_DIR = "data"
OUTPUT_FILE = "dataset.csv"


LABELS = {
    "full_capture.pcap": "icmp",
    "icmp_01.pcap": "icmp",

    "web_01.pcap": "web",
    "web_02.pcap": "web",

    "file_01.pcap": "file_transfer",
    "file_02.pcap": "file_transfer",
}


def build_dataset():
    rows = []

    for filename, label in LABELS.items():

        filepath = os.path.join(DATA_DIR, filename)

        if not os.path.exists(filepath):
            print(f"Skipping missing file: {filename}")
            continue

        print(f"Processing: {filename} -> {label}")

        features = extract_features(filepath)

        features["label"] = label
        features["filename"] = filename

        rows.append(features)

    if not rows:
        print("No training PCAPs found.")
        return

    fieldnames = list(rows[0].keys())

    with open(OUTPUT_FILE, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print("\nDataset created:", OUTPUT_FILE)
    print("Samples:", len(rows))


if __name__ == "__main__":
    build_dataset()