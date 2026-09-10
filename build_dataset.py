import os
import csv
import math
import random
from scapy.all import rdpcap, IP
from ml.schema import FEATURE_NAMES

CAPTURES = {
    "Web browsing": [
        "data/web_01.pcap",
        "data/web_02.pcap",
    ],
    "Video streaming": [
        "data/vpn_vimeo_A.pcap",
        "data/vpn_vimeo_B.pcap",
        "data/vpn_youtube_A.pcap",
        "data/vpn_netflix_A.pcap",
    ],
    "E-mail": [
        "data/vpn_email2a.pcap",
        "data/vpn_email2b.pcap",
    ],
    "VoIP": [
        "data/vpn_hangouts_audio1.pcap",
        "data/vpn_hangouts_audio2.pcap",
        "data/vpn_voipbuster1a.pcap",
        "data/vpn_voipbuster1b.pcap",
    ],
    "Bulk File Transfer": [
        "data/vpn_ftps_A.pcap",
        "data/vpn_ftps_B.pcap",
        "data/vpn_sftp_A.pcap",
        "data/vpn_sftp_B.pcap",
    ],
    "ICMP": [
        "data/icmp_01.pcap",
        "data/full_capture.pcap",
    ],
}

WINDOW_SIZE = 20
STEP_SIZE = 10
MIN_PACKETS = 8
MAX_WINDOWS_PER_CAPTURE = 500

random.seed(42)


def mean(values):
    return sum(values) / len(values) if values else 0.0


def std(values):
    if len(values) < 2:
        return 0.0

    m = mean(values)

    return math.sqrt(
        sum((x - m) ** 2 for x in values) / len(values)
    )


def percentile(values, percentage):
    if not values:
        return 0.0

    values = sorted(values)

    k = (len(values) - 1) * percentage / 100
    lower = math.floor(k)
    upper = math.ceil(k)

    if lower == upper:
        return values[lower]

    return (
        values[lower]
        + (values[upper] - values[lower]) * (k - lower)
    )


def entropy(packets):
    data = b"".join(bytes(packet) for packet in packets)

    if not data:
        return 0.0

    counts = [0] * 256

    for byte in data:
        counts[byte] += 1

    total = len(data)

    return -sum(
        (count / total) * math.log2(count / total)
        for count in counts
        if count
    )


def valid_ip_packets(filename):
    packets = rdpcap(filename)

    return [
        packet
        for packet in packets
        if IP in packet
    ]


def calculate_features(packets):
    times = [float(packet.time) for packet in packets]
    sizes = [len(packet) for packet in packets]

    iats = [
        (times[i] - times[i - 1]) * 1000
        for i in range(1, len(times))
    ]

    first_src = packets[0][IP].src

    forward = [
        packet
        for packet in packets
        if packet[IP].src == first_src
    ]

    reverse = [
        packet
        for packet in packets
        if packet[IP].src != first_src
    ]

    forward_bytes = sum(len(packet) for packet in forward)
    reverse_bytes = sum(len(packet) for packet in reverse)

    if reverse_bytes > 0:
        byte_ratio = forward_bytes / reverse_bytes
    else:
        byte_ratio = float(forward_bytes)

    return {
        "packet_size_mean": mean(sizes),
        "packet_size_std": std(sizes),
        "packet_size_p90": percentile(sizes, 90),

        "iat_mean_ms": mean(iats),
        "iat_std_ms": std(iats),
        "iat_p95_ms": percentile(iats, 95),

        "flow_duration_sec": max(times) - min(times),

        "bytes_up_down_ratio": byte_ratio,

        "packet_entropy": entropy(packets),

        "mtu_proximity_ratio": (
            sum(size >= 1400 for size in sizes) / len(sizes)
        ),

        "small_packet_ratio": (
            sum(size <= 200 for size in sizes) / len(sizes)
        ),
    }


def create_windows(packets, label, filename):
    if len(packets) < MIN_PACKETS:
        return []

    windows = []

    for start in range(
        0,
        len(packets) - MIN_PACKETS + 1,
        STEP_SIZE
    ):
        window = packets[
            start:start + WINDOW_SIZE
        ]

        if len(window) < MIN_PACKETS:
            continue

        features = calculate_features(window)

        row = {
            feature: features[feature]
            for feature in FEATURE_NAMES
        }

        row["label"] = label
        row["source"] = os.path.basename(filename)
        row["capture_id"] = os.path.basename(filename)

        windows.append(row)

    if len(windows) > MAX_WINDOWS_PER_CAPTURE:
        windows = random.sample(
            windows,
            MAX_WINDOWS_PER_CAPTURE
        )

    return windows


def process_capture(filename, label):
    if not os.path.exists(filename):
        print(f"WARNING: missing {filename}")
        return []

    print(f"Processing [{label}] {filename}")

    try:
        packets = valid_ip_packets(filename)
    except Exception as error:
        print(f"ERROR reading {filename}: {error}")
        return []

    print(f"  IP packets: {len(packets)}")

    rows = create_windows(
        packets,
        label,
        filename
    )

    print(f"  Windows: {len(rows)}")

    return rows


def main():
    dataset = []

    for label, filenames in CAPTURES.items():
        for filename in filenames:
            dataset.extend(
                process_capture(
                    filename,
                    label
                )
            )

    random.shuffle(dataset)

    fields = (
        FEATURE_NAMES
        + [
            "label",
            "source",
            "capture_id",
        ]
    )

    with open(
        "dataset.csv",
        "w",
        newline=""
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fields
        )

        writer.writeheader()
        writer.writerows(dataset)

    print()
    print("=" * 50)
    print("DATASET CREATED")
    print("=" * 50)
    print(f"Total samples: {len(dataset)}")

    print()
    print("Class distribution:")

    labels = sorted(
        set(row["label"] for row in dataset)
    )

    for label in labels:
        count = sum(
            row["label"] == label
            for row in dataset
        )

        captures = len({
            row["capture_id"]
            for row in dataset
            if row["label"] == label
        })

        print(
            f"{label}: "
            f"{count} samples "
            f"from {captures} captures"
        )

    print()
    print("Dataset written to dataset.csv")


if __name__ == "__main__":
    main()