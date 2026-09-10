"""
Sentinel-IPsec: Canonical Machine Learning Feature Schema
Problem Statement ID: 26160 (Sub-task c)

Shared contract across feature extraction, model training, and runtime inference.
Guarantees consistent feature ordering, naming, and dimensionality.
"""

from typing import List, Dict, Any
import math
from collections import Counter

SCHEMA_VERSION = "2.0.0"

TRAFFIC_CLASSES: List[str] = [
    "VoIP",
    "Video streaming",
    "Web browsing",
    "E-mail",
    "Bulk File Transfer",
    "ICMP"
]

FEATURE_NAMES: List[str] = [
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

FEATURE_DESCRIPTIONS: Dict[str, str] = {
    "packet_size_mean": "Arithmetic mean of all encapsulated packet sizes in bytes.",
    "packet_size_std": "Standard deviation of encapsulated packet sizes.",
    "packet_size_p90": "90th percentile packet size in bytes.",
    "iat_mean_ms": "Mean packet inter-arrival time in milliseconds.",
    "iat_std_ms": "Standard deviation of packet inter-arrival time in milliseconds.",
    "iat_p95_ms": "95th percentile packet inter-arrival time in milliseconds.",
    "flow_duration_sec": "Total active flow capture duration in seconds.",
    "bytes_up_down_ratio": "Ratio of upload bytes to download bytes across observed directions.",
    "packet_entropy": "Shannon byte entropy (0.0 - 8.0) across flow packet headers and payloads.",
    "mtu_proximity_ratio": "Proportion of packets nearing Ethernet MTU ceiling (>= 1300 bytes).",
    "small_packet_ratio": "Proportion of small packets (<= 220 bytes) indicating VoIP, ACKs, or keepalives."
}


def compute_shannon_entropy(byte_sequence: bytes) -> float:
    """Calculates Shannon entropy of raw bytes in range [0.0, 8.0]."""
    if not byte_sequence:
        return 7.9  # Default high entropy for encrypted ESP
    length = len(byte_sequence)
    freq = Counter(byte_sequence)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def extract_canonical_features(packets: List[Dict[str, Any]], raw_sample_bytes: bytes = b"") -> Dict[str, Any]:
    """
    Extracts canonical features from a stream of packet dictionaries.
    Returns both a dictionary mapping feature names to values and the ordered vector.
    """
    if not packets:
        zero_map = {name: 0.0 for name in FEATURE_NAMES}
        return {
            "feature_map": zero_map,
            "feature_vector": [0.0] * len(FEATURE_NAMES),
            "feature_names": FEATURE_NAMES,
            "schema_version": SCHEMA_VERSION
        }

    sizes = [p.get("length", 0) for p in packets]
    count = len(sizes)
    sorted_sizes = sorted(sizes)

    mean_sz = sum(sizes) / count
    p90_sz = float(sorted_sizes[int(count * 0.90)]) if count > 1 else float(sorted_sizes[0])
    var_sz = sum((s - mean_sz) ** 2 for s in sizes) / count
    std_sz = math.sqrt(var_sz)

    # Inter-arrival times (IAT)
    times = [p.get("rel_time", 0.0) for p in packets]
    iats = [(times[i] - times[i - 1]) * 1000.0 for i in range(1, len(times))]
    mean_iat = sum(iats) / len(iats) if iats else 0.0
    var_iat = sum((t - mean_iat) ** 2 for t in iats) / len(iats) if iats else 0.0
    std_iat = math.sqrt(var_iat)
    sorted_iats = sorted(iats) if iats else [0.0]
    p95_iat = float(sorted_iats[int(len(sorted_iats) * 0.95)]) if len(sorted_iats) > 1 else float(sorted_iats[-1])
    duration = max(0.0, times[-1] - times[0]) if len(times) > 1 else 0.0

    # Flow directional ratio
    src_set = set(p.get("src_ip", "") for p in packets if p.get("src_ip"))
    primary_src = packets[0].get("src_ip", "") if packets else ""
    bytes_up = sum(p.get("length", 0) for p in packets if p.get("src_ip") == primary_src)
    bytes_down = sum(p.get("length", 0) for p in packets if p.get("src_ip") != primary_src)

    if bytes_down > 0:
        up_down_ratio = bytes_up / bytes_down
    elif count > 1:
        # Split first half vs second half
        up_down_ratio = sum(sizes[:count // 2]) / (sum(sizes[count // 2:]) + 1e-5)
    else:
        up_down_ratio = 1.0
    up_down_ratio = min(round(float(up_down_ratio), 3), 20.0)

    # MTU proximity & Small packet ratios
    mtu_count = sum(1 for s in sizes if s >= 1300)
    mtu_ratio = round(mtu_count / count, 3)

    small_count = sum(1 for s in sizes if s <= 220)
    small_ratio = round(small_count / count, 3)

    # Shannon byte entropy
    if raw_sample_bytes:
        entropy = round(compute_shannon_entropy(raw_sample_bytes[:4096]), 3)
    else:
        entropy = 7.92  # Typical high-entropy encrypted ciphertext baseline

    feature_map = {
        "packet_size_mean": round(mean_sz, 2),
        "packet_size_std": round(std_sz, 2),
        "packet_size_p90": round(p90_sz, 2),
        "iat_mean_ms": round(mean_iat, 2),
        "iat_std_ms": round(std_iat, 2),
        "iat_p95_ms": round(p95_iat, 2),
        "flow_duration_sec": round(duration, 2),
        "bytes_up_down_ratio": up_down_ratio,
        "packet_entropy": entropy,
        "mtu_proximity_ratio": mtu_ratio,
        "small_packet_ratio": small_ratio
    }

    feature_vector = [feature_map[name] for name in FEATURE_NAMES]

    return {
        "feature_map": feature_map,
        "feature_vector": feature_vector,
        "feature_names": FEATURE_NAMES,
        "schema_version": SCHEMA_VERSION
    }

