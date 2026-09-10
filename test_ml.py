from scapy.all import rdpcap, IP, ESP
from ml.schema import extract_canonical_features
from ml.traffic_classifier import TrafficClassifier

packets = rdpcap("data/full_capture.pcap")

# Use only ESP packets — these represent the encrypted application traffic.
esp_packets = [p for p in packets if ESP in p]

packet_data = []

if esp_packets:
    first_time = float(esp_packets[0].time)

    for p in esp_packets:
        packet_data.append({
            "length": len(p),
            "rel_time": float(p.time) - first_time,
            "src_ip": p[IP].src if IP in p else ""
        })

raw_bytes = b"".join(bytes(p) for p in esp_packets[:50])

result = extract_canonical_features(
    packet_data,
    raw_sample_bytes=raw_bytes
)

print("FEATURE VECTOR:")
for name, value in zip(result["feature_names"], result["feature_vector"]):
    print(f"{name}: {value}")

print("\nML PREDICTION:")
print(TrafficClassifier.predict(result["feature_vector"]))
