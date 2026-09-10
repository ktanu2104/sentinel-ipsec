from scapy.all import rdpcap, IP, UDP, ESP


def extract_features(filename):

    packets = rdpcap(filename)

    features = {
        "packet_count": len(packets),
        "esp_packet_count": 0,
        "udp_500_count": 0,
        "udp_4500_count": 0,
        "total_bytes": 0,
        "forward_packets": 0,
        "reverse_packets": 0,
        "forward_bytes": 0,
        "reverse_bytes": 0,
        "avg_packet_size": 0,
        "min_packet_size": 0,
        "max_packet_size": 0,
        "flow_duration": 0,
        "avg_interarrival": 0,
    }

    packet_sizes = []
    timestamps = []

    source_ip = None
    destination_ip = None

    for packet in packets:

        if IP not in packet:
            continue

        size = len(packet)

        packet_sizes.append(size)
        timestamps.append(float(packet.time))

        features["total_bytes"] += size

        # -------------------------
        # Identify first direction
        # -------------------------

        if source_ip is None:
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst

        # -------------------------
        # Direction
        # -------------------------

        if packet[IP].src == source_ip:
            features["forward_packets"] += 1
            features["forward_bytes"] += size

        else:
            features["reverse_packets"] += 1
            features["reverse_bytes"] += size

        # -------------------------
        # ESP
        # -------------------------

        if ESP in packet:
            features["esp_packet_count"] += 1

        # -------------------------
        # IKE / NAT-T
        # -------------------------

        if UDP in packet:

            if packet[UDP].sport == 500 or packet[UDP].dport == 500:
                features["udp_500_count"] += 1

            if packet[UDP].sport == 4500 or packet[UDP].dport == 4500:
                features["udp_4500_count"] += 1

    # -------------------------
    # Packet size statistics
    # -------------------------

    if packet_sizes:

        features["avg_packet_size"] = round(
            sum(packet_sizes) / len(packet_sizes), 2
        )

        features["min_packet_size"] = min(packet_sizes)
        features["max_packet_size"] = max(packet_sizes)

    # -------------------------
    # Flow duration
    # -------------------------

    if timestamps:

        features["flow_duration"] = round(
            max(timestamps) - min(timestamps),
            6
        )

    # -------------------------
    # Inter-arrival time
    # -------------------------

    if len(timestamps) > 1:

        timestamps.sort()

        intervals = [
            timestamps[i] - timestamps[i - 1]
            for i in range(1, len(timestamps))
        ]

        features["avg_interarrival"] = round(
            sum(intervals) / len(intervals),
            6
        )
            # ML-friendly ratio and rate features
    if features["packet_count"] > 0:
        features["esp_ratio"] = round(
            features["esp_packet_count"] / features["packet_count"], 4
        )
        features["udp_4500_ratio"] = round(
            features["udp_4500_count"] / features["packet_count"], 4
        )

    if features["reverse_packets"] > 0:
        features["forward_reverse_packet_ratio"] = round(
            features["forward_packets"] / features["reverse_packets"], 4
        )

    if features["reverse_bytes"] > 0:
        features["forward_reverse_byte_ratio"] = round(
            features["forward_bytes"] / features["reverse_bytes"], 4
        )

    if features["flow_duration"] > 0:
        features["packets_per_second"] = round(
            features["packet_count"] / features["flow_duration"], 4
        )
        features["bytes_per_second"] = round(
            features["total_bytes"] / features["flow_duration"], 4
        )

    return features





import pprint
import sys
import pprint

if __name__ == "__main__":
    filename = sys.argv[1]

    result = extract_features(filename)

    print("\nTraffic Features")
    print("================")
    pprint.pp(result)

    
    