"""
Sentinel-IPsec: Encrypted Traffic Anomaly Detector
Problem Statement ID: 26160
"""

from typing import Dict, Any, List


class AnomalyDetector:
    """
    Evaluates encrypted IPsec streams for timing jitter, replay sequence gaps,
    and unexpected flow behavior using statistical deviation heuristics.
    """

    @staticmethod
    def detect_anomalies(features: List[float], esp_audit: Dict[str, Any]) -> Dict[str, Any]:
        mean_sz = features[0] if len(features) > 0 else 0.0
        std_sz = features[1] if len(features) > 1 else 0.0
        p90_sz = features[2] if len(features) > 2 else 0.0
        mean_iat = features[3] if len(features) > 3 else 0.0
        std_iat = features[4] if len(features) > 4 else 0.0
        p95_iat = features[5] if len(features) > 5 else 0.0
        duration = features[6] if len(features) > 6 else 0.0

        anomaly_score = 0.05
        reasons = []

        # 1. ESP Sequence violations & duplicates
        replay_violations = esp_audit.get("replay_violations", 0)
        duplicate_seqs = esp_audit.get("duplicate_seqs", 0)
        outside_window = esp_audit.get("outside_window_packets", 0)
        seq_jumps = esp_audit.get("sequence_jumps", 0)

        if duplicate_seqs > 0:
            anomaly_score += 0.40
            reasons.append(f"Potential replay attack: {duplicate_seqs} duplicate ESP sequence numbers detected.")

        if outside_window > 0:
            anomaly_score += 0.35
            reasons.append(f"Anti-replay window exceeded: {outside_window} packets arrived behind the sliding window.")

        if seq_jumps > 0:
            anomaly_score += 0.20
            reasons.append(f"Sequence number jump detected: {seq_jumps} abrupt sequence skips indicate packet drops or SA rekeying.")

        # 2. Timing jitter & abnormal stall
        if p95_iat > 15000.0:
            anomaly_score += 0.20
            reasons.append("Abnormally long idle gap (>15s) in active Security Association.")

        # 3. Variance dispersion
        if std_sz > 550.0 and duration > 10.0:
            anomaly_score += 0.15
            reasons.append("Extreme packet size dispersion observed across flow.")

        anomaly_score = min(round(anomaly_score, 2), 1.0)
        status = "suspicious" if anomaly_score >= 0.45 else "normal"

        if not reasons:
            reasons.append("Packet cadence and size distributions conform to baseline operational bounds.")
            reasons.append("No sequence discontinuities or replay window infractions observed.")

        return {
            "anomaly_score": anomaly_score,
            "status": status,
            "reasons": reasons
        }
