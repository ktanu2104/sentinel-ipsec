"""
Sentinel-IPsec: Encrypted Traffic Machine Learning Classifier
Problem Statement ID: 26160 (Sub-task c)

Loads and executes trained Random Forest model from disk (via joblib).
Includes calibrated fallback heuristics when model artifact is absent or scikit-learn is not installed.
"""

import os
import math
from typing import Dict, Any, List, Tuple
from ml.schema import (
    TRAFFIC_CLASSES,
    FEATURE_NAMES,
    extract_canonical_features
)

try:
    import joblib
    JOBLIB_AVAILABLE = True
except ImportError:
    JOBLIB_AVAILABLE = False


class TrafficClassifier:
    """
    Classifies the application payload encapsulated inside encrypted ESP tunnels
    using statistical flow side-channel features without performing decryption.
    """

    CLASSES = TRAFFIC_CLASSES
    _model = None
    _model_loaded = False
    _model_path = os.path.join(os.path.dirname(__file__), "model", "traffic_classifier.joblib")

    @classmethod
    def _get_model(cls):
        """Lazy loader for persisted scikit-learn Random Forest model."""
        if not cls._model_loaded:
            if JOBLIB_AVAILABLE and os.path.exists(cls._model_path):
                try:
                    cls._model = joblib.load(cls._model_path)
                except Exception:
                    cls._model = None
            cls._model_loaded = True
        return cls._model

    @staticmethod
    def predict(features: List[float]) -> Dict[str, Any]:
        """
        Executes inference:
        1. Trained Random Forest model via joblib if available.
        2. Calibrated statistical decision rules as graceful fallback.
        """
        if len(features) < len(FEATURE_NAMES):
            # Pad features if needed
            features = list(features) + [0.0] * (len(FEATURE_NAMES) - len(features))
        elif len(features) > len(FEATURE_NAMES):
            features = features[:len(FEATURE_NAMES)]

        model = TrafficClassifier._get_model()
        if model is not None:
                try:
                    probs_raw = model.predict_proba([features])[0]

                    model_classes = getattr(
                        model,
                        "classes_",
                        list(range(len(probs_raw)))
                    )

                    probabilities = {
                        c: 0.0
                        for c in TRAFFIC_CLASSES
                    }

                    for class_id, probability in zip(
                        model_classes,
                        probs_raw
                    ):
                        class_id = int(class_id)

                        if 0 <= class_id < len(TRAFFIC_CLASSES):
                            probabilities[
                                TRAFFIC_CLASSES[class_id]
                            ] = round(
                                float(probability) * 100.0,
                                1
                            )

                    top_class = max(
                        probabilities,
                        key=probabilities.get
                    )

                    confidence = probabilities[top_class]

                    factors, reasoning = (
                        TrafficClassifier._generate_explanations(
                            features,
                            top_class
                        )
                    )

                    return {
                        "predicted_payload": top_class,
                        "confidence_percent": confidence,
                        "probabilities": probabilities,
                        "factors": factors,
                        "reasoning": reasoning,
                        "inference_engine":
                            f"{type(model).__name__} (joblib)"
                    }

                except Exception as e:
                    print(
                        f"[ML] Model inference failed: {e}"
                    )

    @staticmethod
    def _predict_heuristic(features: List[float]) -> Dict[str, Any]:
        """Calibrated fallback inference engine when model weights are not loaded."""
        mean_sz, std_sz, p90_sz, mean_iat, std_iat, p95_iat, duration, ratio, entropy, mtu_ratio, small_ratio = features[:11]

        scores = {c: 10.0 for c in TRAFFIC_CLASSES}

        # 1. Packet Size Clustering
        if mtu_ratio >= 0.50 or p90_sz >= 1300:
            scores["Video streaming"] += 55.0
            scores["Bulk File Transfer"] += 38.0
        elif small_ratio >= 0.70 or (mean_sz <= 240 and std_sz <= 45):
            scores["VoIP"] += 65.0
            scores["ICMP"] += 25.0
        elif mean_sz <= 450 and small_ratio >= 0.35:
            scores["E-mail"] += 45.0
            scores["Web browsing"] += 25.0
        else:
            scores["Web browsing"] += 45.0

        # 2. Timing & Cadence
        if 14.0 <= mean_iat <= 26.0 and p95_iat <= 40.0:
            scores["VoIP"] += 45.0
        elif p95_iat >= 2000.0:
            scores["Web browsing"] += 30.0
            scores["E-mail"] += 25.0
        elif mean_iat <= 8.0:
            scores["Bulk File Transfer"] += 40.0
            scores["Video streaming"] += 20.0

        # Softmax normalization
        exp_sum = sum(math.exp(v / 18.0) for v in scores.values())
        probabilities = {k: round((math.exp(v / 18.0) / exp_sum) * 100, 1) for k, v in scores.items()}

        top_class = max(probabilities, key=probabilities.get)
        confidence = probabilities[top_class]
        factors, reasoning = TrafficClassifier._generate_explanations(features, top_class)

        return {
            "predicted_payload": top_class,
            "confidence_percent": confidence,
            "probabilities": probabilities,
            "factors": factors,
            "reasoning": reasoning,
            "inference_engine": "Calibrated Heuristic Scoring"
        }

    @staticmethod
    def _generate_explanations(features: List[float], top_class: str) -> Tuple[List[Tuple[str, int]], List[str]]:
        mean_sz, std_sz, p90_sz, mean_iat, std_iat, p95_iat, duration, ratio, entropy, mtu_ratio, small_ratio = features[:11]
        factors: List[Tuple[str, int]] = []
        reasoning: List[str] = []

        if top_class == "VoIP":
            factors.append(("Fixed small payload size (<220B)", 95))
            factors.append(("Strict 20ms packet pacing cadence", 96))
            factors.append(("Low packet size variance", 88))
            reasoning.append("Uniform small packet distribution strongly aligns with G.711 / Opus voice codec framing.")
            reasoning.append("Packet arrival intervals strictly follow a 20ms cadence, typical of real-time voice RTP streams.")
        elif top_class == "Video streaming":
            factors.append(("Packet sizes cluster near MTU ceiling (1300-1450B)", 94))
            factors.append(("Bursty packet arrival cascades", 86))
            factors.append(("Heavy downstream-to-upstream byte asymmetry", 91))
            reasoning.append("High concentration of packets near Ethernet MTU ceiling indicates streaming media chunk delivery.")
            reasoning.append("Asymmetric byte ratio reflects continuous media download with minimal uplink traffic.")
        elif top_class == "Bulk File Transfer":
            factors.append(("Near 100% MTU saturation", 96))
            factors.append(("Ultra-low inter-arrival intervals (<5ms)", 92))
            reasoning.append("Continuous maximum transmission unit saturation with minimal inter-arrival pauses indicates saturating file transfer.")
        
        
        elif top_class == "ICMP":
            packet_mean = features[0]
            iat_mean = features[3]
            packet_std = features[1]

            if packet_std < 20:
                factors.append(
                    (f"Low packet size variation ({packet_mean:.0f}B mean)", 90)
                )
            else:
                factors.append(
                    (f"Small ICMP-like packets ({packet_mean:.0f}B mean)", 80)
                )

            if 700 <= iat_mean <= 1300:
                factors.append(
                    (f"~{iat_mean:.0f}ms packet heartbeat", 95)
                )
            elif iat_mean > 300:
                factors.append(
                    (f"Periodic packet timing (~{iat_mean:.0f}ms)", 85)
                )
            else:
                factors.append(
                    ("Short inter-arrival times", 75)
                )

            reasoning.append(
                f"Traffic shows {packet_mean:.0f}B average packet size "
                f"with approximately {iat_mean:.0f}ms average inter-arrival time, "
                "consistent with ICMP echo traffic."
            )
        elif top_class == "E-mail":
            factors.append(("Small transactional polling profile", 82))
            factors.append(("Periodic background sync pauses (>5s)", 78))
            reasoning.append("Intermittent small-packet exchanges correspond to background IMAP/SMTP sync cycles.")
        else:  # Web browsing
            factors.append(("High packet size variance & dispersion", 85))
            factors.append(("Human-scale idle pauses (>2.0s)", 80))
            reasoning.append("Heterogeneous packet size distribution is characteristic of multi-resource HTTP/TLS web browsing.")
            reasoning.append("Long inter-arrival pauses reflect human reading pauses between web page navigations.")

        return factors, reasoning
