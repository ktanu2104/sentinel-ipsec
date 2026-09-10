"""
Sentinel-IPsec: Encrypted Traffic Feature Extractor
Problem Statement ID: 26160 (Sub-task c)
"""

from typing import List, Dict, Any
from ml.schema import (
    FEATURE_NAMES,
    FEATURE_DESCRIPTIONS,
    SCHEMA_VERSION,
    extract_canonical_features
)


class FeatureExtractor:
    """
    Extracts statistical side-channel features from encrypted ESP traffic flows
    without decrypting packet payloads, adhering strictly to the canonical FeatureSchema.
    """

    FEATURE_NAMES = FEATURE_NAMES
    FEATURE_DESCRIPTIONS = FEATURE_DESCRIPTIONS
    SCHEMA_VERSION = SCHEMA_VERSION

    @staticmethod
    def extract_feature_vector(packets: List[Dict[str, Any]], raw_sample_bytes: bytes = b"") -> List[float]:
        """Extracts canonical ordered feature vector."""
        result = extract_canonical_features(packets, raw_sample_bytes)
        return result["feature_vector"]

    @staticmethod
    def extract_feature_map(packets: List[Dict[str, Any]], raw_sample_bytes: bytes = b"") -> Dict[str, Any]:
        """Extracts named feature map along with metadata."""
        return extract_canonical_features(packets, raw_sample_bytes)
