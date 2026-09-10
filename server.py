from scapy.all import rdpcap, IP, ESP
from ml.schema import extract_canonical_features, FEATURE_NAMES
from ml.traffic_classifier import TrafficClassifier
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import tempfile
import os
import uuid
from datetime import datetime

from analyzer import analyze_pcap
from security import assess_security


app = FastAPI(title="IPsec VPN Analyzer API")
app.mount("/static", StaticFiles(directory="frontend"), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)




@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...)):
    data = await file.read()
    suffix = os.path.splitext(file.filename)[1] or ".pcap"

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(data)
        temp_path = tmp.name

    try:
        analysis = analyze_pcap(temp_path)

        packets = rdpcap(temp_path)

        packet_data = []

        if packets:
            first_time = float(packets[0].time)

            for p in packets:
                packet_data.append({
                    "length": len(p),
                    "rel_time": float(p.time) - first_time,
                    "src_ip": p[IP].src if IP in p else ""
                })

        raw_bytes = b"".join(bytes(p) for p in packets[:50])

        ml_features = extract_canonical_features(
            packet_data,
            raw_sample_bytes=raw_bytes
        )
        print("\n[ML FEATURES FROM WEBSITE]")
        for name, value in zip(
              FEATURE_NAMES,
              ml_features["feature_vector"]
         ):
            print(f"{name}: {value}")
        ml_result = TrafficClassifier.predict(
            ml_features["feature_vector"]
        )
        print("[ML FEATURES]", ml_features["feature_vector"], flush=True)
        print("[ML RESULT]", ml_result, flush=True)
        assessment = assess_security(analysis)

        vulnerabilities = []

        for finding in assessment["findings"]:
            severity = finding.get("severity", "LOW").lower()

            if severity not in ["high", "medium", "low"]:
                continue

            vulnerabilities.append({
                "id": finding.get("id", "security-finding"),
                "title": finding.get("title", "Security finding"),
                "severity": severity,
                "detail": finding.get("detail", "")
            })

        return {
            "status": "complete",
            "filename": file.filename,
            "securityScore": assessment["score"],

            "securityAssessment": {
                "score": assessment["score"],
                "risk": assessment["risk"],
                "assessment_status": assessment["assessment_status"],
                "unknown_count": assessment["unknown_count"],
                "compliance": assessment["compliance"],
                "findings": assessment["findings"],
                "threats": assessment["threats"],
                "recommendations": assessment["recommendations"]
            },

            "analysis": analysis,

            "vulnerabilities": vulnerabilities,

            "mlVerdict": {
                "classification": ml_result["predicted_payload"],
                "confidence": ml_result["confidence_percent"],
                "probabilities": ml_result["probabilities"],
                "factors": ml_result["factors"],
                "reasoning": ml_result["reasoning"],
                "modelNote": "XGBoost traffic classification"
            },

            "blockchainProof": {
                "txHash": "N/A",
                "blockNumber": 0,
                "verified": False,
                "note": "Blockchain integration not configured."
            },

            "generatedAt": datetime.now().isoformat()
        }

    finally:
        os.unlink(temp_path)




@app.get("/")
def root():
    return FileResponse("frontend/index.html")