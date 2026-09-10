from fastapi import FastAPI, UploadFile, File
from analyzer import analyze_pcap
from security import assess_security
import shutil
import os


app = FastAPI(
    title="IPsec Sentinel API",
    description="IPsec VPN protocol analysis and security assessment API",
    version="1.0"
)


@app.get("/")
def home():

    return {
        "status": "online",
        "service": "IPsec Sentinel"
    }


@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):

    os.makedirs("data", exist_ok=True)

    file_path = "data/uploaded_capture.pcap"

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Analyze PCAP
    analysis = analyze_pcap(file_path)

    # Current lab configuration
    # Later this can come from IKE negotiation parsing.
    config = {
        "encryption": "AES-256-CBC",
        "dh_group": 14,
        "pfs": True,
        "replay_protection": True,
        "sa_lifetime": 3600
    }

    security = assess_security(config)

    return {
        "protocol": "IPsec",
        "ike_version": "IKEv2",
        "mode": "Tunnel",

        "encryption": config["encryption"],
        "dh_group": config["dh_group"],
        "pfs": config["pfs"],
        "replay_protection": config["replay_protection"],

        "packet_analysis": analysis,

        "security": security
    }