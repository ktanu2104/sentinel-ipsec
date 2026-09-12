# AI-Powered IPsec VPN Protocol Analyzer & Security Assessment Framework

An AI-assisted security analysis framework that accepts IPsec/IKE PCAP
or PCAPNG files, extracts VPN protocol and cryptographic information,
classifies encrypted traffic using machine learning, and presents the
results through an interactive web dashboard.

## Problem Statement

Encrypted VPN traffic protects application payloads but makes monitoring
and security assessment difficult. Analysts often need to manually
determine the VPN protocol, IKE version, cryptographic parameters, ESP
traffic characteristics, application traffic type, and possible security
weaknesses.

This project automates that workflow from a raw packet capture to an
interpretable security assessment.

## Key Features

### Protocol Intelligence

-   IPsec protocol detection
-   IKE version identification
-   Encryption algorithm and key length
-   Integrity algorithm
-   PRF
-   Diffie-Hellman group
-   ESP detection and packet count

### AI Traffic Classification

Because ESP encrypts application payloads, the classifier does not
inspect payload contents. It uses observable traffic behaviour and
statistical features including packet size, inter-arrival time, flow
duration, byte ratios, entropy, MTU proximity, and small-packet ratio.

Supported traffic classes: - ICMP - Web browsing - E-mail - VoIP - Video
streaming - Bulk file transfer

### Security Assessment

The dashboard presents: - Security score - Risk level - Compliance
status - PFS - Replay protection - SA lifetime - Authentication -
Cryptographic strength - Metadata exposure - Threat findings -
Recommendations

### Interactive Dashboard

The frontend includes PCAP upload, security score, findings breakdown,
Protocol Intelligence, ML Verdict, Security Assessment, Threat Matrix,
Recommendations, Protocol Findings, and VPN tested configurations.

## Architecture

``` text
IPsec Client + IPsec Server
          |
       strongSwan
       IKEv2/IPsec
          |
   Traffic Generation
          |
 tcpdump / Wireshark
          |
         PCAP
          |
      FastAPI
          |
        Scapy
       /     \
Protocol     ESP
Analysis    Extraction
              |
        Feature Extraction
              |
         XGBoost Model
              |
     Security Assessment
              |
      Interactive Dashboard
```

## Our IPsec Testbed

The project was validated using two Ubuntu Server ARM64 virtual machines
running in UTM:

``` text
IPSEC-CLIENT  <------ IKEv2/IPsec ------>  IPSEC-SERVER
   Ubuntu             strongSwan             Ubuntu
```

strongSwan was installed and configured on both machines. We established
a working IKEv2 IPsec tunnel using pre-shared-key authentication,
AES-GCM encryption with a 256-bit key, HMAC-SHA2 based cryptographic
parameters, Diffie-Hellman key exchange, and ESP.

We generated controlled traffic through the tunnel, including ICMP,
HTTP/web traffic, and file-transfer traffic, and captured that
communication into PCAP files.

This gave us a controlled environment where the VPN configuration and
generated traffic were known before testing the analyzer.

## PCAP Analysis Pipeline

1.  **PCAP Upload** --- the user uploads a `.pcap` or `.pcapng` file.
2.  **Packet Parsing** --- the FastAPI backend processes packets using
    Scapy.
3.  **Protocol Analysis** --- IKE/IPsec packets are inspected for
    protocol and cryptographic characteristics.
4.  **ESP Isolation** --- ESP packets are separated for
    encrypted-traffic analysis.
5.  **Feature Extraction** --- packet size, timing, flow and entropy
    features are calculated.
6.  **ML Classification** --- extracted features are passed to the
    trained XGBoost model.
7.  **Security Assessment** --- protocol information and security rules
    produce risk, findings and recommendations.
8.  **Dashboard Rendering** --- results are returned to the frontend and
    displayed in a single security-analysis interface.

## Machine Learning

The project uses XGBoost for encrypted-traffic classification.

Main features:

``` text
packet_size_mean
packet_size_std
packet_size_p90
iat_mean_ms
iat_std_ms
iat_p95_ms
flow_duration_sec
bytes_up_down_ratio
packet_entropy
mtu_proximity_ratio
small_packet_ratio
```

The project evaluated Random Forest and XGBoost. XGBoost was selected
with approximately:

-   Accuracy: **70.96%**
-   Macro-F1: **80.78%**

These metrics describe the project's dataset evaluation and should not
be interpreted as universal IPsec classification performance.

## Project Structure

``` text
ipsec-sentinel/
├── analyzer.py
├── api.py
├── app.py
├── build_dataset.py
├── dataset.csv
├── dataset.py
├── features.py
├── security.py
├── server.py
├── test_ml.py
├── train_classifier.py
│
├── frontend/
│   ├── index.html
│   ├── app.js
│   └── style.css
│
├── ml/
│   ├── __init__.py
│   ├── anomaly_detector.py
│   ├── feature_extractor.py
│   ├── schema.py
│   ├── traffic_classifier.py
│   └── model/
│       ├── traffic_classifier.joblib
│       └── classifier_meta.json
│
└── data/
    └── *.pcap
```

PCAP files are excluded from Git using `.gitignore`.

## Technology Stack

**VPN / Networking** - strongSwan - IKEv2 - IPsec - ESP - tcpdump -
Wireshark - UTM - Ubuntu Server

**Backend** - Python - FastAPI - Uvicorn - Scapy

**Machine Learning** - XGBoost - Scikit-learn - Joblib - Pandas - NumPy

**Frontend** - HTML - CSS - JavaScript

**Development** - Git - GitHub - VS Code

## Installation

### Requirements

-   Python 3.10+
-   PCAP/PCAPNG input
-   Python virtual environment

Clone the repository:

``` bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd ipsec-sentinel
```

Create a virtual environment:

``` bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

``` bash
pip install fastapi uvicorn python-multipart scapy pandas numpy scikit-learn xgboost joblib
```

## Running the Dashboard

Start the backend:

``` bash
python3 -m uvicorn server:app --port 8000
```

Open:

``` text
http://127.0.0.1:8000
```

API health check:

``` text
http://127.0.0.1:8000/api/health
```

Expected response:

``` json
{"status":"ok"}
```

## Using the Application

1.  Start the FastAPI server.
2.  Open the dashboard.
3.  Upload a `.pcap` or `.pcapng` file.
4.  Click **Analyze PCAP**.
5.  Review the Security Score, Findings Breakdown, Protocol
    Intelligence, ML Verdict, Security Assessment, Threat Matrix,
    Recommendations, and Protocol Findings.

The current web workflow focuses on PCAP/PCAPNG upload.

## Example IPsec Analysis

A project-generated capture can produce results such as:

``` text
Protocol       : IPsec
IKE Version    : IKEv2
Encryption     : AES-GCM
Key Length     : 256-bit
Integrity      : HMAC-SHA2-256-128
PRF            : HMAC-SHA2-256
DH Group       : MODP2048 / DH14
ESP Traffic    : Detected
```

The ML layer then uses encrypted-traffic behaviour to produce a traffic
classification and confidence score.

## Security Philosophy

The framework does not attempt to break IPsec encryption.

Instead, it combines:

``` text
IKE Negotiation
      +
IPsec / ESP Metadata
      +
Encrypted Traffic Statistics
      +
Machine Learning
      |
      v
Security Intelligence
```

The objective is to extract useful security intelligence from
information that remains observable even when application payloads are
encrypted.

## Limitations

### Encrypted Payloads

The traffic classifier does not inspect decrypted application content.
It relies on statistical characteristics of encrypted traffic.

### PCAP Evidence

A PCAP cannot always prove every VPN configuration parameter. Some
values, such as PFS configuration, replay settings, SA lifetime, or
authentication configuration, may require the original VPN configuration
or runtime SA state.

For the current prototype/demo dashboard, selected fields that cannot be
directly established from the PCAP are presented using predefined
assessment values.

### Dataset

A larger and more diverse IPsec-specific dataset would improve
generalization. Model performance can vary with VPN implementation,
network conditions, packet loss, applications, and capture environment.

### Blockchain

The dashboard contains an integrity-anchor interface, but blockchain
integration is currently a placeholder and is not part of the core PCAP
analysis pipeline.

## Future Improvements

-   Build a larger IPsec-specific dataset.
-   Add AES-128, AES-256, AES-GCM, AES-CBC + HMAC, multiple DH groups,
    PFS modes, tunnel/transport mode, IPv4/IPv6, and AH captures.
-   Add more traffic classes such as DNS, SSH, messaging, cloud
    applications, streaming and gaming.
-   Improve ML using more captures, capture-level validation, tuning,
    ensembles, deep learning and explainable AI.
-   Add runtime strongSwan SA-state integration.
-   Add configuration-aware validation, replay-window analysis, SA
    lifetime verification and PFS verification.
-   Generate downloadable executive and technical PDF reports.
-   Add historical analysis and automated alerts.
-   Integrate with SIEM and SOC workflows.

## Benefits

-   Reduces manual VPN packet analysis
-   Centralizes IPsec security information
-   Helps analysts understand encrypted traffic behaviour
-   Adds AI-based traffic classification
-   Converts packet evidence into security findings
-   Highlights metadata exposure
-   Provides actionable recommendations
-   Supports repeatable PCAP-based assessment
-   Provides a foundation for SOC and enterprise integration

## Responsible Use

This project is intended for authorized VPN and network security
analysis.

Only analyze packet captures and infrastructure that you own or have
explicit permission to test.


