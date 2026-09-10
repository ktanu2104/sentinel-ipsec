import streamlit as st
from analyzer import analyze_pcap
from security import assess_security


# --------------------------------------------------
# PAGE CONFIG
# --------------------------------------------------

st.set_page_config(
    page_title="IPsec Sentinel",
    page_icon="🛡️",
    layout="wide"
)


# --------------------------------------------------
# CUSTOM CSS
# --------------------------------------------------

st.markdown("""
<style>

.stApp {
    background-color: #0b0f14;
    color: #e6edf3;
}

.block-container {
    padding-top: 2rem;
    padding-bottom: 2rem;
}

h1 {
    color: #ffffff;
    letter-spacing: 2px;
}

h2, h3 {
    color: #dbe7f3;
}

.metric-card {
    background-color: #111820;
    border: 1px solid #263341;
    border-radius: 10px;
    padding: 20px;
    text-align: center;
}

.metric-title {
    font-size: 13px;
    color: #8b9aaa;
    text-transform: uppercase;
    letter-spacing: 1px;
}

.metric-value {
    font-size: 30px;
    font-weight: bold;
    color: #ffffff;
}

.finding {
    background-color: #111820;
    border-left: 4px solid #4caf50;
    padding: 12px;
    margin-bottom: 8px;
    border-radius: 5px;
}

.warning {
    background-color: #111820;
    border-left: 4px solid #ffb300;
    padding: 12px;
    margin-bottom: 8px;
    border-radius: 5px;
}

</style>
""", unsafe_allow_html=True)


# --------------------------------------------------
# HEADER
# --------------------------------------------------

st.title("🛡️ IPsec SENTINEL")

st.caption(
    "AI-Powered VPN Protocol Intelligence & Security Assessment"
)

st.divider()


# --------------------------------------------------
# LOAD PCAP
# --------------------------------------------------

pcap_file = "data/experiment_001_ipsec.pcap"

try:

    analysis = analyze_pcap(pcap_file)

except Exception as e:

    st.error(f"Unable to analyze PCAP: {e}")
    st.stop()


# --------------------------------------------------
# SECURITY CONFIGURATION
# --------------------------------------------------

config = {
    "encryption": "AES-256-CBC",
    "dh_group": 14,
    "pfs": True,
    "replay_protection": True,
    "sa_lifetime": 3600
}

security = assess_security(config)


# --------------------------------------------------
# TOP METRICS
# --------------------------------------------------

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">Security Score</div>
            <div class="metric-value">{security["score"]}/100</div>
        </div>
        """,
        unsafe_allow_html=True
    )

with col2:
    st.markdown(
        """
        <div class="metric-card">
            <div class="metric-title">Protocol</div>
            <div class="metric-value">IKEv2</div>
        </div>
        """,
        unsafe_allow_html=True
    )

with col3:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">ESP Packets</div>
            <div class="metric-value">{analysis["esp_packets"]}</div>
        </div>
        """,
        unsafe_allow_html=True
    )

with col4:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">Risk Level</div>
            <div class="metric-value">{security["risk"]}</div>
        </div>
        """,
        unsafe_allow_html=True
    )


st.write("")


# --------------------------------------------------
# PROTOCOL FINGERPRINT
# --------------------------------------------------

st.subheader("Protocol Fingerprint")

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("VPN", "IPsec")

with col2:
    st.metric("Key Exchange", "IKEv2")

with col3:
    st.metric("Data Protocol", "ESP")

with col4:
    st.metric("Mode", "Tunnel")


# --------------------------------------------------
# CRYPTOGRAPHIC CONFIGURATION
# --------------------------------------------------

st.subheader("Cryptographic Configuration")

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Encryption", config["encryption"])

with col2:
    st.metric("DH Group", config["dh_group"])

with col3:
    st.metric("PFS", "ENABLED" if config["pfs"] else "DISABLED")

with col4:
    st.metric(
        "Replay Protection",
        "ENABLED" if config["replay_protection"] else "DISABLED"
    )


# --------------------------------------------------
# PACKET TELEMETRY
# --------------------------------------------------

st.subheader("Packet Telemetry")

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Total Packets", analysis["total_packets"])

with col2:
    st.metric("ESP Packets", analysis["esp_packets"])

with col3:
    st.metric("IKE Packets", analysis["ike_packets"])

with col4:
    st.metric("Unique SPIs", analysis["unique_spis"])


col1, col2 = st.columns(2)

with col1:
    st.metric(
        "ESP Sequence Range",
        f'{analysis["sequence_min"]} → {analysis["sequence_max"]}'
    )

with col2:
    st.metric(
        "Average ESP Size",
        f'{analysis["average_esp_size"]} bytes'
    )


# --------------------------------------------------
# SECURITY FINDINGS
# --------------------------------------------------

st.subheader("Security Findings")

for finding in security["findings"]:

    severity = finding["severity"]

    if severity == "GOOD":

        st.markdown(
            f"""
            <div class="finding">
            <b>✓ {finding["title"]}</b><br>
            {finding["detail"]}
            </div>
            """,
            unsafe_allow_html=True
        )

    else:

        st.markdown(
            f"""
            <div class="warning">
            <b>⚠ {finding["title"]}</b><br>
            {finding["detail"]}
            </div>
            """,
            unsafe_allow_html=True
        )


# --------------------------------------------------
# RECOMMENDATIONS
# --------------------------------------------------

st.subheader("Analyst Recommendations")

if security["recommendations"]:

    for recommendation in security["recommendations"]:

        st.warning(recommendation)

else:

    st.success("No immediate security recommendations.")


# --------------------------------------------------
# AI SECTION
# --------------------------------------------------

st.subheader("AI Traffic Classification")

st.info(
    "AI traffic classification module will be connected here. "
    "The ML model can classify encrypted traffic such as "
    "web, VoIP, video, messaging, or ICMP."
)


# --------------------------------------------------
# FOOTER
# --------------------------------------------------

st.divider()

st.caption(
    "IPsec SENTINEL • Protocol telemetry + security assessment + AI intelligence"
)