def assess_security(analysis):

    findings = []
    recommendations = []
    threats = []
    score = 100
    unknown_count = 0

    crypto = analysis.get("crypto", {})
    ike = analysis.get("ike", {})
    esp = analysis.get("esp", {})

    def add_finding(severity, title, detail):
        findings.append({
            "severity": severity,
            "title": title,
            "detail": detail
        })

    def add_threat(threat, severity, detail):
        threats.append({
            "threat": threat,
            "severity": severity,
            "detail": detail
        })

    def add_recommendation(text):
        recommendations.append(text)

    # -------------------------
    # IKE version
    # -------------------------

    version = ike.get("version")

    if version == "IKEv2":

        add_finding(
            "GOOD",
            "Modern IKE version",
            "IKEv2 was detected from the packet capture."
        )

    elif version:

        score -= 20

        add_finding(
            "HIGH",
            "Weak or outdated IKE version",
            f"Detected version: {version}."
        )

        add_threat(
            "Legacy IKE protocol",
            "HIGH",
            "Older IKE versions may provide weaker negotiation and security properties."
        )

        add_recommendation(
            "Use IKEv2 for modern IPsec deployments."
        )

    else:

        unknown_count += 1

        add_finding(
            "UNKNOWN",
            "IKE version could not be determined",
            "The IKE version could not be determined from the capture."
        )

    # -------------------------
    # Encryption
    # -------------------------

    encryption = crypto.get("encryption")
    key_length = crypto.get("key_length")

    if encryption == "AES-GCM" and key_length and key_length >= 256:

        add_finding(
            "GOOD",
            "Strong authenticated encryption",
            f"AES-GCM with a {key_length}-bit key was detected."
        )

    elif encryption == "AES-GCM":

        add_finding(
            "GOOD",
            "Authenticated encryption detected",
            f"AES-GCM with a {key_length}-bit key was detected."
        )

        if key_length and key_length < 256:
            score -= 5

            add_threat(
                "Reduced cipher strength",
                "LOW",
                "AES-GCM was detected with a key size below 256 bits."
            )

    elif encryption == "AES-CBC":

        score -= 10

        add_finding(
            "MEDIUM",
            "AES-CBC encryption",
            "AES-CBC was detected. Authenticated encryption such as AES-GCM is preferred."
        )

        add_threat(
            "Non-AEAD encryption",
            "MEDIUM",
            "AES-CBC does not provide authenticated encryption by itself."
        )

        add_recommendation(
            "Prefer AES-GCM over AES-CBC where supported."
        )

    elif encryption:

        add_finding(
            "MEDIUM",
            "Encryption detected",
            f"Detected encryption: {encryption}, key length: {key_length} bits."
        )

    else:

        unknown_count += 1

        add_finding(
            "UNKNOWN",
            "Encryption could not be determined",
            "No encryption transform was extracted from the capture."
        )

    # -------------------------
    # DH group
    # -------------------------

    dh_group = crypto.get("dh_group")

    if dh_group in ["MODP768", "MODP1024"]:

        score -= 20

        add_finding(
            "HIGH",
            "Weak DH group",
            f"{dh_group} was detected. A stronger Diffie-Hellman group is recommended."
        )

        add_threat(
            "Weak key exchange",
            "HIGH",
            f"{dh_group} provides comparatively weak Diffie-Hellman security."
        )

        add_recommendation(
            "Use a stronger DH group such as MODP3072 or an approved elliptic-curve group."
        )

    elif dh_group in ["MODP1536", "MODP2048"]:

        score -= 5

        add_finding(
            "LOW",
            "Moderate DH group",
            f"{dh_group} was detected. Stronger groups such as MODP3072 or elliptic-curve groups are preferred."
        )

        add_recommendation(
            "Consider a stronger DH group such as MODP3072 or an approved elliptic-curve group."
        )

    elif dh_group in [
        "MODP3072",
        "MODP4096",
        "MODP6144",
        "MODP8192",
        "ECP256",
        "ECP384",
        "ECP521"
    ]:

        add_finding(
            "GOOD",
            "Strong DH group",
            f"{dh_group} was detected."
        )

    elif dh_group:

        add_finding(
            "MEDIUM",
            "Unrecognized DH group",
            f"Detected DH group: {dh_group}."
        )

    else:

        unknown_count += 1

        add_finding(
            "UNKNOWN",
            "DH group could not be determined",
            "No DH transform was extracted from the capture."
        )

    # -------------------------
    # Integrity
    # -------------------------

    integrity = crypto.get("integrity")

    if integrity:

        add_finding(
            "GOOD",
            "Integrity protection detected",
            f"Detected integrity algorithm: {integrity}."
        )

    else:

        unknown_count += 1

        add_finding(
            "UNKNOWN",
            "Integrity algorithm unknown",
            "The integrity transform could not be determined."
        )

    # -------------------------
    # PRF
    # -------------------------

    prf = crypto.get("prf")

    if prf:

        add_finding(
            "GOOD",
            "PRF detected",
            f"Detected PRF: {prf}."
        )

    else:

        unknown_count += 1

        add_finding(
            "UNKNOWN",
            "PRF unknown",
            "The PRF could not be determined from the capture."
        )

    # -------------------------
    # PFS
    # -------------------------

    pfs = crypto.get("pfs")

    if pfs is True:

        add_finding(
            "GOOD",
            "Perfect Forward Secrecy enabled",
            "The capture provides evidence that PFS is enabled for the Child SA."
        )

    elif pfs is False:

        score -= 10

        add_finding(
            "MEDIUM",
            "Perfect Forward Secrecy disabled",
            "The Child SA was negotiated without an additional DH exchange."
        )

        add_threat(
            "Lack of Perfect Forward Secrecy",
            "MEDIUM",
            "Compromise of long-term key material may increase exposure of past session keys."
        )

        add_recommendation(
            "Enable PFS for Child SA negotiations."
        )

    else:

        unknown_count += 1

        add_finding(
            "UNKNOWN",
            "PFS status unknown",
            "The capture does not provide sufficient evidence to determine whether PFS is enabled."
        )

    # -------------------------
    # Replay protection
    # -------------------------

    replay = esp.get("replay_protection")

    if replay is True:

        add_finding(
            "GOOD",
            "Replay protection detected",
            "ESP replay-protection information was detected."
        )

    elif replay is False:

        score -= 10

        add_finding(
            "MEDIUM",
            "Replay protection disabled",
            "The captured SA indicates that replay protection is disabled."
        )

        add_threat(
            "Replay attack exposure",
            "MEDIUM",
            "Without replay protection, previously captured packets may be susceptible to replay."
        )

        add_recommendation(
            "Enable IPsec anti-replay protection."
        )

    else:

        unknown_count += 1

        add_finding(
            "UNKNOWN",
            "Replay protection status unknown",
            "The capture does not provide sufficient evidence to determine the replay-protection configuration."
        )

    # -------------------------
    # SA / key lifetime
    # -------------------------

    lifetime = crypto.get("key_lifetime")

    if lifetime:

        add_finding(
            "GOOD",
            "SA key lifetime detected",
            f"Detected lifetime: {lifetime}."
        )

    else:

        unknown_count += 1

        add_finding(
            "UNKNOWN",
            "SA key lifetime unknown",
            "The key lifetime could not be determined from the available packet capture."
        )

    # -------------------------
    # Authentication
    # -------------------------

    authentication = crypto.get("authentication")

    if authentication:

        add_finding(
            "GOOD",
            "Authentication method detected",
            f"Detected authentication method: {authentication}."
        )

    else:

        unknown_count += 1

        add_finding(
            "UNKNOWN",
            "Authentication method unknown",
            "The authentication method could not be determined from the capture."
        )

    # -------------------------
    # Metadata exposure
    # -------------------------

    esp_count = analysis.get("esp", {}).get("packet_count", 0)
    if esp_count > 0:

        add_finding(
            "MEDIUM",
            "Encrypted traffic metadata remains visible",
            f"{esp_count} ESP packets were observed. IP addresses, packet sizes, timing and traffic volume remain observable even though payload contents are encrypted."
        )

        add_threat(
            "Traffic analysis / metadata exposure",
            "MEDIUM",
            "Encrypted IPsec traffic can still expose communication endpoints, packet sizes, timing and volume patterns."
        )

        add_recommendation(
            "Use traffic padding, aggregation or other traffic-analysis-resistant techniques when metadata confidentiality is required."
        )

    else:

        add_finding(
            "UNKNOWN",
            "Metadata exposure could not be assessed",
            "No ESP traffic was available for metadata analysis."
        )

    # -------------------------
    # IPsec traffic
    # -------------------------

    if esp_count > 0:

        add_finding(
            "GOOD",
            "ESP traffic detected",
            f"{esp_count} ESP packets were observed in the capture."
        )

    # -------------------------
    # Compliance
    # -------------------------

    compliance = "PASS"

    if encryption == "AES-CBC":
        compliance = "REVIEW"

    if dh_group in ["MODP768", "MODP1024"]:
        compliance = "FAIL"

    if version and version != "IKEv2":
        compliance = "FAIL"

    if unknown_count > 0 and compliance == "PASS":
        compliance = "INCOMPLETE"

    # -------------------------
    # Final risk
    # -------------------------

    score = max(0, min(100, score))

    if score >= 90:
        risk = "LOW"

    elif score >= 70:
        risk = "MEDIUM"

    else:
        risk = "HIGH"

    # -------------------------
    # Assessment status
    # -------------------------

    if unknown_count > 0:
        assessment_status = "INCOMPLETE"
    else:
        assessment_status = "COMPLETE"

    # -------------------------
    # Return
    # -------------------------

    return {
        "score": score,
        "risk": risk,
        "assessment_status": assessment_status,
        "unknown_count": unknown_count,
        "compliance": compliance,
        "findings": findings,
        "threats": threats,
        "recommendations": recommendations
    }


if __name__ == "__main__":

    import analyzer

    analysis = analyzer.analyze_pcap(
       "data/full_capture.pcap"
    )

    security = assess_security(analysis)

    print("\nSecurity Assessment")
    print("===================")

    print("Security Score:", security["score"])
    print("Risk:", security["risk"])
    print("Compliance:", security["compliance"])
    print("Assessment:", security["assessment_status"])
    print("Unknown properties:", security["unknown_count"])

    print("\nFindings")
    print("--------")

    for finding in security["findings"]:

        print(
            f"[{finding['severity']}] "
            f"{finding['title']}: "
            f"{finding['detail']}"
        )

    print("\nThreats")
    print("-------")

    for threat in security["threats"]:

        print(
            f"[{threat['severity']}] "
            f"{threat['threat']}: "
            f"{threat['detail']}"
        )

    print("\nRecommendations")
    print("----------------")

    for recommendation in security["recommendations"]:

        print("-", recommendation)