"""Rule-based AI security assistant."""


def summarize_security_state(scan_results=None, vulnerability_results=None, malware_results=None, threat_results=None):
    scan_results = scan_results or {}
    vulnerability_results = vulnerability_results or []
    malware_results = malware_results or {}
    threat_results = threat_results or {}

    notes = []

    if vulnerability_results:
        high_risk = [item for item in vulnerability_results if item.get("severity") == "high"]
        if high_risk:
            notes.append(f"Found {len(high_risk)} high-risk exposure(s).")

    if malware_results.get("risk") == "high":
        notes.append("Malware scan shows high-risk indicators.")
    elif malware_results.get("risk") == "medium":
        notes.append("Malware scan shows suspicious indicators.")

    if threat_results.get("risk_score", 0) >= 70:
        notes.append("Threat intelligence lookup is high risk.")

    if not notes:
        notes.append("No critical signals detected from the latest checks.")

    recommendations = [
        "Patch exposed services and disable anything unused.",
        "Keep backups off-host and test restore procedures.",
        "Review authentication logs and enable alerts for critical events.",
    ]

    return {
        "summary": " ".join(notes),
        "recommendations": recommendations,
        "signals": {
            "scans": scan_results,
            "vulnerabilities": vulnerability_results,
            "malware": malware_results,
            "threat_intel": threat_results,
        },
    }