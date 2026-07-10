"""Threat intelligence enrichment helpers."""

from ipaddress import ip_address


KNOWN_BAD_IPS = {
    "127.0.0.2": "Loopback test indicator",
}


def lookup_indicator(indicator):
    indicator = indicator.strip()
    verdict = {
        "indicator": indicator,
        "risk_score": 10,
        "source": "local heuristic",
        "tags": [],
        "summary": "No external intelligence provider configured.",
    }

    if indicator in KNOWN_BAD_IPS:
        verdict["risk_score"] = 90
        verdict["tags"] = ["known-bad"]
        verdict["summary"] = KNOWN_BAD_IPS[indicator]
        return verdict

    try:
        ip_address(indicator)
        verdict["risk_score"] = 35
        verdict["tags"] = ["ip"]
        verdict["summary"] = "IP address analyzed with local heuristics."
    except ValueError:
        if "." in indicator or "/" in indicator:
            verdict["risk_score"] = 30
            verdict["tags"] = ["domain-or-network"]
            verdict["summary"] = "Domain/network analyzed with local heuristics."

    return verdict