"""
Severity & confidence model for reconbox findings.

Implements the researched, standards-backed model (see the notes below each
block for the primary source):

1. SEVERITY BAND from the CVSS base score — FIRST.org's official qualitative
   bands, identical in CVSS v3.x and v4.0:
     None/Info 0.0 · Low 0.1-3.9 · Medium 4.0-6.9 · High 7.0-8.9 · Critical 9.0-10.0
   FIRST and NVD are explicit that a CVSS *base* score is a SEVERITY measure,
   NOT a risk score, and "should not be used alone." So we always pair it with
   a confidence tier and (when online) exploitation-likelihood signals.
   Source: https://www.first.org/cvss/specification-document ,
           https://nvd.nist.gov/vuln-metrics/cvss

2. CONFIDENCE TIER — modeled on Greenbone/OpenVAS "Quality of Detection" (QoD).
   Unauthenticated version-banner matching (nmap `vulners`) is inherently
   low-confidence and prone to false positives (esp. distro backports, where
   the banner version looks vulnerable but the package is patched). We separate
   behaviorally CONFIRMED findings from VERSION-INFERRED ones and default to
   surfacing only the confident tier.
   Source: https://docs.greenbone.net/GSM-Manual/gos-24.10/en/reports.html

3. ENRICHMENT — EPSS (probability of exploitation in the wild within 30 days)
   and CISA KEV (known-exploited catalog) to reprioritize the survivors rather
   than trust raw CVSS. Both are best-effort: an offline run degrades to
   CVSS-only ordering and never blocks report generation.
   Source: https://www.first.org/epss/ , https://api.first.org/data/v1/epss
"""

import json
import urllib.request
import urllib.parse

# --------------------------------------------------------------------------
# 1. Severity bands (FIRST.org official qualitative mapping)
# --------------------------------------------------------------------------
def band_for_cvss(score):
    """CVSS base score -> qualitative band. Returns 'Unknown' if unparseable."""
    if score is None or score == "":
        return "Unknown"
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "Unknown"
    if s <= 0.0:
        return "Info"
    if s < 4.0:
        return "Low"
    if s < 7.0:
        return "Medium"
    if s < 9.0:
        return "High"
    return "Critical"


# High-to-low ordering for sorting/summaries.
BAND_RANK = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1, "Unknown": 0}
BANDS_HIGH_TO_LOW = ["Critical", "High", "Medium", "Low", "Info", "Unknown"]


# --------------------------------------------------------------------------
# 2. Confidence tiers (Greenbone/OpenVAS QoD-style)
# --------------------------------------------------------------------------
# (label, quality-of-detection %). CONFIRMED comes from a behavioral check that
# asserted the host is definitively vulnerable (nmap "State: VULNERABLE").
# HEURISTIC is a check that only *suspected* it ("State: LIKELY VULNERABLE" /
# "UNKNOWN", or a DoS-susceptibility guess) — these mis-fire against proxies/
# CDNs/load-balancers, so they must NOT sit in the confirmed tier. INFERRED is
# a bare version-banner match.
CONF_CONFIRMED = ("Confirmed", 100)          # State: VULNERABLE (definitive)
CONF_HEURISTIC = ("Heuristic", 50)           # LIKELY VULNERABLE / DoS guess
CONF_VERSION_PATCH = ("Version (patch-aware)", 80)
CONF_INFERRED = ("Version-inferred", 30)     # bare vulners match; hidden by default

# Greenbone hides < 70% QoD by default; we mirror that: the inferred tier is
# collapsed into a clearly-labeled "verify before acting" appendix.
DEFAULT_DISPLAY_QOD = 70


# --------------------------------------------------------------------------
# 3. Enrichment (EPSS + CISA KEV) — best-effort, never raises
# --------------------------------------------------------------------------
_EPSS_API = "https://api.first.org/data/v1/epss"
_KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json")


def _http_json(url, timeout=20):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "reconbox"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", errors="replace"))
    except Exception:
        return None


def enrich_epss(cve_ids, timeout=20):
    """
    Map each CVE -> {'epss': 0-1 float, 'percentile': 0-1 float} via the free
    FIRST EPSS API (batched). Returns {} on any failure (offline / rate-limit).
    """
    out = {}
    ids = [c for c in dict.fromkeys(cve_ids) if c]
    for i in range(0, len(ids), 100):  # keep URLs a sane length
        chunk = ids[i:i + 100]
        url = _EPSS_API + "?cve=" + urllib.parse.quote(",".join(chunk))
        data = _http_json(url, timeout)
        if not data:
            continue
        for row in data.get("data", []):
            try:
                out[row["cve"]] = {"epss": float(row["epss"]),
                                   "percentile": float(row["percentile"])}
            except (KeyError, TypeError, ValueError):
                pass
    return out


def load_kev(timeout=20):
    """Set of CVE IDs in the CISA KEV catalog. Empty set on any failure."""
    data = _http_json(_KEV_URL, timeout)
    if not data:
        return set()
    return {v.get("cveID") for v in data.get("vulnerabilities", [])
            if v.get("cveID")}


# --------------------------------------------------------------------------
# Prioritization
# --------------------------------------------------------------------------
def priority_key(finding):
    """
    Sort key (descending) for ranking findings. Order of importance, per the
    research: known-exploited (KEV) first, then exploitation probability
    (EPSS), then CVSS severity. KEV is treated as a strong escalator, NOT an
    automatic severity override (that override is community convention, not a
    verified primary-source directive), so it leads the sort but does not
    rewrite the band.
    """
    return (
        1 if finding.get("kev") else 0,
        finding.get("epss") or -1.0,
        BAND_RANK.get(finding.get("band", "Unknown"), 0),
        float(finding.get("cvss") or 0.0),
    )
