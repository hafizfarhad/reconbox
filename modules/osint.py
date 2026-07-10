"""
Passive OSINT / domain-information phase (domain targets only).

Fully passive: no packets to the target's own services beyond a single TLS
handshake for certificate inspection. Sources:
  - crt.sh Certificate Transparency logs -> subdomains
  - SSL/TLS certificate SANs (Subject Alternative Names) + issuer/org
  - Shodan host lookup (only if the operator supplied an API key)

Discovered subdomains are written out so a later run / synthesis stage can
feed them back into resolution.
"""

import os
import json

from modules.executor import run_tool
from config.settings import TIMEOUTS


def run_osint(target, phase_dir, error_log, config=None):
    os.makedirs(phase_dir, exist_ok=True)
    config = config or {}
    domain = target.domain
    summary = {"phase": "osint", "steps": []}

    if not domain:
        summary["skipped"] = "No domain for this target (IP-only)."
        return summary

    _crtsh(domain, phase_dir, error_log, summary)
    _cert_sans(target, phase_dir, error_log, summary)
    _shodan(target, phase_dir, error_log, config, summary)
    return summary


def _crtsh(domain, phase_dir, error_log, summary):
    result = run_tool(
        "crtsh-curl",
        ["curl", "-s", "--max-time", "45",
         f"https://crt.sh/?q=%25.{domain}&output=json"],
        output_path=os.path.join(phase_dir, "01_crtsh.json"),
        timeout=TIMEOUTS["crtsh"], error_log=error_log)

    subs = set()
    try:
        for entry in json.loads(result.stdout or "[]"):
            for field in ("common_name", "name_value"):
                val = entry.get(field, "")
                # crt.sh escapes multiple SANs as \n inside the JSON string;
                # json.loads has already turned those into real newlines.
                for name in val.split("\n"):
                    name = name.strip().lstrip("*.").lower()
                    if name.endswith(domain):
                        subs.add(name)
    except (ValueError, AttributeError, TypeError):
        pass

    if subs:
        with open(os.path.join(phase_dir, "02_crtsh_subdomains.txt"), "w") as f:
            f.write("\n".join(sorted(subs)) + "\n")
    summary["steps"].append({"step": "crtsh", "result": repr(result),
                             "unique_subdomains": len(subs)})


def _cert_sans(target, phase_dir, error_log, summary):
    # Grab the leaf cert from the HTTPS service and record it raw; SANs and
    # issuer/org are visible in the captured text for the synthesis stage.
    host = target.domain or target.ip
    result = run_tool(
        "openssl-cert",
        ["openssl", "s_client", "-connect", f"{host}:443", "-servername", host],
        output_path=os.path.join(phase_dir, "03_tls_certificate.txt"),
        timeout=20, error_log=error_log)
    summary["steps"].append({"step": "cert_sans", "result": repr(result)})


def _shodan(target, phase_dir, error_log, config, summary):
    key = config.get("shodan_api_key")
    if not key:
        summary["steps"].append({"step": "shodan", "detail": "skipped -- no API key configured"})
        return
    if not target.ip:
        summary["steps"].append({"step": "shodan", "detail": "skipped -- no IP resolved"})
        return
    result = run_tool(
        "shodan-host",
        ["curl", "-s", "--max-time", "45",
         f"https://api.shodan.io/shodan/host/{target.ip}?key={key}"],
        output_path=os.path.join(phase_dir, "04_shodan.json"),
        timeout=TIMEOUTS["shodan"], error_log=error_log)
    summary["steps"].append({"step": "shodan", "result": repr(result)})
