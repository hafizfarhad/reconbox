"""
DNS-recon phase. Only runs when target.is_domain_target is True.

Simpler than network-scan -- this is closer to a fixed sequence than
a branching tree, since there's no "firewall reaction" equivalent here.
The one real branch: subdomain enumeration only makes sense once we
have a domain, and dnsx only makes sense if subfinder actually found
something.
"""

import os

from modules.executor import run_tool
from config.settings import TIMEOUTS


def run_dns_recon(target, phase_dir, error_log):
    os.makedirs(phase_dir, exist_ok=True)
    domain = target.domain
    summary = {"phase": "dns-recon", "steps": []}

    if not domain:
        summary["skipped"] = "No domain available for this target."
        return summary

    # ---- whois ----------------------------------------------------------
    whois_result = run_tool(
        "whois",
        ["whois", domain],
        output_path=os.path.join(phase_dir, "01_whois.txt"),
        timeout=TIMEOUTS["default"],
        error_log=error_log,
    )
    summary["steps"].append({"step": "whois", "result": repr(whois_result)})

    # ---- dig: A, NS, MX, TXT ---------------------------------------------
    record_types = ["A", "NS", "MX", "TXT"]
    for rtype in record_types:
        result = run_tool(
            f"dig-{rtype}",
            ["dig", domain, rtype, "+noall", "+answer"],
            output_path=os.path.join(phase_dir, f"02_dig_{rtype}.txt"),
            timeout=TIMEOUTS["default"],
            error_log=error_log,
        )
        summary["steps"].append({"step": f"dig_{rtype}", "result": repr(result)})

    # ---- subfinder: passive subdomain enumeration ------------------------
    subfinder_output = os.path.join(phase_dir, "03_subfinder.txt")
    subfinder_result = run_tool(
        "subfinder",
        ["subfinder", "-d", domain, "-silent"],
        output_path=subfinder_output,
        timeout=TIMEOUTS["default"],
        error_log=error_log,
    )
    summary["steps"].append({"step": "subfinder", "result": repr(subfinder_result)})

    # ---- dnsx: resolve whatever subfinder found ---------------------------
    subdomains = _extract_subdomains(subfinder_result.stdout)
    if subdomains:
        dnsx_input = os.path.join(phase_dir, "_subdomains_found.txt")
        with open(dnsx_input, "w") as f:
            f.write("\n".join(subdomains))

        dnsx_result = run_tool(
            "dnsx",
            ["dnsx", "-l", dnsx_input, "-silent"],
            output_path=os.path.join(phase_dir, "04_dnsx_resolved.txt"),
            timeout=TIMEOUTS["default"],
            error_log=error_log,
        )
        summary["steps"].append({"step": "dnsx", "result": repr(dnsx_result)})
        summary["subdomains_found"] = len(subdomains)
    else:
        summary["steps"].append({
            "step": "dnsx",
            "detail": "Skipped -- subfinder returned no subdomains."
        })
        summary["subdomains_found"] = 0

    return summary


def _extract_subdomains(subfinder_stdout):
    if not subfinder_stdout:
        return []
    return [line.strip() for line in subfinder_stdout.splitlines() if line.strip()]
