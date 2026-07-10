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
from config.settings import (
    TIMEOUTS, DEFAULT_SUBDOMAIN_WORDLIST, SUBDOMAIN_BRUTE_MAX,
)


def run_dns_recon(target, phase_dir, error_log, config=None):
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

    # ---- Deeper DNS: ANY, version.bind, per-NS AXFR, subdomain brute ------
    _deep_dns(domain, phase_dir, error_log, config, summary)

    return summary


def _extract_subdomains(subfinder_stdout):
    if not subfinder_stdout:
        return []
    return [line.strip() for line in subfinder_stdout.splitlines() if line.strip()]


def _deep_dns(domain, phase_dir, error_log, config, summary):
    config = config or {}

    # Full ANY dump (server discloses whatever records it's willing to).
    run_tool("dig-ANY", ["dig", "ANY", domain, "+noall", "+answer"],
             output_path=os.path.join(phase_dir, "05_dig_ANY.txt"),
             timeout=TIMEOUTS["default"], error_log=error_log)

    # Enumerate the domain's nameservers, then try an AXFR zone transfer and a
    # version.bind query against each one.
    ns_result = run_tool("dig-ns-list", ["dig", "NS", domain, "+short"],
                         timeout=TIMEOUTS["default"], error_log=error_log)
    nameservers = [l.strip().rstrip(".") for l in (ns_result.stdout or "").splitlines() if l.strip()]
    summary["nameservers"] = nameservers

    transfers = []
    for ns in nameservers:
        axfr = run_tool(
            f"dig-axfr-{ns}", ["dig", "AXFR", domain, f"@{ns}"],
            output_path=os.path.join(phase_dir, f"06_axfr_{_safe(ns)}.txt"),
            timeout=TIMEOUTS["default"], error_log=error_log)
        out = axfr.stdout or ""
        succeeded = axfr.ok and "XFR size" in out and "Transfer failed" not in out
        transfers.append({"nameserver": ns, "zone_transfer_succeeded": succeeded})
        run_tool(
            f"dig-version-{ns}",
            ["dig", "CH", "TXT", "version.bind", f"@{ns}", "+short"],
            output_path=os.path.join(phase_dir, f"07_version_{_safe(ns)}.txt"),
            timeout=TIMEOUTS["default"], error_log=error_log)
    summary["zone_transfers"] = transfers

    # Active subdomain brute-force via dnsx over a wordlist of candidates.
    wordlist = config.get("subdomain_wordlist") or DEFAULT_SUBDOMAIN_WORDLIST
    _subdomain_brute(domain, phase_dir, error_log, wordlist, summary)


def _subdomain_brute(domain, phase_dir, error_log, wordlist, summary):
    if not os.path.isfile(wordlist):
        summary["subdomain_brute"] = f"skipped -- wordlist not found: {wordlist}"
        return

    candidates_path = os.path.join(phase_dir, "_brute_candidates.txt")
    count = 0
    with open(wordlist, errors="replace") as src, open(candidates_path, "w") as out:
        for line in src:
            word = line.strip()
            if not word or word.startswith("#"):
                continue
            out.write(f"{word}.{domain}\n")
            count += 1
            if count >= SUBDOMAIN_BRUTE_MAX:
                break

    result = run_tool(
        "dnsx-brute", ["dnsx", "-l", candidates_path, "-silent", "-a", "-resp"],
        output_path=os.path.join(phase_dir, "08_subdomain_brute.txt"),
        timeout=TIMEOUTS["subdomain_brute"], error_log=error_log)
    resolved = len([l for l in (result.stdout or "").splitlines() if l.strip()])
    summary["subdomain_brute"] = {
        "wordlist": wordlist, "candidates": count,
        "resolved_lines": resolved, "result": repr(result),
    }


def _safe(name):
    import re
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name)
