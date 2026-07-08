"""
Web-recon phase. Only runs when target.is_domain_target is True
(no point crawling/fingerprinting a bare IP with no vhost).
"""

import os

from modules.executor import run_tool
from config.settings import TIMEOUTS


def run_web_recon(target, phase_dir, error_log):
    os.makedirs(phase_dir, exist_ok=True)
    domain = target.domain
    summary = {"phase": "web-recon", "steps": []}

    if not domain:
        summary["skipped"] = "No domain available for this target."
        return summary

    url = domain if domain.startswith("http") else f"https://{domain}"

    # ---- httpx: liveness + basic fingerprint ------------------------------
    httpx_result = run_tool(
        "httpx",
        ["httpx", "-u", url, "-title", "-tech-detect", "-status-code", "-silent"],
        output_path=os.path.join(phase_dir, "01_httpx.txt"),
        timeout=TIMEOUTS["default"],
        error_log=error_log,
    )
    summary["steps"].append({"step": "httpx", "result": repr(httpx_result)})

    # ---- whatweb: secondary fingerprint (different data source) -----------
    whatweb_result = run_tool(
        "whatweb",
        ["whatweb", url],
        output_path=os.path.join(phase_dir, "02_whatweb.txt"),
        timeout=TIMEOUTS["default"],
        error_log=error_log,
    )
    summary["steps"].append({"step": "whatweb", "result": repr(whatweb_result)})

    # ---- katana: JS-aware crawl for endpoints ------------------------------
    katana_result = run_tool(
        "katana",
        ["katana", "-u", url, "-silent"],
        output_path=os.path.join(phase_dir, "03_katana_crawl.txt"),
        timeout=TIMEOUTS["nmap_deep"],  # crawling can be slow; reuse the long timeout
        error_log=error_log,
    )
    summary["steps"].append({"step": "katana", "result": repr(katana_result)})

    # ---- gau: historical/archived URLs -------------------------------------
    gau_result = run_tool(
        "gau",
        ["gau", domain],
        output_path=os.path.join(phase_dir, "04_gau_urls.txt"),
        timeout=TIMEOUTS["default"],
        error_log=error_log,
    )
    summary["steps"].append({"step": "gau", "result": repr(gau_result)})

    return summary
