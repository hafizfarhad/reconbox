"""
Web-recon phase. Only runs when target.is_domain_target is True
(no point crawling/fingerprinting a bare IP with no vhost).

The web endpoints to probe are derived from the open web ports the
network-scan phase found, NOT hardcoded to https://:443. A host serving only
plain HTTP on :80 (or HTTPS on a non-standard port) is probed on the scheme and
port it actually listens on -- otherwise every active tool targets a closed
:443 and the whole phase comes back empty.
"""

import os

from modules.executor import run_tool
from modules.cdn import cdn_for_ip
from config.settings import TIMEOUTS, DEFAULT_FFUF_WORDLIST, FFUF_EXTENSIONS

# Ports/services we treat as TLS ("https") vs plain HTTP.
_HTTPS_PORTS = {"443", "8443", "4443", "9443"}
_HTTP_PORTS = {"80", "8080", "8000", "8008", "8888", "8081"}

# Hard cap on how many web endpoints get the full active toolchain, so a host
# exposing many web ports (esp. a CDN edge) can't turn web-recon into an
# N x 15-minute ffuf loop.
_MAX_ENDPOINTS = 4


def _web_targets(domain, net_summary):
    """
    Build the list of base URLs to probe from the open TCP ports.

    net_summary is None  -> no scan context; probe both https:// and http://
                            (don't assume TLS).
    net_summary provided -> derive strictly from open web ports; may be empty
                            when the host exposes no web port at all.
    """
    if net_summary is None:
        return [f"https://{domain}", f"http://{domain}"]

    open_ports = net_summary.get("open_ports") or []
    services = net_summary.get("services") or {}

    targets = []
    for pk in open_ports:
        if not pk.endswith("/tcp"):
            continue
        num = pk.split("/")[0]
        svc = (services.get(pk) or "").lower()
        is_https = num in _HTTPS_PORTS or "https" in svc or "ssl" in svc
        # http-detection must not fire on "https" (which also contains "http").
        is_http = num in _HTTP_PORTS or (("http" in svc) and not is_https)
        if not (is_https or is_http):
            continue
        scheme = "https" if is_https else "http"
        if (scheme == "https" and num == "443") or (scheme == "http" and num == "80"):
            url = f"{scheme}://{domain}"
        else:
            url = f"{scheme}://{domain}:{num}"
        if url not in targets:
            targets.append(url)
    return targets


def _url_tag(url):
    """https://h:8443 -> 'https_8443'; https://h -> 'https_443'; http://h -> 'http_80'."""
    scheme = "https" if url.startswith("https") else "http"
    rest = url.split("://", 1)[1]
    if ":" in rest:
        port = rest.split(":", 1)[1].rstrip("/")
    else:
        port = "443" if scheme == "https" else "80"
    return f"{scheme}_{port}"


def _dedupe_scheme(targets):
    """Keep at most one http:// and one https:// endpoint (the first of each)."""
    seen, out = set(), []
    for t in targets:
        scheme = "https" if t.startswith("https") else "http"
        if scheme not in seen:
            seen.add(scheme)
            out.append(t)
    return out


def _probe_endpoint(url, phase_dir, error_log, config, summary, skip_ffuf=False):
    """Run the active HTTP tools (httpx, whatweb, katana, ffuf) against one URL."""
    tag = _url_tag(url)

    # ---- httpx: liveness + basic fingerprint ------------------------------
    httpx_result = run_tool(
        "httpx",
        ["httpx", "-u", url, "-title", "-tech-detect", "-status-code", "-silent"],
        output_path=os.path.join(phase_dir, f"01_{tag}_httpx.txt"),
        timeout=TIMEOUTS["default"],
        error_log=error_log,
    )
    summary["steps"].append({"step": "httpx", "target": url, "result": repr(httpx_result)})

    # ---- whatweb: secondary fingerprint (different data source) -----------
    whatweb_result = run_tool(
        "whatweb",
        ["whatweb", url],
        output_path=os.path.join(phase_dir, f"02_{tag}_whatweb.txt"),
        timeout=TIMEOUTS["default"],
        error_log=error_log,
    )
    summary["steps"].append({"step": "whatweb", "target": url, "result": repr(whatweb_result)})

    # ---- katana: JS-aware crawl for endpoints ------------------------------
    katana_result = run_tool(
        "katana",
        ["katana", "-u", url, "-silent"],
        output_path=os.path.join(phase_dir, f"03_{tag}_katana_crawl.txt"),
        timeout=TIMEOUTS["nmap_deep"],  # crawling can be slow; reuse the long timeout
        error_log=error_log,
    )
    summary["steps"].append({"step": "katana", "target": url, "result": repr(katana_result)})

    # ---- ffuf: active content discovery (dirs + files) ---------------------
    # Read-only GET brute-force. -ac auto-calibrates against wildcard responses
    # to cut false positives; JSON goes to its own file, readable results to
    # stdout capture. Loud but non-exploitative.
    if skip_ffuf:
        summary["steps"].append({
            "step": "ffuf", "target": url,
            "detail": "Skipped -- target is a CDN edge; fuzzing it is rate-limited "
                      "and only probes the CDN, not the origin.",
        })
        return
    wordlist = config.get("ffuf_wordlist") or DEFAULT_FFUF_WORDLIST
    if os.path.isfile(wordlist):
        ffuf_json = os.path.join(phase_dir, f"05_{tag}_ffuf.json")
        ffuf_result = run_tool(
            "ffuf",
            ["ffuf", "-u", f"{url.rstrip('/')}/FUZZ", "-w", wordlist,
             "-e", FFUF_EXTENSIONS,
             "-mc", "200,204,301,302,307,401,403,405",
             "-ac", "-t", "40", "-timeout", "10",
             "-o", ffuf_json, "-of", "json", "-s"],
            output_path=os.path.join(phase_dir, f"05_{tag}_ffuf_content.txt"),
            timeout=TIMEOUTS["ffuf"],
            error_log=error_log,
        )
        summary["steps"].append({"step": "ffuf", "target": url,
                                 "result": repr(ffuf_result), "wordlist": wordlist})
    else:
        summary["steps"].append({
            "step": "ffuf", "target": url,
            "detail": f"Skipped -- wordlist not found: {wordlist}",
        })


def run_web_recon(target, phase_dir, error_log, config=None, net_summary=None):
    os.makedirs(phase_dir, exist_ok=True)
    config = config or {}
    domain = target.domain
    summary = {"phase": "web-recon", "steps": []}

    if not domain:
        summary["skipped"] = "No domain available for this target."
        return summary

    # If the operator already handed us a full URL, honor it verbatim.
    if domain.startswith("http"):
        targets = [domain]
    else:
        targets = _web_targets(domain, net_summary)

    # CDN awareness: if the target resolved to a CDN edge (e.g. Cloudflare), the
    # scan describes the CDN, not the origin. Fingerprint one endpoint per
    # scheme but skip ffuf (fuzzing a rate-limiting edge is pointless and was
    # turning web-recon into an N x 15-minute loop).
    cdn = cdn_for_ip(target.ip)
    skip_ffuf = bool(cdn)
    if cdn:
        summary["cdn"] = cdn
        summary["cdn_note"] = (
            f"Target resolved to a {cdn} edge IP ({target.ip}). These results "
            f"describe the {cdn} CDN, NOT keenu's origin server. Endpoints were "
            f"deduped to one per scheme and active content discovery (ffuf) was "
            f"skipped. To assess the real origin, scan its direct IP from an "
            f"allowed network path.")
        targets = _dedupe_scheme(targets)

    # Governor: never run the full toolchain against more than _MAX_ENDPOINTS.
    if len(targets) > _MAX_ENDPOINTS:
        summary["endpoints_capped"] = {"found": len(targets), "probed": _MAX_ENDPOINTS}
        targets = targets[:_MAX_ENDPOINTS]
    summary["web_targets"] = targets

    # Active HTTP tools only make sense against a discovered web endpoint.
    if targets:
        for url in targets:
            _probe_endpoint(url, phase_dir, error_log, config, summary,
                            skip_ffuf=skip_ffuf)
    else:
        summary["steps"].append({
            "step": "active_http",
            "detail": "Skipped -- no open web port (80/443/8080/...) found on the "
                      "target, so httpx/whatweb/katana/ffuf would only hit a closed "
                      "port. gau (passive) still runs below.",
        })

    # ---- gau: historical/archived URLs (passive, domain-based) -------------
    # Independent of the live web port -- always worth running for a domain.
    gau_result = run_tool(
        "gau",
        ["gau", domain],
        output_path=os.path.join(phase_dir, "04_gau_urls.txt"),
        timeout=TIMEOUTS["default"],
        error_log=error_log,
    )
    summary["steps"].append({"step": "gau", "result": repr(gau_result)})

    return summary
