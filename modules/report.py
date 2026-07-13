"""
Report phase — turns the collected evidence into a single clean PDF.

Model (same shape as MobSF's: data -> HTML template -> converter):
  1. Gather findings from the run manifest + the nmap XML we already parse +
     the raw evidence files on disk.
  2. Render one HTML document (Jinja2, autoescaped) with print CSS.
  3. Convert to PDF with WeasyPrint.

Design choices that matter:
  * Autoescaping is ON. Tool output is untrusted (it comes from the target),
    so every value is HTML-escaped before it reaches the renderer.
  * Structured tables are built only from data we can parse reliably (nmap
    XML: ports/services/versions/OS/CVEs; and the manifest summaries for
    DNS/subdomains/evasion/OSINT). Everything else is embedded as the full,
    formatted tool output so nothing is lost when the raw files are deleted.
  * Per-service structured parsers are pluggable via SERVICE_PARSERS — add a
    function there to promote a service's raw output into a findings table.
"""

import os
import re
import glob

from modules.nmap_xml import parse_scan
from modules import severity

CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,7})(?:\s+(\d+\.\d+))?")
_MAX_BLOCK_CHARS = 20000  # cap embedded raw output per file so the PDF stays sane

# Terminal ANSI/VT100 escape sequences (color codes etc.). Tools like ssh-audit
# and whatweb emit these; embedded verbatim they render as visible garbage in
# the HTML/PDF, so we strip them before display.
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------
def _read(path, cap=_MAX_BLOCK_CHARS):
    try:
        with open(path, "r", errors="replace") as f:
            data = f.read()
    except OSError:
        return None
    data = _ANSI_RE.sub("", data)
    if len(data) > cap:
        data = data[:cap] + f"\n... [truncated, {len(data)} bytes total]"
    return data


def _pre(label, path):
    """A formatted-output block from a file, or None if the file is empty/missing."""
    text = _read(path)
    if not text or not text.strip():
        return None
    return {"type": "pre", "label": label, "text": text}


def _first_existing(*paths):
    for p in paths:
        if os.path.isfile(p):
            return p
    return None


# --------------------------------------------------------------------------
# section builders
# --------------------------------------------------------------------------
def _ports_source(d):
    """
    Return (ports_dict, os_matches) from the most accurate scan available:
    deep scan > merged full-sweep chunks > quick scan. The full sweep is now
    written as per-range chunks (03_full_tcp_sweep_c1.xml, ...), so we merge
    them rather than reading one file. Returns ({}, []) if nothing parseable.
    """
    deep = os.path.join(d, "06_deep_scan.xml")
    if os.path.isfile(deep):
        scan = parse_scan(deep)
        return scan.ports, scan.os_matches

    chunks = sorted(glob.glob(os.path.join(d, "03_full_tcp_sweep*.xml")))
    if chunks:
        merged = {}
        for c in chunks:
            merged.update(parse_scan(c).ports)
        return merged, []

    quick = os.path.join(d, "02_quick_scan.xml")
    if os.path.isfile(quick):
        scan = parse_scan(quick)
        return scan.ports, scan.os_matches

    return {}, []


def _ports_from_summary(net):
    """
    Build a port table from the manifest summary alone, used when the raw nmap
    files are gone or unparseable (removed by PDF-only cleanup, or left corrupt
    by a concurrent run). The summary is populated in-memory during the scan, so
    it still holds the ports we found even when the on-disk XML does not. Version
    and OS detail aren't carried in the summary, so those are omitted.
    """
    services = net.get("services") or {}
    rows = []
    seen = set()
    for portkey in net.get("open_ports") or []:
        seen.add(portkey)
        rows.append([portkey, "open", services.get(portkey, ""), ""])
    for portkey in net.get("udp_ports") or []:
        if portkey in seen:
            continue
        seen.add(portkey)
        rows.append([portkey, "open", services.get(portkey, ""), ""])
    rows.sort(key=lambda r: int(r[0].split("/")[0]))
    return rows


def _network_section(d, net):
    """d = network-scan dir, net = its manifest summary."""
    blocks = []

    # Port / service / version table, from the most accurate scan available.
    ports, os_matches = _ports_source(d)
    if ports:
        rows = []
        for portkey, info in sorted(ports.items(), key=lambda kv: int(kv[0].split("/")[0])):
            if info["state"] not in ("open", "open|filtered"):
                continue
            ver = " ".join(x for x in (info.get("product"), info.get("version")) if x)
            rows.append([portkey, info["state"], info.get("service") or "", ver])
        if rows:
            blocks.append({"type": "table",
                           "headers": ["Port", "State", "Service", "Version"],
                           "rows": rows})
        if os_matches:
            os_rows = [[m["name"], f"{m['accuracy']}%"] for m in os_matches[:5]]
            blocks.append({"type": "table", "headers": ["OS guess", "Accuracy"], "rows": os_rows})
    else:
        # Raw nmap XML missing or unparseable -- fall back to the manifest
        # summary so the captured ports still render instead of the whole
        # Network scan section silently vanishing.
        rows = _ports_from_summary(net)
        if rows:
            blocks.append({"type": "note",
                           "text": "Raw nmap output was unavailable at report time; "
                                   "ports below are from the run summary (version/OS "
                                   "detail omitted)."})
            blocks.append({"type": "table",
                           "headers": ["Port", "State", "Service", "Version"],
                           "rows": rows})

    # NOTE: CVE findings are no longer dumped as a flat table here. They are
    # classified into confirmed vs version-inferred tiers by
    # classify_network_findings() and rendered in the Findings summary section.

    # Evasion outcome (which technique revealed a filtered port).
    evasion = net.get("evasion") or []
    if evasion:
        rows = [[t["technique"], "yes" if t.get("got_through") else "no",
                 ", ".join(t.get("revealed_ports", [])) or "-"] for t in evasion]
        blocks.append({"type": "table",
                       "headers": ["Evasion technique", "Got through", "Revealed ports"],
                       "rows": rows})

    # Full formatted nmap output for each step (the complete record).
    for nmap_file in sorted(glob.glob(os.path.join(d, "*.nmap"))):
        b = _pre(os.path.basename(nmap_file), nmap_file)
        if b:
            blocks.append(b)

    return {"id": "network", "title": "Network scan", "blocks": blocks}


def classify_network_findings(d, enrich=True):
    """
    Parse 07_vuln_scan.xml and split its findings into two confidence tiers:
      - confirmed: behavioral --script vuln hits that report State: VULNERABLE
        (high confidence, QoD 100).
      - potential: bare `vulners` version-banner CVE matches (low confidence,
        QoD 30) — the noisy, false-positive-prone tier.
    Enriches all CVEs with EPSS + CISA KEV (best-effort) and ranks. Returns a
    dict {confirmed, potential, summary} or None if there is no vuln scan.
    """
    vxml = os.path.join(d, "07_vuln_scan.xml")
    if not os.path.isfile(vxml):
        return None
    vscan = parse_scan(vxml)

    confirmed = []
    heuristic = []
    potential = {}  # cve -> finding (dedup across ports/scripts)
    for portkey, scripts in vscan.port_scripts.items():
        for s in scripts:
            sid = (s.get("id") or "").lower()
            out = s.get("output") or ""
            cves = CVE_RE.findall(out)  # [(cve, score), ...]
            if sid == "vulners":
                for cve, score in cves:
                    if cve not in potential:
                        potential[cve] = {
                            "cve": cve, "cvss": score or None,
                            "band": severity.band_for_cvss(score or None),
                            "port": portkey, "script": sid,
                            "confidence": severity.CONF_INFERRED[0],
                            "qod": severity.CONF_INFERRED[1],
                        }
                continue

            # Behavioral vuln script. Trust nmap's own State field rather than a
            # substring match: only "State: VULNERABLE" is definitive. "LIKELY
            # VULNERABLE" / "UNKNOWN" (e.g. http-slowloris-check, which mis-fires
            # against CDNs/proxies) go to a separate heuristic tier, never
            # confirmed. "NOT VULNERABLE" is not a finding at all.
            state = _vuln_state(out)
            up = out.upper()
            if state and "NOT VULNERABLE" in state:
                continue
            if state is None and "VULNERABLE" not in up:
                continue
            is_confirmed = bool(state) and state.startswith("VULNERABLE")
            cve_ids = list(dict.fromkeys(c for c, _ in cves))  # dedupe, keep order
            scored = [c[1] for c in cves if c[1]]
            top_cvss = max(scored, key=lambda x: float(x)) if scored else None
            conf = severity.CONF_CONFIRMED if is_confirmed else severity.CONF_HEURISTIC
            rec = {
                "script": s.get("id"), "port": portkey, "cves": cve_ids,
                "cvss": top_cvss,
                "band": severity.band_for_cvss(top_cvss) if top_cvss else "Unknown",
                "confidence": conf[0], "qod": conf[1],
                "state": (state or "reported vulnerable").title(),
            }
            (confirmed if is_confirmed else heuristic).append(rec)

    # A CVE surfaced by a behavioral check must not also sit in the inferred pile.
    behavioral_cves = {c for f in (confirmed + heuristic) for c in f["cves"]}
    for cve in list(potential):
        if cve in behavioral_cves:
            del potential[cve]
    potential_list = list(potential.values())

    # Enrichment (best-effort; offline degrades to CVSS-only ordering).
    epss_map, kev = {}, set()
    if enrich and (potential_list or confirmed or heuristic):
        all_cves = [f["cve"] for f in potential_list]
        all_cves += [c for f in (confirmed + heuristic) for c in f["cves"]]
        try:
            epss_map = severity.enrich_epss(all_cves)
            kev = severity.load_kev()
        except Exception:
            epss_map, kev = {}, set()

    for f in potential_list:
        e = epss_map.get(f["cve"])
        f["epss"] = e["epss"] if e else None
        f["kev"] = f["cve"] in kev
    for f in (confirmed + heuristic):
        best = None
        is_kev = False
        for c in f["cves"]:
            e = epss_map.get(c)
            if e and (best is None or e["epss"] > best):
                best = e["epss"]
            if c in kev:
                is_kev = True
        f["epss"] = best
        f["kev"] = is_kev

    for lst in (potential_list, confirmed, heuristic):
        lst.sort(key=severity.priority_key, reverse=True)

    allf = potential_list + confirmed + heuristic
    summary = {
        "confirmed": len(confirmed),
        "heuristic": len(heuristic),
        "potential": len(potential_list),
        "kev": sum(1 for f in allf if f.get("kev")),
        "enriched": bool(epss_map or kev),
        "by_band": {b: sum(1 for f in allf if f.get("band") == b)
                    for b in severity.BANDS_HIGH_TO_LOW
                    if any(f.get("band") == b for f in allf)},
    }
    return {"confirmed": confirmed, "heuristic": heuristic,
            "potential": potential_list, "summary": summary}


_STATE_RE = re.compile(r"State:\s*(.+)")


def _vuln_state(output):
    """Extract nmap's vuln-library 'State:' value (e.g. VULNERABLE, LIKELY
    VULNERABLE, NOT VULNERABLE, UNKNOWN), upper-cased, or None if absent."""
    m = _STATE_RE.search(output or "")
    return m.group(1).strip().upper() if m else None


def _findings_section(classified):
    """Severity- & confidence-tiered findings, rendered as the report's lead section."""
    confirmed = classified["confirmed"]
    heuristic = classified.get("heuristic", [])
    potential = classified["potential"]
    summ = classified["summary"]
    blocks = []

    pairs = [("Confirmed vulnerabilities", summ["confirmed"])]
    if summ.get("heuristic"):
        pairs.append(("Heuristic (needs verification)", summ["heuristic"]))
    pairs.append(("Potential (version-inferred, unverified)", summ["potential"]))
    if summ.get("kev"):
        pairs.append(("On CISA KEV (known-exploited)", summ["kev"]))
    if not summ.get("enriched"):
        pairs.append(("EPSS / KEV enrichment",
                      "unavailable (offline) — ranked by CVSS only"))
    blocks.append({"type": "kv", "pairs": pairs})

    def _bh_rows(items):
        rows = []
        for f in items:
            cve_txt = ", ".join(f["cves"][:4]) + ("…" if len(f["cves"]) > 4 else "")
            rows.append([f.get("script") or "-", f["port"], f["band"],
                         f.get("cvss") or "-", "yes" if f.get("kev") else "",
                         cve_txt or "-"])
        return rows

    if confirmed:
        blocks.append({"type": "note",
                       "text": "CONFIRMED — nmap reported State: VULNERABLE (definitive):"})
        blocks.append({"type": "table",
                       "headers": ["Check", "Port", "Severity", "CVSS", "KEV", "CVEs"],
                       "rows": _bh_rows(confirmed)})

    if heuristic:
        blocks.append({"type": "note",
            "text": ("HEURISTIC — a check only SUSPECTED a vulnerability (nmap "
                     "'LIKELY VULNERABLE' / DoS-susceptibility guess). These mis-fire "
                     "against CDNs, proxies and load-balancers; verify before acting.")})
        blocks.append({"type": "table",
                       "headers": ["Check", "Port", "Severity", "CVSS", "KEV", "CVEs"],
                       "rows": _bh_rows(heuristic)})

    if potential:
        shown = min(len(potential), 25)
        blocks.append({"type": "note",
            "text": ("POTENTIAL — inferred from version banners (nmap vulners), NOT validated. "
                     "Distro backports mean many are likely already patched; verify before acting. "
                     f"Showing top {shown} of {len(potential)}, ranked by KEV / EPSS / CVSS.")})
        rows = []
        for f in potential[:25]:
            epss = f"{f['epss'] * 100:.1f}%" if f.get("epss") is not None else "-"
            rows.append([f["cve"], f["port"], f["band"], f.get("cvss") or "-",
                         "yes" if f.get("kev") else "", epss, f"{f['qod']}%"])
        blocks.append({"type": "table",
                       "headers": ["CVE", "Port", "Severity", "CVSS", "KEV", "EPSS", "Confidence"],
                       "rows": rows})
        if len(potential) > 25:
            blocks.append({"type": "note",
                           "text": f"… {len(potential) - 25} more version-inferred CVEs omitted (low confidence)."})

    return {"id": "findings", "title": "Findings summary (severity & confidence)",
            "blocks": blocks}


def _smb_parser(files):
    """Promote SMB output into a small findings table (shares + users)."""
    blocks = []
    shares, users = [], []
    for path in files:
        text = _read(path) or ""
        # rpcclient netshareenumall / smbclient -L
        shares += re.findall(r"netname:\s*(\S+)", text)
        shares += re.findall(r"^\s*(\S+)\s+Disk\s", text, re.M)
        # rpcclient enumdomusers -> user:[name] rid:[0x..]
        users += re.findall(r"user:\[([^\]]+)\]", text)
    shares = sorted(set(s for s in shares if s and s not in ("Disk",)))
    users = sorted(set(users))
    if shares:
        blocks.append({"type": "table", "headers": ["SMB share"], "rows": [[s] for s in shares]})
    if users:
        blocks.append({"type": "table", "headers": ["SMB user"], "rows": [[u] for u in users]})
    return blocks


# service key -> function(files) -> [blocks]. Extend to add structured parsing.
SERVICE_PARSERS = {"smb": _smb_parser}


def _service_section(d, svc):
    """d = service-enum dir, svc = its manifest summary."""
    if not os.path.isdir(d):
        return None
    blocks = []
    enumerated = svc.get("enumerated", [])
    if enumerated:
        blocks.append({"type": "note",
                       "text": "Services enumerated: " + ", ".join(sorted(set(enumerated)))})

    # Group evidence files by service key (filename convention: <port>_<svc>_...).
    files = [f for f in sorted(glob.glob(os.path.join(d, "*")))
             if os.path.isfile(f)]
    by_service = {}
    for f in files:
        name = os.path.basename(f)
        parts = name.split("_")
        svc_key = parts[1] if len(parts) > 1 else "misc"
        by_service.setdefault(svc_key, []).append(f)

    for svc_key in sorted(by_service):
        group = by_service[svc_key]
        blocks.append({"type": "note", "text": f"── {svc_key.upper()} ──"})
        # Structured findings if we have a parser for this service.
        parser = SERVICE_PARSERS.get(svc_key)
        if parser:
            blocks += parser(group)
        # Full formatted output for every evidence file (skip .xml/.gnmap dupes).
        for f in group:
            if f.endswith((".xml", ".gnmap")):
                continue
            b = _pre(os.path.basename(f), f)
            if b:
                blocks.append(b)

    return {"id": "services", "title": "Service enumeration", "blocks": blocks}


def _dns_section(d, dns):
    blocks = []
    if dns.get("nameservers"):
        blocks.append({"type": "table", "headers": ["Nameserver"],
                       "rows": [[ns] for ns in dns["nameservers"]]})
    zt = dns.get("zone_transfers") or []
    if zt:
        blocks.append({"type": "table", "headers": ["Nameserver", "Zone transfer"],
                       "rows": [[t["nameserver"],
                                 "SUCCEEDED" if t.get("zone_transfer_succeeded") else "refused"]
                                for t in zt]})
    sb = dns.get("subdomain_brute")
    if isinstance(sb, dict):
        blocks.append({"type": "kv", "pairs": [
            ("Subdomain brute wordlist", sb.get("wordlist")),
            ("Candidates tried", sb.get("candidates")),
            ("Resolved", sb.get("resolved_lines")),
        ]})
    for f in sorted(glob.glob(os.path.join(d, "*.txt"))):
        if os.path.basename(f).startswith("_"):
            continue
        b = _pre(os.path.basename(f), f)
        if b:
            blocks.append(b)
    return {"id": "dns", "title": "DNS reconnaissance", "blocks": blocks}


def _web_section(d, web):
    blocks = []
    if web.get("cdn_note"):
        blocks.append({"type": "note", "text": "⚠ " + web["cdn_note"]})
    for f in sorted(glob.glob(os.path.join(d, "*.txt"))):
        b = _pre(os.path.basename(f), f)
        if b:
            blocks.append(b)
    return {"id": "web", "title": "Web reconnaissance", "blocks": blocks}


def _osint_section(d, osint):
    blocks = []
    subs = os.path.join(d, "02_crtsh_subdomains.txt")
    if os.path.isfile(subs):
        b = _pre("crt.sh subdomains", subs)
        if b:
            blocks.append(b)
    cert = _pre("TLS certificate", os.path.join(d, "03_tls_certificate.txt"))
    if cert:
        blocks.append(cert)
    return {"id": "osint", "title": "Passive OSINT", "blocks": blocks}


# --------------------------------------------------------------------------
# assembly
# --------------------------------------------------------------------------
def _summary(target, phases, classified):
    net = next((p for p in phases if p.get("phase") == "network-scan"), {})
    svc = next((p for p in phases if p.get("phase") == "service-enum"), {})
    dns = next((p for p in phases if p.get("phase") == "dns-recon"), {})
    web = next((p for p in phases if p.get("phase") == "web-recon"), {})
    csumm = (classified or {}).get("summary", {})
    rows = [
        ("Target", target.get("raw_input")),
        ("Resolved domain", target.get("domain") or "—"),
        ("Resolved IP", target.get("ip") or "—"),
    ]
    if web.get("cdn"):
        rows.append(("CDN edge detected", f"{web['cdn']} — results reflect the CDN, not the origin"))
    rows += [
        ("Open TCP ports", len(net.get("open_ports", []))),
        ("Open UDP ports", len(net.get("udp_ports", []))),
    ]
    # Only surface the ambiguous count when there is one, and label it honestly
    # (nmap could not confirm these open vs filtered).
    udp_unconfirmed = len(net.get("udp_open_filtered", []))
    if udp_unconfirmed:
        rows.append(("UDP open|filtered (unconfirmed)", udp_unconfirmed))
    rows.append(("Confirmed vulnerabilities", csumm.get("confirmed", 0)))
    if csumm.get("heuristic"):
        rows.append(("Heuristic findings (needs verification)", csumm["heuristic"]))
    rows.append(("Potential CVEs (version-inferred, unverified)", csumm.get("potential", 0)))
    if csumm.get("kev"):
        rows.append(("On CISA KEV (known-exploited)", csumm["kev"]))
    rows += [
        ("Services enumerated", len(set(svc.get("enumerated", [])))),
        ("Subdomains (brute resolved)",
         (dns.get("subdomain_brute") or {}).get("resolved_lines")
         if isinstance(dns.get("subdomain_brute"), dict) else "—"),
    ]
    return rows


def build_context(target, dirs, manifest, enrich=True):
    phases = manifest.get("phases", [])

    def summ(name):
        return next((p for p in phases if p.get("phase") == name), {})

    # Classify vuln findings into confirmed vs version-inferred tiers (never
    # let enrichment or parsing break report generation).
    try:
        classified = classify_network_findings(dirs["network-scan"], enrich)
    except Exception:
        classified = None

    sections = []
    if classified and (classified["confirmed"] or classified.get("heuristic")
                       or classified["potential"]):
        sections.append(_findings_section(classified))
    sections.append(_network_section(dirs["network-scan"], summ("network-scan")))
    svc = _service_section(dirs["service-enum"], summ("service-enum"))
    if svc and svc["blocks"]:
        sections.append(svc)
    if os.path.isdir(dirs["dns-recon"]):
        sections.append(_dns_section(dirs["dns-recon"], summ("dns-recon")))
    if os.path.isdir(dirs["web-recon"]):
        sections.append(_web_section(dirs["web-recon"], summ("web-recon")))
    if os.path.isdir(dirs["osint"]):
        sections.append(_osint_section(dirs["osint"], summ("osint")))

    return {
        "target": manifest.get("target", {}),
        "started": manifest.get("target", {}).get("run_started"),
        "finished": manifest.get("run_finished"),
        "summary": _summary(manifest.get("target", {}), phases, classified),
        "sections": [s for s in sections if s and s["blocks"]],
    }


def render_html(context):
    # Imported here rather than at module top so a missing jinja2 degrades to
    # "no report" (raw evidence kept), like WeasyPrint does — instead of
    # blocking the whole run at import time. autoescape is always on because
    # the embedded tool output is untrusted (it comes from the target).
    from jinja2 import Environment
    env = Environment(autoescape=True)
    return env.from_string(_TEMPLATE).render(**context)


def generate_report(target, dirs, manifest, config=None, error_log=None):
    """
    Build report.pdf in the target's base dir. Returns a summary dict for the
    manifest; never raises. On any failure the PDF is simply not produced (and
    the caller keeps the raw evidence).
    """
    result = {"phase": "report"}
    # EPSS/KEV enrichment hits the network; allow disabling for offline/airgapped
    # runs. Default on.
    enrich = os.environ.get("RECONBOX_NO_ENRICH") != "1"
    try:
        html = render_html(build_context(target, dirs, manifest, enrich=enrich))
    except Exception as e:  # pragma: no cover - defensive
        result["error"] = f"HTML render failed: {type(e).__name__}: {e}"
        return result

    try:
        html_path = os.path.join(dirs["base"], "report.html")
        with open(html_path, "w") as f:
            f.write(html)
        result["html"] = html_path
    except OSError as e:
        # Honor the "never raises" contract even if the HTML write fails.
        result["error"] = f"HTML write failed: {type(e).__name__}: {e}"
        result["pdf_ok"] = False
        return result

    try:
        import weasyprint
    except Exception as e:
        result["error"] = ("WeasyPrint not available -- wrote report.html only. "
                            f"({type(e).__name__}: {e})")
        result["pdf_ok"] = False
        return result

    pdf_path = os.path.join(dirs["base"], "report.pdf")
    try:
        weasyprint.HTML(string=html, base_url=dirs["base"]).write_pdf(pdf_path)
        result["pdf"] = pdf_path
        result["pdf_ok"] = True
    except Exception as e:
        result["error"] = f"PDF conversion failed: {type(e).__name__}: {e}"
        result["pdf_ok"] = False
    return result


# --------------------------------------------------------------------------
# template
# --------------------------------------------------------------------------
_TEMPLATE = """<!doctype html>
<html><head><meta charset="utf-8"><style>
  @page { size: A4; margin: 1.5cm 1.2cm;
          @bottom-right { content: "ReconBox report — page " counter(page) " / " counter(pages);
                          font-size: 8pt; color: #888; } }
  * { box-sizing: border-box; }
  body { font-family: "DejaVu Sans", Arial, sans-serif; font-size: 9.5pt;
         color: #1a1a1a; line-height: 1.4; }
  h1 { font-size: 20pt; margin: 0 0 2pt; color: #0f2b46; }
  h2 { font-size: 13pt; margin: 18pt 0 6pt; padding-bottom: 3pt;
       border-bottom: 2px solid #0f2b46; color: #0f2b46; page-break-after: avoid; }
  .sub { color: #555; font-size: 9pt; margin-bottom: 14pt; }
  table { border-collapse: collapse; width: 100%; margin: 6pt 0 12pt;
          font-size: 8.5pt; page-break-inside: auto; }
  th { background: #0f2b46; color: #fff; text-align: left; padding: 4pt 6pt; }
  td { padding: 3pt 6pt; border-bottom: 1px solid #e3e3e3; vertical-align: top;
       word-break: break-word; }
  tr:nth-child(even) td { background: #f6f8fa; }
  .kv td:first-child { font-weight: bold; width: 34%; color: #0f2b46; }
  pre { background: #f6f8fa; border: 1px solid #e3e3e3; border-left: 3px solid #0f2b46;
        padding: 6pt 8pt; font-family: "DejaVu Sans Mono", monospace; font-size: 7.5pt;
        white-space: pre-wrap; word-break: break-all; margin: 4pt 0 10pt;
        page-break-inside: avoid; }
  .lbl { font-family: "DejaVu Sans Mono", monospace; font-size: 8pt; color: #0f2b46;
         font-weight: bold; margin: 8pt 0 2pt; }
  .note { color: #444; margin: 6pt 0; font-weight: bold; }
  .summary { background: #f0f4f8; border: 1px solid #d0dae4; border-radius: 4px;
             padding: 4pt 10pt; }
</style></head><body>

<h1>ReconBox Report</h1>
<div class="sub">Target: <b>{{ target.raw_input }}</b>
  &nbsp;·&nbsp; started {{ started }} &nbsp;·&nbsp; finished {{ finished }}</div>

<h2>Executive summary</h2>
<table class="kv summary">
  {% for k, v in summary %}<tr><td>{{ k }}</td><td>{{ v }}</td></tr>{% endfor %}
</table>

{% for section in sections %}
<h2>{{ section.title }}</h2>
  {% for b in section.blocks %}
    {% if b.type == "table" %}
      <table><thead><tr>{% for h in b.headers %}<th>{{ h }}</th>{% endfor %}</tr></thead>
        <tbody>{% for row in b.rows %}<tr>{% for cell in row %}<td>{{ cell }}</td>{% endfor %}</tr>{% endfor %}</tbody>
      </table>
    {% elif b.type == "kv" %}
      <table class="kv">{% for k, v in b.pairs %}<tr><td>{{ k }}</td><td>{{ v }}</td></tr>{% endfor %}</table>
    {% elif b.type == "pre" %}
      <div class="lbl">{{ b.label }}</div><pre>{{ b.text }}</pre>
    {% elif b.type == "note" %}
      <div class="note">{{ b.text }}</div>
    {% endif %}
  {% endfor %}
{% endfor %}

</body></html>"""
