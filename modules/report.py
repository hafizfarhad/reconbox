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

CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,7})(?:\s+(\d+\.\d+))?")
_MAX_BLOCK_CHARS = 20000  # cap embedded raw output per file so the PDF stays sane


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------
def _read(path, cap=_MAX_BLOCK_CHARS):
    try:
        with open(path, "r", errors="replace") as f:
            data = f.read()
    except OSError:
        return None
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
def _network_section(d, net):
    """d = network-scan dir, net = its manifest summary."""
    blocks = []

    # Port / service / version table (prefer the accurate deep scan).
    xml = _first_existing(os.path.join(d, "06_deep_scan.xml"),
                          os.path.join(d, "03_full_tcp_sweep.xml"),
                          os.path.join(d, "02_quick_scan.xml"))
    cve_rows = []
    if xml:
        scan = parse_scan(xml)
        rows = []
        for portkey, info in sorted(scan.ports.items(), key=lambda kv: int(kv[0].split("/")[0])):
            if info["state"] not in ("open", "open|filtered"):
                continue
            ver = " ".join(x for x in (info.get("product"), info.get("version")) if x)
            rows.append([portkey, info["state"], info.get("service") or "", ver])
        if rows:
            blocks.append({"type": "table",
                           "headers": ["Port", "State", "Service", "Version"],
                           "rows": rows})
        if scan.os_matches:
            os_rows = [[m["name"], f"{m['accuracy']}%"] for m in scan.os_matches[:5]]
            blocks.append({"type": "table", "headers": ["OS guess", "Accuracy"], "rows": os_rows})

    # CVEs from the vuln scan's NSE script output.
    vxml = os.path.join(d, "07_vuln_scan.xml")
    if os.path.isfile(vxml):
        vscan = parse_scan(vxml)
        seen = set()
        for portkey, scripts in vscan.port_scripts.items():
            for s in scripts:
                for cve, score in CVE_RE.findall(s["output"]):
                    if cve not in seen:
                        seen.add(cve)
                        cve_rows.append([cve, score or "-", portkey])
    if cve_rows:
        cve_rows.sort(key=lambda r: float(r[1]) if r[1] not in ("-", "") else -1, reverse=True)
        blocks.append({"type": "table", "headers": ["CVE", "CVSS", "Port"], "rows": cve_rows})

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

    return {"id": "network", "title": "Network scan", "blocks": blocks,
            "cves": len(cve_rows)}


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
def _summary(target, phases, sections):
    net = next((p for p in phases if p.get("phase") == "network-scan"), {})
    svc = next((p for p in phases if p.get("phase") == "service-enum"), {})
    dns = next((p for p in phases if p.get("phase") == "dns-recon"), {})
    net_section = next((s for s in sections if s["id"] == "network"), {})
    return [
        ("Target", target.get("raw_input")),
        ("Resolved domain", target.get("domain") or "—"),
        ("Resolved IP", target.get("ip") or "—"),
        ("Open TCP ports", len(net.get("open_ports", []))),
        ("Open UDP ports", len(net.get("udp_ports", []))),
        ("Likely CVEs flagged", net_section.get("cves", 0)),
        ("Services enumerated", len(set(svc.get("enumerated", [])))),
        ("Subdomains (brute resolved)",
         (dns.get("subdomain_brute") or {}).get("resolved_lines")
         if isinstance(dns.get("subdomain_brute"), dict) else "—"),
    ]


def build_context(target, dirs, manifest):
    phases = manifest.get("phases", [])

    def summ(name):
        return next((p for p in phases if p.get("phase") == name), {})

    sections = []
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
        "summary": _summary(manifest.get("target", {}), phases, sections),
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
    try:
        html = render_html(build_context(target, dirs, manifest))
    except Exception as e:  # pragma: no cover - defensive
        result["error"] = f"HTML render failed: {type(e).__name__}: {e}"
        return result

    html_path = os.path.join(dirs["base"], "report.html")
    with open(html_path, "w") as f:
        f.write(html)
    result["html"] = html_path

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
