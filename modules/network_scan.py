"""
Network-scan phase. This is the real decision tree, not a fixed pipeline,
and it implements the Nmap techniques from the "Network Enumeration with
Nmap" methodology (host discovery, host/port scanning, service/OS/NSE
enumeration, and firewall/IDS evasion) adapted to a single automated
target.

Output model
------------
Every nmap step writes nmap-native files via -oA (<name>.nmap / .gnmap /
.xml). We parse the .xml (modules/nmap_xml.py) to drive decisions, because
XML is structured and survives partial/timed-out scans better than
regex-over-stdout. After the run, each .xml is rendered to HTML with
xsltproc for human-readable reporting.

Flow
----
  1. Host discovery (-sn -PE --reason). If no reply, force -Pn on every
     later step (real hosts routinely drop ICMP) and note it.
  2. Privilege-aware port scan: SYN (-sS) when we have raw-socket
     privileges (root, as in the container), else a Connect scan (-sT).
       a. Quick top-100 scan (-F) for fast signal.
       b. Full 65535-port sweep (-p-) as the authoritative open-port list.
  3. UDP scan (-sU, top ports) -- admins often forget to filter UDP.
  4. Firewall detection: ACK scan (-sA). ACK is harder to filter than SYN;
     'unfiltered' vs 'filtered'/dropped replies reveal firewall behavior.
  5. Adaptive evasion (only when filtered ports / a firewall are seen):
     fragmentation (-f), decoys (-D RND:n), source-port 53 (--source-port),
     plus operator-supplied source-IP (-S/-e) and DNS-relay (--dns-server).
     Each technique is saved separately and we report which one (if any)
     newly revealed a filtered port. Revealed source-port ports are then
     confirmed with ncat.
  6. Deep scan on confirmed-open ports: -sV -sC -O --traceroute.
  7. Vulnerability assessment: --script vuln on open ports.

All raw-socket techniques (SYN/ACK/UDP/OS/frag/decoy/source-port/spoof)
require root; when unprivileged we fall back to a Connect scan and skip
the privileged techniques with a note in the manifest.
"""

import os
import glob
import ipaddress

from modules.executor import run_tool, tool_available
from modules.nmap_xml import parse_scan
from config.settings import (
    TIMEOUTS, DECOY_COUNT, EVASION_SOURCE_PORT, FAST_TIMING,
    FULL_SWEEP_MIN_RATE, FULL_SWEEP_CHUNKS, UDP_TOP_PORTS,
)


def _privileged():
    """Raw-socket scans (SYN/ACK/UDP/OS/evasion) need root."""
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _port_num(port_key):
    """'80/tcp' -> '80'."""
    return port_key.split("/")[0]


def _is_ipv6(host):
    """True only for a literal IPv6 address. Hostnames (and IPv4) return False;
    domain targets resolve via IPv4 (gethostbyname) so only an operator-supplied
    IPv6 literal reaches here."""
    try:
        return ipaddress.ip_address(host).version == 6
    except ValueError:
        return False


def _run_nmap(name, flags, host, phase_dir, out_name, timeout, error_log):
    """
    Run one nmap invocation with -oA (nmap writes its own .nmap/.gnmap/.xml),
    then parse the .xml. Returns (ToolResult, NmapScan). NmapScan is empty
    but valid if nmap was missing/timed out or the XML was unreadable.
    """
    base = os.path.join(phase_dir, out_name)
    # `--` ends option parsing so a target that begins with '-' (e.g. a hostile
    # PTR record) can never be interpreted as an nmap flag. -oA must precede
    # `--`; everything after it is treated strictly as a scan target.
    command = ["nmap"] + flags + ["-oA", base, "--", host]
    result = run_tool(name, command, output_path=None, timeout=timeout, error_log=error_log)
    scan = parse_scan(base + ".xml")
    return result, scan


def run_network_scan(target, phase_dir, error_log, config=None):
    """
    target    - Target object from resolver.py
    phase_dir - <output_root>/<label>/network-scan
    error_log - path to meta/errors.log
    config    - run configuration dict (from modules.config_wizard.load_config)

    Returns a summary dict describing what happened, for the run manifest.
    """
    config = config or {}
    os.makedirs(phase_dir, exist_ok=True)
    host = target.ip or target.domain

    # nmap refuses an IPv6 target unless it is told -6; without it every scan
    # below would non-zero-exit and the phase would produce nothing.
    ipv6 = _is_ipv6(host)

    privileged = _privileged()
    scan_type = "-sS" if privileged else "-sT"

    summary = {
        "phase": "network-scan",
        "privileged": privileged,
        "scan_type": "syn" if privileged else "connect",
        "steps": [],
    }
    if not privileged:
        summary["steps"].append({
            "step": "privilege_note",
            "detail": "Not running as root -- using TCP Connect scan (-sT) and "
                      "skipping raw-socket techniques (UDP, ACK, OS detection, "
                      "and all evasion). Run as root (the container does) for full coverage.",
        })

    # ---- Step 1: host discovery -------------------------------------
    sn_result, sn_scan = _run_nmap(
        "nmap-host-discovery",
        (["-6"] if ipv6 else []) + ["-sn", "-PE", "--reason"],
        host, phase_dir, "01_host_discovery",
        TIMEOUTS["nmap_ping"], error_log,
    )
    summary["steps"].append({
        "step": "host_discovery",
        "result": repr(sn_result),
        "host_up": sn_scan.host_up,
        "reason": sn_scan.host_reason,
    })

    if sn_result.missing or sn_result.timed_out:
        summary["aborted"] = "nmap unavailable or host discovery timed out"
        return summary

    force_pn = not sn_scan.host_up
    if force_pn:
        summary["steps"].append({
            "step": "liveness_note",
            "detail": "No reply to -sn (host may be dropping ICMP). Forcing -Pn "
                      "on all subsequent scans instead of skipping the target.",
        })

    # Common flags applied to every real scan below.
    def base_flags(*extra):
        flags = ["-n", "--reason"]  # -n: no DNS resolution (faster, quieter)
        if force_pn:
            flags.insert(0, "-Pn")
        if ipv6:
            flags.insert(0, "-6")
        return flags + list(extra)

    # ---- Step 2a: quick scan (top 100) --------------------------------
    quick_result, quick_scan = _run_nmap(
        "nmap-quick-scan",
        base_flags(scan_type, "-F", FAST_TIMING),
        host, phase_dir, "02_quick_scan",
        TIMEOUTS["nmap_quick"], error_log,
    )
    summary["steps"].append({"step": "quick_scan", "result": repr(quick_result)})

    if quick_result.missing or quick_result.timed_out:
        summary["aborted"] = "quick scan failed to produce usable output"
        return summary

    # ---- Step 2b: full 65535-port sweep (chunked) --------------------
    full_open, full_filtered, full_ports, full_steps = _run_full_sweep(
        scan_type, base_flags, host, phase_dir, error_log)
    summary["steps"].extend(full_steps)

    # Authoritative TCP port picture = union of quick + full.
    open_tcp = _merge_ports(quick_scan.open_ports, full_open)
    filtered_tcp = _merge_ports(quick_scan.filtered_ports, full_filtered)
    # A port confirmed open anywhere is not "filtered".
    filtered_tcp = [p for p in filtered_tcp if p not in open_tcp]

    summary["open_ports"] = open_tcp
    summary["filtered_ports"] = filtered_tcp

    # Service-name map (port/proto -> detected service) consumed by the
    # service-enum phase. Seed with quick/full -sV guesses; the deep scan and
    # UDP scan below override/extend it with more accurate detections.
    services = {}
    for ports in (quick_scan.ports, full_ports):
        for p, info in ports.items():
            if info["state"] == "open" and info.get("service"):
                services[p] = info["service"]
    summary["services"] = services

    # ---- Step 3: UDP scan --------------------------------------------
    if privileged:
        udp_result, udp_scan = _run_nmap(
            "nmap-udp-scan",
            base_flags("-sU", "--top-ports", str(UDP_TOP_PORTS), FAST_TIMING),
            host, phase_dir, "04_udp_scan",
            TIMEOUTS["nmap_udp"], error_log,
        )
        # Only "open" is a confirmed-open UDP port. "open|filtered" means nmap
        # got no response and cannot tell open from filtered -- reporting those
        # as "open" overstates exposure, so we track them separately.
        udp_open = udp_scan.ports_in_state("open")
        udp_open_filtered = udp_scan.ports_in_state("open|filtered")
        summary["steps"].append({"step": "udp_scan", "result": repr(udp_result)})
        summary["udp_ports"] = udp_open
        summary["udp_open_filtered"] = udp_open_filtered
        for p, info in udp_scan.ports.items():
            # Seed enumeration for both confirmed and ambiguous UDP ports.
            if info["state"] in ("open", "open|filtered") and info.get("service"):
                services[p] = info["service"]
    else:
        summary["steps"].append({
            "step": "udp_scan",
            "detail": "Skipped -- UDP scan (-sU) requires root.",
        })

    # ---- Step 4: firewall detection via ACK scan ----------------------
    firewall_detected = bool(filtered_tcp)
    if privileged:
        ack_result, ack_scan = _run_nmap(
            "nmap-ack-firewall-map",
            base_flags("-sA", "-F"),
            host, phase_dir, "05_firewall_ack",
            TIMEOUTS["nmap_ack"], error_log,
        )
        # In an ACK scan: 'unfiltered' => reply got through (stateless FW or none);
        # 'filtered' => no reply / ICMP-prohibited => a stateful firewall is dropping.
        # nmap collapses a large all-filtered result (e.g. "Not shown: 100
        # filtered ports") into <extraports> and lists no individual ports, so
        # we must use filtered_signal (individual + aggregate), not just
        # filtered_ports -- otherwise a fully-firewalled host reads as "no
        # firewall", the exact opposite of reality.
        ack_filtered = ack_scan.filtered_ports
        ack_filtered_aggregate = ack_scan.extra_filtered_count()
        firewall_via_ack = ack_scan.filtered_signal
        if firewall_via_ack:
            firewall_detected = True
        summary["steps"].append({
            "step": "firewall_ack_scan",
            "result": repr(ack_result),
            "filtered_via_ack": ack_filtered,
            "filtered_via_ack_aggregate": ack_filtered_aggregate,
            "interpretation": "Filtered/no-response to ACK indicates a stateful "
                              "firewall dropping packets."
                              if firewall_via_ack else
                              "ACK replies received (unfiltered) -- no stateful "
                              "drop detected on tested ports.",
        })
    else:
        summary["steps"].append({
            "step": "firewall_ack_scan",
            "detail": "Skipped -- ACK scan (-sA) requires root.",
        })

    # ---- Step 5: adaptive evasion (only if a firewall/filtered ports) --
    if firewall_detected and filtered_tcp and privileged and not ipv6:
        summary["steps"].append({
            "step": "evasion_branch",
            "detail": f"{len(filtered_tcp)} filtered port(s) / firewall detected -- "
                      f"escalating to evasion techniques against the filtered ports.",
        })
        evasion = _run_evasion(host, phase_dir, error_log, force_pn, scan_type,
                               filtered_tcp, set(open_tcp), config)
        summary["evasion"] = evasion["results"]
        summary["steps"].extend(evasion["steps"])
        # Fold any newly revealed ports into the authoritative open list.
        for tech in evasion["results"]:
            for port in tech["revealed_ports"]:
                if port not in open_tcp:
                    open_tcp.append(port)
        summary["open_ports"] = open_tcp
    elif firewall_detected and filtered_tcp and privileged and ipv6:
        summary["steps"].append({
            "step": "evasion_branch",
            "detail": "Filtered ports seen but the evasion techniques "
                      "(fragmentation, decoys, source-port) are IPv4-only -- "
                      "skipped for this IPv6 target.",
        })
    elif firewall_detected and filtered_tcp and not privileged:
        summary["steps"].append({
            "step": "evasion_branch",
            "detail": "Filtered ports seen but evasion requires root -- skipped.",
        })
    else:
        summary["steps"].append({
            "step": "evasion_branch",
            "detail": "No filtered ports / firewall signal -- evasion not needed.",
        })

    # ---- Step 6: deep scan on confirmed-open ports --------------------
    if open_tcp:
        port_list = ",".join(_port_num(p) for p in open_tcp)
        deep_extra = [scan_type, "-sV", "-sC", "-p", port_list]
        if privileged:
            deep_extra += ["-O", "--traceroute"]  # both need raw sockets
        deep_result, deep_scan = _run_nmap(
            "nmap-deep-scan",
            base_flags(*deep_extra),
            host, phase_dir, "06_deep_scan",
            TIMEOUTS["nmap_deep"], error_log,
        )
        # Accurate -sV names override the earlier quick/full guesses.
        for p, info in deep_scan.ports.items():
            if info.get("service"):
                services[p] = info["service"]
        summary["steps"].append({
            "step": "deep_scan",
            "result": repr(deep_result),
            "os_detection": privileged,
            "ports": port_list,
        })

        # ---- Step 7: vulnerability assessment (--script vuln) ----------
        vuln_result, _ = _run_nmap(
            "nmap-vuln-scan",
            base_flags(scan_type, "-sV", "--script", "vuln", "-p", port_list),
            host, phase_dir, "07_vuln_scan",
            TIMEOUTS["nmap_vuln"], error_log,
        )
        summary["steps"].append({"step": "vuln_scan", "result": repr(vuln_result)})
    else:
        summary["steps"].append({
            "step": "deep_scan",
            "detail": "Skipped -- no open TCP ports confirmed.",
        })

    # ---- Reporting: render every nmap XML to HTML ---------------------
    summary["html_reports"] = _generate_html_reports(phase_dir, error_log)

    return summary


def _merge_ports(*lists):
    """Union of port lists, order-preserving."""
    seen = []
    for lst in lists:
        for p in lst:
            if p not in seen:
                seen.append(p)
    return seen


def _run_full_sweep(scan_type, base_flags, host, phase_dir, error_log):
    """
    Full 1-65535 TCP sweep, split into FULL_SWEEP_CHUNKS contiguous port-range
    chunks run as separate nmap invocations (03_full_tcp_sweep_c1, _c2, ...).

    Why chunk: nmap flushes a host's port results -- and closes </host> in the
    XML -- only when that host's scan completes. A single monolithic -p- that
    hits its timeout therefore leaves an unterminated document with ZERO
    parseable ports, and everything the sweep found is lost. With chunks, each
    range that finishes has already written a complete, parseable XML, so a
    timeout costs only the one in-progress range. On the first timed-out chunk
    we stop -- a host slow enough to time out one range will time out the rest,
    and continuing would only burn the budget -- and record what went unscanned.

    The nmap_full time budget is divided evenly across the chunks so total
    wall-clock is unchanged from the old single-sweep behavior.

    Returns (open_ports, filtered_ports, ports_dict, step_records).
    """
    total_ports = 65535
    n = max(1, FULL_SWEEP_CHUNKS)
    chunk_size = -(-total_ports // n)  # ceil division
    per_chunk_timeout = max(60, TIMEOUTS["nmap_full"] // n)

    open_ports, filtered_ports, ports = [], [], {}
    steps = []
    start = 1
    idx = 0
    while start <= total_ports:
        idx += 1
        end = min(start + chunk_size - 1, total_ports)
        prange = f"{start}-{end}"
        result, scan = _run_nmap(
            f"nmap-full-sweep-{idx}",
            base_flags(scan_type, "-p", prange, FAST_TIMING,
                       "--min-rate", str(FULL_SWEEP_MIN_RATE)),
            host, phase_dir, f"03_full_tcp_sweep_c{idx}",
            per_chunk_timeout, error_log,
        )
        open_ports = _merge_ports(open_ports, scan.open_ports)
        filtered_ports = _merge_ports(filtered_ports, scan.filtered_ports)
        ports.update(scan.ports)
        steps.append({
            "step": f"full_tcp_sweep_chunk_{idx}",
            "ports": prange,
            "result": repr(result),
        })

        if result.timed_out:
            steps.append({
                "step": "full_tcp_sweep_incomplete",
                "detail": (f"Chunk {prange} timed out after {per_chunk_timeout}s. "
                           f"nmap flushes port results only at host completion, so "
                           f"this range contributed no ports; ports {end + 1}-"
                           f"{total_ports} were not scanned. Completed chunks above "
                           f"are unaffected. Raise the full-sweep timeout or "
                           f"--min-rate for deeper coverage."),
            })
            break
        start = end + 1

    return open_ports, filtered_ports, ports, steps


def _run_evasion(host, phase_dir, error_log, force_pn, scan_type,
                 filtered_ports, baseline_open, config):
    """
    Fire evasion techniques against the filtered ports and report which one
    (if any) newly revealed a previously-filtered port. Every technique's
    raw output is saved to its own file for human comparison.
    """
    pn = ["-Pn"] if force_pn else []
    port_arg = ["-p", ",".join(_port_num(p) for p in filtered_ports)]
    common = pn + ["-n", "--reason", scan_type] + port_arg

    decoys = config.get("decoy_count") or DECOY_COUNT
    src_port = config.get("source_port") or EVASION_SOURCE_PORT

    # (name, extra flags, output filename). Auto-safe techniques first.
    techniques = [
        ("fragmentation", ["-f"], "06a_evasion_fragmentation"),
        ("decoys", ["-D", f"RND:{decoys}"], "06b_evasion_decoys"),
        (f"source_port_{src_port}", ["--source-port", str(src_port)], "06c_evasion_source_port"),
    ]

    # Operator-supplied, config-gated techniques (off unless provided).
    if config.get("source_ip"):
        if config.get("interface"):
            techniques.append((
                "source_ip_spoof",
                ["-S", str(config["source_ip"]), "-e", str(config["interface"])],
                "06d_evasion_source_ip",
            ))
        else:
            # Can't spoof a source IP without an interface -- note and skip.
            techniques.append(("source_ip_spoof__skipped", None, None))
    if config.get("dns_server"):
        # --dns-server needs DNS resolution active, so drop -n for this one.
        techniques.append((
            "dns_relay",
            ["--dns-server", str(config["dns_server"])],
            "06e_evasion_dns_relay",
        ))

    results = []
    steps = []
    for name, extra, out_name in techniques:
        if extra is None:
            steps.append({
                "step": f"evasion_{name}",
                "detail": "Source-IP spoof requested but no interface (-e) provided; skipped.",
            })
            continue

        flags = list(common)
        if name == "dns_relay":
            flags = [f for f in flags if f != "-n"]  # let it actually resolve
        flags += extra

        result, scan = _run_nmap(
            f"nmap-evasion-{name}", flags, host, phase_dir, out_name,
            TIMEOUTS["nmap_evasion"], error_log,
        )
        revealed = [p for p in scan.open_ports if p not in baseline_open]
        results.append({
            "technique": name,
            "revealed_ports": revealed,
            "got_through": bool(revealed),
        })
        steps.append({
            "step": f"evasion_{name}",
            "result": repr(result),
            "revealed_ports": revealed,
        })

        # Confirm source-port-revealed ports with ncat, as the methodology does.
        if name.startswith("source_port") and revealed:
            steps.extend(_ncat_verify(host, revealed[:5], src_port, phase_dir, error_log))

    return {"results": results, "steps": steps}


def _ncat_verify(host, ports, src_port, phase_dir, error_log):
    """
    Confirm a port opened up via the source-port trick by actually
    connecting with ncat from that same source port and grabbing the banner.
    """
    steps = []
    if not tool_available("ncat"):
        steps.append({
            "step": "ncat_verify",
            "detail": "ncat not available -- skipping source-port connect verification.",
        })
        return steps

    for port in ports:
        pnum = _port_num(port)
        out = os.path.join(phase_dir, f"06c_ncat_verify_{pnum}.txt")
        result = run_tool(
            f"ncat-verify-{pnum}",
            ["ncat", "-nv", "--source-port", str(src_port), host, pnum],
            output_path=out, timeout=TIMEOUTS["ncat"], error_log=error_log,
        )
        steps.append({"step": f"ncat_verify_{pnum}", "result": repr(result)})
    return steps


def _generate_html_reports(phase_dir, error_log):
    """
    Render each nmap XML file to HTML via xsltproc, into network-scan/html/.
    Returns the list of HTML files produced (empty if xsltproc is missing).
    """
    if not tool_available("xsltproc"):
        return []

    html_dir = os.path.join(phase_dir, "html")
    os.makedirs(html_dir, exist_ok=True)
    produced = []
    for xml_path in sorted(glob.glob(os.path.join(phase_dir, "*.xml"))):
        name = os.path.splitext(os.path.basename(xml_path))[0]
        html_path = os.path.join(html_dir, f"{name}.html")
        result = run_tool(
            "xsltproc",
            ["xsltproc", xml_path, "-o", html_path],
            output_path=None, timeout=TIMEOUTS["xsltproc"], error_log=error_log,
        )
        if result.ok:
            produced.append(html_path)
    return produced
