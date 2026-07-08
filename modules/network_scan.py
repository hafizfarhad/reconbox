"""
Network-scan phase. This is the actual decision tree, not a fixed
pipeline:

  1. Host discovery (-sn). If no response, don't assume it's down --
     lots of real hosts drop ICMP. Fall back to -Pn and note that we
     forced it.
  2. Quick scan (-F, top 100 ports) to get fast signal.
  3. Branch on what we saw:
       - any 'filtered' ports -> looks like a firewall. Try evasion
         techniques (fragmentation, decoys, source-port tricks, ACK
         scan to map the ruleset) rather than just giving up.
       - open ports found -> queue them for deep inspection.
  4. Deep scan (-sV -sC) only on the ports we actually confirmed open,
     not a blind full-range scan. Full -p- is offered as an optional
     last resort, not the default (it's slow and usually low-yield
     once you've evasion-tested the fast scan).

Every step's raw nmap output is saved to disk. Parsing of that output
happens only in memory, to decide what to do next -- it is not what
gets written to disk (raw-output-only policy).
"""

import os
import re

from modules.executor import run_tool
from config.settings import TIMEOUTS

PORT_LINE_RE = re.compile(r"^(\d+)/(tcp|udp)\s+(open|closed|filtered|open\|filtered)\s+(\S+)", re.M)


def _parse_ports(nmap_stdout):
    """Returns dict: {port: state} from nmap normal-format stdout."""
    ports = {}
    for match in PORT_LINE_RE.finditer(nmap_stdout or ""):
        port, proto, state, service = match.groups()
        ports[f"{port}/{proto}"] = {"state": state, "service": service}
    return ports


def _host_seems_up(sn_stdout):
    if not sn_stdout:
        return False
    return "Host is up" in sn_stdout


def run_network_scan(target, phase_dir, error_log):
    """
    target    - Target object from resolver.py
    phase_dir - e.g. <output_root>/<label>/network-scan
    error_log - path to meta/errors.log

    Returns a summary dict describing what happened, for the run manifest.
    """
    os.makedirs(phase_dir, exist_ok=True)
    host = target.ip or target.domain
    summary = {"phase": "network-scan", "steps": []}

    # ---- Step 1: host discovery -------------------------------------
    sn_result = run_tool(
        "nmap-host-discovery",
        ["nmap", "-sn", host],
        output_path=os.path.join(phase_dir, "01_host_discovery.txt"),
        timeout=TIMEOUTS["nmap_ping"],
        error_log=error_log,
    )
    summary["steps"].append({"step": "host_discovery", "result": repr(sn_result)})

    force_pn = False
    if sn_result.missing or sn_result.timed_out:
        # nmap itself unavailable or hung -- log and bail on this phase
        summary["aborted"] = "nmap unavailable or host discovery timed out"
        return summary

    if not _host_seems_up(sn_result.stdout):
        force_pn = True
        summary["steps"].append({
            "step": "liveness_note",
            "detail": "No response to -sn (host may be dropping ICMP). "
                      "Forcing scan with -Pn instead of skipping the target."
        })

    # ---- Step 2: quick scan -------------------------------------------
    quick_cmd = ["nmap", "-F", "-T4", host]
    if force_pn:
        quick_cmd.insert(1, "-Pn")

    quick_result = run_tool(
        "nmap-quick-scan",
        quick_cmd,
        output_path=os.path.join(phase_dir, "02_quick_scan.txt"),
        timeout=TIMEOUTS["nmap_quick"],
        error_log=error_log,
    )
    summary["steps"].append({"step": "quick_scan", "result": repr(quick_result)})

    if quick_result.missing or quick_result.timed_out:
        summary["aborted"] = "quick scan failed to produce usable output"
        return summary

    ports = _parse_ports(quick_result.stdout)
    open_ports = [p for p, info in ports.items() if info["state"] == "open"]
    filtered_ports = [p for p, info in ports.items() if info["state"] in ("filtered", "open|filtered")]

    summary["open_ports"] = open_ports
    summary["filtered_ports"] = filtered_ports

    # ---- Step 3: branch on filtered ports (evasion) --------------------
    if filtered_ports:
        summary["steps"].append({
            "step": "evasion_branch",
            "detail": f"{len(filtered_ports)} filtered port(s) detected -- "
                      f"likely firewall/IDS in the path. Trying evasion techniques."
        })
        evasion_results = _run_evasion_techniques(host, phase_dir, error_log, force_pn)
        summary["steps"].extend(evasion_results)

    # ---- Step 4: deep scan on confirmed open ports ----------------------
    if open_ports:
        port_list = ",".join(p.split("/")[0] for p in open_ports)
        deep_cmd = ["nmap", "-sV", "-sC", "-p", port_list, host]
        if force_pn:
            deep_cmd.insert(1, "-Pn")

        deep_result = run_tool(
            "nmap-deep-scan",
            deep_cmd,
            output_path=os.path.join(phase_dir, "03_deep_scan.txt"),
            timeout=TIMEOUTS["nmap_deep"],
            error_log=error_log,
        )
        summary["steps"].append({"step": "deep_scan", "result": repr(deep_result)})
    else:
        summary["steps"].append({
            "step": "deep_scan",
            "detail": "Skipped -- no open ports confirmed from quick scan."
        })

    return summary


def _run_evasion_techniques(host, phase_dir, error_log, force_pn):
    """
    Runs when filtered ports suggest a firewall/IDS. Each technique is
    saved to its own file so a human can compare which one actually
    got through.
    """
    steps = []
    pn_flag = ["-Pn"] if force_pn else []

    techniques = [
        ("fragmentation", ["nmap", "-f"] + pn_flag + ["-F", host], "04_evasion_fragmentation.txt"),
        ("decoys", ["nmap", "-D", "RND:10"] + pn_flag + ["-F", host], "05_evasion_decoys.txt"),
        ("source_port_53", ["nmap", "--source-port", "53"] + pn_flag + ["-F", host], "06_evasion_source_port.txt"),
        ("ack_firewall_map", ["nmap", "-sA"] + pn_flag + ["-F", host], "07_evasion_ack_map.txt"),
    ]

    for name, cmd, filename in techniques:
        result = run_tool(
            f"nmap-evasion-{name}",
            cmd,
            output_path=os.path.join(phase_dir, filename),
            timeout=TIMEOUTS["nmap_evasion"],
            error_log=error_log,
        )
        steps.append({"step": f"evasion_{name}", "result": repr(result)})

    return steps
