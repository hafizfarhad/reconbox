#!/usr/bin/env python3
"""
Entrypoint for the recon container.

Usage:
    python3 brain.py <target>
    (or, as designed: `docker run <image> <target>`)

Builds:
    /output/<label>/
        meta/            (target info, run manifest, errors.log)
        network-scan/    (nmap decision tree)
        dns-recon/       (whois, dig, subfinder, dnsx)      -- domain targets only
        web-recon/       (httpx, whatweb, katana, gau)      -- domain targets only
"""

import sys
import os
import json
import time
import shutil

from config.settings import ALL_TOOLS, OUTPUT_ROOT
from modules import progress
from modules.executor import register_secret
from modules.resolver import resolve_target
from modules.config_wizard import load_config, redact_for_manifest
from modules.network_scan import run_network_scan
from modules.service_enum import run_service_enum
from modules.dns_recon import run_dns_recon
from modules.web_recon import run_web_recon
from modules.osint import run_osint
from modules.report import generate_report


def check_tools():
    """Startup check: log which required binaries are missing, but
    don't hard-fail -- individual phases already degrade gracefully
    per-tool via executor.run_tool()."""
    missing = [t for t in ALL_TOOLS if shutil.which(t) is None]
    if missing:
        print(f"[STARTUP WARNING] Missing tools on PATH: {', '.join(missing)}")
        print("Affected steps will be skipped and logged to meta/errors.log")
    return missing


def build_dirs(label):
    base = os.path.join(OUTPUT_ROOT, label)
    dirs = {
        "base": base,
        "meta": os.path.join(base, "meta"),
        "network-scan": os.path.join(base, "network-scan"),
        "service-enum": os.path.join(base, "service-enum"),
        "dns-recon": os.path.join(base, "dns-recon"),
        "web-recon": os.path.join(base, "web-recon"),
        "osint": os.path.join(base, "osint"),
    }
    for d in dirs.values():
        os.makedirs(d, exist_ok=True)
    return dirs


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 brain.py <domain-or-ip>")
        sys.exit(1)

    raw_input = sys.argv[1]
    run_started = time.strftime("%Y-%m-%d %H:%M:%S")

    missing_tools = check_tools()

    # Optional launch-time configuration (interactive only on a TTY; otherwise
    # driven purely by env vars / defaults so headless runs never block).
    config = load_config()

    # Mask supplied secrets everywhere the executor serializes a command or its
    # output (per-service files, errors.log, container log).
    for _secret_key in ("password", "shodan_api_key"):
        register_secret(config.get(_secret_key))

    try:
        target = resolve_target(raw_input)
    except ValueError as e:
        print(f"[FATAL] {e}")
        sys.exit(2)
    dirs = build_dirs(target.label)
    error_log = os.path.join(dirs["meta"], "errors.log")

    # Resolution runs before the error_log path is known (the path depends on
    # the resolved label), so any resolver-stage errors were buffered on the
    # target. Flush them now that errors.log exists.
    for message in target.log_messages:
        with open(error_log, "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {message}\n")

    # Write target/meta info first, so even a crash mid-run leaves a trace
    target_info = {
        "raw_input": target.raw_input,
        "domain": target.domain,
        "ip": target.ip,
        "is_domain_target": target.is_domain_target,
        "ptr_hostname": target.ptr_hostname,
        "ptr_note": target.ptr_note,
        "run_started": run_started,
        "missing_tools_at_startup": missing_tools,
        "run_config": redact_for_manifest(config),
    }
    with open(os.path.join(dirs["meta"], "target_info.json"), "w") as f:
        json.dump(target_info, f, indent=2)

    print(f"[*] Target resolved: {target}")
    if target.ptr_note:
        print(f"[*] {target.ptr_note}")

    manifest = {"target": target_info, "phases": []}

    # Declare the phase plan up front so progress can show "phase i/N".
    phase_plan = ["network-scan", "service-enum"]
    if target.is_domain_target:
        phase_plan += ["dns-recon", "web-recon", "osint"]
    phase_plan.append("report")
    progress.configure(phase_plan)

    # ---- Phase 1: network-scan (always runs) ------------------------------
    progress.start_phase("network-scan")
    net_summary = run_network_scan(target, dirs["network-scan"], error_log, config)
    manifest["phases"].append(net_summary)

    # ---- Phase 2: service-enum (always runs; port-driven) -----------------
    progress.start_phase("service-enum")
    svc_summary = run_service_enum(target, dirs["service-enum"], error_log, config, net_summary)
    manifest["phases"].append(svc_summary)
    if not svc_summary.get("enumerated"):
        # No open port mapped to an enumerator -- drop the empty directory.
        shutil.rmtree(dirs["service-enum"], ignore_errors=True)

    # ---- Phase 3, 4 & 5: domain-only phases --------------------------------
    if target.is_domain_target:
        progress.start_phase("dns-recon")
        dns_summary = run_dns_recon(target, dirs["dns-recon"], error_log, config)
        manifest["phases"].append(dns_summary)

        progress.start_phase("web-recon")
        web_summary = run_web_recon(target, dirs["web-recon"], error_log, config,
                                    net_summary)
        manifest["phases"].append(web_summary)

        progress.start_phase("osint")
        osint_summary = run_osint(target, dirs["osint"], error_log, config)
        manifest["phases"].append(osint_summary)
    else:
        print("[*] Skipping dns-recon / web-recon / osint -- target classified as IP-only.")
        shutil.rmtree(dirs["dns-recon"], ignore_errors=True)
        shutil.rmtree(dirs["web-recon"], ignore_errors=True)
        shutil.rmtree(dirs["osint"], ignore_errors=True)

    manifest["run_finished"] = time.strftime("%Y-%m-%d %H:%M:%S")

    # ---- Final phase: build the PDF report from everything collected -------
    progress.start_phase("report")
    report_summary = generate_report(target, dirs, manifest, config, error_log)
    manifest["phases"].append(report_summary)

    with open(os.path.join(dirs["meta"], "run_manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)

    # PDF-only mode: once the PDF is safely written, drop the raw evidence
    # folders (keep meta/ + report.pdf). Never delete if the PDF failed, or if
    # the operator asked to keep raw.
    keep_raw = os.environ.get("RECONBOX_KEEP_RAW") == "1"
    if report_summary.get("pdf_ok") and not keep_raw:
        for key in ("network-scan", "service-enum", "dns-recon", "web-recon", "osint"):
            shutil.rmtree(dirs[key], ignore_errors=True)
        print("[*] Raw evidence removed (PDF-only mode). Set RECONBOX_KEEP_RAW=1 to keep it.")
    elif not report_summary.get("pdf_ok"):
        print(f"[!] PDF not generated ({report_summary.get('error')}); raw evidence kept.")

    progress.finish()
    print(f"[*] Done. Output written to {dirs['base']}")


if __name__ == "__main__":
    main()
