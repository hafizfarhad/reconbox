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
from modules.resolver import resolve_target
from modules.network_scan import run_network_scan
from modules.dns_recon import run_dns_recon
from modules.web_recon import run_web_recon


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
        "dns-recon": os.path.join(base, "dns-recon"),
        "web-recon": os.path.join(base, "web-recon"),
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

    error_log_tmp = None  # set after we know the label
    missing_tools = check_tools()

    target = resolve_target(raw_input)
    dirs = build_dirs(target.label)
    error_log = os.path.join(dirs["meta"], "errors.log")

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
    }
    with open(os.path.join(dirs["meta"], "target_info.json"), "w") as f:
        json.dump(target_info, f, indent=2)

    print(f"[*] Target resolved: {target}")
    if target.ptr_note:
        print(f"[*] {target.ptr_note}")

    manifest = {"target": target_info, "phases": []}

    # ---- Phase 1: network-scan (always runs) ------------------------------
    print("[*] Running network-scan phase...")
    net_summary = run_network_scan(target, dirs["network-scan"], error_log)
    manifest["phases"].append(net_summary)

    # ---- Phase 2 & 3: domain-only phases -----------------------------------
    if target.is_domain_target:
        print("[*] Running dns-recon phase...")
        dns_summary = run_dns_recon(target, dirs["dns-recon"], error_log)
        manifest["phases"].append(dns_summary)

        print("[*] Running web-recon phase...")
        web_summary = run_web_recon(target, dirs["web-recon"], error_log)
        manifest["phases"].append(web_summary)
    else:
        print("[*] Skipping dns-recon / web-recon -- target classified as IP-only.")
        shutil.rmtree(dirs["dns-recon"], ignore_errors=True)
        shutil.rmtree(dirs["web-recon"], ignore_errors=True)

    manifest["run_finished"] = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(os.path.join(dirs["meta"], "run_manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"[*] Done. Output written to {dirs['base']}")


if __name__ == "__main__":
    main()
