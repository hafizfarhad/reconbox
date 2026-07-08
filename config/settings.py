"""
Central configuration for the recon container.
Single source of truth for: which binaries each phase needs,
timeouts, and the cloud-provider PTR patterns used to decide
whether a resolved hostname counts as a "real" domain or just
an auto-generated cloud reverse-DNS name.
"""

import re

# ---------------------------------------------------------------------------
# Tool registry: every external binary the brain will shell out to.
# Used at startup to check availability (shutil.which) so we fail loud
# and specific instead of crashing deep inside a phase.
# ---------------------------------------------------------------------------
REQUIRED_TOOLS = {
    "network-scan": ["nmap"],
    "dns-recon": ["whois", "dig", "subfinder", "dnsx"],
    "web-recon": ["httpx", "whatweb", "katana", "gau"],
}

# Flatten for a single startup check
ALL_TOOLS = sorted({t for tools in REQUIRED_TOOLS.values() for t in tools})

# ---------------------------------------------------------------------------
# Timeouts (seconds) per tool call, so a hung process can't stall the
# whole run indefinitely. Generous but bounded.
# ---------------------------------------------------------------------------
TIMEOUTS = {
    "nmap_quick": 120,
    "nmap_ping": 30,
    "nmap_deep": 600,
    "nmap_evasion": 300,
    "default": 180,
}

# ---------------------------------------------------------------------------
# Cloud-provider auto-generated PTR hostname patterns.
# If a reverse-DNS lookup on a raw IP matches one of these, we treat the
# target as IP-only (no domain-level tools) even though a PTR exists,
# because the PTR is not something the owner actually configured.
# ---------------------------------------------------------------------------
CLOUD_PTR_PATTERNS = [
    re.compile(r"\.compute\.amazonaws\.com$", re.I),
    re.compile(r"\.compute-1\.amazonaws\.com$", re.I),
    re.compile(r"\.amazonaws\.com$", re.I),
    re.compile(r"\.cloudapp\.azure\.com$", re.I),
    re.compile(r"\.azure\.com$", re.I),
    re.compile(r"\.bc\.googleusercontent\.com$", re.I),
    re.compile(r"\.googleusercontent\.com$", re.I),
    re.compile(r"\.digitalocean\.com$", re.I),
    re.compile(r"\.linode\.com$", re.I),
    re.compile(r"\.vultr\.com$", re.I),
    re.compile(r"\.ovh\.net$", re.I),
    re.compile(r"\.hetzner\.(com|cloud)$", re.I),
]

# Root output directory inside the container
OUTPUT_ROOT = "/output"
