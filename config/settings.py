"""
Central configuration for the recon container.
Single source of truth for: which binaries each phase needs,
timeouts, scan tuning constants, and the cloud-provider PTR patterns
used to decide whether a resolved hostname counts as a "real" domain
or just an auto-generated cloud reverse-DNS name.
"""

import os
import re

# ---------------------------------------------------------------------------
# Tool registry: every external binary the brain will shell out to.
# Used at startup to check availability (shutil.which) so we fail loud
# and specific instead of crashing deep inside a phase.
#
# nmap is the only hard requirement for the network-scan phase. xsltproc
# (HTML report generation) and ncat (evasion connect-verification) are
# soft dependencies -- the phase degrades gracefully via run_tool() if
# they are missing, but we still surface them at startup.
# ---------------------------------------------------------------------------
REQUIRED_TOOLS = {
    "network-scan": ["nmap", "xsltproc", "ncat"],
    "dns-recon": ["whois", "dig", "subfinder", "dnsx"],
    "web-recon": ["httpx", "whatweb", "katana", "gau", "ffuf"],
    # Service enumeration. nmap is the hard requirement; the rest are
    # per-service native clients that degrade gracefully via run_tool().
    "service-enum": [
        "nmap", "smbclient", "rpcclient", "enum4linux-ng", "smbmap",
        "showmount", "rsync", "snmpwalk", "onesixtyone", "braa",
        "ssh-audit", "dnsx", "dig", "mysql", "openssl", "nxc",
        "impacket-rpcdump",
    ],
    "osint": ["curl", "jq", "openssl"],
}

# Flatten for a single startup check
ALL_TOOLS = sorted({t for tools in REQUIRED_TOOLS.values() for t in tools})

# ---------------------------------------------------------------------------
# Timeouts (seconds) per tool call, so a hung process can't stall the
# whole run indefinitely. These follow the "generous, thorough" posture:
# a full run (full -p- sweep + UDP + OS + vuln scripts) may take 20-30
# minutes, and we would rather let a slow-but-legitimate scan finish than
# cut it off early. A timed-out scan is still captured (partial nmap -oA
# files are parsed best-effort) and logged.
# ---------------------------------------------------------------------------
TIMEOUTS = {
    "nmap_ping": 60,        # host discovery (-sn)
    "nmap_quick": 180,      # fast top-100 scan (-F)
    "nmap_full": 1200,      # full 65535-port sweep (-p-)
    "nmap_udp": 900,        # UDP scan (-sU) -- inherently slow
    "nmap_ack": 180,        # ACK firewall-mapping scan (-sA)
    "nmap_evasion": 300,    # each individual evasion technique
    "nmap_deep": 900,       # -sV -sC -O --traceroute on open ports
    "nmap_vuln": 900,       # --script vuln (hits external CVE databases)
    "xsltproc": 60,         # XML -> HTML report conversion
    "ncat": 30,             # evasion connect-verification
    "default": 300,
}

# ---------------------------------------------------------------------------
# Scan tuning constants. Centralized so behavior is one edit away.
# ---------------------------------------------------------------------------
# Number of random decoys for -D RND:<n> evasion.
DECOY_COUNT = 10
# Source port used for the --source-port evasion technique. 53 (DNS) is the
# classic choice: firewalls that trust DNS egress often let it back in.
EVASION_SOURCE_PORT = 53
# Timing template for the noisy/fast steps (quick + full sweep). Evasion
# steps deliberately run at nmap's default timing to stay quieter.
FAST_TIMING = "-T4"
# Minimum packet rate for the full -p- sweep, so it stays bounded without
# dropping accuracy the way a low --max-retries would.
FULL_SWEEP_MIN_RATE = 1000
# The full 1-65535 sweep is split into this many contiguous port-range chunks,
# each run as its own nmap invocation. nmap only flushes a host's results (and
# closes </host> in the XML) at host completion, so a single monolithic -p-
# that hits its timeout yields ZERO parsed ports. Chunking bounds the loss to
# the one in-progress range; every finished chunk has already written a
# complete, parseable XML. The per-tool nmap_full timeout is divided across
# the chunks so the total time budget is unchanged.
FULL_SWEEP_CHUNKS = 4
# UDP scan is bounded to the top N ports (a full UDP -p- is impractically slow).
UDP_TOP_PORTS = 100

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

# ---------------------------------------------------------------------------
# Service enumeration
# ---------------------------------------------------------------------------
# Additional per-step timeouts for the service-enum phase.
TIMEOUTS.update({
    "nse_default": 300,     # a service's NSE script bundle
    "nse_slow": 600,        # oracle-sid-brute etc.
    "service_native": 120,  # a single native client invocation
    "nfs_mount": 60,
    "subdomain_brute": 900,
    "crtsh": 60,
    "shodan": 60,
    "ffuf": 900,            # web content discovery — bounded but generous
})

# Map nmap-detected service names to a canonical handler key. Dispatch prefers
# the -sV-detected service; STANDARD_PORT_MAP is the fallback when detection
# failed or returned something generic.
SERVICE_ALIASES = {
    "ftp": "ftp", "ftp-data": "ftp",
    "tftp": "tftp",
    "ssh": "ssh",
    "smtp": "smtp", "smtps": "smtp", "submission": "smtp",
    "domain": "dns",
    "netbios-ssn": "smb", "microsoft-ds": "smb",
    "rpcbind": "nfs", "nfs": "nfs", "nfs_acl": "nfs", "mountd": "nfs",
    "pop3": "pop3", "pop3s": "pop3",
    "imap": "imap", "imaps": "imap",
    "snmp": "snmp",
    "mysql": "mysql", "mariadb": "mysql",
    "ms-sql-s": "mssql", "ms-sql": "mssql", "mssql": "mssql",
    "oracle-tns": "oracle", "oracle": "oracle",
    "asf-rmcp": "ipmi", "ipmi": "ipmi",
    "ms-wbt-server": "rdp", "rdp": "rdp",
    "rsync": "rsync",
    "exec": "rservices", "login": "rservices", "shell": "rservices",
    "msrpc": "wmi",
}

# Fallback: standard well-known port -> canonical handler key.
STANDARD_PORT_MAP = {
    "21/tcp": "ftp", "22/tcp": "ssh", "25/tcp": "smtp",
    "53/tcp": "dns", "53/udp": "dns", "69/udp": "tftp",
    "110/tcp": "pop3", "111/tcp": "nfs", "111/udp": "nfs",
    "135/tcp": "wmi", "139/tcp": "smb", "143/tcp": "imap",
    "161/udp": "snmp", "445/tcp": "smb", "465/tcp": "smtp",
    "512/tcp": "rservices", "513/tcp": "rservices", "514/tcp": "rservices",
    "587/tcp": "smtp", "623/udp": "ipmi", "873/tcp": "rsync",
    "993/tcp": "imap", "995/tcp": "pop3", "1433/tcp": "mssql",
    "1521/tcp": "oracle", "2049/tcp": "nfs", "2049/udp": "nfs",
    "3306/tcp": "mysql", "3389/tcp": "rdp",
    "5985/tcp": "winrm", "5986/tcp": "winrm",
}

# NSE script bundles per service. All within the recon/vuln-assessment
# boundary: default/safe/discovery/version scripts plus default-credential and
# null-session *checks* (e.g. mysql-empty-password, smb-enum-*). No brute-force
# scripts (ftp-brute/mysql-brute/etc.) and nothing that executes commands.
NSE_SCRIPTS = {
    "ftp": "ftp-anon,ftp-syst,ftp-bounce",
    "tftp": "tftp-enum",
    "smb": "smb-os-discovery,smb-security-mode,smb2-security-mode,smb2-time,"
           "smb-enum-shares,smb-enum-users,smb-enum-domains,smb-enum-groups,nbstat",
    "nfs": "rpcinfo,nfs-ls,nfs-showmount,nfs-statfs",
    "smtp": "smtp-commands,smtp-open-relay,smtp-ntlm-info",
    "imap": "imap-capabilities,imap-ntlm-info,ssl-cert",
    "pop3": "pop3-capabilities,pop3-ntlm-info,ssl-cert",
    "snmp": "snmp-info,snmp-sysdescr,snmp-interfaces,snmp-processes,snmp-netstat",
    "mysql": "mysql-info,mysql-empty-password,mysql-users,mysql-databases,mysql-variables",
    "mssql": "ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password,ms-sql-config",
    "oracle": "oracle-tns-version,oracle-sid-brute",
    "ipmi": "ipmi-version,ipmi-cipher-zero",
    "rdp": "rdp-enum-encryption,rdp-ntlm-info",
    "ssh": "ssh2-enum-algos,ssh-hostkey,ssh-auth-methods",
    "rsync": "rsync-list-modules",
    "winrm": "http-title,http-headers",
    "wmi": "msrpc-enum",
    "rservices": "rusers,finger",
}

# Bundled wordlists (SecLists is installed into the image). Operators can point
# elsewhere via the config wizard / env vars.
SECLISTS_ROOT = "/usr/share/seclists"
DEFAULT_SUBDOMAIN_WORDLIST = os.path.join(
    SECLISTS_ROOT, "Discovery", "DNS", "subdomains-top1million-20000.txt")
DEFAULT_SNMP_WORDLIST = os.path.join(
    SECLISTS_ROOT, "Discovery", "SNMP", "snmp.txt")
# Web content discovery (ffuf). common.txt is a fast, high-ROI default; point
# RECONBOX_FFUF_WORDLIST at a bigger list (e.g. raft-medium-directories.txt)
# for deeper coverage. Extensions are appended to each candidate.
DEFAULT_FFUF_WORDLIST = os.path.join(
    SECLISTS_ROOT, "Discovery", "Web-Content", "common.txt")
FFUF_EXTENSIONS = os.environ.get("RECONBOX_FFUF_EXTENSIONS", ".php,.html,.txt")

# Upper bound on candidates fed to the dnsx-based subdomain brute, so a huge
# wordlist doesn't blow past the phase timeout. Configurable via env.
SUBDOMAIN_BRUTE_MAX = int(os.environ.get("RECONBOX_SUBDOMAIN_MAX", "20000"))

# Root output directory inside the container
OUTPUT_ROOT = "/output"
