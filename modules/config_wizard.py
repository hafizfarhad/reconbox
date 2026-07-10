"""
Launch-time configuration for a run.

Some evasion techniques need values that cannot be auto-derived for an
arbitrary target -- a spoofed source IP (-S), the interface to send it on
(-e), or a trusted DNS server to relay through (--dns-server). These stay
OFF unless the operator supplies them.

Two ways to supply them, in priority order:

  1. Environment variables (always respected, works headless/in CI):
       RECONBOX_SOURCE_IP, RECONBOX_INTERFACE, RECONBOX_DNS_SERVER,
       RECONBOX_SOURCE_PORT, RECONBOX_DECOY_COUNT
  2. An interactive wizard, shown ONLY when stdin is a real terminal
     (so `docker run -it ... reconbox <target>` prompts, but a piped or
     detached run does not hang). The wizard asks once whether you want
     to configure anything; answering "no" proceeds with defaults.

The question set is a registry (CONFIG_QUESTIONS) -- adding a new option
later is a one-line append, and both the env-var path and the interactive
path pick it up automatically.
"""

import os
import sys

from config.settings import (
    EVASION_SOURCE_PORT, DECOY_COUNT,
    DEFAULT_SUBDOMAIN_WORDLIST, DEFAULT_SNMP_WORDLIST,
)


# Each question: key used in the returned config dict, the env var that
# provides/overrides it, the interactive prompt text, a default, and a
# validator (value -> bool) so bad input is re-asked rather than accepted.
def _is_int(v):
    try:
        int(v)
        return True
    except (TypeError, ValueError):
        return False


CONFIG_QUESTIONS = [
    {
        "key": "source_ip",
        "env": "RECONBOX_SOURCE_IP",
        "prompt": "Spoofed source IP for -S evasion (blank to skip)",
        "default": "",
        "validate": lambda v: True,
    },
    {
        "key": "interface",
        "env": "RECONBOX_INTERFACE",
        "prompt": "Network interface for -e, e.g. eth0/tun0 (required if source IP is set)",
        "default": "",
        "validate": lambda v: True,
    },
    {
        "key": "dns_server",
        "env": "RECONBOX_DNS_SERVER",
        "prompt": "Custom DNS server for --dns-server evasion (blank to skip)",
        "default": "",
        "validate": lambda v: True,
    },
    {
        "key": "source_port",
        "env": "RECONBOX_SOURCE_PORT",
        "prompt": "Source port for source-port evasion",
        "default": str(EVASION_SOURCE_PORT),
        "validate": _is_int,
    },
    {
        "key": "decoy_count",
        "env": "RECONBOX_DECOY_COUNT",
        "prompt": "Number of random decoys for -D RND:<n>",
        "default": str(DECOY_COUNT),
        "validate": _is_int,
    },
    # --- Service-enum: optional read-only credentials -----------------------
    # When provided, service modules perform authenticated READ-ONLY
    # enumeration (never write/modify/delete, never execute commands).
    {
        "key": "username",
        "env": "RECONBOX_USERNAME",
        "prompt": "Username for authenticated read-only enumeration (blank = anonymous)",
        "default": "",
        "validate": lambda v: True,
    },
    {
        "key": "password",
        "env": "RECONBOX_PASSWORD",
        "prompt": "Password for the above user (blank if none)",
        "default": "",
        "validate": lambda v: True,
    },
    {
        "key": "domain",
        "env": "RECONBOX_DOMAIN",
        "prompt": "Windows/SMB domain for the above user (blank if none)",
        "default": "",
        "validate": lambda v: True,
    },
    {
        "key": "ssh_key",
        "env": "RECONBOX_SSH_KEY",
        "prompt": "Path to an SSH private key for key-based auth (blank if none)",
        "default": "",
        "validate": lambda v: True,
    },
    # --- OSINT / wordlists --------------------------------------------------
    {
        "key": "shodan_api_key",
        "env": "RECONBOX_SHODAN_KEY",
        "prompt": "Shodan API key for host lookups (blank to skip Shodan)",
        "default": "",
        "validate": lambda v: True,
    },
    {
        "key": "subdomain_wordlist",
        "env": "RECONBOX_SUBDOMAIN_WORDLIST",
        "prompt": "Subdomain brute-force wordlist path",
        "default": DEFAULT_SUBDOMAIN_WORDLIST,
        "validate": lambda v: True,
    },
    {
        "key": "snmp_wordlist",
        "env": "RECONBOX_SNMP_WORDLIST",
        "prompt": "SNMP community-string wordlist path",
        "default": DEFAULT_SNMP_WORDLIST,
        "validate": lambda v: True,
    },
]


def _coerce(key, value):
    """Normalize a few values to their runtime type."""
    if key in ("source_port", "decoy_count") and value not in (None, ""):
        return int(value)
    return value or None  # empty string -> None (feature simply off)


def _defaults_from_env():
    """Config populated purely from env vars / built-in defaults."""
    config = {}
    for q in CONFIG_QUESTIONS:
        raw = os.environ.get(q["env"], q["default"])
        config[q["key"]] = _coerce(q["key"], raw)
    return config


def _wizard_enabled():
    """
    Decide whether to show the interactive wizard.

    RECONBOX_NO_PROMPT=1 forces off (useful to be explicit in scripts).
    RECONBOX_CONFIGURE=1 forces on. Otherwise: only if stdin is a TTY.
    """
    if os.environ.get("RECONBOX_NO_PROMPT") == "1":
        return False
    if os.environ.get("RECONBOX_CONFIGURE") == "1":
        return True
    try:
        return sys.stdin.isatty()
    except (AttributeError, ValueError):
        return False


def _ask(question, current):
    """Prompt for a single question, showing the current value as default."""
    default = "" if current is None else str(current)
    shown = f" [{default}]" if default else ""
    while True:
        try:
            answer = input(f"  - {question['prompt']}{shown}: ").strip()
        except EOFError:
            return current
        if answer == "":
            return current
        if question["validate"](answer):
            return _coerce(question["key"], answer)
        print(f"    invalid value for {question['key']}, try again.")


def load_config():
    """
    Build the run configuration. Env vars first (so a headless run is
    fully configurable), then an optional interactive wizard on top.
    Returns a plain dict the phases can read.
    """
    config = _defaults_from_env()

    if not _wizard_enabled():
        return config

    print("\n[*] Advanced configuration")
    print("    Optional evasion settings (spoofed source IP, interface, DNS relay, etc.).")
    try:
        choice = input("    Configure advanced options now? [y/N]: ").strip().lower()
    except EOFError:
        choice = "n"

    if choice not in ("y", "yes"):
        print("[*] Using defaults (env vars honored where set).\n")
        return config

    for q in CONFIG_QUESTIONS:
        config[q["key"]] = _ask(q, config[q["key"]])

    print("[*] Configuration captured.\n")
    return config


_SECRET_KEYS = {"password", "shodan_api_key"}


def redact_for_manifest(config):
    """
    A copy of the config safe to embed in the run manifest. Secrets are masked
    to a boolean-ish marker so the manifest records that a credential was
    supplied without writing the secret itself to disk.
    """
    redacted = {}
    for k, v in config.items():
        if k in _SECRET_KEYS and v:
            redacted[k] = "***set***"
        else:
            redacted[k] = v
    return redacted
