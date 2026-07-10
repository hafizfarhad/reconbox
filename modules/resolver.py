"""
Resolves the raw CLI input into a structured target the rest of the
brain can branch on.

Logic agreed on:
  - if input is a domain -> also resolve its IP (needed for network-scan)
  - if input is a raw IP  -> try reverse DNS (PTR)
        - no PTR at all           -> IP-only target
        - PTR matches a known
          cloud auto-gen pattern  -> IP-only target (PTR isn't a real domain)
        - PTR is a "real" hostname -> treat as a domain too, run domain tools
"""

import ipaddress
import socket

from config.settings import CLOUD_PTR_PATTERNS


class Target:
    def __init__(self, raw_input, domain=None, ip=None, is_domain_target=False,
                 ptr_hostname=None, ptr_note=None, log_messages=None):
        self.raw_input = raw_input
        self.domain = domain
        self.ip = ip
        self.is_domain_target = is_domain_target  # whether domain-tools phase should run
        self.ptr_hostname = ptr_hostname
        self.ptr_note = ptr_note
        # Resolution happens before we know the output label (and therefore
        # before errors.log exists), so any resolver-stage errors are buffered
        # here and flushed to errors.log by brain.py once the path is known.
        self.log_messages = log_messages or []

    @property
    def label(self):
        """Used for the parent output directory name."""
        return self.domain if self.domain else self.ip

    def __repr__(self):
        return (f"<Target raw={self.raw_input} domain={self.domain} ip={self.ip} "
                f"is_domain_target={self.is_domain_target}>")


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _matches_cloud_ptr(hostname):
    return any(pattern.search(hostname) for pattern in CLOUD_PTR_PATTERNS)


def resolve_target(raw_input):
    raw_input = raw_input.strip()

    if _is_ip(raw_input):
        return _resolve_from_ip(raw_input)
    else:
        return _resolve_from_domain(raw_input)


def _resolve_from_domain(domain):
    ip = None
    log_messages = []
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror as e:
        msg = f"[RESOLVER] Could not resolve IP for domain '{domain}': {e}"
        print(msg)
        log_messages.append(msg)

    return Target(
        raw_input=domain,
        domain=domain,
        ip=ip,
        is_domain_target=True,
        log_messages=log_messages,
    )


def _resolve_from_ip(ip):
    ptr_hostname = None
    try:
        ptr_hostname, _, _ = socket.gethostbyaddr(ip)
    except (socket.herror, socket.gaierror):
        ptr_hostname = None

    if ptr_hostname is None:
        return Target(
            raw_input=ip,
            domain=None,
            ip=ip,
            is_domain_target=False,
            ptr_note="No PTR record found. Treating as network IP target only.",
        )

    if _matches_cloud_ptr(ptr_hostname):
        return Target(
            raw_input=ip,
            domain=None,
            ip=ip,
            is_domain_target=False,
            ptr_hostname=ptr_hostname,
            ptr_note=(f"PTR '{ptr_hostname}' matches a cloud-provider auto-generated "
                       f"pattern. Treating as network IP target only, skipping domain tools."),
        )

    # PTR exists and doesn't look auto-generated -> treat as a real domain too
    return Target(
        raw_input=ip,
        domain=ptr_hostname,
        ip=ip,
        is_domain_target=True,
        ptr_hostname=ptr_hostname,
        ptr_note=f"PTR '{ptr_hostname}' looks like a real domain. Running domain tools too.",
    )
