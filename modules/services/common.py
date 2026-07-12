"""
Shared plumbing for the per-service enumeration modules.

Each service module registers one or more handler functions against the
canonical service keys it covers, using the @register decorator. The
dispatcher (modules/service_enum.py) imports the package (which imports every
module, running the decorators) and then looks handlers up by key.

A handler receives a ServiceContext and returns a small dict summarizing what
it did (for the run manifest). Raw evidence is written to files in the phase
directory: nmap steps use nmap-native -oA output; native clients use the
executor's raw stdout capture. Nothing here writes to the target — every
action is read-only enumeration.
"""

import contextlib
import ipaddress
import os
import socket
import tempfile

from modules.executor import run_tool, tool_available
from config.settings import TIMEOUTS

# canonical service key -> handler function
HANDLERS = {}


def _is_ipv6(host):
    """True only for a literal IPv6 address (hostnames/IPv4 -> False)."""
    try:
        return ipaddress.ip_address(host).version == 6
    except ValueError:
        return False


def nse_base_cmd(ctx, scripts):
    """
    Shared nmap command prefix for NSE service handlers.

    - -Pn: we already know this port is open (the network-scan phase confirmed
      it), so host discovery must be skipped. Without it, a host that drops
      ICMP is judged "down" and nmap runs NONE of the scripts -- a silent,
      total loss of service enumeration on firewalled hosts.
    - -6: nmap requires it for an IPv6 target, else the scan errors out.
    """
    cmd = ["nmap", "-Pn", "-sV", "-p", ctx.port, "--script", scripts]
    if _is_ipv6(ctx.host):
        cmd.insert(1, "-6")
    return cmd


def curl_config_value(s):
    r"""
    Escape a username/password for use inside a double-quoted curl --config
    value. curl treats \" and \\ as escapes within quotes, so an unescaped
    quote or backslash in a credential would truncate/corrupt the value (and
    could cause a wrong-credential auth). Returns the escaped inner text only
    (caller supplies the surrounding quotes).
    """
    return (s or "").replace("\\", "\\\\").replace('"', '\\"')


def register(*names):
    """Register a handler for one or more canonical service keys."""
    def deco(fn):
        for n in names:
            HANDLERS[n] = fn
        return fn
    return deco


class ServiceContext:
    """Everything a service handler needs about one open port."""

    def __init__(self, host, ip, domain, port, proto, service,
                 phase_dir, error_log, config):
        self.host = host
        self.ip = ip
        self.domain = domain
        self.port = str(port)
        self.proto = proto
        self.service = service
        self.phase_dir = phase_dir
        self.error_log = error_log
        self.config = config or {}

    @property
    def creds(self):
        c = self.config
        return {
            "username": c.get("username"),
            "password": c.get("password"),
            "domain": c.get("domain"),
            "ssh_key": c.get("ssh_key"),
        }

    @property
    def has_creds(self):
        return bool(self.config.get("username"))

    def out(self, name):
        return os.path.join(self.phase_dir, name)


def run_nse(ctx, scripts, timeout=None, extra_args=None):
    """
    Run an nmap NSE bundle against this service's port, writing nmap-native
    -oA output (<port>_<service>_nse.{nmap,gnmap,xml}). Returns a ToolResult.
    """
    base = ctx.out(f"{ctx.port}_{ctx.service}_nse")
    cmd = nse_base_cmd(ctx, scripts)
    if ctx.proto == "udp":
        cmd.append("-sU")
    if extra_args:
        cmd += extra_args
    cmd += [ctx.host, "-oA", base]
    return run_tool(f"nse-{ctx.service}-{ctx.port}", cmd, output_path=None,
                    timeout=timeout or TIMEOUTS["nse_default"], error_log=ctx.error_log)


def run_native(ctx, tool_name, argv, out_name, timeout=None):
    """Run a native client, capturing raw stdout/stderr to out_name."""
    return run_tool(tool_name, argv, output_path=ctx.out(out_name),
                    timeout=timeout or TIMEOUTS["service_native"],
                    error_log=ctx.error_log)


@contextlib.contextmanager
def creds_file(content, prefix="reconbox_", suffix=".conf"):
    """
    Write credential material (e.g. a password) to a private, short-lived temp
    file OUTSIDE /output and yield its path, deleting it in a finally.

    This is the pattern mssql.py already uses, generalized: process argv is
    world-readable (any local user can read /proc/<pid>/cmdline via `ps`), so a
    password passed as `-pSECRET` leaks to every process on the host for the
    tool's lifetime. Tools that can read the credential from a config/auth file
    (mysql --defaults-extra-file, curl --config, samba -A) keep it off argv
    entirely; mkstemp creates the file 0600 so only we can read it.
    """
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=suffix)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
        yield path
    finally:
        if os.path.exists(path):
            os.remove(path)


def write_text(path, text):
    """Persist an in-process probe result (e.g. a socket banner) to disk."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text or "")


def raw_banner(host, port, send=None, timeout=10):
    """
    Minimal read-only TCP probe: connect, read the greeting, optionally send a
    few fixed lines (e.g. EHLO/VRFY, CAPABILITY) and read the responses. Used
    for plaintext banner/capability grabbing where an NSE script isn't enough.
    Never raises — returns a diagnostic string on failure.
    """
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as s:
            s.settimeout(timeout)
            data = b""
            try:
                data += s.recv(4096)
            except socket.timeout:
                pass
            for line in (send or []):
                try:
                    s.sendall(line.encode() + b"\r\n")
                    data += s.recv(4096)
                except (socket.timeout, OSError):
                    break
            return data.decode(errors="replace")
    except (OSError, ValueError) as e:
        return f"[probe error] {e}"
