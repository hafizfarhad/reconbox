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

import os
import socket

from modules.executor import run_tool, tool_available
from config.settings import TIMEOUTS

# canonical service key -> handler function
HANDLERS = {}


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
    cmd = ["nmap", "-sV", "-p", ctx.port, "--script", scripts]
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
