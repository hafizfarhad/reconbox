"""
Shared execution layer. Every tool call in every phase goes through
run_tool() so we get one consistent behavior for:
  - timeouts
  - missing binaries
  - non-zero exit codes
  - raw output saved to disk
  - a structured result handed back to the caller for branching logic

This is the seam that keeps the decision tree from breaking the moment
a tool misbehaves.
"""

import subprocess
import shutil
import time
import os

from modules import progress

# ---------------------------------------------------------------------------
# Secret redaction.
#
# Service-enum commands carry credentials / API keys in their argv (mysql -p,
# curl --user, rpcclient -U user%pass, impacket user:pass@host, shodan ?key=).
# The command line, stdout, and stderr are all written to disk (per-service
# output files, meta/errors.log) and printed to the container log. To keep
# secrets out of those, callers register the exact secret VALUES here at
# startup and we mask them wherever we serialize a command or its output.
#
# Value-based (not flag-based) on purpose: it never mistakes nmap's real
# "-p 445" port argument for a password.
# ---------------------------------------------------------------------------
_SECRETS = set()


def register_secret(value):
    """Register a secret string to be masked in all logged/written output."""
    if value and len(str(value)) >= 3:
        _SECRETS.add(str(value))


def _redact(text):
    if not text or not _SECRETS:
        return text
    for secret in _SECRETS:
        text = text.replace(secret, "***REDACTED***")
    return text


class ToolResult:
    """What every tool call returns to the decision tree."""

    def __init__(self, tool, command, returncode, stdout, stderr,
                 timed_out=False, missing=False, duration=0.0, output_file=None):
        self.tool = tool
        self.command = command
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out
        self.missing = missing
        self.duration = duration
        self.output_file = output_file

    @property
    def ok(self):
        return not self.missing and not self.timed_out and self.returncode == 0

    def __repr__(self):
        status = "MISSING" if self.missing else "TIMEOUT" if self.timed_out else self.returncode
        return f"<ToolResult {self.tool} status={status} dur={self.duration:.1f}s>"


def tool_available(binary_name):
    return shutil.which(binary_name) is not None


def run_tool(tool_name, command_list, output_path=None, timeout=180, error_log=None):
    """
    Run a single external tool.

    tool_name    - short name, e.g. "nmap"
    command_list - full argv list, e.g. ["nmap", "-sn", "10.0.0.1"]
    output_path  - if given, raw stdout is written here (raw-output-only policy)
    timeout      - seconds before we kill it
    error_log    - path to append error lines to (meta/errors.log)

    Returns a ToolResult. Never raises — every failure mode is captured
    and returned so the caller can branch on it.
    """
    binary = command_list[0]
    progress.tool_start(tool_name)

    if not tool_available(binary):
        msg = f"[MISSING TOOL] '{binary}' not found on PATH. Command skipped: {' '.join(command_list)}"
        _log_error(error_log, msg)
        res = ToolResult(tool_name, command_list, None, "", msg, missing=True)
        progress.tool_end(res)
        return res

    start = time.time()
    try:
        proc = subprocess.run(
            command_list,
            capture_output=True,
            text=True,
            timeout=timeout,
            # Many service-enum tools (openssl s_client, mysql, ncat, smbclient)
            # block reading stdin if it's a TTY. Feed them EOF so they run
            # non-interactively and terminate instead of hanging to timeout.
            stdin=subprocess.DEVNULL,
        )
        duration = time.time() - start

        if output_path:
            _write_raw_output(output_path, command_list, proc.stdout, proc.stderr)

        if proc.returncode != 0:
            msg = (f"[NON-ZERO EXIT] {tool_name} exited {proc.returncode}. "
                   f"cmd: {' '.join(command_list)} | stderr: {proc.stderr.strip()[:300]}")
            _log_error(error_log, msg)

        res = ToolResult(tool_name, command_list, proc.returncode,
                         proc.stdout, proc.stderr, duration=duration,
                         output_file=output_path)
        progress.tool_end(res)
        return res

    except subprocess.TimeoutExpired as e:
        duration = time.time() - start
        msg = f"[TIMEOUT] {tool_name} exceeded {timeout}s. cmd: {' '.join(command_list)}"
        _log_error(error_log, msg)
        partial_out = e.stdout or ""
        partial_err = e.stderr or ""
        if output_path:
            _write_raw_output(output_path, command_list, partial_out,
                               partial_err + "\n[PROCESS KILLED: TIMEOUT]")
        res = ToolResult(tool_name, command_list, None, partial_out, partial_err,
                         timed_out=True, duration=duration, output_file=output_path)
        progress.tool_end(res)
        return res

    except Exception as e:
        msg = f"[EXEC ERROR] {tool_name} raised {type(e).__name__}: {e}. cmd: {' '.join(command_list)}"
        _log_error(error_log, msg)
        res = ToolResult(tool_name, command_list, None, "", str(e))
        progress.tool_end(res)
        return res


def _write_raw_output(path, command_list, stdout, stderr):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(f"# command: {_redact(' '.join(command_list))}\n")
        f.write(f"# timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("# ---- stdout ----\n")
        f.write(_redact(stdout or ""))
        if stderr:
            f.write("\n# ---- stderr ----\n")
            f.write(_redact(stderr))


def _log_error(error_log, message):
    message = _redact(message)
    print(message)
    if error_log:
        os.makedirs(os.path.dirname(error_log), exist_ok=True)
        with open(error_log, "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {message}\n")
