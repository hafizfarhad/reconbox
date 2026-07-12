"""
MSSQL enumeration (read-only).

nmap ms-sql-* scripts, including the default-credential check
ms-sql-empty-password. When read-only creds are supplied they are passed to
the NSE scripts so the info/config scripts run authenticated — no separate
interactive client needed, and nothing writes.

Credentials are handed to nmap via --script-args-file (a short-lived temp
file we delete) rather than --script-args, so the password never lands on the
command line and therefore never in nmap's own -oA XML (which records args=
verbatim).
"""

import os
import tempfile

from modules.executor import run_tool
from modules.services.common import register, nse_base_cmd
from config.settings import NSE_SCRIPTS, TIMEOUTS


@register("mssql")
def enum_mssql(ctx):
    base = ctx.out(f"{ctx.port}_mssql_nse")
    # -Pn (port already known open) + -6 for IPv6 hosts, same as run_nse.
    cmd = nse_base_cmd(ctx, NSE_SCRIPTS["mssql"])

    args_file = None
    if ctx.has_creds:
        u = ctx.creds["username"]
        p = ctx.creds["password"] or ""
        # Temp file in /tmp (not /output), one key=value per line.
        fd, args_file = tempfile.mkstemp(prefix="reconbox_mssql_", suffix=".args")
        with os.fdopen(fd, "w") as f:
            f.write(f"mssql.username={u}\nmssql.password={p}\n")
        cmd += ["--script-args-file", args_file]

    cmd += [ctx.host, "-oA", base]
    try:
        r = run_tool("nse-mssql", cmd, output_path=None,
                     timeout=TIMEOUTS["nse_default"], error_log=ctx.error_log)
    finally:
        if args_file and os.path.exists(args_file):
            os.remove(args_file)

    return {"steps": [{"nse": repr(r), "authenticated": ctx.has_creds}]}
