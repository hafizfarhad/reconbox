"""
MSRPC / WMI endpoint enumeration (read-only).

Port 135 is the RPC endpoint mapper. We enumerate the exposed endpoints via
nmap msrpc-enum and impacket's rpcdump. We deliberately do NOT run wmiexec or
any command-execution path — that would be remote code execution, outside the
enumeration boundary.
"""

from modules.services.common import register, run_nse, run_native
from modules.executor import tool_available
from config.settings import NSE_SCRIPTS


@register("wmi")
def enum_wmi(ctx):
    steps = [{"nse": repr(run_nse(ctx, NSE_SCRIPTS["wmi"]))}]

    if tool_available("impacket-rpcdump"):
        target = ctx.host
        if ctx.has_creds:
            u = ctx.creds["username"]
            p = ctx.creds["password"] or ""
            dom = ctx.creds["domain"] or ""
            prefix = f"{dom}/" if dom else ""
            target = f"{prefix}{u}:{p}@{ctx.host}"
        steps.append({"rpcdump": repr(run_native(
            ctx, "impacket-rpcdump", ["impacket-rpcdump", target],
            f"{ctx.port}_msrpc_rpcdump.txt"))})

    return {"steps": steps}
