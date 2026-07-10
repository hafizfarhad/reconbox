"""
WinRM enumeration (read-only).

Detection via HTTP fingerprint on 5985/5986, plus — only when read-only creds
are supplied and netexec is available — an authenticated WinRM check
(protocol/host info). We never open a shell or run remote commands.
"""

from modules.services.common import register, run_nse, run_native
from modules.executor import tool_available
from config.settings import NSE_SCRIPTS


@register("winrm")
def enum_winrm(ctx):
    steps = [{"nse": repr(run_nse(ctx, NSE_SCRIPTS["winrm"]))}]

    if ctx.has_creds and tool_available("nxc"):
        u = ctx.creds["username"]
        p = ctx.creds["password"] or ""
        cmd = ["nxc", "winrm", ctx.host, "-u", u, "-p", p]
        if ctx.creds["domain"]:
            cmd += ["-d", ctx.creds["domain"]]
        steps.append({"nxc_winrm": repr(run_native(
            ctx, "nxc-winrm", cmd, f"{ctx.port}_winrm_nxc.txt"))})
    else:
        steps.append({"authenticated": "skipped (needs creds + netexec; "
                                        "read-only, no remote shell)"})
    return {"steps": steps}
