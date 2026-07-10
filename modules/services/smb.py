"""
SMB / NetBIOS enumeration (read-only).

Combines nmap NSE, a share listing (null session or authenticated), rpcclient
null-session queries, smbmap, and enum4linux-ng. All queries are read-only:
share/user/group/domain enumeration and RID cycling — no writes, no
credential brute-force.
"""

from modules.services.common import register, run_nse, run_native
from config.settings import NSE_SCRIPTS


def _user_arg(ctx):
    """smbclient/-U style 'user%pass' (or empty for null session)."""
    u = ctx.creds["username"]
    if not u:
        return None
    dom = ctx.creds["domain"]
    p = ctx.creds["password"] or ""
    prefix = f"{dom}/" if dom else ""
    return f"{prefix}{u}%{p}"


@register("smb")
def enum_smb(ctx):
    steps = [{"nse": repr(run_nse(ctx, NSE_SCRIPTS["smb"]))}]
    auth = _user_arg(ctx)

    # Share listing.
    smb_cmd = ["smbclient", "-L", f"//{ctx.host}/", "-t", "15"]
    smb_cmd += ["-U", auth] if auth else ["-N"]
    steps.append({"smbclient_shares": repr(
        run_native(ctx, "smbclient-L", smb_cmd, f"{ctx.port}_smb_shares.txt"))})

    # rpcclient null/authenticated session: server info, domains, shares,
    # users, groups. RID cycling stays within enumeration.
    rpc_cmds = ("srvinfo;enumdomains;querydominfo;netshareenumall;"
                "enumdomusers;enumdomgroups;enumalsgroups builtin")
    rpc_user = auth if auth else "%"
    steps.append({"rpcclient": repr(run_native(
        ctx, "rpcclient", ["rpcclient", "-U", rpc_user, "-c", rpc_cmds, ctx.host],
        f"{ctx.port}_smb_rpcclient.txt"))})

    # smbmap: share permissions.
    smbmap = ["smbmap", "-H", ctx.host]
    if ctx.creds["username"]:
        smbmap += ["-u", ctx.creds["username"], "-p", ctx.creds["password"] or ""]
        if ctx.creds["domain"]:
            smbmap += ["-d", ctx.creds["domain"]]
    else:
        smbmap += ["-u", "", "-p", ""]
    steps.append({"smbmap": repr(run_native(ctx, "smbmap", smbmap, f"{ctx.port}_smb_smbmap.txt"))})

    # enum4linux-ng: broad automated enumeration.
    e4 = ["enum4linux-ng", "-A", ctx.host]
    if ctx.creds["username"]:
        e4 += ["-u", ctx.creds["username"], "-p", ctx.creds["password"] or ""]
    steps.append({"enum4linux_ng": repr(run_native(
        ctx, "enum4linux-ng", e4, f"{ctx.port}_smb_enum4linux.txt", timeout=300))})

    return {"steps": steps}
