"""
SMB / NetBIOS enumeration (read-only).

Combines nmap NSE, a share listing (null session or authenticated), rpcclient
null-session queries, smbmap, and enum4linux-ng. All queries are read-only:
share/user/group/domain enumeration and RID cycling — no writes, no
credential brute-force.
"""

import contextlib

from modules.services.common import register, run_nse, run_native, creds_file
from config.settings import NSE_SCRIPTS


def _authfile_body(ctx):
    """
    Samba -A authentication-file body, or None for a null session.

    The file is line-oriented (`key = value`) with no quoting/escaping, so a
    CR or LF in any value would inject a new directive. Such a character cannot
    be part of a real SMB credential passed this way, so we return None (null
    session) rather than build a corrupted file.
    """
    u = ctx.creds["username"]
    if not u:
        return None
    pw = ctx.creds["password"] or ""
    dom = ctx.creds["domain"] or ""
    if any(("\n" in v) or ("\r" in v) for v in (u, pw, dom)):
        return None
    lines = [f"username = {u}", f"password = {pw}"]
    if dom:
        lines.append(f"domain = {dom}")
    return "\n".join(lines) + "\n"


@register("smb")
def enum_smb(ctx):
    steps = [{"nse": repr(run_nse(ctx, NSE_SCRIPTS["smb"]))}]
    authenticated = bool(ctx.creds["username"])

    rpc_cmds = ("srvinfo;enumdomains;querydominfo;netshareenumall;"
                "enumdomusers;enumdomgroups;enumalsgroups builtin")

    with contextlib.ExitStack() as stack:
        # Samba tools (smbclient, rpcclient) read credentials from an -A
        # authentication-file, keeping the password off argv. smbmap and
        # enum4linux-ng have no equivalent option, so when authenticated they
        # still take -p on argv (see the caveat below).
        authfile = None
        if authenticated:
            body = _authfile_body(ctx)
            if body:
                authfile = stack.enter_context(
                    creds_file(body, prefix="reconbox_smb_", suffix=".auth"))

        # Share listing.
        smb_cmd = ["smbclient", "-L", f"//{ctx.host}/", "-t", "15"]
        smb_cmd += ["-A", authfile] if authfile else ["-N"]
        steps.append({"smbclient_shares": repr(
            run_native(ctx, "smbclient-L", smb_cmd, f"{ctx.port}_smb_shares.txt"))})

        # rpcclient null/authenticated session: server info, domains, shares,
        # users, groups. RID cycling stays within enumeration.
        rpc_cmd = ["rpcclient", "-c", rpc_cmds]
        rpc_cmd += ["-A", authfile] if authfile else ["-U", "%"]
        rpc_cmd.append(ctx.host)
        steps.append({"rpcclient": repr(run_native(
            ctx, "rpcclient", rpc_cmd, f"{ctx.port}_smb_rpcclient.txt"))})

        # smbmap: share permissions. NOTE: smbmap has no auth-file option, so
        # an authenticated password is passed on argv here -- redacted in the
        # on-disk output but visible via `ps` for the tool's lifetime.
        smbmap = ["smbmap", "-H", ctx.host]
        if authenticated:
            smbmap += ["-u", ctx.creds["username"], "-p", ctx.creds["password"] or ""]
            if ctx.creds["domain"]:
                smbmap += ["-d", ctx.creds["domain"]]
        else:
            smbmap += ["-u", "", "-p", ""]
        steps.append({"smbmap": repr(run_native(ctx, "smbmap", smbmap, f"{ctx.port}_smb_smbmap.txt"))})

        # enum4linux-ng: broad automated enumeration. Same argv caveat as
        # smbmap ('-A' here is enum4linux-ng's own "all enumeration" flag).
        e4 = ["enum4linux-ng", "-A", ctx.host]
        if authenticated:
            e4 += ["-u", ctx.creds["username"], "-p", ctx.creds["password"] or ""]
        steps.append({"enum4linux_ng": repr(run_native(
            ctx, "enum4linux-ng", e4, f"{ctx.port}_smb_enum4linux.txt", timeout=300))})

    return {"steps": steps}
