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
            # impacket parses the inline "domain/user:password@host" target by
            # splitting on '/', ':' and '@' with NO escaping mechanism, so these
            # characters in a credential would silently mis-parse and auth as the
            # wrong principal. '@' or '/' anywhere, or ':' in the username/domain,
            # are unrepresentable -- fall back to an unauthenticated rpcdump
            # rather than authenticate incorrectly. ('/' allowed in password.)
            unsafe = (any(c in u for c in "@/:")
                      or any(c in dom for c in "@/:")
                      or "@" in p)
            if unsafe:
                steps.append({"rpcdump_auth_note":
                              "credential contains a character impacket's inline "
                              "target syntax cannot escape (@ / : in user/domain, "
                              "or @ in password) -- running unauthenticated rpcdump."})
            else:
                prefix = f"{dom}/" if dom else ""
                # NOTE: impacket-rpcdump encodes the password in the connection
                # string on argv (visible via `ps`); it has no off-argv option
                # that works non-interactively. Still redacted in on-disk output.
                target = f"{prefix}{u}:{p}@{ctx.host}"
        steps.append({"rpcdump": repr(run_native(
            ctx, "impacket-rpcdump", ["impacket-rpcdump", target],
            f"{ctx.port}_msrpc_rpcdump.txt"))})

    return {"steps": steps}
