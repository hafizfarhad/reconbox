"""
IMAP / POP3 enumeration (read-only).

NSE capability + ssl-cert scripts, a capability/banner grab (openssl for the
implicit-TLS ports 993/995, a plain socket for 110/143), and — only when
read-only credentials are supplied — a mailbox/folder listing via curl.
"""

from modules.services.common import register, run_nse, run_native, raw_banner, write_text
from config.settings import NSE_SCRIPTS

# implicit-TLS port -> the curl scheme used for an authenticated listing
_TLS_PORTS = {"993": "imaps", "995": "pop3s"}


@register("imap")
def enum_imap(ctx):
    return _enum_mailbox(ctx, "imap")


@register("pop3")
def enum_pop3(ctx):
    return _enum_mailbox(ctx, "pop3")


def _enum_mailbox(ctx, kind):
    steps = [{"nse": repr(run_nse(ctx, NSE_SCRIPTS[kind]))}]

    if ctx.port in _TLS_PORTS:
        cert = run_native(
            ctx, f"openssl-{kind}",
            ["openssl", "s_client", "-connect", f"{ctx.host}:{ctx.port}"],
            f"{ctx.port}_{kind}_cert.txt", timeout=20)
        steps.append({"tls_cert_and_banner": repr(cert)})
    else:
        probe = "a CAPABILITY" if kind == "imap" else "CAPA"
        convo = raw_banner(ctx.host, ctx.port, send=[probe, "a LOGOUT" if kind == "imap" else "QUIT"])
        write_text(ctx.out(f"{ctx.port}_{kind}_probe.txt"), convo)
        steps.append({"capability_probe": "captured"})

    # Authenticated read-only mailbox listing (only if creds + TLS port).
    if ctx.has_creds and ctx.port in _TLS_PORTS:
        scheme = _TLS_PORTS[ctx.port]
        u = ctx.creds["username"]
        p = ctx.creds["password"] or ""
        listing = run_native(
            ctx, f"curl-{scheme}",
            ["curl", "-k", "-s", f"{scheme}://{ctx.host}:{ctx.port}", "--user", f"{u}:{p}"],
            f"{ctx.port}_{kind}_listing.txt", timeout=30)
        steps.append({"authenticated_listing": repr(listing)})

    return {"steps": steps}
