"""
SMTP enumeration (read-only).

nmap smtp-commands / smtp-open-relay / smtp-ntlm-info, plus a direct
banner+EHLO+VRFY probe on plaintext ports and a STARTTLS/implicit-TLS
certificate grab. VRFY of a couple of fixed names is user-existence
enumeration, not brute-force.
"""

from modules.services.common import register, run_nse, run_native, raw_banner, write_text
from config.settings import NSE_SCRIPTS

_IMPLICIT_TLS_PORTS = {"465"}


@register("smtp")
def enum_smtp(ctx):
    steps = [{"nse": repr(run_nse(ctx, NSE_SCRIPTS["smtp"]))}]

    if ctx.port in _IMPLICIT_TLS_PORTS:
        cert = run_native(
            ctx, "openssl-smtps",
            ["openssl", "s_client", "-connect", f"{ctx.host}:{ctx.port}"],
            f"{ctx.port}_smtp_cert.txt", timeout=20)
        steps.append({"tls_cert": repr(cert)})
    else:
        convo = raw_banner(ctx.host, ctx.port,
                           send=["EHLO reconbox.local", "VRFY root",
                                 "VRFY admin", "QUIT"])
        write_text(ctx.out(f"{ctx.port}_smtp_probe.txt"), convo)
        steps.append({"smtp_probe": "captured"})
        # STARTTLS cert on submission/25 if available.
        cert = run_native(
            ctx, "openssl-smtp",
            ["openssl", "s_client", "-connect", f"{ctx.host}:{ctx.port}", "-starttls", "smtp"],
            f"{ctx.port}_smtp_cert.txt", timeout=20)
        steps.append({"starttls_cert": repr(cert)})

    return {"steps": steps}
