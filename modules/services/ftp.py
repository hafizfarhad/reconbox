"""FTP / FTPS enumeration (read-only)."""

from modules.services.common import register, run_nse, run_native
from config.settings import NSE_SCRIPTS


@register("ftp")
def enum_ftp(ctx):
    steps = [{"nse": repr(run_nse(ctx, NSE_SCRIPTS["ftp"]))}]

    # Directory listing over FTP. Uses supplied creds if any, else anonymous.
    user = ctx.creds["username"] or "anonymous"
    pw = ctx.creds["password"] or "anonymous"
    url = f"ftp://{ctx.host}:{ctx.port}/"
    listing = run_native(
        ctx, "curl-ftp",
        ["curl", "-s", "--connect-timeout", "10", "--user", f"{user}:{pw}", url],
        f"{ctx.port}_ftp_listing.txt",
    )
    steps.append({"listing": repr(listing), "auth": "creds" if ctx.has_creds else "anonymous"})

    # STARTTLS certificate (reveals hostnames / org for FTPS-capable servers).
    cert = run_native(
        ctx, "openssl-ftp",
        ["openssl", "s_client", "-connect", f"{ctx.host}:{ctx.port}", "-starttls", "ftp"],
        f"{ctx.port}_ftp_cert.txt", timeout=20,
    )
    steps.append({"starttls_cert": repr(cert)})
    return {"steps": steps}
