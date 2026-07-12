"""FTP / FTPS enumeration (read-only)."""

from modules.services.common import (
    register, run_nse, run_native, creds_file, curl_config_value,
)
from config.settings import NSE_SCRIPTS


@register("ftp")
def enum_ftp(ctx):
    steps = [{"nse": repr(run_nse(ctx, NSE_SCRIPTS["ftp"]))}]

    # Directory listing over FTP. Uses supplied creds if any, else anonymous.
    url = f"ftp://{ctx.host}:{ctx.port}/"
    if ctx.has_creds:
        # Escape for the double-quoted curl --config value so a quote/backslash
        # in the credential can't corrupt the config or truncate the secret.
        user = curl_config_value(ctx.creds["username"])
        pw = curl_config_value(ctx.creds["password"] or "")
        # Real credentials go in a curl --config file, never on argv.
        with creds_file(f'user = "{user}:{pw}"\n',
                        prefix="reconbox_ftp_", suffix=".cfg") as cfg:
            listing = run_native(
                ctx, "curl-ftp",
                ["curl", "-s", "--connect-timeout", "10", "--config", cfg, url],
                f"{ctx.port}_ftp_listing.txt",
            )
        steps.append({"listing": repr(listing), "auth": "creds"})
    else:
        # Anonymous: no secret, so the login can stay on argv.
        listing = run_native(
            ctx, "curl-ftp",
            ["curl", "-s", "--connect-timeout", "10",
             "--user", "anonymous:anonymous", url],
            f"{ctx.port}_ftp_listing.txt",
        )
        steps.append({"listing": repr(listing), "auth": "anonymous"})

    # STARTTLS certificate (reveals hostnames / org for FTPS-capable servers).
    cert = run_native(
        ctx, "openssl-ftp",
        ["openssl", "s_client", "-connect", f"{ctx.host}:{ctx.port}", "-starttls", "ftp"],
        f"{ctx.port}_ftp_cert.txt", timeout=20,
    )
    steps.append({"starttls_cert": repr(cert)})
    return {"steps": steps}
