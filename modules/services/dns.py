"""
DNS server enumeration (read-only) — for when the target host itself runs a
DNS server (port 53 open). Domain-wide DNS work (subdomain brute, per-NS
transfers) lives in modules/dns_recon.py; this targets THIS host as a
resolver: version.bind, ANY, and an AXFR attempt against it.
"""

from modules.services.common import register, run_native


@register("dns")
def enum_dns(ctx):
    server = ctx.host
    steps = []

    steps.append({"version_bind": repr(run_native(
        ctx, "dig-version",
        ["dig", "CH", "TXT", "version.bind", f"@{server}", "+short"],
        f"{ctx.port}_dns_version.txt"))})

    if ctx.domain:
        steps.append({"any": repr(run_native(
            ctx, "dig-any",
            ["dig", "ANY", ctx.domain, f"@{server}", "+noall", "+answer"],
            f"{ctx.port}_dns_any.txt"))})
        steps.append({"axfr": repr(run_native(
            ctx, "dig-axfr",
            ["dig", "AXFR", ctx.domain, f"@{server}"],
            f"{ctx.port}_dns_axfr.txt"))})
    else:
        steps.append({"zone_queries": "skipped (no domain known for this target)"})

    return {"steps": steps}
