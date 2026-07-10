"""Rsync daemon enumeration (read-only)."""

from modules.services.common import register, run_nse, run_native
from config.settings import NSE_SCRIPTS


@register("rsync")
def enum_rsync(ctx):
    steps = [{"nse": repr(run_nse(ctx, NSE_SCRIPTS["rsync"]))}]

    # List available modules (shares). --list-only never transfers files.
    listing = run_native(
        ctx, "rsync-list",
        ["rsync", "--list-only", "--contimeout=15", f"rsync://{ctx.host}:{ctx.port}/"],
        f"{ctx.port}_rsync_modules.txt",
    )
    steps.append({"modules": repr(listing)})
    return {"steps": steps}
