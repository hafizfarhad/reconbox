"""TFTP (UDP) enumeration (read-only)."""

from modules.services.common import register, run_nse
from config.settings import NSE_SCRIPTS


@register("tftp")
def enum_tftp(ctx):
    return {"steps": [{"nse": repr(run_nse(ctx, NSE_SCRIPTS["tftp"]))}]}
