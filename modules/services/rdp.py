"""RDP enumeration (read-only): encryption/security layer + NTLM info."""

from modules.services.common import register, run_nse
from config.settings import NSE_SCRIPTS


@register("rdp")
def enum_rdp(ctx):
    return {"steps": [{"nse": repr(run_nse(ctx, NSE_SCRIPTS["rdp"]))}]}
