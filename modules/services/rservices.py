"""
R-services (rexec/rlogin/rsh on 512-514) enumeration (read-only).

These legacy services are mostly identified by port presence; nmap's rusers /
finger scripts surface any logged-in-user info they leak. We do not attempt
rlogin/rsh trust-relationship logins (that crosses into access, not
enumeration).
"""

from modules.services.common import register, run_nse
from config.settings import NSE_SCRIPTS


@register("rservices")
def enum_rservices(ctx):
    return {"steps": [{"nse": repr(run_nse(ctx, NSE_SCRIPTS["rservices"]))}]}
