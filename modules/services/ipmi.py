"""
IPMI enumeration (read-only, UDP 623).

nmap ipmi-version + ipmi-cipher-zero (a config/vuln check). RAKP password-hash
retrieval requires Metasploit, which the balanced build does not bundle; the
manifest records that so the operator knows to run it separately if wanted.
"""

from modules.services.common import register, run_nse
from config.settings import NSE_SCRIPTS


@register("ipmi")
def enum_ipmi(ctx):
    return {"steps": [
        {"nse": repr(run_nse(ctx, NSE_SCRIPTS["ipmi"]))},
        {"note": "RAKP hash retrieval needs Metasploit "
                 "(auxiliary/scanner/ipmi/ipmi_dumphashes); not in balanced build."},
    ]}
