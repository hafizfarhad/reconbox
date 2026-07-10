"""
Oracle TNS enumeration (read-only).

nmap oracle-tns-version + oracle-sid-brute (SID guessing is identifier
enumeration, not a password brute-force). Heavier tooling (sqlplus /
instantclient / ODAT) is intentionally not bundled in this balanced build.
"""

from modules.services.common import register, run_nse
from config.settings import NSE_SCRIPTS, TIMEOUTS


@register("oracle")
def enum_oracle(ctx):
    r = run_nse(ctx, NSE_SCRIPTS["oracle"], timeout=TIMEOUTS["nse_slow"])
    return {"steps": [
        {"nse": repr(r)},
        {"note": "Credentialed SID/data enumeration (sqlplus/ODAT) not bundled "
                 "in the balanced build."},
    ]}
