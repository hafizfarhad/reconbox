"""
SNMP enumeration (read-only).

onesixtyone discovers valid community strings from a wordlist (string
guessing, within the enumeration boundary — not a password brute-force), then
snmpwalk dumps the MIB for each discovered community (falling back to
'public').
"""

import re

from modules.services.common import register, run_native
from config.settings import NSE_SCRIPTS, DEFAULT_SNMP_WORDLIST, TIMEOUTS
from modules.services.common import run_nse

_COMMUNITY_RE = re.compile(r"\[([^\]]+)\]")


def _parse_communities(stdout):
    found = []
    for line in (stdout or "").splitlines():
        m = _COMMUNITY_RE.search(line)
        if m and m.group(1) not in found:
            found.append(m.group(1))
    return found


@register("snmp")
def enum_snmp(ctx):
    steps = [{"nse": repr(run_nse(ctx, NSE_SCRIPTS["snmp"]))}]

    wordlist = ctx.config.get("snmp_wordlist") or DEFAULT_SNMP_WORDLIST
    o161 = run_native(
        ctx, "onesixtyone", ["onesixtyone", "-c", wordlist, ctx.host],
        f"{ctx.port}_snmp_onesixtyone.txt", timeout=TIMEOUTS["service_native"])
    steps.append({"onesixtyone": repr(o161)})

    communities = _parse_communities(o161.stdout) or ["public"]
    for comm in communities[:5]:
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", comm)
        walk = run_native(
            ctx, f"snmpwalk-{safe}",
            ["snmpwalk", "-v2c", "-c", comm, "-t", "5", ctx.host],
            f"{ctx.port}_snmp_walk_{safe}.txt", timeout=TIMEOUTS["nse_default"])
        steps.append({f"snmpwalk[{comm}]": repr(walk)})

    steps.append({"communities_found": communities})
    return {"steps": steps}
