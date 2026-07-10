"""SSH enumeration (read-only): algorithms, host keys, auth methods, banner."""

from modules.services.common import register, run_nse, run_native, raw_banner, write_text
from modules.executor import tool_available
from config.settings import NSE_SCRIPTS


@register("ssh")
def enum_ssh(ctx):
    steps = [{"nse": repr(run_nse(ctx, NSE_SCRIPTS["ssh"]))}]

    if tool_available("ssh-audit"):
        steps.append({"ssh_audit": repr(run_native(
            ctx, "ssh-audit", ["ssh-audit", "-p", ctx.port, ctx.host],
            f"{ctx.port}_ssh_audit.txt"))})

    # Banner (protocol + server version).
    banner = raw_banner(ctx.host, ctx.port)
    write_text(ctx.out(f"{ctx.port}_ssh_banner.txt"), banner)
    steps.append({"banner": banner.strip()[:120]})
    return {"steps": steps}
