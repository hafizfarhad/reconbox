"""
NFS / RPC enumeration (read-only).

nmap rpcinfo + nfs-* scripts, showmount for exports, and — when running as
root — a read-only mount of the export to list contents (uid/gid ownership is
often revealing). The mount is always ro,nolock and is unmounted afterwards.
"""

import os

from modules.services.common import register, run_nse, run_native
from modules.executor import run_tool, tool_available
from config.settings import NSE_SCRIPTS, TIMEOUTS


@register("nfs")
def enum_nfs(ctx):
    steps = [{"nse": repr(run_nse(ctx, NSE_SCRIPTS["nfs"]))}]

    steps.append({"showmount": repr(run_native(
        ctx, "showmount", ["showmount", "-e", ctx.host], f"{ctx.port}_nfs_showmount.txt"))})

    privileged = hasattr(os, "geteuid") and os.geteuid() == 0
    if privileged and tool_available("mount"):
        mp = ctx.out(f"nfs_mount_{ctx.port}")
        os.makedirs(mp, exist_ok=True)
        m = run_native(
            ctx, "mount-nfs",
            ["mount", "-t", "nfs", "-o", "ro,nolock,soft", f"{ctx.host}:/", mp],
            f"{ctx.port}_nfs_mount.txt", timeout=TIMEOUTS["nfs_mount"])
        steps.append({"mount": repr(m)})
        if m.ok:
            # -n shows raw uid/gid; -laR walks the tree.
            run_native(ctx, "ls-nfs", ["ls", "-laRn", mp], f"{ctx.port}_nfs_listing.txt")
            run_tool("umount", ["umount", "-f", "-l", mp], timeout=30, error_log=ctx.error_log)
    else:
        steps.append({"mount": "skipped (read-only mount requires root)"})

    return {"steps": steps}
