"""
MySQL / MariaDB enumeration (read-only).

nmap mysql-* scripts (mysql-info + the default-credential check
mysql-empty-password), and — only when read-only creds are supplied — a
version/database listing via the mysql client.
"""

from modules.services.common import register, run_nse, run_native
from config.settings import NSE_SCRIPTS


@register("mysql")
def enum_mysql(ctx):
    steps = [{"nse": repr(run_nse(ctx, NSE_SCRIPTS["mysql"]))}]

    if ctx.has_creds:
        u = ctx.creds["username"]
        p = ctx.creds["password"]
        args = ["mysql", "-h", ctx.host, "-P", ctx.port, "-u", u]
        if p:
            args.append(f"-p{p}")
        args += ["--connect-timeout=15", "-e",
                 "select version(); show databases;"]
        steps.append({"mysql_query": repr(run_native(
            ctx, "mysql", args, f"{ctx.port}_mysql_query.txt"))})

    return {"steps": steps}
