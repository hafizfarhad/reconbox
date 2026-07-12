"""
MySQL / MariaDB enumeration (read-only).

nmap mysql-* scripts (mysql-info + the default-credential check
mysql-empty-password), and — only when read-only creds are supplied — a
version/database listing via the mysql client.
"""

import contextlib

from modules.services.common import register, run_nse, run_native, creds_file
from config.settings import NSE_SCRIPTS


def _mycnf_value(s):
    r"""
    Encode a password as a MySQL option-file double-quoted value. MySQL
    recognizes \\ \" \n \r \t escapes inside a quoted value, so escaping these
    stops a newline (or quote) in the password from starting a second, injected
    directive line in the [client] section.
    """
    s = (s or "").replace("\\", "\\\\").replace('"', '\\"')
    s = s.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return f'"{s}"'


@register("mysql")
def enum_mysql(ctx):
    steps = [{"nse": repr(run_nse(ctx, NSE_SCRIPTS["mysql"]))}]

    if ctx.has_creds:
        u = ctx.creds["username"]
        p = ctx.creds["password"]
        # Password goes in a --defaults-extra-file, never on argv (see
        # creds_file). --defaults-extra-file must be mysql's first option.
        with contextlib.ExitStack() as stack:
            args = ["mysql"]
            if p:
                cnf = stack.enter_context(
                    creds_file(f"[client]\npassword={_mycnf_value(p)}\n",
                               prefix="reconbox_mysql_", suffix=".cnf"))
                args.append(f"--defaults-extra-file={cnf}")
            args += ["-h", ctx.host, "-P", ctx.port, "-u", u,
                     "--connect-timeout=15", "-e",
                     "select version(); show databases;"]
            steps.append({"mysql_query": repr(run_native(
                ctx, "mysql", args, f"{ctx.port}_mysql_query.txt"))})

    return {"steps": steps}
