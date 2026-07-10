"""
Service-enumeration handlers.

Importing this package imports every service module, which runs their
@register decorators and populates modules.services.common.HANDLERS. The
dispatcher (modules/service_enum.py) then looks handlers up by canonical
service key.
"""

from modules.services import (  # noqa: F401  (imported for registration side effects)
    ftp, tftp, smb, nfs, rsync, smtp, mail, dns, snmp,
    mysql, mssql, oracle, ssh, rdp, winrm, wmi, rservices, ipmi,
)
