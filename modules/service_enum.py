"""
Service-enumeration phase.

Reads the open ports (TCP + UDP) and the -sV-detected service names produced
by the network-scan phase, then dispatches each to the matching per-service
handler in modules/services/. Dispatch prefers the detected service name (so a
MySQL on 3307 or SSH on 2222 still gets the right handler) and falls back to
the standard-port map. Each canonical service is enumerated once per host.
"""

import os

import modules.services  # noqa: F401  (registers all handlers)
from modules import progress
from modules.services.common import HANDLERS, ServiceContext
from config.settings import SERVICE_ALIASES, STANDARD_PORT_MAP

# Services whose enumeration covers the whole host regardless of which port it
# was found on — run these once. Everything else (mail on 143+993, SMTP on
# 25+465, etc.) runs per port so we capture each port's nuances (plaintext
# capabilities vs. the TLS certificate).
_HOST_WIDE = {"smb", "nfs", "rservices", "wmi"}


def _canonical(service_name, portkey):
    """Resolve (nmap service name, 'port/proto') -> canonical handler key."""
    if service_name:
        key = SERVICE_ALIASES.get(service_name.lower())
        if key:
            return key
    return STANDARD_PORT_MAP.get(portkey)


def run_service_enum(target, phase_dir, error_log, config, net_summary):
    """
    target      - Target object from resolver.py
    phase_dir   - <output_root>/<label>/service-enum
    net_summary - the network-scan phase summary (open_ports, udp_ports, services)

    Returns a summary dict for the run manifest.
    """
    os.makedirs(phase_dir, exist_ok=True)
    host = target.ip or target.domain
    services = net_summary.get("services", {}) if net_summary else {}
    ports = list(net_summary.get("open_ports", []) if net_summary else [])
    ports += list(net_summary.get("udp_ports", []) if net_summary else [])

    summary = {"phase": "service-enum", "enumerated": [], "steps": []}

    # Pass 1: decide the work list (dispatch + dedup) so we know the total up
    # front and can report "service j/N".
    work = []            # (portkey, portnum, proto, canon, handler)
    seen = set()
    for portkey in ports:
        if "/" not in portkey:
            continue
        portnum, proto = portkey.split("/", 1)
        svc_name = services.get(portkey)
        canon = _canonical(svc_name, portkey)

        if not canon:
            summary["steps"].append(
                {"port": portkey, "service": svc_name, "detail": "no enumerator for this service"})
            continue
        handler = HANDLERS.get(canon)
        if not handler:
            summary["steps"].append(
                {"port": portkey, "service": svc_name, "handler": canon,
                 "detail": "handler not implemented"})
            continue
        if canon in _HOST_WIDE and canon in seen:
            summary["steps"].append(
                {"port": portkey, "service": canon, "detail": "already enumerated on this host"})
            continue
        seen.add(canon)
        work.append((portkey, portnum, proto, canon, handler))

    # Pass 2: run each, announcing progress.
    progress.set_subtotal(len(work))
    for portkey, portnum, proto, canon, handler in work:
        progress.start_subitem(f"{canon} ({portkey})")
        ctx = ServiceContext(host, target.ip, target.domain, portnum, proto,
                             canon, phase_dir, error_log, config)
        try:
            result = handler(ctx)
        except Exception as e:  # a broken handler must not kill the phase
            result = {"error": f"{type(e).__name__}: {e}"}
            _log(error_log, f"[SERVICE-ENUM] handler '{canon}' raised: {e}")

        summary["enumerated"].append(canon)
        summary["steps"].append({"port": portkey, "service": canon, "result": result})

    if not summary["enumerated"]:
        summary["detail"] = "No open ports mapped to a service enumerator."
    return summary


def _log(error_log, message):
    print(message)
    if error_log:
        import time
        os.makedirs(os.path.dirname(error_log), exist_ok=True)
        with open(error_log, "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {message}\n")
