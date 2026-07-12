"""
Robust parsing of nmap's XML output (-oX / -oA .xml).

The network-scan phase decides what to do next based on port state, so
parsing has to be reliable. nmap's normal (stdout) format is easy to
regex but lossy and format-fragile; the XML output is structured and
carries the extra fields we care about (reason, service product/version,
OS matches). We parse the XML file nmap writes rather than its stdout.

Everything here is defensive: a scan that timed out may leave a partial,
unclosed XML document on disk. We recover whatever hosts/ports nmap
managed to flush and never raise -- callers fall back to an empty result.
"""

import xml.etree.ElementTree as ET


class NmapScan:
    """Parsed view of a single nmap XML file."""

    # States we treat as "filtered" for firewall/evasion decisions.
    _FILTERED_STATES = ("filtered", "open|filtered", "closed|filtered")

    def __init__(self, host_up=False, host_reason=None, ports=None,
                 os_matches=None, parse_error=None,
                 port_scripts=None, host_scripts=None, extra_ports=None):
        self.host_up = host_up
        self.host_reason = host_reason        # e.g. "arp-response", "echo-reply", "user-set"
        self.ports = ports or {}              # {"22/tcp": {state, reason, service, product, version}}
        self.os_matches = os_matches or []    # [{"name": ..., "accuracy": ...}]
        self.parse_error = parse_error        # str if the file was unreadable/partial
        self.port_scripts = port_scripts or {}   # {"80/tcp": [{"id":..., "output":...}]}
        self.host_scripts = host_scripts or []   # [{"id":..., "output":...}] (host-level NSE)
        # Aggregate {state: count} from nmap's <extraports> summaries. nmap
        # collapses large groups of same-state ports (e.g. "Not shown: 100
        # filtered tcp ports") into a single <extraports> element instead of
        # listing each <port>, so for those ports this count is the ONLY record.
        self.extra_ports = extra_ports or {}

    def ports_in_state(self, *states):
        """Port keys (e.g. '22/tcp') whose state is one of `states`."""
        return [p for p, info in self.ports.items() if info["state"] in states]

    @property
    def open_ports(self):
        return self.ports_in_state("open")

    @property
    def filtered_ports(self):
        # open|filtered and closed|filtered are ambiguous-but-possibly-blocked;
        # we treat them as "filtered" for firewall/evasion decisions. These are
        # the individually-listed ports only (usable as evasion targets).
        return self.ports_in_state(*self._FILTERED_STATES)

    def extra_filtered_count(self):
        """Number of filtered-ish ports that nmap reported only as an
        <extraports> aggregate (never as individual <port> elements)."""
        return sum(c for s, c in self.extra_ports.items()
                   if s in self._FILTERED_STATES)

    @property
    def filtered_signal(self):
        """True if ANY port is filtered — whether listed individually or
        collapsed into an <extraports> summary. Use this (not filtered_ports)
        to answer 'is a firewall dropping packets?': an ACK scan of a
        firewalled host reports every filtered port only via <extraports>, so
        filtered_ports would be empty even though a firewall is clearly present."""
        return bool(self.filtered_ports) or self.extra_filtered_count() > 0


def _read_root(xml_path):
    """
    Parse the XML file into a root element. Handles the common
    timed-out-scan case where nmap left an unterminated document by
    retrying against a repaired copy.
    """
    try:
        return ET.parse(xml_path).getroot(), None
    except (ET.ParseError, FileNotFoundError, OSError) as e:
        # Attempt recovery: nmap flushes <host> elements as it goes, so a
        # truncated file is often valid up to the last complete tag. Close
        # the root element and re-parse whatever we have.
        try:
            with open(xml_path, "r", errors="replace") as f:
                data = f.read()
            if "<nmaprun" in data and "</nmaprun>" not in data:
                # Trim to the last complete </host> and close the run.
                cut = data.rfind("</host>")
                if cut != -1:
                    data = data[:cut + len("</host>")] + "\n</nmaprun>"
                    return ET.fromstring(data), f"recovered-partial: {e}"
        except (ET.ParseError, OSError):
            pass
        return None, str(e)


def parse_scan(xml_path):
    """Parse an nmap XML file into an NmapScan. Never raises."""
    root, err = _read_root(xml_path)
    if root is None:
        return NmapScan(parse_error=err)

    host_up = False
    host_reason = None
    ports = {}
    os_matches = []
    port_scripts = {}
    host_scripts = []
    extra_ports = {}

    host = root.find("host")
    if host is not None:
        status = host.find("status")
        if status is not None:
            host_up = status.get("state") == "up"
            host_reason = status.get("reason")

        for port in host.findall("./ports/port"):
            portid = port.get("portid")
            proto = port.get("protocol")
            if not portid or not proto:
                continue
            key = f"{portid}/{proto}"
            state_el = port.find("state")
            svc_el = port.find("service")
            state = state_el.get("state") if state_el is not None else "unknown"
            reason = state_el.get("reason") if state_el is not None else None
            entry = {"state": state, "reason": reason, "service": None,
                     "product": None, "version": None}
            if svc_el is not None:
                entry["service"] = svc_el.get("name")
                entry["product"] = svc_el.get("product")
                entry["version"] = svc_el.get("version")
            ports[key] = entry

            scripts = _scripts(port)
            if scripts:
                port_scripts[key] = scripts

        # <extraports state="filtered" count="100"> — ports nmap did not list
        # individually. Critical for firewall detection (an ACK scan of a
        # firewalled host puts ALL filtered ports here and lists none).
        ports_el = host.find("ports")
        if ports_el is not None:
            for ep in ports_el.findall("extraports"):
                st = ep.get("state")
                cnt = ep.get("count")
                if not st or not cnt:
                    continue
                try:
                    extra_ports[st] = extra_ports.get(st, 0) + int(cnt)
                except (TypeError, ValueError):
                    pass

        for osmatch in host.findall("./os/osmatch"):
            os_matches.append({
                "name": osmatch.get("name"),
                "accuracy": osmatch.get("accuracy"),
            })

        host_scripts = _scripts(host.find("hostscript")) if host.find("hostscript") is not None else []

    return NmapScan(host_up=host_up, host_reason=host_reason, ports=ports,
                    os_matches=os_matches, parse_error=err,
                    port_scripts=port_scripts, host_scripts=host_scripts,
                    extra_ports=extra_ports)


def _scripts(parent):
    """Extract [{id, output}] from an element's direct <script> children."""
    out = []
    if parent is None:
        return out
    for script in parent.findall("script"):
        sid = script.get("id")
        output = script.get("output") or ""
        if sid:
            out.append({"id": sid, "output": output})
    return out
