"""
CDN / reverse-proxy edge detection.

When a domain resolves to a CDN/WAF edge (Cloudflare, etc.), an unauthenticated
external scan describes the CDN, NOT the origin server: the "open ports" are the
CDN's standard proxy ports, banners are the CDN's, and active content discovery
(ffuf) just hits a rate-limiting edge that returns challenge/error pages. So we
detect this and let the phases downgrade accordingly (skip fuzzing, cap
endpoints, and flag the finding loudly).

IP ranges are the published Cloudflare lists (https://www.cloudflare.com/ips/).
They change rarely; kept static so detection needs no network call.
"""

import ipaddress

# Cloudflare published ranges (v4 + v6).
_CLOUDFLARE_V4 = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]
_CLOUDFLARE_V6 = [
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]

_CDN_NETS = [("Cloudflare", ipaddress.ip_network(c))
             for c in _CLOUDFLARE_V4 + _CLOUDFLARE_V6]


def cdn_for_ip(ip):
    """Return the CDN name if `ip` falls in a known CDN range, else None."""
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for name, net in _CDN_NETS:
        if addr.version == net.version and addr in net:
            return name
    return None
