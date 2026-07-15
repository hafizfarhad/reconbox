# Vendored wordlists

These three files are a subset of [SecLists](https://github.com/danielmiessler/SecLists)
(MIT licensed), vendored into the image instead of installing the full ~1.9GB
`seclists` apt package. They are placed at the same paths the package used, so
`config/settings.py` (`SECLISTS_ROOT=/usr/share/seclists`) needs no changes.

| File | Purpose | Setting |
|------|---------|---------|
| `Discovery/DNS/subdomains-top1million-20000.txt` | subdomain brute-force | `DEFAULT_SUBDOMAIN_WORDLIST` |
| `Discovery/Web-Content/common.txt` | ffuf content discovery | `DEFAULT_FFUF_WORDLIST` |
| `Discovery/SNMP/snmp.txt` | SNMP community strings | `DEFAULT_SNMP_WORDLIST` |

Operators can point at their own lists at runtime via the `RECONBOX_SUBDOMAIN_WORDLIST`,
`RECONBOX_FFUF_WORDLIST`, and `RECONBOX_SNMP_WORDLIST` environment variables
(mount the file into the container and set the path).

To refresh from upstream SecLists, replace these files with the current versions
from https://github.com/danielmiessler/SecLists.
