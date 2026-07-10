# ReconBox

A single-command reconnaissance container. Point it at one domain or IP and
it runs the full **recon → footprinting → vulnerability-assessment** arc —
port scanning, per-service enumeration, DNS, and passive OSINT — then folds
everything into one clean **`report.pdf`**.

**It does not exploit.** No password brute-forcing, no remote command
execution, no writes to the target. It maps the attack surface and flags
known issues; it doesn't try to break in. See [The line it won't
cross](#the-line-it-wont-cross).

> ⚠️ Only run this against systems you are authorized to test. The container
> assumes permission has already been established.

---

## Quick start

Pull it (or build it — see [Building](#building)):

```bash
docker pull hafizfarhad/reconbox:latest
```

Run it, mounting a folder for the results:

```bash
mkdir -p output
docker run --rm -v "$(pwd)/output:/output" hafizfarhad/reconbox scanme.nmap.org
```

The result is a clean **`report.pdf`** in `./output/<target>/`. A full run is
thorough and can take a while — watch the [live progress](#watching-progress)
to see where it's at.

For the raw-socket features (SYN/UDP/OS scans, evasion, NFS mount) grant the
extra capabilities:

```bash
docker run --rm \
  --cap-add=NET_RAW --cap-add=NET_ADMIN --cap-add=SYS_ADMIN \
  -v "$(pwd)/output:/output" \
  hafizfarhad/reconbox 10.129.2.28
```

Without them nothing crashes — those steps are skipped and noted.

---

## What it runs

| Phase | When | What it does |
|-------|------|--------------|
| **network-scan** | always | Host discovery, port scan (SYN as root, else Connect), full `-p-` sweep, UDP scan, firewall detection (ACK), adaptive evasion, service/OS/version deep scan, `vuln` NSE scripts, HTML reports. |
| **service-enum** | always | Enumerates every open service in depth — FTP, SMB, NFS, Rsync, SMTP, IMAP/POP3, DNS, SNMP, MySQL, MSSQL, Oracle, SSH, RDP, WinRM, WMI, R-services, IPMI, TFTP. |
| **dns-recon** | domains | whois, `dig` records, subfinder/dnsx, `ANY`, per-nameserver AXFR + `version.bind`, subdomain brute-force. |
| **web-recon** | domains | httpx, whatweb, katana crawl, gau (archived URLs), ffuf content discovery (dirs + files). |
| **osint** | domains | crt.sh certificate transparency, TLS certificate SANs, optional Shodan lookup. |
| **report** | always | Parses everything into a single clean **`report.pdf`** (WeasyPrint) — findings tables + full formatted evidence. |

**network-scan is a decision tree, not a fixed list** — evasion only fires
when a firewall is detected, the deep scan only targets confirmed-open ports,
and so on. Everything degrades gracefully: a missing tool or a timeout is
logged, never fatal.

---

## Watching progress

The container prints a live heartbeat (names, counts, timings — never tool
output) so you can gauge how much longer to wait:

```
[00:00] Phase 1/6 · network-scan
[00:02]   ✓ nmap-host-discovery (2.1s, exit 0) · 1 steps done
[03:20] Phase 2/6 · service-enum
[03:20]   [1/8] smb (445/tcp)
[03:20]     ▶ nse-smb-445 …
[19:40] Done · 63 tool runs across 6 phase(s) · total 19:40
```

Running detached? Follow it with `docker logs -f <container>`.

---

## Configuration

Everything is configured at **run time** — there's no file to edit. Two ways:

### Interactive (add `-it`)

```bash
docker run --rm -it -v "$(pwd)/output:/output" hafizfarhad/reconbox 10.129.2.28
```

A short wizard asks whether you want to set advanced options, then walks you
through them. Just press Enter to accept defaults.

### Environment variables (headless / CI)

| Variable | Purpose | Default |
|----------|---------|---------|
| `RECONBOX_USERNAME` / `RECONBOX_PASSWORD` / `RECONBOX_DOMAIN` | Authenticated **read-only** enumeration | anonymous |
| `RECONBOX_SSH_KEY` | SSH private-key path (must be mounted in) | — |
| `RECONBOX_SHODAN_KEY` | Enables the Shodan lookup | skipped |
| `RECONBOX_SOURCE_IP` / `RECONBOX_INTERFACE` / `RECONBOX_DNS_SERVER` | Evasion (off unless set) | off |
| `RECONBOX_SOURCE_PORT` / `RECONBOX_DECOY_COUNT` | Evasion tuning | `53` / `10` |
| `RECONBOX_SUBDOMAIN_WORDLIST` / `RECONBOX_SNMP_WORDLIST` / `RECONBOX_FFUF_WORDLIST` | Wordlists (SecLists bundled) | SecLists |
| `RECONBOX_FFUF_EXTENSIONS` | Extensions ffuf appends to each candidate | `.php,.html,.txt` |
| `RECONBOX_SUBDOMAIN_MAX` | Cap on subdomain brute candidates | `20000` |
| `RECONBOX_KEEP_RAW=1` | Keep raw phase folders (default: deleted after the PDF) | delete |
| `RECONBOX_CONFIGURE=1` / `RECONBOX_NO_PROMPT=1` | Force the wizard on / off | — |

```bash
docker run --rm \
  -e RECONBOX_USERNAME=robin -e RECONBOX_PASSWORD=robin \
  -v "$(pwd)/output:/output" \
  hafizfarhad/reconbox inlanefreight.htb
```

**Two tips:**

- **Secrets** (`PASSWORD`, `SHODAN_KEY`) are safer in a file than on the
  command line (which shows in `docker inspect`): use
  `--env-file secrets.env`. ReconBox masks them in its own output/logs, but
  that's separate from Docker's exposure.
- **File paths** (SSH key, custom wordlist) are paths *inside* the container,
  so mount the file and point the variable at it:
  ```bash
  -v "$(pwd)/id_rsa:/keys/id_rsa:ro" -e RECONBOX_SSH_KEY=/keys/id_rsa
  ```

---

## Output layout

By default the run is **PDF-only** — once `report.pdf` is written, the raw
phase folders are deleted (everything worth keeping is in the PDF):

```
output/<target>/
├── report.pdf              # the deliverable — findings tables + full evidence
├── report.html             # same report, pre-conversion
└── meta/
    ├── target_info.json    # input classification + run config (secrets masked)
    ├── run_manifest.json    # index of every step, per phase, with status
    └── errors.log           # missing tools / timeouts / non-zero exits
```

Two safety rules: the raw folders are **only** removed after the PDF is
successfully generated (if WeasyPrint fails, the raw evidence is kept so you
still have results), and you can keep everything with **`RECONBOX_KEEP_RAW=1`**:

```
output/<target>/
├── report.pdf
├── meta/ …
├── network-scan/            # nmap .nmap/.gnmap/.xml per step + html/ reports
├── service-enum/            # per-service evidence
├── dns-recon/ web-recon/ osint/   # domains only
```

The PDF opens with an executive summary, then per-phase findings tables
(ports/services/versions, CVEs, DNS/subdomains, SMB shares & users, evasion
results …) followed by the full, formatted tool output so nothing is lost.

---

## The line it won't cross

ReconBox stops at enumeration and vulnerability *assessment*. On its own it
will **not**:

- brute-force passwords (identifier guessing like RID cycling / Oracle SIDs
  and *default-credential checks* are allowed; password brute-forcing is not);
- execute remote commands (WMI enumeration uses `rpcdump`, never `wmiexec`);
- write, upload, delete, or transfer files to the target;
- run intrusive or denial-of-service NSE scripts.

If you supply credentials, they're used for **read-only** enumeration only.
The `vuln` NSE category it runs *reports* likely CVEs from service versions —
it does not confirm or trigger them.

---

## Requirements

- **Docker.** Everything (nmap, the ProjectDiscovery tools, the service-enum
  clients, SecLists) is baked into the image — nothing to install on the host.
- **Capabilities** for the full feature set: `NET_RAW` + `NET_ADMIN` (raw-socket
  scans/evasion) and `SYS_ADMIN` (read-only NFS mount). See [Quick
  start](#quick-start).

### Building

```bash
git clone https://github.com/hafizfarhad/reconbox.git && cd reconbox
docker build -t reconbox .
```

Heavy first build (Kali base + Go tools + SecLists) — expect 15–30 min.

---

## Extending

The code is small and each piece is self-contained:

- **New service enumerator** → add `modules/services/<svc>.py` with a
  `@register("<key>")` handler, import it in `modules/services/__init__.py`,
  and map the service in `SERVICE_ALIASES` / `STANDARD_PORT_MAP`.
- **New config option** → append one entry to `CONFIG_QUESTIONS` in
  `modules/config_wizard.py` (both env-var and wizard pick it up).
- **New phase** → a `run_<phase>(target, phase_dir, error_log, config)` in
  `modules/`, wired into `brain.py`.

Every external command goes through `modules/executor.py:run_tool()` — the
single choke point that handles timeouts, missing binaries, raw output
capture, secret redaction, and progress reporting.

---

## License

[MIT](LICENSE) © 2026 Hafiz Farhad
