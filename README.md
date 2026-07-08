# Recon Container

Automated information-gathering/reconnaissance against a domain or IP.
Give it one target, get back a structured directory of raw tool output,
organized by phase, plus a machine-readable run manifest.

This is **recon only** — no exploitation, no active vulnerability
confirmation. It answers "what does this target's attack surface look
like," not "is it vulnerable."

## Usage

```
docker build -t reconbox .
docker run --rm -v $(pwd)/output:/output reconbox <domain-or-ip>
```

Example:
```
docker run --rm -v $(pwd)/output:/output reconbox example.com
docker run --rm -v $(pwd)/output:/output reconbox 8.8.8.8
```

## Output structure

```
output/<label>/
├── meta/
│   ├── target_info.json     # how the input was classified, PTR notes, missing tools
│   ├── run_manifest.json    # every step taken, per phase, with status
│   └── errors.log           # every missing tool / timeout / non-zero exit, timestamped
├── network-scan/            # always runs
│   ├── 01_host_discovery.txt
│   ├── 02_quick_scan.txt
│   ├── 03_deep_scan.txt
│   └── 0[4-7]_evasion_*.txt # only created if filtered ports were found
├── dns-recon/                # domain targets only
│   ├── 01_whois.txt
│   ├── 02_dig_{A,NS,MX,TXT}.txt
│   ├── 03_subfinder.txt
│   └── 04_dnsx_resolved.txt
└── web-recon/                 # domain targets only
    ├── 01_httpx.txt
    ├── 02_whatweb.txt
    ├── 03_katana_crawl.txt
    └── 04_gau_urls.txt
```

`<label>` is the resolved domain if one exists, otherwise the raw IP.

All tool output files are **raw** — exactly what the tool printed,
untouched. This is deliberate: it keeps this stage a faithful record of
what actually happened, and pushes normalization/summarization to a
later (LLM synthesis) stage rather than lossy-parsing it here.

## Target classification logic (`modules/resolver.py`)

Input can be a domain or a raw IP. Domain-level tools (whois, subdomain
enum, crawling, fingerprinting) only make sense against a domain, so:

- **Input is a domain** → resolve its IP too (network-scan needs an IP
  or hostname either way), run all three phases.
- **Input is an IP** → reverse-DNS it (PTR lookup):
  - No PTR at all → IP-only target. Skip dns-recon and web-recon.
  - PTR resolves but matches a known cloud-provider auto-generated
    pattern (e.g. `*.compute.amazonaws.com`, `*.cloudapp.azure.com`) →
    still IP-only. That PTR isn't something the owner configured, so
    it's not a domain worth running WHOIS/subdomain-enum against.
  - PTR resolves to something else → treat as a real domain, run all
    three phases against it.

Cloud PTR patterns live in `config/settings.py` (`CLOUD_PTR_PATTERNS`)
— add more there as needed.

## Network-scan decision tree (`modules/network_scan.py`)

This is the one phase built as an actual branching tree rather than a
fixed sequence, because port-scan results legitimately change what you
should do next:

1. **Host discovery** (`nmap -sn`). If no response, don't conclude the
   host is down — many real hosts drop ICMP. Instead, force `-Pn` on
   every subsequent step and note that in the manifest.
2. **Quick scan** (`nmap -F -T4`, top 100 ports) — fast signal before
   committing to anything expensive.
3. **Branch:** if any ports came back `filtered`, that's a firewall/IDS
   signal. Run four evasion techniques and save each to its own file
   so a human can see which one (if any) got through:
   - packet fragmentation (`-f`)
   - decoy scanning (`-D RND:10`)
   - source-port spoofing (`--source-port 53`)
   - ACK scan to map the firewall ruleset itself (`-sA`)
4. **Deep scan** (`-sV -sC`) runs only against ports confirmed `open`
   in step 2 — not a blind full-range sweep. (A full `-p-` sweep is
   intentionally *not* run by default; it's slow and low-yield once
   you've already evasion-tested the fast scan. Add it as an explicit
   opt-in later if needed.)

## Execution layer (`modules/executor.py`)

Every external tool call goes through `run_tool()`, which guarantees:
- missing binaries are caught and logged, never crash the run
- timeouts are enforced per tool (configured in `config/settings.py`)
- raw stdout/stderr is written to disk
- a structured `ToolResult` is returned so calling code can branch on
  what happened, without re-parsing files from disk

This is the seam that keeps the decision tree reliable — a single
choke point for "what do we do when a tool misbehaves," instead of
handling it ad hoc in every phase.

## Extending

- **New tool in an existing phase**: add a `run_tool(...)` call in the
  relevant `modules/*.py` file, add the binary name to
  `REQUIRED_TOOLS` in `config/settings.py`, add the install step to
  the `Dockerfile` if it's not on Kali by default.
- **New phase**: create `modules/new_phase.py` following the same
  pattern (`run_<phase>(target, phase_dir, error_log) -> summary dict`),
  wire it into `brain.py`, add its directory to `build_dirs()`.
- **LLM synthesis stage (planned, not built yet)**: should read
  `meta/run_manifest.json` for structure + status, then read the raw
  files it references for content. The manifest is the index; the
  phase folders are the evidence.

## What this does NOT do

- No active exploitation or vulnerability confirmation — recon only.
- No automatic scope expansion beyond the given target (no walking out
  to unrelated subdomains/orgs without being told to).
- No authorization/legality check — this container assumes whoever
  runs it already has permission to test the given target. That check
  belongs one layer up, outside this container.
