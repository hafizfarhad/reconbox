FROM kalilinux/kali-rolling:latest

# ---------------------------------------------------------------------------
# System tools: nmap (+ncat for evasion connect-verification), xsltproc
# (nmap XML -> HTML reports), whois, dig (dnsutils), whatweb, python3, go
# (needed to build the ProjectDiscovery tools below), git.
# Most of these already ship on Kali -- apt install is idempotent, so this
# is just a safety net if the base image slims down in future.
# ---------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    ncat \
    xsltproc \
    whois \
    dnsutils \
    whatweb \
    python3 \
    python3-pip \
    golang-go \
    git \
    curl \
    jq \
    openssl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# Service-enumeration tooling (balanced set): native protocol clients + a few
# focused frameworks. nmap NSE covers the rest. SecLists provides the bundled
# wordlists for subdomain / SNMP-community enumeration.
#   - smbclient / samba-common-bin -> smbclient, rpcclient
#   - smbmap, enum4linux-ng        -> SMB enumeration
#   - nfs-common                   -> showmount, mount.nfs
#   - rsync, snmp, onesixtyone, braa, ssh-audit
#   - mariadb-client               -> mysql
#   - netexec                      -> nxc (authenticated WinRM/SMB checks)
#   - python3-impacket             -> impacket-rpcdump (MSRPC enumeration)
#   - seclists                     -> /usr/share/seclists
# ---------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    smbclient \
    samba-common-bin \
    smbmap \
    enum4linux-ng \
    nfs-common \
    rsync \
    snmp \
    onesixtyone \
    braa \
    ssh-audit \
    mariadb-client \
    netexec \
    python3-impacket \
    seclists \
    python3-jinja2 \
    fonts-dejavu-core \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libcairo2 \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

# WeasyPrint (the report PDF engine) is not packaged for Kali, so install it
# via pip. Its Pango/Cairo/gdk-pixbuf runtime libraries are the apt packages
# above; jinja2 comes from python3-jinja2.
RUN pip3 install --no-cache-dir --break-system-packages weasyprint

# ---------------------------------------------------------------------------
# ProjectDiscovery tools + gau are Go tools, not guaranteed to be on a slim
# Kali image. Installing explicitly so the container is self-contained.
# ---------------------------------------------------------------------------
ENV GOPATH=/root/go
# Go tools MUST come first on PATH. Some apt packages (e.g. the netexec /
# python3-httpx dependency chain) install a Python `httpx` CLI into a system
# bin dir; if /root/go/bin were appended, that CLI would shadow
# ProjectDiscovery's httpx (which web-recon calls with `-u`). Prepending makes
# our Go-installed subfinder/dnsx/httpx/katana/gau/ffuf win.
ENV PATH=/root/go/bin:$PATH
# Unbuffered stdout so the live progress heartbeat shows up immediately in
# `docker run` / `docker logs -f` instead of being block-buffered.
ENV PYTHONUNBUFFERED=1

RUN go install -v github.com/ffuf/ffuf/v2@latest && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest

# Enforce the httpx resolution at BUILD time. The netexec / python3-httpx apt
# chain ships a Python `httpx` CLI (Click-based, rejects web-recon's `-u` with
# "No such option") on the system PATH; if it ever wins over ProjectDiscovery's
# Go httpx, web-recon silently produces nothing. Fail the build loudly instead
# of shipping a broken image. The symlink in /usr/local/bin removes any
# dependence on PATH ordering; the `-version` check is a functional guard --
# ProjectDiscovery httpx exits 0 for `-version`, the Python httpx CLI errors on
# the single-dash flag, so a wrong binary can never pass here.
RUN ln -sf /root/go/bin/httpx /usr/local/bin/httpx && \
    resolved="$(command -v httpx)" && \
    echo "httpx resolves to: ${resolved}" && \
    case "${resolved}" in \
      /root/go/bin/httpx|/usr/local/bin/httpx) : ;; \
      *) echo "FATAL: wrong httpx on PATH (${resolved}); expected ProjectDiscovery httpx"; exit 1 ;; \
    esac && \
    httpx -version >/dev/null 2>&1 || \
    { echo "FATAL: 'httpx -version' failed -- resolved binary is not ProjectDiscovery httpx"; exit 1; }

# ---------------------------------------------------------------------------
# App code
# ---------------------------------------------------------------------------
WORKDIR /app
COPY brain.py /app/brain.py
COPY modules/ /app/modules/
COPY config/ /app/config/
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

# Output volume -- mount this from the host to actually get the results out
VOLUME ["/output"]

# The entrypoint runs brain.py as root (raw-socket scans need it) and then
# chowns /output back to the host user so results aren't left root-owned.
ENTRYPOINT ["/app/docker-entrypoint.sh"]
