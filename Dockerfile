# syntax=docker/dockerfile:1

# ===========================================================================
# Stage 1 -- Go builder.
# Compiles the ProjectDiscovery tools + ffuf + gau, then we copy ONLY the
# resulting binaries into the final image. This keeps the ~1.3GB Go module
# cache, the ~1.1GB build cache, and the ~260MB Go toolchain OUT of the
# shipped image. Built on the same Kali base as the runtime stage so the
# binaries link against an identical libc.
# CGO is disabled so the binaries are fully static and portable.
# ===========================================================================
FROM kalilinux/kali-rolling:latest AS gobuilder

RUN apt-get update && apt-get install -y --no-install-recommends \
    golang-go \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV GOPATH=/root/go
ENV CGO_ENABLED=0
ENV PATH=/root/go/bin:$PATH

RUN go install -v github.com/ffuf/ffuf/v2@latest && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest

# ===========================================================================
# Stage 2 -- runtime image.
# ===========================================================================
FROM kalilinux/kali-rolling:latest

# ---------------------------------------------------------------------------
# System tools: nmap (+ncat for evasion connect-verification), xsltproc
# (nmap XML -> HTML reports), whois, dig (dnsutils), whatweb, python3.
# NOTE: golang-go is intentionally NOT installed here -- it is only needed to
# BUILD the Go tools (stage 1), never at runtime.
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
    curl \
    jq \
    openssl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# Service-enumeration tooling (balanced set): native protocol clients + a few
# focused frameworks. nmap NSE covers the rest.
#   - smbclient / samba-common-bin -> smbclient, rpcclient
#   - smbmap, enum4linux-ng        -> SMB enumeration
#   - nfs-common                   -> showmount, mount.nfs
#   - rsync, snmp, onesixtyone, braa, ssh-audit
#   - mariadb-client               -> mysql
#   - netexec                      -> nxc (authenticated WinRM/SMB checks)
#   - python3-impacket             -> impacket-rpcdump (MSRPC enumeration)
# The bundled wordlists (SecLists subset) are vendored in via COPY below --
# the full `seclists` apt package is ~1.9GB and we only use three files.
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

# Unbuffered stdout so the live progress heartbeat shows up immediately in
# `docker run` / `docker logs -f` instead of being block-buffered.
ENV PYTHONUNBUFFERED=1

# ---------------------------------------------------------------------------
# Go tool binaries, copied from the builder stage. Landing them in
# /usr/local/bin (which precedes /usr/bin on PATH) guarantees our
# ProjectDiscovery httpx wins over any Python `httpx` CLI that the
# netexec / python3-httpx apt chain may drop into /usr/bin.
# ---------------------------------------------------------------------------
COPY --from=gobuilder /root/go/bin/ /usr/local/bin/

# Functional guard: fail the build loudly if the wrong `httpx` is on PATH.
# ProjectDiscovery httpx exits 0 for `-version`; the Python httpx CLI errors
# on the single-dash flag, so a wrong binary can never pass here.
RUN resolved="$(command -v httpx)" && \
    echo "httpx resolves to: ${resolved}" && \
    case "${resolved}" in \
      /usr/local/bin/httpx) : ;; \
      *) echo "FATAL: wrong httpx on PATH (${resolved}); expected ProjectDiscovery httpx"; exit 1 ;; \
    esac && \
    httpx -version >/dev/null 2>&1 || \
    { echo "FATAL: 'httpx -version' failed -- resolved binary is not ProjectDiscovery httpx"; exit 1; }

# ---------------------------------------------------------------------------
# Vendored wordlists (SecLists subset). Placed at the same paths the full
# seclists package used, so config/settings.py needs no changes:
#   /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
#   /usr/share/seclists/Discovery/Web-Content/common.txt
#   /usr/share/seclists/Discovery/SNMP/snmp.txt
# ---------------------------------------------------------------------------
COPY wordlists/ /usr/share/seclists/

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
