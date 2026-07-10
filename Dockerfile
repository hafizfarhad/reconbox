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
ENV PATH=$PATH:/root/go/bin
# Unbuffered stdout so the live progress heartbeat shows up immediately in
# `docker run` / `docker logs -f` instead of being block-buffered.
ENV PYTHONUNBUFFERED=1

RUN go install -v github.com/ffuf/ffuf/v2@latest && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest

# ---------------------------------------------------------------------------
# App code
# ---------------------------------------------------------------------------
WORKDIR /app
COPY brain.py /app/brain.py
COPY modules/ /app/modules/
COPY config/ /app/config/

# Output volume -- mount this from the host to actually get the results out
VOLUME ["/output"]

ENTRYPOINT ["python3", "/app/brain.py"]
