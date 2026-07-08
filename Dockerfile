FROM kalilinux/kali-rolling:latest

# ---------------------------------------------------------------------------
# System tools: nmap, whois, dig (dnsutils), whatweb, python3, go (needed to
# build the ProjectDiscovery tools below), git.
# Most of these already ship on Kali -- apt install is idempotent, so this
# is just a safety net if the base image slims down in future.
# ---------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    whois \
    dnsutils \
    whatweb \
    python3 \
    python3-pip \
    golang-go \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# ProjectDiscovery tools + gau are Go tools, not guaranteed to be on a slim
# Kali image. Installing explicitly so the container is self-contained.
# ---------------------------------------------------------------------------
ENV GOPATH=/root/go
ENV PATH=$PATH:/root/go/bin

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
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
