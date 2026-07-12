#!/bin/sh
# reconbox entrypoint.
#
# The tool runs as root because its raw-socket nmap scans (SYN/ACK/UDP, OS
# fingerprint, and the evasion techniques) require it. Writing to a
# bind-mounted /output as root leaves root-owned result files the invoking
# host user cannot read or delete without sudo.
#
# To avoid that, after the run we hand ownership of everything under /output
# back to whoever owns the /output mount on the host (which, for the documented
# `-v "$(pwd)/output:/output"` invocation, is the invoking user). Override with
# -e HOST_UID=... -e HOST_GID=... for named volumes or unusual setups.
set -e

_hand_back_output() {
    _owner="${HOST_UID:-$(stat -c '%u' /output 2>/dev/null || true)}"
    _group="${HOST_GID:-$(stat -c '%g' /output 2>/dev/null || true)}"
    if [ -n "${_owner}" ] && [ "${_owner}" != "0" ]; then
        chown -R "${_owner}:${_group:-$_owner}" /output 2>/dev/null || true
    fi
}
# Fire on normal exit and on interruption so results are never left root-owned.
trap _hand_back_output EXIT INT TERM

python3 /app/brain.py "$@"
