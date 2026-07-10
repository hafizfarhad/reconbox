"""
Live run progress.

Prints an append-only, timestamped heartbeat so whoever launched the container
can see, at a glance: which phase is running (phase i of N), which service is
being enumerated (j of M), which external tool is running *right now*, and how
long each one took. It deliberately never prints tool output — just names,
counts, and timings — so the log stays a lightweight "how much longer?" view.

Append-only lines (no cursor tricks) so it reads correctly whether attached
(`docker run`) or detached (`docker logs -f`), TTY or not. Every line is
flushed immediately.

The step total across a whole run can't be known in advance (the scan is a
decision tree), so denominators are shown where they ARE known — phases, and
services within service-enum — and the rest is an incrementing step counter
plus elapsed time.
"""

import time

_state = {
    "phase_names": [],
    "phase_i": 0,
    "run_start": None,
    "steps": 0,       # total external tool runs so far
    "sub_i": 0,       # current sub-item index within a phase (e.g. service #)
    "sub_n": None,    # sub-item total, if known
    "cur_sub": None,  # current sub-item label (indents tool lines under it)
}


def _elapsed():
    start = _state["run_start"] or time.time()
    secs = int(time.time() - start)
    return f"{secs // 60:02d}:{secs % 60:02d}"


def _emit(message):
    print(f"[{_elapsed()}] {message}", flush=True)


def configure(phase_names):
    """Declare the phase plan up front so phases can show 'i/N'."""
    _state["phase_names"] = list(phase_names)
    _state["phase_i"] = 0
    _state["run_start"] = time.time()


def start_phase(name):
    _state["phase_i"] += 1
    _state["sub_i"] = 0
    _state["sub_n"] = None
    _state["cur_sub"] = None
    total = len(_state["phase_names"]) or "?"
    _emit(f"Phase {_state['phase_i']}/{total} · {name}")


def set_subtotal(n):
    """For phases that know their unit count (service-enum: number of services)."""
    _state["sub_n"] = n


def start_subitem(label):
    _state["sub_i"] += 1
    _state["cur_sub"] = label
    tag = f"{_state['sub_i']}/{_state['sub_n']}" if _state["sub_n"] else f"{_state['sub_i']}"
    _emit(f"  [{tag}] {label}")


def tool_start(tool_name):
    """Announce the tool that is about to run (so a long/hung step is visible)."""
    _state["steps"] += 1
    indent = "    " if _state["cur_sub"] else "  "
    _emit(f"{indent}▶ {tool_name} …")


def tool_end(result):
    """Announce completion + timing for the tool that just finished."""
    if result.missing:
        status = "missing"
    elif result.timed_out:
        status = "TIMEOUT"
    else:
        status = f"exit {result.returncode}"
    indent = "    " if _state["cur_sub"] else "  "
    _emit(f"{indent}✓ {result.tool} ({result.duration:.1f}s, {status}) "
          f"· {_state['steps']} steps done")


def finish():
    _emit(f"Done · {_state['steps']} tool runs across "
          f"{_state['phase_i']} phase(s) · total {_elapsed()}")
