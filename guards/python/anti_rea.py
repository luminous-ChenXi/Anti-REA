"""anti_rea.py — Anti-REA runtime guard (Python)

Detection surface aligned with anti_rea.h / AntiRea.cs: REA environment
variables, analyst parent processes, rea-provider-* IPC traces, Python
debuggers and frida injection.

Score-based and side-effect-free by default:
    from anti_rea import threat_score
    s = threat_score()          # {'score': int, 'hits': [...]}
    if s["score"] >= 60:
        ...                     # app decides: log / degrade / exit

MIT License — Anti-REA project
"""

from __future__ import annotations

import os
import sys

WEIGHTS = {
    "env_run_id": 60,   # REA_PROCESS_RUN_ID: REA launched this process
    "env_bridge": 40,   # REA bridge environment variables
    "parent_tool": 40,  # parent process is an analysis tool
    "ipc_dir": 35,      # rea-provider-* under TMPDIR
    "debugger": 55,     # Python debugger/tracer
    "frida": 70,        # frida injected into this process
}

_PARENT_MARKERS = (
    "rea.mjs", "frida", "gdb", "lldb", "ghidra", "ida",
    "hopper", "rizin", "mitmdump", "jadx", "apktool",
)
_BRIDGE_ENV = ("REA_SOCKET", "REA_TOKEN", "REA_RUN_ID", "REA_TARGET_PATH")


def _parent_cmdline() -> str:
    try:
        with open(f"/proc/{os.getppid()}/cmdline", "rb") as f:
            return f.read().replace(b"\0", b" ").decode("utf-8", "replace").lower()
    except OSError:
        return ""


def threat_score() -> dict:
    hits: list[tuple[str, str]] = []

    if os.environ.get("REA_PROCESS_RUN_ID"):
        hits.append(("env_run_id", "REA_PROCESS_RUN_ID"))
    for var in _BRIDGE_ENV:
        if os.environ.get(var):
            hits.append(("env_bridge", var))

    cmdline = _parent_cmdline()
    if cmdline:
        for marker in _PARENT_MARKERS:
            if marker in cmdline:
                hits.append(("parent_tool", f"parent:{marker}"))
                break

    tmp = os.environ.get("TMPDIR", "/tmp")
    try:
        for name in os.listdir(tmp):
            if name.startswith("rea-provider-") or name.startswith("rea-browser-scenario-"):
                hits.append(("ipc_dir", name))
                break
    except OSError:
        pass

    # sys.settrace set (Python debugger trait)
    if sys.gettrace() is not None:
        hits.append(("debugger", "sys.gettrace"))

    # pdb / pydevd (PyCharm) present in sys.modules
    loaded = ",".join(sys.modules.keys())
    for marker in ("pydevd", "debugpy", "pdb "):
        if marker.strip() in loaded:
            hits.append(("debugger", marker.strip()))
            break
    if "frida" in sys.modules:
        hits.append(("frida", "frida-imported"))

    score = min(100, sum(WEIGHTS.get(kind, 0) for kind, _ in hits))
    return {"score": score, "hits": hits}


def check(threshold: int = 60) -> bool:
    """True when the score reaches the threshold."""
    return threat_score()["score"] >= threshold


if __name__ == "__main__":
    result = threat_score()
    print(f"score={result['score']}  hits={result['hits']}")
