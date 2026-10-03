#!/usr/bin/env python3
"""Verify device-gate preconditions before spending a run on the device.

Usage:
    python3 tools/gate_preflight.py [--release <uname -r>] [--max-uptime-ms N]

Exits 0 only when every check passes. Each check prints PASS, FAIL or SKIP with
the observed value, so a failed precondition names itself instead of surfacing
later as an unattributable panic.

Why this exists
---------------
The first 6.12.58 gate (docs/analysis/device-gates/
PROFILE-61258-01-20261003-fdgraph-fail.md) was run on a device that had been up
for 42853 ms, which AGENTS.md does not accept as a cold boot, and the KernelSU
load state was never recorded. The run then panicked and, because neither
precondition had been checked up front, the panic could not be attributed. This
tool makes those preconditions checkable.

Checks
------
device      exactly one device attached; a second attached device silently
            changes which device a gate runs against.
uptime      uptime below --max-uptime-ms (default 120000). A cold boot is the
            precondition for the causal claim "the write caused the panic".
kernelsu    no KernelSU module or marker present. AGENTS.md requires KernelSU
            unloaded, since a loaded module changes the kernel's memory layout.
release     uname -r equals the expected release. GhostLock matches the profile
            by exact uname -r and refuses to run on a mismatch.
nofile      reports the shell's RLIMIT_NOFILE and whether it leaves the headroom
            the fd graph needs. The graph builds 96 * 256 = 24576 nested epoll
            descriptors and the reference aborts unless the limit is at least
            current + 0x60a0 (24736). Checking here turns a mid-run EMFILE into
            a preflight FAIL. See docs/analysis/fd-graph-primitive-scoping.md
            sections 2.14 and 2.16.

This tool never writes to the device; it only reads.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from dataclasses import dataclass

DEFAULT_RELEASE = "6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k"
DEFAULT_MAX_UPTIME_MS = 120_000
# 96 * 256 nested epolls plus the reference's remaining 160 descriptors.
GRAPH_FD_HEADROOM = 0x60A0

KERNELSU_MARKERS = (
    "/debug_ramdisk/ksud",
    "/debug_ramdisk/ksu.debuggable",
    "/data/adb/ksu",
    "/data/adb/modules/ksu",
)


@dataclass
class Result:
    name: str
    status: str  # PASS | FAIL | SKIP
    detail: str

    def render(self) -> str:
        return f"[{self.status:4}] {self.name}: {self.detail}"


def run_adb(serial: str | None, *args: str, timeout: int = 20) -> tuple[int, str]:
    """Run an adb command, returning (exit code, combined output)."""
    cmd = ["adb"]
    if serial:
        cmd += ["-s", serial]
    cmd += list(args)
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return 1, f"adb invocation failed: {exc}"
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def check_device() -> tuple[Result, str | None]:
    """Require exactly one attached device and return its serial."""
    if shutil.which("adb") is None:
        return Result("device", "FAIL", "adb not found on PATH"), None
    code, out = run_adb(None, "devices")
    if code != 0:
        return Result("device", "FAIL", f"adb devices failed: {out}"), None
    serials = [
        line.split("\t")[0].strip()
        for line in out.splitlines()
        if line.strip() and not line.startswith("List of devices")
        and line.strip().endswith("device")
    ]
    if not serials:
        return Result("device", "FAIL", "no device attached; gate cannot run"), None
    if len(serials) > 1:
        joined = ", ".join(serials)
        return Result(
            "device", "FAIL", f"{len(serials)} devices attached ({joined}); pass -s"
        ), None
    return Result("device", "PASS", f"exactly one device: {serials[0]}"), serials[0]


def check_uptime(serial: str, max_uptime_ms: int) -> Result:
    """Require a cold boot by bounding how long the device has been up."""
    code, out = run_adb(serial, "shell", "cat", "/proc/uptime")
    if code != 0 or not out:
        return Result("uptime", "FAIL", f"could not read /proc/uptime: {out}")
    try:
        seconds = float(out.split()[0])
    except (IndexError, ValueError):
        return Result("uptime", "FAIL", f"unparsable /proc/uptime: {out!r}")
    uptime_ms = int(seconds * 1000)
    detail = f"uptime={uptime_ms}ms (limit {max_uptime_ms}ms)"
    if uptime_ms > max_uptime_ms:
        return Result(
            "uptime",
            "FAIL",
            f"{detail}; not a cold boot, reboot and re-check before gating",
        )
    return Result("uptime", "PASS", detail)


def check_kernelsu(serial: str) -> Result:
    """Require KernelSU to be absent, since it changes kernel memory layout."""
    code, out = run_adb(serial, "shell", "cat", "/proc/modules")
    modules = out.lower() if code == 0 else ""
    if "kernelsu" in modules or "ksu" in modules.split():
        return Result(
            "kernelsu", "FAIL", "a KernelSU module is loaded; unload before gating"
        )
    present = [
        path
        for path in KERNELSU_MARKERS
        if run_adb(serial, "shell", "test", "-e", path)[0] == 0
    ]
    if present:
        return Result(
            "kernelsu", "FAIL", f"KernelSU markers present: {', '.join(present)}"
        )
    return Result("kernelsu", "PASS", "no KernelSU module or marker found")


def check_release(serial: str, expected: str) -> Result:
    """Require the exact uname -r the profile is keyed to."""
    code, out = run_adb(serial, "shell", "uname", "-r")
    if code != 0 or not out:
        return Result("release", "FAIL", f"could not read uname -r: {out}")
    actual = out.strip()
    if actual != expected:
        return Result(
            "release", "FAIL", f"uname -r={actual!r}, expected {expected!r}"
        )
    return Result("release", "PASS", f"uname -r={actual}")


def check_nofile(serial: str) -> Result:
    """Report RLIMIT_NOFILE headroom for the 24576-descriptor fd graph.

    Reads /proc/self/limits, not `ulimit -n`: adb re-splits the argv so
    `shell sh -c "ulimit -n"` arrives as `sh -c ulimit -n`, printing "unlimited".
    Verified on device. /proc/self/limits also exposes the hard limit.
    """
    code, out = run_adb(serial, "shell", "cat", "/proc/self/limits")
    if code != 0 or not out:
        return Result(
            "nofile", "SKIP", f"could not read /proc/self/limits: {out or 'no output'}"
        )
    for line in out.splitlines():
        if "open files" not in line:
            continue
        parts = line.split()
        # "Max open files <soft> <hard> files"
        if len(parts) < 4:
            return Result("nofile", "SKIP", f"unparsable limits line: {line.strip()!r}")
        soft_s, hard_s = parts[3], parts[4] if len(parts) > 4 else "?"
        detail = f"RLIMIT_NOFILE soft={soft_s} hard={hard_s}, fd graph needs +{GRAPH_FD_HEADROOM}"
        if not soft_s.isdigit():
            return Result(
                "nofile", "FAIL", f"{detail}; soft limit is not a number, cannot gate"
            )
        soft = int(soft_s)
        if soft < GRAPH_FD_HEADROOM:
            return Result(
                "nofile",
                "FAIL",
                f"{detail}; raise before gating or the graph hits EMFILE mid-build",
            )
        if hard_s.isdigit() and soft > int(hard_s):
            return Result(
                "nofile", "FAIL", f"{detail}; soft limit exceeds the hard limit"
            )
        return Result("nofile", "PASS", detail)
    return Result("nofile", "SKIP", "no 'open files' row in /proc/self/limits")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify device-gate preconditions before spending a run."
    )
    parser.add_argument(
        "--release",
        default=DEFAULT_RELEASE,
        help=f"expected uname -r (default: {DEFAULT_RELEASE})",
    )
    parser.add_argument(
        "--max-uptime-ms",
        type=int,
        default=DEFAULT_MAX_UPTIME_MS,
        help=f"cold-boot uptime ceiling (default: {DEFAULT_MAX_UPTIME_MS})",
    )
    parser.add_argument("-s", "--serial", default=None, help="target device serial")
    args = parser.parse_args(argv)

    print("GhostLock device-gate preflight (read-only)\n")

    if args.serial:
        device_result = Result("device", "PASS", f"using requested serial {args.serial}")
        serial: str | None = args.serial
    else:
        device_result, serial = check_device()
    print(device_result.render())
    if serial is None:
        print("\nBLOCKED: no usable device. Every later check needs one.")
        return 2

    results = [
        check_uptime(serial, args.max_uptime_ms),
        check_kernelsu(serial),
        check_release(serial, args.release),
        check_nofile(serial),
    ]
    for result in results:
        print(result.render())

    failed = [r for r in results if r.status == "FAIL"]
    skipped = [r for r in results if r.status == "SKIP"]
    print()
    if failed:
        print(
            f"PREFLIGHT FAIL: {len(failed)} blocking check(s): "
            + ", ".join(r.name for r in failed)
        )
        print("Do not start the gate. Fix these first, or the run proves nothing.")
        return 1
    if skipped:
        print(
            f"PREFLIGHT PASS (with SKIP): {', '.join(r.name for r in skipped)} "
            "could not be verified; state them in the gate record."
        )
        return 0
    print("PREFLIGHT PASS: all gate preconditions hold; the run is attributable.")
    return 0


if __name__ == "__main__":
    sys.exit(main())