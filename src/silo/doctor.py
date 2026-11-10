"""Host and configuration posture checks.

The sandbox is only as strong as the kernel and engine underneath it, and only as strict as its
configuration. `bad` means containment is materially weakened; `warn` means there is a stronger
setting available and says what it costs.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from silo.config import Config

OK, WARN, BAD = "ok", "warn", "bad"


@dataclass
class Check:
    name: str
    level: str
    detail: str
    fix: str = ""


def _sysctl(path: str) -> int | None:
    try:
        return int(Path("/proc/sys", path).read_text().strip())
    except (OSError, ValueError):
        return None


# (sysctl path, predicate, recommended value, why)
SYSCTLS = [
    ("kernel/yama/ptrace_scope", lambda v: v >= 1, ">=1", "limits ptrace to descendants (2 = admin-only)"),
    ("kernel/unprivileged_bpf_disabled", lambda v: v >= 1, ">=1", "unprivileged eBPF is a recurring LPE source"),
    ("kernel/kptr_restrict", lambda v: v >= 1, ">=1", "hides kernel pointers (KASLR)"),
    ("kernel/dmesg_restrict", lambda v: v == 1, "1", "hides the kernel log from unprivileged users"),
    ("kernel/perf_event_paranoid", lambda v: v >= 2, ">=2", "restricts perf for unprivileged users"),
    ("kernel/io_uring_disabled", lambda v: v >= 1, ">=1", "io_uring off for unprivileged users host-wide"),
    ("vm/unprivileged_userfaultfd", lambda v: v == 0, "0", "userfaultfd widens kernel race windows"),
    ("vm/memfd_noexec", lambda v: v >= 1, ">=1", "memfds non-executable by default (fileless exec)"),
    ("dev/tty/ldisc_autoload", lambda v: v == 0, "0", "no TTY line-discipline module autoload"),
    ("net/core/bpf_jit_harden", lambda v: v >= 1, ">=1", "constant blinding in the BPF JIT"),
]


def _podman_info() -> dict | None:
    try:
        res = subprocess.run(["podman", "info", "--format", "json"], capture_output=True, text=True, timeout=30)
        return json.loads(res.stdout) if res.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return None


def run_checks(cfg: Config) -> list[Check]:
    checks: list[Check] = []
    add = checks.append

    # ------------------------------------------------------------------------------ container engine
    if not shutil.which("podman"):
        add(Check("podman", BAD, "podman not found", "sudo dnf install podman"))
        return checks
    info = _podman_info()
    if info is None:
        add(Check("podman", BAD, "`podman info` failed"))
        return checks
    host = info.get("host", {})
    sec = host.get("security", {})
    add(Check("podman rootless", OK if sec.get("rootless") else BAD,
              "rootless" if sec.get("rootless") else "running rootful: a container escape lands as root",
              "" if sec.get("rootless") else "run silo as an unprivileged user"))
    runtime = host.get("ociRuntime", {}).get("name", "?")
    add(Check("OCI runtime", OK if runtime in ("crun", "runc") else WARN, runtime))
    stronger = [name for name in ("runsc", "krun") if shutil.which(name)]
    if stronger:
        add(Check("kernel isolation", WARN, f"{'/'.join(stronger)} is installed but silo does not use it yet",
                  "user-space kernel / microVM backends are on the roadmap"))
    else:
        add(Check("kernel isolation", WARN, "sandbox shares the host kernel: a kernel 0-day reachable through "
                  "the allowed syscalls is the main residual risk",
                  "keep the kernel patched; gVisor (runsc) / libkrun backends are on the roadmap"))
    cg = host.get("cgroupVersion")
    add(Check("cgroups", OK if cg == "v2" else BAD, f"cgroup {cg}",
              "" if cg == "v2" else "rootless resource limits require cgroup v2"))
    controllers = set(host.get("cgroupControllers") or [])
    missing = {"memory", "pids", "cpu"} - controllers
    add(Check("cgroup delegation", OK if not missing else WARN,
              f"delegated: {sorted(controllers)}" if not missing else f"not delegated: {sorted(missing)}",
              "" if not missing else "enable systemd user delegation (Delegate=memory pids cpu)"))

    enforce_file = Path("/sys/fs/selinux/enforce")
    enforcing = enforce_file.exists() and enforce_file.read_text().strip() == "1"
    if sec.get("selinuxEnabled") and enforcing:
        add(Check("SELinux", OK, "enforcing (sandbox confined as container_t with its own MCS categories)"))
    elif sec.get("selinuxEnabled"):
        add(Check("SELinux", BAD, "enabled but permissive", "sudo setenforce 1 and persist in /etc/selinux/config"))
    elif sec.get("apparmorEnabled"):
        add(Check("LSM", WARN, "AppArmor only; SELinux MCS separation is stronger"))
    else:
        add(Check("LSM", BAD, "no SELinux/AppArmor confinement"))

    sock = Path(os.environ.get("XDG_RUNTIME_DIR", "/nonexistent")) / "podman" / "podman.sock"
    active = subprocess.run(["systemctl", "--user", "is-active", "podman.socket"],
                            capture_output=True, text=True).stdout.strip() == "active"
    if active or sock.exists():
        add(Check("podman API socket", WARN, f"user API socket is active ({sock})",
                  "systemctl --user disable --now podman.socket (whatever reaches it controls your containers)"))
    else:
        add(Check("podman API socket", OK, "inactive"))

    base = cfg.runtime.seccomp_base
    add(Check("seccomp base profile", OK if base.is_file() else BAD, str(base),
              "" if base.is_file() else "sudo dnf install containers-common"))

    # --------------------------------------------------------------------------------- host kernel
    for path, good_value, recommended, why in SYSCTLS:
        current = _sysctl(path)
        if current is None:
            continue
        good = good_value(current)
        add(Check(f"sysctl {path.replace('/', '.')}", OK if good else WARN,
                  f"= {current} (want {recommended}: {why})",
                  "" if good else "see host/sysctl/90-silo-hardening.conf"))

    # ------------------------------------------------------------------------ images and model files
    for label, image in (("model image", cfg.runtime.image), ("probe image", cfg.runtime.probe_image)):
        pinned = "@sha256:" in image
        present = subprocess.run(["podman", "image", "exists", image]).returncode == 0
        level = OK if pinned and present else (WARN if present else BAD)
        detail = f"{image} ({'digest-pinned' if pinned else 'mutable tag'}, {'present' if present else 'not pulled'})"
        fix = "" if level == OK else "run `silo pull` and pin the printed digest in silo.toml"
        add(Check(label, level, detail, fix))
    if cfg.model.dir:
        if cfg.manifest_path.is_file():
            add(Check("model manifest", OK, str(cfg.manifest_path)))
        else:
            add(Check("model manifest", WARN, "no manifest yet", "silo intake"))

    # --------------------------------------------------------------------------------- configuration
    if cfg.runtime.gpu != "none":
        add(Check("GPU passthrough", WARN, f"gpu={cfg.runtime.gpu}: the GPU driver is exposed to the sandbox and "
                  "memfd_create stays allowed", "GPU drivers are large kernel attack surface; prefer CPU for "
                  "untrusted models"))
    if cfg.runtime.seccomp_action == "kill":
        add(Check("seccomp action", OK, "kill: the first denied syscall terminates the runtime"))
    else:
        add(Check("seccomp action", WARN, "errno: denied syscalls fail quietly, so a compromised runtime can "
                  "keep probing", 'runtime.seccomp_action = "kill" once your model runs cleanly'))
    if cfg.gateway.scanner == "enforce":
        add(Check("output scanner", OK, "enforce: high-severity completions are withheld"))
    else:
        add(Check("output scanner", WARN, f"{cfg.gateway.scanner}: suspicious completions are "
                  f"{'logged but not' if cfg.gateway.scanner == 'monitor' else 'neither logged nor'} blocked",
                  'gateway.scanner = "enforce" (streams are then delivered only once complete)'))
    if cfg.gateway.allow_tools:
        add(Check("tool calling", WARN, "allowed: whatever executes the model's tool calls is outside the silo",
                  "that executor is now your containment boundary; sandbox it too"))
    else:
        add(Check("tool calling", OK, "refused: the model can only produce text"))
    return checks
