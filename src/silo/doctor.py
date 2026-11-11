"""Host and configuration posture checks.

The sandbox is only as strong as the kernel and engine underneath it, and only as strict as its
configuration. `bad` means containment is materially weakened; `warn` means there is a stronger
setting available and says what it costs.
"""

from __future__ import annotations

import getpass
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path

from silo.config import Config

OK, WARN, BAD = "ok", "warn", "bad"
_IMAGE_ID_RE = re.compile(r"^(sha256:)?[0-9a-f]{64}$")


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


def kernel_isolation_check(virt: str | None, sealed: bool | None, unused_runtimes: list[str]) -> Check:
    """What stands between a kernel exploit in the sandbox and the rest of the world.

    The sandbox always shares a kernel with the machine it runs on. On a physical machine that is
    the user's own. In a virtual machine it is the guest's, and the VM is a second boundary, but
    only as far as the guest is sealed: `sealed` is None when that was not tested, else the result
    of `silo doctor --sealed`.
    """
    name = "kernel isolation"
    if virt is None:
        unused = f" ({'/'.join(unused_runtimes)} is installed; silo does not use it yet)" if unused_runtimes else ""
        return Check(name, WARN, "the sandbox shares this machine's kernel: a kernel vulnerability reachable through "
                     f"the allowed syscalls leads to your own account{unused}",
                     "put a second boundary around it: a VM with no network device (docs/LOCAL_VM.md) or a "
                     "dedicated, sealed server (docs/VPS.md)")
    if sealed:
        return Check(name, OK, f"inside a virtual machine ({virt}) whose outbound traffic is blocked: a kernel "
                     "exploit from the sandbox is confined to this guest")
    if sealed is False:
        return Check(name, WARN, f"inside a virtual machine ({virt}) that can reach the network: a kernel exploit "
                     "from the sandbox could call out from this guest",
                     "seal it (docs/VPS.md), or use a VM with no network device (docs/LOCAL_VM.md)")
    return Check(name, WARN, f"inside a virtual machine ({virt}): that is a second boundary only if this machine "
                 "is sealed and holds nothing else", "confirm with `silo doctor --sealed`")


def run_checks(cfg: Config, sealed: bool | None = None) -> list[Check]:
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
    unused_runtimes = [name for name in ("runsc", "krun") if shutil.which(name)]
    add(kernel_isolation_check(_virtualization(), sealed, unused_runtimes))
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
    try:
        active = subprocess.run(["systemctl", "--user", "is-active", "podman.socket"],
                                capture_output=True, text=True, timeout=10).stdout.strip() == "active"
    except (OSError, subprocess.TimeoutExpired):  # no systemd here: the socket file is then the only evidence
        active = False
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
        pinned = "@sha256:" in image or bool(_IMAGE_ID_RE.match(image))
        present = subprocess.run(["podman", "image", "exists", image]).returncode == 0
        level = OK if pinned and present else (WARN if present else BAD)
        detail = f"{image} ({'pinned' if pinned else 'mutable tag'}, {'present' if present else 'not present'})"
        if not present:
            fix = "`silo pull`, or `podman load` an archive on a host without network access"
        else:
            fix = "" if pinned else "run `silo images` and put the printed image ID in silo.toml"
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
    checks.extend(session_checks())
    return checks


# ----------------------------------------------------------------------------- remote / server hosts

def _linger() -> bool | None:
    try:
        res = subprocess.run(["loginctl", "show-user", getpass.getuser(), "--property=Linger", "--value"],
                             capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired, KeyError):
        return None
    return {"yes": True, "no": False}.get(res.stdout.strip())


def _virtualization() -> str | None:
    try:
        res = subprocess.run(["systemd-detect-virt", "--vm"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    kind = res.stdout.strip()
    if not kind or kind == "none":
        return None
    try:
        vendor = Path("/sys/class/dmi/id/sys_vendor").read_text().strip()
    except OSError:
        vendor = ""
    return f"{kind}, {vendor}" if vendor else kind


def session_checks() -> list[Check]:
    """Things that only matter when silo runs on a machine you reach over SSH."""
    checks: list[Check] = []
    remote = bool(os.environ.get("SSH_CONNECTION"))
    if remote and os.environ.get("SSH_AUTH_SOCK"):
        checks.append(Check("SSH agent forwarding", WARN, "an SSH agent is reachable from this session",
                            "whoever takes over this host can use your keys while you are connected: "
                            "connect with `ssh -a`"))
    elif remote:
        checks.append(Check("SSH agent forwarding", OK, "no agent reachable from this session"))
    linger = _linger()
    graphical = os.environ.get("XDG_SESSION_TYPE") in ("wayland", "x11")
    if linger:
        checks.append(Check("user lingering", OK, "on: this account's services outlive its login sessions"))
    elif linger is False and (remote or not graphical):
        checks.append(Check("user lingering", WARN, "off: the runtime directory, and the sandbox with it, goes "
                            "away when you log out", f"sudo loginctl enable-linger {getpass.getuser()}"))
    return checks


# ------------------------------------------------------------------------------------- sealed host
#
# `silo doctor --sealed` is for a machine dedicated to the model, whose outbound traffic is supposed
# to be denied from outside (docs/VPS.md). It proves that by trying to get out the ways an escaped
# process would, from the host itself. It is opt-in because it sends packets to public addresses.

_DEFINITE_DNS_ANSWERS = {getattr(socket, name) for name in ("EAI_NONAME", "EAI_NODATA") if hasattr(socket, name)}
PUBLIC_V4 = "1.1.1.1"
PUBLIC_V4_ALT = "8.8.8.8"
PUBLIC_V6 = "2606:4700:4700::1111"
METADATA = "169.254.169.254"


def _why(exc: OSError) -> str:
    return exc.strerror or type(exc).__name__


def _tcp(family: int, address: tuple[str, int], timeout: float = 3.0) -> tuple[bool | None, str]:
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
    except OSError as exc:
        return None, f"not testable ({_why(exc)})"
    with sock:
        sock.settimeout(timeout)
        try:
            sock.connect(address)
            return True, "connected"
        except ConnectionRefusedError:
            # The targets are public services that are known to listen, so a refusal does not come
            # from them: a firewall or router on the way rejected the connection instead of dropping it.
            return False, "rejected on the way"
        except OSError as exc:
            return False, _why(exc)


def _udp_dns(address: tuple[str, int], timeout: float = 3.0) -> tuple[bool | None, str]:
    query = (struct.pack("!HHHHHH", uuid.uuid4().int & 0xFFFF, 0x0100, 1, 0, 0, 0)
             + b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(query, address)
            sock.recvfrom(2048)
            return True, "a DNS answer came back"
        except OSError as exc:
            return False, _why(exc)


def _icmp(address: str = PUBLIC_V4, timeout: float = 2.0) -> tuple[bool | None, str]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    except OSError as exc:  # unprivileged ICMP sockets are a per-group sysctl
        return None, f"not testable without privileges ({_why(exc)})"
    with sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(struct.pack("!BBHHH", 8, 0, 0, 0, 1) + b"silo doctor", (address, 0))
            sock.recvfrom(2048)
            return True, "echo reply received"
        except OSError as exc:
            return False, _why(exc)


def _system_resolver(timeout: float = 6.0) -> tuple[bool | None, str]:
    """Ask the configured resolver for a name nobody has cached.

    Some clouds exempt their own resolver from firewall rules, which leaves DNS as a data channel
    even when every direct connection is blocked. Any definite answer, a negative one included,
    means the resolver reached the internet on this host's behalf.
    """
    name = f"{uuid.uuid4().hex}.example.com"
    result: list[tuple[bool, str]] = []

    def lookup() -> None:
        try:
            socket.getaddrinfo(name, None)
            result.append((True, "the name resolved"))
        except socket.gaierror as exc:
            # "no such name" and "no address" are answers; "try again" is what an unreachable
            # resolver produces.
            if exc.errno in _DEFINITE_DNS_ANSWERS:
                result.append((True, f"the resolver returned a definite answer ({exc.strerror})"))
            else:
                result.append((False, exc.strerror or "lookup failed"))
        except OSError as exc:
            result.append((False, _why(exc)))

    thread = threading.Thread(target=lookup, daemon=True)
    thread.start()
    thread.join(timeout)
    return result[0] if result else (False, "no answer")


def sealed_checks() -> list[Check]:
    probes = [
        (f"egress: TCP to {PUBLIC_V4}:443", lambda: _tcp(socket.AF_INET, (PUBLIC_V4, 443))),
        (f"egress: TCP to {PUBLIC_V4_ALT}:53", lambda: _tcp(socket.AF_INET, (PUBLIC_V4_ALT, 53))),
        ("egress: TCP over IPv6", lambda: _tcp(socket.AF_INET6, (PUBLIC_V6, 443))),
        (f"egress: UDP DNS to {PUBLIC_V4}", lambda: _udp_dns((PUBLIC_V4, 53))),
        (f"egress: ICMP echo to {PUBLIC_V4}", _icmp),
        ("egress: DNS through the system resolver", _system_resolver),
    ]
    checks = []
    for name, probe in probes:
        reached, detail = probe()
        if reached:
            checks.append(Check(name, BAD, f"OPEN: {detail}", "this host is not sealed: deny outbound traffic in the "
                                "provider's firewall, or apply `silo nft --sealed` (docs/VPS.md)"))
        elif reached is None:
            checks.append(Check(name, OK, detail))
        else:
            checks.append(Check(name, OK, f"blocked ({detail})"))
    reached, detail = _tcp(socket.AF_INET, (METADATA, 80), timeout=2.0)
    if reached:
        checks.append(Check("cloud metadata service", WARN, f"reachable at {METADATA}: {detail}",
                            "anything that reaches this host can read it: attach no role or API keys to the "
                            "instance and keep secrets out of user-data (`silo nft --sealed` also blocks it)"))
    else:
        checks.append(Check("cloud metadata service", OK, f"not reachable ({detail})"))
    return checks
