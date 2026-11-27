"""Hardened `podman run` command construction.

Every container silo starts (model runtime and escape probes alike) goes through `podman_run_args`,
and the result is checked by `assert_hardened` before execution so that a refactor cannot quietly
drop a control.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from silo.config import Config

CONTAINER_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
SANDBOX_USER = "65534:65534"  # nobody; maps to an unprivileged subordinate UID on the host
LABEL = "io.silo.managed=true"

# Masked on top of podman's defaults: kernel layout/config disclosure, and /dev/pts. Masking the
# devpts mount leaves /dev/ptmx dangling, so the sandbox cannot allocate a pty at all, which takes
# the whole TTY layer (line-discipline autoload, TIOCSTI, n_gsm & co) off the attack surface.
EXTRA_MASKED_PATHS = ("/proc/kallsyms", "/proc/modules", "/proc/cmdline", "/sys/module", "/sys/kernel",
                      "/dev/pts")

GPU_DEVICES = {
    "none": (),
    "nvidia": ("nvidia.com/gpu=all",),  # CDI; requires nvidia-container-toolkit CDI spec
    "amd": ("/dev/kfd",),  # plus the render nodes (ROCm)
    "dri": (),  # the render nodes only (Vulkan: Intel, AMD, ...)
}
DRI_DIR = Path("/dev/dri")


def gpu_devices(gpu: str, dri_dir: Path = DRI_DIR) -> tuple[str, ...]:
    """Device nodes for a GPU mode.

    For DRM GPUs only the render nodes (/dev/dri/renderD*) are passed: they are all compute needs.
    The primary nodes (/dev/dri/card*) carry modesetting and display control, a larger and more
    privileged driver interface, and are never handed to a sandbox.
    """
    devices = GPU_DEVICES[gpu]
    if gpu in ("amd", "dri"):
        render = sorted(str(p) for p in dri_dir.glob("renderD*"))
        if not render:
            raise HardeningError(f"runtime.gpu = {gpu!r} but there is no render node in {dri_dir}")
        devices = devices + tuple(render)
    return devices

# Flags that must appear in every silo container.
REQUIRED_FLAGS = (
    "--network=none",
    "--cap-drop=all",
    "--security-opt=no-new-privileges",
    "--read-only",
    "--read-only-tmpfs=false",
    "--image-volume=ignore",
    "--unsetenv-all",
    f"--user={SANDBOX_USER}",
    "--pull=never",
    "--ipc=private",
    "--cgroupns=private",
    "--uts=private",
    "--pid=private",
)

# Prefixes that must never appear, whatever the config says.
FORBIDDEN_PREFIXES = (
    "--privileged",
    "--network=host",
    "--net=",
    "--network=pasta",
    "--network=slirp4netns",
    "--network=bridge",
    "--network=container:",
    "--pid=host",
    "--ipc=host",
    "--uts=host",
    "--userns=host",
    "--cgroupns=host",
    "--cap-add",
    "--security-opt=seccomp=unconfined",
    "--security-opt=label=disable",
    "--security-opt=apparmor=unconfined",
    "--security-opt=unmask",
    "--security-opt=systempaths=unconfined",
    "--systemd=true",
    "--env-host",
    "--http-proxy=true",
    "--volumes-from",
    "--publish",
    "-p",
)


# Global podman flags for a sandbox on gVisor (runtime.runsc).
#   ignore-cgroups, cgroup-manager=cgroupfs: rootless runsc cannot manage cgroups, so the launcher wraps
#       podman in a systemd user scope that carries the memory and task limits instead (gvisor_scope).
#   network=none: no network stack beyond loopback inside gVisor either.
#   directfs=false: gVisor's sentry, the process sandboxed code attacks, then runs as the sandbox's own
#       unprivileged subordinate UID with no capabilities, and reaches files only through the gofer.
#       With gVisor's default (directfs on) it would run as the invoking user with DAC-override
#       capabilities in a user namespace.
#   host-uds=create: the runtime may create its listening socket in the one directory silo mounts for
#       it. It may not connect to any host socket.
# runsc does not accept SELinux process labels, so the container is started with label=disable:
# under gVisor the user-space kernel is the confinement layer, and SELinux does not confine it.
GVISOR_RUNTIME_FLAGS = ("--runtime-flag=ignore-cgroups", "--runtime-flag=network=none",
                        "--runtime-flag=directfs=false", "--runtime-flag=host-uds=create",
                        "--cgroup-manager=cgroupfs")
GVISOR_ONLY = "--security-opt=label=disable"


def gvisor_globals(rt) -> list[str]:
    """Global podman flags for a sandbox on gVisor; empty without runtime.runsc.

    The platform is always named, so the sandbox does not change with runsc's default: systrap
    intercepts syscalls with seccomp and works everywhere, VMs included; kvm runs the workload in a
    hardware-virtualised guest, is faster, and hands /dev/kvm to gVisor's sentry.
    """
    if rt.runsc is None:
        return []
    return [f"--runtime={rt.runsc}", *GVISOR_RUNTIME_FLAGS, f"--runtime-flag=platform={rt.gvisor_platform}"]


class HardeningError(RuntimeError):
    pass


@dataclass(frozen=True)
class Mount:
    source: Path
    target: str
    writable: bool = False
    shared_label: bool = False

    def flag(self) -> str:
        # Z: private SELinux label (container_file_t + this container's MCS pair).
        # z: shared label, for read-only data several sandboxes mount at once (model weights);
        #    a private relabel there would revoke a running model's access whenever a probe starts.
        if self.writable and self.shared_label:
            raise HardeningError("writable mounts must use a private SELinux label")
        mode = "rw" if self.writable else "ro"
        label = "z" if self.shared_label else "Z"
        return f"--volume={self.source}:{self.target}:{mode},{label},nosuid,nodev,noexec"


def podman_run_args(
    cfg: Config,
    *,
    name: str,
    image: str,
    command: list[str],
    seccomp_profile: Path,
    mounts: list[Mount] = (),
    detach: bool = False,
    interactive: bool = False,
    memory: str | None = None,
    pids_limit: int | None = None,
    gpu: str = "none",
    umask: str = "0022",
    remove: bool = True,
    oci_runtime: Path | None = None,
) -> list[str]:
    rt = cfg.runtime
    memory = memory or rt.memory
    gvisor = rt.runsc is not None
    args = [
        "podman",
        *runtime_globals(rt, oci_runtime),
        "run",
        *(["--rm"] if remove else []),
        f"--name={name}",
        f"--label={LABEL}",
        # --- network: no interfaces except a private loopback; no resolver, no hosts file
        "--network=none",
        "--no-hosts",
        "--hostname=silo",
        # --- privileges
        f"--user={SANDBOX_USER}",
        "--cap-drop=all",
        "--security-opt=no-new-privileges",
        f"--security-opt=seccomp={seccomp_profile}",
        f"--security-opt=mask={':'.join(EXTRA_MASKED_PATHS)}",
        # --- filesystem: immutable root, scratch tmpfs that cannot hold executables
        "--read-only",
        "--read-only-tmpfs=false",
        "--image-volume=ignore",
        "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777",
        # --- namespaces (explicit, not inherited from containers.conf)
        "--ipc=private",
        "--cgroupns=private",
        "--uts=private",
        "--pid=private",
        "--systemd=false",
        # --- resources
        f"--memory={memory}",
        f"--memory-swap={memory}",
        f"--pids-limit={pids_limit or rt.pids_limit}",
        "--ulimit=core=0:0",
        "--ulimit=nofile=4096:4096",
        # --- environment: drop everything the image or containers.conf would inject
        "--unsetenv-all",
        f"--env=PATH={CONTAINER_PATH}",
        f"--umask={umask}",
        # --- logs: bounded file owned by the container instead of an unbounded stream into the journal
        "--log-driver=k8s-file",
        "--log-opt=max-size=16m",
        # --- supply chain: never pull at launch; images are pulled (and pinned) explicitly
        "--pull=never",
        "--stop-timeout=10",
    ]
    if gvisor:
        args.append(GVISOR_ONLY)
    if rt.cpus:
        args.append(f"--cpus={rt.cpus}")
    for device in gpu_devices(gpu):
        args.append(f"--device={device}")
    for mount in mounts:
        args.append(mount.flag())
    if detach:
        args.append("--detach")
    if interactive:
        args.append("--interactive")
    args.append(image)
    args.extend(command)
    assert_hardened(args, gpu=gpu, gvisor=gvisor_globals(rt), oci_runtime=oci_runtime)
    return args


def runtime_globals(rt, oci_runtime: Path | None = None) -> list[str]:
    """Global podman flags that choose the OCI runtime: gVisor, or silo's AppArmor wrapper around the
    default one (silo.apparmor). gVisor takes precedence; host LSM profiles do not reach inside it."""
    if rt.runsc is not None:
        return gvisor_globals(rt)
    return [f"--runtime={oci_runtime}"] if oci_runtime is not None else []


def gvisor_scope(memory_bytes: int, tasks: int, cpus: float | None = None) -> list[str]:
    """systemd-run prefix that puts podman, conmon and the gVisor sandbox under one limited scope.

    The limits therefore cover gVisor's own processes as well as the workload: nothing started for
    this sandbox can use more than runtime.memory, swap, more tasks than the cap, or more CPU time
    than runtime.cpus.
    """
    scope = ["systemd-run", "--user", "--scope", "--quiet", "--collect", "-p", "Delegate=yes",
             "-p", f"MemoryMax={memory_bytes}", "-p", "MemorySwapMax=0", "-p", f"TasksMax={tasks}"]
    if cpus:
        scope += ["-p", f"CPUQuota={round(cpus * 100)}%"]
    return scope


def assert_hardened(args: list[str], gpu: str = "none", gvisor: list[str] = (),
                    oci_runtime: Path | None = None) -> None:
    """Check a podman command line before it runs.

    `gvisor` is gvisor_globals() for the sandbox, and `oci_runtime` silo's AppArmor wrapper if one
    is in use: the only global flags a silo command line may carry.
    """
    if args[:1] != ["podman"] or "run" not in args:
        raise HardeningError("not a podman run command")
    run_idx = args.index("run")
    expected = list(gvisor) or ([f"--runtime={oci_runtime}"] if oci_runtime is not None else [])
    if args[1:run_idx] != expected:
        raise HardeningError(f"unexpected global podman flags: {args[1:run_idx]}")
    try:
        image_idx = next(i for i, a in enumerate(args) if i > run_idx and not a.startswith("-"))
    except StopIteration:
        raise HardeningError("no image in podman args")
    opts = args[run_idx + 1:image_idx]
    missing = [f for f in REQUIRED_FLAGS if f not in opts]
    if missing:
        raise HardeningError(f"missing required flags: {missing}")
    if not any(o.startswith("--security-opt=seccomp=") and not o.endswith("=unconfined") for o in opts):
        raise HardeningError("no custom seccomp profile")
    for opt in opts:
        if opt == GVISOR_ONLY and gvisor:
            continue
        for bad in FORBIDDEN_PREFIXES:
            if opt == bad or opt.startswith(bad + "=") or (bad.endswith(("=", ":")) and opt.startswith(bad)):
                raise HardeningError(f"forbidden flag: {opt}")
    if gpu == "none" and any(o.startswith("--device") for o in opts):
        raise HardeningError("device passthrough without runtime.gpu set")
    nets = [o for o in opts if o.startswith("--network")]
    if nets != ["--network=none"]:
        raise HardeningError(f"network must be exactly --network=none, got {nets}")
    masks = [o for o in opts if o.startswith("--security-opt=mask=")]
    if len(masks) != 1 or set(EXTRA_MASKED_PATHS) - set(masks[0].split("=", 2)[2].split(":")):
        raise HardeningError("masked paths are missing")
