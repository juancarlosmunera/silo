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
    "amd": ("/dev/kfd", "/dev/dri"),
    "dri": ("/dev/dri",),  # Vulkan / Intel
}

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
) -> list[str]:
    rt = cfg.runtime
    memory = memory or rt.memory
    args = [
        "podman", "run",
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
    if rt.cpus:
        args.append(f"--cpus={rt.cpus}")
    for device in GPU_DEVICES[gpu]:
        args.append(f"--device={device}")
    for mount in mounts:
        args.append(mount.flag())
    if detach:
        args.append("--detach")
    if interactive:
        args.append("--interactive")
    args.append(image)
    args.extend(command)
    assert_hardened(args, gpu=gpu)
    return args


def assert_hardened(args: list[str], gpu: str = "none") -> None:
    try:
        image_idx = next(i for i, a in enumerate(args) if i > 1 and not a.startswith("-"))
    except StopIteration:
        raise HardeningError("no image in podman args")
    opts = args[2:image_idx]
    missing = [f for f in REQUIRED_FLAGS if f not in opts]
    if missing:
        raise HardeningError(f"missing required flags: {missing}")
    if not any(o.startswith("--security-opt=seccomp=") and not o.endswith("=unconfined") for o in opts):
        raise HardeningError("no custom seccomp profile")
    for opt in opts:
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
