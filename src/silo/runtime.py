"""Model sandbox lifecycle: prepare, launch, wait, stop, probe."""

from __future__ import annotations

import importlib.resources
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from silo import intake, sandbox, seccomp
from silo.config import Config, ConfigError, runtime_root
from silo.gateway import UnixHTTPConnection
from silo.util import safe_text

SOCKET_NAME = "llama.sock"
SOCKET_IN_CONTAINER = f"/run/silo/{SOCKET_NAME}"

# llama-server flags that would hand the runtime network access, tools, a shell, other models or
# host-facing endpoints. The sandbox contains all of them anyway (no network, read-only root); the
# filter keeps the layers independent. Long flags are matched per dash-separated word so that new
# upstream flags in the same families are refused without a silo release.
FORBIDDEN_SERVER_WORDS = frozenset({
    "url", "hf", "repo", "docker", "download", "default",      # weight downloads
    "tool", "tools", "agent", "mcp", "proxy", "rpc",           # tools, agents, remote backends
    "host", "port", "ssl", "api", "ui", "webui",               # listeners and web UI
    "props", "slot", "slots", "metrics", "media", "models",    # admin/state endpoints, router mode
})
FORBIDDEN_SERVER_FLAGS = frozenset({
    "-m", "--model", "--path", "--log-prompts-dir", "--video-ffmpeg-dir",
    "-mu", "-hf", "-hfr", "-hff", "-hft", "-hfd", "-hfrd", "-dr", "-mmu", "-ag",
})
SAFETY_SWITCHES = ["--offline", "--no-webui", "--no-webui-mcp-proxy", "--no-agent", "--no-slots"]

SIGSYS_EXIT = 128 + 31
_IMAGE_ID_RE = re.compile(r"^(sha256:)?[0-9a-f]{64}$")


class LaunchError(RuntimeError):
    pass


def run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, text=True, capture_output=True, errors="replace")


# ------------------------------------------------------------------------------------ llama-server

def check_extra_args(extra: list[str]) -> None:
    for arg in extra:
        if not arg.startswith("-"):
            continue
        flag = arg.split("=", 1)[0]
        words = set(flag.lstrip("-").lower().split("-"))
        if flag in FORBIDDEN_SERVER_FLAGS or (flag.startswith("--") and words & FORBIDDEN_SERVER_WORDS):
            raise ConfigError(f"model.extra_args: {flag} is not allowed inside a silo")


def server_command(cfg: Config) -> list[str]:
    _, model_file = cfg.require_model()
    check_extra_args(cfg.model.extra_args)
    cmd = ["--model", f"/models/{model_file}", "--host", SOCKET_IN_CONTAINER,
           "--ctx-size", str(cfg.model.ctx_size), *SAFETY_SWITCHES]
    if cfg.model.threads:
        cmd += ["--threads", str(cfg.model.threads)]
    return cmd + list(cfg.model.extra_args)


# --------------------------------------------------------------------------------------- host prep

def prepare_seccomp(cfg: Config) -> Path:
    if not cfg.runtime.seccomp_base.is_file():
        raise LaunchError(f"base seccomp profile not found: {cfg.runtime.seccomp_base} (install containers-common)")
    return seccomp.write_profile(cfg.runtime.seccomp_base, cfg.seccomp_path, action=cfg.runtime.seccomp_action,
                                 cpu_only=cfg.runtime.gpu == "none")


def require_image(image: str) -> None:
    if subprocess.run(["podman", "image", "exists", image]).returncode != 0:
        raise LaunchError(f"image {image} is not present locally; silo never pulls at launch. Run `silo pull`.")


def _private_root() -> Path:
    root = runtime_root()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)  # host-side gate: only this user can reach anything silo shares with a sandbox
    return root


def _remove_dir(path: Path) -> None:
    """Delete a directory a sandbox may have written to (entries can belong to its subordinate UID)."""
    if path.parent != runtime_root():
        raise LaunchError(f"refusing to delete {path}: not a silo runtime directory")
    if path.is_symlink():
        path.unlink()
        return
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)
    if path.exists():  # something inside is owned by the sandbox UID; remove it from inside the userns
        run(["podman", "unshare", "rm", "-rf", "--", str(path)], check=False)
    if path.exists():
        raise LaunchError(f"cannot clean up {path}")


def prepare_socket_dir(cfg: Config) -> Path:
    """Create the one host directory the model sandbox can write to, empty and private.

    It has to be writable by the sandbox UID until llama-server has bound its socket; `lock_socket_dir`
    then takes that away again. The 0700 parent keeps every other host user out throughout.
    """
    _private_root()
    _remove_dir(cfg.socket_dir)
    cfg.socket_dir.mkdir(mode=0o700)
    os.chmod(cfg.socket_dir, 0o777)
    return cfg.socket_dir


def _is_socket(path: Path) -> bool:
    try:
        return stat.S_ISSOCK(os.lstat(path).st_mode)
    except OSError:
        return False


def lock_socket_dir(cfg: Config) -> None:
    """Freeze the shared directory once the runtime's socket exists.

    After this the sandbox (which is "other" for a directory owned by the host user) can no longer
    create, rename or delete entries: it cannot fill the host's runtime tmpfs and cannot replace the
    socket with a symlink to another host socket. The content check runs after the chmod, so what it
    sees is final.
    """
    os.chmod(cfg.socket_dir, 0o755)
    entries = sorted(os.listdir(cfg.socket_dir))
    if entries != [SOCKET_NAME] or not _is_socket(cfg.socket_path):
        raise LaunchError(f"unexpected content in the socket directory ({[safe_text(e) for e in entries]}); "
                          "the sandbox did something other than bind its socket. Refusing to connect.")


class SocketDirWatcher(threading.Thread):
    """Locks the socket directory the moment anything appears in it.

    llama-server binds its socket and goes straight on to read the model file, so the lock cannot
    land before model loading starts; it can only land close behind the bind. This thread is started
    before the container and does nothing but watch, so nothing else silo is doing (podman calls take
    tens of milliseconds) delays it. Whatever a load-time exploit left in the directory in the
    meantime fails the content check in `lock_socket_dir`, and the launch with it.
    """

    INTERVAL = 0.0005

    def __init__(self, cfg: Config, deadline: float):
        super().__init__(daemon=True, name="silo-socket-lock")
        self.cfg, self.deadline = cfg, deadline
        self.locked = threading.Event()
        self.error: LaunchError | None = None
        self._cancelled = threading.Event()

    def cancel(self) -> None:
        self._cancelled.set()

    def run(self) -> None:
        directory = self.cfg.socket_dir
        while not self._cancelled.is_set() and time.monotonic() < self.deadline:
            try:
                with os.scandir(directory) as it:
                    empty = next(it, None) is None
            except OSError:
                empty = True
            if not empty:
                try:
                    lock_socket_dir(self.cfg)
                except LaunchError as exc:
                    self.error = exc
                except OSError as exc:
                    self.error = LaunchError(f"cannot lock {directory}: {exc.strerror}")
                self.locked.set()
                return
            time.sleep(self.INTERVAL)


def socket_dir_locked(cfg: Config) -> bool:
    try:
        st = os.lstat(cfg.socket_dir)
    except OSError:
        return False
    return (stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid() and not st.st_mode & 0o022
            and _is_socket(cfg.socket_path))


# --------------------------------------------------------------------------------------- lifecycle

def container_running(name: str) -> bool:
    res = run(["podman", "container", "inspect", "--format", "{{.State.Running}}", name], check=False)
    return res.returncode == 0 and res.stdout.strip() == "true"


def health(socket_path: Path, timeout: float = 5) -> int | None:
    conn = UnixHTTPConnection(str(socket_path), timeout=timeout)
    try:
        conn.request("GET", "/health")
        return conn.getresponse().status
    except Exception:  # noqa: BLE001 - a hostile runtime may answer with anything; that is "not healthy"
        return None
    finally:
        conn.close()


def _tail_logs(name: str, lines: int = 30) -> str:
    res = run(["podman", "logs", "--tail", str(lines), name], check=False)
    return safe_text((res.stdout + res.stderr).strip())


def _exit_hint(name: str) -> str:
    res = run(["podman", "container", "inspect", "--format", "{{.State.ExitCode}} {{.State.OOMKilled}}", name],
              check=False)
    code, _, oom = res.stdout.strip().partition(" ")
    if oom == "true":
        return "killed by the kernel OOM killer: the model does not fit in runtime.memory"
    if code == str(SIGSYS_EXIT):
        return ("killed by seccomp (SIGSYS): the runtime used a syscall the profile denies. "
                'Set runtime.seccomp_action = "errno" to keep it running and find out which')
    return f"exit code {code or 'unknown'}"


def _remove(name: str) -> None:
    run(["podman", "rm", "--force", "--ignore", name], check=False)


def up(cfg: Config, verify: bool = True, full_verify: bool = False) -> None:
    models_dir, model_file = cfg.require_model()
    if not (models_dir / model_file).is_file():
        raise LaunchError(f"model file not found: {models_dir / model_file}")
    if container_running(cfg.container_name):
        raise LaunchError(f"{cfg.container_name} is already running")
    _remove(cfg.container_name)  # a stopped container kept from the last run (for its logs)
    if verify:
        problems = intake.verify(models_dir, cfg.manifest_path, full=full_verify)
        if problems:
            shown = "\n  ".join(safe_text(p) for p in problems[:20])
            raise LaunchError(f"model directory does not match its manifest:\n  {shown}")
    require_image(cfg.runtime.image)
    profile = prepare_seccomp(cfg)
    prepare_socket_dir(cfg)
    args = sandbox.podman_run_args(
        cfg,
        name=cfg.container_name,
        image=cfg.runtime.image,
        command=server_command(cfg),
        seccomp_profile=profile,
        mounts=[sandbox.Mount(models_dir, "/models", shared_label=True),
                sandbox.Mount(cfg.socket_dir, "/run/silo", writable=True)],
        detach=True,
        gpu=cfg.runtime.gpu,
        umask="0000",  # socket must be connectable by the host user (outside the sandbox's subuid)
        remove=False,  # keep logs of a failed start; `silo down` / the next `silo up` removes it
    )
    deadline = time.monotonic() + cfg.runtime.startup_timeout
    watcher = SocketDirWatcher(cfg, deadline)
    watcher.start()  # before the container exists, so it is already watching when the socket appears
    try:
        res = run(args, check=False)
        if res.returncode != 0:
            raise LaunchError(f"podman run failed:\n{safe_text(res.stderr.strip())}")
        _wait_until_healthy(cfg, watcher, deadline)
    except BaseException:
        watcher.cancel()
        down(cfg)  # fail closed: nothing half-started is left behind
        raise


def _wait_until_healthy(cfg: Config, watcher: SocketDirWatcher, deadline: float) -> None:
    name = cfg.container_name
    last = None
    while time.monotonic() < deadline:
        if watcher.error:
            raise watcher.error
        if not container_running(name):
            raise LaunchError(f"{name} exited during startup ({_exit_hint(name)}):\n{_tail_logs(name)}")
        if watcher.locked.is_set():  # never talk to the socket before the directory is frozen and checked
            last = health(cfg.socket_path)
            if last == 200:
                return
        if watcher.locked.is_set():
            time.sleep(0.5)
        else:
            watcher.locked.wait(0.5)
    raise LaunchError(f"model not healthy within {cfg.runtime.startup_timeout:.0f}s (last status {last}):\n"
                      f"{_tail_logs(name)}")


def down(cfg: Config) -> bool:
    was_running = container_running(cfg.container_name)
    if was_running:
        run(["podman", "stop", "--time", "10", cfg.container_name], check=False)
    _remove(cfg.container_name)
    if cfg.socket_dir.exists() or cfg.socket_dir.is_symlink():
        _remove_dir(cfg.socket_dir)
    return was_running


def status(cfg: Config) -> dict:
    running = container_running(cfg.container_name)
    locked = socket_dir_locked(cfg)
    return {
        "name": cfg.name,
        "container": cfg.container_name,
        "running": running,
        "socket": str(cfg.socket_path),
        "socket_dir_locked": locked,
        "health": health(cfg.socket_path) if running and locked else None,
        "image": cfg.runtime.image,
        "seccomp_action": cfg.runtime.seccomp_action,
        "gateway": f"http://{cfg.gateway.listen}:{cfg.gateway.port}/v1",
        "scanner": cfg.gateway.scanner,
        "allow_tools": cfg.gateway.allow_tools,
        "audit_log": str(cfg.audit_log),
    }


def logs(cfg: Config, follow: bool = False) -> int:
    """Print runtime logs with control characters escaped: GGUF metadata and prompts end up in them."""
    cmd = ["podman", "logs"] + (["--follow"] if follow else []) + [cfg.container_name]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        for raw in proc.stdout:
            sys.stdout.write(safe_text(raw.decode("utf-8", "replace")))
            sys.stdout.flush()
    except KeyboardInterrupt:
        proc.terminate()
    return proc.wait()


# ------------------------------------------------------------------------------------------ probes

def probe_script() -> str:
    return importlib.resources.files("silo.probes").joinpath("escape_probes.py").read_text()


def probe(cfg: Config, baseline: bool = False) -> tuple[int, list[dict]]:
    """Run the escape probes in a sandbox built exactly like the model runtime (or a stock container)."""
    image = cfg.runtime.probe_image
    require_image(image)
    scratch = None
    if baseline:
        args = ["podman", "run", "--rm", "--interactive", "--pull=never", image, "python3", "-I", "-"]
    else:
        profile = prepare_seccomp(cfg)
        scratch = Path(tempfile.mkdtemp(prefix="probe-", dir=_private_root()))
        os.chmod(scratch, 0o755)  # the steady state of the model's socket directory: locked
        mounts = [sandbox.Mount(scratch, "/run/silo", writable=True)]
        if cfg.model.dir and cfg.model.dir.is_dir():
            mounts.insert(0, sandbox.Mount(cfg.model.dir, "/models", shared_label=True))
        args = sandbox.podman_run_args(
            cfg, name=f"{cfg.container_name}-probe", image=image, command=["python3", "-I", "-"],
            seccomp_profile=profile, mounts=mounts, interactive=True, memory="512m", gpu=cfg.runtime.gpu,
        )
    try:
        res = subprocess.run(args, input=probe_script(), text=True, capture_output=True, timeout=300,
                             errors="replace")
    finally:
        if scratch:
            _remove_dir(scratch)
    results, summary = [], None
    for line in res.stdout.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        if "summary" in item:
            summary = item["summary"]
        elif {"probe", "status", "detail"} <= set(item):
            results.append({k: str(item[k]) for k in ("probe", "status", "detail")})
    if not isinstance(summary, dict):
        hint = ""
        if res.returncode == SIGSYS_EXIT:
            hint = " - the probe runner itself was killed by seccomp (SIGSYS)"
        elif res.returncode == 125:
            hint = " - podman could not start the container"
        raise LaunchError(f"probe run did not complete (exit {res.returncode}{hint}); "
                          f"{len(results)} results before it stopped\n{safe_text(res.stderr.strip()[-800:])}")
    # Never trust the sandbox's own tally: count what was actually reported.
    return (1 if any(r["status"] == "FAIL" for r in results) else 0), results


def is_pinned(image: str) -> bool:
    """True if the reference names exact content: a registry digest or a full image ID."""
    return "@sha256:" in image or bool(_IMAGE_ID_RE.match(image))


def image_info(image: str) -> dict:
    """What the local store holds for a reference, and the two ways to pin it.

    A registry digest (`repo@sha256:...`) only exists for images that were pulled; `podman load`
    assigns a different one. The image ID is the hash of the image's own configuration, layer
    hashes included, and is the same wherever the image goes, so it is the pin that also works on a
    host that received its images as archives.
    """
    res = run(["podman", "image", "inspect", "--format", "{{.Id}}\t{{json .RepoDigests}}", image], check=False)
    if res.returncode != 0:
        return {"image": image, "present": False, "pinned": is_pinned(image)}
    image_id, _, digests = res.stdout.strip().partition("\t")
    try:
        digests = [d for d in json.loads(digests) or [] if isinstance(d, str)]
    except json.JSONDecodeError:
        digests = []
    return {"image": image, "present": True, "pinned": is_pinned(image), "id": image_id,
            "pin_by_id": f"sha256:{image_id}", "registry_digests": digests}


def images(cfg: Config) -> list[dict]:
    return [image_info(image) for image in dict.fromkeys([cfg.runtime.image, cfg.runtime.probe_image])]


def pull(cfg: Config) -> list[dict]:
    for image in dict.fromkeys([cfg.runtime.image, cfg.runtime.probe_image]):
        subprocess.run(["podman", "pull", image], check=True)
    return images(cfg)
