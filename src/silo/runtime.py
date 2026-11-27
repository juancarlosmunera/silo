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
from silo.config import Config, ConfigError, memory_bytes, runtime_root
from silo.gateway import UnixHTTPConnection, runtime_dialer, runtime_path
from silo.util import safe_text

# llama-server listens on this abstract UNIX socket: it exists only in the sandbox's own network
# namespace, so no host directory is shared (see silo.connector).
ABSTRACT_SOCKET = "silo-llama.sock"
CONNECTOR_START_TIMEOUT = 15.0
# The exec supervisor's files, in the sandbox's runtime directory (or a probe run's own).
EXEC_SOCKET, EXEC_PIDFILE, EXEC_LOG = "exec.sock", "execlock.pid", "execlock.log"
# On gVisor (runtime.runsc) abstract sockets live inside gVisor's own kernel, where the connector
# cannot reach them. There the runtime binds a socket in a mounted directory instead, which gVisor
# creates on the host (host-uds=create) and which silo locks as soon as the socket appears.
GVISOR_SOCKET_DIR_IN_CONTAINER = "/run/silo"
# The scope's task limit covers gVisor's own threads too: each sandboxed thread has a host thread
# behind it, and the sentry and gofer need their own.
GVISOR_TASK_HEADROOM = 512
SIGKILL_EXIT = 128 + 9
# Seconds the runtime gets to exit by itself before it is killed. On gVisor llama-server never gets
# there: its HTTP library stops the accept loop with shutdown() on the listening socket, which
# wakes accept() on Linux but, on gVisor, fails with ENOTCONN and leaves accept() blocked. The
# sandbox holds no state, so it is given a short grace period and then killed.
STOP_GRACE = 10
GVISOR_STOP_GRACE = 2

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


def run_detached(cmd: list[str]) -> tuple[int, str]:
    """Run a command that leaves processes behind (podman run --detach), without pipes.

    Under gVisor the sandbox process inherits the launcher's stdout and stderr; a captured pipe would
    then never reach EOF. Output goes to an unnamed temporary file instead.
    """
    with tempfile.TemporaryFile() as err:
        code = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=err).returncode
        err.seek(0)
        return code, err.read().decode("utf-8", "replace")


def run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, text=True, capture_output=True, errors="replace")


# ------------------------------------------------------------------------------------ llama-server

def physical_cores(sysfs: Path = Path("/sys/devices/system/cpu")) -> int | None:
    """Physical cores this process may run on, from the kernel's CPU topology; None if unknown."""
    cores = set()
    try:
        for cpu in os.sched_getaffinity(0):
            topology = sysfs / f"cpu{cpu}" / "topology"
            cores.add((topology.joinpath("physical_package_id").read_text().strip(),
                       topology.joinpath("core_id").read_text().strip()))
    except OSError:
        return None
    return len(cores) or None


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
    host = (f"{GVISOR_SOCKET_DIR_IN_CONTAINER}/{cfg.gvisor_socket_path.name}" if gvisor(cfg)
            else f"@{ABSTRACT_SOCKET}")
    cmd = ["--model", f"/models/{model_file}", "--host", host,
           "--ctx-size", str(cfg.model.ctx_size), *SAFETY_SWITCHES]
    threads = cfg.model.threads
    if threads is None and gvisor(cfg):
        # llama.cpp starts one thread per physical core, which it reads from the CPU topology in
        # sysfs. gVisor does not show the host's topology, so llama.cpp would start one per logical
        # CPU instead, which on a hyperthreaded machine costs about a third of the throughput.
        threads = physical_cores()
    if threads:
        cmd += ["--threads", str(threads)]
    return cmd + list(cfg.model.extra_args)


# --------------------------------------------------------------------------------------- host prep

def exec_lock(cfg: Config) -> bool:
    """Whether execve is decided by silo's supervisor (silo.execlock) for this sandbox.

    Not on gVisor: its seccomp implementation has no user notification and refuses such a profile.
    """
    return cfg.runtime.exec_lock and not gvisor(cfg)


def prepare_seccomp(cfg: Config, exec_dir: Path | None = None, probe: bool = False) -> Path:
    """Write the hardened profile. `exec_dir` is where this sandbox's exec supervisor listens."""
    if not cfg.runtime.seccomp_base.is_file():
        raise LaunchError(f"base seccomp profile not found: {cfg.runtime.seccomp_base} (install containers-common)")
    return seccomp.write_profile(cfg.runtime.seccomp_base, cfg.probe_seccomp_path if probe else cfg.seccomp_path,
                                 action=cfg.runtime.seccomp_action, cpu_only=cfg.runtime.gpu == "none",
                                 exec_listener=exec_dir / EXEC_SOCKET if exec_dir else None)


def require_image(image: str) -> None:
    if subprocess.run(["podman", "image", "exists", image]).returncode != 0:
        raise LaunchError(f"image {image} is not present locally; silo never pulls at launch. Run `silo pull`.")


def _private_root() -> Path:
    root = runtime_root()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)  # only this user can reach the connector's control socket
    return root


def _remove_dir(path: Path) -> None:
    """Delete a silo runtime directory (entries the connector made can belong to a subordinate UID)."""
    if path.parent != runtime_root():
        raise LaunchError(f"refusing to delete {path}: not a silo runtime directory")
    if path.is_symlink():
        path.unlink()
        return
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)
    if path.exists():
        run(["podman", "unshare", "rm", "-rf", "--", str(path)], check=False)
    if path.exists():
        raise LaunchError(f"cannot clean up {path}")


def prepare_run_dir(cfg: Config) -> Path:
    """The host-side directory for the connector's control socket. Never mounted into a sandbox."""
    _private_root()
    _remove_dir(cfg.socket_dir)
    cfg.socket_dir.mkdir(mode=0o700)
    return cfg.socket_dir


def gvisor(cfg: Config) -> bool:
    return cfg.runtime.runsc is not None


def scoped(cfg: Config, args: list[str], memory: str | None = None) -> list[str]:
    """On gVisor, run podman inside a systemd user scope that carries the resource limits.

    Rootless runsc cannot configure cgroups, so podman's --memory, --pids-limit and --cpus would be
    silently without effect. Refusing to start is better than starting unlimited.
    """
    if not gvisor(cfg):
        return args
    if not shutil.which("systemd-run"):
        raise LaunchError("runtime.runsc needs systemd-run: under gVisor the memory and task limits are "
                          "enforced by a systemd user scope")
    tasks = 2 * cfg.runtime.pids_limit + GVISOR_TASK_HEADROOM
    return sandbox.gvisor_scope(memory_bytes(memory or cfg.runtime.memory), tasks, cfg.runtime.cpus) + args


class GvisorSocketLock(threading.Thread):
    """Locks the gVisor socket directory the moment anything appears in it, then checks it."""

    INTERVAL = 0.002

    def __init__(self, cfg: Config, deadline: float):
        super().__init__(daemon=True, name="silo-gvisor-socket-lock")
        self.directory, self.deadline = cfg.gvisor_socket_dir, deadline
        self.socket_name = cfg.gvisor_socket_path.name
        self.locked = threading.Event()
        self.error: LaunchError | None = None

    def run(self) -> None:
        while time.monotonic() < self.deadline:
            try:
                entries = os.listdir(self.directory)
            except OSError:
                entries = []
            if entries:
                # The directory belongs to this user, container root inside the sandbox. Once it is 0755
                # the runtime (nobody) can no longer add, rename or remove entries: gVisor's own
                # permission checks refuse it, and its gofer re-reads the mode from the host.
                os.chmod(self.directory, 0o755)
                entries = sorted(os.listdir(self.directory))
                if entries != [self.socket_name] or not _is_socket(self.directory / self.socket_name):
                    self.error = LaunchError(f"unexpected content in the socket directory "
                                             f"({[safe_text(e) for e in entries]}); refusing to connect")
                self.locked.set()
                return
            time.sleep(self.INTERVAL)


def _is_socket(path: Path) -> bool:
    try:
        return stat.S_ISSOCK(os.lstat(path).st_mode)
    except OSError:
        return False


# --------------------------------------------------------------------------------------- connector

def connector_script() -> str:
    return importlib.resources.files("silo").joinpath("connector.py").read_text()


def container_pid(name: str) -> int:
    res = run(["podman", "container", "inspect", "--format", "{{.State.Pid}}", name], check=False)
    pid = res.stdout.strip()
    if res.returncode != 0 or not pid.isdigit() or int(pid) <= 1:
        raise LaunchError(f"cannot find the process of {name}")
    return int(pid)


def connector_pid(cfg: Config) -> int | None:
    return _helper_pid(cfg.connector_pidfile)


def _start_helper(what: str, source: str, args: list[str], log_path: Path, socket_path: Path) -> None:
    """Start one of silo's helpers under `podman unshare`, from source text, and wait until it listens."""
    log = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        proc = subprocess.Popen(["podman", "unshare", sys.executable, "-I", "-", *args],
                                stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=log, start_new_session=True)
    finally:
        os.close(log)
    proc.stdin.write(source.encode())
    proc.stdin.close()
    deadline = time.monotonic() + CONNECTOR_START_TIMEOUT
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        if _is_socket(socket_path) and "ready" in _read_log(log_path):
            return
        time.sleep(0.05)
    raise LaunchError(f"{what} did not start:\n{_read_log(log_path)[-800:]}")


def _helper_pid(pidfile: Path) -> int | None:
    try:
        pid = int(pidfile.read_text().strip())
    except (OSError, ValueError):
        return None
    if pid <= 1:
        return None
    # A pidfile outlives its process (a crash, a reboot) and PIDs are reused, by the sandbox too, which
    # can burn through them quickly. Only a process started with this very pidfile is ours.
    try:
        argv = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    except OSError:
        return None
    return pid if os.fsencode(str(pidfile)) in argv else None


def _stop_helper(pidfile: Path) -> None:
    pid = _helper_pid(pidfile)
    if pid is None:
        return
    deadline = time.monotonic() + 3  # helpers exit by themselves once the sandbox's processes are gone
    while time.monotonic() < deadline and _helper_pid(pidfile) == pid:
        time.sleep(0.1)
    if _helper_pid(pidfile) == pid:  # they may run as a subordinate UID: signal from inside the namespace
        run(["podman", "unshare", "kill", "-KILL", str(pid)], check=False)


def _read_log(path: Path) -> str:
    try:
        return safe_text(path.read_text(errors="replace"))
    except OSError:
        return ""


def start_connector(cfg: Config, pid: int) -> None:
    """Start the connector for the sandbox whose process is `pid` and wait until it serves."""
    _start_helper("connector", connector_script(),
                  ["--pid", str(pid), "--address", ABSTRACT_SOCKET, "--control", str(cfg.control_path),
                   "--pidfile", str(cfg.connector_pidfile)], cfg.connector_log, cfg.control_path)


def stop_connector(cfg: Config) -> None:
    _stop_helper(cfg.connector_pidfile)


# ----------------------------------------------------------------------------------- exec lock

def execlock_script() -> str:
    return importlib.resources.files("silo").joinpath("execlock.py").read_text()


def start_exec_supervisor(cfg: Config, directory: Path) -> None:
    """Start the exec supervisor for a sandbox whose seccomp profile names `directory`'s socket.

    It has to listen before the container is created: the runtime hands it the notification
    descriptor while it sets the container up, and refuses to start the container if nobody answers.
    """
    cfg.audit_log.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    args = ["--listen", str(directory / EXEC_SOCKET), "--pidfile", str(directory / EXEC_PIDFILE),
            "--audit", str(cfg.audit_log), "--name", cfg.name]
    if cfg.runtime.seccomp_action == "kill":
        args.append("--kill")
    _start_helper("exec supervisor", execlock_script(), args, directory / EXEC_LOG, directory / EXEC_SOCKET)


def execs_refused(directory: Path) -> int:
    """How many execve calls this sandbox's supervisor has refused so far."""
    # Lines carry the running number of the execve (the allowed first one included); after the first
    # hundred refusals the supervisor records only a sample, so the last number is the count.
    numbers = re.findall(r"^execlock: execve #(\d+) ", _read_log(directory / EXEC_LOG), re.M)
    return int(numbers[-1]) - 1 if numbers else 0


# --------------------------------------------------------------------------------------- lifecycle

def container_running(name: str) -> bool:
    res = run(["podman", "container", "inspect", "--format", "{{.State.Running}}", name], check=False)
    return res.returncode == 0 and res.stdout.strip() == "true"


def health(cfg: Config, timeout: float = 5) -> int | None:
    conn = None
    try:
        conn = UnixHTTPConnection(runtime_dialer(cfg), timeout=timeout)
        conn.request("GET", "/health")
        return conn.getresponse().status
    except Exception:  # noqa: BLE001 - a hostile runtime may answer with anything; that is "not healthy"
        return None
    finally:
        if conn is not None:
            conn.close()


def _tail_logs(name: str, lines: int = 30) -> str:
    res = run(["podman", "logs", "--tail", str(lines), name], check=False)
    return safe_text((res.stdout + res.stderr).strip())


def _exit_hint(cfg: Config) -> str:
    name = cfg.container_name
    res = run(["podman", "container", "inspect", "--format", "{{.State.ExitCode}} {{.State.OOMKilled}}", name],
              check=False)
    code, _, oom = res.stdout.strip().partition(" ")
    if oom == "true":
        return "killed by the kernel OOM killer: the model does not fit in runtime.memory"
    if code == str(SIGSYS_EXIT):
        return ("killed by seccomp (SIGSYS): the runtime used a syscall the profile denies. "
                'Set runtime.seccomp_action = "errno" to keep it running and find out which')
    if code == str(SIGKILL_EXIT) and exec_lock(cfg) and execs_refused(cfg.socket_dir):
        return ("killed by silo's exec lock: the runtime tried to execute another program. If the image's "
                "entrypoint is a wrapper that starts the real server, set runtime.exec_lock = false")
    if exec_lock(cfg) and execs_refused(cfg.socket_dir):
        return (f"exit code {code or 'unknown'}, after silo's exec lock refused an execve. If the image's "
                "entrypoint is a wrapper that starts the real server, set runtime.exec_lock = false")
    if code == str(SIGKILL_EXIT) and gvisor(cfg):
        return ("killed (SIGKILL): under gVisor that is what running out of runtime.memory looks like, "
                "because the limit covers the whole gVisor sandbox")
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
    prepare_run_dir(cfg)
    profile = prepare_seccomp(cfg, exec_dir=cfg.socket_dir if exec_lock(cfg) else None)
    mounts = [sandbox.Mount(models_dir, "/models", shared_label=True)]
    if gvisor(cfg):
        cfg.gvisor_socket_dir.mkdir(mode=0o700)
        os.chmod(cfg.gvisor_socket_dir, 0o777)  # until the runtime has bound its socket; then locked
        mounts.append(sandbox.Mount(cfg.gvisor_socket_dir, GVISOR_SOCKET_DIR_IN_CONTAINER, writable=True))
    args = sandbox.podman_run_args(
        cfg,
        name=cfg.container_name,
        image=cfg.runtime.image,
        command=server_command(cfg),
        seccomp_profile=profile,
        mounts=mounts,
        detach=True,
        gpu=cfg.runtime.gpu,
        umask="0000" if gvisor(cfg) else "0022",  # the host-side socket must be connectable by this user
        remove=False,  # keep logs of a failed start; `silo down` / the next `silo up` removes it
    )
    deadline = time.monotonic() + cfg.runtime.startup_timeout
    lock = GvisorSocketLock(cfg, deadline) if gvisor(cfg) else None
    if lock:
        lock.start()  # before the container exists, so it is already watching when the socket appears
    try:
        if exec_lock(cfg):
            start_exec_supervisor(cfg, cfg.socket_dir)  # before the container: the runtime reports to it
        code, err = run_detached(scoped(cfg, args))
        if code != 0:
            raise LaunchError(f"podman run failed:\n{safe_text(err.strip())}")
        if not lock:
            try:
                start_connector(cfg, container_pid(cfg.container_name))
            except LaunchError:
                _raise_if_exited(cfg)  # a runtime that died at once is the news, not the connector missing it
                raise
        _wait_until_healthy(cfg, deadline, lock)
    except BaseException:
        down(cfg)  # fail closed: nothing half-started is left behind
        raise


def _raise_if_exited(cfg: Config) -> None:
    name = cfg.container_name
    if not container_running(name):
        raise LaunchError(f"{name} exited during startup ({_exit_hint(cfg)}):\n{_tail_logs(name)}") from None


def _wait_until_healthy(cfg: Config, deadline: float, lock: GvisorSocketLock | None = None) -> None:
    name = cfg.container_name
    last = None
    while time.monotonic() < deadline:
        _raise_if_exited(cfg)
        if lock and lock.error:
            raise lock.error
        if lock and not lock.locked.is_set():  # never talk to the socket before it is locked and checked
            lock.locked.wait(0.5)
            continue
        last = health(cfg)
        if last == 200:
            return
        time.sleep(0.5)
    raise LaunchError(f"model not healthy within {cfg.runtime.startup_timeout:.0f}s (last status {last}):\n"
                      f"{_tail_logs(name)}")


def down(cfg: Config) -> bool:
    was_running = container_running(cfg.container_name)
    if was_running:
        grace = GVISOR_STOP_GRACE if gvisor(cfg) else STOP_GRACE
        run(["podman", "stop", "--time", str(grace), cfg.container_name], check=False)
    _remove(cfg.container_name)
    stop_connector(cfg)
    _stop_helper(cfg.socket_dir / EXEC_PIDFILE)
    if cfg.socket_dir.exists() or cfg.socket_dir.is_symlink():
        _remove_dir(cfg.socket_dir)
    return was_running


def runtime_reachable(cfg: Config) -> bool:
    """Whether the runtime can be reached: the connector, or on gVisor the locked host-side socket."""
    if gvisor(cfg):
        try:
            st = os.lstat(cfg.gvisor_socket_dir)
        except OSError:
            return False
        locked = stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid() and not st.st_mode & 0o022
        return locked and _is_socket(cfg.gvisor_socket_path)
    return connector_pid(cfg) is not None and _is_socket(cfg.control_path)


def exec_lock_state(cfg: Config) -> str:
    if gvisor(cfg):
        return "not available on gVisor"
    if not cfg.runtime.exec_lock:
        return "off (runtime.exec_lock = false)"
    return "on" if _helper_pid(cfg.socket_dir / EXEC_PIDFILE) else "on (supervisor not running)"


def status(cfg: Config) -> dict:
    running = container_running(cfg.container_name)
    reachable = runtime_reachable(cfg)
    return {
        "name": cfg.name,
        "container": cfg.container_name,
        "running": running,
        "kernel": f"gvisor ({cfg.runtime.gvisor_platform})" if gvisor(cfg) else "host",
        "socket": str(runtime_path(cfg)),
        "reached_through": "locked socket directory" if gvisor(cfg) else "connector",
        "reachable": reachable,
        "health": health(cfg) if running and reachable else None,
        "exec_lock": exec_lock_state(cfg),
        "execs_refused": execs_refused(cfg.socket_dir) if exec_lock(cfg) else None,
        "image": cfg.runtime.image,
        "seccomp_action": cfg.runtime.seccomp_action,
        "gateway": f"http://{cfg.gateway.listen}:{cfg.gateway.port}/v1",
        "scanner": cfg.gateway.scanner,
        "allow_tools": cfg.gateway.allow_tools,
        "tools": list(cfg.gateway.tools),
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
        # The probe run's own runtime directory: its exec supervisor's files, never mounted anywhere.
        scratch = Path(tempfile.mkdtemp(prefix="probe-", dir=_private_root()))
        mounts = []
        if cfg.model.dir and cfg.model.dir.is_dir():
            mounts.append(sandbox.Mount(cfg.model.dir, "/models", shared_label=True))
        if gvisor(cfg):  # the steady state of the runtime's socket directory: shared, and locked
            shared = scratch / "sock"
            shared.mkdir()
            os.chmod(shared, 0o755)
            mounts.append(sandbox.Mount(shared, GVISOR_SOCKET_DIR_IN_CONTAINER, writable=True))
        locked = exec_lock(cfg)
        profile = prepare_seccomp(cfg, exec_dir=scratch if locked else None, probe=True)
        flags = [*(["--gpu"] if cfg.runtime.gpu != "none" else []), *(["--gvisor"] if gvisor(cfg) else []),
                 *([] if locked else ["--no-exec-lock"])]
        args = scoped(cfg, sandbox.podman_run_args(
            cfg, name=f"{cfg.container_name}-probe", image=image, command=["python3", "-I", "-", *flags],
            seccomp_profile=profile, mounts=mounts, interactive=True, memory="512m", gpu=cfg.runtime.gpu,
        ), memory="512m")
    try:
        if scratch and exec_lock(cfg):
            start_exec_supervisor(cfg, scratch)
        res = subprocess.run(args, input=probe_script(), text=True, capture_output=True, timeout=300,
                             errors="replace")
    finally:
        if scratch:
            _stop_helper(scratch / EXEC_PIDFILE)
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
