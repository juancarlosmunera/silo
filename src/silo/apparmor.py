"""AppArmor confinement for the sandbox on hosts without SELinux.

Rootless Podman applies no AppArmor profile and refuses an explicit one ("Apparmor is not enabled on
this system"), so on Ubuntu and Debian the sandbox ran without any mandatory access control. The OCI
runtime underneath has no such objection: crun applies `process.apparmorProfile` from the
container's configuration, and changing into a profile that is already loaded takes no privilege.

So silo does two things when root has loaded its profile (host/apparmor/silo-runtime):

  * it starts Podman with a small wrapper as the OCI runtime. The wrapper writes the profile's name
    into the container's configuration and then becomes the real runtime;
  * it checks, as an ordinary process, that the profile is loaded, and `silo probe` checks from
    inside that it is enforced.

With no_new_privs set, as it always is in a silo, AppArmor does not replace the label the runtime
already has: it stacks the profile on top of it (`crun//&silo-runtime`). Every profile in a stack
has to allow an operation, so the sandbox is confined by silo's all the same.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

PROFILE = "silo-runtime"
ENABLED = Path("/sys/module/apparmor/parameters/enabled")
INSTALL_HINT = ("sudo install -m 0644 host/apparmor/silo-runtime /etc/apparmor.d/silo-runtime && "
                "sudo apparmor_parser -r /etc/apparmor.d/silo-runtime")

# The wrapper Podman runs as its OCI runtime. It stands alone: no imports from silo, and -I keeps the
# current directory and the user's site-packages off its import path.
WRAPPER = '''#!{python} -I
"""silo's OCI runtime wrapper: put the container under the AppArmor profile {profile!r}, then run {runtime}."""
import json
import os
import sys

RUNTIME = {runtime!r}
PROFILE = {profile!r}


def option(args, long, short):
    for i, arg in enumerate(args):
        if arg in (long, short) and i + 1 < len(args):
            return args[i + 1]
        if arg.startswith(long + "="):
            return arg.split("=", 1)[1]
    return None


def rewrite(path, edit):
    with open(path) as fh:
        document = json.load(fh)
    edit(document)
    tmp = path + ".silo"
    with open(tmp, "w") as fh:
        json.dump(document, fh)
    os.replace(tmp, path)


# Global options of crun and runc that take a separate value: that value is not the subcommand.
VALUED = {{"--root", "--log", "--log-format", "--log-level", "--cgroup-manager", "--criu", "--rootless"}}
STARTS_A_CONTAINER = {{"create", "run", "restore"}}
COMMANDS = STARTS_A_CONTAINER | {{"exec", "start", "state", "kill", "delete", "pause", "resume", "update",
                                  "features", "checkpoint", "list", "ps", "spec", "events"}}


def subcommand(args):
    """(index, name) of the subcommand: the first argument that is neither an option nor its value."""
    i = 0
    while i < len(args):
        arg = args[i]
        if not arg.startswith("-"):
            return i, arg
        i += 2 if arg in VALUED else 1
    return None, None


args = sys.argv[1:]
at, command = subcommand(args)
if command is not None and command not in COMMANDS:
    sys.exit(f"silo: unknown runtime command {{command!r}}; refusing to run it unconfined")
rest = args[at + 1:] if at is not None else []
if command in STARTS_A_CONTAINER:          # the container's first process
    bundle = option(rest, "--bundle", "-b")
    if bundle is None:
        sys.exit("silo: no --bundle in the runtime's arguments; refusing to start an unconfined container")
    rewrite(os.path.join(bundle, "config.json"), lambda spec: spec["process"].__setitem__("apparmorProfile", PROFILE))
elif command == "exec":                    # a process added later (podman exec)
    process = option(rest, "--process", "-p")
    if process is None:
        sys.exit("silo: no --process in the runtime's arguments; refusing to start an unconfined process")
    rewrite(process, lambda spec: spec.__setitem__("apparmorProfile", PROFILE))
os.execv(RUNTIME, [RUNTIME, *args])
'''


def enabled() -> bool:
    """Whether the kernel has AppArmor switched on."""
    try:
        return ENABLED.read_text().strip() == "Y"
    except OSError:
        return False


def profile_loaded(name: str = PROFILE) -> bool:
    """Whether a profile of that name is loaded. Needs no privilege.

    A child process asks the kernel to switch to the profile at its next exec, and never execs.
    The kernel refuses with ENOENT if there is no such profile. (The list of loaded profiles itself
    can only be read by root.)
    """
    if not enabled():
        return False
    pid = os.fork()
    if pid == 0:
        status = 1
        try:
            fd = os.open("/proc/self/attr/apparmor/exec", os.O_WRONLY)
            os.write(fd, f"exec {name}".encode())
            status = 0
        except OSError:
            pass
        os._exit(status)
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status) == 0


def wrapper_source(runtime: str, profile: str = PROFILE) -> str:
    return WRAPPER.format(python=sys.executable, runtime=runtime, profile=profile)


def install_wrapper(directory: Path, runtime: str, profile: str = PROFILE) -> Path:
    """Write the wrapper for `runtime` and return its path.

    It lives in silo's state directory, not in a per-run one: Podman records the runtime a container
    was created with and calls it again to stop and remove that container.
    """
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    path = directory / "silo-oci-runtime"
    source = wrapper_source(runtime, profile)
    try:
        if path.read_text() == source and path.stat().st_mode & 0o777 == 0o700:
            return path
    except OSError:
        pass
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o700)
    with os.fdopen(fd, "w") as fh:
        fh.write(source)
    os.chmod(tmp, 0o700)
    tmp.replace(path)
    return path
