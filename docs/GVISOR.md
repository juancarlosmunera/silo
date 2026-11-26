# A second kernel without a VM: gVisor

silo's sandbox shares your machine's kernel. That is its main limit: a kernel vulnerability
reachable from inside the sandbox is a way out.

[gVisor](https://gvisor.dev) puts a second kernel in between without a virtual machine. Its
`runsc` runtime starts the container on a kernel written in Go that runs as an ordinary process,
the *sentry*. The model's runtime makes its system calls to the sentry, not to Linux. With
`runtime.runsc` set, silo starts its sandbox that way.

```
 client ─▶ gateway ─▶ socket in a locked directory ─▶ gVisor ─▶ llama-server
 you, your tools      your user, on the host         sentry: the kernel the runtime sees
                                                      gofer:  the only path to files
```

## What you get, and what it costs

- The kernel the runtime can attack is gVisor's. The host kernel only sees the small set of
  system calls the sentry itself is allowed, behind gVisor's own seccomp filter.
- silo's controls still apply inside: no network, read-only root, `noexec` scratch space, no
  capabilities, and silo's seccomp profile, which gVisor enforces on the runtime. The escape
  probes pass there, and in kill mode denied calls still read `SIGSYS`.
- silo starts gVisor so that the sentry, the process a break-out from the runtime would land in,
  is as unprivileged as silo's ordinary sandbox: a subordinate UID that owns nothing on the host,
  with no capabilities.

The cost:

- **SELinux does not confine the sandbox.** `runsc` refuses SELinux labels, so its processes run
  in the container runtime's own domain instead of `container_t`. You trade one layer for
  another. On a host without SELinux, such as Ubuntu, nothing is lost.
- **One directory is shared with the sandbox again**, for the runtime's socket. See
  [The socket](#the-socket).
- **No exec lock.** Refusing every `execve` after the runtime's own needs seccomp's user
  notification, which gVisor does not have (it rejects such a profile). A compromised runtime can
  run the programs in its image, inside gVisor.
- **Speed.** About 20% slower here, or 8% on gVisor's KVM platform. See [Speed](#speed).
- **No GPU.** silo refuses `runtime.gpu` together with `runtime.runsc`.
- **gVisor joins what has to be correct**, and what you keep up to date.

## What this was tested on

Fedora 43 (kernel 7.3), rootless Podman 5.8.9, gVisor `release-20261123.1`, x86_64, llama.cpp's
server image (build b12242), Qwen2.5-0.5B-Instruct. Not tried: aarch64, Ubuntu, a host that is
itself a virtual machine, and an installation in `/usr/local/bin` (the test machine had no root
access, so gVisor was unpacked into a directory owned by the user and readable by everyone).

## 1. Install gVisor

gVisor is not in Fedora's repositories. Its own instructions are a download and a checksum:

```sh
(
  set -e
  ARCH=$(uname -m)
  URL=https://storage.googleapis.com/gvisor/releases/release/latest/${ARCH}
  curl -fsSLO ${URL}/gvisor.tar.zstd
  curl -fsSLO ${URL}/gvisor.tar.zstd.sha512
  sha512sum -c gvisor.tar.zstd.sha512                    # must say "OK"
  sudo tar --zstd -xf gvisor.tar.zstd -C /usr/local/bin
)
/usr/local/bin/runsc --version
```

The archive holds `runsc` and a `gvisor-bin/` directory that has to stay next to it.

**Install it outside your home directory.** silo runs gVisor with its `directfs` option off (see
[What silo asks of gVisor](#what-silo-asks-of-gvisor)), and the sentry then runs as the sandbox's
unprivileged UID. That UID has to be able to execute `runsc`, which it cannot do inside a home
directory other users cannot enter. silo checks this and says which directory is in the way. It
also refuses a `runsc` that group or others could replace: whoever can change the runtime controls
the sandbox, which is the reason to prefer a directory owned by root.

## 2. Configure

```toml
[runtime]
runsc = "/usr/local/bin/runsc"
# gvisor_platform = "systrap"     # or "kvm": faster, see Speed
```

Everything else in `silo.toml` stays as it is.

## 3. Verify

```sh
silo doctor
silo probe
```

`silo doctor` now reports gVisor's version, says that the kernel isolation finding is covered, and
warns that SELinux does not confine this sandbox:

```
 ✓ gVisor                    release-20261123.1, platform systrap; its sentry runs as the sandbox's unprivileged UID with no capabilities (directfs off)
 ✓ gVisor resource limits    memory, tasks and CPU are limited by a systemd user scope around the whole gVisor sandbox
 ✓ kernel isolation          gVisor release-20261123.1: the sandbox's system calls are served by gVisor's user-space kernel, ...
 ! SELinux                   enforcing, but it does not confine a gVisor sandbox: ...
```

`silo probe` has to end with `FAIL=0  WARN=0`. Three results are specific to gVisor:

```
 PASS kernel.gvisor          running on gVisor's user-space kernel (4.19.0-gvisor)
 PASS fs.no_shared_dir       the socket directory is the only host directory mounted writable
 PASS fs.socket_dir_locked   shared socket directory is not writable (Permission denied)
```

Three are reported as information: `proc.lsm` (no host LSM reaches the sandbox),
`proc.cgroup_limits` (the limits sit on the host, around gVisor, and cannot be seen from inside)
and `proc.exec_locked` (the exec lock does not exist on gVisor).

## 4. Run it

`silo up`, `silo gateway`, `silo status`, `silo logs` and `silo down` work as before:

```
silo[default] starting silo-default from ghcr.io/ggml-org/llama.cpp:server
silo[default] model healthy on gVisor (systrap), reached through /run/user/1000/silo/default/sock/llama.sock (socket directory locked)
silo[default] gateway on http://127.0.0.1:8088/v1  ->  /run/user/1000/silo/default/sock/llama.sock (gVisor)
```

The systemd unit in `examples/systemd/` needs no change. A service with its settings was started,
used and stopped with gVisor configured; stopping it removed the sandbox.

## What silo asks of gVisor

| | |
|---|---|
| `directfs` off | With gVisor's default, the sentry runs as *your* user, with the capabilities that override file permissions, inside a user namespace that maps your UID and all your subordinate UIDs. With it off, the sentry runs as the sandbox's single subordinate UID, with no capabilities and an empty bounding set, and reaches files only by asking the gofer. silo always turns it off. |
| `network=none` | No network stack beyond loopback inside gVisor, on top of Podman's `--network=none`. |
| `host-uds=create` | The runtime may create its listening socket in the one directory mounted for it. It may not connect to a socket on the host. |
| the platform, by name | `systrap` unless you choose `kvm`, so the sandbox does not change when gVisor's default does. |
| a systemd scope around everything | Rootless `runsc` cannot set up cgroups, so Podman's `--memory`, `--pids-limit` and `--cpus` would do nothing. silo starts Podman inside a systemd user scope that carries `runtime.memory` (with no swap), a task limit and `runtime.cpus`, and refuses to start if `systemd-run` is missing. The limits cover gVisor's own processes too. |
| the thread count | llama.cpp starts one thread per physical core, which it reads from the CPU topology. gVisor does not show the host's topology, so llama.cpp would start one per logical CPU. Unless `model.threads` is set, silo passes the host's physical core count. |

Checked on the running sandbox: the sentry had UID 589821 (the subordinate UID silo's ordinary
sandbox uses), `CapEff` and `CapBnd` zero, a user namespace mapping that one UID, a network
namespace holding only loopback, and a root directory holding nothing but `/etc/localtime`.

## The socket

Without gVisor, the runtime listens on an abstract socket inside its own network namespace and no
directory is shared. That does not work here: an abstract socket created under gVisor exists only
inside gVisor's kernel, where nothing on the host can connect to it.

So with gVisor one host directory is mounted into the sandbox, as in silo 0.1. gVisor creates the
runtime's socket in it, and silo locks the directory as soon as the socket appears: owned by you,
writable by nobody else. gVisor's gofer re-reads the mode from the host, so from then on the
runtime cannot create, rename or delete anything there. This was tested by having a process in
the sandbox create files in a loop while the directory was locked from the host: every attempt
after the lock was refused, and so were deleting and renaming what was already there.

Anything in the directory besides that one socket fails the launch. The gateway checks on every
connection that the directory is still locked, that the path is a socket and not a symlink, and
that the process listening on it is one of yours, which gVisor's gofer is.

What is left is the window before the lock. From container start until the socket is bound, the
directory is writable from inside. A model file that took over the runtime that early could put
files there; they would fail the launch, but could fill the runtime directory for a moment.

## Speed

One machine, four physical cores with hyperthreading, the same model, three completions of 120
tokens each:

| | tokens per second |
|---|---|
| silo's ordinary sandbox | 46 to 47 |
| gVisor, `systrap` | 36 to 38 |
| gVisor, `kvm` | 43 |
| gVisor, `systrap`, eight threads (what llama.cpp would pick by itself there) | 23 to 25 |

`gvisor_platform = "kvm"` runs the workload in a hardware-virtualised guest. It needs a `/dev/kvm`
that the sandbox's UID can open (on the Fedora test machine everyone can), and it hands that device
to the sentry: faster, and one more kernel interface within reach of a compromised sentry. `systrap`
needs nothing and also works where there is no KVM, such as most rented servers.

## Stopping takes two seconds

llama.cpp's server never finishes its own shutdown under gVisor. Its HTTP library stops the accept
loop by calling `shutdown()` on the listening socket. On Linux that wakes the thread blocked in
`accept()`. On gVisor `shutdown()` on a listening UNIX socket fails with `ENOTCONN` and `accept()`
stays blocked, with or without any of silo's flags. The sandbox holds no state, so silo gives the
runtime two seconds and then kills it, where it otherwise waits up to ten.

## What holds when

| If this happens | What still stands |
|---|---|
| A crafted model file or prompt takes over the runtime | Everything in the README, enforced inside gVisor: no network, no capabilities, nowhere to write a binary, silo's seccomp profile. Its system calls go to gVisor, not to your kernel. |
| It breaks out of gVisor's kernel and runs as the sentry | It is an unprivileged UID that owns nothing on the host, with no capabilities, no network interface but loopback, a root directory with nothing in it, and gVisor's seccomp filter around it. It reaches files only through the gofer. SELinux does not confine it. |
| It takes over the gofer as well | It runs as your user, inside a user namespace, with a seccomp filter and no network interface but loopback. Its root is the container's filesystem, mounted read-only like the model directory; the socket directory is the only thing it can write to. From here a host kernel vulnerability is what is left. |
| In every one of these | What the model writes still reaches you through the gateway. The limits on output described in the README apply unchanged. |

gVisor does not replace the VM or the sealed server, which put the model on a kernel that is not
yours and a machine that holds nothing. Using it inside either of them has not been tried.

## Keeping it current

`silo doctor` prints the gVisor version in use. To update, run the installation step again; the
next `silo up` uses the new binary. Run `silo probe` after every update: it tests the gVisor you
have, not the one silo was developed with.
