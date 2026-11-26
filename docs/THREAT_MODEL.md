# Threat model

## Assumption

The model is adversarial and the runtime will be compromised.

silo does not try to decide whether a set of weights is safe. It assumes the worst case that
weights, a chat template or a crafted model file can produce: arbitrary native code running as the
runtime's user inside the container, with a goal of its own. Every control is designed to hold in
that situation. A misbehaving but uncompromised runtime is the easy case.

The container image is in the same position. llama-server and everything shipped with it run
inside the sandbox, so a bad image is contained the same way a bad model is.

## What has to hold

1. **No egress.** Nothing leaves the machine at the model's initiative: no packets, no DNS, no
   connections to local services.
2. **No reach into the host.** No access to the user's files, credentials, processes, IPC sockets
   or other containers.
3. **No persistence.** Nothing the model does survives `silo down`.
4. **One audited channel.** Everything the model emits passes through the gateway, which records
   what it delivered.

## Trusted computing base

What has to be correct for the above to hold:

- the host kernel (namespaces, seccomp, cgroups, SELinux enforcement);
- Podman, crun and conmon, and the SELinux container policy;
- silo's launcher, connector, exec supervisor and gateway: about 2,100 lines of Python (`sandbox.py`,
  `seccomp.py`, `runtime.py`, `connector.py`, `execlock.py`, `gateway.py`), standard library only;
- the base seccomp profile shipped by the distribution, which silo tightens but does not replace;
- with `runtime.runsc`: gVisor (`runsc`, its sentry and its gofer), which then stands where the host
  kernel's system call interface stood, and without SELinux around it;
- `silo.toml`, which chooses the image, the model directory and the seccomp base. It is read only
  from an explicit path or the user's configuration directory, never from the current directory,
  and silo prints which file it used whenever it launches something.

Not trusted: the model files, the container image, everything the runtime says on its socket,
and clients of the gateway.

## Routes out, and what stands in each

### Network

| Layer | Control | Verified by |
|---|---|---|
| Namespace | `--network=none`: private loopback only, no routes, no resolver, no hosts file | `net.interfaces`, `net.routes`, `net.dns`, `net.tcp_egress` |
| Syscall filter | `socket()` and `socketpair()` allowed for `AF_UNIX` only. Probed: INET, INET6, raw INET, NETLINK, PACKET, VSOCK, ALG, XDP, Bluetooth, CAN, TIPC, RDS | `net.socket.*`, `net.socketpair.*` |
| Filter bypasses | io_uring (performs socket operations without the filtered syscalls), `socketcall`, and the i386 and x32 ABIs are denied; the profile lists the native architecture only | `sys.io_uring_setup`, `abi.*` |
| Host IPC | Abstract UNIX sockets are scoped to the network namespace; no host socket paths are mounted | `net.abstract_unix`, `host.sockets` |
| Host firewall (optional, root) | nftables drops everything the sandbox's host UID originates; `--sealed` stops the whole machine from sending anything but SSH replies | applied as root on test machines, see `docs/VPS.md`; `silo doctor --sealed` |

The first two layers are independent: a process that somehow obtained a network namespace with
interfaces still could not create an IP socket, and one that somehow bypassed the filter would
have no interface to use.

### Kernel

The sandbox shares the host kernel, so the syscall surface is the attack surface. silo starts from
the distribution's container profile and removes what a hostile workload must not have and an
inference server does not need. `silo seccomp` lists the difference; `seccomp.py` gives a reason
for each entry.

- **Namespaces and mounts:** `unshare`, `setns`, `clone` with any namespace flag, `clone3`
  (forced to `ENOSYS` because its flags sit behind a pointer seccomp cannot read; libc falls back to
  `clone`), the old and new mount APIs, `pivot_root`, `chroot`. A nested user namespace would hand
  the process a full capability set over new namespaces and with it netfilter, mounts and more.
- **Interfaces with a long exploit history:** `bpf`, `perf_event_open`, `userfaultfd`, keyrings,
  `ptrace`, `process_vm_readv/writev`, `pidfd_getfd`, `kcmp`, file-handle calls, `fanotify_init`.
- **Exploitation primitives:** SysV and POSIX message queues, `splice`/`vmsplice`/`tee`, legacy
  AIO, `remap_file_pages`. Legitimate elsewhere, useless to llama-server, and the standard tools for
  turning a kernel bug into a working exploit.
- **Argument allowlists (CPU-only sandboxes):** `ioctl`, `prctl` and `setsockopt` are allowed only
  with the values an inference server uses, measured by tracing llama-server through startup,
  model loading, buffered and streamed completions, tool calls, embeddings and concurrent requests,
  plus the two `prctl` operations crun performs while dropping capabilities and a few read-only or
  self-directed ones. Everything else is denied: driver-specific ioctls, `PR_SET_MM`, `PR_SET_VMA`,
  syscall user dispatch, and classic BPF socket filters (`SO_ATTACH_FILTER`), which would otherwise
  reach the BPF interpreter without `bpf()`. Each allowlist is written as allow rules for the exact
  values plus deny rules that cover every other 64-bit value, and a unit test checks that the two
  never overlap and leave nothing out. Verified by `args.*`. GPU drivers issue device ioctls that
  cannot be listed in advance, so with GPU passthrough the stock rules for these three apply.
- **The TTY layer:** `/dev/pts` is masked, so no pty can be allocated; line-discipline autoloading
  and `TIOCSTI` have nothing to act on.
- **Kernel layout:** `/proc/kallsyms`, `/proc/modules`, `/proc/cmdline`, `/sys/module` and
  `/sys/kernel` are masked in addition to Podman's defaults.

One libseccomp behaviour shapes the profile: an unconditional rule for a syscall silently overrides
any argument-filtered rule for the same syscall. `socket`, `socketpair` and `clone` are therefore
removed from the base profile entirely and re-added with conditions that are disjoint and
exhaustive, and a unit test asserts no unconditional rule for them survives.

### Privilege

Rootless Podman, so root inside the container maps to the invoking user and not to host root. The
runtime does not run as that root either: it runs as UID 65534, which maps to a subordinate UID
that owns nothing on the host. All capabilities are dropped, the bounding set is empty,
`no-new-privileges` is set, and SELinux confines the process as `container_t` with categories
unique to the container. Verified by `proc.uid`, `proc.capabilities`, `proc.no_new_privs`,
`proc.seccomp`, `proc.lsm`.

### Filesystem and persistence

Read-only root filesystem; image volumes ignored; model directory mounted read-only, `noexec`,
`nosuid`, `nodev`. The one writable location is a 64 MB `noexec` tmpfs at `/tmp`. On CPU-only
sandboxes `memfd_create` is denied, which closes the usual fileless-exec path. The environment is
emptied. Verified by `fs.*`, `proc.environment`, `host.secrets`.

`noexec` raises the cost of running a dropped binary; it does not stop code execution inside an
already compromised process, which can still map executable memory.

### Running other programs

The runtime image is not empty. llama.cpp's ships a shell, `curl` and a Python interpreter, and a
runtime that has been taken over could run any of them, or something it carried in. `noexec` only
covers the one place a new file could be written.

Once the runtime has started, nothing else can be executed. A seccomp filter cannot express that
by itself: it is fixed before the container's entrypoint is executed, and would have to count. So
silo's profile hands `execve` and `execveat` to a supervisor on the host (`silo/execlock.py`)
through seccomp's user notification: the kernel suspends the caller and asks. The container
runtime passes the supervisor the notification descriptor together with the PID of the
container's first process, and the supervisor:

- lets exactly one call continue: the first, and only if that process makes it. That is the
  runtime executing the image's entrypoint, before any code from the image has run;
- refuses every later one with `EPERM`, or with `seccomp_action = "kill"` kills the process that
  made it, as a seccomp kill would;
- writes each refusal to the audit log (`"event": "exec_refused"`).

The decision depends only on which call it is, never on its arguments, so the known weakness of
continuing a notified system call (the caller can change the arguments after they were looked at)
has nothing to act on. If the supervisor dies, the kernel answers every `execve` with `ENOSYS`: the
lock fails closed. The supervisor runs as an unprivileged UID of the user namespace with no
capabilities, or with `CAP_KILL` alone in kill mode. Once it holds the descriptor it removes its
socket, so `podman exec` into the sandbox is refused by the container runtime as well.

What it does not do: code already running inside the runtime can still do whatever the runtime
could, in its own process. The lock takes away the tools around it, and in kill mode turns the
most common second step of an exploit, starting a shell, into the runtime's death.

Verified by `proc.exec_locked`, and by a unit test that runs the supervisor against a real
notification descriptor. It is on by default; `runtime.exec_lock = false` is for an image whose
entrypoint is a wrapper that starts the real server, which needs a second `execve`. On GPU
sandboxes, where `memfd_create` has to stay allowed, the lock is also what stops fileless
execution (`fs.memfd_exec`). It is not available on gVisor, which has no user notification.

### The runtime's socket

The gateway has to reach the runtime, but no host directory is shared with the sandbox for it.
llama-server listens on an abstract UNIX socket. Abstract sockets belong to a network namespace,
not to the filesystem, so this one exists only inside the sandbox's `--network=none` namespace:
no host process can see it, and the sandbox gets nothing on the host to write to.

To reach it, silo starts a connector (`silo/connector.py`, about 170 lines, standard library) under
`podman unshare`, as root of the rootless user namespace that owns the container's namespaces. It
binds a control socket (0600, in the 0700 runtime directory in `$XDG_RUNTIME_DIR`), joins the
container's network namespace after checking it is not its own, and drops to an unprivileged UID of
the user namespace, which leaves it with no capabilities. From then on it only does this, on
request: connect to the runtime's abstract socket and pass the connected socket to the gateway over
the control socket. It never reads what the runtime sends, and it exits when the container's
process does. The gateway checks that the control socket is a socket owned by the user (`lstat`, so
not a symlink) and, on every connection, that the peer is the sandbox's host UID (`SO_PEERCRED`).
Verified by `fs.no_shared_dir`; the connector's state is shown by `silo status`.

### Model files

`silo intake` accepts GGUF and safetensors plus tokenizer/config data, checks magic bytes rather
than trusting extensions, and rejects pickles, zip archives, code, executables, symlinks and
anything unknown, hidden directories included. It records size, mtime and SHA-256 per file in a
manifest outside the model directory; `silo up` refuses to start if the directory no longer
matches.

GGUF headers are parsed in full before the runtime sees them (`silo/gguf.py`): every count, length
and string is bounded by the file, keys and tensor names must be unique, arrays cannot nest,
`general.alignment` must be a power of two, tensors have one to four dimensions whose product fits
in int64 and a type from ggml's table, and each tensor's data must be aligned, lie inside the file
and not overlap another. Crafted files aimed at a loader are usually malformed in exactly these
places. Unknown tensor types are refused unless `silo intake --allow-unknown` is given.

This is a format gate and an integrity record. It does not prove a GGUF is benign: a well-formed
file can still carry a hostile chat template or trigger a parser bug the check does not foresee.
`silo intake` shows the size of each file's chat template so that it can be reviewed. That is what the sandbox is
for. The default launch check compares size and mtime; `silo up --full-verify` rehashes.

### The gateway

Described in the README. The properties that matter here:

- It never connects anywhere except the UNIX socket, and never interprets model output as a URL,
  path or command. There is nothing in it for the model to redirect.
- Requests and responses are re-serialised from the parsed form, so the scanner, the audit hash and
  the recipient all see the same bytes.
- It decides the response content type, so the runtime cannot make a browser render anything.
- Text from a sandbox, a model file or a model directory is escaped before silo prints it, so
  GGUF metadata, file names and runtime logs cannot drive the operator's terminal.

### On gVisor (optional)

With `runtime.runsc` the same sandbox is started on gVisor's user-space kernel
(`docs/GVISOR.md`). What changes in the routes above:

- **Kernel.** The runtime's system calls are served by gVisor's sentry. The host kernel sees only
  the sentry's own calls, behind gVisor's seccomp filter. silo's seccomp profile is still applied
  to the runtime, by gVisor.
- **Privilege.** silo turns gVisor's `directfs` off, so the sentry runs as the sandbox's
  subordinate UID with no capabilities and an empty bounding set, in a user namespace that maps
  that one UID, and reaches files only through the gofer. The gofer runs as the invoking user in a
  user namespace, with a seccomp filter; the container's root and the model directory are mounted
  read-only for it.
- **SELinux** does not confine the sandbox: `runsc` refuses SELinux labels, and its processes run
  in the container runtime's domain.
- **The runtime's socket.** An abstract socket would stay inside gVisor's kernel, so one host
  directory is shared for the socket. silo locks it (owned by the user, writable by nobody else)
  as soon as the socket appears, fails the launch if anything else is in it, and the gateway checks
  the lock, the socket and the listener's UID on every connection.
- **Running other programs.** The exec lock is not available: gVisor's seccomp has no user
  notification and refuses a profile that asks for it. Programs in the image can be executed
  inside the sandbox, on gVisor's kernel.
- **Resources.** Rootless `runsc` cannot set up cgroups. silo starts Podman inside a systemd user
  scope that carries the memory, swap, task and CPU limits for the whole gVisor sandbox, and
  refuses to start without one.

Verified by the same probes, with `kernel.gvisor`, `fs.socket_dir_locked` and `fs.no_shared_dir`
(the socket directory must be the only writable host mount) in addition.

## Residual risk

Stated plainly, in rough order of importance.

1. **Kernel vulnerabilities.** About 320 syscalls remain reachable, among them `mmap`, `execve`, the
   socket calls for `AF_UNIX`, and the allowlisted values of `ioctl`, `prctl` and `setsockopt`.
   With GPU passthrough those three are not argument-filtered at all. A bug behind any of them is a way out, and
   SELinux and the user namespace are then the only things left. Use `seccomp_action = "kill"` so a
   probing exploit dies on its first denied call, keep the kernel patched, and apply the host
   sysctls. The real fix is a second boundary around the kernel. silo offers three: gVisor's
   user-space kernel in place of the host's (`docs/GVISOR.md`), a local VM with no network device
   (`docs/LOCAL_VM.md`), and a dedicated server that holds nothing and cannot start a connection
   (`docs/VPS.md`). Without one of them, the host kernel is the only thing between a compromised
   runtime and your account.
2. **The person reading the output.** A contained model can still write "run this". The tripwire
   recognises common shapes and can be evaded by any model capable enough to matter. Treat output
   as untrusted input, especially commands.
3. **The client.** A chat UI that renders markdown will fetch a remote image by itself, with data
   in the URL. An agent harness will execute tool calls. Both act with the client's network access,
   not the model's. Tool calling is off by default for this reason; if you turn it on, whatever
   executes the calls is the boundary and needs its own sandbox. `gateway.tools` limits which tools
   can be offered and the model can only call what was offered, but the gateway does not judge a
   call's arguments beyond size and the output tripwire.
4. **Local processes.** The gateway listens on loopback, which every process and user on the
   machine can reach. Set `api_key_env` if that matters. The model socket itself is reachable only
   by your user.
5. **GPU passthrough.** A GPU driver is a large, privileged kernel interface handed to the
   sandbox, and `memfd_create` stays allowed for it. With `dri` or `amd`, only the render nodes
   are passed: the display nodes (`/dev/dri/card*`), which carry modesetting, never are. Verified
   on an Intel Iris Xe GPU with llama.cpp's Vulkan image in kill mode: the Vulkan driver needed no
   syscall silo denies. NVIDIA and AMD are not verified. For a model you do not trust, use the CPU.
6. **Covert channels.** Timing, CPU load and memory pressure can carry bits to a cooperating
   process outside. Containers do not address this and neither does silo.
7. **Information visible inside.** Kernel version, CPU details, memory size and the host path of
   the model directory (through the mount table) are readable in the sandbox.
8. **Denial of service.** The sandbox can use all the CPU it is given and all of its memory cap.
9. **Hosts without SELinux.** On Ubuntu, rootless Podman applies no SELinux or AppArmor policy, so
   the sandbox process is not confined by any mandatory access control. Everything else is in
   place there, but the layer that limits what a process can touch once it is past the others is
   missing. `silo doctor` fails such a host and `silo probe` reports it.
10. **Streaming in monitor mode.** Findings in a live stream are logged after the text has been
    delivered. Only `enforce` withholds.
11. **gVisor sandboxes.** They exchange one layer for another. SELinux does not confine them and
    the exec lock is not available. The socket directory is shared, and writable from inside from container start until the runtime
    has bound its socket: a model file that took over the runtime that early could put files there,
    which fails the launch but could fill the runtime directory for a moment. And gVisor's own
    kernel, with its bugs, is now in the path.

## Not goals

- Judging or changing what a model wants to do. silo is containment, not alignment.
- Content moderation. The scanner looks for escape and exfiltration attempts, not harmful topics.
- Protecting the model or its weights from the user.
- Multi-tenant isolation between mutually distrusting users of one gateway.

## Roadmap

- Mandatory access control for the sandbox on AppArmor hosts.
- Verification on NVIDIA and AMD GPUs.
