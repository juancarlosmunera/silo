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
- silo's launcher and gateway: about 1,400 lines of Python (`sandbox.py`, `seccomp.py`, `runtime.py`,
  `gateway.py`), standard library only;
- the base seccomp profile shipped by the distribution, which silo tightens but does not replace;
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

### The socket directory

The runtime has to create a UNIX socket that the gateway can reach, so one host directory is
shared with the sandbox. It sits inside a 0700 directory in `$XDG_RUNTIME_DIR` and starts out
writable for the sandbox UID. A watcher thread, started before the container, makes it read-only
for that UID as soon as anything appears in it, and then checks that it holds exactly one entry, a
socket (by `lstat`, so a symlink to some other host socket is refused). Anything else aborts the
launch. silo does not connect to the socket before that check has passed, and the gateway repeats
the `lstat` check on every connection. Verified by `fs.socket_dir_locked`.

The lock cannot land before model loading: llama-server binds and goes straight on to read the
model file. Measured from inode timestamps on the development machine it lands about a millisecond
after the bind, which is the resolution of those timestamps. See the startup window under residual
risk.

### Model files

`silo intake` accepts GGUF and safetensors plus tokenizer/config data, checks magic bytes rather
than trusting extensions, and rejects pickles, zip archives, code, executables, symlinks and
anything unknown, hidden directories included. It records size, mtime and SHA-256 per file in a
manifest outside the model directory; `silo up` refuses to start if the directory no longer
matches.

This is a format gate and an integrity record. It does not prove a GGUF is benign: a well-formed
file can still carry a hostile chat template or trigger a parser bug. That is what the sandbox is
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

## Residual risk

Stated plainly, in rough order of importance.

1. **Kernel vulnerabilities.** About 320 syscalls remain reachable, among them `ioctl`, `prctl`,
   `mmap`, `execve` and the socket calls for `AF_UNIX`. A bug behind any of them is a way out, and
   SELinux and the user namespace are then the only things left. Use `seccomp_action = "kill"` so a
   probing exploit dies on its first denied call, keep the kernel patched, and apply the host
   sysctls. The real fix is a second boundary around the kernel. silo offers two, both outside the
   sandbox itself: a local VM with no network device (`docs/LOCAL_VM.md`), and a dedicated server
   that holds nothing and cannot start a connection (`docs/VPS.md`). Without one of them, the
   host kernel is the only thing between a compromised runtime and your account.
2. **The person reading the output.** A contained model can still write "run this". The tripwire
   recognises common shapes and can be evaded by any model capable enough to matter. Treat output
   as untrusted input, especially commands.
3. **The client.** A chat UI that renders markdown will fetch a remote image by itself, with data
   in the URL. An agent harness will execute tool calls. Both act with the client's network access,
   not the model's. Tool calling is off by default for this reason; if you turn it on, whatever
   executes the calls is the boundary and needs its own sandbox.
4. **Local processes.** The gateway listens on loopback, which every process and user on the
   machine can reach. Set `api_key_env` if that matters. The model socket itself is reachable only
   by your user.
5. **GPU passthrough.** A GPU driver is a large, privileged kernel interface handed to the
   sandbox, and `memfd_create` stays allowed for it. The code path exists and has not been run on
   real hardware. For a model you do not trust, use the CPU.
6. **Covert channels.** Timing, CPU load and memory pressure can carry bits to a cooperating
   process outside. Containers do not address this and neither does silo.
7. **Information visible inside.** Kernel version, CPU details, memory size and the host path of
   the model directory (through the mount table) are readable in the sandbox.
8. **Denial of service.** The sandbox can use all the CPU it is given and all of its memory cap.
9. **Hosts without SELinux.** On Ubuntu, rootless Podman applies no SELinux or AppArmor policy, so
   the sandbox process is not confined by any mandatory access control. Everything else is in
   place there, but the layer that limits what a process can touch once it is past the others is
   missing. `silo doctor` fails such a host and `silo probe` reports it.
10. **The startup window.** From container start until about a millisecond after the socket is
   bound, the socket directory is writable by the sandbox UID. Model loading begins right after the
   bind, so its first instants fall inside that window. A model file that exploits the loader that
   quickly could write there: what it leaves behind fails the launch, but a brief fill of the
   runtime tmpfs is possible. The fix is not to share a directory at all.
11. **Streaming in monitor mode.** Findings in a live stream are logged after the text has been
    delivered. Only `enforce` withholds.

## Not goals

- Judging or changing what a model wants to do. silo is containment, not alignment.
- Content moderation. The scanner looks for escape and exfiltration attempts, not harmful topics.
- Protecting the model or its weights from the user.
- Multi-tenant isolation between mutually distrusting users of one gateway.

## Roadmap

- gVisor (`runsc`) as the sandbox runtime: a second kernel boundary without a whole VM.
- Mandatory access control for the sandbox on AppArmor hosts.
- Handing the runtime's socket to the gateway without a shared host directory.
- Argument-level allowlists for `ioctl`, `setsockopt` and `prctl`.
- Locking down `execve` after the runtime has started.
- An origin allowlist with proper CORS handling, for browser-based clients.
- Tool-call mediation: per-tool policy instead of all-or-nothing.
- Structural validation of GGUF files at intake.
- The probe suite as a CI gate, and verification on GPU hardware and aarch64.
