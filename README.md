# silo

Run a local LLM as if it were hostile.

silo puts the model runtime in a container that has no network, no capabilities, nowhere to write
anything executable and a syscall filter built for an adversarial workload. It leaves the runtime
exactly one way to talk: a UNIX socket to a small gateway on the host, which parses, checks and
logs everything that passes in either direction.

```
 client ──HTTP, loopback──▶ silo gateway ──UNIX socket──▶ llama-server
 you, your tools            your user, on the host        rootless container: no network, no caps,
                            allowlist · scan · audit      read-only, seccomp, SELinux
```

The model cannot open a connection, resolve a name, read your files or start anything on the host.
What it can still do is answer, so the answer is the channel that remains, and the gateway exists
to narrow and record it.

**Status: 0.1, early.** Developed and verified on Fedora 43 (kernel 7.2, SELinux enforcing) with
rootless Podman 5.8 and crun, x86_64, CPU inference, using the llama.cpp server image. Not yet
verified: GPU passthrough, aarch64, hosts without SELinux. Python 3.11+, standard library only.

## What stops what

| Way out | Control |
|---|---|
| **Network** | `--network=none`: a private loopback, no routes, no resolver. Independently, seccomp allows `socket()` and `socketpair()` for `AF_UNIX` only and denies the ways around that filter: io_uring, `socketcall`, and the 32-bit and x32 syscall ABIs. Optionally, a host firewall rule drops everything the sandbox UID originates ([host/](host/README.md)). |
| **Kernel attack surface** | The distro seccomp profile, tightened: no new namespaces (`unshare`, `setns`, `clone` namespace flags, `clone3`), no mount API, bpf, perf, userfaultfd, keyrings, ptrace, `process_vm_*`, file handles, SysV/POSIX message queues, splice family, legacy AIO. No pty can be allocated. Kernel symbol, module and boot-parameter files are masked. |
| **Privilege** | Rootless Podman, so container root is not host root. The runtime runs as `nobody`, mapped to a subordinate UID that owns nothing on the host. Every capability dropped, bounding set included. `no-new-privileges`. SELinux `container_t` with per-container categories. |
| **Filesystem, persistence** | Read-only root. Model directory mounted read-only. The only writable location is a 64 MB `noexec` tmpfs. No `memfd_create` on CPU-only sandboxes, so no fileless exec either. Environment stripped. No Podman, D-Bus, display, audio or agent sockets visible. |
| **The shared socket directory** | The one host directory the sandbox can touch is locked within about a millisecond of the runtime binding its socket. From then on the sandbox cannot fill it and cannot swap the socket for a symlink to another host socket, and anything found in it besides that socket fails the launch. |
| **Resources** | Memory cap with no swap, PID cap, file-descriptor cap, size-capped log. |
| **Model files** | `silo intake`: format allowlist (GGUF, safetensors), magic-byte checks, no pickles, code or symlinks, and a SHA-256 manifest kept outside the model directory and checked before every launch. |
| **The runtime's own features** | llama-server flags that add listeners, downloads, tools, agents, MCP or remote backends are refused; web UI, slots and the MCP proxy are switched off; images are never pulled at launch. |
| **The output** | The gateway, below. |

## Check it yourself

Nothing above is taken on trust. `silo probe` starts a sandbox with exactly the flags the model
gets and runs 66 probes inside it: reach the network through a dozen socket types,
create namespaces, call the kernel interfaces listed above, find a writable-and-executable
location, find host sockets and credentials, plus checks of the process's own privileges and limits. `silo probe --baseline` runs the same attempts in a
stock rootless Podman container.

| | stock rootless Podman | silo |
|---|---|---|
| contained (PASS) | 26 | 66 |
| not contained (FAIL) | 31 | 0 |
| weaker than intended (WARN) | 7 | 0 |

(On the development machine. Two probes are skipped in the baseline because it has no model or
socket mounts.) The stock container resolved DNS, opened a TCP connection to the internet, created
a user namespace and executed a file it had just written. Stock Podman is a good default for
software you trust; it is not built for software you assume is trying to leave.

With `seccomp_action = "kill"` every denied syscall in the probe output shows up as
`process killed by seccomp (SIGSYS)`, which is how you confirm the filter itself is what stops it,
not a capability check further in.

## Quick start

Needs Podman (rootless) and Python 3.11+.

```sh
pip install .                               # or run in place: PYTHONPATH=src python3 -m silo ...
cp examples/silo.example.toml silo.toml     # set [model] dir and file
silo doctor                                 # host and configuration posture
silo pull                                   # pull both images; prints digests to pin in silo.toml
silo intake                                 # vet the model directory, write its manifest
silo probe                                  # escape probes in an identical sandbox
silo up                                     # sandbox + gateway; Ctrl-C stops both
```

```sh
curl -s http://127.0.0.1:8088/v1/chat/completions -H 'Content-Type: application/json' \
  -d '{"messages":[{"role":"user","content":"hello"}]}'
```

Point an OpenAI-compatible client at `http://127.0.0.1:8088/v1`. Browser-based clients are refused
(any request carrying an `Origin` header is).

Use a directory that contains only model files: it is bind-mounted and relabelled for SELinux
(`container_file_t`), and intake rejects anything in it that is not a vetted format.

Other commands: `status`, `logs` (control characters escaped), `down`, `verify [--full]`,
`seccomp` (show what was removed from the stock profile), `nft` (print the host firewall rule),
`up --detach` plus `gateway` to run the two halves separately.

## The gateway

The gateway treats both sides as untrusted and terminates the protocol instead of piping bytes.

- **Five routes**, matched verbatim: `/health`, `/v1/models`, `/v1/chat/completions`,
  `/v1/completions`, `/v1/embeddings`. No admin, slots, props, metrics or web UI.
- **JSON in, JSON out.** Every body is parsed strictly and re-serialised, in both directions, so
  what was inspected is byte for byte what is forwarded. No client header reaches the model and no
  model header reaches the client.
- **Nothing renderable.** The gateway sets the response type itself (JSON or an event stream) and
  sends `nosniff` and a deny-all CSP, so a compromised runtime cannot serve a page to a browser that
  opens the gateway URL.
- **No drive-by access.** Requests with an `Origin` header, a non-loopback `Host` (DNS rebinding)
  or a POST that is not `application/json` are refused.
- **Text only by default.** Requests that carry tools or functions are refused, and tool calls from
  the model are cut off, unless `allow_tools = true`.
- **Output tripwire.** Completions are scanned for the usual ways text borrows someone else's
  network or hands: pipe-to-shell, reverse shells, remote images that a markdown renderer would
  fetch on its own, raw terminal escape sequences, sandbox-weakening flags, hidden Unicode,
  credential paths. `monitor` logs and alerts. `enforce` withholds high-severity completions, and
  holds streams until they finish clean so a blocked one is never partly delivered.
- **Limits.** Size caps both ways, one total deadline per request, bounded concurrency.
- **Audit log.** One JSON line per request in `~/.local/state/silo/audit/`, mode 0600: hashes of
  what was sent and delivered, findings, tool-call names. Prompts and completions are recorded only
  with `log_content = true`.

## What silo does not do

Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before relying on it. The short version:

- **The kernel is shared.** A kernel vulnerability reachable through the roughly 320 syscalls still
  allowed is the main way out. silo shrinks that surface; it does not remove it. A user-space
  kernel or microVM backend is the planned answer.
- **The answer still reaches you.** A model with no network can ask you to run something. The
  tripwire catches obvious shapes and is a regex, not a boundary.
- **Your client is outside the silo.** If it renders HTML, fetches images or executes tool calls,
  that is where containment now has to hold.
- **Loopback is shared.** Any process on the machine can talk to the gateway unless you set an API
  key.
- **GPU passthrough** exposes a large driver to the sandbox and is unverified.
- **Covert channels** (timing, load) are out of scope.

## Development

```sh
PYTHONPATH=src python3 -m unittest discover -s tests   # no network, no Podman needed
```

```
src/silo/sandbox.py     the podman flags, and the check that refuses to launch without them
src/silo/seccomp.py     profile hardening, with the reason for every denied syscall
src/silo/gateway.py     the host-side proxy
src/silo/scanner.py     output tripwire rules
src/silo/intake.py      model-directory vetting and manifest
src/silo/runtime.py     lifecycle: launch, socket-directory lock, probes
src/silo/probes/        the escape-probe suite that runs inside the sandbox
src/silo/doctor.py      host and configuration checks
src/silo/hostrules.py   host firewall rule generation
host/                   optional root-level hardening: firewall rule, sysctls
```
