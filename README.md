# silo

**Containment for local LLMs.** Run a model as if it were hostile: no network, no privileges,
nowhere to go, and one narrow, logged channel for prompts and answers.

[![ci](https://github.com/juancarlosmunera/silo/actions/workflows/ci.yml/badge.svg)](https://github.com/juancarlosmunera/silo/actions/workflows/ci.yml)

When you run open-weight models on your own machine or on a VPS, you load a multi-gigabyte file
from the internet into a runtime that parses it, usually on a box that also holds your SSH keys,
browser sessions or cloud credentials. silo assumes the worst about that file and about the
process that loads it, and builds the box accordingly.

```
 client ──HTTP, loopback──▶ silo gateway ──UNIX socket──▶ llama-server
 you, your tools            your user, on the host        rootless container: no network, no caps,
                            allowlist · scan · audit      read-only, seccomp, SELinux
```

Inside that box the runtime cannot open a connection, resolve a name, read your files or start
anything on the host. What it can still do is answer, so the answer is the one channel left, and
the gateway exists to narrow and record it.

> **Status: 0.1, early.** Verified on Fedora 43 (SELinux enforcing) with rootless Podman 5.6 and
> 5.8, x86_64, CPU inference, running llama.cpp's server. Also exercised on Ubuntu 24.04, where one
> layer is missing ([details](docs/VPS.md#other-distributions)). Not yet verified: GPU passthrough,
> aarch64. silo lowers risk; it is not a guarantee. Read [Limits](#limits) before relying on it.

**Contents:** [Isn't a container enough?](#isnt-a-container-enough) ·
[How it works](#how-it-works) · [Check it yourself](#check-it-yourself) ·
[Requirements](#requirements) · [Install](#install) · [Quick start](#quick-start) ·
[On a VPS](#on-a-vps) · [In a local VM](#in-a-local-vm) · [Commands](#commands) ·
[Configuration](#configuration) ·
[The gateway](#the-gateway) ·
[Tightening it further](#tightening-it-further) · [Limits](#limits) · [Roadmap](#roadmap) ·
[Development](#development) · [Security](#security) · [License](#license)

## Isn't a container enough?

No. A default container has full internet access. In the same test suite that silo passes, a stock
rootless Podman container resolved DNS, opened a TCP connection to the internet, created a user
namespace and executed a file it had just written.

Containment comes from specific controls, matched to the only three ways a model can reach the
network. A model only produces text. For it to reach the net, one of these has to happen:

| | Route | What silo does about it |
|---|---|---|
| 1 | **Someone hands it a tool.** Web fetch, shell or code execution, wired up by an agent framework or a runtime flag. By far the most common way. | Refuses the llama-server flags that enable tools, agents, MCP, remote backends and downloads. The gateway refuses tool calling unless you turn it on. The model can only return text. |
| 2 | **Code runs inside the runtime.** A crafted model file exploits the loader, or a pickle checkpoint executes on load. | Intake rejects pickles, code and anything that is not a vetted format. The runtime has no network device, cannot create an internet socket, cannot create namespaces to get around either, holds no privileges and has nowhere to put a binary. |
| 3 | **Its text gets someone else to do it.** "Run this command", or an image link that your chat UI fetches on its own. | The gateway re-serialises, scans and logs every completion, and can withhold the obvious cases. |

Routes 1 and 2 are closed by construction and checked by a test suite you can run yourself.
Route 3 is narrowed, not closed. Route 2 has one known exception, a kernel exploit, which is the
first item under [Limits](#limits).

## How it works

| Way out | Control |
|---|---|
| **Network** | `--network=none`: a private loopback, no routes, no resolver. Independently, seccomp allows `socket()` and `socketpair()` for `AF_UNIX` only and denies the ways around that filter: io_uring, `socketcall`, and the 32-bit and x32 syscall ABIs. Optionally, a host firewall rule drops everything the sandbox user originates ([host/](host/README.md)). |
| **Kernel attack surface** | The distribution's seccomp profile, tightened: no new namespaces (`unshare`, `setns`, `clone` namespace flags, `clone3`), no mount API, bpf, perf, userfaultfd, keyrings, ptrace, `process_vm_*`, file handles, SysV/POSIX message queues, splice family or legacy AIO. No pty can be allocated. Kernel symbol, module and boot-parameter files are masked. |
| **Privilege** | Rootless Podman, so container root is not host root. The runtime runs as `nobody`, mapped to a subordinate UID that owns nothing on the host. Every capability dropped, bounding set included. `no-new-privileges`. SELinux `container_t` with per-container categories. |
| **Filesystem, persistence** | Read-only root. Model directory mounted read-only. The only writable location is a 64 MB `noexec` tmpfs. No `memfd_create` on CPU-only sandboxes, so no fileless exec either. Environment stripped. No Podman, D-Bus, display, audio or agent sockets visible. |
| **The shared socket directory** | The one host directory the sandbox can touch is locked within about a millisecond of the runtime binding its socket. From then on the sandbox cannot fill it or swap the socket for a symlink to another host socket, and anything found in it besides that socket fails the launch. |
| **Resources** | Memory cap with no swap, PID cap, file-descriptor cap, size-capped log. |
| **Model files** | `silo intake`: format allowlist (GGUF, safetensors), magic-byte checks, no pickles, code or symlinks, and a SHA-256 manifest kept outside the model directory and checked before every launch. |
| **The runtime's own features** | llama-server flags that add listeners, downloads, tools, agents, MCP or remote backends are refused. Web UI, slots and the MCP proxy are switched off. Images are never pulled at launch. |
| **The output** | [The gateway](#the-gateway). |

The reasoning behind each control, and what is left over, is in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Check it yourself

None of the above is taken on trust. `silo probe` starts a sandbox with exactly the flags the model
gets and runs 66 probes inside it: reach the network through a dozen socket types, create
namespaces, call the kernel interfaces listed above, find a location that is both writable and
executable, find host sockets and credentials, and check the process's own privileges and limits.
`silo probe --baseline` runs the same probes in a stock rootless Podman container.

| | stock rootless Podman | silo |
|---|---|---|
| contained (PASS) | 26 | 66 |
| not contained (FAIL) | 31 | 0 |
| weaker than intended (WARN) | 7 | 0 |

These are the numbers from the development machine. Two probes are skipped in the baseline because
it has no model or socket mounts. Stock Podman is a good default for software you trust. It is not
built for software you assume is trying to leave.

With `seccomp_action = "kill"`, every denied syscall in the probe output reads
`process killed by seccomp (SIGSYS)`. That is how you confirm the filter itself is what stops the
call, and not a capability check further in.

Run the probes on every machine you deploy to. They test your kernel, your Podman and your
configuration, not the ones silo was developed on.

## Requirements

- Linux on x86_64 with cgroup v2.
- Podman, running rootless. Verified with 5.8. Docker is not supported.
- SELinux in enforcing mode is strongly recommended, and is what silo is verified with. On Ubuntu
  rootless Podman gets no SELinux or AppArmor confinement at all, so that layer is absent there.
  `silo doctor` reports what your host provides.
- Python 3.11 or newer. silo has no Python dependencies.
- A model in GGUF format and enough RAM to hold it. Inference runs on the CPU.

silo runs llama.cpp's `llama-server`. Other runtimes (Ollama, vLLM, LM Studio), macOS and Windows
are not supported.

## Install

```sh
git clone https://github.com/juancarlosmunera/silo.git
cd silo
python3 -m venv .venv && . .venv/bin/activate
pip install .
silo --version
```

Or skip the install: `bin/silo` runs straight from the checkout, wherever the examples say `silo`.

Do not run silo as `python3 -m silo`. That form puts the current directory first on Python's import
path, so running it from inside a downloaded model directory would execute a `json.py` planted
there. The `silo` command and `bin/silo` do not look in the current directory.

## Quick start

**1. Get a model.** Any GGUF works. This one is 145 MB, small enough to try the whole flow in a
couple of minutes:

```sh
mkdir -p ~/models/smollm2
curl -L -o ~/models/smollm2/SmolLM2-135M-Instruct-Q8_0.gguf \
  https://huggingface.co/bartowski/SmolLM2-135M-Instruct-GGUF/resolve/main/SmolLM2-135M-Instruct-Q8_0.gguf
```

Keep each model in a directory of its own. silo mounts that directory read-only into the sandbox
and relabels it for SELinux (`container_file_t`), and intake rejects anything in it that is not a
vetted format.

**2. Configure.** Copy the example and point it at the model:

```sh
mkdir -p ~/.config/silo
cp examples/silo.example.toml ~/.config/silo/silo.toml
```

```toml
[model]
dir = "~/models/smollm2"
file = "SmolLM2-135M-Instruct-Q8_0.gguf"
```

**3. Check the host, vet the model, test the sandbox.**

```sh
silo doctor     # host and configuration posture, and what could be stricter
silo pull       # pull the two container images; prints how to pin them in silo.toml
silo intake     # vet the model directory and record its SHA-256 manifest
silo probe      # run the escape probes in a sandbox identical to the model's
```

`silo probe` has to end with `FAIL=0`:

```
 PASS net.tcp_egress                 no route out (OSError: [Errno 97] Address family not supported by protocol)
 PASS sys.unshare                    unshare(CLONE_NEWUSER): refused (EPERM)
 PASS fs.writable_noexec             writable locations ['/tmp'] are all noexec
 ...
PASS=66  FAIL=0  WARN=0  SKIP=0
```

**4. Start it.**

```sh
silo up
```

```
silo[default] config: /home/you/.config/silo/silo.toml
silo[default] starting silo-default from ghcr.io/ggml-org/llama.cpp:server
silo[default] model healthy on /run/user/1000/silo/default/llama.sock (socket directory locked)
silo[default] gateway on http://127.0.0.1:8088/v1  ->  /run/user/1000/silo/default/llama.sock
silo[default] scanner=monitor tools=refused audit=/home/you/.local/state/silo/audit/default.jsonl
```

**5. Talk to it.** The gateway speaks the OpenAI API:

```sh
curl -s http://127.0.0.1:8088/v1/chat/completions -H 'Content-Type: application/json' \
  -d '{"messages":[{"role":"user","content":"hello"}]}'
```

```python
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:8088/v1", api_key="unused")
reply = client.chat.completions.create(
    model="local",
    messages=[{"role": "user", "content": "hello"}],
)
print(reply.choices[0].message.content)
```

Streaming works the same way. Browser-based clients are refused: any request that carries an
`Origin` header is.

Ctrl-C stops the gateway and the sandbox and removes the socket directory.

## On a VPS

A machine that exists only to run the model can be given a boundary your workstation cannot have:
it holds nothing, and it can be forbidden from starting any connection at all. Then even a kernel
exploit leaves the attacker on a box that cannot call out.

[docs/VPS.md](docs/VPS.md) is the full walkthrough, tested end to end on a fresh Fedora machine:
a dedicated unprivileged account, images and model pushed over SSH so the server needs no outbound
access, firewall rules that seal the host, a systemd service, and an SSH tunnel to the gateway.
`silo doctor --sealed` then proves from the machine itself that nothing gets out.

## In a local VM

On your own computer the equivalent boundary is a virtual machine. `bin/silo-vm` creates one from
a Fedora Cloud image and runs it with **no network device at all**: the only channel is a VM
socket that carries SSH, opened from your side. silo runs inside it as on a server, and a kernel
exploit inside the sandbox then lands in a guest that has nothing to send packets with and holds
nothing of yours.

```sh
bin/silo-vm create Fedora-Cloud-Base-Generic-43-1.6.x86_64.qcow2
bin/silo-vm update      # first boot only: updates the guest, then powers off
bin/silo-vm start       # from now on: no network device
```

It needs KVM and costs the guest's memory. In a quick test, inference in the VM was as fast as on
the host. [docs/LOCAL_VM.md](docs/LOCAL_VM.md) has the walkthrough, tested from a fresh VM.

## Commands

| Command | What it does |
|---|---|
| `silo doctor [--sealed]` | Checks the host (Podman, SELinux, cgroups, kernel settings) and your configuration, and lists what could be stricter. `--sealed` also proves that the host itself cannot reach the network. |
| `silo pull` | Pulls the runtime and probe images and prints how to pin them. silo never pulls at launch. |
| `silo images` | Shows the local images and how to pin them, without touching the network. |
| `silo intake [--allow-unknown]` | Vets the model directory and writes its manifest. |
| `silo verify [--full]` | Compares the model directory with its manifest. `--full` rehashes every file. |
| `silo probe [--baseline] [-q] [--json]` | Runs the escape probes in a silo sandbox, or in a stock container for comparison. |
| `silo up [--detach] [--full-verify]` | Starts the sandbox and the gateway. `--detach` starts only the sandbox. |
| `silo gateway` | Serves the gateway for a sandbox started with `up --detach`. |
| `silo status`, `silo logs [-f]`, `silo down` | Shows state, prints runtime logs with control characters escaped, stops and cleans up. |
| `silo seccomp [--out FILE]` | Shows what silo removes from the stock seccomp profile, or writes the hardened profile. |
| `silo nft [--sealed]` | Prints a host firewall rule that drops all traffic from the sandbox user. `--sealed` prints one that stops the whole machine from sending anything but SSH replies. See [host/](host/README.md). |

Configuration is read from `--config PATH`, else `$SILO_CONFIG`, else `~/.config/silo/silo.toml`,
and silo prints which file it used whenever it launches something. It is never read from the
current directory: silo is routinely run next to files it does not trust, and a downloaded model
must not be able to bring its own `silo.toml`.

## Configuration

The settings that matter most. Every option, with comments, is in
[examples/silo.example.toml](examples/silo.example.toml). Unknown keys and wrong types are errors.

| Setting | Default | Meaning |
|---|---|---|
| `model.dir`, `model.file` | none | A directory that holds only model files, and the GGUF inside it. |
| `model.ctx_size` | `4096` | Context window passed to llama-server. |
| `runtime.memory` | `"8g"` | Hard memory cap, with no swap on top. It has to fit the model plus its context. |
| `runtime.seccomp_action` | `"errno"` | `"errno"` makes denied syscalls fail. `"kill"` terminates the runtime on the first one. |
| `runtime.image` | llama.cpp server | Pin it with the image ID printed by `silo images`. |
| `runtime.gpu` | `"none"` | GPU passthrough. Exposes a GPU driver to the sandbox and is not yet verified. |
| `gateway.listen`, `gateway.port` | `127.0.0.1`, `8088` | A non-loopback address is refused unless `api_key_env` is set. |
| `gateway.scanner` | `"monitor"` | `"off"`, `"monitor"` (log and alert) or `"enforce"` (withhold high-severity completions). |
| `gateway.allow_tools` | `false` | Tool calling. When on, whatever executes the calls is outside the silo. |
| `gateway.log_content` | `false` | Record prompts and completions in the audit log, not only their hashes. |
| `gateway.api_key_env` | none | Name of an environment variable holding a bearer token that clients must send. |

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
  holds streams until they finish clean so that a blocked one is never partly delivered.
- **Limits.** Size caps both ways, one total deadline per request, bounded concurrency.
- **Audit log.** One JSON line per request in `~/.local/state/silo/audit/`, mode 0600: hashes of
  what was sent and delivered, findings, tool-call names. Prompts and completions are recorded only
  with `log_content = true`.

## Tightening it further

The defaults favour getting a model running. Once yours runs cleanly:

1. Set `runtime.seccomp_action = "kill"`. A compromised runtime that probes for a way out then dies
   on its first denied call, which you will notice, instead of getting an error and trying the next.
2. Set `gateway.scanner = "enforce"`.
3. Pin both images with the IDs printed by `silo images`.
4. Apply the host firewall rule and the kernel settings in [host/](host/README.md). They need root
   and are the layers that still stand if something gets out of the container.
5. Set `gateway.api_key_env` if other users or untrusted processes share the machine.

`silo doctor` lists whichever of these are still open.

## Limits

Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before relying on silo. The short version:

- **The kernel is shared.** A kernel vulnerability reachable through the roughly 320 syscalls still
  allowed is the main way out of the sandbox. silo shrinks that surface; it does not remove it.
  Put a second boundary around it: a VM with no network device on your own machine
  ([docs/LOCAL_VM.md](docs/LOCAL_VM.md)), or a dedicated, sealed server ([docs/VPS.md](docs/VPS.md)).
- **The answer still reaches you.** A model with no network can ask you to run something. The
  tripwire catches obvious shapes and is a regex, not a boundary. Treat output as untrusted input.
- **Your client is outside the silo.** If it renders HTML, fetches images or executes tool calls,
  that is where containment now has to hold.
- **Loopback is shared.** Any process on the machine can talk to the gateway unless you set an API
  key.
- **GPU passthrough** exposes a large driver to the sandbox and is unverified.
- **Covert channels** (timing, load) are out of scope.

## Roadmap

- A lighter second kernel boundary than a full VM: gVisor as the sandbox runtime.
- Mandatory access control for the sandbox on AppArmor hosts such as Ubuntu.
- Handing the runtime's socket to the gateway without a shared host directory.
- Argument-level allowlists for `ioctl`, `setsockopt` and `prctl`.
- An origin allowlist with proper CORS handling, for browser-based clients.
- Per-tool policy for tool calling, in place of all-or-nothing.
- Verification on GPU hardware, aarch64 and hosts without SELinux.

## Development

```sh
PYTHONPATH=src python3 -m unittest discover -s tests   # no network, no Podman needed
```

The unit tests run in CI on Python 3.11 and 3.13. The escape probes need a real Podman host, so
run `silo probe` and `silo probe --baseline` locally when you change anything in `sandbox.py`,
`seccomp.py` or `runtime.py`.

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
bin/silo                runs silo from a checkout, ignoring the current directory
bin/silo-vm             creates and runs a local VM with no network device
host/                   optional root-level hardening: firewall rules, sysctls
examples/               annotated configuration, systemd unit
docs/THREAT_MODEL.md    assumptions, controls, residual risk
docs/VPS.md             deploying on a rented server, step by step
docs/LOCAL_VM.md        a second kernel on your own machine: silo inside a VM
```

## Security

If you find a way out of the sandbox or past the gateway, please do not post the details in a
public issue. Open an issue that says you have a security report, without the specifics, so that a
private channel can be arranged.

What the documentation already lists as a limit, such as kernel vulnerabilities in general or text
that persuades a person, is known. Concrete improvements for those are welcome as normal issues.

## License

No license has been chosen yet. Until one is added, default copyright applies: you can read and
fork the code on GitHub, but you have no license to use, modify or redistribute it.
