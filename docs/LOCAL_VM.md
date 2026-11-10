# A second kernel on your own machine

silo's sandbox shares your machine's kernel. That is its main limit: a kernel vulnerability
reachable from inside the sandbox is a way out, and what lies outside is your own account, on the
computer that holds your keys and sessions.

This guide puts a virtual machine between the two. silo runs inside the VM exactly as it would on
a server, and the VM has no network device.

```
 your machine                                          the VM: no network device
 client ─▶ 127.0.0.1:8088 ══ ssh over a VM socket ══▶ sshd ─▶ gateway ─▶ sandbox
```

## What you get, and what it costs

- The kernel the model's runtime can attack is the guest's, not yours. Getting from the guest to
  your machine means breaking out of KVM and QEMU, which is a different and much smaller target
  than the Linux system call interface.
- There is nothing to seal. The VM has no network device, so no firewall rule has to be right.
  The only channel is a VM socket (`AF_VSOCK`) that carries SSH and is opened from your side.
- silo's own sandbox still runs inside, unchanged, and passes the same probes there.

The cost is memory for the guest (the model plus about 2 GB), a second operating system to keep
updated, and a few seconds of boot. Inference speed is not part of the cost: with the same model
and four threads, a quick test gave about 126 tokens per second in the VM and 127 directly on the
host.

## What this was tested on

Host: Fedora 43, QEMU 10.1, systemd 258. Guest: the Fedora 43 Cloud image, updated on its first
boot. Everything below was run from a freshly created VM. Other hosts and other guests have not
been tried.

## Requirements

On your machine:

- KVM, usable by your account: `/dev/kvm` and `/dev/vhost-vsock`;
- `qemu-system-x86_64` and `qemu-img`;
- a systemd user session, and OpenSSH with `systemd-ssh-proxy` (systemd 256 or newer);
- `genisoimage`, `mkisofs` or `xorrisofs`.

## 1. Get the guest image and verify it

Use the Fedora Cloud "Base Generic" image. Check the signature on the checksum file, then the
image against the checksum:

```sh
base=https://download.fedoraproject.org/pub/fedora/linux/releases/43/Cloud/x86_64/images
curl -LO $base/Fedora-Cloud-43-1.6-x86_64-CHECKSUM
curl -LO $base/Fedora-Cloud-Base-Generic-43-1.6.x86_64.qcow2

# on a Fedora host, the release key is already on disk
gpg --dearmor < /etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-43-primary > fedora.gpg
gpgv --keyring ./fedora.gpg Fedora-Cloud-43-1.6-x86_64-CHECKSUM      # must say "Good signature"
sha256sum --ignore-missing -c Fedora-Cloud-43-1.6-x86_64-CHECKSUM    # must say "OK"
```

`sha256sum` also warns about lines it cannot parse. Those are the signature, and the warning is
expected. On another distribution, get the Fedora key from <https://fedoraproject.org/security>
and check its fingerprint there.

## 2. Create the VM

```sh
bin/silo-vm create Fedora-Cloud-Base-Generic-43-1.6.x86_64.qcow2
bin/silo-vm update     # the first boot, and the only routine one WITH a network device
bin/silo-vm status     # repeat until it says "not running"; this took about three minutes
bin/silo-vm start      # from now on: no network device
```

`create` makes a disk, an SSH key used for this VM only, and a first-boot recipe. On that first
boot, started by `update`, the guest installs all pending updates, creates two accounts and powers
itself off. `admin` has sudo. `silo` has none, and is the account that will run the model.

The update is not optional. Besides the usual reasons, the SELinux policy on the released Fedora 43
image stops its SSH server from accepting connections over a VM socket, and the updated policy
does not.

During `update` the VM has outbound access through QEMU's user-mode networking. Nothing on your
machine listens for it, and nothing of yours is in the VM yet.

The VM lives in `~/.local/share/silo-vm`. Set `SILO_VM_MEMORY` (MiB, default 4096) and
`SILO_VM_CPUS` (default 4) before `start` to size it for your model.

## 3. Reach it

```sh
ssh -F ~/.local/share/silo-vm/ssh_config silo-vm           # the unprivileged account
ssh -F ~/.local/share/silo-vm/ssh_config silo-vm-admin     # the account with sudo
```

To drop the `-F`, add this line to `~/.ssh/config`:

```
Include ~/.local/share/silo-vm/ssh_config
```

The rest of this guide assumes you did.

## 4. Put silo in it

This is the server deployment from [VPS.md](VPS.md), with `silo-vm` as the host. The VM cannot
download anything, so everything goes in over SSH. Pull the images and vet the model on your own
machine first (`silo pull`, `silo intake`).

```sh
# on your machine
rsync -a --exclude .git silo/ silo-vm:silo/

podman save ghcr.io/ggml-org/llama.cpp:server  | ssh silo-vm podman load
podman save docker.io/library/python:3.13-slim | ssh silo-vm podman load

ssh silo-vm mkdir -p models/smollm2
rsync -a --progress ~/models/smollm2/ silo-vm:models/smollm2/
```

Then in the VM, as `silo` (`ssh silo-vm`):

```sh
mkdir -p ~/.config/silo
cp ~/silo/examples/silo.example.toml ~/.config/silo/silo.toml
~/silo/bin/silo images              # the image IDs to put in silo.toml
```

Edit `~/.config/silo/silo.toml` as in [VPS.md, step 5](VPS.md#5-configure-and-verify): the model,
the two image IDs, `memory`, `seccomp_action = "kill"`, `scanner = "enforce"`. Then:

```sh
~/silo/bin/silo intake
~/silo/bin/silo doctor --sealed     # every egress line says "blocked (Network is unreachable)"
~/silo/bin/silo probe               # ends with PASS=66  FAIL=0  WARN=0
```

Install the service, together with the drop-in that keeps the model from starting whenever the VM
has a network interface other than loopback:

```sh
mkdir -p ~/.config/systemd/user/silo.service.d
cp ~/silo/examples/systemd/silo.service ~/.config/systemd/user/
cp ~/silo/examples/systemd/silo.service.d/no-network.conf ~/.config/systemd/user/silo.service.d/
systemctl --user daemon-reload
systemctl --user enable --now silo
```

The kernel settings from [VPS.md, step 4](VPS.md#4-root-level-layers) are worth applying in the
guest as well. The firewall rules there are not needed: there is no device to send with.

## 5. Use it

```sh
# on your machine
ssh -N -L 8088:127.0.0.1:8088 silo-vm
```

Clients talk to `http://127.0.0.1:8088/v1` as in the README.

## Day to day

```sh
bin/silo-vm start      # the model service starts with the VM
bin/silo-vm stop       # asks the guest to shut down
bin/silo-vm status     # also says whether a network device is attached
```

To update the guest:

```sh
bin/silo-vm stop
bin/silo-vm update                                       # boots WITH a network device
ssh silo-vm-admin 'sudo dnf -y upgrade && sudo poweroff'
bin/silo-vm start
```

While the VM is in update mode the model service does not start: the drop-in from step 4 skips it
as long as any interface besides loopback exists. After an update, run `silo doctor --sealed` and
`silo probe` in the VM again. A new kernel or a new Podman is a new thing to verify.

## What holds when

| If this happens | What still stands |
|---|---|
| A crafted model file or prompt takes over the runtime, inside silo's sandbox | Everything in the README: no network, no privileges, nowhere to write a binary. |
| It breaks out of that sandbox through a kernel bug and becomes root in the guest | The guest has no network device and holds nothing of yours. Your machine is on the other side of KVM. |
| It breaks out of the VM | It runs as your account, inside the QEMU process. QEMU's own seccomp filter forbids that process to fork, execute programs or change privileges, which limits what an attacker can do from there but is not a second sandbox. |
| In every one of these | What the model writes still reaches you through the tunnel. The limits on output described in the README apply unchanged. |

Beyond the emulated chipset, what the guest can reach in QEMU is little: two virtio disks, one a read-only
seed, a serial port that writes to a log file, and the VM socket device, which the host kernel
handles and QEMU does not. There is no network device, display, USB or any other default device.

Two things to know:

- A VM socket also lets the guest connect to anything on your machine that listens on `AF_VSOCK`.
  Normally nothing does. `ss -l --vsock` shows what is there.
- A VM does nothing about side channels through shared hardware, such as CPU caches.

If your machine cannot spare the memory, or you would rather not run the model at home at all,
the same setup on a rented server is in [VPS.md](VPS.md).
