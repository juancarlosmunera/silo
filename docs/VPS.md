# Running silo on a VPS

A rented server is a better home for an untrusted model than your own computer, for one reason:
you can put a boundary around the whole machine. Your workstation holds your keys, your sessions
and your files, and it has to reach the internet. A VPS that exists only to run the model holds
nothing, and can be told to reach nothing. Then even the worst case, a kernel exploit that takes
over the machine, leaves the attacker on a box that cannot call out and has nothing on it.

This guide sets that up:

- the machine is dedicated to the model and disposable;
- it cannot start a connection to anywhere, enforced outside the machine where the provider allows
  it, and inside the machine as well;
- you reach it only over SSH, and the gateway never listens on a public address;
- each of those is checked from the machine itself before you rely on it.

```
 your machine                               the VPS
 client ─▶ 127.0.0.1:8088 ═══ ssh -L ═══▶ sshd ─▶ 127.0.0.1:8088 gateway ─▶ sandbox
                                            outbound: nothing
```

## What this was tested on

Every command below was run on a Fedora 43 Cloud image (kernel 6.17, Podman 5.6, SELinux
enforcing) in a virtual machine standing in for the VPS, with the hypervisor dropping everything
the guest sent out in place of a provider's firewall. Ubuntu 24.04 was tested the same way; see
[Other distributions](#other-distributions).

Not tested: any particular provider's firewall product, a real cloud metadata service, and
IPv6-only hosts. `silo doctor --sealed` exists so that you can check those on your own machine
rather than take them on trust.

## 1. The machine

**Distribution.** Use Fedora (Cloud or Server). SELinux in enforcing mode is one of silo's layers,
and Fedora Cloud 43 already ships Podman, nftables, rsync and Python, so the machine never needs
outbound access, not even during setup.

**Size.** Enough RAM for the model file plus its context, and about 1 GB on top.

**Attach nothing.** No cloud role or instance profile, no API keys, no secrets in user-data, no
other services, no data you care about. The plan for a compromise is to delete the machine.

**The provider's firewall** (security group, cloud firewall):

- inbound: SSH from your own address, nothing else;
- outbound: nothing. Many providers allow all outbound traffic by default, and you have to remove
  that rule.

If your provider cannot filter outbound traffic, the sealed ruleset in step 4 does it from inside
the machine.

Keep the provider's web console or rescue mode within reach until you have finished step 4.

## 2. Accounts

Two accounts: the administrative one the image came with (root, or a user with sudo), and an
unprivileged one that runs the model and can do nothing else.

```sh
# on the VPS, as the administrative account
sudo dnf -y install podman nftables rsync      # already present on Fedora Cloud 43
sudo useradd --create-home --shell /bin/bash silo
sudo loginctl enable-linger silo               # its services start at boot and survive logout
sudo install -d -m 700 -o silo -g silo /home/silo/.ssh
sudo install -m 600 -o silo -g silo ~/.ssh/authorized_keys /home/silo/.ssh/authorized_keys
```

The `silo` account has no sudo rights. Do not give it any.

Always connect without agent forwarding (`ssh -a`). A forwarded agent lets whoever controls the
server use your keys for as long as you are connected. `silo doctor` warns if it finds one.

## 3. Push silo, the images and the model

Everything goes in over your SSH connection, so the VPS needs no outbound access. On your own
machine, pull the images (`silo pull`) and vet the model (`silo intake`) first.

```sh
# on your machine
rsync -a --exclude .git silo/ silo@VPS:silo/

podman save ghcr.io/ggml-org/llama.cpp:server  | ssh -a silo@VPS podman load
podman save docker.io/library/python:3.13-slim | ssh -a silo@VPS podman load

ssh -a silo@VPS mkdir -p models/smollm2        # rsync does not create missing parent directories
rsync -a --progress ~/models/smollm2/ silo@VPS:models/smollm2/
```

`bin/silo` runs straight from that checkout. Nothing has to be installed, which also means nothing
has to be downloaded.

## 4. Root-level layers

Do this before the first model runs, while nothing untrusted has executed on the machine.

**Kernel settings.** Read the file first; it says what each line costs.

```sh
# as the administrative account
sudo cat /home/silo/silo/host/sysctl/90-silo-hardening.conf | sudo install -m 0644 /dev/stdin /etc/sysctl.d/90-silo-hardening.conf
sudo sysctl --system
```

**Firewall rules.** There are two, and on a dedicated machine you want the second:

- `silo nft` drops everything the sandbox's own user originates. This is the rule for a machine
  that still needs the network for other things.
- `silo nft --sealed` also stops the whole machine from sending anything except replies from its
  SSH server, DHCP and IPv6 neighbour discovery. Nothing on it can start a connection, whoever it
  runs as, and a process that got out and listens on some port cannot be reached, because its
  replies never leave. Use it under the provider's firewall as a second layer, or in place of one.

The sealed ruleset names the port your SSH server listens on. If it names the wrong one, loading
it cuts you off. It takes the port from the SSH session it is generated in, else assumes 22; pass
`--ssh-port N` to set it. An SSH port below 1024 is the safe choice here, because the rule lets
replies out by source port and only root can send from a port below 1024.

```sh
# as the administrative account
sudo mkdir -p /etc/nftables
sudo -u silo -H /home/silo/silo/bin/silo nft --sealed --ssh-port 22 | sudo install -m 0600 /dev/stdin /etc/nftables/silo.nft
sudo cat /etc/nftables/silo.nft                # read it: it is a dozen lines, and it states the SSH port
sudo nft -f /etc/nftables/silo.nft
```

Now open a **second** SSH connection and check that you get in. The rules are not permanent yet:
if you are locked out, a reboot from the provider's panel removes them.

Once a new connection works, load the rules at every boot:

```sh
sudo tee /etc/systemd/system/silo-nft.service >/dev/null <<'EOF'
[Unit]
Description=silo: drop all traffic from the sandbox UID
# after anything that might flush the ruleset at boot
After=nftables.service firewalld.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/nftables/silo.nft
ExecStop=/usr/sbin/nft delete table inet silo

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable silo-nft
```

## 5. Configure and verify

```sh
# on the VPS, as silo
mkdir -p ~/.config/silo
cp ~/silo/examples/silo.example.toml ~/.config/silo/silo.toml
~/silo/bin/silo images                         # prints the image IDs to pin
```

Edit `~/.config/silo/silo.toml`:

```toml
[model]
dir = "~/models/smollm2"
file = "SmolLM2-135M-Instruct-Q8_0.gguf"

[runtime]
image = "sha256:..."            # the image IDs printed by `silo images`
probe_image = "sha256:..."
memory = "2g"                   # what your model needs
seccomp_action = "kill"

[gateway]
scanner = "enforce"
```

Pin by image ID, not by registry digest. An image keeps its ID through `podman save` and
`podman load`; its digest changes, so a digest noted on your own machine does not match on the VPS.

Then check everything from the machine itself:

```sh
~/silo/bin/silo intake              # vet the model directory, record its manifest
~/silo/bin/silo doctor --sealed     # host posture, and proof that the machine cannot get out
~/silo/bin/silo probe               # the escape probes, in a sandbox identical to the model's
```

`doctor --sealed` tries to leave the machine the ways an escaped process would: TCP to public
addresses over IPv4 and IPv6, a UDP DNS query, ICMP, a lookup through the system resolver, and the
cloud metadata address. Every line has to say `blocked`:

```
 ✓ egress: TCP to 1.1.1.1:443             blocked (TimeoutError)
 ✓ egress: UDP DNS to 1.1.1.1             blocked (Operation not permitted)
 ✓ egress: DNS through the system resolver blocked (no answer)
 ✓ cloud metadata service                 not reachable (TimeoutError)
```

The resolver line matters on clouds that exempt their own DNS service from firewall rules: a
resolver that still answers is a way to carry data out one lookup at a time, whatever the firewall
says about direct connections.

`silo probe` has to end with `FAIL=0`, and on Fedora with `WARN=0` as well.

## 6. Run it as a service

```sh
# on the VPS, as silo
mkdir -p ~/.config/systemd/user
cp ~/silo/examples/systemd/silo.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now silo
systemctl --user status silo
journalctl --user -u silo -f                   # startup, and the gateway's alerts
```

With lingering enabled in step 2, the service starts at boot without anyone logging in. Stopping
it removes the container and the socket directory.

## 7. Use it

The gateway listens on the VPS's loopback only. Reach it through a tunnel:

```sh
# on your machine
ssh -a -N -L 8088:127.0.0.1:8088 silo@VPS
```

Your clients then talk to `http://127.0.0.1:8088/v1` exactly as in the README. Use `-L`, never `-R`
or `-D`: a local forward gives the server no way to open connections back into your network.

Do not put the gateway on a public address. It has no TLS, and silo refuses a non-loopback listen
address unless an API key is configured.

## Maintenance

A sealed machine cannot fetch updates, by design. To patch it:

1. Open outbound traffic: stop the host rules (`sudo systemctl stop silo-nft`) and, if you use one,
   relax the provider's firewall.
2. `sudo dnf -y upgrade`, then reboot. The rules load again at boot.
3. Close the provider's firewall again.
4. `~/silo/bin/silo doctor --sealed` and `~/silo/bin/silo probe`. A new kernel or a new Podman is a
   new thing to verify.

New models and new images arrive the way the first ones did, over SSH. Run `silo intake` again for
a changed model directory, and update the image IDs in `silo.toml`.

Time synchronisation stops while the machine is sealed, so its clock drifts. silo does not depend
on it; the timestamps in the audit log will be off by the drift.

## Watching it

```sh
sudo nft list table inet silo                  # as the administrative account
journalctl --user -u silo | grep ALERT         # as silo
tail ~/.local/state/silo/audit/default.jsonl   # as silo
```

The counter on the `meta skuid` rule must stay at zero. A sandbox behaving normally never reaches
that rule, so any packet counted there came from something that left its network namespace. The
counter on the last rule of the sealed ruleset is not an alarm: the operating system's own
resolver and time client run into it all day.

If the sandbox UID's counter moves, or anything else about the machine looks wrong, do not
investigate on it. Delete the machine and build a new one. That is what keeping it empty is for.

## What holds when

| If this happens | What still stands |
|---|---|
| A crafted model file or prompt takes over the runtime, inside the sandbox | Everything in the README: no network, no privileges, nowhere to write a binary. |
| It gets out of the container but still runs as the sandbox's UID | The host rule drops everything that UID sends, loopback included, and counts it. |
| The `silo` account is taken over, for example through the gateway | No sudo. The sealed ruleset and the provider's firewall stop every outbound connection. Nothing else is on the machine. |
| The whole machine is taken over (a kernel exploit, root) | Root can remove the host ruleset. The provider's firewall still denies outbound traffic, and the machine holds no keys, no role and no data. |
| In every one of these | What the model writes still reaches you through the tunnel. The limits on output described in the README apply unchanged. |

The last row is why the provider's firewall matters more than anything inside the machine: it is
the one control an attacker on the machine cannot touch. If your provider has none, the sealed
ruleset is the best available, and it stops everything short of root.

## Other distributions

**Ubuntu 24.04** (kernel 6.8, Podman 4.9, installed with `apt-get install podman`): silo runs, the
service and the tunnel work, the kernel settings and both firewall rulesets load, and 65 of the 66
escape probes pass. The one that does not is confinement by a mandatory access control policy.
Rootless Podman gets none on Ubuntu: Podman reports AppArmor as not enabled for rootless
containers and refuses an explicit profile, so the sandbox process runs unconfined by any LSM.
`silo doctor` fails the host on that line, and `silo probe` reports

```
 WARN proc.lsm                       not confined: AppArmor profile 'crun' is in unconfined mode
```

Network isolation, the syscall filter, the privilege drop and the read-only filesystem are all in
place there. What is missing is the layer that limits what a process can touch after it has found
a way around the others. If you have the choice, use Fedora.

Debian and the RHEL family have not been tested. On any distribution, `silo doctor` and
`silo probe` tell you what you actually have.

## The same thing at home

The setup in this guide also works against a virtual machine on your own computer, which can be
stricter than any rented server: [LOCAL_VM.md](LOCAL_VM.md) runs it in a VM that has no network
device at all.
