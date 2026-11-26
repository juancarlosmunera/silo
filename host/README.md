# Host-side hardening

Everything silo does on its own runs as your user, with no root and no changes outside its own
state directories. The pieces here are different: they need root, they are host-wide, and they
are optional. They are the layers that still stand if something gets out of the container.

Both were applied and exercised as root on Fedora 43 and Ubuntu 24.04 test machines; the results
are in [docs/VPS.md](../docs/VPS.md), which is also the place to start if the machine is a rented
server. They have not been applied on the workstation silo is developed on.

## 1. No network for the sandbox UID, enforced by the host

Inside the sandbox there is no network at all. This rule is for the case where a process leaves its
network namespace anyway: it still runs as the sandbox's subordinate UID, and the host refuses to
send anything that UID originates, loopback included.

```sh
silo nft                 # prints the rule for your account, with the UID worked out from /etc/subuid
silo nft | sudo nft -f - # apply
sudo nft list table inet silo
```

The rule matches one UID: the host UID that container user 65534 maps to under your account. Other
rootless containers are not affected unless they also run as container UID 65534 *and* use host
networking. A sandbox behaving normally never reaches this hook, so a counter above zero means
something left its network namespace and tried to talk.

Tested: with the rule loaded, a process running as that UID gets `Operation not permitted` on UDP
and no answer on TCP, loopback included, while every other account is unaffected.

### A sealed host

On a machine dedicated to the model, `silo nft --sealed` goes further: the whole machine sends
nothing except replies from its SSH server, DHCP and IPv6 neighbour discovery. Nothing on it can
start a connection, and a process that listens on some port cannot be reached from outside,
because its replies never leave.

```sh
silo nft --sealed --ssh-port 22 | sudo install -m 0600 /dev/stdin /etc/nftables/silo.nft
sudo cat /etc/nftables/silo.nft          # read it; check the SSH port it names
sudo nft -f /etc/nftables/silo.nft
```

It names the port your SSH server listens on, and loading it with the wrong port cuts you off.
Open a second SSH connection to confirm you still get in before making it permanent; until then a
reboot removes it. Package updates, DNS and time synchronisation stop while it is loaded, so
maintenance means `sudo nft delete table inet silo` for the duration. `silo doctor --sealed`
confirms from the machine itself that nothing gets out.

### Making it permanent

Either ruleset lives until reboot. To load it at boot, save it as `/etc/nftables/silo.nft` and add
a oneshot unit:

```ini
# /etc/systemd/system/silo-nft.service
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
```

firewalld manages only its own tables, so the two coexist. If your subordinate UID range in
`/etc/subuid` ever changes, regenerate the rule.

## 2. Kernel settings

[`sysctl/90-silo-hardening.conf`](sysctl/90-silo-hardening.conf) has two groups: settings that are
low risk on a workstation, and two that can break other software and are commented out. Each line
says what it costs. `silo doctor` reports the current value of every one of them.

```sh
sudo install -m 0644 host/sysctl/90-silo-hardening.conf /etc/sysctl.d/
sudo sysctl --system
```

## 3. AppArmor, on hosts without SELinux

On Ubuntu and Debian, rootless Podman puts its containers under no mandatory access control: it
does not apply an AppArmor profile and refuses one that is named explicitly. silo can set one
itself, through the container runtime, but only a profile that is already loaded, and loading one
takes root:

```sh
sudo install -m 0644 host/apparmor/silo-runtime /etc/apparmor.d/silo-runtime
sudo apparmor_parser -r /etc/apparmor.d/silo-runtime
```

Nothing else has to be configured. From then on silo starts its sandboxes under that profile, and

```sh
silo doctor    # "AppArmor: sandbox confined by the profile silo-runtime"
silo probe     # "proc.lsm: confined by AppArmor as crun//&silo-runtime: the profile refused the write that only it forbids"
```

The profile repeats, in a mechanism of its own, what the other layers already say: read the image
and the model, write only to the scratch space and execute nothing from it, UNIX sockets and no
other network, no capability, no mount, no ptrace. It only applies to containers silo starts.
`silo doctor` fails the host as long as AppArmor is enabled and the profile is not loaded.

The label has two parts because silo sets `no-new-privileges`: AppArmor then adds silo's profile to
the one the container runtime already had (Ubuntu's `crun` profile, which confines nothing)
instead of replacing it, and every profile in such a stack has to allow an operation.

Tested in CI on Ubuntu 24.04 (Podman 4.9, crun 1.14), x86_64 and aarch64: the probes in both
seccomp modes and a model in a silo, with a check that the profile denied nothing but the probes'
deliberate attempt. Not tested: GPU sandboxes under the profile, Debian, and SELinux hosts, where
silo does not use it.

## 4. Things only you can do

- Keep the kernel patched. The sandbox shares the host kernel; that is its main residual risk.
  To put a second boundary around it, run silo in a VM with no network device
  ([docs/LOCAL_VM.md](../docs/LOCAL_VM.md)), on a dedicated, sealed server
  ([docs/VPS.md](../docs/VPS.md)), or on gVisor's user-space kernel
  ([docs/GVISOR.md](../docs/GVISOR.md)).
- Keep SELinux enforcing where the host has it. `silo doctor` fails the check if it is not.
- Leave the user Podman API socket off (`systemctl --user disable --now podman.socket`) unless you
  need it: anything that can reach it controls every container you own.
