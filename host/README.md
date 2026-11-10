# Host-side hardening

Everything silo does on its own runs as your user, with no root and no changes outside its own
state directories. The two pieces here are different: they need root, they are host-wide, and they
are optional. They are the layers that still stand if something gets out of the container.

Neither has been applied on the machine silo was developed on (that takes root). The firewall rule
below was checked for syntax and loadability inside a throwaway user+network namespace only.

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

The table lives until reboot. To make it permanent, save the output of `silo nft` as
`/etc/nftables/silo.nft` and load it at boot, for example with a oneshot unit:

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

## 3. Things only you can do

- Keep the kernel patched. The sandbox shares the host kernel; that is its main residual risk.
- Keep SELinux enforcing. `silo doctor` fails the check if it is not.
- Leave the user Podman API socket off (`systemctl --user disable --now podman.socket`) unless you
  need it: anything that can reach it controls every container you own.
