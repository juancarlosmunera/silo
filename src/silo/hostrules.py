"""Host firewall rule: a second, independent no-egress control.

Inside the sandbox there is no network: no interface, no route, and seccomp refuses every socket
family except AF_UNIX. This module covers the case where that is somehow not enough: a process that
gets out of its network namespace still runs as the sandbox's subordinate UID, and the host can
refuse to route anything that UID originates. Applying the rule needs root, so silo only prints it.
"""

from __future__ import annotations

import os
import pwd
from pathlib import Path

from silo.sandbox import SANDBOX_USER

SUBUID = Path("/etc/subuid")


class HostRuleError(RuntimeError):
    pass


def subuid_ranges(path: Path = SUBUID, uid: int | None = None) -> list[tuple[int, int]]:
    """(start, count) ranges delegated to the user, in file order (podman maps them in that order)."""
    uid = os.getuid() if uid is None else uid
    names = {str(uid)}
    try:
        names.add(pwd.getpwuid(uid).pw_name)
    except KeyError:
        pass
    ranges = []
    try:
        lines = path.read_text().splitlines()
    except OSError as exc:
        raise HostRuleError(f"cannot read {path}: {exc.strerror}") from exc
    for line in lines:
        parts = line.strip().split(":")
        if len(parts) == 3 and parts[0] in names and parts[1].isdigit() and parts[2].isdigit():
            ranges.append((int(parts[1]), int(parts[2])))
    return ranges


def sandbox_host_uid(ranges: list[tuple[int, int]], container_uid: int | None = None) -> int:
    """Host UID that a rootless container UID maps to.

    Rootless podman maps container UID 0 to the invoking user and container UIDs 1.. onto the
    subordinate ranges in order, so container UID n is the (n-1)th subordinate UID.
    """
    if container_uid is None:
        container_uid = int(SANDBOX_USER.split(":")[0])
    if container_uid < 1:
        raise HostRuleError("container UID 0 maps to the invoking user, not to a subordinate UID")
    offset = container_uid - 1
    for start, count in ranges:
        if offset < count:
            return start + offset
        offset -= count
    raise HostRuleError(f"no subordinate UID for container UID {container_uid}; check /etc/subuid")


def nft_ruleset(host_uid: int, sealed: bool = False, ssh_port: int = 22) -> str:
    if not 1 <= ssh_port <= 65535:
        raise HostRuleError(f"invalid SSH port {ssh_port}")
    container_uid = SANDBOX_USER.split(":")[0]
    head = f"""#!/usr/sbin/nft -f
# silo: host UID {host_uid} is what the sandbox user (container UID {container_uid}) maps to.
# Nothing that UID originates in the host network namespace is ever sent, loopback included.
# A sandbox in its own network namespace never reaches this hook; a non-zero counter means something
# got out of that namespace and tried to talk. Inspect with: nft list table inet silo
"""
    sandbox_rule = f'meta skuid {host_uid} counter drop comment "silo sandbox UID: no network, ever"'
    if not sealed:
        return head + f"""table inet silo
delete table inet silo
table inet silo {{
    chain output {{
        type filter hook output priority filter; policy accept;
        {sandbox_rule}
    }}
}}
"""
    return head + f"""#
# Sealed host: on top of that, this machine sends nothing except what is listed below, whoever asks.
#
#   SSH SERVER PORT: {ssh_port}. If your SSH server listens on another port, loading this cuts you off.
#   Regenerate with `silo nft --sealed --ssh-port N`.
#
# The list is stateless on purpose. "Allow established connections" would be wrong twice over: it
# lets a process that got out and listens on some port be connected to from outside (its replies are
# "established"), and it freezes the SSH session you load the rules from, because connection
# tracking only starts at that moment. Replies from the SSH port can only be sent by the SSH server:
# binding a port below 1024, or one that is already listening, takes root.
#
# Use it on a machine dedicated to the model, under the provider's firewall or in place of one. It
# stops a process that escaped as an unprivileged user and a compromised gateway alike. Root can
# remove it. Package updates, image pulls, DNS and time synchronisation stop while it is loaded:
#   nft delete table inet silo      (as root, for the duration of the maintenance)
table inet silo
delete table inet silo
table inet silo {{
    chain output {{
        type filter hook output priority filter; policy drop;
        {sandbox_rule}
        oifname "lo" accept
        tcp sport {ssh_port} accept comment "replies from the SSH server"
        udp sport 68 udp dport 67 accept comment "DHCP client: keep the address lease"
        udp sport 546 udp dport 547 accept comment "DHCPv6 client"
        icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, mld-listener-report, mld2-listener-report }} accept comment "IPv6 neighbour discovery"
        counter comment "silo sealed host: outbound packet dropped"
    }}
}}
"""
