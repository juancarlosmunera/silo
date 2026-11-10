"""silo command line."""

from __future__ import annotations

import argparse
import json
import signal
import subprocess
import sys
from pathlib import Path

from silo import __version__, doctor, gateway, hostrules, intake, runtime, seccomp
from silo.config import Config, ConfigError, default_config_path, load
from silo.sandbox import HardeningError
from silo.util import safe_text

COLOR = sys.stdout.isatty()


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if COLOR else text


STATUS_COLORS = {"PASS": "32", "ok": "32", "FAIL": "31", "bad": "31", "WARN": "33", "warn": "33", "SKIP": "90",
                 "INFO": "90"}


def _note(text: str) -> None:
    print(text, file=sys.stderr, flush=True)


def _announce(cfg: Config) -> None:
    # The config picks the image, the model directory and the seccomp base: never use one silently.
    _note(f"silo[{cfg.name}] config: {cfg.source or 'built-in defaults (no silo.toml found)'}")
    if cfg.source is None and Path("silo.toml").is_file():
        _note(f"silo[{cfg.name}] note: ./silo.toml is not read. silo never takes configuration from the "
              f"current directory; pass --config silo.toml or move it to {default_config_path()}")


def cmd_doctor(cfg: Config, args) -> int:
    _announce(cfg)
    worst = 0
    for check in doctor.run_checks(cfg):
        mark = {"ok": "✓", "warn": "!", "bad": "✗"}[check.level]
        print(f" {_c(mark, STATUS_COLORS[check.level])} {check.name:<38} {check.detail}")
        if check.fix:
            print(f"   {'':<38} {_c('→ ' + check.fix, '90')}")
        worst = max(worst, {"ok": 0, "warn": 1, "bad": 2}[check.level])
    return 1 if worst == 2 else 0


def cmd_seccomp(cfg: Config, args) -> int:
    base = json.loads(cfg.runtime.seccomp_base.read_text())
    profile = seccomp.harden(base, action=cfg.runtime.seccomp_action, cpu_only=cfg.runtime.gpu == "none")
    if args.out:
        Path(args.out).write_text(json.dumps(profile, indent=2) + "\n")
        print(f"wrote {args.out}")
        return 0
    before = seccomp.allowed_unconditionally(base)
    after = seccomp.allowed_unconditionally(profile)
    removed = sorted(before - after)
    print(f"base profile: {cfg.runtime.seccomp_base}")
    print(f"architectures: {[a['architecture'] for a in profile['archMap']]} (no compat ABIs)")
    print(f"unconditionally allowed: {len(before)} -> {len(after)} syscalls")
    print(f"removed from the stock allowlist ({len(removed)}): {', '.join(removed)}")
    print("socket()/socketpair(): AF_UNIX only · clone(): no namespace flags · clone3(): ENOSYS")
    print(f"deny action: {cfg.runtime.seccomp_action}")
    return 0


def cmd_nft(cfg: Config, args) -> int:
    uid = hostrules.sandbox_host_uid(hostrules.subuid_ranges())
    print(hostrules.nft_ruleset(uid), end="")
    _note("\n# review, then apply as root:  silo nft | sudo nft -f -")
    return 0


def cmd_intake(cfg: Config, args) -> int:
    root, _ = cfg.require_model()
    if not root.is_dir():
        raise ConfigError(f"model.dir does not exist: {root}")
    verdicts = intake.scan(root, allow_unknown=args.allow_unknown)
    rejected = [v for v in verdicts if not v.ok]
    for v in verdicts:
        mark = _c("✓", "32") if v.ok else _c("✗", "31")
        print(f" {mark} {safe_text(v.path):<60} {v.kind:<12} {v.reason}")
    if rejected:
        print(f"\n{len(rejected)} file(s) rejected. Remove them from {root} (or obtain a safe format) and rerun.")
        if any(v.path.startswith((".cache/", ".git/")) for v in rejected):
            print("hint: .cache/ and .git/ are download-tool metadata; the runtime does not need them.")
        if any(v.kind == "unknown" for v in rejected):
            print("hint: --allow-unknown accepts unlisted extensions (code, pickles and symlinks stay rejected).")
        return 1
    if not any(v.kind in ("gguf", "safetensors") for v in verdicts):
        print("no weights found (expected .gguf or .safetensors)")
        return 1
    manifest = intake.build_manifest(root, verdicts)
    intake.write_manifest(manifest, cfg.manifest_path)
    print(f"\nmanifest: {cfg.manifest_path} ({len(manifest['files'])} files)")
    return 0


def cmd_verify(cfg: Config, args) -> int:
    root, _ = cfg.require_model()
    problems = intake.verify(root, cfg.manifest_path, full=args.full)
    for p in problems:
        print(f" {_c('✗', '31')} {safe_text(p)}")
    if not problems:
        mode = "full rehash" if args.full else "size + mtime; use --full to rehash"
        print(f" {_c('✓', '32')} {root} matches {cfg.manifest_path} ({mode})")
    return 1 if problems else 0


def cmd_up(cfg: Config, args) -> int:
    def stop(*_):
        raise KeyboardInterrupt

    # From here on SIGTERM unwinds like Ctrl-C, so an interrupted start still tears the sandbox down.
    signal.signal(signal.SIGTERM, stop)
    _announce(cfg)
    _note(f"silo[{cfg.name}] starting {cfg.container_name} from {cfg.runtime.image}")
    runtime.up(cfg, verify=not args.no_verify, full_verify=args.full_verify)
    _note(f"silo[{cfg.name}] model healthy on {cfg.socket_path} (socket directory locked)")
    if args.detach:
        return 0
    try:
        gateway.serve(cfg)
    except KeyboardInterrupt:
        pass
    finally:
        _note(f"\nsilo[{cfg.name}] stopping {cfg.container_name}")
        runtime.down(cfg)
    return 0


def cmd_gateway(cfg: Config, args) -> int:
    _announce(cfg)
    if not runtime.socket_dir_locked(cfg):
        raise runtime.LaunchError(f"{cfg.socket_dir} is missing or not locked; start the sandbox with "
                                  "`silo up --detach` first")
    try:
        gateway.serve(cfg)
    except KeyboardInterrupt:
        pass
    return 0


def cmd_down(cfg: Config, args) -> int:
    print(f"{cfg.container_name}: {'stopped' if runtime.down(cfg) else 'not running'}")
    return 0


def cmd_status(cfg: Config, args) -> int:
    print(json.dumps(runtime.status(cfg), indent=2))
    return 0


def cmd_logs(cfg: Config, args) -> int:
    return runtime.logs(cfg, follow=args.follow)


def cmd_pull(cfg: Config, args) -> int:
    for image, pinned in runtime.pull(cfg):
        print(f"{image}\n  pin as: {pinned}")
    return 0


def cmd_probe(cfg: Config, args) -> int:
    if not args.json:
        _announce(cfg)
    rc, results = runtime.probe(cfg, baseline=args.baseline)
    if args.json:
        print(json.dumps(results, indent=2))
        return rc
    title = "baseline (stock rootless podman)" if args.baseline else f"silo sandbox ({cfg.container_name})"
    print(f"escape probes — {title}\n")
    for r in results:
        status = r["status"] if r["status"] in STATUS_COLORS else "WARN"
        if args.quiet and status in ("PASS", "INFO"):
            continue
        print(f" {_c(f'{status:<4}', STATUS_COLORS[status])} {safe_text(r['probe']):<30} {safe_text(r['detail'])}")
    counts = {s: sum(r["status"] == s for r in results) for s in ("PASS", "FAIL", "WARN", "SKIP")}
    print("\n" + "  ".join(f"{k}={v}" for k, v in counts.items()))
    return rc


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="silo", description="Defense-in-depth containment for local LLMs.")
    p.add_argument("--config", type=Path, help="path to silo.toml")
    p.add_argument("--version", action="version", version=f"silo {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("doctor", help="check host and configuration posture")
    s = sub.add_parser("seccomp", help="show or write the hardened seccomp profile")
    s.add_argument("--out", help="write the profile to this path")
    sub.add_parser("nft", help="print the host firewall rule that drops all traffic from the sandbox UID")
    s = sub.add_parser("intake", help="vet the model directory and record a SHA-256 manifest")
    s.add_argument("--allow-unknown", action="store_true", help="accept files with unlisted extensions")
    s = sub.add_parser("verify", help="check the model directory against its manifest")
    s.add_argument("--full", action="store_true", help="rehash every file")
    s = sub.add_parser("up", help="start the model sandbox and serve the gateway")
    s.add_argument("--detach", action="store_true", help="start the sandbox only (run `silo gateway` separately)")
    s.add_argument("--full-verify", action="store_true", help="rehash every model file before launch")
    s.add_argument("--no-verify", action="store_true", help="skip manifest verification (not recommended)")
    sub.add_parser("gateway", help="serve the gateway for an already running sandbox")
    sub.add_parser("down", help="stop the model sandbox")
    sub.add_parser("status", help="show sandbox status")
    s = sub.add_parser("logs", help="show model runtime logs (control characters escaped)")
    s.add_argument("-f", "--follow", action="store_true")
    sub.add_parser("pull", help="pull runtime and probe images and print digests to pin")
    s = sub.add_parser("probe", help="run the escape-probe suite inside a sandbox")
    s.add_argument("--baseline", action="store_true", help="run against a stock container for comparison")
    s.add_argument("--json", action="store_true")
    s.add_argument("-q", "--quiet", action="store_true", help="only show non-PASS results")
    return p


COMMANDS = {
    "doctor": cmd_doctor, "seccomp": cmd_seccomp, "nft": cmd_nft, "intake": cmd_intake, "verify": cmd_verify,
    "up": cmd_up, "gateway": cmd_gateway, "down": cmd_down, "status": cmd_status, "logs": cmd_logs,
    "pull": cmd_pull, "probe": cmd_probe,
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        cfg = load(args.config)
        return COMMANDS[args.command](cfg, args)
    except (ConfigError, runtime.LaunchError, hostrules.HostRuleError, HardeningError) as exc:
        print(f"silo: {exc}", file=sys.stderr)
        return 2
    except subprocess.CalledProcessError as exc:
        print(f"silo: command failed ({exc.returncode}): {' '.join(map(str, exc.cmd[:3]))} ...", file=sys.stderr)
        return 2
    except OSError as exc:  # e.g. the gateway port is already in use
        print(f"silo: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
