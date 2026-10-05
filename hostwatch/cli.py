"""Operator commands for users and API keys.

  python -m hostwatch bootstrap-admin [--username NAME]
  python -m hostwatch user create|disable|unlock|passwd|grant-admin|revoke-admin USERNAME
  python -m hostwatch key create --scopes a,b [--owner NAME] [--host NAME] | list | revoke ID
  python -m hostwatch source forget HOST SOURCE
  python -m hostwatch event ack ID
  python -m hostwatch cert bind SUBJECT USER | list | revoke SUBJECT
  python -m hostwatch windows run [--data-dir DIR] [--env-file FILE]
  python -m hostwatch control run [--config FILE] [--data-dir DIR] [--env-file FILE]
  python -m hostwatch control cancel [--config FILE]

These commands open the database directly (except `windows run`, which runs the agent and
only uses its outbox, and `control`, the separate hostwatch-control daemon that never opens the hub database), so they are for someone who already
has shell access to the data directory. That is the trust boundary: they are not
reachable over the network. Passwords are read with getpass on a terminal or one
line from stdin otherwise, and are never taken from arguments, echoed or logged.
A new API key secret and a bootstrap password are printed once to stdout and are
not recoverable afterwards, because only hashes are stored. Every action, including
a refused one, appends a row to the audit log with kind "cli". Audit detail never
holds a secret.
"""

from __future__ import annotations

import argparse
import getpass
import secrets
import sqlite3
import sys
from datetime import datetime, timezone

from . import auth
from .config import Config
from .store import Store

COMMANDS = {"user", "key", "cert", "source", "event", "boot", "bootstrap-admin", "windows", "control"}
MIN_PASSWORD_LEN = 12


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m hostwatch", description="Manage hostwatch users and API keys.")
    sub = p.add_subparsers(dest="command", required=True)
    boot = sub.add_parser("bootstrap-admin",
                          help="create the first user with a random password (only when no users exist)")
    boot.add_argument("--username", default="admin")
    user = sub.add_parser("user", help="manage users").add_subparsers(dest="action", required=True)
    for name in ("create", "disable", "unlock", "passwd", "grant-admin", "revoke-admin"):
        user.add_parser(name).add_argument("username")
    key = sub.add_parser("key", help="manage API keys").add_subparsers(dest="action", required=True)
    create = key.add_parser("create")
    create.add_argument("--scopes", required=True, help="comma separated: " + ", ".join(sorted(auth.SCOPES)))
    create.add_argument("--owner", default="cli")
    create.add_argument("--host", default=None, help="bind the key to one host name; required for the ingest scope")
    key.add_parser("list")
    key.add_parser("revoke").add_argument("key_id", type=int)
    cert = sub.add_parser("cert", help="manage client certificate bindings").add_subparsers(dest="action", required=True)
    bind = cert.add_parser("bind", help="map a certificate subject (or san:<entry>) to a user")
    bind.add_argument("subject")
    bind.add_argument("username")
    cert.add_parser("list")
    cert.add_parser("revoke").add_argument("subject")
    source = sub.add_parser("source", help="manage what the hub remembers about sources").add_subparsers(
        dest="action", required=True)
    forget = source.add_parser("forget", help="declare that a source was removed on purpose")
    forget.add_argument("host")
    forget.add_argument("source")
    event = sub.add_parser("event", help="manage events").add_subparsers(dest="action", required=True)
    event.add_parser("ack", help="acknowledge a crash event so it stops holding the host critical").add_argument(
        "event_id", type=int)
    bootp = sub.add_parser("boot", help="manage boot events").add_subparsers(dest="action", required=True)
    reassess = bootp.add_parser("reassess", help="ask the power witnesses again about an unclean boot")
    reassess.add_argument("host")
    reassess.add_argument("boot_id")
    win = sub.add_parser("windows", help="run the native Windows agent").add_subparsers(dest="action", required=True)
    run_win = win.add_parser("run", help="run the agent loop in the foreground with the outbox in the data directory")
    run_win.add_argument("--data-dir", default=None,
                         help="agent data directory (default: HOSTWATCH_DATA_DIR or C:/ProgramData/hostwatch)")
    run_win.add_argument("--env-file", default=None, help="settings file (default: agent.env in the data directory)")
    ctl = sub.add_parser("control", help="the hostwatch-control command daemon").add_subparsers(
        dest="action", required=True)
    run_ctl = ctl.add_parser("run", help="pull and run signed commands from Observe in the foreground")
    run_ctl.add_argument("--config", default=None, help="control.toml (default: HOSTWATCH_CONTROL_CONFIG or the platform path)")
    run_ctl.add_argument("--data-dir", default=None, help="state and outbox folder (default: HOSTWATCH_CONTROL_DATA_DIR)")
    run_ctl.add_argument("--env-file", default=None, help="settings file (default: control.env in the data directory)")
    cancel_ctl = ctl.add_parser("cancel", help="cancel a scheduled reboot on this host")
    cancel_ctl.add_argument("--config", default=None, help="control.toml (default: HOSTWATCH_CONTROL_CONFIG or the platform path)")
    return p


def _read_password() -> str:
    if sys.stdin.isatty():
        first = getpass.getpass("Password: ")
        if getpass.getpass("Repeat password: ") != first:
            raise ValueError("passwords do not match")
    else:
        first = sys.stdin.readline().rstrip("\r\n")
    if len(first) < MIN_PASSWORD_LEN:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LEN} characters")
    return first


def _actor() -> str:
    try:
        who = getpass.getuser()
    except Exception:
        who = "unknown"
    return f"cli:{who}"


def _fmt(ts: float | None) -> str:
    return "-" if ts is None else datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run(argv: list[str], cfg: Config) -> int:
    args = _parser().parse_args(argv)
    if args.command == "windows":
        # The agent keeps its own outbox and never opens the hub database.
        from .windows.service import run_foreground
        return run_foreground(args.data_dir, args.env_file)
    if args.command == "control":
        # A separate daemon with its own account, data folder and outbox. The collector never imports it.
        from .control import daemon
        if args.action == "cancel":
            return daemon.run_cancel(args.config)
        return daemon.run_foreground(args.config, args.data_dir, args.env_file)
    store = Store(cfg.data_dir / "hostwatch.db")
    actor = _actor()
    label = args.command + (" " + args.action if getattr(args, "action", None) else "")

    def audit(status: int, detail: dict) -> None:
        store.append_audit(actor, "cli", "CLI", label, status, "local", detail)

    def fail(msg: str, detail: dict) -> int:
        audit(1, {**detail, "reason": msg})
        print(f"error: {msg}", file=sys.stderr)
        return 1

    if args.command == "bootstrap-admin":
        if store.count_users() > 0:
            return fail("users already exist; bootstrap-admin only runs on an empty user table", {})
        password = secrets.token_urlsafe(18)
        try:
            store.create_user(args.username, auth.hash_password(cfg, password), is_admin=True)
        except sqlite3.IntegrityError:
            return fail("username already exists", {"username": args.username})
        audit(0, {"username": args.username})
        print(f"Created user {args.username!r}. The password below is shown once and is not stored:",
              file=sys.stderr)
        print(password)
        return 0

    if args.command == "user":
        name = args.username
        detail = {"username": name[:64]}
        if args.action in ("create", "passwd"):
            if args.action == "passwd" and store.get_user(name) is None:
                return fail("unknown user", detail)
            try:
                password = _read_password()
            except ValueError as exc:
                return fail(str(exc), detail)
            pw_hash = auth.hash_password(cfg, password)
            if args.action == "create":
                try:
                    store.create_user(name, pw_hash)
                except sqlite3.IntegrityError:
                    return fail("username already exists", detail)
                audit(0, detail)
                print(f"Created user {name!r}.", file=sys.stderr)
            else:
                store.set_password_hash(name, pw_hash)
                store.reset_failures(name)
                revoked = store.revoke_user_sessions(name)
                audit(0, {**detail, "sessions_revoked": revoked})
                print(f"Password changed for {name!r}; {revoked} session(s) revoked.", file=sys.stderr)
            return 0
        if store.get_user(name) is None:
            return fail("unknown user", detail)
        if args.action == "disable":
            store.set_user_disabled(name, True)
            revoked = store.revoke_user_sessions(name)
            audit(0, {**detail, "sessions_revoked": revoked})
            print(f"Disabled {name!r}.", file=sys.stderr)
        elif args.action in ("grant-admin", "revoke-admin"):
            granting = args.action == "grant-admin"
            store.set_user_admin(name, granting)
            audit(0, {**detail, "is_admin": granting})
            print(f"{'Granted' if granting else 'Revoked'} admin for {name!r}.", file=sys.stderr)
        else:  # unlock
            store.reset_failures(name)
            audit(0, detail)
            print(f"Cleared lockout and failure count for {name!r}.", file=sys.stderr)
        return 0

    if args.command == "source":
        detail = {"host": args.host[:128], "source": args.source[:64]}
        if not store.forget_source(args.host, args.source):
            return fail("the hub has never seen that source present and available on that host", detail)
        audit(0, detail)
        print(f"Forgot {args.source!r} on {args.host!r}. A report of present false now reads as absent "
              "by design until the source is seen again.", file=sys.stderr)
        return 0

    if args.command == "boot":
        from .witness.homeassistant import HomeAssistantWitness
        from .witness.power import assess_boot_event, eligible
        detail = {"host": args.host[:128], "boot_id": args.boot_id[:64]}
        rows = store.boot_events(args.host, args.boot_id)
        if any(r["kind"] == "boot.power_loss" for r in rows):
            return fail("that boot is already recorded as a power loss", detail)
        rows = [r for r in rows if eligible(r)]
        if not rows:
            return fail("no unclean boot event for that host and boot id", detail)
        witness = HomeAssistantWitness.from_config(cfg)
        outcome = assess_boot_event(store, witness if witness.configured else None, args.host, rows[0],
                                    cfg.witness_skew_s, cfg.witness_retry_s, force=True)
        audit(0, {**detail, "outcome": outcome or "nothing applied"})
        print(f"Reassessed boot {args.boot_id!r} on {args.host!r}: {outcome or 'nothing applied'}.", file=sys.stderr)
        return 0

    if args.command == "event":
        detail = {"event_id": args.event_id}
        if not store.ack_event(args.event_id, actor):
            return fail("no event with that id", detail)
        audit(0, detail)
        print(f"Acknowledged event {args.event_id}. A crash it held critical now reads as recovered.",
              file=sys.stderr)
        return 0

    if args.command == "cert":
        if args.action == "bind":
            from .mtls import normalize
            subject = normalize(args.subject)
            detail = {"subject": subject[:256], "username": args.username[:64]}
            user = store.get_user(args.username)
            if not subject:
                return fail("subject must not be empty", detail)
            if user is None:
                return fail("unknown user", detail)
            store.bind_cert(subject, user["id"])
            audit(0, detail)
            print(f"Bound {subject!r} to {args.username!r}.", file=sys.stderr)
            return 0
        if args.action == "list":
            for b in store.list_cert_bindings():
                state = "revoked " + _fmt(b["revoked_at"]) if b["revoked_at"] else "active"
                print(f"{b['subject']}	{b['username']}	created {_fmt(b['created'])}	{state}")
            audit(0, {})
            return 0
        from .mtls import normalize
        subject = normalize(args.subject)
        if not store.revoke_cert(subject):
            return fail("no active binding for that subject", {"subject": subject[:256]})
        audit(0, {"subject": subject[:256]})
        print(f"Revoked the binding for {subject!r}. It is rejected on its next request.", file=sys.stderr)
        return 0

    if args.action == "create":
        try:
            secret, row = auth.generate_api_key(store, args.scopes, args.owner, host=args.host)
        except ValueError as exc:
            return fail(str(exc), {"scopes": args.scopes[:200]})
        audit(0, {"key_id": row["id"], "prefix": row["prefix"], "scopes": row["scopes"], "owner": row["owner"],
                  "host": row["host"]})
        print(f"Created key id {row['id']} with scopes {','.join(row['scopes'])}{' bound to host ' + row['host'] if row['host'] else ''}. The secret below is shown once:",
              file=sys.stderr)
        print(secret)
        return 0
    if args.action == "list":
        for k in store.list_api_keys():
            state = "revoked " + _fmt(k["revoked_at"]) if k["revoked_at"] else "active"
            print(f"{k['id']}\t{k['prefix']}\t{','.join(k['scopes'])}\t{k['owner']}\t"
                  f"host {k['host'] or 'unbound'}\t"
                  f"created {_fmt(k['created'])}\tlast used {_fmt(k['last_used'])}\t{state}")
        audit(0, {})
        return 0
    if not store.revoke_api_key(args.key_id):
        return fail("no active key with that id", {"key_id": args.key_id})
    audit(0, {"key_id": args.key_id})
    print(f"Revoked key {args.key_id}. It is rejected on its next request.", file=sys.stderr)
    return 0
