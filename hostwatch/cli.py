"""Subcommands that run something other than the Linux collector agent.

  python -m hostwatch windows run [--data-dir DIR] [--env-file FILE]
  python -m hostwatch control run [--config FILE] [--data-dir DIR] [--env-file FILE]
  python -m hostwatch control cancel [--config FILE]
  python -m hostwatch control state-upgrade [--data-dir DIR] [--env-file FILE]
  python -m hostwatch control state-reset --yes [--last-seq N] [--data-dir DIR] [--env-file FILE]

`windows run` runs the native Windows agent in the foreground with its outbox in the data
directory. `control` is the separate hostwatch-control daemon, which has its own account, data
folder and outbox and which the collector never imports.
"""

from __future__ import annotations

import argparse

COMMANDS = {"windows", "control"}


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m hostwatch", description="Run hostwatch components.")
    sub = p.add_subparsers(dest="command", required=True)
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
    up = ctl.add_parser("state-upgrade", help="upgrade an old replay state file, keeping its sequence number and ids")
    rs = ctl.add_parser("state-reset", help="delete the replay state (last resort); stop the service first")
    for sp in (up, rs):
        sp.add_argument("--data-dir", default=None, help="state folder (default: HOSTWATCH_CONTROL_DATA_DIR)")
        sp.add_argument("--env-file", default=None, help="settings file (default: control.env in the data directory)")
    rs.add_argument("--yes", action="store_true", help="confirm that the replay history is deleted")
    rs.add_argument("--last-seq", type=int, default=None, metavar="N",
                    help="start again with this highest executed sequence number, so the seq-jump limit still applies")
    return p


def run(argv: list[str], cfg=None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "windows":
        from .windows.service import run_foreground
        return run_foreground(args.data_dir, args.env_file)
    from .control import daemon
    if args.action == "cancel":
        return daemon.run_cancel(args.config)
    if args.action in ("state-upgrade", "state-reset"):
        return daemon.run_state_tool(args.action, args.data_dir, args.env_file,
                                     getattr(args, "yes", False), getattr(args, "last_seq", None))
    return daemon.run_foreground(args.config, args.data_dir, args.env_file)
