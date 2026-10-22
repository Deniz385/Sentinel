#!/usr/bin/env python3
"""Sentinel CLI entry point.

The application itself lives in the `sentinel` package; this file is a
thin wrapper for users used to running `python main.py`. After
installation the `sentinel` command does the same thing.

The legacy invocation still works:
    python main.py --target test_data --no-html
The new one:
    python main.py scan test_data --format html,csv,sarif
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sentinel.cli import main as cli_main  # noqa: E402

# v3.0 had no subcommands; bare arguments default to `scan`.
_COMMANDS = {
    "scan", "watch", "vault", "rules", "precommit", "init", "doctor",
    "-h", "--help", "--version",
}


def main() -> int:
    argv = sys.argv[1:]
    if argv and argv[0] not in _COMMANDS and not argv[0].startswith("--no-color"):
        argv = ["scan"] + argv
    elif not argv:
        argv = ["scan"]
    return cli_main(argv)


if __name__ == "__main__":
    sys.exit(main())
