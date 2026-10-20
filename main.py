#!/usr/bin/env python3
"""Sentinel CLI giriş noktası.

Asıl uygulama `sentinel` paketindedir; bu dosya `python main.py` ile
çalıştırmaya alışmış kullanıcılar için ince bir sarmalayıcıdır.
Kurulumdan sonra `sentinel` komutu da aynı işi yapar.

Eski kullanım korunur:
    python main.py --target test_data --no-html
Yeni kullanım:
    python main.py scan test_data --format html,csv,sarif
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sentinel.cli import main as cli_main  # noqa: E402

# v3.0'da alt komut yoktu; argümanlar doğrudan verilince `scan` varsayılır.
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
