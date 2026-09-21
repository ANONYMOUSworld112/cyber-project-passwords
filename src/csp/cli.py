from __future__ import annotations

import argparse
import sys
from typing import List, Optional


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="csp",
        description="CyberBlack-Passwords: Fully offline multi-user cybersecurity credential and forensics platform.",
    )
    parser.add_argument("-v", "--version", action="store_true", help="print version and exit")
    parser.add_argument(
        "--port", type=int, default=8899,
        help="web server port (default: 8899)",
    )
    parser.add_argument(
        "--host", type=str, default="127.0.0.1",
        help="web server host (default: 127.0.0.1)",
    )

    subparsers = parser.add_subparsers(dest="command", help="subcommands")

    serve_parser = subparsers.add_parser("serve", help="start the web interface server")
    serve_parser.add_argument("--port", type=int, default=8899, help="port (default: 8899)")
    serve_parser.add_argument("--host", type=str, default="127.0.0.1", help="host (default: 127.0.0.1)")

    subparsers.add_parser("status", help="display platform and storage status")

    reset_parser = subparsers.add_parser("reset", help="wipe all local platform data")
    reset_parser.add_argument("--confirm-wipe", action="store_true", help="confirm complete data wipe")

    args = parser.parse_args(argv)

    if args.version:
        from csp import __version__
        print(f"CyberBlack-Passwords v{__version__}")
        return 0

    if args.command == "status":
        from csp.auth.users import first_run, list_users
        from csp.paths import data_dir
        print(f"Data Directory: {data_dir()}")
        print(f"First Run Needed: {first_run()}")
        print(f"Registered Users: {len(list_users())}")
        for u in list_users():
            print(f"  - {u}")
        return 0

    if args.command == "reset":
        if not args.confirm_wipe:
            print("Error: full data wipe requires --confirm-wipe flag.", file=sys.stderr)
            return 1
        import shutil
        from csp.paths import data_dir
        from csp.web.session import wipe_all as wipe_all_sessions
        d = data_dir()
        if d.exists():
            for child in d.iterdir():
                if child.is_dir():
                    shutil.rmtree(child, ignore_errors=True)
                else:
                    child.unlink()
        wipe_all_sessions()
        from csp.auth.session import set_session
        set_session(None)
        print("All data in data directory wiped successfully.")
        return 0

    port = getattr(args, "port", 8899)
    host = getattr(args, "host", "127.0.0.1")
    from csp.web.server import run_server
    run_server(host=host, port=port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
