from __future__ import annotations

import argparse
import sys
from typing import List, Optional


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="csp",
        description="Fully offline multi-user cybersecurity platform.",
    )
    parser.add_argument("--version", action="store_true", help="print version and exit")
    parser.add_argument(
        "--port", type=int, default=8899,
        help="web server port (default: 8899)",
    )
    parser.add_argument(
        "--host", type=str, default="127.0.0.1",
        help="web server host (default: 127.0.0.1)",
    )
    args = parser.parse_args(argv)

    if args.version:
        from csp import __version__
        print(f"csp {__version__}")
        return 0

    from csp.web.server import run_server
    run_server(host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
