#!/usr/bin/env python3
"""
hack5250 — tn5250 MITM proxy for IBM i (AS/400) pentesting.

Mirror of hack3270.py for the 5250 protocol. No legacy compat layer:
the orchestration is in libhack5250.Hack5250 (~150 LOC vs hack3270's 1700+).
"""
import sys
import os
import argparse
import logging

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'hackterm-core'))

from hack5250.libhack5250 import Hack5250, DEFAULT_PROXY_PORT, DEFAULT_API_PORT
from hack5250.gui import Hack5250GUI


def main():
    parser = argparse.ArgumentParser(
        prog="hack5250.py",
        description="hack5250 - tn5250 MITM proxy for IBM i pentesting",
        epilog="Example: %(prog)s 10.0.0.50 23 -n production_ibmi --tls",
    )
    parser.add_argument("host", help="IBM i server IP address")
    parser.add_argument("port", type=int,
                        help="IBM i telnet port (usually 23, or 992 for TLS)")
    parser.add_argument("-n", "--name", default="ibmi_pentest",
                        help="Project name — db file becomes <name>.db (default: %(default)s)")
    parser.add_argument("-p", "--proxy-port", type=int, default=DEFAULT_PROXY_PORT,
                        help="Local proxy port (default: %(default)s)")
    parser.add_argument("--proxy-ip", default="127.0.0.1",
                        help="Local proxy bind address (default: %(default)s)")
    parser.add_argument("--api-port", type=int, default=DEFAULT_API_PORT,
                        help="Local API port (default: %(default)s)")
    parser.add_argument("-t", "--tls", action="store_true",
                        help="Use TLS for the upstream connection to the IBM i")
    parser.add_argument("-c", "--codepage", default="cp037",
                        help="EBCDIC codepage: cp037, cp500, cp1140, ... (default: %(default)s)")
    parser.add_argument("-d", "--debug", action="store_const",
                        const=logging.DEBUG, default=logging.WARNING,
                        dest="loglevel", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=args.loglevel,
        format="%(name)s :: %(levelname)s :: %(funcName)s :: %(message)s",
    )

    h = Hack5250(
        server_ip=args.host,
        server_port=args.port,
        proxy_port=args.proxy_port,
        proxy_ip=args.proxy_ip,
        project_name=args.name,
        tls_enabled=args.tls,
        codepage=args.codepage,
        api_port=args.api_port,
        loglevel=args.loglevel,
    )

    gui = Hack5250GUI(h)
    gui.run()  # blocks; handles Ctrl-C via SIGINT→quit(); shutdown in finally


if __name__ == "__main__":
    main()
