#!/usr/bin/env python3
"""Serve a signed Sparkle pilot feed over loopback HTTPS in a disposable VM."""

import argparse
import functools
import http.server
import ssl
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("feed", type=Path, help="directory containing appcast.xml")
    parser.add_argument("certificate", type=Path)
    parser.add_argument("key", type=Path)
    args = parser.parse_args()
    if not (args.feed / "appcast.xml").is_file():
        parser.error("feed does not contain appcast.xml")
    if not args.certificate.is_file() or not args.key.is_file():
        parser.error("certificate and key files are required")

    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(args.certificate, args.key)
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=args.feed)
    with http.server.ThreadingHTTPServer(("127.0.0.1", 8443), handler) as server:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
