#!/usr/bin/env python3
"""Echo small laboratory request markers with the source seen at the server."""

import argparse
import ipaddress
import re
import socketserver
import time


LAB_NETWORKS = tuple(ipaddress.ip_network(prefix) for prefix in
                     ("10.61.10.0/24", "10.62.10.0/24", "127.0.0.0/8"))
MARKER = re.compile(rb"lab-[A-Za-z0-9._-]{1,64}\n")


class Echo(socketserver.StreamRequestHandler):
    def handle(self):
        source, port = self.client_address
        if not any(ipaddress.ip_address(source) in subnet for subnet in LAB_NETWORKS):
            return
        self.request.settimeout(180)
        try:
            while marker := self.rfile.readline(70):
                if not MARKER.fullmatch(marker):
                    return
                self.wfile.write(f"{source} ".encode("ascii") + marker)
                self.wfile.flush()
                print(time.time_ns(), self.server.server_address[0], source, port,
                      marker.decode("ascii").strip(), flush=True)
        except (ConnectionError, TimeoutError):
            return


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("address", type=ipaddress.IPv4Address)
    parser.add_argument("port", type=int, choices=(8443, 9443))
    args = parser.parse_args()
    if not any(args.address in subnet for subnet in LAB_NETWORKS):
        parser.error("bind the server to an address in the HA lab topology")
    with Server((str(args.address), args.port), Echo) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
