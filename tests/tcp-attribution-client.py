#!/usr/bin/env python3
"""One real TCP socket owner for the isolated attribution regression."""

import argparse
import json
import os
import socket
import sys
from pathlib import Path

from integration_support import receive_exact, require_isolation


def main():
    require_isolation()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('local_ip')
    parser.add_argument('local_port', type=int)
    parser.add_argument('remote_ip')
    parser.add_argument('remote_port', type=int)
    parser.add_argument('payload')
    parser.add_argument('result', type=Path)
    arguments = parser.parse_args()
    with socket.socket() as client:
        client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        client.settimeout(10)
        client.bind((arguments.local_ip, arguments.local_port))
        client.connect((arguments.remote_ip, arguments.remote_port))
        client.sendall(arguments.payload.encode('ascii'))
        result = {
            'pid': os.getpid(), 'local': client.getsockname(),
            'peer': client.getpeername(),
            'reply': receive_exact(client, 4).decode('ascii'),
        }
        pending = arguments.result.with_suffix('.pending')
        pending.write_text(json.dumps(result))
        pending.replace(arguments.result)
        # Keep both socket owners alive through both attribution checks. The
        # parent releases us only after checking results; EOF also releases us.
        sys.stdin.buffer.readline()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
