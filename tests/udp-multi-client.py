#!/usr/bin/env python3
"""Private child socket owner for the isolated synthetic UDP test."""
import json
import os
import socket
import sys

from integration_support import require_isolation, run_main


def main():
    require_isolation()
    if (len(sys.argv) not in (4, 5) or sys.argv[1] not in ('4', '6') or
            (len(sys.argv) == 5 and sys.argv[4] != 'reuse')):
        raise RuntimeError('private UDP child: family, local address, local port required')
    family = socket.AF_INET if sys.argv[1] == '4' else socket.AF_INET6
    with socket.socket(family, socket.SOCK_DGRAM) as client:
        if len(sys.argv) == 5:
            client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        client.settimeout(4)
        client.bind((sys.argv[2], int(sys.argv[3])))
        print(json.dumps({'pid': os.getpid(), 'local': client.getsockname()[:2]}), flush=True)
        for line in sys.stdin:
            command = json.loads(line)
            if command['action'] == 'close':
                break
            if command['action'] == 'batch':
                requests = command['requests']
                if not 1 <= len(requests) <= 16:
                    raise RuntimeError('private UDP child batch must contain 1-16 datagrams')
                for request in requests:
                    client.sendto(bytes.fromhex(request['payload']), tuple(request['remote']))
                responses = []
                for _request in requests:
                    reply, peer = client.recvfrom(65535)
                    responses.append({'payload': reply.hex(), 'peer': peer[:2]})
                print(json.dumps({'pid': os.getpid(), 'responses': responses,
                                  'local': client.getsockname()[:2]}), flush=True)
                continue
            if command['action'] != 'request':
                raise RuntimeError('unknown private UDP child action')
            remote = tuple(command['remote'])
            payload = bytes.fromhex(command['payload'])
            client.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, int(command.get('mark', 0)))
            client.setsockopt(socket.SOL_SOCKET, socket.SO_PRIORITY, int(command.get('priority', 0)))
            if command.get('connected'):
                client.connect(remote)
                client.send(payload)
            else:
                client.sendto(payload, remote)
            if command.get('notify_sent'):
                print(json.dumps({'event': 'sent', 'pid': os.getpid()}), flush=True)
            reply, peer = client.recvfrom(65535)
            print(json.dumps({'pid': os.getpid(), 'payload': reply.hex(),
                              'peer': peer[:2], 'local': client.getsockname()[:2],
                              'connected_peer': client.getpeername()[:2]
                              if command.get('connected') else None}), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(run_main(main))
