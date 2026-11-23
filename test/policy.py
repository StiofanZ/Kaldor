"""Exercise production SOCKS forwarding and TLS latency probes entirely on Linux loopback."""
import contextlib
from dns import Doh, ENCRYPTED
import json
import os
from pathlib import Path
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time


def read(sock, size):
    parts = bytearray()
    while len(parts) < size:
        chunk = sock.recv(size - len(parts))
        if not chunk:
            raise EOFError()
        parts.extend(chunk)
    return bytes(parts)


def request(host):
    return b'\x05\x01\x00\x03' + bytes([len(host)]) + host.encode() + struct.pack('!H', 443)


class Member(socketserver.BaseRequestHandler):
    def handle(self):
        conn = self.request
        version, count = read(conn, 2)
        assert version == 5 and 0 in read(conn, count)
        conn.sendall(b'\x05\x00')
        version, cmd, _, kind = read(conn, 4)
        assert version == 5 and cmd in (1, 3)
        host = socket.inet_ntoa(read(conn, 4)) if kind == 1 else read(conn, read(conn, 1)[0]).decode()
        read(conn, 2)
        if cmd == 3:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as relay:
                relay.bind(('127.0.0.1', 0))
                relay.settimeout(5)
                conn.sendall(b'\x05\x00\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', relay.getsockname()[1]))
                for _ in range(2):
                    packet, sender = relay.recvfrom(2048)
                    relay.sendto(packet[:10] + self.server.label.encode(), sender)
            return
        if host == 'failover.test' and self.server.label == 'fast':
            conn.sendall(b'\x05\x05\x00\x01' + bytes(6))
            return
        conn.sendall(b'\x05\x00\x00\x01' + bytes(6))
        if host == '1.1.1.1':
            if self.server.label == 'slow':
                time.sleep(0.3)
            with self.server.tls.wrap_socket(conn, server_side=True) as tls:
                Doh(tls, self.client_address, self.server)
            return
        conn.sendall((self.server.label + '\n').encode())


def routed(port, host):
    with socket.create_connection(('127.0.0.1', port), timeout=10) as conn:
        conn.sendall(b'\x05\x01\x00')
        assert read(conn, 2) == b'\x05\x00'
        conn.sendall(request(host))
        reply = read(conn, 4)
        assert reply[:2] == b'\x05\x00', (host, reply)
        read(conn, (4 if reply[3] == 1 else 16) + 2)
        return conn.makefile('rb').readline().decode().strip()


def udp_flow(port):
    with socket.create_connection(('127.0.0.1', port), timeout=5) as conn, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        conn.sendall(b'\x05\x01\x00')
        assert read(conn, 2) == b'\x05\x00'
        conn.sendall(b'\x05\x03\x00\x01' + bytes(6))
        assert read(conn, 4) == b'\x05\x00\x00\x01'
        relay = (socket.inet_ntoa(read(conn, 4)), struct.unpack('!H', read(conn, 2))[0])
        udp.settimeout(5)
        header = b'\x00\x00\x00\x01' + socket.inet_aton('192.0.2.10') + struct.pack('!H', 8080)
        nodes = []
        for _ in range(2):
            udp.sendto(header + b'ping', relay)
            data = udp.recv(128)
            assert data.startswith(header)
            nodes.append(data[len(header):].decode())
        return nodes


def port_available():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def verify(engine, root, resources):
    key, cert = root / 'key', root / 'cert'
    subprocess.run(['openssl', 'req', '-newkey', 'rsa:2048', '-x509', '-nodes', '-days', '1',
                    '-subj', '/CN=cloudflare-dns.com', '-keyout', key, '-out', cert],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    nodes = []
    for label in ('slow', 'fast'):
        peer = resources.enter_context(socketserver.ThreadingTCPServer(('127.0.0.1', 0), Member))
        peer.tls, peer.label = tls, label
        threading.Thread(target=peer.serve_forever, daemon=True).start()
        resources.callback(peer.shutdown)
        nodes.append(dict(name=label, protocol='socks5', server='127.0.0.1:%d' % peer.server_address[1]))
    nodes.append(dict(name='offline', protocol='socks5', server='127.0.0.1:%d' % port_available()))
    port = port_available()
    cfg = dict(enabled=True, devices=['127.0.0.1/32'], listen_port=port, default='speed', upstreams=nodes,
               policies=[dict(name=name, type=kind, members=['slow', 'fast'], **extra)
                         for name, kind, extra in [('speed', 'auto', {}), ('rotate', 'load_balance', {}),
                                                  ('pick', 'manual', {'selected': 'slow'})]],
               rules=[dict(domain_suffix=host, outbound=out) for host, out in
                      [('rotate.test', 'rotate'), ('manual.test', 'pick')]])
    cfg['policies'].append(dict(name='unavailable', type='auto', members=['offline']))
    cfg['rules'].append(dict(domain_suffix='offline.test', outbound='unavailable'))
    cfg['rules'].append(dict(domain_suffix='cloudflare-dns.com', outbound='rotate'))
    cfg['rules'].append(dict(network='udp', outbound='rotate'))
    path, ready = root / 'cfg', root / 'ready'
    path.write_text(json.dumps(cfg))
    nvram = root / 'nvram'
    nvram.write_text('#!/bin/sh\necho 0\n')
    nvram.chmod(0o700)
    worker = subprocess.Popen([engine, 'serve', path, '127.0.0.1', 'lo', ready],
                              env=dict(os.environ, SSL_CERT_FILE=str(cert), PATH=str(root) + os.pathsep + os.environ["PATH"]))
    try:
        deadline = time.monotonic() + 10
        while not ready.exists():
            assert worker.poll() is None and time.monotonic() < deadline, 'listener did not start'
            time.sleep(0.05)
        assert routed(port, 'speed.test') == 'fast'
        assert routed(port, 'failover.test') == 'slow'
        assert routed(port, 'manual.test') == 'slow'
        assert [routed(port, 'rotate.test') for _ in range(4)] == ['slow', 'fast'] * 2
        assert udp_flow(port) == ['slow', 'slow']
        assert udp_flow(port) == ['fast', 'fast']
        with socket.create_connection(('127.0.0.1', port), timeout=5) as sock:
            sock.sendall(b'\x05\x01\x00')
            assert read(sock, 2) == b'\x05\x00'
            sock.sendall(request('offline.test'))
            assert read(sock, 2) == b'\x05\x01'
        question = bytes.fromhex('102001000001000000000000') + b'\x03www\x04test\0\0\x01\0\x01'
        for _ in range(2):
            with socket.create_connection(('127.0.0.1', 7893), timeout=5) as sock:
                sock.sendall(struct.pack('!H', len(question)) + question)
                answer = read(sock, struct.unpack('!H', read(sock, 2))[0])
                assert answer[:2] == question[:2] and socket.inet_ntoa(answer[-4:]) == ENCRYPTED
        with socket.socket(socket.AF_UNIX) as activity:
            activity.connect(str(root / 'activity.sock'))
            recent = json.load(activity.makefile('rb'))['recent']
        assert any(r['target'] == 'failover.test' and r['outbound'] == 'slow' for r in recent)
        assert [r['outbound'] for r in recent if r['transport'] == 'UDP'] == ['fast','slow']
        assert [r['outbound'] for r in recent if r['ingress'] == '透明 DNS'] == ['fast','slow']
        assert any(r['outbound'] == 'unavailable' and r['result'] == 'failed' for r in recent)
        print('DoH via selected nodes and all-offline policy failure PASS')
        print('UDP per-flow affinity and activity actual node PASS')
        print('measured TLS latency, failover, manual node and round-robin PASS')
    finally:
        worker.terminate()
        worker.wait(timeout=5)


if __name__ == '__main__':
    with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as resources:
        verify(sys.argv[1], Path(directory), resources)
