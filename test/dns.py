"""Network-namespace regression for transparent DNS. All answers are synthetic."""
import http.server
from pathlib import Path
import secrets
import socket
import socketserver
import ssl
import struct
import sys
import threading

PUBLIC = "1.1.1.1"
AUTHORITY = "cloudflare-dns.com"
WAN = "198.51.100.2"
ENCRYPTED = "203.0.113.22"
PLAIN = "203.0.113.11"


def response(query, addr):
    count = 40 if b"oversize" in query else 1
    rr = bytes.fromhex("c00c00010001000000010004") + socket.inet_aton(addr)
    return query[:2] + struct.pack("!5H", 0x8180, 1, count, 0, 0) + query[12:] + rr * count


class Doh(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        assert self.headers["Host"] == AUTHORITY and self.path == "/dns-query"
        assert self.headers["Content-Type"] == "application/dns-message"
        query = self.rfile.read(int(self.headers["Content-Length"]))
        body = response(query, ENCRYPTED)
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-message")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def server(root):
    class PlainUDP(socketserver.BaseRequestHandler):
        def handle(self):
            query, sock = self.request
            sock.sendto(response(query, PLAIN), self.client_address)

    class PlainTCP(socketserver.StreamRequestHandler):
        def handle(self):
            length, = struct.unpack("!H", self.rfile.read(2))
            reply = response(self.rfile.read(length), PLAIN)
            self.wfile.write(struct.pack("!H", len(reply)) + reply)

    def context(cert, key):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        return ctx

    good = context(root / "dns.crt", root / "dns.key")
    bad = context(root / "ca.pem", root / "key")

    def select_cert(sock, name, _):
        assert name == AUTHORITY
        if (root / "wrong-cert").exists():
            sock.context = bad

    good.set_servername_callback(select_cert)
    https = http.server.ThreadingHTTPServer((PUBLIC, 443), Doh)
    https.socket = good.wrap_socket(https.socket, server_side=True)
    for fixture in [socketserver.UDPServer((WAN, 53), PlainUDP), socketserver.TCPServer((WAN, 53), PlainTCP)]:
        threading.Thread(target=fixture.serve_forever, daemon=True).start()
    https.serve_forever()


def query(src, dst, proto, label):
    tx = secrets.token_bytes(2)
    data = tx + bytes.fromhex("01000001000000000000") + bytes([len(label)]) + label.encode() + b"\x04test\0\0\x01\0\x01"
    with socket.socket(socket.AF_INET6 if ":" in src else socket.AF_INET,
                       socket.SOCK_DGRAM if proto == "udp" else socket.SOCK_STREAM) as sock:
        sock.settimeout(8)
        sock.bind((src, 0))
        sock.connect((dst, 53))
        if proto == "udp":
            sock.send(data)
            reply = sock.recv(65535)
        else:
            sock.sendall(struct.pack("!H", len(data)) + data)
            with sock.makefile("rb") as reader:
                length, = struct.unpack("!H", reader.read(2))
                reply = reader.read(length)
                assert len(reply) == length
    assert reply[:2] == tx and reply[2] & 128
    if reply[3] & 15:
        print("rcode", reply[3] & 15)
    elif reply[2] & 2:
        assert len(reply) <= 512
        print("truncated")
    else:
        print(socket.inet_ntoa(reply[-4:]))


def verify(root, command, spawn, wait, client, wan, sing, conf, control, activity, peer, sing_conf):
    import copy
    script = str(Path(__file__).resolve())
    command(*wan, "ip", "addr", "add", PUBLIC + "/32", "dev", "lo")
    # Only the proxy server namespace can reach the HTTPS listener.
    command("ip", "route", "add", "unreachable", PUBLIC + "/32")
    command("openssl", "req", "-new", "-nodes", "-newkey", "rsa:2048", "-subj", "/CN=" + AUTHORITY,
            "-out", root / "dns.csr", "-keyout", root / "dns.key")
    (root / "dns.ext").write_text("subjectAltName=DNS:" + AUTHORITY + "\n")
    command("openssl", "x509", "-req", "-in", root / "dns.csr", "-CA", root / "ca.pem", "-CAkey", root / "key",
            "-CAcreateserial", "-days", "1", "-extfile", root / "dns.ext", "-out", root / "dns.crt")
    spawn(*wan, sys.executable, script, "server", str(root))
    wait(lambda: ":443 " in command(*wan, "ss", "-ltn"))
    remote = copy.deepcopy(sing_conf)
    inbound = remote["inbounds"][0]
    inbound.update(listen=WAN)
    remote["inbounds"] = [inbound]
    spawn(*wan, sing, "run", "-c", str(conf("dns-node.json", remote)))
    wait(lambda: ":19443" in command(*wan, "ss", "-ltn"))
    selected, other = "192.0.2.2", "192.0.2.3"
    cfg = conf("dns-client.json", {"enabled": True, "devices": [selected + "/32"], "default": "node",
                                  "upstreams": [dict(peer, name="node", server=WAN + ":19443")]})
    control("configure", cfg)

    def lookup(src, dst, proto, label="example"):
        return command(*client, sys.executable, script, "query", src, dst, proto, label)

    for proto in ("udp", "tcp"):
        for dst in (WAN, "192.0.2.1"):
            assert lookup(selected, dst, proto) == ENCRYPTED
        assert lookup(other, WAN, proto) == PLAIN
    assert lookup(selected, WAN, "udp", "oversize") == "truncated"
    assert lookup(selected, WAN, "tcp", "oversize") == ENCRYPTED
    assert any(r["ingress"] == "透明 DNS" and r["outbound"] == "node" and r["result"] == "opened"
               for r in activity()["recent"])
    (root / "wrong-cert").touch()
    control("configure", cfg)
    assert lookup(selected, WAN, "udp") == "rcode 2"
    assert lookup(other, WAN, "udp") == PLAIN
    (root / "wrong-cert").unlink()
    print("DoH via AnyTLS only, UDP/TCP router and external DNS, reverse NAT, device isolation, TC retry and TLS failure PASS", flush=True)


if __name__ == "__main__":
    if sys.argv[1] == "server":
        server(Path(sys.argv[2]))
    else:
        query(*sys.argv[2:])
