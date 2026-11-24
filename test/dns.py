"""Network-namespace regression for transparent DNS. All answers are synthetic."""
import http.server
import json
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
DIRECT_DOH = "203.0.113.33"


def response(query, addr):
    count = 40 if b"oversize" in query else 1
    qtype = int.from_bytes(query[-4:-2], "big")
    data = socket.inet_pton(socket.AF_INET6, "2001:db8::"+addr.split(".")[-1]) if qtype==28 else socket.inet_aton(addr)
    rr = struct.pack("!HHHIH", 0xc00c, qtype, 1, 1, len(data)) + data
    return query[:2] + struct.pack("!5H", 0x8180, 1, count, 0, 0) + query[12:] + rr * count


class Doh(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        assert self.headers["Host"] == AUTHORITY and self.path == "/dns-query"
        assert self.headers["Content-Type"] == "application/dns-message"
        query = self.rfile.read(int(self.headers["Content-Length"]))
        body = response(query, DIRECT_DOH if self.client_address[0]=="198.51.100.1" else ENCRYPTED)
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


def query(src, dst, proto, label, qtype="A"):
    tx = secrets.token_bytes(2)
    qname=b"".join(bytes([len(part)])+part.encode() for part in (label+".test").split("."))+b"\0"
    data=tx+bytes.fromhex("01000001000000000000")+qname+struct.pack("!HH",28 if qtype=="AAAA" else 1,1)
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
        print(socket.inet_ntop(socket.AF_INET6,reply[-16:]) if qtype=="AAAA" else socket.inet_ntoa(reply[-4:]))


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

    def lookup(src, dst, proto, label="example", qtype="A"):
        return command(*client, sys.executable, script, "query", src, dst, proto, label, qtype)

    for proto in ("udp", "tcp"):
        for dst in (WAN, "192.0.2.1"):
            assert lookup(selected, dst, proto) == ENCRYPTED
        assert lookup(other, WAN, proto) == ENCRYPTED
    assert lookup(selected, WAN, "udp", "oversize") == "truncated"
    assert lookup(selected, WAN, "tcp", "oversize") == ENCRYPTED
    assert any(r["ingress"] == "透明 DNS" and r["outbound"] == "node" and r["result"] == "opened"
               for r in activity()["recent"])
    (root / "wrong-cert").touch()
    control("configure", cfg)
    assert lookup(selected, WAN, "udp") == "rcode 2"
    assert lookup(other, WAN, "udp") == "rcode 2"
    (root / "wrong-cert").unlink()
    modes = json.loads(cfg.read_text())
    modes.pop("devices", None)
    modes.update(global_outbound="node", rules=[{"port":443,"outbound":"reject"}])
    # The DoH test server returns a different answer for a direct TCP peer and a proxy peer.
    command("ip","route","replace",PUBLIC+"/32","via",WAN,"dev","wan0")
    settings=dict(modes, default="reject", rules=[{"standard":"DOMAIN,listed.test","outbound":"node"}],
                  policies=[{"name":"selected","type":"manual","members":["node"],"selected":"node"}],
                  dns={"default":"@rules","rules":[
                      {"type":"exact","value":"safe.blocked.test","outbound":"direct"},
                      {"type":"suffix","value":"BLOCKED.test.","outbound":"selected"},
                      {"type":"keyword","value":"local","outbound":"direct"}]})
    control("configure",conf("query-routing.json",settings))
    for proto in ("udp","tcp"):
        for kind in ("A","AAAA"):
            for label,expected in [("blocked",ENCRYPTED),("www.blocked",ENCRYPTED),("safe.blocked",DIRECT_DOH),
                                   ("localname",DIRECT_DOH),("listed",ENCRYPTED),("notblocked","rcode 2")]:
                want="2001:db8::"+expected.split(".")[-1] if kind=="AAAA" and "." in expected else expected
                assert lookup(selected,WAN,proto,label,kind)==want,(label,proto,kind)
    records=[r for r in activity()["recent"] if r["ingress"]=="透明 DNS"]
    assert {"node","direct","reject"} <= {r["outbound"] for r in records}
    assert all(r["target"]==AUTHORITY for r in records)
    # The direct DoH path still works when the selected proxy fails.
    broken=dict(settings,upstreams=[dict(settings["upstreams"][0],server=WAN+":19446")])
    control("configure",conf("query-failure.json",broken))
    assert lookup(selected,WAN,"udp","blocked")=="rcode 2"
    assert lookup(selected,WAN,"udp","safe.blocked")==DIRECT_DOH
    command("ip","route","replace","unreachable",PUBLIC+"/32")
    modes["dns"]={"default":"reject","rules":[]}
    print("DNS query policy: on-wire direct/proxy answers, A/AAAA over UDP/TCP, domain precedence, ordinary rules and no direct retry PASS",flush=True)
    for mode, expected in [("global",ENCRYPTED),("direct",PLAIN),("rules","rcode 2")]:
        modes["outbound_mode"] = mode
        control("configure", conf("dns-mode.json", modes))
        for source in (selected, other):
            for proto in ("udp","tcp"):
                assert lookup(source, WAN, proto) == expected, (mode, source, proto)
        if mode == "direct":
            control("firewall")
            assert control("status") == "running"
            for args in [("iptables","-t","mangle","-S"),("iptables","-t","nat","-S"),("ip6tables","-t","mangle","-S")]:
                assert "AXPROXY" not in command(*args)
            for family in ("-4","-6"):
                assert "10891:" not in command("ip",family,"rule","show")
            assert ":6000 " in command("ss","-ltn")
            assert ":7893 " not in command("ss","-ltun")
    print("DoH via AnyTLS only, UDP/TCP router and external DNS, reverse NAT, all LAN sources, global/bypass/rules switches, TC retry and TLS failure PASS", flush=True)


if __name__ == "__main__":
    if sys.argv[1] == "server":
        server(Path(sys.argv[2]))
    else:
        query(*sys.argv[2:])
