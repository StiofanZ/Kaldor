"""Test rule downloads through a SOCKS node and a policy without a live router."""
import hashlib
import http.server
import json
import os
from pathlib import Path
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading


class Rules(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests.append(self.path)
        if self.path == "/start":
            self.send_response(302)
            self.send_header("Location", "rules?rev=1")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(self.server.content)))
        self.end_headers()
        self.wfile.write(self.server.content)

    def log_message(self, *args):
        pass


class Provider(socketserver.StreamRequestHandler):
    def handle(self):
        if self.server.socks:
            assert self.rfile.read(3) == bytes.fromhex("050100")
            self.request.sendall(bytes.fromhex("0500"))
            assert self.rfile.read(4) == bytes.fromhex("05010003")
            assert self.rfile.read(self.rfile.read(1)[0]) == b"provider.invalid"
            assert int.from_bytes(self.rfile.read(2), "big") == 443
            self.request.sendall(bytes.fromhex("05000001000000000000"))
        with self.server.tls.wrap_socket(self.request, server_side=True) as conn:
            Rules(conn, self.client_address, self.server)


def verify(bin_path, root, content):
    cert, key = root/"cert.pem", root/"key.pem"
    subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-days","1",
                    "-subj","/CN=provider.invalid","-addext","subjectAltName=DNS:provider.invalid,IP:127.0.0.1",
                    "-keyout",key,"-out",cert],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert,key)
    env = dict(os.environ, SSL_CERT_FILE=str(cert))
    old, draft = root/"old", root/"draft"
    old.write_text('{"default":"direct"}')
    def merge(cfg, ok=True):
        draft.write_text(json.dumps(cfg))
        res = subprocess.run([bin_path,"merge",draft,old],env=env,capture_output=True,timeout=15)
        assert (res.returncode == 0) == ok, res.stderr.decode()
        if ok:
            return json.loads(res.stdout)
    with socketserver.ThreadingTCPServer(("127.0.0.1",0),Provider) as server:
        server.tls, server.content, server.requests = tls, content, []
        threading.Thread(target=server.serve_forever,daemon=True).start()
        port = server.server_address[1]
        cfg = {"default":"direct","outbound_mode":"direct",
               "upstreams":[{"name":"node","protocol":"socks5","server":f"127.0.0.1:{port}"}],
               "policies":[{"name":"proxy","type":"manual","members":["node"],"selected":"node"}]}
        for outlet in ("direct","node","proxy"):
            server.socks = outlet != "direct"
            host = "provider.invalid" if server.socks else f"127.0.0.1:{port}"
            cfg["rules"] = [{"rule_url":"https://"+host+"/start", "outbound":"reject","download_outbound":outlet}]
            saved = merge(cfg)
            digest = saved["rules"][0]["rule_digest"]
            assert digest == hashlib.sha256(content).hexdigest()
            assert (root/"rule-files"/digest).read_bytes() == content
            assert server.requests == ["/start","/rules?rev=1"]
            server.requests.clear()
            old.write_text(json.dumps(saved))
            assert merge(saved) == saved and not server.requests
        for bad in ("reject","unknown"):
            cfg["rules"][0]["download_outbound"] = bad
            merge(cfg,ok=False)
        assert not server.requests
        server.shutdown()
    print("PASS: direct, SOCKS node and policy, verified HTTPS redirects, cache and invalid outlets")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmp:
        verify(sys.argv[1], Path(tmp), Path(sys.argv[2]).read_bytes() if len(sys.argv)>2 else b"DOMAIN,example.test\n")
