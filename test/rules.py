"""Exercise a pinned remote provider using a local HTTPS origin in the interop namespace."""
import http.server
import json
import ssl
import subprocess
import threading

def verify(root, env, conf, control, get):
    class Provider(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(self.server.content)
        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1",0), Provider)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(root/"ca.pem",root/"key")
    server.socket = tls.wrap_socket(server.socket,server_side=True)
    env["SSL_CERT_FILE"] = str(root/"ca.pem")
    env["NO_PROXY"] = "127.0.0.1"
    threading.Thread(target=server.serve_forever,daemon=True).start()
    def manual(port):
        return get(port,"--noproxy","","-x","http://192.0.2.1:6000")
    def rejected(port):
        try: manual(port)
        except subprocess.CalledProcessError: return
        raise AssertionError("request should have been rejected")
    try:
        url=f"https://127.0.0.1:{server.server_port}/rules"
        cfg={"enabled":True,"default":"reject","rules":[{"rule_url":url,"outbound":"direct"},{"standard":"MATCH","outbound":"reject"}]}
        server.content=b"payload:\n  - DST-PORT,18480\n"
        control("configure",conf("remote.json",cfg))
        saved=(root/"slots/config.json").read_bytes()
        digest=json.loads(saved)["rules"][0]["rule_digest"]
        cache=root/"slots/rule-files"
        assert (cache/digest).read_bytes()==server.content
        assert manual(18480)=="198.51.100.1"
        rejected(18481)
        pid=(root/"runtime/pid").read_bytes()
        server.content=b"GEOIP,CN\n"
        try: control("configure",conf("remote.json",cfg))
        except subprocess.CalledProcessError: pass
        else: raise AssertionError("invalid update accepted")
        assert saved==(root/"slots/config.json").read_bytes() and pid==(root/"runtime/pid").read_bytes()
        assert manual(18480)=="198.51.100.1"
        server.content=b"DST-PORT,18481\n"
        control("configure",conf("remote.json",cfg))
        assert not (cache/digest).exists()
        rejected(18480)
        assert manual(18481)=="198.51.100.1"
    finally:
        server.shutdown()
        server.server_close()
    control("stop")
    control("start")
    assert manual(18481)=="198.51.100.1"
    print("HTTPS rules: first match, invalid refresh preserves worker/config, replacement, pruning and offline restart PASS",flush=True)
