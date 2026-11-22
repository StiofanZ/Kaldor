"""Run as root inside a fresh Linux network namespace. All peers are local."""
import contextlib
import hashlib
import http.server
import json
import os
from pathlib import Path
import secrets
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import uuid

def command(*args, **kwargs):
    return subprocess.run([str(v) for v in args], check=True,
                          capture_output=True, text=True, **kwargs).stdout.strip()

def wait(check):
    for _ in range(200):
        if check():
            return
        time.sleep(.05)
    raise RuntimeError("listener or namespace did not become ready")

def origin():
    class Server(http.server.ThreadingHTTPServer):
        def server_bind(self):
            socketserver.TCPServer.server_bind(self)

    class Echo(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            data = self.client_address[0].encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        def log_message(self, *args):
            pass

    for port in [80,18480,18481,18482]:
        server = Server(("198.51.100.2", port), Echo)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("198.51.100.2", 18482))
        while True:
            data, peer = s.recvfrom(65535)
            s.sendto(data + b"/" + peer[0].encode(), peer)

def probe(root, engine, ctl, sing, xray, upgrade, stack):
    def spawn(*cmd):
        p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        def close():
            p.terminate()
            try:
                p.wait(3)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
        stack.callback(close)
        return p

    assert "lan0" not in command("ip", "link"), "run in a fresh namespace"
    command("ip", "link", "set", "lo", "up")
    def side(name, gateway, endpoint):
        p = spawn("unshare", "-n", "sleep", "3600")
        wait(lambda: os.readlink(f"/proc/{p.pid}/ns/net") != os.readlink("/proc/self/ns/net"))
        ns = ["nsenter", "-t", str(p.pid), "-n"]
        command("ip","link","add",name,"type","veth","peer","name",name+"p")
        command("ip","link","set",name+"p","netns",p.pid)
        command("ip","addr","add",gateway+"/24","dev",name)
        command("ip","link","set",name,"up")
        command(*ns,"ip","link","set","lo","up")
        command(*ns,"ip","addr","add",endpoint+"/24","dev",name+"p")
        command(*ns,"ip","link","set",name+"p","up")
        command(*ns,"ip","route","add","default","via",gateway)
        return ns

    client=side("lan0","192.0.2.1","192.0.2.2")
    command(*client,"ip","addr","add","192.0.2.3/24","dev","lan0p")
    wan=side("wan0","198.51.100.1","198.51.100.2")
    Path("/proc/sys/net/ipv4/ip_forward").write_text("1")
    spawn(*wan,sys.executable,__file__,"origin")
    wait(lambda: ":18482" in command(*wan,"ss","-uln"))
    env = os.environ.copy()
    env.update(AXPROXY_HOME=str(root/"slots"), AXPROXY_RUN=str(root/"runtime"),
               SSL_CERT_FILE=str(root/"ca.pem"), PATH=str(root)+":"+env["PATH"])
    (root/"nvram").write_text('#!/bin/sh\ncase "$2" in lan_ipaddr) echo 192.0.2.1;; lan_ifname) echo lan0;; *) exit 1;; esac\n')
    (root/"nvram").chmod(0o700)
    def control(*args):
        return command(ctl,*args,env=env)
    command("openssl","req","-x509","-newkey","rsa:2048","-nodes","-days","1",
            "-subj","/CN=peer.test","-addext","subjectAltName=DNS:peer.test","-keyout",root/"key","-out",root/"ca.pem")
    secret=secrets.token_hex(24)
    sing_conf={"log":{"level":"error"},"inbounds":[
        {"type":"anytls","tag":"any","listen":"127.0.0.1","listen_port":19443,
         "users":[{"name":"test","password":secret}],
         "tls":{"enabled":True,"certificate_path":str(root/"ca.pem"),"key_path":str(root/"key")}},
        {"type":"socks","tag":"socks","listen":"127.0.0.1","listen_port":19080}],
        "outbounds":[{"type":"direct","tag":"direct"}]}
    hybrid_target = os.environ.get("KALDOR_TEST_HYBRID") == "1"
    if hybrid_target:
        # Require real ML-KEM decapsulation on the client when Xray relays this ServerHello.
        import copy
        tls_target = copy.deepcopy(sing_conf["inbounds"][0])
        tls_target.update(tag="tls-target", listen_port=19445)
        tls_target["tls"].update(curve_preferences=["X25519MLKEM768"], alpn=["h2","http/1.1"])
        sing_conf["inbounds"].append(tls_target)
    def conf(name, value):
        p=root/name
        p.write_text(json.dumps(value));p.chmod(0o600)
        return p
    spawn(sing,"run","-c",str(conf("sing.json",sing_conf)))
    wait(lambda: ":19443" in command("ss","-ltn"))
    if not hybrid_target:
        spawn("openssl","s_server","-accept","127.0.0.1:19445","-cert",str(root/"ca.pem"),"-key",str(root/"key"),"-tls1_3","-alpn","h2,http/1.1","-groups","X25519","-num_tickets","1","-ign_eof","-www")
    wait(lambda: ":19445" in command("ss","-ltn"))
    keys=[v.split(":",1)[1].strip() for v in command(xray,"x25519").splitlines()]
    user=str(uuid.uuid4())
    vision_user=str(uuid.uuid4())
    sid=secrets.token_hex(4)
    xconf={"log":{"loglevel":"debug","error":str(root/"xray.log")},"inbounds":[{"port":19444,"listen":"127.0.0.1","protocol":"vless","settings":{
        "clients":[{"id":user},{"id":vision_user,"flow":"xtls-rprx-vision"}],"decryption":"none"},"streamSettings":{"network":"tcp","security":"reality",
        "realitySettings":{"target":"127.0.0.1:19445","serverNames":["peer.test"],"privateKey":keys[0],"shortIds":[sid]}}}],
        "outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","network":"tcp,udp","ip":["198.51.100.2/32"],"port":"80,18480-18482"}]}}]}
    spawn(xray,"run","-c",str(conf("xray.json",xconf)))
    wait(lambda: ":19444" in command("ss","-ltn"))
    checksum=hashlib.sha256(engine.read_bytes()).hexdigest()
    control("install",engine,checksum)
    stack.callback(lambda: control("stop"))
    assert control("status")=="stopped"
    peers=[
        {"protocol":"anytls","server":"127.0.0.1:19443","server_name":"peer.test","secret":secret},
        {"protocol":"socks5","server":"127.0.0.1:19080"},
        {"protocol":"vless-reality","server":"127.0.0.1:19444","server_name":"peer.test","public_key":keys[1],"short_id":sid,"secret":user}]
    peers.append(dict(peers[-1],flow="xtls-rprx-vision",secret=vision_user))
    def get(port,*flags):
        return command(*client,"curl","-fsS","--max-time","8",*flags,f"http://198.51.100.2:{port}/")
    for p in peers:
        cfg={"enabled":True,"devices":["192.0.2.2/32"],"upstreams":[dict(name="node",**p)],"default":"node",
             "rules":[{"port":18481,"outbound":"reject"},{"domain_suffix":"blocked.example","outbound":"reject"}]}
        emulator=os.environ.get("KALDOR_TEST_QEMU")
        if emulator:
            arm=Path(os.environ["KALDOR_TEST_ARM"]).resolve()
            ready=root/"arm-ready"
            target_config=conf("arm.json",dict(cfg,devices=[]))
            target=subprocess.Popen([emulator,str(arm),"serve",str(target_config),"127.0.0.1","lo",str(ready)],env=env)
            try:
                wait(lambda: ready.exists() or target.poll() is not None)
                assert target.poll() is None,"ARMv7 manual listener"
                for addr in ["http://127.0.0.1:7890","socks5h://127.0.0.1:7891"]:
                    assert command("curl","--noproxy","","-x",addr,"-fsS","--max-time","8","http://198.51.100.2:18480")=="198.51.100.1"
                print("ARMv7 HTTP/SOCKS5",p["protocol"],p.get("flow",""),"PASS",flush=True)
            finally:
                target.terminate();target.wait(5)
        control("configure",conf("input.json",cfg))
        assert control("status")=="running"
        assert all(not x["secret"] if "secret" in x else True for x in json.loads(control("view"))["upstreams"])
        for proto,port in [("http",7890),("socks5h",7891)]:
            assert get(18480,"--noproxy","","-x",f"{proto}://192.0.2.1:{port}")=="198.51.100.1",(p["protocol"],proto)
        assert get(18480,"--noproxy","","--proxytunnel","-x","http://192.0.2.1:7890")=="198.51.100.1"
        assert get(18480,"--noproxy","*")=="198.51.100.1","transparent TCP"
        assert get(18481,"--noproxy","*","--interface","192.0.2.3")=="192.0.2.3","unselected"
        try: get(18481,"--noproxy","*")
        except subprocess.CalledProcessError: pass
        else: raise AssertionError("reject rule")
        assert command(*client,sys.executable,"-c",
            "import socket;s=socket.socket(2,2);s.settimeout(8);s.sendto(b'udp',('198.51.100.2',18482));print(s.recv(64).decode())")=="udp/198.51.100.1","transparent UDP"
        try:
            command(*client,"curl","--noproxy","*","-fsS","--max-time","3","--resolve","blocked.example:80:198.51.100.2","http://blocked.example/")
        except subprocess.CalledProcessError: pass
        else: raise AssertionError("transparent HTTP domain rule")
        assert command(*client,"curl","--noproxy","*","-fsS","--resolve","allowed.example:80:198.51.100.2","http://allowed.example/")=="198.51.100.1"
        assert command(*client,sys.executable,__file__,"socks-udp")=="udp/198.51.100.1"
        print(p["protocol"],p.get("flow",""),"HTTP, CONNECT, SOCKS5, transparent TCP/UDP, bypass and reject PASS",flush=True)
    edited = json.loads(control("view"))
    edited["upstreams"][0].update(previous_name="node", name="renamed")
    edited.update(default="reject", rules=[{"port": 18480, "outbound": "renamed"}])
    control("configure", conf("edit.json", edited))
    assert get(18480, "--noproxy", "", "-x", "http://192.0.2.1:7890") == "198.51.100.1"
    try:
        get(18481, "--noproxy", "", "-x", "http://192.0.2.1:7890")
    except subprocess.CalledProcessError:
        pass
    else:
        raise AssertionError("new default reject was ignored")
    view = json.loads(control("view"))
    assert view["default"] == "reject" and not view["upstreams"][0].get("secret")
    assert "previous_name" not in json.loads((root/"slots/config.json").read_text())["upstreams"][0]
    control("configure", conf("restore.json", cfg))
    print("rename with masked credentials, switch default, rule precedence PASS", flush=True)
    # Same device, address and port: only the transport distinguishes these flows.
    def tcp_split(*flags):
        return get(18482, "--noproxy", "*", *flags)
    def udp_split():
        return command(*client, sys.executable, "-c",
            "import socket;s=socket.socket(2,2);s.settimeout(5);s.sendto(b'udp',('198.51.100.2',18482));print(s.recv(64).decode())")
    assert tcp_split() == "198.51.100.1"
    rules = [{"source":"192.0.2.2/32", "port":18482, "network":"tcp", "outbound":"reject"},
             {"port":18482, "network":"udp", "outbound":"node"}]
    control("configure", conf("split.json", dict(cfg, rules=rules, default="direct")))
    for flags in [("--noproxy", "*"), ("--noproxy", "", "-x", "http://192.0.2.1:7890"),
                  ("--noproxy", "", "-x", "socks5h://192.0.2.1:7891")]:
        try:
            get(18482, *flags)
        except subprocess.CalledProcessError:
            pass
        else:
            raise AssertionError(("TCP rule ignored", flags))
    assert get(18482, "--interface", "192.0.2.3", "--noproxy", "", "-x", "http://192.0.2.1:7890") == "198.51.100.1"
    assert tcp_split("--interface", "192.0.2.3") == "192.0.2.3"
    assert udp_split() == "udp/198.51.100.1"
    assert command(*client, sys.executable, __file__, "socks-udp") == "udp/198.51.100.1"
    # A failing default proves UDP reached the named node through its rule.
    control("configure", conf("split.json", dict(cfg, rules=rules, default="reject")))
    assert udp_split() == "udp/198.51.100.1"
    invalid = dict(cfg, rules=[{"domain_suffix":".", "outbound":"reject"}])
    try:
        control("configure", conf("invalid.json", invalid))
    except subprocess.CalledProcessError:
        pass
    else:
        raise AssertionError("empty domain label accepted")
    assert json.loads(control("view"))["rules"] == rules
    assert udp_split() == "udp/198.51.100.1"
    control("configure", conf("restore.json", cfg))
    print("same-port TCP/UDP, per-device selection, invalid edit preserves routing PASS", flush=True)
    before=(root/"slots/config.json").read_bytes()
    try:control("install",engine,"0"*64)
    except subprocess.CalledProcessError:pass
    else:raise AssertionError("checksum mismatch accepted")
    bad=root/"bad"
    bad.write_text('#!/bin/sh\nif [ "$1" = serve ]; then exit 1; fi\nexec "'+str(engine)+'" "$@"\n')
    bad.chmod(0o700)
    try:control("install",bad,hashlib.sha256(bad.read_bytes()).hexdigest())
    except subprocess.CalledProcessError:pass
    else:raise AssertionError("broken candidate accepted")
    assert (root/"slots/active").read_text().strip()=="a" and control("status")=="running"
    assert get(18480,"--noproxy","*")=="198.51.100.1"
    assert command(upgrade,"version")!=command(engine,"version")
    control("install",upgrade,hashlib.sha256(upgrade.read_bytes()).hexdigest())
    assert (root/"slots/active").read_text().strip()=="b" and command(root/"slots/b","version")==command(upgrade,"version")
    assert control("status")=="running" and before==(root/"slots/config.json").read_bytes()
    assert get(18480,"--noproxy","*")=="198.51.100.1"
    # Real versions share a config: restart the Rust candidate from the prior slot.
    control("rollback")
    assert (root/"slots/active").read_text().strip()=="a"
    assert control("status")=="running" and before==(root/"slots/config.json").read_bytes()
    assert get(18480,"--noproxy","*")=="198.51.100.1"
    control("rollback")
    assert command(root/"slots/b","version")==command(upgrade,"version")
    control("install",engine,checksum)
    assert (root/"slots/active").read_text().strip()=="a"
    assert control("status")=="running" and before==(root/"slots/config.json").read_bytes()
    assert get(18480,"--noproxy","*")=="198.51.100.1"
    control("firewall")
    assert control("status")=="running"
    os.kill(int((root/"runtime/pid").read_text()),9)
    wait(lambda: not (root/"runtime/firewall").exists())
    assert control("status")=="stopped"
    control("start");assert control("status")=="running"
    control("stop")
    assert "AXPROXY_LAN" not in command("iptables","-t","mangle","-S")
    assert "10891:" not in command("ip","rule","show")
    print("install, upgrade, checksum rejection, rollback, firewall cleanup PASS")

if __name__=="__main__":
    if sys.argv[1:]==["origin"]:origin()
    elif sys.argv[1:]==["socks-udp"]:
        with socket.create_connection(("192.0.2.1",7891),timeout=5) as control:
            control.sendall(bytes.fromhex("050100"));assert control.recv(2)==bytes.fromhex("0500")
            control.sendall(bytes.fromhex("05030001000000000000"))
            fp=control.makefile("rb");head=fp.read(4);assert head==bytes.fromhex("05000001")
            addr=socket.inet_ntoa(fp.read(4));port=int.from_bytes(fp.read(2),"big")
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as u:
                u.settimeout(5);header=bytes.fromhex("00000001")+socket.inet_aton("198.51.100.2")+(18482).to_bytes(2,"big")
                u.sendto(header+b"udp",(addr,port));response=u.recv(128);assert response.startswith(header);print(response[len(header):].decode())
    else:
        if os.readlink("/proc/self/ns/net")==os.readlink("/proc/1/ns/net"):
            sys.exit("run inside a fresh network namespace")
        with tempfile.TemporaryDirectory() as temp, contextlib.ExitStack() as stack:
            try:
                probe(Path(temp),*(Path(a).resolve() for a in sys.argv[1:]),stack)
            except Exception:
                log=Path(temp)/"runtime/service.log"
                if log.is_file():
                    print(log.read_text()[-4500:],file=sys.stderr)
                xlog=Path(temp)/"xray.log"
                if xlog.exists(): print(xlog.read_text()[-1800:],file=sys.stderr)
                raise
