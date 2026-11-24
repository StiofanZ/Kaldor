"""IPv6 transparent routing with a reserved dual-stack client and an unselected peer."""
import http.server
import json
from pathlib import Path
import socket
import sys

LAN = "2001:db8:1::1"
PHONE = "2001:db8:1::10"
TEMP = "2001:db8:1::20"
SERVER = "2001:db8:2::2"


def origin():
    class Reflect(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(self.client_address[0].encode())
        def log_message(self, *args):
            pass

    class Server(http.server.ThreadingHTTPServer):
        address_family = socket.AF_INET6
    Server((SERVER, 18480), Reflect).serve_forever()


def verify(root, command, spawn, wait, client, wan, sing, conf, control, activity, peer):
    command("sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")
    for ns, iface, address in [([], "lan0", LAN), (client, "lan0p", PHONE), (client, "lan0p", TEMP),
                              ([], "wan0", "2001:db8:2::1"), (wan, "wan0p", SERVER)]:
        command(*ns, "ip", "-6", "addr", "add", address + "/64", "dev", iface, "nodad")
    command(*client, "ip", "-6", "route", "add", "default", "via", LAN)
    command(*wan, "ip", "-6", "route", "add", "default", "via", "2001:db8:2::1")
    spawn(*wan, sys.executable, __file__, "origin")
    wait(lambda: ":18480" in command(*wan, "ss", "-6ltn"))
    mac = json.loads(command(*client, "ip", "-j", "link", "show", "lan0p"))[0]["address"]
    # An unreserved peer enters the engine and uses its direct outbound.
    def get(src):
        return command(*client, "curl", "-gfsS", "--noproxy", "*", "--max-time", "8",
                       "--interface", src, "http://[" + SERVER + "]:18480/")
    cfg = {"enabled": True, "devices": ["192.0.2.2/32"], "default": "direct",
           "upstreams": [dict(peer, name="node", server="198.51.100.2:19443")],
           "rules": [{"source":"192.0.2.2/32","outbound":"node"}]}
    config = conf("ipv6.json", cfg)
    control("configure", config)
    assert get(PHONE) == "2001:db8:2::1"
    reservations = root / "runtime/reservations"
    reservations.write_text("<" + mac + ">192.0.2.2>>test")
    control("configure", config)
    other = spawn("unshare", "-n", "sleep", "3600")
    import os
    wait(lambda: os.readlink(f"/proc/{other.pid}/ns/net") != os.readlink("/proc/self/ns/net"))
    other_ns = ["nsenter", "-t", str(other.pid), "-n"]
    command(*client, "ip", "link", "add", "link", "lan0p", "unselected", "type", "macvlan", "mode", "bridge")
    command(*client, "ip", "link", "set", "unselected", "netns", other.pid)
    command(*other_ns, "ip", "link", "set", "unselected", "up")
    command(*other_ns, "ip", "-6", "addr", "add", "2001:db8:1::33/64", "dev", "unselected", "nodad")
    command(*other_ns, "ip", "-6", "route", "add", "default", "via", LAN)
    assert command(*other_ns, "curl", "-gfsS", "--noproxy", "*", "--max-time", "6",
                   "http://["+SERVER+"]:18480/") == "2001:db8:2::1"
    for src in (PHONE, TEMP):
        assert get(src) == SERVER, "IPv4 source rule must follow the selected device"
        for proto in ("udp", "tcp"):
            for dst in (LAN, SERVER):
                assert command(*client, sys.executable, str(Path(__file__).with_name("dns.py")),
                               "query", src, dst, proto, "example") == "203.0.113.22"
    cfg["dns"]={"default":"reject","rules":[{"type":"suffix","value":"proxied.test","outbound":"node"}]}
    control("configure",conf("qname-v6.json",cfg))
    for proto in ("udp","tcp"):
        for label, expected in [("www.proxied","2001:db8::22"),("notproxied","rcode 2")]:
            assert command(*client, sys.executable, str(Path(__file__).with_name("dns.py")),
                           "query", TEMP, LAN, proto, label, "AAAA")==expected
    cfg.pop("dns")
    # Real QUIC, including return datagrams and domain recognition, through the remote AnyTLS node.
    hy_server = {"type":"hysteria2","listen":SERVER,"listen_port":18444,
                 "users":[{"password":peer["secret"]}],"tls":{"enabled":True,"certificate_path":str(root/"ca.pem"),"key_path":str(root/"key")}}
    hy_client = {"type":"hysteria2","server":SERVER,"server_port":18444,"password":peer["secret"],
                 "tls":{"enabled":True,"server_name":"peer.test","certificate_path":str(root/"ca.pem")}}
    spawn(*wan,sing,"run","-c",str(conf("quic6-server.json",{"inbounds":[hy_server],"outbounds":[{"type":"direct"}]})))
    wait(lambda: ":18444" in command(*wan,"ss","-uln"))
    spawn(*client,sing,"run","-c",str(conf("quic6-client.json",{"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":18109}],"outbounds":[hy_client]})))
    wait(lambda: ":18109" in command(*client,"ss","-ltn"))
    assert command(*client,"curl","-gfsS","--max-time","10","--noproxy","","-x","socks5h://127.0.0.1:18109","http://["+SERVER+"]:18480/") == SERVER
    rows=activity()["recent"]
    assert any(r["transport"]=="UDP" and r["port"]==18444 and r["target"]=="peer.test" and r["outbound"]=="node" for r in rows)
    reservations.unlink()
    cfg.update(rules=[{"source":PHONE+"/128","destination":SERVER+"/128","outbound":"node"}])
    control("configure",conf("native-v6.json",cfg))
    assert get(PHONE) == SERVER and get(TEMP) == "2001:db8:2::1"
    cfg.pop("devices", None)
    cfg.update(outbound_mode="global", global_outbound="node", rules=[{"port":18480,"outbound":"reject"}])
    control("configure",conf("global-v6.json",cfg))
    assert get(PHONE)==SERVER and get(TEMP)==SERVER
    cfg.update(outbound_mode="direct")
    control("configure",conf("bypass-v6.json",cfg))
    assert control("status")=="running"
    assert get(PHONE)==PHONE and get(TEMP)==TEMP
    control("stop")
    assert "AXPROXY6_LAN" not in command("ip6tables","-t","mangle","-S")
    assert "10891:" not in command("ip","-6","rule","show")
    print("IPv6 MAC and temporary addresses, IPv6 CIDRs, unselected peer, DoH (UDP/TCP), real QUIC via AnyTLS, cleanup PASS",flush=True)


if __name__ == "__main__":
    origin()
