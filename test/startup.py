"""Run with the native Linux engine inside an isolated PID and network namespace."""
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time


def test_startup(engine, loader, work):
    slots = work / "slots"
    runtime = work / "run"
    slots.mkdir()
    shutil.copy2(engine, slots / "a")
    (slots / "active").write_text("a\n")
    (slots / "config.json").write_text('{"enabled":true,"default":"direct"}')
    nvram = work / "nvram"
    nvram.write_text('#!/bin/sh\ncase "$2" in\n'
                     'lan_ipaddr) sleep 2; echo 127.0.0.1;;\n'
                     'lan_ifname) echo lo;;\n*) exit 1;;\nesac\n')
    nvram.chmod(0o700)
    env = dict(os.environ, AXPROXY_HOME=str(slots), AXPROXY_RUN=str(runtime),
               PATH=str(work) + ":" + os.environ["PATH"])

    def control(action):
        return subprocess.run([loader, action], env=env, capture_output=True,
                              text=True, timeout=20)

    before = time.monotonic()
    result = control("start")
    print(f"delayed LAN lookup: start rc={result.returncode}, "
          f"elapsed={time.monotonic()-before:.2f}s, "
          f"status={control('status').stdout.strip()}", flush=True)
    assert result.returncode == 0, result.stderr
    try:
        assert control("status").stdout.strip() == "running"
        with socket.create_connection(("127.0.0.1", 6000), timeout=2) as conn:
            conn.sendall(bytes.fromhex("050100"))
            assert conn.recv(2) == bytes.fromhex("0500")
    finally:
        assert control("stop").returncode == 0

    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 6000))
        occupied.listen()
        result = control("start")
        assert result.returncode != 0
        assert control("status").stdout.strip() == "stopped"
        assert not (runtime / "pid").exists()
        assert not (runtime / "ready").exists()
        assert "Address in use" in (runtime / "service.log").read_text()
    assert control("start").returncode == 0
    assert control("status").stdout.strip() == "running"
    assert control("stop").returncode == 0
    # Pause the freshly forked worker before exec and require bounded cleanup.
    slot = slots / "a"
    slot.rename(slots / "engine")
    slot.write_text('#!/bin/sh\nif [ "$1" = serve ]; then\n'
                    ' echo $$ > "$AXPROXY_RUN/stalled"\n kill -STOP $$\nfi\n'
                    'exec "$AXPROXY_HOME/engine" "$@"\n')
    slot.chmod(0o700)
    assert control("start").returncode != 0
    stalled = int((runtime / "stalled").read_text())
    assert not Path(f"/proc/{stalled}").exists()
    assert "readiness timed out" in (runtime / "service.log").read_text()
    assert control("status").stdout.strip() == "stopped"
    print("SOCKS5 greeting, bind failure, timeout cleanup and next start passed")


if __name__ == "__main__":
    if os.getpid() != 1:
        sys.exit("run under unshare --pid --fork --mount-proc --net")
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    with tempfile.TemporaryDirectory() as tmp:
        test_startup(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), Path(tmp))
