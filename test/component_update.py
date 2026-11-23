"""Exercise the management POST and update worker on Linux using two real builds."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time

current, candidate, ctl = (Path(arg).resolve() for arg in sys.argv[1:])
with tempfile.TemporaryDirectory() as temp:
    base = Path(temp)
    root, run = base / "slots", base / "run"
    env = dict(os.environ, AXPROXY_HOME=str(root), AXPROXY_RUN=str(run),
               PATH=str(base) + ":" + os.environ["PATH"], FIXTURE=temp, BINARY=str(candidate))
    def control(*args, check=True):
        return subprocess.run([ctl, *args], env=env, check=check, capture_output=True, text=True, timeout=15)
    def post(**payload):
        path=base / "request.json"
        path.write_text(json.dumps(payload))
        return control("configure", path, check=False).returncode
    def state(want):
        for _ in range(150):
            if (run/"release.json").exists():
                data=json.loads((run/"release.json").read_text())
                if data["phase"] == want:
                    assert f'data-phase="{want}"' in control("page").stdout
                    return data
            time.sleep(.05)
        raise AssertionError((want, data))
    latest=subprocess.check_output([candidate, "version"],text=True).strip()
    sha=hashlib.sha256(candidate.read_bytes()).hexdigest()
    def manifest(version, digest):
        (base/"manifest").write_text(f"{version} {digest}\n")
    curl=base/"curl"
    curl.write_text('''#!/bin/sh
set -eu
while [ "$1" != --output ]; do shift; done
case "$3" in
 */rt-ax89x.manifest) while [ -e "$FIXTURE/pause" ]; do sleep .1; done; cp "$FIXTURE/manifest" "$2";;
 */kaldor) cp "$BINARY" "$2";;
 *) exit 1;;
esac
''')
    curl.chmod(0o700)
    control("install",current,hashlib.sha256(current.read_bytes()).hexdigest())
    # Simulate a committed installation interrupted before the deferred cleanup ran.
    for _ in range(100):
        if not (root/"prune.pending").exists(): break
        time.sleep(.05)
    (root/"b").write_text("old binary")
    control("start")
    assert (root/"b").exists(), "ordinary start pruned without a committed cleanup intent"
    installed=subprocess.check_output([current,"version"],text=True).strip()
    (root/"prune.pending").write_text(f"{installed}:{(root/'a').stat().st_ino}")
    control("start")
    for _ in range(100):
        if not (root/"prune.pending").exists(): break
        time.sleep(.05)
    assert not (root/"b").exists() and not (root/"prune.pending").exists()
    config=(root/"config.json").read_bytes()
    assert post(component_action="upgrade", version=latest)!=0
    manifest(latest, sha)
    (base/"pause").touch()
    assert post(component_action="check")==0
    state("checking")
    assert post(component_action="check")!=0
    (base/"pause").unlink()
    assert state("available")["version"]==latest
    manifest("9.99.99",sha)
    assert post(component_action="upgrade", version=latest)==0
    state("failed")
    assert (root/"a").exists() and not (root/"b").exists()
    manifest(latest,"0"*64)
    assert post(component_action="check")==0
    state("available")
    assert post(component_action="upgrade",version=latest)==0
    state("failed")
    assert (root/"active").read_text().strip()=="a"
    manifest(latest,sha)
    assert post(component_action="check")==0
    state("available")
    assert post(component_action="upgrade",version=latest)==0
    state("done")
    assert (root/"active").read_text().strip()=="b" and not (root/"a").exists()
    assert hashlib.sha256((root/"b").read_bytes()).hexdigest()==sha
    assert (root/"config.json").read_bytes()==config and control("status").stdout.strip()=="stopped"
    assert post(component_action="check")==0
    state("current")
    print("Management check, duplicate request, changed release, corrupt download, upgrade, cleanup and disabled state PASS")
