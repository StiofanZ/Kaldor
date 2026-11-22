"""Run the shipped updater locally with a simulated Release and component slots."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile

UPDATER = Path(__file__).resolve().parents[1] / "kaldor-update"


def script(path, body):
    path.write_text("#!/bin/sh\nset -eu\n" + body + "\n")
    path.chmod(0o700)


with tempfile.TemporaryDirectory() as temp:
    base = Path(temp)
    slots = base / "slots"
    slots.mkdir()
    version = "0.10.0"
    script(slots / "a", "echo 0.9.9")
    (slots / "active").write_text("a\n")
    script(base / "binary", "echo " + version)
    digest = hashlib.sha256((base / "binary").read_bytes()).hexdigest()
    script(base / "curl", '''
while [ "$1" != --output ]; do shift; done
case "$3" in
 https://github.com/StiofanZ/Kaldor/releases/latest/download/rt-ax89x.manifest) cp "$FIXTURE/manifest" "$2";;
 https://github.com/StiofanZ/Kaldor/releases/download/v0.10.0/kaldor) cp "$FIXTURE/binary" "$2";;
 *) exit 1;;
esac''')
    script(base / "ctl", '''
case "$1" in
 install) cp "$2" "$AXPROXY_HOME/b"; echo b > "$AXPROXY_HOME/active"; echo install >> "$FIXTURE/events";;
 status) echo running;;
 *) exit 1;;
esac''')
    env = dict(os.environ, PATH=f"{base}:{os.environ['PATH']}", FIXTURE=temp,
               AXPROXY_HOME=str(slots), AXPROXY_RUN=str(base / "run"), AXPROXY_CTL=str(base / "ctl"))
    def call(action):
        return subprocess.run([str(UPDATER), action], capture_output=True, text=True, env=env)
    manifest = base / "manifest"
    manifest.write_text(f"{version} {digest}\n")
    checked = call("check")
    assert "decision=upgrade" in checked.stdout, checked.stderr
    for invalid in ["bad", f"{version} {'0'*64}", f"00.10.0 {digest}", f"{version} {digest}\nextra"]:
        manifest.write_text(invalid + "\n")
        assert call("upgrade").returncode != 0
    manifest.write_text(f"{version} {digest}\n")
    script(base / "binary", "echo 0.8.0")
    mismatch = hashlib.sha256((base / "binary").read_bytes()).hexdigest()
    manifest.write_text(f"{version} {mismatch}\n")
    assert "binary version" in call("upgrade").stderr
    assert not (base / "events").exists()
    script(base / "binary", "echo " + version)
    manifest.write_text(f"{version} {digest}\n")
    applied = call("upgrade")
    assert applied.returncode == 0, applied.stderr
    assert "decision=current" in call("upgrade").stdout
    manifest.write_text(f"0.2.2 {digest}\n")
    assert "decision=newer" in call("upgrade").stdout
    assert (base / "events").read_text() == "install\n"
    print("Release discovery, hash and version rejection, install, no-op and downgrade protection PASS")
