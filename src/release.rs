use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::ErrorKind,
    os::unix::fs::MetadataExt,
    path::Path,
    process::{Command, Stdio},
};

#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
pub struct State {
    phase: String,
    version: String,
}

fn state(dir: &Path) -> State {
    fs::read(dir.join("release.json"))
        .ok()
        .and_then(|data| serde_json::from_slice(&data).ok())
        .unwrap_or_default()
}

fn save(dir: &Path, phase: &str, version: &str) -> Result<()> {
    let tmp = dir.join("release.json.new");
    fs::write(
        &tmp,
        serde_json::to_vec(&State {
            phase: phase.into(),
            version: version.into(),
        })?,
    )?;
    fs::rename(tmp, dir.join("release.json"))?;
    Ok(())
}

fn stable(s: &str) -> bool {
    let parts: Vec<_> = s.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.bytes().all(|b| b.is_ascii_digit())
                && (p.len() == 1 || !p.starts_with('0'))
        })
}

pub fn page(dir: &Path) -> Result<String> {
    let mut snapshot = state(dir);
    if matches!(snapshot.phase.as_str(), "checking" | "upgrading") {
        let lock = File::open(dir.join("web-release.lock"))?;
        if lock.try_lock().is_ok() {
            snapshot = state(dir);
            if matches!(snapshot.phase.as_str(), "checking" | "upgrading") {
                snapshot.phase = "failed".into();
            }
        }
    }
    // Only known updater states and stable numeric versions enter HTML attributes.
    if !matches!(
        snapshot.phase.as_str(),
        "checking" | "upgrading" | "available" | "current" | "newer" | "done" | "failed"
    ) {
        snapshot.phase.clear();
    }
    if !stable(&snapshot.version) {
        snapshot.version.clear();
    }
    Ok(include_str!("../panel.html")
        .replace("COMPONENT_VERSION", crate::VERSION)
        .replace("RELEASE_PHASE", &snapshot.phase)
        .replace("RELEASE_VERSION", &snapshot.version))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    component_action: String,
    #[serde(default)]
    version: String,
}

// All other POST bodies use the existing configuration merge and validation.
pub fn submit(file: &Path, dir: &Path) -> Result<()> {
    if fs::metadata(file)?.len() > 256 {
        println!("configure");
        return Ok(());
    }
    let Ok(req) = serde_json::from_slice::<Request>(&fs::read(file)?) else {
        println!("configure");
        return Ok(());
    };
    let phase = match req.component_action.as_str() {
        "check" if req.version.is_empty() => "checking",
        "upgrade" if stable(&req.version) => "upgrading",
        _ => bail!("invalid release request"),
    };
    let lock = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join("web-release.lock"))?;
    lock.try_lock()
        .context("release operation already in progress")?;
    if phase == "upgrading" {
        let previous = state(dir);
        ensure!(
            previous.phase == "available" && previous.version == req.version,
            "check the selected release first"
        );
    }
    save(dir, phase, &req.version)?;
    // The worker inherits this open file description as stdin and holds its flock until exit.
    let spawned = Command::new("/proc/self/exe")
        .arg("release-worker")
        .arg(dir)
        .arg(req.component_action)
        .arg(req.version)
        .stdin(Stdio::from(lock))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    if let Err(err) = spawned {
        save(dir, "failed", "")?;
        return Err(err.into());
    }
    println!("queued");
    Ok(())
}

pub fn worker(dir: &Path, action: &str, expected: &str) -> Result<()> {
    let result = (|| -> Result<()> {
        let output = Command::new("sh")
            .args([
                "-c",
                include_str!("../kaldor-update"),
                "kaldor-update",
                action,
            ])
            .env("KALDOR_EXPECTED_VERSION", expected)
            .stdin(Stdio::null())
            .output()?;
        if !output.status.success() {
            fs::write(dir.join("release-error.log"), &output.stderr)?;
            bail!("release operation failed");
        }
        let stdout = std::str::from_utf8(&output.stdout)?;
        let mut fields = stdout
            .lines()
            .next()
            .context("missing release metadata")?
            .split_whitespace();
        fields
            .next()
            .and_then(|s| s.strip_prefix("installed="))
            .context("missing installed version")?;
        let version = fields
            .next()
            .and_then(|s| s.strip_prefix("release="))
            .filter(|v| stable(v))
            .context("invalid stable version")?;
        let phase = match (action, fields.next()) {
            ("check", Some("decision=upgrade")) => "available",
            ("check", Some("decision=current")) => "current",
            ("check", Some("decision=newer")) => "newer",
            ("upgrade", _) if version == expected => "done",
            _ => bail!("unexpected release decision"),
        };
        save(dir, phase, version)
    })();
    if result.is_err() {
        save(dir, "failed", "")?;
    }
    result
}

// Persist the intent before the firmware commits the slot. The inode survives its rename.
fn identity(m: &fs::Metadata) -> String {
    format!("{}:{}", crate::VERSION, m.ino())
}

pub fn mark_candidate(root: &Path) -> Result<()> {
    let candidate = fs::metadata(root.join("candidate"))?;
    let me = fs::metadata("/proc/self/exe")?;
    ensure!(
        candidate.dev() == me.dev() && candidate.ino() == me.ino(),
        "not the installation candidate"
    );
    let tmp = root.join("prune.pending.new");
    fs::write(&tmp, identity(&me))?;
    fs::rename(tmp, root.join("prune.pending"))?;
    Ok(())
}

// Both the deployed firmware loader and the packaged loader serialize slot changes on this lock.
pub fn prune(root: &Path, run: &Path) -> Result<()> {
    let lock = File::open(run.join("lock"))?;
    lock.lock()?;
    let (active, old) = match fs::read_to_string(root.join("active"))?.trim() {
        "a" => ("a", "b"),
        "b" => ("b", "a"),
        _ => bail!("invalid active slot"),
    };
    let active_inode = fs::metadata(root.join(active))?;
    let same = |p: &Path| -> Result<bool> {
        let m = fs::metadata(p)?;
        Ok(m.dev() == active_inode.dev() && m.ino() == active_inode.ino())
    };
    ensure!(
        same(Path::new("/proc/self/exe"))?,
        "candidate did not become active"
    );
    let cfg = crate::config::Config::read(
        root.join("config.json")
            .to_str()
            .context("invalid config path")?,
    )?;
    cfg.validate()?;
    if cfg.enabled {
        let pid = fs::read_to_string(run.join("pid"))?.trim().parse::<u32>()?;
        ensure!(
            same(&Path::new("/proc").join(pid.to_string()).join("exe"))?
                && fs::read_to_string(run.join("ready"))? == crate::VERSION
                && !run.join("routing-error").exists(),
            "active service is not ready"
        );
    }
    let pending = root.join("prune.pending");
    match fs::read_to_string(&pending) {
        Ok(intent) if intent == identity(&active_inode) => {}
        Ok(_) => bail!("cleanup belongs to another installation"),
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    }
    match fs::remove_file(root.join(old)) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    fs::remove_file(pending)?;
    Ok(())
}
