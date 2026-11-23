use super::*;
use anyhow::bail;
use ring::digest::{SHA256, digest};
use std::{
    fs,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const MAX_FILE: usize = 1024 * 1024;
const MAX_ENTRIES: usize = 16384;
fn fingerprint(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect()
}
fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

impl Rule {
    pub(super) fn validate_source(&self, conditions: bool) -> Result<()> {
        let remote = !self.rule_url.is_empty();
        ensure!(
            usize::from(conditions) + usize::from(remote) + usize::from(!self.standard.is_empty())
                == 1,
            "choose one rule type"
        );
        ensure!(
            self.rule_digest.is_empty() || (remote && is_digest(&self.rule_digest)),
            "invalid rule file digest"
        );
        if remote {
            let url = self.rule_url.parse::<hyper::Uri>()?;
            ensure!(
                url.scheme_str() == Some("https")
                    && url.host().is_some_and(|h| !h.is_empty())
                    && !url.authority().unwrap().as_str().contains('@')
                    && self.rule_url.len() <= 2048,
                "expected HTTPS rules URL"
            );
        } else if !self.standard.is_empty() {
            parse_condition(&self.standard, &self.outbound)?;
        }
        Ok(())
    }
}

fn parse_condition(line: &str, outbound: &str) -> Result<Rule> {
    let mut parts = line.split(',').map(str::trim);
    let kind = parts.next().unwrap_or("").to_ascii_uppercase();
    let value = parts.next();
    let mut rule = Rule {
        outbound: outbound.to_owned(),
        ..Default::default()
    };
    if kind == "MATCH" {
        ensure!(value.is_none(), "MATCH takes no value");
        return Ok(rule);
    }
    let value = value
        .filter(|s| !s.is_empty())
        .context("missing rule value")?;
    let option = parts.next();
    ensure!(
        parts.next().is_none()
            && (option.is_none()
                || (matches!(kind.as_str(), "IP-CIDR" | "IP-CIDR6")
                    && option == Some("no-resolve"))),
        "unsupported rule option or embedded outbound"
    );
    match kind.as_str() {
        "DOMAIN" | "DOMAIN-SUFFIX" => {
            let domain = value.strip_suffix('.').unwrap_or(value);
            ensure!(
                domain.len() <= 253
                    && domain.split('.').all(|l| !l.is_empty()
                        && l.len() <= 63
                        && l.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')),
                "invalid DNS name"
            );
            if kind == "DOMAIN" {
                rule.domain = domain.into()
            } else {
                rule.domain_suffix = domain.into()
            }
        }
        "DOMAIN-KEYWORD" => {
            ensure!(
                value.len() <= 253
                    && value.is_ascii()
                    && !value
                        .bytes()
                        .any(|v| v.is_ascii_whitespace() || v.is_ascii_control()),
                "invalid domain keyword"
            );
            rule.domain_keyword = value.into();
        }
        "IP-CIDR" | "IP-CIDR6" => {
            let net: IpNet = value.parse()?;
            ensure!(
                kind != "IP-CIDR6" || matches!(net, IpNet::V6(_)),
                "IPv6 CIDR required"
            );
            rule.destination = Some(net);
        }
        "SRC-IP-CIDR" => rule.source = Some(value.parse()?),
        "DST-PORT" => rule.port = value.parse::<NonZeroU16>()?.get(),
        "NETWORK" => {
            rule.network = Some(match value.to_ascii_lowercase().as_str() {
                "tcp" => Network::Tcp,
                "udp" => Network::Udp,
                _ => bail!("expected TCP or UDP"),
            })
        }
        _ => bail!("unsupported rule type"),
    }
    Ok(rule)
}

// Accept text lines or a YAML payload containing a block list of plain/quoted scalar rules.
fn parse_file(bytes: &[u8], outbound: &str, budget: usize) -> Result<Vec<Rule>> {
    ensure!(bytes.len() <= MAX_FILE, "rule file exceeds 1 MiB");
    let text = std::str::from_utf8(bytes)?.trim_start_matches('\u{feff}');
    let mut rules = Vec::new();
    let mut yaml = false;
    for (idx, line) in text.lines().enumerate() {
        let line = line.split_once(" #").map_or(line, |(s, _)| s).trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "payload:" && !yaml && rules.is_empty() {
            yaml = true;
            continue;
        }
        let parsed = (|| -> Result<_> {
            ensure!(rules.len() < budget, "too many rule entries");
            let mut item = if yaml {
                line.strip_prefix("- ")
                    .context("expected YAML list item")?
                    .trim()
            } else {
                line
            };
            if item.starts_with(['\'', '"']) {
                ensure!(
                    item.len() >= 2 && item.as_bytes().first() == item.as_bytes().last(),
                    "unclosed quote"
                );
                item = &item[1..item.len() - 1];
            }
            if item.contains(',') || item.eq_ignore_ascii_case("MATCH") {
                parse_condition(item, outbound)
            } else if item.parse::<IpNet>().is_ok() {
                parse_condition(&format!("IP-CIDR,{item}"), outbound)
            } else if let Some(suffix) = item.strip_prefix("+.") {
                parse_condition(&format!("DOMAIN-SUFFIX,{suffix}"), outbound)
            } else {
                parse_condition(&format!("DOMAIN,{item}"), outbound)
            }
        })()
        .with_context(|| format!("rule file line {}", idx + 1))?;
        rules.push(parsed)
    }
    ensure!(!rules.is_empty(), "empty rule file");
    Ok(rules)
}

fn download(url: &str, seconds: u64) -> Result<Vec<u8>> {
    let mut curl = Command::new("curl")
        .args([
            "-q",
            "--fail",
            "--silent",
            "--location",
            "--globoff",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--connect-timeout",
            "8",
            "--max-time",
            &seconds.to_string(),
            "--max-filesize",
            &MAX_FILE.to_string(),
            "--",
            url,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut data = Vec::new();
    let read = curl
        .stdout
        .take()
        .unwrap()
        .take(MAX_FILE as u64 + 1)
        .read_to_end(&mut data);
    if read.is_err() || data.len() > MAX_FILE {
        let _ = curl.kill();
    }
    let status = curl.wait()?;
    read?;
    ensure!(
        status.success() && data.len() <= MAX_FILE,
        "rule file download failed or exceeded 1 MiB"
    );
    Ok(data)
}

impl Config {
    // Fetch only new or explicitly refreshed URLs while the previous worker is still running.
    // The saved configuration pins an immutable content digest for offline restart and rollback.
    pub fn prepare_rule_files(&mut self, old: &Config, dir: &Path) -> Result<()> {
        let start = Instant::now();
        let cache = dir.join("rule-files");
        let mut updates = std::collections::HashMap::new();
        for rule in &mut self.rules {
            if rule.rule_url.is_empty() {
                continue;
            }
            if !rule.rule_digest.is_empty() {
                ensure!(
                    old.rules
                        .iter()
                        .any(|r| r.rule_url == rule.rule_url && r.rule_digest == rule.rule_digest),
                    "unknown rule file revision"
                );
                continue;
            }
            if let Some(key) = updates.get(&rule.rule_url) {
                rule.rule_digest = String::clone(key);
                continue;
            }
            let seconds = Duration::from_secs(30)
                .saturating_sub(start.elapsed())
                .as_secs()
                .min(15);
            ensure!(seconds > 0, "rule download timeout");
            let content = download(&rule.rule_url, seconds)?;
            parse_file(&content, &rule.outbound, MAX_ENTRIES)?;
            let key = fingerprint(&content);
            fs::create_dir_all(&cache)?;
            let path = cache.join(&key);
            let temp = cache.join("pending");
            fs::write(&temp, content)?;
            fs::rename(temp, path)?;
            updates.insert(rule.rule_url.clone(), key.clone());
            rule.rule_digest = key;
        }
        self.expand_rules(dir)
    }

    pub fn expand_rules(&mut self, dir: &Path) -> Result<()> {
        if self
            .rules
            .iter()
            .all(|r| r.rule_url.is_empty() && r.standard.is_empty())
        {
            return Ok(());
        }
        let mut effective = Vec::new();
        for (idx, r) in self.rules.iter().enumerate() {
            ensure!(effective.len() < MAX_ENTRIES, "too many rule entries");
            if !r.rule_url.is_empty() {
                ensure!(
                    is_digest(&r.rule_digest),
                    "rule {} missing saved rule file",
                    idx + 1
                );
                let mut content = Vec::new();
                File::open(dir.join("rule-files").join(&r.rule_digest))?
                    .take(MAX_FILE as u64 + 1)
                    .read_to_end(&mut content)?;
                ensure!(
                    fingerprint(&content) == r.rule_digest,
                    "rule file checksum mismatch"
                );
                effective.extend(parse_file(
                    &content,
                    &r.outbound,
                    MAX_ENTRIES - effective.len(),
                )?);
            } else if !r.standard.is_empty() {
                effective.push(parse_condition(&r.standard, &r.outbound)?);
            } else {
                effective.push(r.clone());
            }
        }
        self.effective_rules = Some(effective);
        Ok(())
    }

    pub fn prune_rule_files(&self, dir: &Path) -> Result<()> {
        let cache = dir.join("rule-files");
        if !cache.exists() {
            return Ok(());
        }
        let active: HashSet<_> = self.rules.iter().map(|r| r.rule_digest.as_str()).collect();
        for entry in fs::read_dir(cache)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == "pending" || (is_digest(&name) && !active.contains(name.as_ref())) {
                fs::remove_file(entry.path())?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compiled_rules_keep_order_and_file_snapshot() {
        let dir = std::env::temp_dir().join(format!("kaldor-rules-{}", std::process::id()));
        let cache = dir.join("rule-files");
        fs::create_dir_all(&cache).unwrap();
        let bytes=b"payload:\n  - 'DOMAIN,one.example'\n  - +.two.example\n  - 2001:db8::/32\n  - SRC-IP-CIDR,192.0.2.0/24\n";
        let hash = fingerprint(bytes);
        fs::write(cache.join(&hash), bytes).unwrap();
        let mut cfg: Config =
            serde_json::from_value(serde_json::json!({"default":"direct","rules":[
            {"standard":"DOMAIN,allow.two.example","outbound":"direct"},
            {"rule_url":"https://example.org/r.list","rule_digest":hash,"outbound":"reject"},
            {"standard":"DOMAIN-KEYWORD,AdVeRt","outbound":"reject"},
            {"standard":"MATCH","outbound":"direct"}]}))
            .unwrap();
        cfg.validate().unwrap();
        cfg.expand_rules(&dir).unwrap();
        assert!(cfg.has_ipv4_source_rules());
        let route = |host| {
            cfg.route(
                "198.51.100.1".parse().unwrap(),
                None,
                None,
                443,
                host,
                Network::Tcp,
            )
        };
        for (host, want) in [
            ("ONE.EXAMPLE.", "reject"),
            ("sub.one.example", "direct"),
            ("allow.two.example", "direct"),
            ("sub.two.example", "reject"),
            ("myadvert.test", "reject"),
            ("nottwo.example", "direct"),
        ] {
            assert_eq!(route(host), want);
        }
        assert_eq!(
            cfg.route(
                "::1".parse().unwrap(),
                None,
                Some("2001:db8::2".parse().unwrap()),
                80,
                "",
                Network::Udp
            ),
            "reject"
        );
        fs::write(cache.join(&hash), b"modified").unwrap();
        assert!(cfg.expand_rules(&dir).is_err());
        let err = parse_file(b"payload:\n - DOMAIN,a.test\n - GEOIP,CN", "direct", 50)
            .err()
            .unwrap();
        assert!(err.to_string().contains("line 3"));
        fs::remove_dir_all(dir).unwrap();
    }
}
