use anyhow::{Context, Result, ensure};
use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize};
use std::{collections::HashSet, fs::File, io::Read, net::IpAddr};

fn list<'de, T: Deserialize<'de>, D: Deserializer<'de>>(d: D) -> Result<Vec<T>, D::Error> {
    Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
}

#[derive(Deserialize, Serialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub enabled: bool,
    pub default: String,
    #[serde(deserialize_with = "list")]
    pub devices: Vec<IpNet>,
    #[serde(deserialize_with = "list")]
    pub rules: Vec<Rule>,
    #[serde(deserialize_with = "list")]
    pub upstreams: Vec<Upstream>,
}
#[derive(Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Rule {
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<IpNet>,
    #[serde(skip_serializing_if = "Option::is_none")]
    destination: Option<IpNet>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub domain_suffix: String,
    port: u16,
    outbound: String,
}
#[derive(Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Upstream {
    pub name: String,
    pub protocol: String,
    pub server: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub secret: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub username: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub server_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub public_key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub short_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub flow: String,
}
impl Config {
    pub fn read(file: &str) -> Result<Self> {
        let mut buf = Vec::new();
        File::open(file)?.take(65537).read_to_end(&mut buf)?;
        ensure!(buf.len() <= 65536, "configuration exceeds size limit");
        serde_json::from_slice(&buf)
            .map_err(|_| anyhow::anyhow!("invalid configuration JSON or unknown field"))
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.upstreams.len() <= 32 && self.devices.len() <= 128 && self.rules.len() <= 512,
            "configuration limit exceeded"
        );
        let mut names = HashSet::from(["direct", "reject"]);
        for u in &self.upstreams {
            ensure!(
                !u.name.is_empty()
                    && u.name.len() <= 48
                    && u.name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
                    && names.insert(&u.name),
                "duplicate or invalid upstream name"
            );
            u.validate()
                .with_context(|| format!("upstream {}", u.name))?;
        }
        ensure!(
            self.devices.iter().all(|p| matches!(p, IpNet::V4(_))),
            "transparent device prefixes must be IPv4"
        );
        ensure!(
            names.contains(self.default.as_str()),
            "unknown default outbound"
        );
        for rule in &self.rules {
            ensure!(
                names.contains(rule.outbound.as_str()),
                "unknown rule outbound"
            );
            ensure!(
                rule.source.is_some()
                    || rule.destination.is_some()
                    || rule.port != 0
                    || !rule.domain_suffix.is_empty(),
                "empty rule"
            );
        }
        Ok(())
    }
    pub fn route(&self, src: IpAddr, dst: Option<IpAddr>, port: u16, domain: &str) -> &str {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        self.rules
            .iter()
            .find(|r| {
                let suffix = r.domain_suffix.trim_end_matches('.').to_ascii_lowercase();
                r.source.is_none_or(|p| p.contains(&src))
                    && r.destination
                        .is_none_or(|p| dst.is_some_and(|ip| p.contains(&ip)))
                    && (r.port == 0 || r.port == port)
                    && (suffix.is_empty()
                        || domain == suffix
                        || domain
                            .strip_suffix(&suffix)
                            .is_some_and(|s| s.ends_with('.')))
            })
            .map_or(&self.default, |r| &r.outbound)
    }
    pub fn merge(&mut self, old: &Self) {
        for u in &mut self.upstreams {
            if u.secret.is_empty()
                && let Some(p) = old.upstreams.iter().find(|p| p.identity() == u.identity())
            {
                u.secret.clone_from(&p.secret);
            }
        }
    }
}
impl Upstream {
    fn identity(&self) -> [&str; 7] {
        [
            &self.name,
            &self.protocol,
            &self.server,
            &self.username,
            &self.server_name,
            &self.public_key,
            &self.short_id,
        ]
    }
    pub fn endpoint(&self) -> Result<(String, u16)> {
        let a = self.server.parse::<hyper::http::uri::Authority>()?;
        let host = a.host().trim_start_matches('[').trim_end_matches(']');
        ensure!(
            !host.is_empty() && !self.server.contains('@'),
            "invalid server"
        );
        Ok((
            host.to_owned(),
            a.port_u16()
                .filter(|n| *n > 0)
                .context("invalid server port")?,
        ))
    }
    pub fn reality_keys(&self) -> Result<([u8; 32], [u8; 8])> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let key = URL_SAFE_NO_PAD
            .decode(&self.public_key)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid REALITY public key"))?;
        ensure!(
            self.short_id.len() <= 16 && self.short_id.len() % 2 == 0 && self.short_id.is_ascii(),
            "invalid REALITY short ID"
        );
        let mut sid = [0; 8];
        for (i, b) in self.short_id.as_bytes().chunks_exact(2).enumerate() {
            sid[i] = u8::from_str_radix(std::str::from_utf8(b)?, 16)?;
        }
        Ok((key, sid))
    }
    fn validate(&self) -> Result<()> {
        self.endpoint()?;
        match self.protocol.as_str() {
            "anytls" => ensure!(!self.secret.is_empty(), "AnyTLS password required"),
            "socks5" => ensure!(
                (self.secret.is_empty() || !self.username.is_empty())
                    && self.secret.len() <= 255
                    && self.username.len() <= 255,
                "invalid SOCKS5 credentials"
            ),
            "vless-reality" => {
                self.reality_keys()?;
                ensure!(
                    self.secret.len() == 36 && uuid::Uuid::parse_str(&self.secret).is_ok(),
                    "invalid VLESS UUID"
                );
                ensure!(
                    !self.server_name.is_empty()
                        && matches!(self.flow.as_str(), "" | "xtls-rprx-vision"),
                    "invalid REALITY server name or flow"
                );
            }
            _ => anyhow::bail!("unknown protocol"),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rule_order_and_label_boundary() {
        let cfg:Config=serde_json::from_str(r#"{"default":"direct","rules":[{"source":"192.0.2.7/32","domain_suffix":"example.test","outbound":"reject"},{"port":443,"outbound":"direct"}]}"#).unwrap();
        cfg.validate().unwrap();
        for (ip, host, want) in [
            ("192.0.2.7", "WWW.Example.Test.", "reject"),
            ("192.0.2.8", "www.example.test", "direct"),
            ("192.0.2.7", "notexample.test", "direct"),
        ] {
            assert_eq!(cfg.route(ip.parse().unwrap(), None, 443, host), want);
        }
    }
    #[test]
    fn configuration_contract() {
        for s in [r#"{"unknown":1}"#, "{}{}", r#"{"devices":["invalid"]}"#] {
            assert!(serde_json::from_str::<Config>(s).is_err());
        }
        for s in [
            r#"{"default":"missing"}"#,
            r#"{"default":"direct","rules":[{"outbound":"direct"}]}"#,
            r#"{"default":"direct","upstreams":[{"name":"direct"}]}"#,
        ] {
            assert!(
                serde_json::from_str::<Config>(s)
                    .unwrap()
                    .validate()
                    .is_err()
            );
        }
        let cfg: Config = serde_json::from_str(
            r#"{"default":"direct","devices":null,"upstreams":null,"rules":null}"#,
        )
        .unwrap();
        cfg.validate().unwrap();
    }
}
