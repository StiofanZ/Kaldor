use anyhow::{Context, Result, ensure};
use ipnet::IpNet;
use meow_common::Network;
use serde::{Deserialize, Deserializer, Serialize};
use std::{collections::HashSet, fs::File, io::Read, net::IpAddr, num::NonZeroU16};

fn list<'de, T: Deserialize<'de>, D: Deserializer<'de>>(d: D) -> Result<Vec<T>, D::Error> {
    Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
}

// Consume and validate the former device filter when reading an existing
// configuration. Newly saved configurations have interface-wide ingress.
fn read_old_devices<'de, D: Deserializer<'de>>(d: D) -> Result<(), D::Error> {
    let _ = Option::<Vec<IpNet>>::deserialize(d)?;
    Ok(())
}

#[derive(Deserialize, Serialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub enabled: bool,
    #[serde(
        default,
        rename = "devices",
        deserialize_with = "read_old_devices",
        skip_serializing
    )]
    _old_devices: (),
    #[serde(skip_serializing_if = "Option::is_none")]
    listen_port: Option<NonZeroU16>,
    pub outbound_mode: OutboundMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_outbound: Option<String>,
    pub default: String,
    #[serde(deserialize_with = "list")]
    pub rules: Vec<Rule>,
    #[serde(deserialize_with = "list")]
    pub upstreams: Vec<Upstream>,
    #[serde(deserialize_with = "list", skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<Policy>,
}
#[derive(Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboundMode {
    Direct,
    Global,
    #[default]
    Rules,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: PolicyType,
    pub members: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyType {
    Manual,
    Auto,
    LoadBalance,
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 48
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

#[derive(Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Rule {
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<IpNet>,
    #[serde(skip_serializing_if = "Option::is_none")]
    destination: Option<IpNet>,
    #[serde(skip_serializing_if = "String::is_empty")]
    domain_suffix: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<Network>,
    port: u16,
    outbound: String,
}
impl Rule {
    pub fn needs_tcp_domain(&self) -> bool {
        !self.domain_suffix.is_empty() && self.network != Some(Network::Udp)
    }
    fn matches_domain(&self, domain: &str) -> bool {
        if self.domain_suffix.is_empty() {
            return true;
        }
        let suffix = self
            .domain_suffix
            .strip_suffix('.')
            .unwrap_or(&self.domain_suffix);
        let Some(start) = domain.len().checked_sub(suffix.len()) else {
            return false;
        };
        !suffix.is_empty()
            && (start == 0 || domain.as_bytes()[start - 1] == b'.')
            && domain
                .get(start..)
                .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
    }
}
#[derive(Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Upstream {
    // Original row selected in the editor. Used only when applying a change.
    #[serde(default, skip_serializing)]
    previous_name: Option<String>,
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
pub const TRANSPARENT_PORT: u16 = 7893;

impl Config {
    pub fn listen_port(&self) -> u16 {
        self.listen_port.map_or(6000, NonZeroU16::get)
    }
    pub fn read(file: &str) -> Result<Self> {
        let mut buf = Vec::new();
        File::open(file)?.take(65537).read_to_end(&mut buf)?;
        ensure!(buf.len() <= 65536, "configuration exceeds size limit");
        serde_json::from_slice(&buf)
            .map_err(|_| anyhow::anyhow!("invalid configuration JSON or unknown field"))
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.listen_port() != TRANSPARENT_PORT,
            "manual port conflicts with transparent listener"
        );
        ensure!(
            self.upstreams.len() <= 32 && self.rules.len() <= 512,
            "configuration limit exceeded"
        );
        let mut names = HashSet::from(["direct", "reject"]);
        for u in &self.upstreams {
            ensure!(
                valid_name(&u.name) && names.insert(&u.name),
                "duplicate or invalid upstream name"
            );
            u.validate()
                .with_context(|| format!("upstream {}", u.name))?;
        }
        ensure!(self.policies.len() <= 32, "too many policies");
        let nodes: HashSet<_> = self.upstreams.iter().map(|n| n.name.as_str()).collect();
        for p in &self.policies {
            ensure!(
                valid_name(&p.name) && names.insert(&p.name),
                "duplicate or invalid policy name"
            );
            let mut seen = HashSet::new();
            ensure!(
                !p.members.is_empty()
                    && p.members
                        .iter()
                        .all(|n| nodes.contains(n.as_str()) && seen.insert(n)),
                "policy {} requires distinct existing nodes",
                p.name
            );
            match p.kind {
                PolicyType::Manual => ensure!(
                    p.selected.as_ref().is_some_and(|n| seen.contains(n)),
                    "manual policy requires a selected member"
                ),
                _ => ensure!(
                    p.selected.is_none(),
                    "only manual policies accept a selected member"
                ),
            }
        }
        ensure!(
            names.contains(self.default.as_str()),
            "unknown default outbound"
        );
        if let Some(name) = &self.global_outbound {
            ensure!(
                names.contains(name.as_str()) && !matches!(name.as_str(), "direct" | "reject"),
                "global outbound must be a proxy node or policy"
            );
        }
        ensure!(
            self.outbound_mode != OutboundMode::Global || self.global_outbound.is_some(),
            "select a global proxy outbound"
        );
        for (index, rule) in self.rules.iter().enumerate() {
            if !rule.domain_suffix.is_empty() {
                let suffix = rule
                    .domain_suffix
                    .strip_suffix('.')
                    .unwrap_or(&rule.domain_suffix);
                ensure!(
                    suffix.split('.').all(|label| !label.is_empty()),
                    "rule {}: empty domain label",
                    index + 1
                );
            }
            ensure!(
                names.contains(rule.outbound.as_str()),
                "unknown rule outbound"
            );
            ensure!(
                rule.source.is_some()
                    || rule.destination.is_some()
                    || rule.network.is_some()
                    || rule.port != 0
                    || !rule.domain_suffix.is_empty(),
                "empty rule"
            );
        }
        Ok(())
    }
    pub fn has_ipv4_source_rules(&self) -> bool {
        self.outbound_mode == OutboundMode::Rules
            && self
                .rules
                .iter()
                .any(|r| matches!(r.source, Some(IpNet::V4(_))))
    }
    pub fn matches_reserved_source(&self, ip: std::net::Ipv4Addr) -> bool {
        self.rules
            .iter()
            .any(|r| r.source.is_some_and(|net| net.contains(&IpAddr::V4(ip))))
    }
    pub fn route(
        &self,
        src: IpAddr,
        reserved: Option<std::net::Ipv4Addr>,
        dst: Option<IpAddr>,
        port: u16,
        domain: &str,
        network: Network,
    ) -> &str {
        match self.outbound_mode {
            OutboundMode::Global => {
                return self
                    .global_outbound
                    .as_deref()
                    .expect("validated global outbound");
            }
            OutboundMode::Direct => return "direct",
            OutboundMode::Rules => {}
        }
        let domain = domain.strip_suffix('.').unwrap_or(domain);
        let domain = if domain.parse::<IpAddr>().is_ok() {
            ""
        } else {
            domain
        };
        self.rules
            .iter()
            .find(|r| {
                r.network.is_none_or(|n| n == network)
                    && r.source.is_none_or(|p| {
                        p.contains(&src) || reserved.is_some_and(|v| p.contains(&IpAddr::V4(v)))
                    })
                    && r.destination
                        .is_none_or(|p| dst.is_some_and(|ip| p.contains(&ip)))
                    && (r.port == 0 || r.port == port)
                    && r.matches_domain(domain)
            })
            .map_or(&self.default, |r| &r.outbound)
    }
    pub fn merge(&mut self, old: &Self) -> Result<()> {
        let mut originals = HashSet::new();
        for node in &mut self.upstreams {
            let original = match node.previous_name.take() {
                // The editor explicitly marks a newly added row.
                Some(name) if name.is_empty() => continue,
                Some(name) => {
                    ensure!(originals.insert(name.clone()), "duplicate original node");
                    Some(
                        old.upstreams
                            .iter()
                            .find(|p| p.name == name)
                            .context("original node no longer exists")?,
                    )
                }
                None => old.upstreams.iter().find(|p| p.name == node.name),
            };
            if let Some(previous) = original
                && node.secret.is_empty()
            {
                if previous.identity() == node.identity() {
                    node.secret.clone_from(&previous.secret);
                } else if node.protocol == "socks5" && !node.username.is_empty() {
                    ensure!(previous.secret.is_empty(), "re-enter SOCKS5 credentials");
                }
            }
        }
        Ok(())
    }
}
impl Upstream {
    fn identity(&self) -> [&str; 6] {
        [
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
            assert_eq!(
                cfg.route(ip.parse().unwrap(), None, None, 443, host, Network::Tcp),
                want
            );
        }
    }
    #[test]
    fn transport_combines_with_device_and_preserves_first_match() {
        let cfg: Config = serde_json::from_str(r#"{
            "default":"reject","rules":[
              {"network":"udp","source":"192.0.2.2/32","destination":"198.51.100.0/24","port":443,"outbound":"direct"},
              {"network":"udp","outbound":"reject"},
              {"port":443,"outbound":"direct"}
            ]}"#).unwrap();
        cfg.validate().unwrap();
        for (src, dst, port, network, want) in [
            (
                "192.0.2.2",
                Some("198.51.100.1"),
                443,
                Network::Udp,
                "direct",
            ),
            ("192.0.2.2", None, 443, Network::Udp, "reject"),
            (
                "192.0.2.2",
                Some("203.0.113.1"),
                443,
                Network::Udp,
                "reject",
            ),
            (
                "192.0.2.3",
                Some("198.51.100.1"),
                443,
                Network::Udp,
                "reject",
            ),
            (
                "192.0.2.2",
                Some("198.51.100.1"),
                53,
                Network::Udp,
                "reject",
            ),
            ("192.0.2.3", None, 443, Network::Tcp, "direct"),
            ("192.0.2.3", None, 53, Network::Tcp, "reject"),
        ] {
            assert_eq!(
                cfg.route(
                    src.parse().unwrap(),
                    None,
                    dst.map(|ip| ip.parse().unwrap()),
                    port,
                    "",
                    network
                ),
                want
            );
        }
        let view = serde_json::to_value(&cfg).unwrap();
        assert_eq!(view["rules"][0]["network"], "udp");
        assert!(view["rules"][2].get("network").is_none());
    }

    #[test]
    fn domains_require_nonempty_labels_and_a_hostname() {
        let mut cfg = Config {
            default: "direct".into(),
            rules: vec![Rule {
                outbound: "reject".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        for suffix in [".", "...", ".example", "example..org", "example.org.."] {
            cfg.rules[0].domain_suffix = suffix.into();
            assert!(cfg.validate().is_err(), "{suffix}");
        }
        let src = "192.0.2.2".parse().unwrap();
        for (suffix, host, want) in [
            ("2", "192.0.2.2", "direct"),
            ("EXAMPLE.org.", "example.ORG", "reject"),
            ("example.org.", "x.Example.org.", "reject"),
            ("example.org.", "", "direct"),
        ] {
            cfg.rules[0].domain_suffix = suffix.into();
            cfg.validate().unwrap();
            assert_eq!(cfg.route(src, None, None, 443, host, Network::Tcp), want);
        }
    }

    #[test]
    fn renames_keep_credentials_bound_to_the_original_peer() {
        fn node(name: &str, server: &str) -> Upstream {
            Upstream {
                name: name.into(),
                protocol: "anytls".into(),
                server: server.into(),
                ..Default::default()
            }
        }
        let mut old = Config::default();
        for name in ["east", "west"] {
            let mut n = node(name, &format!("{name}.test:443"));
            n.secret = format!("test-{name}");
            old.upstreams.push(n);
        }
        let mut cfg = Config {
            default: "west".into(),
            ..Default::default()
        };
        for (original, target) in [("east", "west"), ("west", "east")] {
            let mut n = node(target, &format!("{original}.test:443"));
            n.previous_name = Some(original.into());
            cfg.upstreams.push(n);
        }
        cfg.merge(&old).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.upstreams[0].secret, old.upstreams[0].secret);
        assert_eq!(cfg.upstreams[1].secret, old.upstreams[1].secret);
        assert!(
            !serde_json::to_string(&cfg)
                .unwrap()
                .contains("previous_name")
        );
        for (original, name, host, reuse) in [
            (None, "east", "east.test:443", true),
            (Some(""), "east", "east.test:443", false),
            (Some("east"), "renamed", "other.test:443", false),
        ] {
            let mut n = node(name, host);
            n.previous_name = original.map(String::from);
            cfg.upstreams = vec![n];
            cfg.merge(&old).unwrap();
            assert_eq!(!cfg.upstreams[0].secret.is_empty(), reuse);
        }
    }

    #[test]
    fn policy_references_must_resolve_to_nodes_and_manual_selection_to_a_member() {
        let base = serde_json::json!({
            "default":"group", "rules":[{"network":"udp","outbound":"group"}],
            "upstreams":[{"name":"east","protocol":"socks5","server":"east.test:1080"}],
            "policies":[{"name":"group","type":"manual","members":["east"],"selected":"east"}]
        });
        for (key, value) in [
            ("members", serde_json::json!([])),
            ("members", serde_json::json!(["east", "east"])),
            ("members", serde_json::json!(["reject"])),
            ("members", serde_json::json!(["group"])),
            ("members", serde_json::json!(["missing"])),
            ("selected", serde_json::json!("missing")),
            ("selected", serde_json::Value::Null),
            ("type", serde_json::json!("auto")),
            ("name", serde_json::json!("east")),
            ("name", serde_json::json!("direct")),
        ] {
            let mut invalid = base.clone();
            invalid["policies"][0][key] = value;
            assert!(
                serde_json::from_value::<Config>(invalid)
                    .unwrap()
                    .validate()
                    .is_err(),
                "{key}"
            );
        }
        serde_json::from_value::<Config>(base)
            .unwrap()
            .validate()
            .unwrap();
    }

    #[test]
    fn modes_validate_global_target_and_migrate_old_scope() {
        let legacy = serde_json::json!({"enabled":true,"devices":["192.0.2.8/32"],"default":"direct",
            "rules":[{"port":443,"outbound":"reject"}],
            "upstreams":[{"name":"east","protocol":"socks5","server":"east.test:1080"}]});
        let mut cfg: Config = serde_json::from_value(legacy).unwrap();
        assert!(serde_json::to_value(&cfg).unwrap().get("devices").is_none());
        let src = "192.0.2.9".parse().unwrap();
        assert_eq!(cfg.route(src, None, None, 443, "", Network::Udp), "reject");
        cfg.outbound_mode = OutboundMode::Global;
        for bad in [None, Some("direct"), Some("reject"), Some("missing")] {
            cfg.global_outbound = bad.map(String::from);
            assert!(cfg.validate().is_err());
        }
        cfg.global_outbound = Some("east".into());
        cfg.validate().unwrap();
        assert_eq!(cfg.route(src, None, None, 443, "", Network::Udp), "east");
        cfg.outbound_mode = OutboundMode::Direct;
        assert_eq!(cfg.route(src, None, None, 443, "", Network::Tcp), "direct");
    }

    #[test]
    fn configuration_contract() {
        for s in [
            r#"{"unknown":1}"#,
            "{}{}",
            r#"{"devices":["invalid"]}"#,
            r#"{"rules":[{"network":"quic"}]}"#,
        ] {
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
        let cfg: Config =
            serde_json::from_str(r#"{"default":"direct","upstreams":null,"rules":null}"#).unwrap();
        cfg.validate().unwrap();
    }
}
