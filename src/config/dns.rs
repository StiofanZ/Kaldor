use super::*;

const USE_QUERY_RULES: &str = "@rules";

#[derive(Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct DnsRouting {
    #[serde(skip_serializing_if = "Option::is_none")]
    default: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    rules: Vec<QueryRule>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct QueryRule {
    #[serde(rename = "type")]
    kind: MatchType,
    value: String,
    outbound: String,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum MatchType {
    Exact,
    Suffix,
    Keyword,
}

impl DnsRouting {
    pub(super) fn is_empty(&self) -> bool {
        self.default.is_none() && self.rules.is_empty()
    }

    pub(super) fn validate(&self, names: &HashSet<&str>) -> Result<()> {
        let known = |name: &str| name == USE_QUERY_RULES || names.contains(name);
        ensure!(
            self.default.as_deref().is_none_or(known),
            "unknown default DNS outbound"
        );
        ensure!(self.rules.len() <= 512, "too many DNS rules");
        for (i, r) in self.rules.iter().enumerate() {
            ensure!(known(&r.outbound), "DNS rule {}: unknown outbound", i + 1);
            let valid = match r.kind {
                MatchType::Exact | MatchType::Suffix => valid_domain(&r.value),
                MatchType::Keyword => valid_keyword(&r.value),
            };
            ensure!(valid, "DNS rule {}: invalid query name pattern", i + 1);
        }
        Ok(())
    }
}

impl Config {
    pub fn uses_dns_rules(&self) -> bool {
        self.outbound_mode == OutboundMode::Rules && !self.dns.is_empty()
    }

    /// None preserves routing for the resolver's own HTTPS connection.
    pub fn query_outbound(
        &self,
        src: IpAddr,
        reserved: Option<std::net::Ipv4Addr>,
        domain: &str,
        network: Network,
    ) -> Option<&str> {
        if !self.uses_dns_rules() {
            return None;
        }
        let domain = domain.strip_suffix('.').unwrap_or(domain);
        let selected = self
            .dns
            .rules
            .iter()
            .find(|r| match r.kind {
                MatchType::Exact => domain.eq_ignore_ascii_case(r.value.trim_end_matches('.')),
                MatchType::Suffix => matches_suffix(domain, r.value.trim_end_matches('.')),
                MatchType::Keyword => contains_keyword(domain, &r.value),
            })
            .map(|r| r.outbound.as_str())
            .or(self.dns.default.as_deref())?;
        Some(if selected == USE_QUERY_RULES {
            // The original DNS query has no resolved destination address yet.
            self.route(src, reserved, None, 53, domain, network)
        } else {
            selected
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn dns_defaults_and_references() {
        let mut cfg: Config = serde_json::from_value(json!({"default":"direct"})).unwrap();
        assert!(serde_json::to_value(&cfg).unwrap().get("dns").is_none());
        for bad in [
            json!({"default":"unknown"}),
            json!({"rules":[{"type":"suffix","value":"bad..example","outbound":"direct"}]}),
            json!({"rules":[{"type":"exact","value":"valid.test","outbound":"unknown"}]}),
        ] {
            cfg.dns = serde_json::from_value(bad).unwrap();
            assert!(cfg.validate().is_err());
        }
        cfg.dns = serde_json::from_value(
            json!({"rules":[{"type":"suffix","value":"Example.TeSt.","outbound":"reject"}]}),
        )
        .unwrap();
        cfg.validate().unwrap();
        let src = "192.0.2.1".parse().unwrap();
        assert_eq!(
            cfg.query_outbound(src, None, "sub.EXAMPLE.test.", Network::Udp),
            Some("reject")
        );
        assert_eq!(
            cfg.query_outbound(src, None, "notexample.test.", Network::Tcp),
            None
        );
        cfg.outbound_mode = OutboundMode::Direct;
        assert_eq!(
            cfg.query_outbound(src, None, "example.test", Network::Udp),
            None
        );
    }
}
