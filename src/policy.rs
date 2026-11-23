//! Outbound policy selection. Latencies and round-robin positions live only in memory.
use crate::{
    config::{Config, PolicyType},
    outbound::{Engine, Target, verified_tls},
};
use anyhow::{Result, anyhow};
use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{sync::watch, task::JoinSet, time::timeout};

type Measurements = HashMap<String, Duration>;

pub struct Policies {
    rotations: HashMap<String, AtomicUsize>,
    measurements: watch::Sender<Option<Measurements>>,
}

impl Policies {
    pub fn new(cfg: &Config) -> Self {
        Self {
            rotations: cfg
                .policies
                .iter()
                .filter(|p| p.kind == PolicyType::LoadBalance)
                .map(|p| (p.name.clone(), AtomicUsize::new(0)))
                .collect(),
            measurements: watch::channel(None).0,
        }
    }
}

impl Engine {
    // A flow chooses its node before opening the connection. Established flows keep it.
    pub async fn via<'a, T, F: Future<Output = Result<T>>>(
        &'a self,
        outbound: &'a str,
        mut open: impl FnMut(&'a str) -> F,
    ) -> (&'a str, Result<T>) {
        let Some(p) = self.cfg.policies.iter().find(|p| p.name == outbound) else {
            return (outbound, open(outbound).await);
        };
        let node = match p.kind {
            PolicyType::Manual => p.selected.as_deref().expect("validated manual policy"),
            PolicyType::LoadBalance => {
                let i = self.policies.rotations[&p.name].fetch_add(1, Ordering::Relaxed);
                &p.members[i % p.members.len()]
            }
            PolicyType::Auto => {
                let mut rx = self.policies.measurements.subscribe();
                let ranked = {
                    let snapshot = rx
                        .wait_for(Option::is_some)
                        .await
                        .expect("engine owns sender");
                    let results = snapshot.as_ref().unwrap();
                    let mut ranked: Vec<_> = p
                        .members
                        .iter()
                        .filter_map(|name| results.get(name).map(|delay| (*delay, name.as_str())))
                        .collect();
                    ranked.sort_by_key(|(delay, _)| *delay);
                    ranked
                };
                let mut last = (
                    outbound,
                    Err(anyhow!("no reachable node in policy {outbound}")),
                );
                for (_, name) in ranked {
                    last = (name, open(name).await);
                    if last.1.is_ok() {
                        break;
                    }
                }
                return last;
            }
        };
        (node, open(node).await)
    }

    pub fn start_probes(self: &Arc<Self>, workers: &mut JoinSet<Result<()>>) -> Result<()> {
        let nodes: HashSet<_> = self
            .cfg
            .policies
            .iter()
            .filter(|p| p.kind == PolicyType::Auto)
            .flat_map(|p| p.members.iter().cloned())
            .collect();
        if nodes.is_empty() {
            return Ok(());
        }
        let tls = verified_tls()?;
        let engine = self.clone();
        workers.spawn(async move {
            loop {
                let mut pending = JoinSet::new();
                for name in &nodes {
                    let (engine, tls, name) = (engine.clone(), tls.clone(), name.clone());
                    pending.spawn(async move {
                        let start = Instant::now();
                        let ping = async {
                            let dst = Target {
                                host: "1.1.1.1".into(),
                                port: 443,
                            };
                            let stream = engine
                                .dial_tcp(std::net::Ipv4Addr::UNSPECIFIED.into(), &dst, &name)
                                .await?;
                            tokio_boring::connect(tls.configure()?, "cloudflare-dns.com", stream)
                                .await
                                .map_err(|e| anyhow!("{e}"))?;
                            Ok::<_, anyhow::Error>(())
                        };
                        timeout(Duration::from_secs(5), ping).await.ok()?.ok()?;
                        Some((name, start.elapsed()))
                    });
                }
                let mut results = Measurements::new();
                while let Some(probe) = pending.join_next().await {
                    if let Some((name, latency)) = probe? {
                        results.insert(name, latency);
                    }
                }
                engine.policies.measurements.send_replace(Some(results));
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });
        Ok(())
    }
}
