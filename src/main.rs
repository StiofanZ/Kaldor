mod activity;
mod config;
mod outbound;
mod policy;
mod release;
use std::path::Path;
#[cfg(target_os = "linux")]
mod server;
use anyhow::{Context, Result, bail, ensure};
use config::Config;
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    if let Err(e) = execute().await {
        eprintln!("Kaldor: {e:#}");
        std::process::exit(1);
    }
}
async fn execute() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let cmd = args.first().context("command required")?.as_str();
    match cmd {
        "version" => {
            println!("{VERSION}");
            return Ok(());
        }
        "manager" => {
            print!("{}", include_str!("../service.sh"));
            return Ok(());
        }
        "page" => {
            let dir = std::env::var("AXPROXY_RUN").unwrap_or_else(|_| "/tmp/axproxy".into());
            print!(
                "{}",
                release::page(Path::new(&dir))?.replace(
                    "ACTIVITY_SNAPSHOT",
                    &activity::panel_data(Path::new(&dir)).await
                )
            );
            return Ok(());
        }
        "release-request" if args.len() == 3 => {
            return release::submit(Path::new(&args[1]), Path::new(&args[2]));
        }
        "release-worker" if args.len() == 4 => {
            return release::worker(Path::new(&args[1]), &args[2], &args[3]);
        }
        "mark-candidate" if args.len() == 2 => return release::mark_candidate(Path::new(&args[1])),
        "prune-installed" if args.len() == 3 => {
            return release::prune(Path::new(&args[1]), Path::new(&args[2]));
        }
        _ => {}
    }
    let mut cfg = Config::read(args.get(1).context("configuration required")?)?;
    match cmd {
        "view" => {
            for u in &mut cfg.upstreams {
                u.secret.clear()
            }
            println!("{}", serde_json::to_string(&cfg)?);
        }
        "merge" => {
            cfg.merge(&Config::read(
                args.get(2).context("previous configuration required")?,
            )?)?;
            cfg.validate()?;
            println!("{}", serde_json::to_string(&cfg)?);
        }
        "check" => cfg.validate()?,
        "enabled" => {
            cfg.validate()?;
            ensure!(cfg.enabled, "disabled");
        }
        "devices" => {
            cfg.validate()?;
            for net in cfg.devices {
                if net.addr().is_ipv4() {
                    println!("{}", net.trunc());
                }
            }
        }
        #[cfg(target_os = "linux")]
        "serve" => {
            ensure!(
                cfg.enabled && args.len() == 5,
                "enabled configuration, LAN, interface and readiness path required"
            );
            server::run(cfg, &args[2], &args[3], &args[4]).await?;
        }
        _ => bail!("unsupported command"),
    }
    Ok(())
}
