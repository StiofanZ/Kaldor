mod config;
mod outbound;
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
            print!(
                "{}",
                include_str!("../panel.html").replace("COMPONENT_VERSION", VERSION)
            );
            return Ok(());
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
            )?);
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
                println!("{}", net.trunc());
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
