mod dns;
mod http;
mod ipv6;
mod quic;
mod sniff;
mod udp;
use crate::{
    VERSION,
    config::{Config, TRANSPARENT_PORT},
    outbound::{Engine, Target},
};
use anyhow::{Context, Result, bail, ensure};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
    time::timeout,
};
#[derive(Clone)]
struct Service {
    engine: Arc<Engine>,
    lan: Ipv4Addr,
    iface: Arc<str>,
    reserved: Option<Ipv4Addr>,
    tcp_slots: Arc<Semaphore>,
    udp_slots: Arc<Semaphore>,
    dns: Option<Arc<dns::Resolver>>,
}
impl Service {
    fn device_dns(&self, src: SocketAddr) -> Option<&Arc<dns::Resolver>> {
        self.dns.as_ref().filter(|_| {
            self.engine
                .cfg
                .devices
                .iter()
                .any(|net| net.contains(&src.ip()))
        })
    }
    fn socket(&self, udp: bool, transparent: bool, addr: SocketAddr) -> Result<Socket> {
        let (kind, proto) = if udp {
            (Type::DGRAM, Protocol::UDP)
        } else {
            (Type::STREAM, Protocol::TCP)
        };
        let sock = Socket::new(Domain::for_address(addr), kind, Some(proto))?;
        if addr.is_ipv6() {
            sock.set_only_v6(true)?;
        }
        sock.set_reuse_address(true)?;
        sock.bind_device(Some(self.iface.as_bytes()))?;
        if transparent {
            if addr.is_ipv6() {
                sock.set_ip_transparent_v6(true)?;
            } else {
                sock.set_ip_transparent_v4(true)?;
            }
        }
        sock.bind(&addr.into())?;
        sock.set_nonblocking(true)?;
        Ok(sock)
    }
    fn listener(&self, port: u16, transparent: bool) -> Result<TcpListener> {
        let s = self.socket(false, transparent, (self.lan, port).into())?;
        s.listen(128)?;
        Ok(TcpListener::from_std(s.into())?)
    }
    fn datagram(&self, port: u16, transparent: bool) -> Result<UdpSocket> {
        let s = self.socket(true, transparent, (self.lan, port).into())?;
        if transparent {
            udp::original_address(&s, false)?;
        }
        Ok(UdpSocket::from_std(s.into())?)
    }
}
pub async fn run(cfg: Config, lan: &str, iface: &str, path: &str) -> Result<()> {
    let lan = lan.parse::<Ipv4Addr>()?;
    ensure!(
        !lan.is_unspecified() && !iface.is_empty(),
        "LAN address and interface required"
    );
    let port = cfg.listen_port();
    let transparent = !cfg.devices.is_empty();
    let service = Service {
        dns: transparent
            .then(dns::Resolver::new)
            .transpose()?
            .map(Arc::new),
        engine: Arc::new(Engine::new(cfg)?),
        lan,
        iface: iface.into(),
        reserved: None,
        tcp_slots: Arc::new(Semaphore::new(256)),
        udp_slots: Arc::new(Semaphore::new(256)),
    };
    let mut workers = tokio::task::JoinSet::new();
    service.engine.start_probes(&mut workers)?;
    let manual = service.listener(port, false)?;
    workers.spawn(accept(manual, service.clone(), false));
    if transparent {
        let tcp = service.listener(TRANSPARENT_PORT, true)?;
        workers.spawn(accept(tcp, service.clone(), true));
        let u = service.datagram(TRANSPARENT_PORT, true)?;
        let s = service.clone();
        workers.spawn(async move { udp::transparent(u, s).await });
    }
    let directory = std::path::Path::new(path)
        .parent()
        .context("missing runtime directory")?;
    if transparent {
        ipv6::start(&service, directory, &mut workers)?;
    }
    let activity = service.engine.activity.clone();
    let socket = crate::activity::Activity::listener(directory)?;
    workers.spawn(activity.serve(socket));
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?
        .write_all(VERSION.as_bytes())?;
    let result = tokio::select! {
        _=term.recv()=>Ok(()),
        r=tokio::signal::ctrl_c()=>Ok(r?),
        r=workers.join_next()=>r.context("listener stopped")??,
    };
    std::fs::remove_file(path)?;
    result
}
async fn accept(listener: TcpListener, s: Service, transparent: bool) -> Result<()> {
    let slots = if transparent {
        s.tcp_slots.clone()
    } else {
        Arc::new(Semaphore::new(256))
    };
    loop {
        let (mut c, from) = listener.accept().await?;
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let s = s.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if transparent {
                let dest = c.local_addr()?;
                if dest.is_ipv6() && dest.port() == 53 {
                    s.dns
                        .as_ref()
                        .context("missing DNS resolver")?
                        .tcp(&s, from, &mut c)
                        .await?;
                    return Ok(());
                }
                if dest == SocketAddr::from((s.lan, TRANSPARENT_PORT)) {
                    if let Some(resolver) = s.device_dns(from) {
                        resolver.tcp(&s, from, &mut c).await?;
                    }
                    return Ok(());
                }
                let domain_routing = s.engine.cfg.rules.iter().any(|r| r.needs_tcp_domain());
                let (data, domain) = if domain_routing {
                    sniff::read(&mut c, dest.port()).await?
                } else {
                    (vec![], String::new())
                };
                let target = Target::from_socket(dest);
                let (mut up, session) = s
                    .engine
                    .tcp(from, &target, &domain, "透明代理", s.reserved)
                    .await?;
                if !domain_routing && sniff::supported(dest.port()) {
                    let (reader, writer) = c.split();
                    let mut observed = tokio::io::join(
                        sniff::ObservedReader::new(reader, dest.port(), &session),
                        writer,
                    );
                    tokio::io::copy_bidirectional(&mut observed, &mut up).await?;
                } else {
                    up.write_all(&data).await?;
                    tokio::io::copy_bidirectional(&mut c, &mut up).await?;
                }
                Ok(())
            } else {
                // Peek preserves the SOCKS greeting or HTTP method for its protocol handler.
                let mut first = [0];
                ensure!(
                    timeout(Duration::from_secs(12), c.peek(&mut first)).await?? == 1,
                    "empty proxy request"
                );
                if first[0] == 5 {
                    socks(c, from, s).await
                } else {
                    http::serve(c, from, s).await
                }
            }
        });
    }
}
async fn target<R: AsyncRead + Unpin>(r: &mut R) -> Result<Target> {
    let host = match r.read_u8().await? {
        1 => {
            let mut ip = [0; 4];
            r.read_exact(&mut ip).await?;
            Ipv4Addr::from(ip).to_string()
        }
        4 => {
            let mut ip = [0; 16];
            r.read_exact(&mut ip).await?;
            std::net::Ipv6Addr::from(ip).to_string()
        }
        3 => {
            let len = r.read_u8().await?;
            ensure!(len > 0, "empty domain");
            let mut name = vec![0; len as usize];
            r.read_exact(&mut name).await?;
            String::from_utf8(name)?
        }
        _ => bail!("invalid address type"),
    };
    Ok(Target {
        host,
        port: r.read_u16().await?,
    })
}
async fn reply(c: &mut TcpStream, code: u8, addr: Option<SocketAddr>) -> Result<()> {
    let mut b = vec![5, code, 0];
    b.extend(Target::from_socket(addr.unwrap_or_else(|| SocketAddr::from(([0; 4], 0)))).header()?);
    c.write_all(&b).await?;
    Ok(())
}
async fn socks(mut c: TcpStream, src: SocketAddr, s: Service) -> Result<()> {
    let (cmd, t) = timeout(Duration::from_secs(12), async {
        ensure!(c.read_u8().await? == 5, "SOCKS version");
        let mut methods = vec![0; c.read_u8().await? as usize];
        c.read_exact(&mut methods).await?;
        if !methods.contains(&0) {
            c.write_all(&[5, 255]).await?;
            bail!("unsupported auth")
        }
        c.write_all(&[5, 0]).await?;
        ensure!(c.read_u8().await? == 5, "SOCKS version");
        let cmd = c.read_u8().await?;
        ensure!(c.read_u8().await? == 0, "SOCKS reserved field");
        Ok::<_, anyhow::Error>((cmd, target(&mut c).await?))
    })
    .await??;
    match cmd {
        1 => {
            let Ok((mut up, _session)) = s.engine.tcp(src, &t, &t.host, "SOCKS5", None).await
            else {
                return reply(&mut c, 1, None).await;
            };
            reply(&mut c, 0, None).await?;
            tokio::io::copy_bidirectional(&mut c, &mut up).await?;
            Ok(())
        }
        3 => udp::associate(c, src, t, s).await,
        _ => reply(&mut c, 7, None).await,
    }
}
