use crate::config::{Config, Upstream};
use anyhow::{Result, bail, ensure};
use anytls_rs::{
    AsyncStream, TlsConnect, TlsConnectFuture, client::Client, padding::PaddingFactory,
};
use boring::ssl::{SslConnector, SslMethod, SslVersion};
use bytes::Bytes;
use meow_common::{Metadata, Network, ProxyAdapter, ProxyPacketConn};
use meow_proxy::{
    DirectAdapter, Socks5Adapter, TransportChain, VlessAdapter, VlessFlow, dialer::DirectDialer,
};
use meow_transport::tls::{RealityConfig, TlsConfig, TlsLayer};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
    time::timeout,
};

pub trait Stream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Stream for T {}
pub type Connection = Box<dyn Stream>;
struct AnyTlsConnector {
    tls: SslConnector,
    name: String,
}
impl TlsConnect for AnyTlsConnector {
    fn connect(&self, tcp: TcpStream) -> TlsConnectFuture<'_> {
        Box::pin(async move {
            let tls = self.tls.configure().map_err(std::io::Error::other)?;
            let stream = tokio_boring::connect(tls, &self.name, tcp)
                .await
                .map_err(std::io::Error::other)?;
            Ok(Box::new(stream) as Box<dyn AsyncStream>)
        })
    }
}
enum Adapter {
    Standard(Box<dyn ProxyAdapter>),
    Vision {
        tcp: Box<dyn ProxyAdapter>,
        udp: Box<dyn ProxyAdapter>,
    },
    AnyTls(Client),
}
pub enum Packets {
    Standard(Box<dyn ProxyPacketConn>, SocketAddr),
    Framed(
        Mutex<tokio::io::ReadHalf<Connection>>,
        Mutex<tokio::io::WriteHalf<Connection>>,
    ),
}
impl Packets {
    pub async fn send(&self, data: &[u8]) -> Result<()> {
        match self {
            Self::Standard(conn, addr) => {
                conn.write_packet(data, addr).await?;
            }
            Self::Framed(_, w) => {
                let mut w = w.lock().await;
                w.write_u16(data.len().try_into()?).await?;
                w.write_all(data).await?;
                w.flush().await?;
            }
        }
        Ok(())
    }
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        match self {
            Self::Standard(conn, dst) => loop {
                let (n, src) = conn.read_packet(buf).await?;
                if src.ip().is_unspecified()
                    || (dst.ip().is_unspecified() && dst.port() == src.port())
                    || src == *dst
                {
                    return Ok(n);
                }
            },
            Self::Framed(r, _) => {
                let mut r = r.lock().await;
                let n = r.read_u16().await? as usize;
                ensure!(n <= buf.len(), "datagram too large");
                r.read_exact(&mut buf[..n]).await?;
                Ok(n)
            }
        }
    }
}
#[derive(Clone, Hash, Eq, PartialEq)]
pub struct Target {
    pub host: String,
    pub port: u16,
}
impl Target {
    pub fn addr(&self) -> Option<IpAddr> {
        self.host.parse().ok()
    }
    pub fn from_socket(a: SocketAddr) -> Self {
        Self {
            host: a.ip().to_string(),
            port: a.port(),
        }
    }
    pub fn header(&self) -> Result<Vec<u8>> {
        let mut b = Vec::new();
        match self.addr() {
            Some(IpAddr::V4(ip)) => {
                b.push(1);
                b.extend(ip.octets())
            }
            Some(IpAddr::V6(ip)) => {
                b.push(4);
                b.extend(ip.octets())
            }
            None => {
                ensure!(!self.host.is_empty(), "empty host");
                b.push(3);
                b.push(self.host.len().try_into()?);
                b.extend(self.host.as_bytes());
            }
        }
        b.extend(self.port.to_be_bytes());
        Ok(b)
    }
}
pub struct Engine {
    pub cfg: Config,
    pub activity: crate::activity::Activity,
    nodes: HashMap<String, Adapter>,
}
impl Engine {
    pub fn new(cfg: Config) -> Result<Self> {
        cfg.validate()?;
        let mut nodes = HashMap::new();
        nodes.insert(
            "direct".into(),
            Adapter::Standard(Box::new(DirectAdapter::new())),
        );
        for u in &cfg.upstreams {
            nodes.insert(u.name.clone(), adapter(u)?);
        }
        Ok(Self {
            cfg,
            nodes,
            activity: Default::default(),
        })
    }
    fn select(
        &self,
        src: IpAddr,
        t: &Target,
        outbound: &str,
        network: Network,
    ) -> Result<(&Adapter, Metadata)> {
        ensure!(t.port > 0, "invalid port");
        let a = self
            .nodes
            .get(outbound)
            .ok_or_else(|| anyhow::anyhow!("rejected by rule"))?;
        let mut meta = Metadata {
            src_ip: Some(src),
            dst_ip: t.addr(),
            dst_port: t.port,
            network,
            ..Default::default()
        };
        if meta.dst_ip.is_none() {
            meta.host = t.host.as_str().into();
        }
        Ok((a, meta))
    }
    pub async fn tcp(
        &self,
        src: SocketAddr,
        t: &Target,
        domain: &str,
        ingress: &'static str,
        reserved: Option<std::net::Ipv4Addr>,
    ) -> Result<(Connection, crate::activity::Session)> {
        let outbound = self
            .cfg
            .route(src.ip(), reserved, t.addr(), t.port, domain, Network::Tcp);
        let result = self.dial_tcp(src.ip(), t, outbound).await;
        self.activity.record(
            crate::activity::Access {
                source: src,
                target: t,
                domain,
                ingress,
                transport: "TCP",
                outbound,
            },
            result,
        )
    }
    pub(crate) async fn dial_tcp(
        &self,
        src: IpAddr,
        t: &Target,
        outbound: &str,
    ) -> Result<Connection> {
        let (adapter, m) = self.select(src, t, outbound, Network::Tcp)?;
        timeout(Duration::from_secs(12), async {
            match adapter {
                Adapter::Standard(a) | Adapter::Vision { tcp: a, .. } => {
                    Ok(Box::new(a.dial_tcp(&m).await?) as Connection)
                }
                Adapter::AnyTls(a) => any_stream(a, t, None).await,
            }
        })
        .await?
    }
    pub async fn udp(
        &self,
        src: SocketAddr,
        t: &Target,
        ingress: &'static str,
        reserved: Option<std::net::Ipv4Addr>,
    ) -> Result<(Packets, crate::activity::Session)> {
        let outbound = self
            .cfg
            .route(src.ip(), reserved, t.addr(), t.port, &t.host, Network::Udp);
        let result = self.dial_udp(src.ip(), t, outbound).await;
        self.activity.record(
            crate::activity::Access {
                source: src,
                target: t,
                domain: &t.host,
                ingress,
                transport: "UDP",
                outbound,
            },
            result,
        )
    }
    async fn dial_udp(&self, src: IpAddr, t: &Target, outbound: &str) -> Result<Packets> {
        let (adapter, m) = self.select(src, t, outbound, Network::Udp)?;
        timeout(Duration::from_secs(12), async {
            match adapter {
                Adapter::Standard(a) | Adapter::Vision { udp: a, .. } => {
                    let ip = match t.addr() {
                        Some(ip) => ip,
                        None if !matches!(a.adapter_type(), meow_common::AdapterType::Direct) => {
                            std::net::Ipv4Addr::UNSPECIFIED.into()
                        }
                        None => tokio::net::lookup_host((t.host.as_str(), t.port))
                            .await?
                            .next()
                            .ok_or_else(|| anyhow::anyhow!("no destination address"))?
                            .ip(),
                    };
                    Ok(Packets::Standard(
                        a.dial_udp(&m).await?,
                        SocketAddr::new(ip, t.port),
                    ))
                }
                Adapter::AnyTls(a) => {
                    let mut request = vec![1];
                    request.extend(t.header()?);
                    let magic = Target {
                        host: "sp.v2.udp-over-tcp.arpa".into(),
                        port: 0,
                    };
                    let (r, w) =
                        tokio::io::split(any_stream(a, &magic, Some(request.into())).await?);
                    Ok(Packets::Framed(Mutex::new(r), Mutex::new(w)))
                }
            }
        })
        .await?
    }
}
pub(crate) fn verified_tls() -> Result<SslConnector> {
    let mut tls = SslConnector::builder(SslMethod::tls())?;
    tls.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    if let Some(path) = std::env::var_os("SSL_CERT_FILE") {
        tls.set_ca_file(path)?;
    } else if let Some(path) = [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/ssl/cert.pem",
        "/rom/etc/ssl/certs/ca-certificates.crt",
        "/usr/sbin/ca-bundle.crt",
    ]
    .iter()
    .find(|p| std::path::Path::new(p).is_file())
    {
        tls.set_ca_file(path)?;
    }
    Ok(tls.build())
}

fn adapter(u: &Upstream) -> Result<Adapter> {
    let (host, port) = u.endpoint()?;
    let dialer = Arc::new(DirectDialer);
    match u.protocol.as_str() {
        "anytls" => {
            let name = if u.server_name.is_empty() {
                host
            } else {
                u.server_name.clone()
            };
            Ok(Adapter::AnyTls(Client::new(
                &u.secret,
                u.server.clone(),
                Arc::new(AnyTlsConnector {
                    tls: verified_tls()?,
                    name,
                }),
                PaddingFactory::default(),
            )))
        }
        "socks5" => Ok(Adapter::Standard(Box::new(
            Socks5Adapter::new(
                &u.name,
                &host,
                port,
                (!u.username.is_empty()).then(|| (u.username.clone(), u.secret.clone())),
                false,
                false,
                dialer,
            )
            .with_udp(true),
        ))),
        "vless-reality" => {
            let (public_key, short_id) = u.reality_keys()?;
            let mut tls = TlsConfig::new(&u.server_name);
            tls.fingerprint = Some("chrome".into());
            tls.reality = Some(RealityConfig {
                public_key,
                short_id,
                support_x25519_mlkem768: true,
            });
            let make = || -> Result<VlessAdapter> {
                let mut layers = TransportChain::empty();
                layers.push(Box::new(TlsLayer::new(&tls)?));
                Ok(VlessAdapter::new(
                    &u.name,
                    &host,
                    port,
                    *uuid::Uuid::parse_str(&u.secret)?.as_bytes(),
                    (!u.flow.is_empty()).then_some(VlessFlow::XtlsRprxVision),
                    true,
                    layers,
                    dialer.clone(),
                ))
            };
            if u.flow.is_empty() {
                Ok(Adapter::Standard(Box::new(make()?)))
            } else {
                use meow_proxy::mux::{MuxOptions, Protocol};
                let udp = make()?.with_mux(MuxOptions {
                    protocol: Protocol::MuxCool,
                    ..Default::default()
                });
                Ok(Adapter::Vision {
                    tcp: Box::new(make()?),
                    udp: Box::new(udp),
                })
            }
        }
        _ => bail!("unknown protocol"),
    }
}
async fn any_stream(client: &Client, t: &Target, initial: Option<Bytes>) -> Result<Connection> {
    let (stream, session) = client
        .create_proxy_stream_with_payload((t.host.clone(), t.port), initial)
        .await?;
    let (local, bridge) = tokio::io::duplex(16384);
    let (mut from, mut to) = tokio::io::split(bridge);
    tokio::spawn(async move {
        let upload = async {
            let mut buf = [0; 8192];
            loop {
                let n = from.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                stream.send_data(Bytes::copy_from_slice(&buf[..n])).await?;
            }
            stream.close();
            Ok::<_, anyhow::Error>(())
        };
        let download = async {
            let mut buf = [0; 8192];
            let mut reader = stream.reader().lock().await;
            loop {
                let n = reader.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                to.write_all(&buf[..n]).await?;
            }
            to.shutdown().await?;
            Ok::<_, anyhow::Error>(())
        };
        let _ = tokio::try_join!(upload, download);
        stream.close();
        drop(session);
    });
    Ok(Box::new(local))
}
