use super::*;
use crate::activity::Access;
use boring::ssl::SslConnector;
use bytes::Bytes;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, StatusCode, client::conn::http1};
use hyper_util::rt::TokioIo;
use meow_common::Network;
use std::sync::Mutex;

const HOST: &str = "cloudflare-dns.com";
const RESOLVER_IP: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
const LIMIT: Duration = Duration::from_secs(12);
type Sender = http1::SendRequest<Full<Bytes>>;

pub(super) struct Resolver {
    tls: SslConnector,
    idle: Mutex<Vec<(String, Sender)>>,
    slots: Arc<Semaphore>,
}

impl Resolver {
    pub fn new() -> Result<Self> {
        Ok(Self {
            tls: crate::outbound::verified_tls()?,
            idle: Mutex::new(Vec::new()),
            slots: Arc::new(Semaphore::new(32)),
        })
    }

    async fn connect(
        &self,
        engine: &Engine,
        src: SocketAddr,
        resolver: &Target,
        outbound: &str,
    ) -> Result<Sender> {
        let up = engine.dial_tcp(src.ip(), resolver, outbound).await?;
        let tls = tokio_boring::connect(self.tls.configure()?, HOST, up)
            .await
            .map_err(|e| anyhow::anyhow!("DoH TLS: {e}"))?;
        let (tx, connection) = http1::handshake(TokioIo::new(tls)).await?;
        tokio::spawn(connection);
        Ok(tx)
    }

    async fn exchange(
        &self,
        engine: &Engine,
        src: SocketAddr,
        resolver: &Target,
        outbound: &str,
        wire: Bytes,
    ) -> Result<Bytes> {
        let reused = {
            let mut idle = self.idle.lock().unwrap();
            idle.retain(|(_, tx)| !tx.is_closed());
            idle.iter()
                .position(|(key, _)| key == outbound)
                .map(|i| idle.swap_remove(i).1)
        };
        let mut tx = match reused {
            Some(tx) => tx,
            None => self.connect(engine, src, resolver, outbound).await?,
        };
        let request = || {
            Request::post("/dns-query")
                .header("host", HOST)
                .header("content-type", "application/dns-message")
                .header("accept", "application/dns-message")
                .body(Full::new(wire.clone()))
        };
        // A peer can close a keep-alive connection between the idle check and a write.
        let response = match tx.try_send_request(request()?).await {
            Ok(response) => response,
            Err(e) if e.message().is_some() => {
                tx = self.connect(engine, src, resolver, outbound).await?;
                tx.send_request(request()?).await?
            }
            Err(e) => return Err(e.into_error().into()),
        };
        ensure!(
            response.status() == StatusCode::OK,
            "DoH HTTP status {}",
            response.status()
        );
        ensure!(
            response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .eq_ignore_ascii_case("application/dns-message")),
            "invalid DoH content type"
        );
        let data = Limited::new(response.into_body(), u16::MAX as usize)
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("DoH body: {e}"))?
            .to_bytes();
        let mut idle = self.idle.lock().unwrap();
        if idle.len() < 8 && !tx.is_closed() {
            idle.push((outbound.to_owned(), tx));
        }
        Ok(data)
    }

    async fn answer(
        &self,
        service: &Service,
        src: SocketAddr,
        wire: Vec<u8>,
        udp: bool,
    ) -> Result<Bytes> {
        let engine = &service.engine;
        let query = Message::from_vec(&wire)?;
        ensure!(
            query.metadata.message_type == MessageType::Query
                && query.metadata.op_code == OpCode::Query
                && query.queries.len() == 1,
            "expected a single DNS question"
        );
        let resolver = &Target {
            host: RESOLVER_IP.to_string(),
            port: 443,
        };
        let selected = if engine.cfg.uses_dns_rules() {
            // A literal dot within a wire label must never become a suffix boundary.
            let name = query.queries[0].name().to_ascii().replace(r"\.", r"\056");
            engine.cfg.query_outbound(
                src.ip(),
                service.reserved,
                &name,
                if udp { Network::Udp } else { Network::Tcp },
            )
        } else {
            None
        };
        let outbound = selected.unwrap_or_else(|| {
            engine.cfg.route(
                src.ip(),
                service.reserved,
                resolver.addr(),
                443,
                HOST,
                Network::Tcp,
            )
        });
        let wire = Bytes::from(wire);
        let (outbound, result) = engine
            .via(outbound, |node| {
                let query = &query;
                let wire = wire.clone();
                async move {
                    let data =
                        timeout(LIMIT, self.exchange(engine, src, resolver, node, wire)).await??;
                    let reply = Message::from_vec(&data)?;
                    ensure!(
                        reply.metadata.id == query.metadata.id
                            && reply.metadata.message_type == MessageType::Response
                            && reply.metadata.op_code == OpCode::Query
                            && reply.queries == query.queries,
                        "unmatched DoH reply"
                    );
                    if udp && data.len() > usize::from(query.max_payload().min(1232)) {
                        let mut truncated = reply.truncate();
                        truncated.edns = None;
                        return Ok(truncated.to_vec()?.into());
                    }
                    Ok(data)
                }
            })
            .await;
        match engine.activity.record(
            Access {
                source: src,
                target: resolver,
                domain: HOST,
                ingress: "透明 DNS",
                transport: "TCP",
                outbound,
            },
            result,
        ) {
            Ok((body, _)) => Ok(body),
            Err(_) => {
                let mut fail =
                    Message::error_msg(query.metadata.id, OpCode::Query, ResponseCode::ServFail);
                fail.metadata.recursion_desired = query.metadata.recursion_desired;
                fail.metadata.recursion_available = true;
                fail.queries = query.queries;
                Ok(fail.to_vec()?.into())
            }
        }
    }

    pub fn udp(
        self: &Arc<Self>,
        service: &Service,
        original_v6: Option<SocketAddr>,
        sock: &Arc<UdpSocket>,
        src: SocketAddr,
        query: &[u8],
    ) {
        if query.len() < 12 {
            return;
        }
        let Ok(permit) = self.slots.clone().try_acquire_owned() else {
            return;
        };
        let resolver = self.clone();
        let (service, sock, query) = (service.clone(), sock.clone(), query.to_vec());
        tokio::spawn(async move {
            let _permit = permit;
            if let Ok(reply) = resolver.answer(&service, src, query, true).await {
                if let Some(original) = original_v6 {
                    let _ = super::ipv6::send_dns(&service, original, src, &reply);
                } else {
                    let _ = sock.send_to(&reply, src).await;
                }
            }
        });
    }

    pub async fn tcp(
        &self,
        service: &Service,
        src: SocketAddr,
        stream: &mut TcpStream,
    ) -> Result<()> {
        loop {
            let packet = timeout(LIMIT, async {
                let length = stream.read_u16().await? as usize;
                ensure!(length >= 12, "short DNS frame");
                let mut packet = vec![0; length];
                stream.read_exact(&mut packet).await?;
                Ok::<_, anyhow::Error>(packet)
            })
            .await??;
            let _permit = self.slots.try_acquire()?;
            let reply = self.answer(service, src, packet, false).await?;
            timeout(LIMIT, async {
                stream.write_u16(reply.len().try_into()?).await?;
                stream.write_all(&reply).await?;
                Ok::<_, anyhow::Error>(())
            })
            .await??;
        }
    }
}
