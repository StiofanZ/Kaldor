use super::*;
fn part<'a>(src: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    let (v, rest) = src.split_at_checked(n)?;
    *src = rest;
    Some(v)
}
fn number(src: &mut &[u8], count: usize) -> Option<usize> {
    Some(
        part(src, count)?
            .iter()
            .fold(0, |n, b| (n << 8) + usize::from(*b)),
    )
}
fn field<'a>(src: &mut &'a [u8], count: usize) -> Option<&'a [u8]> {
    let n = number(src, count)?;
    part(src, n)
}
pub(super) fn sni(mut hello: &[u8]) -> Option<String> {
    part(&mut hello, 34)?;
    field(&mut hello, 1)?;
    field(&mut hello, 2)?;
    field(&mut hello, 1)?;
    let mut ext = field(&mut hello, 2)?;
    while !ext.is_empty() {
        let typ = number(&mut ext, 2)?;
        let mut data = field(&mut ext, 2)?;
        if typ != 0 {
            continue;
        }
        let mut names = field(&mut data, 2)?;
        while !names.is_empty() {
            let typ = number(&mut names, 1)?;
            let name = field(&mut names, 2)?;
            if typ == 0 {
                return Some(std::str::from_utf8(name).ok()?.to_string());
            }
        }
    }
    None
}
const LIMIT: usize = 32768;

pub(super) fn supported(port: u16) -> bool {
    matches!(port, 80 | 8080 | 443 | 8443)
}

// A partial header returns None. A complete or unrecognizable header returns
// Some, including when it carries no usable name.
#[derive(Default)]
struct Probe {
    scanned: usize,
    handshake: Vec<u8>,
}
impl Probe {
    fn inspect(&mut self, wire: &[u8], port: u16) -> Option<Option<String>> {
        if matches!(port, 80 | 8080) {
            let end = wire[self.scanned..]
                .windows(4)
                .position(|p| p == b"\r\n\r\n");
            if let Some(end) = end {
                let name = std::str::from_utf8(&wire[..self.scanned + end])
                    .ok()
                    .and_then(|head| {
                        head.lines()
                            .skip(1)
                            .filter_map(|l| l.split_once(':'))
                            .find(|(k, _)| k.eq_ignore_ascii_case("host"))
                            .and_then(|(_, v)| v.trim().parse::<hyper::http::uri::Authority>().ok())
                            .map(|a| a.host().to_owned())
                    });
                return Some(name);
            }
            self.scanned = wire.len().saturating_sub(3);
        } else {
            while let Some(head) = wire.get(self.scanned..self.scanned + 5) {
                if head[0] != 22 {
                    return Some(None);
                }
                let end = self.scanned + 5 + usize::from(u16::from_be_bytes([head[3], head[4]]));
                let body = wire.get(self.scanned + 5..end)?;
                self.handshake.extend_from_slice(body);
                self.scanned = end;
                if self.handshake.len() >= 4 {
                    let mut data = &self.handshake[..];
                    if number(&mut data, 1)? != 1 {
                        return Some(None);
                    }
                    if let Some(hello) = field(&mut data, 3) {
                        return Some(sni(hello));
                    }
                }
            }
        }
        None
    }
}

pub(super) async fn read(c: &mut TcpStream, port: u16) -> Result<(Vec<u8>, String)> {
    let mut captured = Vec::new();
    if !supported(port) {
        return Ok((captured, String::new()));
    }
    let mut probe = Probe::default();
    let sniff = async {
        let mut chunk = [0; 2048];
        while captured.len() < LIMIT {
            let cap = chunk.len().min(LIMIT - captured.len());
            let n = c.read(&mut chunk[..cap]).await?;
            if n == 0 {
                break;
            }
            captured.extend_from_slice(&chunk[..n]);
            if let Some(name) = probe.inspect(&captured, port) {
                return Ok::<_, std::io::Error>(name);
            }
        }
        Ok(None)
    };
    let domain = match timeout(Duration::from_secs(1), sniff).await {
        Ok(result) => result?.unwrap_or_default(),
        Err(_) => String::new(),
    };
    Ok((captured, domain))
}

// Observe only bytes delivered by the ordinary relay. No reads, timers or
// DNS lookups are added to the connection's establishment or the return path.
pub(super) struct ObservedReader<'a> {
    client: tokio::net::tcp::ReadHalf<'a>,
    pending: Option<(Probe, Vec<u8>)>,
    port: u16,
    session: &'a crate::activity::Session,
}
impl<'a> ObservedReader<'a> {
    pub fn new(
        client: tokio::net::tcp::ReadHalf<'a>,
        port: u16,
        session: &'a crate::activity::Session,
    ) -> Self {
        Self {
            client,
            pending: Some(Default::default()),
            port,
            session,
        }
    }
}
impl AsyncRead for ObservedReader<'_> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        std::task::ready!(std::pin::Pin::new(&mut self.client).poll_read(cx, buf))?;
        let port = self.port;
        if let Some((probe, wire)) = &mut self.pending {
            let chunk = &buf.filled()[before..];
            wire.extend_from_slice(&chunk[..chunk.len().min(LIMIT - wire.len())]);
            if let Some(name) = probe.inspect(wire, port) {
                if let Some(name) = name {
                    self.session.set_domain(&name);
                }
                self.pending = None;
            } else if wire.len() == LIMIT || chunk.is_empty() {
                self.pending = None;
            }
        }
        std::task::Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn replays_fragmented_client_hello() {
        let mut hello = vec![3, 3];
        hello.extend([0; 32]);
        hello.extend([0, 0, 2, 0x13, 1, 1, 0]);
        let name = b"test.example";
        let mut ext = vec![
            0,
            0,
            0,
            (5 + name.len()) as u8,
            0,
            (3 + name.len()) as u8,
            0,
            0,
            name.len() as u8,
        ];
        ext.extend(name);
        hello.extend((ext.len() as u16).to_be_bytes());
        hello.extend(ext);
        let mut hs = vec![1, 0, 0, hello.len() as u8];
        hs.extend(hello);
        let mut wire = Vec::new();
        for segment in hs.chunks(26) {
            wire.extend([22, 3, 1, 0, segment.len() as u8]);
            wire.extend(segment);
        }
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let mut tx = TcpStream::connect(l.local_addr().unwrap()).await.unwrap();
        let (mut rx, _) = l.accept().await.unwrap();
        tx.write_all(&wire).await.unwrap();
        let (seen, domain) = read(&mut rx, 443).await.unwrap();
        assert_eq!(domain, "test.example");
        assert_eq!(seen, wire);
    }
}
