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
fn sni(mut hello: &[u8]) -> Option<String> {
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
pub(super) async fn read(c: &mut TcpStream, port: u16) -> Result<(Vec<u8>, String)> {
    let mut captured = Vec::new();
    if !matches!(port, 80 | 8080 | 443 | 8443) {
        return Ok((captured, String::new()));
    }
    let mut chunk = [0; 2048];
    let sniff = async {
        let mut records = 0;
        let mut handshake = Vec::new();
        while captured.len() < 32768 {
            let cap = chunk.len().min(32768 - captured.len());
            let n = c.read(&mut chunk[..cap]).await.ok()?;
            if n == 0 {
                break;
            }
            captured.extend_from_slice(&chunk[..n]);
            if matches!(port, 80 | 8080) {
                if let Some(end) = captured.windows(4).position(|p| p == b"\r\n\r\n") {
                    return std::str::from_utf8(&captured[..end])
                        .ok()?
                        .lines()
                        .skip(1)
                        .filter_map(|l| l.split_once(':'))
                        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
                        .and_then(|(_, v)| v.trim().parse::<hyper::http::uri::Authority>().ok())
                        .map(|a| a.host().to_owned());
                }
            } else {
                while let Some(head) = captured.get(records..records + 5) {
                    if head[0] != 22 {
                        return None;
                    }
                    let end = records + 5 + usize::from(u16::from_be_bytes([head[3], head[4]]));
                    let Some(body) = captured.get(records + 5..end) else {
                        break;
                    };
                    handshake.extend_from_slice(body);
                    records = end;
                    if handshake.len() >= 4 {
                        let mut data = &handshake[..];
                        if number(&mut data, 1)? != 1 {
                            return None;
                        }
                        if let Some(hello) = field(&mut data, 3) {
                            return sni(hello);
                        }
                    }
                }
            }
        }
        None
    };
    let domain = timeout(Duration::from_secs(1), sniff)
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
    Ok((captured, domain))
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
