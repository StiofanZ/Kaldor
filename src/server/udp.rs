use super::*;
use std::{collections::HashMap, io, mem, os::fd::AsRawFd};
use tokio::{io::Interest, sync::mpsc, task::JoinSet};
pub(super) fn original_address(sock: &Socket, ipv6: bool) -> io::Result<()> {
    let flag: libc::c_int = 1;
    // setsockopt copies this integer before returning.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            if ipv6 {
                libc::IPPROTO_IPV6
            } else {
                libc::IPPROTO_IP
            },
            if ipv6 {
                libc::IPV6_RECVORIGDSTADDR
            } else {
                libc::IP_RECVORIGDSTADDR
            },
            (&raw const flag).cast(),
            mem::size_of_val(&flag) as _,
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn address(sa: libc::sockaddr_in) -> SocketAddr {
    (
        Ipv4Addr::from(sa.sin_addr.s_addr.to_ne_bytes()),
        u16::from_be(sa.sin_port),
    )
        .into()
}
fn receive(sock: &UdpSocket, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    // The ancillary buffer is aligned for cmsghdr. Source, iovec and control
    // storage stay live for recvmsg and the subsequent bounded header walk.
    unsafe {
        let mut src: libc::sockaddr_storage = mem::zeroed();
        let mut control = [0usize; 16];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut msg: libc::msghdr = mem::zeroed();
        msg.msg_name = (&raw mut src).cast();
        msg.msg_namelen = mem::size_of_val(&src) as _;
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = mem::size_of_val(&control) as _;
        let n = libc::recvmsg(sock.as_raw_fd(), &mut msg, 0);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut hdr = libc::CMSG_FIRSTHDR(&msg);
        while !hdr.is_null() {
            if src.ss_family as i32 == libc::AF_INET
                && (*hdr).cmsg_level == libc::IPPROTO_IP
                && (*hdr).cmsg_type == libc::IP_ORIGDSTADDR
                && (*hdr).cmsg_len as usize
                    >= libc::CMSG_LEN(mem::size_of::<libc::sockaddr_in>() as _) as usize
            {
                let dst = libc::CMSG_DATA(hdr)
                    .cast::<libc::sockaddr_in>()
                    .read_unaligned();
                return Ok((
                    n as usize,
                    address((&raw const src).cast::<libc::sockaddr_in>().read()),
                    address(dst),
                ));
            }
            if src.ss_family as i32 == libc::AF_INET6
                && (*hdr).cmsg_level == libc::IPPROTO_IPV6
                && (*hdr).cmsg_type == libc::IPV6_ORIGDSTADDR
                && (*hdr).cmsg_len as usize
                    >= libc::CMSG_LEN(mem::size_of::<libc::sockaddr_in6>() as _) as usize
            {
                let to_addr = |a: libc::sockaddr_in6| {
                    SocketAddr::V6(std::net::SocketAddrV6::new(
                        a.sin6_addr.s6_addr.into(),
                        u16::from_be(a.sin6_port),
                        0,
                        a.sin6_scope_id,
                    ))
                };
                return Ok((
                    n as usize,
                    to_addr((&raw const src).cast::<libc::sockaddr_in6>().read()),
                    to_addr(
                        libc::CMSG_DATA(hdr)
                            .cast::<libc::sockaddr_in6>()
                            .read_unaligned(),
                    ),
                ));
            }
            hdr = libc::CMSG_NXTHDR(&msg, hdr);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "original destination missing",
    ))
}
type Key = (SocketAddr, Target);
struct Flows {
    workers: JoinSet<()>,
    senders: HashMap<Key, mpsc::Sender<Vec<u8>>>,
    service: Service,
    manual: Option<Arc<UdpSocket>>,
}
impl Flows {
    fn new(service: Service, manual: Option<Arc<UdpSocket>>) -> Self {
        Self {
            workers: JoinSet::new(),
            senders: HashMap::new(),
            service,
            manual,
        }
    }
    fn feed(&mut self, src: SocketAddr, t: Target, data: &[u8]) {
        while self.workers.try_join_next().is_some() {}
        let key = (src, t.clone());
        if let Some(tx) = self.senders.get(&key)
            && !tx.is_closed()
        {
            let _ = tx.try_send(data.to_vec());
            return;
        }
        self.senders.retain(|_, tx| !tx.is_closed());
        if self.senders.len() >= 256 {
            return;
        }
        let permit = if self.manual.is_none() {
            let Ok(permit) = self.service.udp_slots.clone().try_acquire_owned() else {
                return;
            };
            Some(permit)
        } else {
            None
        };
        let (tx, rx) = mpsc::channel::<Vec<u8>>(16);
        let _ = tx.try_send(data.to_vec());
        self.senders.insert(key, tx);
        let service = self.service.clone();
        let manual = self.manual.clone();
        self.workers.spawn(async move {
            let _permit = permit;
            let _ = forward(service, manual, src, t, rx).await;
        });
    }
}

async fn forward(
    service: Service,
    manual: Option<Arc<UdpSocket>>,
    src: SocketAddr,
    target: Target,
    mut outgoing: mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    let ingress = if manual.is_some() {
        "SOCKS5"
    } else {
        "透明代理"
    };
    let mut probe = manual.is_none().then(super::quic::Probe::default);
    let (upstream, session) = service
        .engine
        .udp(src, &target, ingress, service.reserved)
        .await?;
    let (socket, prefix) = match manual {
        Some(socket) => {
            let mut prefix = vec![0; 3];
            prefix.extend(target.header()?);
            (socket, prefix)
        }
        None => {
            let dest = SocketAddr::new(
                target.addr().context("missing transparent destination")?,
                target.port,
            );
            let socket = service.socket(true, true, dest)?;
            (Arc::new(UdpSocket::from_std(socket.into())?), Vec::new())
        }
    };
    let mut response = vec![0; 65535 + prefix.len()];
    response[..prefix.len()].copy_from_slice(&prefix);
    loop {
        // A framed read can consume a partial length header. Keep it alive across writes.
        let received = {
            let read = upstream.recv(&mut response[prefix.len()..]);
            tokio::pin!(read);
            loop {
                tokio::select! {
                    result = &mut read => break result?,
                    packet = outgoing.recv() => {
                        let Some(packet) = packet else { return Ok(()) };
                        timeout(Duration::from_secs(12), upstream.send(&packet)).await??;
                        if let Some(observer) = &mut probe {
                            if let Some(name) = observer.inspect(&packet) {
                                session.set_domain(&name);
                            }
                            if observer.finished() { probe = None; }
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_secs(60)) => return Ok(()),
                }
            }
        };
        socket
            .send_to(&response[..prefix.len() + received], src)
            .await?;
    }
}
pub(super) async fn transparent(sock: UdpSocket, s: Service) -> Result<()> {
    let sock = Arc::new(sock);
    let mut flows = Flows::new(s.clone(), None);
    let mut data = vec![0; 65535];
    loop {
        sock.readable().await?;
        match sock.try_io(Interest::READABLE, || receive(&sock, &mut data)) {
            Ok((n, src, dst)) if dst.is_ipv6() && dst.port() == 53 => {
                if let Some(resolver) = &s.dns {
                    resolver.udp(&s, Some(dst), &sock, src, &data[..n]);
                }
            }
            Ok((n, src, dst)) if dst == SocketAddr::from((s.lan, TRANSPARENT_PORT)) => {
                if let Some(resolver) = s.device_dns(src) {
                    resolver.udp(&s, None, &sock, src, &data[..n]);
                }
            }
            Ok((n, src, dst)) => flows.feed(src, Target::from_socket(dst), &data[..n]),
            Err(e)
                if e.kind() != io::ErrorKind::WouldBlock
                    && e.kind() != io::ErrorKind::InvalidData =>
            {
                return Err(e.into());
            }
            _ => {}
        }
    }
}
pub(super) async fn associate(
    mut c: TcpStream,
    src: SocketAddr,
    hint: Target,
    s: Service,
) -> Result<()> {
    if !hint
        .addr()
        .is_some_and(|ip| ip.is_unspecified() || ip == src.ip())
    {
        return reply(&mut c, 2, None).await;
    }
    let sock = Arc::new(s.datagram(0, false)?);
    reply(&mut c, 0, Some(sock.local_addr()?)).await?;
    let mut flows = Flows::new(s, Some(sock.clone()));
    let mut port = hint.port;
    let mut data = vec![0; 65535];
    loop {
        let mut ctl = [0];
        tokio::select! {
            _=c.read(&mut ctl)=>return Ok(()),
            result=sock.recv_from(&mut data)=>{
                let (n,addr)=result?;if addr.ip()!=src.ip() || port!=0 && port!=addr.port() || !data[..n].starts_with(&[0,0,0]){continue}
                let mut body=&data[3..n];if let Ok(t)=target(&mut body).await && t.port!=0 {port=addr.port();flows.feed(addr,t,body);}
            }
        }
    }
}
