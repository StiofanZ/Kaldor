use super::*;
use std::{
    collections::BTreeMap, fs, net::Ipv6Addr, os::fd::AsRawFd, path::Path, process::Command,
};

fn nvram(key: &str) -> Result<String> {
    let value = Command::new("nvram").args(["get", key]).output()?;
    ensure!(value.status.success(), "cannot read {key}");
    Ok(String::from_utf8(value.stdout)?)
}

/// Bind a separate loopback-only transparent port for each reserved IPv4 identity.
/// The firewall selects this port by the inbound MAC, including for temporary IPv6 addresses.
pub(super) fn start(
    service: &Service,
    dir: &Path,
    workers: &mut tokio::task::JoinSet<Result<()>>,
) -> Result<()> {
    let cfg = &service.engine.cfg;
    let mut selectors = BTreeMap::new();
    if cfg.has_ipv4_source_rules() && nvram("dhcp_static_x")?.trim() == "1" {
        let list = nvram("dhcp_staticlist")?;
        for row in list.trim().split('<') {
            let mut fields = row.split('>');
            let (Some(mac), Some(ip)) = (fields.next(), fields.next()) else {
                continue;
            };
            let Ok(ip) = ip.parse::<Ipv4Addr>() else {
                continue;
            };
            if cfg.matches_reserved_source(ip) {
                ensure!(
                    mac.len() == 17
                        && mac
                            .split(':')
                            .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit())),
                    "invalid MAC in selected reservation"
                );
                let old = selectors.insert(("mac", mac.to_ascii_lowercase()), Some(ip));
                ensure!(
                    old.is_none() || old == Some(Some(ip)),
                    "ambiguous DHCP reservation"
                );
            }
        }
    }
    // BTreeMap emits specific MAC matches before the catch-all network.
    selectors.insert(("net", "::/0".to_owned()), None);
    let mut plan = String::new();
    for ((kind, selector), reserved) in selectors {
        let tcp = service.socket(false, true, (Ipv6Addr::LOCALHOST, 0).into())?;
        tcp.listen(128)?;
        let local = tcp
            .local_addr()?
            .as_socket()
            .context("invalid IPv6 listener")?;
        let udp = service.socket(true, true, local)?;
        udp::original_address(&udp, true)?;
        let mut instance = service.clone();
        instance.reserved = reserved;
        let listener = TcpListener::from_std(tcp.into())?;
        workers.spawn(accept(listener, instance.clone(), true));
        let datagrams = UdpSocket::from_std(udp.into())?;
        workers.spawn(udp::transparent(datagrams, instance));
        use std::fmt::Write;
        writeln!(plan, "{kind} {selector} {}", local.port())?;
    }
    fs::write(dir.join("ipv6-rules"), plan)?;
    Ok(())
}

/// A query can target the router's own port 53, already bound by dnsmasq.
/// A raw UDP reply preserves its source without competing for that port.
pub(super) fn send_dns(
    service: &Service,
    original: SocketAddr,
    client: SocketAddr,
    data: &[u8],
) -> Result<()> {
    let sock = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::UDP))?;
    sock.bind_device(Some(service.iface.as_bytes()))?;
    sock.set_ip_transparent_v6(true)?;
    sock.set_nonblocking(true)?;
    let mut source = original;
    source.set_port(0);
    sock.bind(&source.into())?;
    let checksum_offset: libc::c_int = 6;
    // Linux fills the UDP checksum using the IPv6 pseudo-header.
    if unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_CHECKSUM,
            (&raw const checksum_offset).cast(),
            std::mem::size_of_val(&checksum_offset) as _,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let len = u16::try_from(8 + data.len())?;
    let mut packet = Vec::with_capacity(len as usize);
    for field in [original.port(), client.port(), len, 0] {
        packet.extend_from_slice(&field.to_be_bytes());
    }
    packet.extend_from_slice(data);
    let mut dest = client;
    dest.set_port(0);
    sock.send_to(&packet, &dest.into())?;
    Ok(())
}
