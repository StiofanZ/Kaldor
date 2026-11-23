//! Bounded, process-local proxy activity. Only the authenticated panel reads snapshots.
use crate::outbound::Target;
use serde::Serialize;
use std::{
    collections::{BTreeMap, VecDeque},
    fs,
    hash::{BuildHasher, RandomState},
    io::{self, ErrorKind},
    net::{IpAddr, SocketAddr},
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::timeout,
};

const LIMIT: usize = 128;
const SOCKET: &str = "activity.sock";

#[derive(Clone, Serialize)]
struct Entry {
    #[serde(skip)]
    id: u64,
    time: u64,
    device: String,
    target: String,
    port: u16,
    ingress: &'static str,
    transport: &'static str,
    outbound: String,
    result: &'static str,
}
#[derive(Default)]
struct State {
    serial: u64,
    total: usize,
    active: BTreeMap<u64, (SocketAddr, Entry)>,
    recent: VecDeque<Entry>,
}
#[derive(Default, Clone)]
pub struct Activity {
    state: Arc<Mutex<State>>,
    device_key: RandomState,
}
pub struct Session {
    activity: Activity,
    id: u64,
}
impl Session {
    pub fn set_domain(&self, name: &str) {
        let name = name.trim_end_matches('.');
        if !valid_host(name) || name.parse::<IpAddr>().is_ok() {
            return;
        }
        let mut state = self.activity.state.lock().unwrap();
        if let Some((_, entry)) = state.active.get_mut(&self.id) {
            entry.target = name.into();
        }
        if let Some(entry) = state.recent.iter_mut().find(|e| e.id == self.id) {
            entry.target = name.into();
        }
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        let mut state = self.activity.state.lock().unwrap();
        state.active.remove(&self.id);
        state.total -= 1;
    }
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
}

fn display_target(host: &str) -> String {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) if ip.is_private() || ip.is_link_local() || ip.is_loopback() => {
            "局域网".into()
        }
        Ok(IpAddr::V6(ip))
            if ip.is_unique_local() || ip.is_unicast_link_local() || ip.is_loopback() =>
        {
            "局域网".into()
        }
        Ok(ip) => ip.to_string(),
        Err(_) if valid_host(host) => host.into(),
        _ => "未知目标".into(),
    }
}

pub struct Access<'a> {
    pub source: SocketAddr,
    pub target: &'a Target,
    pub domain: &'a str,
    pub ingress: &'static str,
    pub transport: &'static str,
    pub outbound: &'a str,
}
impl Activity {
    pub fn record<T>(
        &self,
        access: Access<'_>,
        result: anyhow::Result<T>,
    ) -> anyhow::Result<(T, Session)> {
        let mut entry = Entry {
            id: 0,
            time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            device: format!(
                "{:08x}",
                self.device_key.hash_one(access.source.ip()) as u32
            ),
            target: display_target(if access.domain.is_empty() {
                &access.target.host
            } else {
                access.domain
            }),
            port: access.target.port,
            ingress: access.ingress,
            transport: access.transport,
            outbound: access.outbound.into(),
            result: if result.is_ok() {
                "opened"
            } else if access.outbound == "reject" {
                "rejected"
            } else {
                "failed"
            },
        };
        let mut state = self.state.lock().unwrap();
        if state.recent.len() == LIMIT {
            state.recent.pop_back();
        }
        state.serial += 1;
        let id = state.serial;
        entry.id = id;
        state.recent.push_front(entry.clone());
        let value = result?;
        state.total += 1;
        if state.active.len() < LIMIT {
            state.active.insert(id, (access.source, entry));
        }
        Ok((
            value,
            Session {
                activity: self.clone(),
                id,
            },
        ))
    }
    fn snapshot(&self) -> Vec<u8> {
        let (total, active, recent) = {
            let state = self.state.lock().unwrap();
            (
                state.total,
                state.active.values().rev().cloned().collect::<Vec<_>>(),
                state.recent.clone(),
            )
        };
        serde_json::to_vec(&serde_json::json!({"total":total,"active":active,"recent":recent}))
            .unwrap()
    }
    pub fn listener(dir: &Path) -> io::Result<UnixListener> {
        let path = dir.join(SOCKET);
        let socket = match UnixListener::bind(&path) {
            Ok(listener) => listener,
            Err(e) if e.kind() == ErrorKind::AddrInUse => {
                // An unclean exit can leave the socket inode in the private runtime directory.
                use std::os::unix::{fs::FileTypeExt, net::UnixStream};
                if !fs::symlink_metadata(&path)?.file_type().is_socket()
                    || !UnixStream::connect(&path)
                        .is_err_and(|err| err.kind() == ErrorKind::ConnectionRefused)
                {
                    return Err(e);
                }
                fs::remove_file(&path)?;
                UnixListener::bind(&path)?
            }
            Err(e) => return Err(e),
        };
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(socket)
    }
    pub async fn serve(self, socket: UnixListener) -> anyhow::Result<()> {
        loop {
            let (mut client, _) = socket.accept().await?;
            let data = self.snapshot();
            let _ = timeout(Duration::from_secs(1), client.write_all(&data)).await;
        }
    }
}

// The immutable firmware exposes a page CGI. Embed the in-memory snapshot there
// without changing the configuration JSON accepted by the existing view/edit API.
pub async fn panel_data(dir: &Path) -> String {
    let read = async {
        let mut socket = UnixStream::connect(dir.join(SOCKET)).await?;
        let mut data = String::new();
        socket.read_to_string(&mut data).await?;
        Ok::<_, io::Error>(data)
    };
    match timeout(Duration::from_secs(2), read).await {
        Ok(Ok(data)) if !data.is_empty() => data.replace('<', "\\u003c"),
        _ => "null".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshots_are_bounded_and_sessions_leave_on_drop() {
        let activity = Activity::default();
        let target = Target {
            host: "router.test".into(),
            port: 443,
        };
        let mut held = Vec::new();
        for _ in 0..LIMIT + 8 {
            let (_, session) = activity
                .record(
                    Access {
                        source: "192.0.2.4:12345".parse().unwrap(),
                        target: &target,
                        domain: "",
                        ingress: "HTTP",
                        transport: "TCP",
                        outbound: "direct",
                    },
                    Ok(()),
                )
                .unwrap();
            held.push(session);
        }
        let snapshot =
            || serde_json::from_slice::<serde_json::Value>(&activity.snapshot()).unwrap();
        let result = snapshot();
        assert_eq!(result["total"], LIMIT + 8);
        assert_eq!(result["active"].as_array().unwrap().len(), LIMIT);
        assert_eq!(result["recent"].as_array().unwrap().len(), LIMIT);
        assert!(!result["recent"].to_string().contains("192.0.2.4"));
        drop(held);
        assert_eq!(snapshot()["total"], 0);
        assert_eq!(display_target("user:secret@example.test/path"), "未知目标");
        assert_eq!(display_target("127.0.0.1"), "局域网");
    }
}
