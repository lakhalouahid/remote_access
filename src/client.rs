use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Mutex};
use tokio::time::{timeout, Duration};
use tracing::{error, info, warn};

use crate::framed::{FramedReader, FramedWriter};
use crate::p2p_udp::{bind_and_discover, punch, ReliableUdp};
use crate::protocol::{Message, Role};
use crate::tls::quinn_client_config_trust;

const TCP_TUNNEL_CHUNK: usize = 1024;

pub enum TunnelInner {
    Tcp {
        r: Arc<Mutex<FramedReader<tokio::net::tcp::OwnedReadHalf>>>,
        w: Arc<Mutex<FramedWriter<tokio::net::tcp::OwnedWriteHalf>>>,
    },
    Quic {
        _endpoint: quinn::Endpoint,
        r: Arc<Mutex<FramedReader<quinn::RecvStream>>>,
        w: Arc<Mutex<FramedWriter<quinn::SendStream>>>,
    },
    Udp {
        transport: Arc<ReliableUdp>,
        rx: Arc<Mutex<mpsc::Receiver<Message>>>,
    },
}

#[derive(Clone)]
pub struct Tunnel {
    inner: Arc<TunnelInner>,
}

impl Tunnel {
    pub async fn recv(&self) -> Result<Option<Message>> {
        match &*self.inner {
            TunnelInner::Tcp { r, .. } => r.lock().await.recv().await,
            TunnelInner::Quic { r, .. } => r.lock().await.recv().await,
            TunnelInner::Udp { rx, .. } => Ok(rx.lock().await.recv().await),
        }
    }

    pub async fn send(&self, msg: &Message) -> Result<()> {
        match &*self.inner {
            TunnelInner::Tcp { w, .. } => w.lock().await.send(msg).await,
            TunnelInner::Quic { w, .. } => w.lock().await.send(msg).await,
            TunnelInner::Udp { transport, .. } => transport.send(msg).await,
        }
    }
}

pub async fn open_tcp(server: SocketAddr) -> Result<Tunnel> {
    let s = TcpStream::connect(server).await?;
    let (r, w) = s.into_split();
    Ok(Tunnel {
        inner: Arc::new(TunnelInner::Tcp {
            r: Arc::new(Mutex::new(FramedReader::new(r))),
            w: Arc::new(Mutex::new(FramedWriter::new(w))),
        }),
    })
}

pub async fn open_quic(
    bind: SocketAddr,
    server: SocketAddr,
    server_name: &str,
    trust_cert: &Path,
) -> Result<Tunnel> {
    let mut endpoint = quinn::Endpoint::client(bind).context("quinn client bind")?;
    let cfg = quinn_client_config_trust(trust_cert)?;
    if server_name.parse::<std::net::IpAddr>().is_err() {
        let _ = rustls::pki_types::ServerName::try_from(server_name.to_string()).map_err(|_| {
            anyhow!("invalid TLS server name (use a DNS name or IP present in the cert SANs)")
        })?;
    }
    endpoint.set_default_client_config(cfg);
    let conn = endpoint
        .connect(server, server_name)
        .context("quic connect")?
        .await
        .context("quic handshake")?;
    let (send, recv) = conn.open_bi().await.context("open_bi")?;
    Ok(Tunnel {
        inner: Arc::new(TunnelInner::Quic {
            _endpoint: endpoint,
            r: Arc::new(Mutex::new(FramedReader::new(recv))),
            w: Arc::new(Mutex::new(FramedWriter::new(send))),
        }),
    })
}

pub async fn join_session(t: &Tunnel, session: &str, role: Role, want_udp: bool) -> Result<()> {
    t.send(&Message::Join {
        role,
        session: session.to_string(),
        want_udp,
    })
    .await?;
    match t.recv().await? {
        Some(Message::AckOk) => Ok(()),
        Some(Message::AckErr(e)) => Err(anyhow!("{}", e)),
        Some(m) => Err(anyhow!("unexpected message after join: {m:?}")),
        None => Err(anyhow!("relay closed before ack")),
    }
}

pub async fn switch_to_p2p_udp(
    relay_tunnel: Tunnel,
    p2p_bind: SocketAddr,
    discovery_server: SocketAddr,
    timeout_secs: u64,
) -> Result<Tunnel> {
    let (socket, observed_addr) = match bind_and_discover(p2p_bind, discovery_server).await {
        Ok(v) => v,
        Err(e) => {
            warn!("p2p udp discovery failed, falling back to relay: {e:#}");
            let _ = relay_tunnel
                .send(&Message::P2pFailed {
                    reason: "discovery failed".to_string(),
                })
                .await;
            return Ok(relay_tunnel);
        }
    };
    relay_tunnel
        .send(&Message::P2pCandidate {
            addr: observed_addr.to_string(),
        })
        .await?;

    let peer_addr = match timeout(Duration::from_secs(timeout_secs), async {
        loop {
            match relay_tunnel.recv().await? {
                Some(Message::P2pCandidate { addr }) => {
                    let parsed = addr
                        .parse::<SocketAddr>()
                        .with_context(|| format!("invalid p2p candidate from peer: {addr}"))?;
                    return Ok(Some(parsed));
                }
                Some(Message::P2pFailed { reason }) => {
                    warn!("peer p2p setup failed: {reason}");
                    return Ok(None);
                }
                Some(Message::AckErr(e)) => return Err(anyhow!("relay error: {e}")),
                Some(other) => warn!("ignoring unexpected p2p setup message: {other:?}"),
                None => return Ok(None),
            }
        }
    })
    .await
    {
        Ok(Ok(Some(addr))) => addr,
        Ok(Ok(None)) => return Ok(relay_tunnel),
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            warn!("timed out waiting for p2p candidate, falling back to relay");
            return Ok(relay_tunnel);
        }
    };

    let socket = match punch(socket, peer_addr, timeout_secs).await {
        Ok(socket) => socket,
        Err(e) => {
            warn!("p2p udp punching failed, falling back to relay: {e:#}");
            let _ = relay_tunnel
                .send(&Message::P2pFailed {
                    reason: "punching failed".to_string(),
                })
                .await;
            return Ok(relay_tunnel);
        }
    };
    let _ = relay_tunnel
        .send(&Message::P2pSelected {
            addr: observed_addr.to_string(),
        })
        .await;

    let (transport, rx) = ReliableUdp::spawn(socket, peer_addr).await?;
    info!(local = %observed_addr, peer = %peer_addr, "using direct p2p udp data path");
    Ok(Tunnel {
        inner: Arc::new(TunnelInner::Udp {
            transport,
            rx: Arc::new(Mutex::new(rx)),
        }),
    })
}

pub async fn run_export(
    tunnel: Tunnel,
    to: SocketAddr,
    udp_target: Option<SocketAddr>,
) -> Result<()> {
    let streams: Arc<Mutex<HashMap<u32, tokio::sync::mpsc::UnboundedSender<Bytes>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    if let Some(u) = udp_target {
        let tun = tunnel.clone();
        tokio::spawn(async move {
            if let Err(e) = export_udp_loop(tun, u).await {
                error!("udp export ended: {e:#}");
            }
        });
    }

    loop {
        match tunnel.recv().await? {
            None => break,
            Some(Message::OpenStream { id }) => {
                let tun = tunnel.clone();
                let streams = streams.clone();
                tokio::spawn(async move {
                    if let Err(e) = export_one_tcp(tun, streams, id, to).await {
                        warn!(%id, "export stream ended: {e:#}");
                    }
                });
            }
            Some(Message::TcpData { id, payload }) => {
                let map = streams.lock().await;
                if let Some(tx) = map.get(&id) {
                    let _ = tx.send(payload);
                }
            }
            Some(Message::CloseStream { id }) => {
                streams.lock().await.remove(&id);
            }
            Some(Message::UdpData { .. }) => {}
            Some(Message::P2pOffer { .. }) => {}
            Some(Message::P2pReady) => {}
            Some(Message::P2pCandidate { .. }) => {}
            Some(Message::P2pSelected { .. }) => {}
            Some(Message::P2pFailed { .. }) => {}
            Some(other) => warn!("export ignoring {other:?}"),
        }
    }
    Ok(())
}

async fn export_one_tcp(
    tunnel: Tunnel,
    streams: Arc<Mutex<HashMap<u32, tokio::sync::mpsc::UnboundedSender<Bytes>>>>,
    id: u32,
    to: SocketAddr,
) -> Result<()> {
    let (tx_down, mut rx_down) = tokio::sync::mpsc::unbounded_channel::<Bytes>();
    {
        let mut map = streams.lock().await;
        map.insert(id, tx_down);
    }
    let (mut lr, mut lw) = match TcpStream::connect(to).await {
        Ok(sock) => sock.into_split(),
        Err(e) => {
            streams.lock().await.remove(&id);
            return Err(e.into());
        }
    };

    let tun_uplink = tunnel.clone();
    let uplink = async move {
        let mut buf = vec![0u8; TCP_TUNNEL_CHUNK];
        loop {
            let n = lr.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            tun_uplink
                .send(&Message::TcpData {
                    id,
                    payload: Bytes::copy_from_slice(&buf[..n]),
                })
                .await?;
        }
        Ok::<_, anyhow::Error>(())
    };

    let tun_close = tunnel.clone();
    let downlink = async move {
        while let Some(chunk) = rx_down.recv().await {
            if lw.write_all(&chunk).await.is_err() {
                break;
            }
        }
        let _ = tun_close.send(&Message::CloseStream { id }).await;
        Ok::<_, anyhow::Error>(())
    };

    tokio::select! {
        _ = uplink => {},
        _ = downlink => {},
    }

    streams.lock().await.remove(&id);
    Ok(())
}

async fn export_udp_loop(tunnel: Tunnel, target: SocketAddr) -> Result<()> {
    let sock = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    sock.connect(target).await?;
    let sock_send = sock.clone();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        tokio::select! {
            n = sock.recv(&mut buf) => {
                let n = n?;
                tunnel
                    .send(&Message::UdpData {
                        payload: Bytes::copy_from_slice(&buf[..n]),
                    })
                    .await?;
            }
            m = tunnel.recv() => {
                match m? {
                    None => break,
                    Some(Message::UdpData { payload }) => {
                        let _ = sock_send.send(&payload).await;
                    }
                    Some(Message::CloseStream { .. }) => {}
                    Some(Message::TcpData { .. }) => {}
                    Some(Message::OpenStream { .. }) => {}
                    Some(Message::P2pOffer { .. }) => {}
                    Some(Message::P2pReady) => {}
                    Some(Message::P2pCandidate { .. }) => {}
                    Some(Message::P2pSelected { .. }) => {}
                    Some(Message::P2pFailed { .. }) => {}
                    Some(other) => warn!("udp export unexpected {other:?}"),
                }
            }
        }
    }
    Ok(())
}

pub async fn run_import(
    tunnel: Tunnel,
    listen: SocketAddr,
    udp_listen: Option<SocketAddr>,
) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    info!(%listen, "import listening (tcp)");
    let next_id = AtomicU32::new(1);
    let streams: Arc<Mutex<HashMap<u32, tokio::sync::mpsc::UnboundedSender<Bytes>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    if let Some(u) = udp_listen {
        let tun = tunnel.clone();
        tokio::spawn(async move {
            if let Err(e) = import_udp_loop(tun, u).await {
                error!("udp import ended: {e:#}");
            }
        });
    }

    let tun_reader = tunnel.clone();
    let streams_reader = streams.clone();
    tokio::spawn(async move {
        loop {
            match tun_reader.recv().await {
                Ok(Some(Message::TcpData { id, payload })) => {
                    let map = streams_reader.lock().await;
                    if let Some(tx) = map.get(&id) {
                        let _ = tx.send(payload);
                    }
                }
                Ok(Some(Message::CloseStream { id })) => {
                    streams_reader.lock().await.remove(&id);
                }
                Ok(Some(Message::UdpData { .. })) => {}
                Ok(Some(Message::P2pOffer { .. })) => {}
                Ok(Some(Message::P2pReady)) => {}
                Ok(Some(Message::P2pCandidate { .. })) => {}
                Ok(Some(Message::P2pSelected { .. })) => {}
                Ok(Some(Message::P2pFailed { .. })) => {}
                Ok(Some(other)) => warn!("import reader ignoring {other:?}"),
                Ok(None) => break,
                Err(e) => {
                    error!("import tunnel read failed: {e:#}");
                    break;
                }
            }
        }
    });

    loop {
        let (sock, peer) = listener.accept().await?;
        let id = next_id.fetch_add(1, Ordering::Relaxed);
        let (tx_down, rx_down) = tokio::sync::mpsc::unbounded_channel::<Bytes>();
        streams.lock().await.insert(id, tx_down);
        if let Err(e) = tunnel.send(&Message::OpenStream { id }).await {
            streams.lock().await.remove(&id);
            return Err(e);
        }
        let tun = tunnel.clone();
        let streams2 = streams.clone();
        tokio::spawn(async move {
            if let Err(e) = import_one_tcp(tun, streams2, id, sock, rx_down).await {
                warn!(%peer, %id, "import stream ended: {e:#}");
            }
        });
    }
}

async fn import_one_tcp(
    tunnel: Tunnel,
    streams: Arc<Mutex<HashMap<u32, tokio::sync::mpsc::UnboundedSender<Bytes>>>>,
    id: u32,
    sock: TcpStream,
    mut rx_down: tokio::sync::mpsc::UnboundedReceiver<Bytes>,
) -> Result<()> {
    let (mut r, mut w) = sock.into_split();
    let tun_up = tunnel.clone();
    let uplink = async move {
        let mut buf = vec![0u8; TCP_TUNNEL_CHUNK];
        loop {
            let n = r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            tun_up
                .send(&Message::TcpData {
                    id,
                    payload: Bytes::copy_from_slice(&buf[..n]),
                })
                .await?;
        }
        Ok::<_, anyhow::Error>(())
    };

    let downlink = async move {
        while let Some(chunk) = rx_down.recv().await {
            if w.write_all(&chunk).await.is_err() {
                break;
            }
        }
        Ok::<_, anyhow::Error>(())
    };

    tokio::select! {
        _ = uplink => {},
        _ = downlink => {},
    }
    let _ = tunnel.send(&Message::CloseStream { id }).await;
    streams.lock().await.remove(&id);
    Ok(())
}

async fn import_udp_loop(tunnel: Tunnel, bind: SocketAddr) -> Result<()> {
    let sock = Arc::new(UdpSocket::bind(bind).await?);
    info!(%bind, "import listening (udp)");
    let sock_send = sock.clone();
    let mut buf = vec![0u8; 64 * 1024];
    let mut peer: Option<SocketAddr> = None;
    loop {
        tokio::select! {
            r = sock.recv_from(&mut buf) => {
                let (n, from) = r?;
                peer = Some(from);
                tunnel
                    .send(&Message::UdpData {
                        payload: Bytes::copy_from_slice(&buf[..n]),
                    })
                    .await?;
            }
            m = tunnel.recv() => {
                match m? {
                    None => break,
                    Some(Message::UdpData { payload }) => {
                        if let Some(p) = peer {
                            let _ = sock_send.send_to(&payload, p).await;
                        }
                    }
                    Some(Message::P2pOffer { .. }) => {}
                    Some(Message::P2pReady) => {}
                    Some(Message::P2pCandidate { .. }) => {}
                    Some(Message::P2pSelected { .. }) => {}
                    Some(Message::P2pFailed { .. }) => {}
                    Some(other) => warn!("udp import unexpected {other:?}"),
                }
            }
        }
    }
    Ok(())
}
