use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::framed::{AnyFramed, FramedRw};
use crate::protocol::{Message, Role};
use crate::tls::{generate_ephemeral_cert_files, quinn_server_config};

pub(crate) struct Pending {
    export: Option<Peer>,
    import: Option<Peer>,
    want_udp: Option<bool>,
}

impl Pending {
    fn new() -> Self {
        Self {
            export: None,
            import: None,
            want_udp: None,
        }
    }
}

pub(crate) type SessionMap = Mutex<HashMap<String, Pending>>;

pub(crate) struct Peer {
    framed: AnyFramed,
    observed_addr: SocketAddr,
}

pub async fn run_udp_discovery(addr: SocketAddr) -> Result<()> {
    let sock = UdpSocket::bind(addr).await?;
    info!(%addr, "relay listening (UDP p2p discovery)");
    let mut buf = [0u8; 64];
    loop {
        let (_, peer) = sock.recv_from(&mut buf).await?;
        let reply = peer.to_string();
        let _ = sock.send_to(reply.as_bytes(), peer).await;
    }
}

fn maybe_rewrite_p2p_offer(msg: Message, observed_addr: SocketAddr) -> Message {
    let Message::P2pOffer { addr } = msg else {
        return msg;
    };

    match addr.parse::<SocketAddr>() {
        Ok(offered) if offered.ip().is_unspecified() => Message::P2pOffer {
            addr: SocketAddr::new(observed_addr.ip(), offered.port()).to_string(),
        },
        _ => Message::P2pOffer { addr },
    }
}

async fn bridge_pair(mut a: Peer, mut b: Peer) {
    loop {
        tokio::select! {
            ra = a.framed.recv() => {
                match ra {
                    Ok(Some(m)) => {
                        let m = maybe_rewrite_p2p_offer(m, a.observed_addr);
                        if b.framed.send(&m).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        error!("relay read a: {e:#}");
                        break;
                    }
                }
            }
            rb = b.framed.recv() => {
                match rb {
                    Ok(Some(m)) => {
                        let m = maybe_rewrite_p2p_offer(m, b.observed_addr);
                        if a.framed.send(&m).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        error!("relay read b: {e:#}");
                        break;
                    }
                }
            }
        }
    }
}

async fn handle_session_pair(
    sessions: Arc<SessionMap>,
    session: String,
    role: Role,
    want_udp: bool,
    framed: AnyFramed,
    observed_addr: SocketAddr,
) -> Result<()> {
    let (peer_a, peer_b) = {
        let mut map = sessions.lock().await;
        let entry = map.entry(session.clone()).or_insert_with(Pending::new);
        if let Some(w) = entry.want_udp {
            if w != want_udp {
                let mut f = framed;
                let _ = f
                    .send(&Message::AckErr(
                        "UDP flag mismatch with peer on this session".into(),
                    ))
                    .await;
                return Err(anyhow!("UDP flag mismatch"));
            }
        } else {
            entry.want_udp = Some(want_udp);
        }

        match role {
            Role::Export => {
                if entry.export.is_some() {
                    let mut f = framed;
                    let _ = f
                        .send(&Message::AckErr(
                            "session already has an export peer".into(),
                        ))
                        .await;
                    return Err(anyhow!("duplicate export"));
                }
                entry.export = Some(Peer {
                    framed,
                    observed_addr,
                });
            }
            Role::Import => {
                if entry.import.is_some() {
                    let mut f = framed;
                    let _ = f
                        .send(&Message::AckErr(
                            "session already has an import peer".into(),
                        ))
                        .await;
                    return Err(anyhow!("duplicate import"));
                }
                entry.import = Some(Peer {
                    framed,
                    observed_addr,
                });
            }
        }

        if entry.export.is_some() && entry.import.is_some() {
            let mut pend = map.remove(&session).unwrap();
            let e = pend.export.take().unwrap();
            let i = pend.import.take().unwrap();
            (e, i)
        } else {
            drop(map);
            return Ok(());
        }
    };
    let (mut peer_a, mut peer_b) = (peer_a, peer_b);

    peer_a
        .framed
        .send(&Message::AckOk)
        .await
        .context("ack export")?;
    peer_b
        .framed
        .send(&Message::AckOk)
        .await
        .context("ack import")?;
    info!(%session, "paired; bridging");
    bridge_pair(peer_a, peer_b).await;
    Ok(())
}

async fn serve_one_tcp(sock: TcpStream, sessions: Arc<SessionMap>) -> Result<()> {
    let observed_addr = sock.peer_addr().context("tcp peer addr")?;
    let (r, w) = sock.into_split();
    let mut framed = AnyFramed::Tcp(FramedRw::new(r, w));
    let join = match framed.recv().await? {
        Some(Message::Join {
            role,
            session,
            want_udp,
        }) => (role, session, want_udp),
        Some(other) => {
            let _ = framed
                .send(&Message::AckErr(format!("expected join, got {other:?}")))
                .await;
            return Err(anyhow!("bad first message"));
        }
        None => return Ok(()),
    };

    let (role, session, want_udp) = join;
    if session.is_empty() {
        let _ = framed.send(&Message::AckErr("empty session".into())).await;
        return Err(anyhow!("empty session"));
    }

    handle_session_pair(sessions, session, role, want_udp, framed, observed_addr).await
}

pub async fn run_tcp(addr: SocketAddr, sessions: Arc<SessionMap>) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "relay listening (TCP transport)");
    loop {
        let (sock, peer) = listener.accept().await?;
        let sessions = sessions.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_one_tcp(sock, sessions).await {
                warn!(%peer, "tcp session ended: {e:#}");
            }
        });
    }
}

pub async fn run_quic(
    addr: SocketAddr,
    cert: PathBuf,
    key: PathBuf,
    auto_tls: bool,
    sessions: Arc<SessionMap>,
) -> Result<()> {
    if auto_tls && (!cert.exists() || !key.exists()) {
        generate_ephemeral_cert_files(&cert, &key, addr.ip())?;
        info!(
            cert = %cert.display(),
            key = %key.display(),
            "generated dev TLS material; copy the cert to clients (--trust-cert)"
        );
    }

    let server_config = quinn_server_config(&cert, &key)?;
    let endpoint = quinn::Endpoint::server(server_config, addr)?;
    info!(%addr, "relay listening (QUIC transport)");

    while let Some(incoming) = endpoint.accept().await {
        let sessions = sessions.clone();
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    warn!("quic handshake failed: {e:#}");
                    return;
                }
            };
            let peer = conn.remote_address();
            let res: Result<(), anyhow::Error> = async {
                let (send, recv) = conn.accept_bi().await?;
                let mut framed = AnyFramed::Quic(FramedRw::new(recv, send));
                let join = match framed.recv().await? {
                    Some(Message::Join {
                        role,
                        session,
                        want_udp,
                    }) => (role, session, want_udp),
                    Some(other) => {
                        let _ = framed
                            .send(&Message::AckErr(format!("expected join, got {other:?}")))
                            .await;
                        return Err(anyhow!("bad first message"));
                    }
                    None => return Ok(()),
                };
                let (role, session, want_udp) = join;
                if session.is_empty() {
                    let _ = framed.send(&Message::AckErr("empty session".into())).await;
                    return Err(anyhow!("empty session"));
                }
                handle_session_pair(sessions, session, role, want_udp, framed, peer).await
            }
            .await;
            if let Err(e) = res {
                warn!(%peer, "quic session ended: {e:#}");
            }
        });
    }
    Ok(())
}
