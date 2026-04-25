use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use bytes::{Buf, BufMut, BytesMut};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time::{timeout, Duration, Instant};
use tracing::warn;

use crate::protocol::{Message, MAX_PAYLOAD};

const DISCOVERY_PAYLOAD: &[u8] = b"remote-access:p2p-discover";
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(3);
const PROBE_INTERVAL: Duration = Duration::from_millis(100);
const SEND_RETRIES: usize = 12;
const SEND_RETRY_DELAY: Duration = Duration::from_millis(150);
const REORDER_WINDOW: u32 = 1024;

const KIND_PROBE: u8 = 1;
const KIND_PROBE_ACK: u8 = 2;
const KIND_DATA: u8 = 3;
const KIND_ACK: u8 = 4;

pub struct ReliableUdp {
    socket: Arc<UdpSocket>,
    next_send: AtomicU32,
    acks: Arc<Mutex<HashMap<u32, oneshot::Sender<()>>>>,
    send_lock: Mutex<()>,
}

impl ReliableUdp {
    pub async fn spawn(
        socket: UdpSocket,
        peer: SocketAddr,
    ) -> Result<(Arc<Self>, mpsc::Receiver<Message>)> {
        socket
            .connect(peer)
            .await
            .context("connect p2p udp socket")?;
        let socket = Arc::new(socket);
        let acks = Arc::new(Mutex::new(HashMap::new()));
        let (incoming_tx, incoming_rx) = mpsc::channel(1024);
        let transport = Arc::new(Self {
            socket: socket.clone(),
            next_send: AtomicU32::new(1),
            acks: acks.clone(),
            send_lock: Mutex::new(()),
        });
        tokio::spawn(recv_loop(socket, acks, incoming_tx));
        Ok((transport, incoming_rx))
    }

    pub async fn send(&self, msg: &Message) -> Result<()> {
        let _guard = self.send_lock.lock().await;
        let seq = self.next_send.fetch_add(1, Ordering::Relaxed);
        let mut encoded = BytesMut::new();
        msg.encode(&mut encoded)?;
        if encoded.len() > MAX_PAYLOAD + 1024 {
            return Err(anyhow!("encoded p2p message too large"));
        }

        let mut packet = BytesMut::with_capacity(1 + 4 + encoded.len());
        packet.put_u8(KIND_DATA);
        packet.put_u32(seq);
        packet.put_slice(&encoded);

        let (ack_tx, mut ack_rx) = oneshot::channel();
        self.acks.lock().await.insert(seq, ack_tx);
        for _ in 0..SEND_RETRIES {
            self.socket.send(&packet).await?;
            if timeout(SEND_RETRY_DELAY, &mut ack_rx).await.is_ok() {
                return Ok(());
            }
        }
        self.acks.lock().await.remove(&seq);
        Err(anyhow!("timed out waiting for p2p udp ack"))
    }
}

async fn recv_loop(
    socket: Arc<UdpSocket>,
    acks: Arc<Mutex<HashMap<u32, oneshot::Sender<()>>>>,
    incoming: mpsc::Sender<Message>,
) {
    let mut buf = vec![0u8; MAX_PAYLOAD + 2048];
    let mut next_recv = 1u32;
    let mut reorder = BTreeMap::<u32, Message>::new();

    loop {
        let n = match socket.recv(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                warn!("p2p udp recv failed: {e:#}");
                break;
            }
        };
        if n < 5 {
            continue;
        }
        let mut cur = &buf[..n];
        let kind = cur.get_u8();
        let seq = cur.get_u32();
        match kind {
            KIND_ACK => {
                if let Some(tx) = acks.lock().await.remove(&seq) {
                    let _ = tx.send(());
                }
            }
            KIND_DATA => {
                let mut payload = BytesMut::from(cur);
                let msg = match Message::decode(&mut payload) {
                    Ok(Some(msg)) if payload.is_empty() => msg,
                    Ok(_) => continue,
                    Err(e) => {
                        warn!("p2p udp frame decode failed: {e:#}");
                        continue;
                    }
                };
                let mut ack = BytesMut::with_capacity(5);
                ack.put_u8(KIND_ACK);
                ack.put_u32(seq);
                let _ = socket.send(&ack).await;

                if seq == next_recv {
                    if incoming.send(msg).await.is_err() {
                        break;
                    }
                    next_recv = next_recv.wrapping_add(1);
                    while let Some(msg) = reorder.remove(&next_recv) {
                        if incoming.send(msg).await.is_err() {
                            return;
                        }
                        next_recv = next_recv.wrapping_add(1);
                    }
                } else if seq > next_recv && seq - next_recv <= REORDER_WINDOW {
                    reorder.entry(seq).or_insert(msg);
                }
            }
            KIND_PROBE => {
                let _ = socket.send(&[KIND_PROBE_ACK, 0, 0, 0, 0]).await;
            }
            KIND_PROBE_ACK => {}
            _ => {}
        }
    }
}

pub async fn bind_and_discover(
    bind: SocketAddr,
    discovery_server: SocketAddr,
) -> Result<(UdpSocket, SocketAddr)> {
    let socket = UdpSocket::bind(bind)
        .await
        .with_context(|| format!("bind p2p udp socket on {bind}"))?;
    socket
        .send_to(DISCOVERY_PAYLOAD, discovery_server)
        .await
        .with_context(|| format!("send p2p discovery to {discovery_server}"))?;

    let mut buf = [0u8; 64];
    let (n, from) = timeout(DISCOVERY_TIMEOUT, socket.recv_from(&mut buf))
        .await
        .context("timed out waiting for p2p discovery response")??;
    if from != discovery_server {
        return Err(anyhow!(
            "p2p discovery response came from unexpected address {from}"
        ));
    }
    let observed = std::str::from_utf8(&buf[..n])
        .context("p2p discovery response must be utf-8")?
        .parse::<SocketAddr>()
        .context("p2p discovery response must be a socket address")?;
    Ok((socket, observed))
}

pub async fn punch(socket: UdpSocket, peer: SocketAddr, timeout_secs: u64) -> Result<UdpSocket> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut buf = [0u8; 64];
    while Instant::now() < deadline {
        let _ = socket.send_to(&[KIND_PROBE, 0, 0, 0, 0], peer).await;
        let wait = timeout(PROBE_INTERVAL, socket.recv_from(&mut buf)).await;
        match wait {
            Ok(Ok((n, from))) if from == peer && n >= 1 && buf[0] == KIND_PROBE_ACK => {
                return Ok(socket);
            }
            Ok(Ok((n, from))) if from == peer && n >= 1 && buf[0] == KIND_PROBE => {
                let _ = socket.send_to(&[KIND_PROBE_ACK, 0, 0, 0, 0], peer).await;
                return Ok(socket);
            }
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {}
        }
    }
    Err(anyhow!("timed out establishing p2p udp path"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn punch_succeeds_on_loopback() {
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a_addr = a.local_addr().unwrap();
        let b_addr = b.local_addr().unwrap();

        let (a, b) = tokio::try_join!(punch(a, b_addr, 1), punch(b, a_addr, 1)).unwrap();
        assert_eq!(a.local_addr().unwrap(), a_addr);
        assert_eq!(b.local_addr().unwrap(), b_addr);
    }

    #[tokio::test]
    async fn reliable_udp_roundtrips_messages() {
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a_addr = a.local_addr().unwrap();
        let b_addr = b.local_addr().unwrap();

        let (a_tx, mut a_rx) = ReliableUdp::spawn(a, b_addr).await.unwrap();
        let (b_tx, mut b_rx) = ReliableUdp::spawn(b, a_addr).await.unwrap();

        a_tx.send(&Message::OpenStream { id: 7 }).await.unwrap();
        let got = timeout(Duration::from_secs(1), b_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, Message::OpenStream { id: 7 });

        b_tx.send(&Message::CloseStream { id: 7 }).await.unwrap();
        let got = timeout(Duration::from_secs(1), a_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, Message::CloseStream { id: 7 });
    }
}
