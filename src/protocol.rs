//! Binary framing between clients and relay.
//! Max payload size keeps memory bounded on the relay.

use anyhow::{anyhow, Context, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};

pub const MAX_PAYLOAD: usize = 256 * 1024;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgType {
    Join = 1,
    AckOk = 2,
    AckErr = 3,
    OpenStream = 4,
    CloseStream = 5,
    TcpData = 6,
    UdpData = 7,
    P2pOffer = 8,
    P2pReady = 9,
    P2pCandidate = 10,
    P2pSelected = 11,
    P2pFailed = 12,
}

impl MsgType {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Join),
            2 => Some(Self::AckOk),
            3 => Some(Self::AckErr),
            4 => Some(Self::OpenStream),
            5 => Some(Self::CloseStream),
            6 => Some(Self::TcpData),
            7 => Some(Self::UdpData),
            8 => Some(Self::P2pOffer),
            9 => Some(Self::P2pReady),
            10 => Some(Self::P2pCandidate),
            11 => Some(Self::P2pSelected),
            12 => Some(Self::P2pFailed),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    Export = 0,
    Import = 1,
}

impl Role {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Export),
            1 => Some(Self::Import),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Join {
        role: Role,
        session: String,
        want_udp: bool,
    },
    AckOk,
    AckErr(String),
    OpenStream {
        id: u32,
    },
    CloseStream {
        id: u32,
    },
    TcpData {
        id: u32,
        payload: Bytes,
    },
    UdpData {
        payload: Bytes,
    },
    P2pOffer {
        addr: String,
    },
    P2pReady,
    P2pCandidate {
        addr: String,
    },
    P2pSelected {
        addr: String,
    },
    P2pFailed {
        reason: String,
    },
}

fn put_string(buf: &mut BytesMut, s: &str) -> Result<()> {
    let b = s.as_bytes();
    if b.len() > u16::MAX as usize {
        return Err(anyhow!("session id too long"));
    }
    buf.put_u16(b.len() as u16);
    buf.put_slice(b);
    Ok(())
}

fn get_string(cur: &mut &[u8]) -> Result<String> {
    if cur.len() < 2 {
        return Err(anyhow!("truncated string length"));
    }
    let n = cur.get_u16() as usize;
    if cur.len() < n {
        return Err(anyhow!("truncated string body"));
    }
    let s = std::str::from_utf8(&cur[..n]).context("session must be utf-8")?;
    cur.advance(n);
    Ok(s.to_owned())
}

impl Message {
    pub fn encode(&self, dst: &mut BytesMut) -> Result<()> {
        let mut body = BytesMut::new();
        match self {
            Message::Join {
                role,
                session,
                want_udp,
            } => {
                body.put_u8(*role as u8);
                body.put_u8(if *want_udp { 1 } else { 0 });
                put_string(&mut body, session)?;
            }
            Message::AckOk => {}
            Message::AckErr(s) => put_string(&mut body, s)?,
            Message::OpenStream { id } => body.put_u32(*id),
            Message::CloseStream { id } => body.put_u32(*id),
            Message::TcpData { id, payload } => {
                if payload.len() > MAX_PAYLOAD {
                    return Err(anyhow!("payload exceeds MAX_PAYLOAD"));
                }
                body.put_u32(*id);
                body.put_slice(payload);
            }
            Message::UdpData { payload } => {
                if payload.len() > MAX_PAYLOAD {
                    return Err(anyhow!("payload exceeds MAX_PAYLOAD"));
                }
                body.put_slice(payload);
            }
            Message::P2pOffer { addr } => put_string(&mut body, addr)?,
            Message::P2pReady => {}
            Message::P2pCandidate { addr } => put_string(&mut body, addr)?,
            Message::P2pSelected { addr } => put_string(&mut body, addr)?,
            Message::P2pFailed { reason } => put_string(&mut body, reason)?,
        }

        let ty = match self {
            Message::Join { .. } => MsgType::Join,
            Message::AckOk => MsgType::AckOk,
            Message::AckErr(_) => MsgType::AckErr,
            Message::OpenStream { .. } => MsgType::OpenStream,
            Message::CloseStream { .. } => MsgType::CloseStream,
            Message::TcpData { .. } => MsgType::TcpData,
            Message::UdpData { .. } => MsgType::UdpData,
            Message::P2pOffer { .. } => MsgType::P2pOffer,
            Message::P2pReady => MsgType::P2pReady,
            Message::P2pCandidate { .. } => MsgType::P2pCandidate,
            Message::P2pSelected { .. } => MsgType::P2pSelected,
            Message::P2pFailed { .. } => MsgType::P2pFailed,
        };

        let len: u32 = body
            .len()
            .try_into()
            .map_err(|_| anyhow!("frame too large"))?;
        dst.reserve(1 + 4 + body.len());
        dst.put_u8(ty as u8);
        dst.put_u32(len);
        dst.put_slice(&body);
        Ok(())
    }

    pub fn decode(src: &mut BytesMut) -> Result<Option<Message>> {
        if src.len() < 5 {
            return Ok(None);
        }
        let mut cur = &src[..];
        let ty = cur.get_u8();
        let len = cur.get_u32() as usize;
        if len > MAX_PAYLOAD + 1024 {
            return Err(anyhow!("frame length unreasonable"));
        }
        if src.len() < 5 + len {
            return Ok(None);
        }
        src.advance(5);
        let body = src.split_to(len);
        let mut cur = &body[..];

        let ty = MsgType::from_u8(ty).ok_or_else(|| anyhow!("unknown message type"))?;
        let msg = match ty {
            MsgType::Join => {
                if cur.is_empty() {
                    return Err(anyhow!("truncated join"));
                }
                let role = Role::from_u8(cur.get_u8()).ok_or_else(|| anyhow!("bad role"))?;
                let want_udp = match cur.get_u8() {
                    0 => false,
                    1 => true,
                    _ => return Err(anyhow!("bad want_udp flag")),
                };
                let session = get_string(&mut cur)?;
                if !cur.is_empty() {
                    return Err(anyhow!("trailing join bytes"));
                }
                Message::Join {
                    role,
                    session,
                    want_udp,
                }
            }
            MsgType::AckOk => {
                if !cur.is_empty() {
                    return Err(anyhow!("trailing ack_ok bytes"));
                }
                Message::AckOk
            }
            MsgType::AckErr => {
                let s = get_string(&mut cur)?;
                if !cur.is_empty() {
                    return Err(anyhow!("trailing ack_err bytes"));
                }
                Message::AckErr(s)
            }
            MsgType::OpenStream => {
                if cur.remaining() < 4 {
                    return Err(anyhow!("truncated open_stream"));
                }
                let id = cur.get_u32();
                if !cur.is_empty() {
                    return Err(anyhow!("trailing open_stream bytes"));
                }
                Message::OpenStream { id }
            }
            MsgType::CloseStream => {
                if cur.remaining() < 4 {
                    return Err(anyhow!("truncated close_stream"));
                }
                let id = cur.get_u32();
                if !cur.is_empty() {
                    return Err(anyhow!("trailing close_stream bytes"));
                }
                Message::CloseStream { id }
            }
            MsgType::TcpData => {
                if cur.remaining() < 4 {
                    return Err(anyhow!("truncated tcp_data"));
                }
                let id = cur.get_u32();
                let payload = Bytes::copy_from_slice(cur);
                Message::TcpData { id, payload }
            }
            MsgType::UdpData => {
                let payload = Bytes::copy_from_slice(cur);
                Message::UdpData { payload }
            }
            MsgType::P2pOffer => {
                let addr = get_string(&mut cur)?;
                if !cur.is_empty() {
                    return Err(anyhow!("trailing p2p_offer bytes"));
                }
                Message::P2pOffer { addr }
            }
            MsgType::P2pReady => {
                if !cur.is_empty() {
                    return Err(anyhow!("trailing p2p_ready bytes"));
                }
                Message::P2pReady
            }
            MsgType::P2pCandidate => {
                let addr = get_string(&mut cur)?;
                if !cur.is_empty() {
                    return Err(anyhow!("trailing p2p_candidate bytes"));
                }
                Message::P2pCandidate { addr }
            }
            MsgType::P2pSelected => {
                let addr = get_string(&mut cur)?;
                if !cur.is_empty() {
                    return Err(anyhow!("trailing p2p_selected bytes"));
                }
                Message::P2pSelected { addr }
            }
            MsgType::P2pFailed => {
                let reason = get_string(&mut cur)?;
                if !cur.is_empty() {
                    return Err(anyhow!("trailing p2p_failed bytes"));
                }
                Message::P2pFailed { reason }
            }
        };

        Ok(Some(msg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(msg: Message) {
        let mut encoded = BytesMut::new();
        msg.encode(&mut encoded).unwrap();
        assert_eq!(Message::decode(&mut encoded).unwrap(), Some(msg));
        assert!(encoded.is_empty());
    }

    #[test]
    fn roundtrips_p2p_signaling() {
        roundtrip(Message::P2pCandidate {
            addr: "203.0.113.10:49152".to_string(),
        });
        roundtrip(Message::P2pSelected {
            addr: "203.0.113.10:49152".to_string(),
        });
        roundtrip(Message::P2pFailed {
            reason: "timeout".to_string(),
        });
    }
}
