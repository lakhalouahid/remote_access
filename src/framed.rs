use anyhow::{anyhow, Result};
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::protocol::Message;

pub struct FramedReader<R> {
    read: R,
    buf: BytesMut,
}

impl<R: AsyncRead + Unpin> FramedReader<R> {
    pub fn new(read: R) -> Self {
        Self {
            read,
            buf: BytesMut::with_capacity(64 * 1024),
        }
    }

    pub async fn recv(&mut self) -> Result<Option<Message>> {
        loop {
            if let Some(m) = Message::decode(&mut self.buf)? {
                return Ok(Some(m));
            }
            let n = self.read.read_buf(&mut self.buf).await?;
            if n == 0 {
                if self.buf.is_empty() {
                    return Ok(None);
                }
                return Err(anyhow!("unexpected eof mid-frame"));
            }
        }
    }
}

pub struct FramedWriter<W> {
    write: W,
}

impl<W: AsyncWrite + Unpin> FramedWriter<W> {
    pub fn new(write: W) -> Self {
        Self { write }
    }

    pub async fn send(&mut self, msg: &Message) -> Result<()> {
        let mut out = BytesMut::new();
        msg.encode(&mut out)?;
        self.write.write_all(&out).await?;
        self.write.flush().await?;
        Ok(())
    }
}

pub struct FramedRw<R, W> {
    read: R,
    write: W,
    buf: BytesMut,
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> FramedRw<R, W> {
    pub fn new(read: R, write: W) -> Self {
        Self {
            read,
            write,
            buf: BytesMut::with_capacity(64 * 1024),
        }
    }

    pub async fn recv(&mut self) -> Result<Option<Message>> {
        loop {
            if let Some(m) = Message::decode(&mut self.buf)? {
                return Ok(Some(m));
            }
            let n = self.read.read_buf(&mut self.buf).await?;
            if n == 0 {
                if self.buf.is_empty() {
                    return Ok(None);
                }
                return Err(anyhow!("unexpected eof mid-frame"));
            }
        }
    }

    pub async fn send(&mut self, msg: &Message) -> Result<()> {
        let mut out = BytesMut::new();
        msg.encode(&mut out)?;
        self.write.write_all(&out).await?;
        self.write.flush().await?;
        Ok(())
    }
}

pub enum AnyFramed {
    Tcp(FramedRw<tokio::net::tcp::OwnedReadHalf, tokio::net::tcp::OwnedWriteHalf>),
    Quic(FramedRw<quinn::RecvStream, quinn::SendStream>),
}

impl AnyFramed {
    pub async fn recv(&mut self) -> Result<Option<Message>> {
        match self {
            AnyFramed::Tcp(f) => f.recv().await,
            AnyFramed::Quic(f) => f.recv().await,
        }
    }

    pub async fn send(&mut self, msg: &Message) -> Result<()> {
        match self {
            AnyFramed::Tcp(f) => f.send(msg).await,
            AnyFramed::Quic(f) => f.send(msg).await,
        }
    }
}
