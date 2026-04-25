mod client;
mod framed;
mod p2p_udp;
mod protocol;
mod relay;
mod tls;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand, ValueEnum};
use tokio::sync::Mutex;
use tracing::error;
use tracing_subscriber::EnvFilter;

use crate::client::{join_session, open_quic, open_tcp, run_export, run_import, switch_to_p2p_udp};
use crate::protocol::Role;
use crate::relay::{run_quic, run_tcp, run_udp_discovery};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Transport {
    Quic,
    Tcp,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum DataPath {
    Relay,
    P2p,
}

#[derive(Parser)]
#[command(name = "remote-access")]
#[command(about = "Forward TCP/UDP through a public relay (QUIC or TCP to the relay)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the public relay (bind on a VPS with a public IP).
    Server {
        #[arg(long, default_value = "0.0.0.0:7844")]
        listen: SocketAddr,
        #[arg(long, value_enum, default_value_t = Transport::Quic)]
        transport: Transport,
        /// PEM certificate (QUIC). With `--auto-tls`, defaults to ./ra-dev-cert.pem
        #[arg(long)]
        cert: Option<PathBuf>,
        /// PEM private key (QUIC). With `--auto-tls`, defaults to ./ra-dev-key.pem
        #[arg(long)]
        key: Option<PathBuf>,
        /// Generate dev cert/key if missing (QUIC only).
        #[arg(long, default_value_t = false)]
        auto_tls: bool,
        /// UDP endpoint used by peers to discover their NAT-mapped p2p address.
        #[arg(long, default_value = "0.0.0.0:7845")]
        p2p_discovery_listen: SocketAddr,
    },
    /// Side that has the private service (connects relay to `127.0.0.1:port`, etc.).
    Export {
        #[arg(long)]
        server: SocketAddr,
        #[arg(long, value_enum, default_value_t = Transport::Quic)]
        transport: Transport,
        /// Shared secret both peers use (acts as pairing token).
        #[arg(long)]
        session: String,
        /// Target service reachable from this machine.
        #[arg(long)]
        to: SocketAddr,
        /// If set, also forward UDP to `--to` (QUIC datagram path; TCP relay still carries UDP frames).
        #[arg(long)]
        udp_target: Option<SocketAddr>,
        /// Local bind for QUIC client socket.
        #[arg(long, default_value = "0.0.0.0:0")]
        bind: SocketAddr,
        /// Trust relay certificate (QUIC, PEM).
        #[arg(long)]
        trust_cert: Option<PathBuf>,
        /// TLS SNI / certificate hostname (QUIC). Defaults to IP string for numeric hosts.
        #[arg(long)]
        server_name: Option<String>,
        /// Data path between peers after signaling.
        #[arg(long, value_enum, default_value_t = DataPath::Relay)]
        data_path: DataPath,
        /// Timeout for establishing direct p2p path in seconds.
        #[arg(long, default_value_t = 15)]
        p2p_timeout_secs: u64,
        /// Local UDP bind for p2p hole punching.
        #[arg(long, default_value = "0.0.0.0:0")]
        p2p_bind: SocketAddr,
        /// Relay UDP discovery endpoint. Defaults to relay IP and relay port + 1.
        #[arg(long)]
        p2p_discovery_server: Option<SocketAddr>,
    },
    /// Side that exposes a local TCP (and optional UDP) listener tunneled to export.
    Import {
        #[arg(long)]
        server: SocketAddr,
        #[arg(long, value_enum, default_value_t = Transport::Quic)]
        transport: Transport,
        #[arg(long)]
        session: String,
        #[arg(long)]
        listen: SocketAddr,
        #[arg(long)]
        udp_listen: Option<SocketAddr>,
        #[arg(long, default_value = "0.0.0.0:0")]
        bind: SocketAddr,
        #[arg(long)]
        trust_cert: Option<PathBuf>,
        #[arg(long)]
        server_name: Option<String>,
        /// Data path between peers after signaling.
        #[arg(long, value_enum, default_value_t = DataPath::Relay)]
        data_path: DataPath,
        /// Timeout for establishing direct p2p path in seconds.
        #[arg(long, default_value_t = 15)]
        p2p_timeout_secs: u64,
        /// Local UDP bind for p2p hole punching.
        #[arg(long, default_value = "0.0.0.0:0")]
        p2p_bind: SocketAddr,
        /// Relay UDP discovery endpoint. Defaults to relay IP and relay port + 1.
        #[arg(long)]
        p2p_discovery_server: Option<SocketAddr>,
    },
}

fn default_p2p_discovery_server(server: SocketAddr) -> Result<SocketAddr> {
    let port = server
        .port()
        .checked_add(1)
        .ok_or_else(|| anyhow!("cannot derive p2p discovery port from {}", server.port()))?;
    Ok(SocketAddr::new(server.ip(), port))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Server {
            listen,
            transport,
            cert,
            key,
            auto_tls,
            p2p_discovery_listen,
        } => {
            let sessions = Arc::new(Mutex::new(std::collections::HashMap::new()));
            tokio::spawn(async move {
                if let Err(e) = run_udp_discovery(p2p_discovery_listen).await {
                    error!("p2p udp discovery server stopped: {e:#}");
                }
            });
            match transport {
                Transport::Tcp => run_tcp(listen, sessions).await?,
                Transport::Quic => {
                    let cert = cert.unwrap_or_else(|| PathBuf::from("ra-dev-cert.pem"));
                    let key = key.unwrap_or_else(|| PathBuf::from("ra-dev-key.pem"));
                    run_quic(listen, cert, key, auto_tls, sessions).await?;
                }
            }
        }
        Cmd::Export {
            server,
            transport,
            session,
            to,
            udp_target,
            bind,
            trust_cert,
            server_name,
            data_path,
            p2p_timeout_secs,
            p2p_bind,
            p2p_discovery_server,
        } => {
            let want_udp = udp_target.is_some();
            let relay_tunnel = match transport {
                Transport::Tcp => open_tcp(server).await?,
                Transport::Quic => {
                    let trust = trust_cert
                        .ok_or_else(|| anyhow!("--trust-cert is required for QUIC transport"))?;
                    let sn = server_name.unwrap_or_else(|| server.ip().to_string());
                    open_quic(bind, server, &sn, &trust).await?
                }
            };
            join_session(&relay_tunnel, &session, Role::Export, want_udp).await?;
            let tunnel = match data_path {
                DataPath::Relay => relay_tunnel,
                DataPath::P2p => {
                    let discovery_server = p2p_discovery_server
                        .map(Ok)
                        .unwrap_or_else(|| default_p2p_discovery_server(server))?;
                    switch_to_p2p_udp(relay_tunnel, p2p_bind, discovery_server, p2p_timeout_secs)
                        .await?
                }
            };
            run_export(tunnel, to, udp_target).await?;
        }
        Cmd::Import {
            server,
            transport,
            session,
            listen,
            udp_listen,
            bind,
            trust_cert,
            server_name,
            data_path,
            p2p_timeout_secs,
            p2p_bind,
            p2p_discovery_server,
        } => {
            let want_udp = udp_listen.is_some();
            let relay_tunnel = match transport {
                Transport::Tcp => open_tcp(server).await?,
                Transport::Quic => {
                    let trust = trust_cert
                        .ok_or_else(|| anyhow!("--trust-cert is required for QUIC transport"))?;
                    let sn = server_name.unwrap_or_else(|| server.ip().to_string());
                    open_quic(bind, server, &sn, &trust).await?
                }
            };
            join_session(&relay_tunnel, &session, Role::Import, want_udp).await?;
            let tunnel = match data_path {
                DataPath::Relay => relay_tunnel,
                DataPath::P2p => {
                    let discovery_server = p2p_discovery_server
                        .map(Ok)
                        .unwrap_or_else(|| default_p2p_discovery_server(server))?;
                    switch_to_p2p_udp(relay_tunnel, p2p_bind, discovery_server, p2p_timeout_secs)
                        .await?
                }
            };
            run_import(tunnel, listen, udp_listen).await?;
        }
    }
    Ok(())
}
