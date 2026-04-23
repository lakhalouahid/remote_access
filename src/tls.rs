use std::fs::File;
use std::io::BufReader;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, ServerConfig};
use rcgen::{CertificateParams, KeyPair, SanType, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig as RustlsClientConfig, RootCertStore};

pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(File::open(path).with_context(|| format!("open {}", path.display()))?);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(anyhow!("no certificates in {}", path.display()));
    }
    Ok(certs)
}

pub fn load_key(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(File::open(path).with_context(|| format!("open {}", path.display()))?);
    if let Some(k) = rustls_pemfile::private_key(&mut reader)? {
        return Ok(k);
    }
    Err(anyhow!("no private key in {}", path.display()))
}

pub fn quinn_server_config(cert_pem: &Path, key_pem: &Path) -> Result<ServerConfig> {
    let certs = load_certs(cert_pem)?;
    let key = load_key(key_pem)?;
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("invalid server cert/key")?;
    tls.alpn_protocols = vec![b"remote-access".to_vec()];
    let q = QuicServerConfig::try_from(tls).context("quic server tls")?;
    Ok(ServerConfig::with_crypto(Arc::new(q)))
}

pub fn quinn_client_config_trust(cert_pem: &Path) -> Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for c in load_certs(cert_pem)? {
        roots.add(c).context("add root cert")?;
    }
    let mut tls = RustlsClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"remote-access".to_vec()];
    let q = QuicClientConfig::try_from(tls).context("quic client tls")?;
    Ok(ClientConfig::new(Arc::new(q)))
}

/// Writes PEM files suitable for `quinn_server_config` / `quinn_client_config_trust`.
/// Includes DNS SANs `localhost` / `remote-access`, loopback IPs, and the relay bind IP when it is concrete.
pub fn generate_ephemeral_cert_files(
    cert_out: &Path,
    key_out: &Path,
    bind_ip: IpAddr,
) -> Result<()> {
    let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut params = CertificateParams::new(vec![
        "localhost".to_string(),
        "remote-access".to_string(),
    ])
    .context("cert params")?;
    params.subject_alt_names.push(SanType::IpAddress(
        std::net::Ipv4Addr::LOCALHOST.into(),
    ));
    params.subject_alt_names.push(SanType::IpAddress(
        std::net::Ipv6Addr::LOCALHOST.into(),
    ));
    if !bind_ip.is_unspecified() {
        params.subject_alt_names.push(SanType::IpAddress(bind_ip));
    }
    let cert = params.self_signed(&kp).context("self-sign")?;
    std::fs::write(cert_out, cert.pem()).with_context(|| format!("write {}", cert_out.display()))?;
    std::fs::write(key_out, kp.serialize_pem())
        .with_context(|| format!("write {}", key_out.display()))?;
    Ok(())
}
