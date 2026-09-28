//! Integration tests for restoring a full snapshot of a sandbox that has secrets and TLS
//! interception configured.
//!
//! Restoring a snapshot of a sandbox created with `--secret ENV@HOST` (or the SDK equivalent,
//! `SandboxBuilder::secret`) must not silently lose TLS interception: the restored guest's
//! reconnected `msb_runtime` share (virtio_fs1) expects `runtime_dir/tls/ca.pem` to exist
//! immediately on resume, and the destination call must re-supply or explicitly drop every
//! secret the snapshot captured (see `RestoreBuilder::secret`/`drop_secret` in
//! `sdk/rust/lib/sandbox/restore_builder.rs`).
//!
//! These tests boot real VMs (KVM on Linux, libkrun on macOS) and are gated behind `#[ignore]`
//! by `#[msb_test]`, matching the rest of this directory (see `tls_intercept.rs`,
//! `http_connect_secret.rs`). Run them explicitly after `just build && just install`:
//!
//! ```sh
//! just build
//! just install
//! MSB_TEST_ISOLATE_HOME=1 cargo test -p microsandbox --test restore_secret_tls --features local,net -- --ignored
//! ```
//!
//! `MSB_TEST_ISOLATE_HOME=1` runs each test against a private `~/.microsandbox`-equivalent
//! tempdir (see `test_utils::init_isolated_home`); omit it to run against the real installed
//! home for a quick local check, but then run one test at a time (`--test-threads=1`).

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use microsandbox::{NetworkPolicy, Sandbox, Snapshot};
use rcgen::CertificateParams;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use test_utils::msb_test;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const CURL_IMAGE: &str = "mirror.gcr.io/curlimages/curl";
const REAL_SECRET: &str = "real-restore-secret";
const ALLOWED_HOST: &str = "host.microsandbox.internal";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Minimal HTTPS server bound to `127.0.0.1` and `::1` on the same port. Records the
/// `Authorization` header of the one request it expects to receive.
struct TargetHttps {
    port: u16,
    handle: Option<JoinHandle<io::Result<String>>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl TargetHttps {
    async fn start() -> io::Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let v4 = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let port = v4.local_addr()?.port();
        let v6 = TcpListener::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, port))).await?;
        let acceptor = TlsAcceptor::from(test_server_tls_config());

        let handle = tokio::spawn(async move {
            let (stream, _) = tokio::select! {
                a = v4.accept() => a?,
                a = v6.accept() => a?,
            };
            let tls = acceptor.accept(stream).await?;
            received_auth_header(tls).await
        });

        Ok(Self {
            port,
            handle: Some(handle),
        })
    }

    fn port(&self) -> u16 {
        self.port
    }

    async fn received_auth(&mut self) -> io::Result<String> {
        self.handle
            .take()
            .expect("target fixture already consumed")
            .await
            .map_err(io::Error::other)?
    }
}

impl Drop for TargetHttps {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Boot a curl sandbox with one header-injected secret and TLS interception on `port`.
async fn spawn_secret_curl_sandbox(name: &str, port: u16) -> Sandbox {
    Sandbox::builder(name)
        .image(CURL_IMAGE)
        .cpus(1)
        .memory(256)
        .user("0")
        .replace()
        .secret(|s| {
            s.env("API_KEY")
                .value(REAL_SECRET)
                .allow(ALLOWED_HOST)
                .substitute_in_headers(true)
        })
        .network(|n| {
            n.policy(NetworkPolicy::allow_all())
                .tls(|t| t.intercepted_ports(vec![port]).verify_upstream(false))
        })
        .create()
        .await
        .expect("create source sandbox")
}

/// Curl command that fails closed on a certificate mismatch or a missing CA file: no `-k`,
/// `--cacert` points at the live-mounted `msb_runtime` share instead of a baked-in system
/// bundle, so this only succeeds if the restored guest's `tls/ca.pem` was rewritten before
/// resume and matches the interception CA that actually signed this connection.
fn verifying_curl_command(port: u16) -> String {
    format!(
        r#"curl --cacert /.msb/tls/ca.pem --http1.1 -m 30 -sS -o /dev/null \
  -w 'code=%{{http_code}}' \
  -H "Authorization: Bearer $API_KEY" \
  https://{ALLOWED_HOST}:{port}/api"#
    )
}

/// Capture a full (memory + devices) snapshot of `source_name`, then stop and remove the
/// source so nothing but the snapshot backs the later restore.
async fn capture_and_remove_source(
    source: Sandbox,
    source_name: &str,
    snapshot_name: &str,
) -> Snapshot {
    let snapshot = Snapshot::builder(snapshot_name)
        .from_sandbox(source_name)
        .full()
        .create()
        .await
        .expect("capture full snapshot");
    source.stop().await.expect("stop source");
    let _ = Sandbox::remove(source_name).await;
    snapshot
}

async fn teardown(sb: Sandbox, name: &str) {
    let _ = sb.stop().await;
    let _ = Sandbox::remove(name).await;
}

fn test_server_tls_config() -> Arc<rustls::ServerConfig> {
    let key_pair = rcgen::KeyPair::generate().expect("generate test key");
    let params =
        CertificateParams::new(vec![ALLOWED_HOST.to_string()]).expect("test certificate params");
    let cert = params.self_signed(&key_pair).expect("self-sign test cert");
    let chain = vec![CertificateDer::from(cert.der().to_vec())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("test server config"),
    )
}

async fn received_auth_header(
    mut stream: tokio_rustls::server::TlsStream<TcpStream>,
) -> io::Result<String> {
    let mut buf = Vec::new();
    loop {
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let headers = String::from_utf8_lossy(&buf);
    let auth = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("authorization")
                .then(|| value.trim().to_string())
        })
        .unwrap_or_default();

    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        .await?;
    stream.shutdown().await?;

    Ok(auth)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

/// Restoring a full snapshot with the captured secret re-supplied must restore TLS
/// interception (proving `runtime_dir/tls/ca.pem` exists again before the guest resumes) and
/// must keep substituting the real secret value for the captured placeholder.
#[msb_test]
async fn restore_full_snapshot_resupplies_secret_and_restores_tls() {
    let mut target = TargetHttps::start().await.expect("https fixture");
    let port = target.port();
    let source_name = "restore-secret-tls-src";
    let dest_name = "restore-secret-tls-dst";
    let snapshot_name = "restore-secret-tls-snap";

    let source = spawn_secret_curl_sandbox(source_name, port).await;
    let snapshot = capture_and_remove_source(source, source_name, snapshot_name).await;

    let dst = Sandbox::restore_ref(snapshot.reference())
        .name(dest_name)
        .secret(|s| {
            s.env("API_KEY")
                .value(REAL_SECRET)
                .allow(ALLOWED_HOST)
                .substitute_in_headers(true)
        })
        .restore()
        .await
        .expect("restore with re-supplied secret");

    let out = dst
        .shell(verifying_curl_command(port))
        .await
        .expect("curl restored guest over verified TLS");

    let stdout = out.stdout().unwrap_or_default();
    assert!(
        stdout.contains("code=200"),
        "expected curl to verify the restored interception CA and receive 200, stdout: {stdout}, stderr: {}",
        out.stderr().unwrap_or_default()
    );

    let auth = target.received_auth().await.expect("target auth");
    assert_eq!(
        auth,
        format!("Bearer {REAL_SECRET}"),
        "restored guest must still substitute the real secret for the captured placeholder; got: {auth:?}"
    );

    teardown(dst, dest_name).await;
    let _ = Snapshot::remove_ref(snapshot.reference(), true).await;
}

/// Restoring a snapshot that captured a secret, without re-supplying or dropping it, must
/// fail closed instead of silently booting a guest whose placeholder never gets substituted.
#[msb_test]
async fn restore_full_snapshot_without_secret_or_drop_fails_closed() {
    let target = TargetHttps::start().await.expect("https fixture");
    let port = target.port();
    let source_name = "restore-secret-tls-unsupplied-src";
    let snapshot_name = "restore-secret-tls-unsupplied-snap";

    let source = spawn_secret_curl_sandbox(source_name, port).await;
    let snapshot = capture_and_remove_source(source, source_name, snapshot_name).await;

    let error = Sandbox::restore_ref(snapshot.reference())
        .name("restore-secret-tls-unsupplied-dst")
        .restore()
        .await
        .err()
        .expect("restore must fail closed without --secret or --drop-secret for API_KEY");

    let message = error.to_string();
    assert!(
        message.contains("API_KEY")
            && message.contains("--secret")
            && message.contains("--drop-secret"),
        "expected a fail-closed message naming API_KEY and both flags, got: {message}"
    );

    let _ = Snapshot::remove_ref(snapshot.reference(), true).await;
}
