// Copyright 2026 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! A connector given a `tls_verify_hook` verifies against the hook's store alone.
//!
//! Its own test binary, holding one test: it points `SSL_CERT_FILE` at the test
//! certificate before anything reads the environment, so the default verify paths trust
//! that certificate — and a connector whose hook installs nothing must not.

#![cfg(any(feature = "openssl", feature = "boringssl"))]

use pingora_core::connectors::{ConnectorOptions, TransportConnector};
use pingora_core::protocols::l4::stream::Stream;
use pingora_core::protocols::tls::server::handshake;
use pingora_core::tls::ssl::{SslAcceptor, SslFiletype, SslMethod};
use pingora_core::upstreams::peer::BasicPeer;
use pingora_error::ErrorType;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;

/// A loopback TLS listener presenting the self-signed test certificate.
async fn self_signed_tls_listener(cert: &str) -> SocketAddr {
    let key = format!("{}/tests/keys/key.pem", env!("CARGO_MANIFEST_DIR"));
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    builder.set_certificate_chain_file(cert).unwrap();
    builder.set_private_key_file(key, SslFiletype::PEM).unwrap();
    let acceptor = Arc::new(builder.build());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = handshake(&acceptor, Stream::from(tcp)).await {
                    // Hold the session until the client is done with it.
                    let mut buf = [0; 1];
                    let _ = tls.read(&mut buf).await;
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn test_tls_verify_hook_store_is_the_hooks_alone() {
    let cert = format!("{}/tests/keys/server.crt", env!("CARGO_MANIFEST_DIR"));
    // The test's runtime is the current thread and nothing has read the environment yet,
    // so nothing reads it concurrently with this write.
    std::env::set_var("SSL_CERT_FILE", &cert);

    let addr = self_signed_tls_listener(&cert).await;
    let mut peer = BasicPeer::new(&addr.to_string());
    peer.sni = "openrusty.org".to_string();
    peer.options.connection_timeout = Some(Duration::from_secs(5));

    // A hook that installs nothing trusts nothing — the default verify paths, which name
    // the certificate, are not consulted.
    let mut options = ConnectorOptions::new(1);
    options.tls_verify_hook = Some(Arc::new(|_builder| {}));
    let err = TransportConnector::new(Some(options))
        .new_stream(&peer)
        .await
        .expect_err("a connector whose hook installs nothing must refuse the server");
    assert_eq!(err.etype(), &ErrorType::InvalidCert, "{err}");

    // Control: without the hook, the default verify paths trust the certificate.
    let stream = TransportConnector::new(Some(ConnectorOptions::new(1)))
        .new_stream(&peer)
        .await;
    assert!(
        stream.is_ok(),
        "the default verify paths trust the certificate SSL_CERT_FILE names: {:?}",
        stream.err()
    );
}
