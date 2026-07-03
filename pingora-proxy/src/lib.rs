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

//! # pingora-proxy
//!
//! Programmable HTTP proxy built on top of [pingora_core].
//!
//! # Features
//! - HTTP/1.x and HTTP/2 for both downstream and upstream
//! - Connection pooling
//! - TLSv1.3, mutual TLS, customizable CA
//! - Request/Response scanning, modification or rejection
//! - Dynamic upstream selection
//! - Configurable retry and failover
//! - Fully programmable and customizable at any stage of a HTTP request
//!
//! # How to use
//!
//! Users of this crate defines their proxy by implementing [ProxyHttp] trait, which contains the
//! callbacks to be invoked at each stage of a HTTP request.
//!
//! Then the service can be passed into [`http_proxy_service()`] for a [pingora_core::server::Server] to
//! run it.
//!
//! See `examples/load_balancer.rs` for a detailed example.

use async_trait::async_trait;
use bytes::Bytes;
use futures::future::BoxFuture;
use futures::future::FutureExt;
use http::{header, version::Version, Method};
use log::{debug, error, trace, warn};
use once_cell::sync::Lazy;
use pingora_http::{RequestHeader, ResponseHeader};
use std::fmt::Debug;
use std::str;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::sync::{mpsc, Notify};
use tokio::time;

use pingora_cache::NoCacheReason;
use pingora_core::apps::{
    HttpPersistentSettings, HttpServerApp, HttpServerOptions, ReusedHttpStream,
};
use pingora_core::connectors::http::custom;
use pingora_core::connectors::{http::Connector, ConnectorOptions};
use pingora_core::modules::http::compression::ResponseCompressionBuilder;
use pingora_core::modules::http::{HttpModuleCtx, HttpModules};
use pingora_core::protocols::http::client::HttpSession as ClientSession;
use pingora_core::protocols::http::custom::CustomMessageWrite;
use pingora_core::protocols::http::subrequest::server::SubrequestHandle;
use pingora_core::protocols::http::v1::client::HttpSession as HttpSessionV1;
use pingora_core::protocols::http::v2::server::H2Options;
use pingora_core::protocols::http::HttpTask;
use pingora_core::protocols::http::ServerSession as HttpSession;
use pingora_core::protocols::http::SERVER_NAME;
use pingora_core::protocols::Stream;
use pingora_core::protocols::{Digest, UniqueID};
use pingora_core::server::configuration::ServerConf;
use pingora_core::server::{RuntimeOpts, ShutdownWatch};
use pingora_core::upstreams::peer::{HttpPeer, Peer};
use pingora_error::{Error, ErrorSource, ErrorType::*, OrErr, Result};

const TASK_BUFFER_SIZE: usize = 4;

mod proxy_cache;
mod proxy_common;
mod proxy_custom;
mod proxy_h1;
mod proxy_h2;
mod proxy_purge;
mod proxy_trait;
pub mod subrequest;

use subrequest::{BodyMode, Ctx as SubrequestCtx};

pub use proxy_cache::range_filter::{range_header_filter, MultiRangeInfo, RangeType};
pub use proxy_purge::PurgeStatus;
pub use proxy_trait::{FailToProxy, ProxyHttp, ProxyWarnLogContext};

pub mod prelude {
    pub use crate::{http_proxy, http_proxy_service, ProxyHttp, ProxyWarnLogContext, Session};
}

pub type ProcessCustomSession<SV, C> = Arc<
    dyn Fn(Arc<HttpProxy<SV, C>>, Stream, &ShutdownWatch) -> BoxFuture<'static, Option<Stream>>
        + Send
        + Sync
        + Unpin
        + 'static,
>;

/// The concrete type that holds the user defined HTTP proxy.
///
/// Users don't need to interact with this object directly.
pub struct HttpProxy<SV, C = ()>
where
    C: custom::Connector, // Upstream custom connector
{
    inner: SV, // TODO: name it better than inner
    client_upstream: Connector<C>,
    shutdown: Notify,
    shutdown_flag: Arc<AtomicBool>,
    pub server_options: Option<HttpServerOptions>,
    pub h2_options: Option<H2Options>,
    pub downstream_modules: HttpModules,
    #[cfg(feature = "upstream_modules")]
    pub upstream_modules: HttpModules,
    max_retries: usize,
    process_custom_session: Option<ProcessCustomSession<SV, C>>,
}

impl<SV> HttpProxy<SV, ()> {
    /// Create a new [`HttpProxy`] with the given [`ProxyHttp`] implementation and [`ServerConf`].
    ///
    /// After creating an `HttpProxy`, you should call [`HttpProxy::handle_init_modules()`] to
    /// initialize the downstream modules before processing requests.
    ///
    /// For most use cases, prefer using [`http_proxy_service()`] which wraps the `HttpProxy` in a
    /// [`Service`]. This constructor is useful when you need to integrate `HttpProxy` into a custom
    /// accept loop (e.g., for SNI-based routing decisions before TLS termination).
    ///
    /// # Example
    ///
    /// ```ignore
    /// use pingora_proxy::HttpProxy;
    /// use std::sync::Arc;
    ///
    /// let mut proxy = HttpProxy::new(my_proxy_app, server_conf);
    /// proxy.handle_init_modules();
    /// let proxy = Arc::new(proxy);
    /// // Use proxy.process_new_http() in your custom accept loop
    /// ```
    pub fn new(inner: SV, conf: Arc<ServerConf>) -> Self {
        HttpProxy {
            inner,
            client_upstream: Connector::new(Some(ConnectorOptions::from_server_conf(&conf))),
            shutdown: Notify::new(),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            server_options: None,
            h2_options: None,
            downstream_modules: HttpModules::new(),
            #[cfg(feature = "upstream_modules")]
            upstream_modules: HttpModules::new(),
            max_retries: conf.max_retries,
            process_custom_session: None,
        }
    }
}

impl<SV, C> HttpProxy<SV, C>
where
    C: custom::Connector,
{
    fn new_custom(
        inner: SV,
        conf: Arc<ServerConf>,
        connector: C,
        on_custom: Option<ProcessCustomSession<SV, C>>,
        server_options: Option<HttpServerOptions>,
        client_options: Option<ConnectorOptions>,
    ) -> Self
    where
        SV: ProxyHttp + Send + Sync + 'static,
        SV::CTX: Send + Sync,
    {
        let client_options =
            client_options.unwrap_or_else(|| ConnectorOptions::from_server_conf(&conf));
        let client_upstream = Connector::new_custom(Some(client_options), connector);

        HttpProxy {
            inner,
            client_upstream,
            shutdown: Notify::new(),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            server_options,
            downstream_modules: HttpModules::new(),
            #[cfg(feature = "upstream_modules")]
            upstream_modules: HttpModules::new(),
            max_retries: conf.max_retries,
            process_custom_session: on_custom,
            h2_options: None,
        }
    }

    /// Return the number of times a pooled upstream connection was found to contain
    /// unexpected data from the server.
    pub fn unexpected_data_connection_count(&self) -> u64 {
        self.client_upstream.unexpected_data_connection_count()
    }

    /// Return a shared reference to the unexpected data connection counter for periodic metric reporting.
    pub fn unexpected_data_connection_counter(&self) -> Arc<AtomicU64> {
        self.client_upstream.unexpected_data_connection_counter()
    }

    /// Initialize the downstream modules for this proxy.
    ///
    /// This method must be called after creating an [`HttpProxy`] with [`HttpProxy::new()`]
    /// and before processing any requests. It invokes [`ProxyHttp::init_downstream_modules()`]
    /// to set up any HTTP modules configured by the user's proxy implementation.
    ///
    /// Note: When using [`http_proxy_service()`] or [`http_proxy_service_with_name()`],
    /// this method is called automatically.
    pub fn handle_init_modules(&mut self)
    where
        SV: ProxyHttp,
    {
        self.inner
            .init_downstream_modules(&mut self.downstream_modules);
        #[cfg(feature = "upstream_modules")]
        self.inner.init_upstream_modules(&mut self.upstream_modules);
    }

    async fn handle_new_request(
        &self,
        mut downstream_session: Box<HttpSession>,
    ) -> Option<Box<HttpSession>>
    where
        SV: ProxyHttp + Send + Sync,
        SV::CTX: Send + Sync,
    {
        // phase 1 read request header

        let res = tokio::select! {
            biased; // biased select is cheaper, and we don't want to drop already buffered requests
            res = downstream_session.read_request() => { res }
            _ = self.shutdown.notified() => {
                // service shutting down, dropping the connection to stop more req from coming in
                return None;
            }
        };
        match res {
            Ok(true) => {
                // TODO: check n==0
                debug!("Successfully get a new request");
            }
            Ok(false) => {
                return None; // TODO: close connection?
            }
            Err(mut e) => {
                e.as_down();
                error!(
                    "Fail to proxy: {e}, downstream session type: {}",
                    downstream_session.session_type()
                );
                if matches!(e.etype, InvalidHTTPHeader) {
                    downstream_session
                        .respond_error(400)
                        .await
                        .unwrap_or_else(|e| {
                            error!("failed to send error response to downstream: {e}");
                        });
                } // otherwise the connection must be broken, no need to send anything
                downstream_session.shutdown().await;
                return None;
            }
        }
        trace!(
            "Request header: {:?}",
            downstream_session.req_header().as_ref()
        );
        // CONNECT method proxying is not default supported by the proxy http logic itself,
        // since the tunneling process changes the request-response flow.
        // https://datatracker.ietf.org/doc/html/rfc9110#name-connect
        // Also because the method impacts message framing in a way is currently unaccounted for
        // (https://datatracker.ietf.org/doc/html/rfc9112#section-6.3-2.2)
        // it is safest to disallow use of the method by default.
        if !self
            .server_options
            .as_ref()
            .is_some_and(|opts| opts.allow_connect_method_proxying)
            && downstream_session.req_header().method == Method::CONNECT
        {
            downstream_session
                .respond_error(405)
                .await
                .unwrap_or_else(|e| {
                    error!("failed to send error response to downstream: {e}");
                });
            downstream_session.shutdown().await;
            return None;
        }
        Some(downstream_session)
    }

    // return bool: server_session can be reused, and error if any
    async fn proxy_to_upstream(
        &self,
        session: &mut Session,
        ctx: &mut SV::CTX,
    ) -> (bool, Option<Box<Error>>)
    where
        SV: ProxyHttp + Send + Sync,
        SV::CTX: Send + Sync,
    {
        let peer = match self.inner.upstream_peer(session, ctx).await {
            Ok(p) => p,
            Err(e) => return (false, Some(e)),
        };

        let client_session = self.client_upstream.get_http_session(&*peer).await;
        match client_session {
            Ok((client_session, client_reused)) => {
                let (server_reused, error) = match client_session {
                    ClientSession::H1(mut h1) => {
                        let (server_reused, client_reuse, error) = self
                            .proxy_to_h1_upstream(session, &mut h1, client_reused, &peer, ctx)
                            .await;
                        if client_reuse {
                            let session = ClientSession::H1(h1);
                            self.client_upstream
                                .release_http_session(session, &*peer, peer.idle_timeout())
                                .await;
                        }
                        (server_reused, error)
                    }
                    ClientSession::H2(mut h2) => {
                        let (server_reused, mut error) = self
                            .proxy_to_h2_upstream(session, &mut h2, client_reused, &peer, ctx)
                            .await;
                        let session = ClientSession::H2(h2);
                        self.client_upstream
                            .release_http_session(session, &*peer, peer.idle_timeout())
                            .await;

                        if let Some(e) = error.as_mut() {
                            // try to downgrade if A. origin says so or B. origin sends an invalid
                            // response, which usually means origin h2 is not production ready
                            if matches!(e.etype, H2Downgrade | InvalidH2) {
                                if peer
                                    .get_alpn()
                                    .is_none_or(|alpn| alpn.get_min_http_version() == 1)
                                {
                                    // Add the peer to prefer h1 so that all following requests
                                    // will use h1
                                    self.client_upstream.prefer_h1(&*peer);
                                } else {
                                    // the peer doesn't allow downgrading to h1 (e.g. gRPC)
                                    e.retry = false.into();
                                }
                            }
                        }

                        (server_reused, error)
                    }
                    ClientSession::Custom(mut c) => {
                        let (server_reused, error) = self
                            .proxy_to_custom_upstream(session, &mut c, client_reused, &peer, ctx)
                            .await;
                        let session = ClientSession::Custom(c);
                        self.client_upstream
                            .release_http_session(session, &*peer, peer.idle_timeout())
                            .await;
                        (server_reused, error)
                    }
                };
                (
                    server_reused,
                    error.map(|e| {
                        self.inner
                            .error_while_proxy(&peer, session, e, ctx, client_reused)
                    }),
                )
            }
            Err(mut e) => {
                e.as_up();
                let new_err = self.inner.fail_to_connect(session, &peer, ctx, e);
                (false, Some(new_err.into_up()))
            }
        }
    }

    async fn upstream_filter(
        &self,
        session: &mut Session,
        task: &mut HttpTask,
        ctx: &mut SV::CTX,
    ) -> Result<Option<Duration>>
    where
        SV: ProxyHttp + Send + Sync,
        SV::CTX: Send + Sync,
    {
        let duration = match task {
            HttpTask::Header(header, _eos) => {
                self.inner
                    .upstream_response_filter(session, header, ctx)
                    .await?;
                None
            }
            HttpTask::Body(data, eos) | HttpTask::UpgradedBody(data, eos) => {
                self.inner
                    .upstream_response_body_filter(session, data, *eos, ctx)
                    .await?
            }
            HttpTask::Trailer(Some(trailers)) => {
                self.inner
                    .upstream_response_trailer_filter(session, trailers, ctx)?;
                None
            }
            _ => {
                // task does not support a filter
                None
            }
        };

        Ok(duration)
    }

    async fn finish(
        &self,
        mut session: Session,
        ctx: &mut SV::CTX,
        reuse: bool,
        error: Option<Box<Error>>,
    ) -> Option<ReusedHttpStream>
    where
        SV: ProxyHttp + Send + Sync,
        SV::CTX: Send + Sync,
    {
        self.inner
            .logging(&mut session, error.as_deref(), ctx)
            .await;

        if let Some(e) = error {
            session.downstream_session.on_proxy_failure(e);
        }

        if reuse {
            // TODO: log error
            let mut persistent_settings = HttpPersistentSettings::for_session(&session);
            if let Some(uc) = self.inner.persist_connection_context(&session, ctx) {
                persistent_settings.set_user_context(uc);
            }
            session
                .downstream_session
                .finish()
                .await
                .ok()
                .flatten()
                .map(|s| ReusedHttpStream::from_reusable_stream(s, persistent_settings))
        } else {
            None
        }
    }

    fn cleanup_sub_req(&self, session: &mut Session) {
        if let Some(ctx) = session.subrequest_ctx.as_mut() {
            ctx.release_write_lock();
        }
    }
}

use pingora_cache::HttpCache;
use pingora_core::protocols::http::compression::ResponseCompressionCtx;

/// The established HTTP session
///
/// This object is what users interact with in order to access the request itself or change the proxy
/// behavior.
pub struct Session {
    /// the HTTP session to downstream (the client)
    pub downstream_session: Box<HttpSession>,
    /// The interface to control HTTP caching
    pub cache: HttpCache,
    /// (de)compress responses coming into the proxy (from upstream)
    pub upstream_compression: ResponseCompressionCtx,
    /// ignore downstream range (skip downstream range filters)
    pub ignore_downstream_range: bool,
    /// Were the upstream request headers modified?
    pub upstream_headers_mutated_for_cache: bool,
    /// Whether downstream and upstream differ on whether this HTTP/1 request is an upgrade.
    upstream_h1_upgrade_status_mismatch: bool,
    /// The context from parent request, if this is a subrequest.
    pub subrequest_ctx: Option<Box<SubrequestCtx>>,
    /// Handle to allow spawning subrequests, assigned by the `Subrequest` app logic.
    pub subrequest_spawner: Option<SubrequestSpawner>,
    // Downstream filter modules
    pub downstream_modules_ctx: HttpModuleCtx,
    /// Upstream filter modules. These run before `upstream_compression` and see the raw
    /// (pre-compression) upstream response body.
    #[cfg(feature = "upstream_modules")]
    pub upstream_modules_ctx: HttpModuleCtx,
    /// Upstream response body bytes received (payload only). Set by proxy layer.
    /// TODO: move this into an upstream session digest for future fields.
    upstream_body_bytes_received: usize,
    /// Upstream write pending time. Set by proxy layer (HTTP/1.x only).
    upstream_write_pending_time: Duration,
    /// Flag that is set when the shutdown process has begun.
    shutdown_flag: Arc<AtomicBool>,
    /// streamscope RESPMOD block-page support: when a `response_filter` requests
    /// it, the downstream response HEADER is held (not written) until the response
    /// body has been fully accumulated and inspected by `response_body_filter`. On
    /// release the held header — or a `response_header_override` supplied by the
    /// body filter — is written ahead of the (possibly replaced) body. This lets a
    /// filter turn an infected download's `200` into a real `403` block page
    /// instead of aborting the stream. Off by default => zero behavior change.
    hold_response_header: bool,
    /// The stashed original downstream response header (fully filtered), retained
    /// across upstream task batches while `hold_response_header` is set.
    held_response_header: Option<Box<ResponseHeader>>,
    /// A replacement response header supplied by `response_body_filter` (e.g. the
    /// `403` block-page header). Takes precedence over `held_response_header` on
    /// release.
    response_header_override: Option<Box<ResponseHeader>>,
    /// streamscope patience support ("sink mode"): set once the app has finished
    /// the downstream response early with a complete synthetic response
    /// ([`Session::finish_downstream_response_early`]). While set, the proxy
    /// drivers keep reading the upstream response and keep running the response
    /// body filters (so the app can keep accumulating the body), but write
    /// nothing further downstream, tolerate downstream read errors the same way
    /// the cache-fill continuation does, and mark the downstream connection
    /// non-reusable. Off by default => zero behavior change.
    downstream_finished_early: bool,
}

impl Session {
    fn new(
        downstream_session: impl Into<Box<HttpSession>>,
        downstream_modules: &HttpModules,
        #[cfg(feature = "upstream_modules")] upstream_modules: &HttpModules,
        shutdown_flag: Arc<AtomicBool>,
    ) -> Self {
        Session {
            downstream_session: downstream_session.into(),
            cache: HttpCache::new(),
            // disable both upstream and downstream compression
            upstream_compression: ResponseCompressionCtx::new(0, false, false),
            ignore_downstream_range: false,
            upstream_headers_mutated_for_cache: false,
            upstream_h1_upgrade_status_mismatch: false,
            subrequest_ctx: None,
            subrequest_spawner: None, // optionally set later on
            downstream_modules_ctx: downstream_modules.build_ctx(),
            #[cfg(feature = "upstream_modules")]
            upstream_modules_ctx: upstream_modules.build_ctx(),
            upstream_body_bytes_received: 0,
            upstream_write_pending_time: Duration::ZERO,
            shutdown_flag,
            hold_response_header: false,
            held_response_header: None,
            response_header_override: None,
            downstream_finished_early: false,
        }
    }

    /// streamscope RESPMOD block-page support. Request (or clear) holding the
    /// downstream response header until the response body is fully inspected.
    ///
    /// Call this from `ProxyHttp::response_filter`. When `hold` is true, the
    /// response header is stashed instead of written; `response_body_filter` can
    /// then buffer/withhold the body (`*body = None`) and, at end-of-stream, either
    /// release it unchanged (clean) or call [`Session::override_response_header`]
    /// to serve a replacement (e.g. a `403` block page) with a replacement body.
    /// Setting it (either value) resets any header held from a prior response —
    /// and any early-finish (sink mode) state — so a reused (keep-alive)
    /// connection never leaks state between requests.
    pub fn set_hold_response_header(&mut self, hold: bool) {
        self.hold_response_header = hold;
        self.held_response_header = None;
        self.response_header_override = None;
        self.downstream_finished_early = false;
    }

    /// streamscope patience support: whether the downstream response was already
    /// finished early with a synthetic response (sink mode). See
    /// [`Session::finish_downstream_response_early`].
    pub fn downstream_finished_early(&self) -> bool {
        self.downstream_finished_early
    }

    /// Finish the downstream response NOW with a complete synthetic response,
    /// then enter sink mode: subsequent upstream tasks still run through the
    /// response body filters (so an inspecting app keeps accumulating the body),
    /// but nothing further is written downstream; the drivers keep pumping the
    /// upstream to end-of-stream (the cache-fill continuation idiom) and report
    /// the downstream connection as non-reusable.
    ///
    /// Intended for `ProxyHttp::response_body_filter` on a withheld (held-header)
    /// response: e.g. replace a slow, still-downloading body with a "please
    /// wait" interstitial while the transfer keeps buffering for inspection.
    /// Consumes/clears any held-header state — the synthetic response replaces
    /// the (never-written) upstream header; a same-batch upstream `Header` task
    /// is discarded by the drivers' sink branch, so exactly one response reaches
    /// the wire. Works on both h1 (header + body finished in one write) and h2
    /// (DATA with END_STREAM).
    ///
    /// The caller should set `Content-Length` (the body is written as one final
    /// chunk) and, for h1 clients, `Connection: close` — the session task stays
    /// busy draining the upstream, so a pipelined keep-alive request would not
    /// be read until the drain completes.
    ///
    /// Sink mode is entered even if the write fails (a broken downstream must
    /// not receive any later writes either); the error is still returned so the
    /// caller can abort/clean up its own state.
    pub async fn finish_downstream_response_early(
        &mut self,
        header: Box<ResponseHeader>,
        body: Bytes,
    ) -> Result<()> {
        // Discard any held/override header state; nothing upstream-originated
        // may be written after this point.
        self.set_hold_response_header(false);
        let res = self
            .write_response_tasks(vec![
                HttpTask::Header(header, false),
                HttpTask::Body(Some(body), true),
            ])
            .await;
        // Note: the `bool` (response done) from `write_response_tasks` is
        // deliberately dropped — it must not feed the driver's response state,
        // which tracks the *upstream* response and must keep the drain loop
        // running until upstream end-of-stream.
        self.downstream_finished_early = true;
        res.map(|_| ())
    }

    /// Supply a replacement downstream response header, used in place of the held
    /// upstream header when the response is released. Intended for
    /// `response_body_filter` to turn an infected download into a block-page
    /// response. No effect unless header holding was enabled via
    /// [`Session::set_hold_response_header`].
    pub fn override_response_header(&mut self, header: Box<ResponseHeader>) {
        self.response_header_override = Some(header);
    }

    /// Apply held-response-header logic to one batch of downstream tasks, in place,
    /// right before they are written downstream. No-op unless holding is active.
    ///
    /// While holding: a `Header` task is stashed (and dropped from the batch) so it
    /// is not written yet; withheld empty `Body` chunks are dropped. When the batch
    /// carries real body bytes or the end-of-stream marker, the response is
    /// released: the override header (if any) else the held header is prepended, and
    /// holding is turned off so any remaining chunks stream through untouched. A
    /// bodyless held header (`end` on the header task) is released immediately.
    pub(crate) fn handle_held_response_header(&mut self, tasks: &mut Vec<HttpTask>) {
        if !self.hold_response_header {
            return;
        }
        let mut out: Vec<HttpTask> = Vec::with_capacity(tasks.len() + 1);
        // `release` = write the (held/override) header in this batch. `header_ends`
        // = the response is bodyless (the header task itself carried end-of-stream).
        let mut release = false;
        let mut header_ends = false;
        for task in tasks.drain(..) {
            match task {
                HttpTask::Header(header, end) => {
                    // Stash the already-filtered header; do not write it yet.
                    self.held_response_header = Some(header);
                    if end {
                        release = true;
                        header_ends = true;
                    }
                }
                HttpTask::Body(data, end) => {
                    let has_data = data.as_ref().is_some_and(|b| !b.is_empty());
                    if has_data || end {
                        // Real body bytes (or stream end): release the header ahead
                        // of this body.
                        release = true;
                        out.push(HttpTask::Body(data, end));
                    }
                    // else: a withheld empty chunk — drop it (write nothing).
                }
                other => {
                    // Trailer/Done/Failed: ensure the header precedes them.
                    release = true;
                    out.push(other);
                }
            }
        }
        if release {
            self.hold_response_header = false;
            // The body filter's override (e.g. a 403 block page) wins over the
            // original upstream header.
            if let Some(header) = self
                .response_header_override
                .take()
                .or_else(|| self.held_response_header.take())
            {
                out.insert(0, HttpTask::Header(header, header_ends));
            }
        }
        // else: only a header was seen (no body yet) — keep holding; the stashed
        // header is retained for a later batch.
        *tasks = out;
    }

    /// Create a new [Session] from the given [Stream]
    ///
    /// This function is mostly used for testing and mocking, given the downstream modules and
    /// shutdown flags will never be set.
    pub fn new_h1(stream: Stream) -> Self {
        let modules = HttpModules::new();
        Self::new(
            Box::new(HttpSession::new_http1(stream)),
            &modules,
            #[cfg(feature = "upstream_modules")]
            &HttpModules::new(),
            Arc::new(AtomicBool::new(false)),
        )
    }

    /// Create a new [Session] from the given [Stream] with modules
    ///
    /// This function is mostly used for testing and mocking, given the shutdown flag will never be
    /// set.
    pub fn new_h1_with_modules(stream: Stream, downstream_modules: &HttpModules) -> Self {
        Self::new(
            Box::new(HttpSession::new_http1(stream)),
            downstream_modules,
            #[cfg(feature = "upstream_modules")]
            &HttpModules::new(),
            Arc::new(AtomicBool::new(false)),
        )
    }

    /// Run upstream module filters on the given [`HttpTask`].
    ///
    /// Upstream modules process each task **before** `upstream_compression` and
    /// see the raw (pre-compression) upstream response. Like the downstream
    /// module path, `response_trailer_filter` and `response_done_filter` return
    /// values are converted to body tasks when present.
    #[cfg(feature = "upstream_modules")]
    pub async fn upstream_modules_filter_task(&mut self, t: &mut HttpTask) -> Result<()> {
        match t {
            HttpTask::Header(header, eos) => {
                self.upstream_modules_ctx
                    .response_header_filter(header, *eos)
                    .await?;
            }
            HttpTask::Body(body, eos) | HttpTask::UpgradedBody(body, eos) => {
                self.upstream_modules_ctx.response_body_filter(body, *eos)?;
            }
            HttpTask::Trailer(trailers) => {
                if let Some(buf) = self
                    .upstream_modules_ctx
                    .response_trailer_filter(trailers)?
                {
                    *t = HttpTask::Body(Some(buf), true);
                }
            }
            HttpTask::Done => {
                if let Some(buf) = self.upstream_modules_ctx.response_done_filter()? {
                    *t = HttpTask::Body(Some(buf), true);
                }
            }
            HttpTask::Failed(_) => {}
        }
        Ok(())
    }

    pub fn as_downstream_mut(&mut self) -> &mut HttpSession {
        &mut self.downstream_session
    }

    pub fn as_downstream(&self) -> &HttpSession {
        &self.downstream_session
    }

    /// Write HTTP response with the given error code to the downstream.
    pub async fn respond_error(&mut self, error: u16) -> Result<()> {
        self.as_downstream_mut().respond_error(error).await
    }

    /// Write HTTP response with the given error code to the downstream with a body.
    pub async fn respond_error_with_body(&mut self, error: u16, body: Bytes) -> Result<()> {
        self.as_downstream_mut()
            .respond_error_with_body(error, body)
            .await
    }

    /// Write the given HTTP response header to the downstream
    ///
    /// Different from directly calling [HttpSession::write_response_header], this function also
    /// invokes the filter modules.
    pub async fn write_response_header(
        &mut self,
        mut resp: Box<ResponseHeader>,
        end_of_stream: bool,
    ) -> Result<()> {
        self.downstream_modules_ctx
            .response_header_filter(&mut resp, end_of_stream)
            .await?;
        self.downstream_session.write_response_header(resp).await
    }

    /// Similar to `write_response_header()`, this fn will clone the `resp` internally
    pub async fn write_response_header_ref(
        &mut self,
        resp: &ResponseHeader,
        end_of_stream: bool,
    ) -> Result<(), Box<Error>> {
        self.write_response_header(Box::new(resp.clone()), end_of_stream)
            .await
    }

    /// Write the given HTTP response body chunk to the downstream
    ///
    /// Different from directly calling [HttpSession::write_response_body], this function also
    /// invokes the filter modules.
    pub async fn write_response_body(
        &mut self,
        mut body: Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<()> {
        self.downstream_modules_ctx
            .response_body_filter(&mut body, end_of_stream)?;

        if body.is_none() && !end_of_stream {
            return Ok(());
        }

        let data = body.unwrap_or_default();
        self.downstream_session
            .write_response_body(data, end_of_stream)
            .await
    }

    // Run downstream module response filters on a single task, updating
    // `seen_upgraded` to track whether an upgrade has been seen. Used by both
    // `send_downstream_proxy_task` and `write_response_tasks`.
    async fn downstream_response_task_filter(
        &mut self,
        task: &mut HttpTask,
        seen_upgraded: &mut bool,
    ) -> Result<()> {
        match task {
            HttpTask::Header(resp, end) => {
                self.downstream_modules_ctx
                    .response_header_filter(resp, *end)
                    .await?;
            }
            HttpTask::Body(data, end) => {
                self.downstream_modules_ctx
                    .response_body_filter(data, *end)?;
            }
            HttpTask::UpgradedBody(data, end) => {
                *seen_upgraded = true;
                self.downstream_modules_ctx
                    .response_body_filter(data, *end)?;
            }
            HttpTask::Trailer(trailers) => {
                if let Some(buf) = self
                    .downstream_modules_ctx
                    .response_trailer_filter(trailers)?
                {
                    // Write the trailers into the body if the filter
                    // returns a buffer.
                    //
                    // Note, this will not work if end of stream has already
                    // been seen or we've written content-length bytes.
                    // (Trailers should never come after upgraded body)
                    *task = HttpTask::Body(Some(buf), true);
                }
            }
            HttpTask::Done => {
                // `Done` can be sent in certain response paths to mark end
                // of response if not already done via trailers or body with
                // end flag set.
                // If the filter returns body bytes on Done,
                // write them into the response.
                //
                // Note, this will not work if end of stream has already
                // been seen or we've written content-length bytes.
                if let Some(buf) = self.downstream_modules_ctx.response_done_filter()? {
                    if *seen_upgraded {
                        *task = HttpTask::UpgradedBody(Some(buf), true);
                    } else {
                        *task = HttpTask::Body(Some(buf), true);
                    }
                }
            }
            _ => { /* Failed */ }
        }
        Ok(())
    }

    /// Queue a downstream proxy task for cancel-safe writing after running
    /// downstream module filters. This allows decoupling cache writes from
    /// downstream writes.
    ///
    /// Only works with sessions that support the proxy task API (currently H1).
    ///
    /// # Panics
    /// Panics if the session doesn't support the proxy task API.
    /// Use `write_response_tasks()` for sessions that don't support the proxy task API.
    pub async fn send_downstream_proxy_task(&mut self, mut task: HttpTask) -> Result<()> {
        let mut seen_upgraded = self.was_upgraded();
        self.downstream_response_task_filter(&mut task, &mut seen_upgraded)
            .await?;
        self.downstream_session.send_downstream_proxy_task(task);
        Ok(())
    }

    /// Enable or disable the cancel-safe proxy task API for this session.
    ///
    /// When disabled, the proxy falls back to the blocking `write_response_tasks`
    /// path. This can be called from request filters to opt out on a per-request
    /// basis.
    pub fn set_proxy_tasks_enabled(&mut self, enabled: bool) {
        self.downstream_session.set_proxy_tasks_enabled(enabled);
    }

    /// Check if there are pending downstream tasks queued for writing.
    /// Used for backpressure - don't queue more cache tasks if we have pending writes.
    /// Returns false for sessions that don't support the proxy task API.
    pub fn has_pending_downstream_tasks(&self) -> bool {
        self.downstream_session.supports_proxy_task_api()
            && self.downstream_session.has_pending_downstream_proxy_tasks()
    }

    /// Write all queued downstream proxy tasks. This is cancel-safe and can be called
    /// in a select! loop while waiting for upstream tasks.
    /// For sessions that don't support the proxy task API, this is a no-op.
    pub async fn write_downstream_proxy_tasks(&mut self) -> Result<bool> {
        if self.downstream_session.supports_proxy_task_api() {
            self.downstream_session.write_downstream_proxy_tasks().await
        } else {
            Ok(false)
        }
    }

    pub async fn write_response_tasks(&mut self, mut tasks: Vec<HttpTask>) -> Result<bool> {
        let mut seen_upgraded = self.was_upgraded();
        for task in tasks.iter_mut() {
            self.downstream_response_task_filter(task, &mut seen_upgraded)
                .await?;
        }
        self.downstream_session.response_duplex_vec(tasks).await
    }

    /// Mark the upstream headers as modified by caching. This should lead to range filters being
    /// skipped when responding to the downstream.
    pub fn mark_upstream_headers_mutated_for_cache(&mut self) {
        self.upstream_headers_mutated_for_cache = true;
    }

    /// Check whether the upstream headers were marked as mutated during the request.
    pub fn upstream_headers_mutated_for_cache(&self) -> bool {
        self.upstream_headers_mutated_for_cache
    }

    /// Get the total upstream response body bytes received (payload only) recorded by the proxy layer.
    pub fn upstream_body_bytes_received(&self) -> usize {
        self.upstream_body_bytes_received
    }

    /// Set the total upstream response body bytes received (payload only). Intended for internal use by proxy layer.
    pub(crate) fn set_upstream_body_bytes_received(&mut self, n: usize) {
        self.upstream_body_bytes_received = n;
    }

    /// Get the upstream write pending time recorded by the proxy layer. Returns [`Duration::ZERO`] for HTTP/2.
    pub fn upstream_write_pending_time(&self) -> Duration {
        self.upstream_write_pending_time
    }

    /// Set the upstream write pending time. Intended for internal use by proxy layer.
    pub(crate) fn set_upstream_write_pending_time(&mut self, d: Duration) {
        self.upstream_write_pending_time = d;
    }

    /// Is the proxy process in the process of shutting down (e.g. due to graceful upgrade)?
    pub fn is_process_shutting_down(&self) -> bool {
        self.shutdown_flag.load(Ordering::Acquire)
    }

    pub fn downstream_custom_message(
        &mut self,
    ) -> Result<
        Option<Box<dyn futures::Stream<Item = Result<Bytes>> + Unpin + Send + Sync + 'static>>,
    > {
        if let Some(custom_session) = self.downstream_session.as_custom_mut() {
            custom_session
                .take_custom_message_reader()
                .map(Some)
                .ok_or(Error::explain(
                    ReadError,
                    "can't extract custom reader from downstream",
                ))
        } else {
            Ok(None)
        }
    }
}

impl AsRef<HttpSession> for Session {
    fn as_ref(&self) -> &HttpSession {
        &self.downstream_session
    }
}

impl AsMut<HttpSession> for Session {
    fn as_mut(&mut self) -> &mut HttpSession {
        &mut self.downstream_session
    }
}

use std::ops::{Deref, DerefMut};

impl Deref for Session {
    type Target = HttpSession;

    fn deref(&self) -> &Self::Target {
        &self.downstream_session
    }
}

impl DerefMut for Session {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.downstream_session
    }
}

// generic HTTP 502 response sent when proxy_upstream_filter refuses to connect to upstream
static BAD_GATEWAY: Lazy<ResponseHeader> = Lazy::new(|| {
    let mut resp = ResponseHeader::build(http::StatusCode::BAD_GATEWAY, Some(3)).unwrap();
    resp.insert_header(header::SERVER, &SERVER_NAME[..])
        .unwrap();
    resp.insert_header(header::CONTENT_LENGTH, 0).unwrap();
    resp.insert_header(header::CACHE_CONTROL, "private, no-store")
        .unwrap();

    resp
});

impl<SV, C> HttpProxy<SV, C>
where
    C: custom::Connector,
{
    async fn process_request(
        self: &Arc<Self>,
        mut session: Session,
        mut ctx: <SV as ProxyHttp>::CTX,
    ) -> Option<ReusedHttpStream>
    where
        SV: ProxyHttp + Send + Sync + 'static,
        <SV as ProxyHttp>::CTX: Send + Sync,
    {
        if let Err(e) = self
            .inner
            .early_request_filter(&mut session, &mut ctx)
            .await
        {
            return self
                .handle_error(session, &mut ctx, e, "Fail to early filter request:")
                .await;
        }

        if self.inner.allow_spawning_subrequest(&session, &ctx) {
            session.subrequest_spawner = Some(SubrequestSpawner::new(self.clone()));
        }

        let req = session.downstream_session.req_header_mut();

        // Built-in downstream request filters go first
        if let Err(e) = session
            .downstream_modules_ctx
            .request_header_filter(req)
            .await
        {
            return self
                .handle_error(
                    session,
                    &mut ctx,
                    e,
                    "Failed in downstream modules request filter:",
                )
                .await;
        }

        match self.inner.request_filter(&mut session, &mut ctx).await {
            Ok(response_sent) => {
                if response_sent {
                    // TODO: log error
                    self.inner.logging(&mut session, None, &mut ctx).await;
                    self.cleanup_sub_req(&mut session);
                    let mut persistent_settings = HttpPersistentSettings::for_session(&session);
                    if let Some(uc) = self.inner.persist_connection_context(&session, &ctx) {
                        persistent_settings.set_user_context(uc);
                    }
                    return session
                        .downstream_session
                        .finish()
                        .await
                        .ok()
                        .flatten()
                        .map(|s| ReusedHttpStream::from_reusable_stream(s, persistent_settings));
                }
                /* else continue */
            }
            Err(e) => {
                return self
                    .handle_error(session, &mut ctx, e, "Fail to filter request:")
                    .await;
            }
        }

        if let Some((reuse, err)) = self.proxy_cache(&mut session, &mut ctx).await {
            // cache hit
            return self.finish(session, &mut ctx, reuse, err).await;
        }
        // either uncacheable, or cache miss

        // there should not be a write lock in the sub req ctx after this point
        self.cleanup_sub_req(&mut session);

        // decide if the request is allowed to go to upstream
        match self
            .inner
            .proxy_upstream_filter(&mut session, &mut ctx)
            .await
        {
            Ok(proxy_to_upstream) => {
                if !proxy_to_upstream {
                    // The hook can choose to write its own response, but if it doesn't, we respond
                    // with a generic 502
                    if session.cache.enabled() {
                        // drop the cache lock that this request may be holding onto
                        session.cache.disable(NoCacheReason::DeclinedToUpstream);
                    }
                    if session.response_written().is_none() {
                        match session.write_response_header_ref(&BAD_GATEWAY, true).await {
                            Ok(()) => {}
                            Err(e) => {
                                return self
                                    .handle_error(
                                        session,
                                        &mut ctx,
                                        e,
                                        "Error responding with Bad Gateway:",
                                    )
                                    .await;
                            }
                        }
                    }

                    return self.finish(session, &mut ctx, true, None).await;
                }
                /* else continue */
            }
            Err(e) => {
                if session.cache.enabled() {
                    session.cache.disable(NoCacheReason::InternalError);
                }

                return self
                    .handle_error(
                        session,
                        &mut ctx,
                        e,
                        "Error deciding if we should proxy to upstream:",
                    )
                    .await;
            }
        }

        let mut retries: usize = 0;

        let mut server_reuse = false;
        let mut proxy_error: Option<Box<Error>> = None;

        while retries < self.max_retries {
            retries += 1;

            let (reuse, e) = self.proxy_to_upstream(&mut session, &mut ctx).await;
            server_reuse = reuse;

            match e {
                Some(error) => {
                    let retry = error.retry();
                    // only log error that will be retried here, the final error will be logged below
                    if retry
                        && !self.inner.suppress_proxy_warn_log(
                            &session,
                            &ctx,
                            &error,
                            ProxyWarnLogContext::UpstreamRetry,
                        )
                    {
                        warn!(
                            "Fail to proxy: {}, tries: {}, retry: {}, {}",
                            error,
                            retries,
                            retry,
                            self.inner.request_summary(&session, &ctx)
                        );
                    }
                    proxy_error = Some(error);
                    if !retry {
                        break;
                    }
                }
                None => {
                    proxy_error = None;
                    break;
                }
            };
        }

        // serve stale if error
        // Check both error and cache before calling the function because await is not cheap
        // allow unwrap until if let chains
        #[allow(clippy::unnecessary_unwrap)]
        let serve_stale_result = if proxy_error.is_some() && session.cache.can_serve_stale_error() {
            self.handle_stale_if_error(&mut session, &mut ctx, proxy_error.as_ref().unwrap())
                .await
        } else {
            None
        };

        let final_error = if let Some((reuse, stale_cache_error)) = serve_stale_result {
            // don't reuse server conn if serve stale polluted it
            server_reuse = server_reuse && reuse;
            stale_cache_error
        } else {
            proxy_error
        };

        if let Some(e) = final_error.as_ref() {
            // If we have errored and are still holding a cache lock, release it.
            if session.cache.enabled() {
                let reason = if *e.esource() == ErrorSource::Upstream {
                    NoCacheReason::UpstreamError
                } else {
                    NoCacheReason::InternalError
                };
                session.cache.disable(reason);
            }
            let res = self.inner.fail_to_proxy(&mut session, e, &mut ctx).await;

            // final error will have > 0 status unless downstream connection is dead
            if !self.inner.suppress_error_log(&session, &ctx, e) {
                error!(
                    "Fail to proxy: {}, status: {}, tries: {}, retry: {}, {}",
                    e,
                    res.error_code,
                    retries,
                    false, // we never retry here
                    self.inner.request_summary(&session, &ctx),
                );
            }
        }

        // logging() will be called in finish()
        self.finish(session, &mut ctx, server_reuse, final_error)
            .await
    }

    async fn handle_error(
        &self,
        mut session: Session,
        ctx: &mut <SV as ProxyHttp>::CTX,
        e: Box<Error>,
        context: &str,
    ) -> Option<ReusedHttpStream>
    where
        SV: ProxyHttp + Send + Sync + 'static,
        <SV as ProxyHttp>::CTX: Send + Sync,
    {
        let res = self.inner.fail_to_proxy(&mut session, &e, ctx).await;
        if !self.inner.suppress_error_log(&session, ctx, &e) {
            error!(
                "{context} {}, status: {}, {}",
                e,
                res.error_code,
                self.inner.request_summary(&session, ctx)
            );
        }
        self.inner.logging(&mut session, Some(&e), ctx).await;
        self.cleanup_sub_req(&mut session);

        session.downstream_session.on_proxy_failure(e);

        if res.can_reuse_downstream {
            let mut persistent_settings = HttpPersistentSettings::for_session(&session);
            if let Some(uc) = self.inner.persist_connection_context(&session, ctx) {
                persistent_settings.set_user_context(uc);
            }
            session
                .downstream_session
                .finish()
                .await
                .ok()
                .flatten()
                .map(|s| ReusedHttpStream::from_reusable_stream(s, persistent_settings))
        } else {
            None
        }
    }
}

/* Make process_subrequest() a trait to workaround https://github.com/rust-lang/rust/issues/78649
   if process_subrequest() is implemented as a member of HttpProxy, rust complains

error[E0391]: cycle detected when computing type of `proxy_cache::<impl at pingora-proxy/src/proxy_cache.rs:7:1: 7:23>::proxy_cache::{opaque#0}`
   --> pingora-proxy/src/proxy_cache.rs:13:10
    |
13  |     ) -> Option<(bool, Option<Box<Error>>)>

*/
#[async_trait]
pub trait Subrequest {
    async fn process_subrequest(
        self: Arc<Self>,
        session: Box<HttpSession>,
        sub_req_ctx: Box<SubrequestCtx>,
    );
}

#[async_trait]
impl<SV, C> Subrequest for HttpProxy<SV, C>
where
    SV: ProxyHttp + Send + Sync + 'static,
    <SV as ProxyHttp>::CTX: Send + Sync,
    C: custom::Connector,
{
    async fn process_subrequest(
        self: Arc<Self>,
        session: Box<HttpSession>,
        sub_req_ctx: Box<SubrequestCtx>,
    ) {
        debug!("starting subrequest");

        let mut session = match self.handle_new_request(session).await {
            Some(downstream_session) => Session::new(
                downstream_session,
                &self.downstream_modules,
                #[cfg(feature = "upstream_modules")]
                &self.upstream_modules,
                self.shutdown_flag.clone(),
            ),
            None => return, // bad request
        };

        // no real downstream to keepalive, but it doesn't matter what is set here because at the end
        // of this fn the dummy connection will be dropped
        session.set_keepalive(None);

        session.subrequest_ctx.replace(sub_req_ctx);
        trace!("processing subrequest");
        let ctx = self.inner.new_ctx();
        self.process_request(session, ctx).await;
        trace!("subrequest done");
    }
}

/// A handle to the underlying HTTP proxy app that allows spawning subrequests.
pub struct SubrequestSpawner {
    app: Arc<dyn Subrequest + Send + Sync>,
}

/// A [`PreparedSubrequest`] that is ready to run.
pub struct PreparedSubrequest {
    app: Arc<dyn Subrequest + Send + Sync>,
    session: Box<HttpSession>,
    sub_req_ctx: Box<SubrequestCtx>,
}

impl PreparedSubrequest {
    pub async fn run(self) {
        self.app
            .process_subrequest(self.session, self.sub_req_ctx)
            .await
    }

    pub fn session(&self) -> &HttpSession {
        self.session.as_ref()
    }

    pub fn session_mut(&mut self) -> &mut HttpSession {
        self.session.deref_mut()
    }
}

impl SubrequestSpawner {
    /// Create a new [`SubrequestSpawner`].
    pub fn new(app: Arc<dyn Subrequest + Send + Sync>) -> SubrequestSpawner {
        SubrequestSpawner { app }
    }

    /// Spawn a background subrequest and return a join handle.
    // TODO: allow configuring the subrequest session before use
    pub fn spawn_background_subrequest(
        &self,
        session: &HttpSession,
        ctx: SubrequestCtx,
    ) -> tokio::task::JoinHandle<()> {
        let new_app = self.app.clone(); // Clone the Arc
        let (mut session, handle) = subrequest::create_session(session);
        if ctx.body_mode() == BodyMode::NoBody {
            session
                .as_subrequest_mut()
                .expect("created subrequest session")
                .clear_request_body_headers();
        }
        let sub_req_ctx = Box::new(ctx);
        handle.drain_tasks();
        tokio::spawn(async move {
            new_app
                .process_subrequest(Box::new(session), sub_req_ctx)
                .await;
        })
    }

    /// Create a subrequest that listens to `HttpTask`s sent from the returned `Sender`
    /// and sends `HttpTask`s to the returned `Receiver`.
    ///
    /// To run that subrequest, call `run()`.
    // TODO: allow configuring the subrequest session before use
    pub fn create_subrequest(
        &self,
        session: &HttpSession,
        ctx: SubrequestCtx,
    ) -> (PreparedSubrequest, SubrequestHandle) {
        let new_app = self.app.clone(); // Clone the Arc
        let (mut session, handle) = subrequest::create_session(session);
        if ctx.body_mode() == BodyMode::NoBody {
            session
                .as_subrequest_mut()
                .expect("created subrequest session")
                .clear_request_body_headers();
        }
        let sub_req_ctx = Box::new(ctx);
        (
            PreparedSubrequest {
                app: new_app,
                session: Box::new(session),
                sub_req_ctx,
            },
            handle,
        )
    }
}

#[async_trait]
impl<SV, C> HttpServerApp for HttpProxy<SV, C>
where
    SV: ProxyHttp + Send + Sync + 'static,
    <SV as ProxyHttp>::CTX: Send + Sync,
    C: custom::Connector,
{
    async fn process_new_http(
        self: &Arc<Self>,
        mut session: HttpSession,
        shutdown: &ShutdownWatch,
    ) -> Option<ReusedHttpStream> {
        // Extract user context from the previous request before the session is moved into the Box
        let prev_user_ctx = session.take_connection_user_context();

        let session = Box::new(session);

        // TODO: keepalive pool, use stack
        let mut session = match self.handle_new_request(session).await {
            Some(downstream_session) => Session::new(
                downstream_session,
                &self.downstream_modules,
                #[cfg(feature = "upstream_modules")]
                &self.upstream_modules,
                self.shutdown_flag.clone(),
            ),
            None => return None, // bad request
        };

        if *shutdown.borrow() {
            // stop downstream from reusing if this service is shutting down soon
            session.set_keepalive(None);
        }

        let mut ctx = self.inner.new_ctx();

        // Deliver user context from the previous request on this reused connection
        if let Some(prev_ctx) = prev_user_ctx {
            self.inner
                .on_connection_reuse(&mut session, &mut ctx, prev_ctx);
        }

        self.process_request(session, ctx).await
    }

    async fn http_cleanup(&self) {
        self.shutdown_flag.store(true, Ordering::Release);
        // Notify all keepalived requests blocking on read_request() to abort
        self.shutdown.notify_waiters();
    }

    fn server_options(&self) -> Option<&HttpServerOptions> {
        self.server_options.as_ref()
    }

    fn h2_options(&self) -> Option<H2Options> {
        self.h2_options.clone()
    }
    async fn process_custom_session(
        self: Arc<Self>,
        stream: Stream,
        shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        let app = self.clone();

        let Some(process_custom_session) = app.process_custom_session.as_ref() else {
            warn!("custom was called on an empty on_custom");
            return None;
        };

        process_custom_session(self.clone(), stream, shutdown).await
    }

    // TODO implement h2_options
}

use pingora_core::services::listening::{RuntimeOptsOverride, Service};

/// Create an [`HttpProxy`] without wrapping it in a [`Service`].
///
/// This is useful when you need to integrate `HttpProxy` into a custom accept loop,
/// for example when implementing SNI-based routing that decides between TLS passthrough
/// and TLS termination on a single port.
///
/// The returned `HttpProxy` is fully initialized and ready to process requests via
/// [`HttpServerApp::process_new_http()`].
///
/// # Example
///
/// ```ignore
/// use pingora_proxy::http_proxy;
/// use std::sync::Arc;
///
/// // Create the proxy
/// let proxy = Arc::new(http_proxy(&server_conf, my_proxy_app));
///
/// // In your custom accept loop:
/// loop {
///     let (stream, addr) = listener.accept().await?;
///
///     // Peek SNI, decide routing...
///     if should_terminate_tls {
///         let tls_stream = my_acceptor.accept(stream).await?;
///         let session = HttpSession::new_http1(Box::new(tls_stream));
///         proxy.process_new_http(session, &shutdown).await;
///     }
/// }
/// ```
pub fn http_proxy<SV>(conf: &Arc<ServerConf>, inner: SV) -> HttpProxy<SV>
where
    SV: ProxyHttp,
{
    let mut proxy = HttpProxy::new(inner, conf.clone());
    proxy.handle_init_modules();
    proxy
}

/// Create a [Service] from the user implemented [ProxyHttp].
///
/// The returned [Service] can be hosted by a [pingora_core::server::Server] directly.
pub fn http_proxy_service<SV>(conf: &Arc<ServerConf>, inner: SV) -> Service<HttpProxy<SV, ()>>
where
    SV: ProxyHttp,
{
    http_proxy_service_with_name(conf, inner, "Pingora HTTP Proxy Service")
}

/// Create a [Service] from the user implemented [ProxyHttp].
///
/// The returned [Service] can be hosted by a [pingora_core::server::Server] directly.
pub fn http_proxy_service_with_name<SV>(
    conf: &Arc<ServerConf>,
    inner: SV,
    name: &str,
) -> Service<HttpProxy<SV, ()>>
where
    SV: ProxyHttp,
{
    let mut proxy = HttpProxy::new(inner, conf.clone());
    proxy.handle_init_modules();
    Service::new(name.to_string(), proxy)
}

/// Create a [Service] from the user implemented [ProxyHttp].
///
/// The returned [Service] can be hosted by a [pingora_core::server::Server] directly.
pub fn http_proxy_service_with_name_custom<SV, C>(
    conf: &Arc<ServerConf>,
    inner: SV,
    name: &str,
    connector: C,
    on_custom: ProcessCustomSession<SV, C>,
) -> Service<HttpProxy<SV, C>>
where
    SV: ProxyHttp + Send + Sync + 'static,
    SV::CTX: Send + Sync + 'static,
    C: custom::Connector,
{
    let mut proxy =
        HttpProxy::new_custom(inner, conf.clone(), connector, Some(on_custom), None, None);
    proxy.handle_init_modules();

    Service::new(name.to_string(), proxy)
}

/// A builder for a [Service] that can be used to create a [HttpProxy] instance
///
/// The [ProxyServiceBuilder] can be used to construct a [HttpProxy] service with a custom name,
/// connector, and custom session handler.
///
pub struct ProxyServiceBuilder<SV, C>
where
    SV: ProxyHttp + Send + Sync + 'static,
    SV::CTX: Send + Sync + 'static,
    C: custom::Connector,
{
    conf: Arc<ServerConf>,
    inner: SV,
    name: String,
    connector: C,
    custom: Option<ProcessCustomSession<SV, C>>,
    server_options: Option<HttpServerOptions>,
    client_options: Option<ConnectorOptions>,
    runtime_opts_override: Option<RuntimeOptsOverride>,
}

impl<SV> ProxyServiceBuilder<SV, ()>
where
    SV: ProxyHttp + Send + Sync + 'static,
    SV::CTX: Send + Sync + 'static,
{
    /// Create a new [ProxyServiceBuilder] with the given [ServerConf] and [ProxyHttp]
    /// implementation.
    ///
    /// The returned builder can be used to construct a [HttpProxy] service with a custom name,
    /// connector, and custom session handler.
    ///
    /// The [ProxyServiceBuilder] will default to using the [ProxyHttp] implementation and no custom
    /// session handler.
    ///
    pub fn new(conf: &Arc<ServerConf>, inner: SV) -> Self {
        ProxyServiceBuilder {
            conf: conf.clone(),
            inner,
            name: "Pingora HTTP Proxy Service".into(),
            connector: (),
            custom: None,
            server_options: None,
            client_options: None,
            runtime_opts_override: None,
        }
    }
}

impl<SV, C> ProxyServiceBuilder<SV, C>
where
    SV: ProxyHttp + Send + Sync + 'static,
    SV::CTX: Send + Sync + 'static,
    C: custom::Connector,
{
    /// Sets the name of the [HttpProxy] service.
    pub fn name(mut self, name: impl AsRef<str>) -> Self {
        self.name = name.as_ref().to_owned();
        self
    }

    /// Set a custom connector and custom session handler for the [ProxyServiceBuilder].
    ///
    /// The custom connector is used to establish a connection to the upstream server.
    ///
    /// The custom session handler is used to handle custom protocol specific logic
    /// between the proxy and the upstream server.
    ///
    /// Returns a new [ProxyServiceBuilder] with the custom connector and session handler.
    pub fn custom<C2: custom::Connector>(
        self,
        connector: C2,
        on_custom: ProcessCustomSession<SV, C2>,
    ) -> ProxyServiceBuilder<SV, C2> {
        let Self {
            conf,
            inner,
            name,
            server_options,
            client_options,
            runtime_opts_override,
            ..
        } = self;
        ProxyServiceBuilder {
            conf,
            inner,
            name,
            connector,
            custom: Some(on_custom),
            server_options,
            client_options,
            runtime_opts_override,
        }
    }

    /// Set the upstream client connector options for the [ProxyServiceBuilder].
    ///
    /// Returns a new [ProxyServiceBuilder] with the upstream client connector options set.
    pub fn client_options(mut self, options: ConnectorOptions) -> Self {
        self.client_options = Some(options);
        self
    }

    /// Set the server options for the [ProxyServiceBuilder].
    ///
    /// Returns a new [ProxyServiceBuilder] with the server options set.
    pub fn server_options(mut self, options: HttpServerOptions) -> Self {
        self.server_options = Some(options);
        self
    }

    /// Set a runtime options override for the [Service] built by this builder.
    ///
    /// Returning [`None`] from the override uses the global runtime options.
    pub fn runtime_opts_override<F>(mut self, override_fn: F) -> Self
    where
        F: Fn(&RuntimeOpts) -> Option<RuntimeOpts> + Send + Sync + 'static,
    {
        self.runtime_opts_override = Some(Arc::new(override_fn));
        self
    }

    /// Builds a new [Service] from the [ProxyServiceBuilder].
    ///
    /// This function takes ownership of the [ProxyServiceBuilder] and returns a new [Service] with
    /// a fully initialized [HttpProxy].
    ///
    /// The returned [Service] is ready to be used by a [pingora_core::server::Server].
    pub fn build(self) -> Service<HttpProxy<SV, C>> {
        let Self {
            conf,
            inner,
            name,
            connector,
            custom,
            server_options,
            client_options,
            runtime_opts_override,
        } = self;

        let mut proxy = HttpProxy::new_custom(
            inner,
            conf,
            connector,
            custom,
            server_options,
            client_options,
        );

        proxy.handle_init_modules();
        let mut service = Service::new(name, proxy);
        if let Some(runtime_opts_override) = runtime_opts_override {
            service.set_runtime_opts_override(runtime_opts_override);
        }
        service
    }
}

#[cfg(test)]
mod session_state_tests {
    use super::*;

    fn mock_session() -> Session {
        // No queued IO actions: this test only exercises Session state flags and
        // never reads/writes the stream (tokio-test panics on unconsumed actions).
        let mock_io = tokio_test::io::Builder::new().build();
        Session::new_h1(Box::new(mock_io) as pingora_core::protocols::Stream)
    }

    /// streamscope sink mode: `set_hold_response_header` (called for every
    /// response once a RESPMOD-style filter is configured) must clear the
    /// early-finish flag so a reused connection never leaks sink state.
    #[tokio::test]
    async fn set_hold_response_header_resets_early_finish_state() {
        let mut session = mock_session();
        assert!(!session.downstream_finished_early());

        session.downstream_finished_early = true;
        session.set_hold_response_header(false);
        assert!(!session.downstream_finished_early());

        session.downstream_finished_early = true;
        session.set_hold_response_header(true);
        assert!(!session.downstream_finished_early());
    }
}
