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

use futures::future::OptionFuture;
use futures::StreamExt;

use super::*;
use crate::proxy_cache::{range_filter::RangeBodyFilter, ServeFromCache};
use crate::proxy_common::*;
use http::{header::CONTENT_LENGTH, Method, StatusCode};
use pingora_cache::CachePhase;
use pingora_core::protocols::http::authority::{
    raw_target_authority, validate_request_authority, RawTargetAuthority,
};
use pingora_core::protocols::http::custom::CUSTOM_MESSAGE_QUEUE_SIZE;
use pingora_core::protocols::http::v2::{client::Http2Session, write_body};

/// Derive H2 `:path`, separating H1 absolute-form components ([RFC 9113 section 8.3.1]).
///
/// Reclassifies after filters and rejects non-UTF-8 or ambiguous targets.
///
/// [RFC 9113 section 8.3.1]: https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3.1
fn h2_path_and_query(header: &RequestHeader) -> Result<http::uri::PathAndQuery> {
    let target = header.raw_path();
    if !header.raw_path_is_utf8() {
        return Error::e_explain(
            InvalidHTTPHeader,
            "non-UTF-8 request target cannot be forwarded over HTTP/2",
        );
    }
    let Some(uri_path_and_query) = header.uri.path_and_query() else {
        return Ok(http::uri::PathAndQuery::from_static("/"));
    };
    // Preserve origin-form and the server-wide `OPTIONS *` asterisk-form (RFC 9112 section 3.2.4).
    // https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2.4
    if target.starts_with(b"/") || target == b"*" {
        return Ok(uri_path_and_query.clone());
    }

    // Origin-form and asterisk-form returned above; classify the remainder to extract an H1
    // absolute-form path/query or reject ambiguous authority syntax.
    let absolute_path_and_query = match raw_target_authority(target) {
        RawTargetAuthority::None => return Ok(uri_path_and_query.clone()),
        RawTargetAuthority::AmbiguousAuthority => {
            return Error::e_explain(
                InvalidHTTPHeader,
                "ambiguous HTTP absolute-form request target",
            )
        }
        RawTargetAuthority::Absolute { path_and_query, .. } => path_and_query,
    };
    if absolute_path_and_query.is_empty() {
        return Ok(http::uri::PathAndQuery::from_static("/"));
    }
    if absolute_path_and_query.first() == Some(&b'?') {
        let mut origin_form = Vec::with_capacity(absolute_path_and_query.len() + 1);
        origin_form.push(b'/');
        origin_form.extend_from_slice(absolute_path_and_query);
        return http::uri::PathAndQuery::try_from(origin_form).or_err(
            InvalidHTTPHeader,
            "invalid query in absolute-form request target",
        );
    }
    http::uri::PathAndQuery::try_from(absolute_path_and_query).or_err(
        InvalidHTTPHeader,
        "invalid path in absolute-form request target",
    )
}

fn update_h2_scheme_authority(
    header: &mut RequestHeader,
    raw_host: &[u8],
    tls: bool,
    path_and_query: http::uri::PathAndQuery,
) -> Result<()> {
    let authority = http::uri::Authority::try_from(raw_host).map_err(|cause| {
        Error::because(
            InvalidHTTPHeader,
            format!("invalid authority from Host {raw_host:?}"),
            cause,
        )
    })?;
    // Last guard before this authority is serialized on the wire.
    if authority.as_str().contains('@') {
        return Error::e_explain(InvalidHTTPHeader, "userinfo in Host header");
    }

    let scheme = if tls { "https" } else { "http" };
    let uri = http::uri::Builder::new()
        .scheme(scheme)
        .authority(authority)
        .path_and_query(path_and_query)
        .build();
    match uri {
        Ok(uri) => {
            header.set_uri(uri);
            Ok(())
        }
        Err(_) => Error::e_explain(
            InvalidHTTPHeader,
            format!("failed to build H2 URI from Host {raw_host:?}"),
        ),
    }
}

impl<SV, C, DS> HttpProxy<SV, C, DS>
where
    C: custom::Connector,
    DS: DownstreamSession,
{
    pub(crate) async fn proxy_down_to_up(
        &self,
        session: &mut Session<DS>,
        client_session: &mut Http2Session,
        peer: &HttpPeer,
        ctx: &mut <SV as ProxyHttp<DS>>::CTX,
    ) -> (bool, Option<Box<Error>>)
    // (reuse_server, error)
    where
        SV: ProxyHttp<DS> + Send + Sync,
        <SV as ProxyHttp<DS>>::CTX: Send + Sync,
    {
        let mut req = session.req_header().clone();
        let authority_policy = AuthorityPolicy::from(session.downstream_session.is_custom());

        // A patched HTTP/1 parser can preserve non-UTF-8 request-target bytes, but `http::Uri`,
        // which the H2 client API requires, cannot represent them. Reject client input as a
        // downstream error before a filter has a chance to mutate the target. This wire-format
        // constraint applies to both standard and custom downstream authority policies.
        if !req.raw_path_is_utf8() {
            let e = Error::explain(
                InvalidHTTPHeader,
                "non-UTF-8 request target cannot be forwarded over HTTP/2",
            );
            return (false, Some(e.into_down()));
        }

        if req.version != Version::HTTP_2 || authority_policy.is_custom() {
            if let Err(e) =
                sanitize_h2_upstream_request(&mut req, peer.options.http_upstream_request_policy)
            {
                return (false, Some(e.into_down()));
            }
            /* remove H1 specific headers */
            // https://github.com/hyperium/h2/blob/d3b9f1e36aadc1a7a6804e2f8e86d3fe4a244b4f/src/proto/streams/send.rs#L72
            req.remove_header(&http::header::TRANSFER_ENCODING);
            req.remove_header(&http::header::CONNECTION);
            req.remove_header(&http::header::UPGRADE);
            req.remove_header(KEEP_ALIVE);
            req.remove_header(PROXY_CONNECTION);
        }

        /* turn it into h2 */
        req.set_version(Version::HTTP_2);

        if session.cache.enabled() {
            pingora_cache::filters::upstream::request_filter(
                &mut req,
                session.cache.maybe_cache_meta(),
            );
            session.mark_upstream_headers_mutated_for_cache();
        }

        match self
            .inner
            .upstream_request_filter(session, &mut req, ctx)
            .await
        {
            Ok(_) => { /* continue */ }
            Err(e) => {
                return (false, Some(e));
            }
        }

        if authority_policy.is_standard() {
            if let Err(e) = reconcile_upstream_authority(&mut req) {
                return (false, Some(e.into_in()));
            }
            if let Err(e) = validate_request_authority(&req) {
                // The final filter-produced request is invalid, so classify this as internal.
                return (false, Some(e.into_in()));
            }
        }

        // A Host-less H1 absolute-form request still needs H2 :authority. Copy its raw target
        // authority into local storage without inserting a temporary Host header.
        let raw_authority =
            if req.headers.get(http::header::HOST).is_none() && authority_policy.is_standard() {
                raw_target_authority(req.raw_path())
                    .authority()
                    .map(<[u8]>::to_owned)
            } else {
                None
            };
        if req.headers.get(http::header::HOST).is_none()
            && req.uri.authority().is_none()
            && raw_authority.is_none()
        {
            // The final filter-produced request has no authority source.
            let e = Error::explain(InvalidHTTPHeader, "no authority for H2 upstream request");
            return (false, Some(e.into_in()));
        }

        // Run for every request, including Host-less HTTP/1.0, before conversion to
        // `http::request::Parts` discards RequestHeader's raw byte fallback. A failure here after
        // the initial check was produced by a filter and is therefore internal.
        let path_and_query = match h2_path_and_query(&req) {
            Ok(path_and_query) => path_and_query,
            Err(e) => return (false, Some(e.into_in())),
        };

        // Remove H1 `Host` header, save it in order to add to :authority
        // We do this because certain H2 servers expect request not to have a host header.
        // The `Host` is removed after the upstream filters above for 2 reasons
        // 1. there is no API to change the :authority header
        // 2. the filter code needs to be aware of the host vs :authority across http versions otherwise
        let host = req.remove_header(&http::header::HOST);

        session.upstream_compression.request_filter(&req);
        let body_empty = session.as_mut().is_body_empty();

        // whether we support sending END_STREAM on HEADERS if body is empty
        let send_end_stream = req.send_end_stream().expect("req must be h2");

        // Host is consumed locally to build :authority and is never sent on the H2 wire.
        let authority = host
            .as_ref()
            .map(|host| host.as_bytes())
            .or(raw_authority.as_deref());
        if let Some(authority) = authority {
            if let Err(e) =
                update_h2_scheme_authority(&mut req, authority, peer.is_tls(), path_and_query)
            {
                return (false, Some(e));
            }
        }

        let req: http::request::Parts = req.into();

        debug!("Request to h2: {req:?}");

        // send END_STREAM on HEADERS
        let send_header_eos = send_end_stream && body_empty;
        debug!("send END_STREAM on HEADERS: {send_end_stream}");

        let req = Box::new(RequestHeader::from(req));
        if let Err(e) = client_session.write_request_header(req, send_header_eos) {
            return (false, Some(e.into_up()));
        }

        if !send_end_stream && body_empty {
            // send END_STREAM on empty DATA frame
            match client_session.write_request_body(Bytes::new(), true).await {
                Ok(()) => debug!("sent empty DATA frame to h2"),
                Err(e) => {
                    return (false, Some(e.into_up()));
                }
            }
        }

        client_session.read_timeout = peer.options.read_timeout;

        let mut downstream_custom_message_writer = session
            .downstream_session
            .as_custom_mut()
            .and_then(|c| c.take_custom_message_writer());
        // Keep the reader in this caller so it is restored even if retryable
        // upstream errors make try_join! cancel the downstream future.
        let mut downstream_custom_message_reader = match session
            .take_downstream_custom_message_reader(&mut downstream_custom_message_writer)
        {
            Ok(reader) => reader,
            Err(e) => return (false, Some(e)),
        };

        // take the body writer out of the client for easy duplex
        let mut client_body = client_session
            .take_request_body_writer()
            .expect("already send request header");

        // need to get the write_timeout here since we pass the h2 SendStream
        // directly to bidirection_down_to_up
        let write_timeout = peer.options.write_timeout;

        let (tx, rx) = mpsc::channel::<HttpTask>(TASK_BUFFER_SIZE);

        session.as_mut().enable_retry_buffering();

        // Shared signal so the upstream half can distinguish an expected task-pipe
        // closure (the downstream half finished and dropped rx) from an unexpected one.
        let pipe_state = Arc::new(AtomicU8::new(PipeState::Active as u8));
        // Only a request whose body is still to be sent can renew a read timeout.
        let progress =
            (!body_empty && client_session.read_timeout.is_some()).then(RequestBodyProgress::new);

        /* read downstream body and upstream response at the same time */

        let ret = tokio::try_join!(
            self.bidirection_down_to_up(
                session,
                &mut client_body,
                rx,
                ctx,
                write_timeout,
                &mut downstream_custom_message_writer,
                &mut downstream_custom_message_reader,
                pipe_state.clone(),
                progress.as_ref(),
                body_empty,
            ),
            pipe_up_to_down_response(client_session, tx, pipe_state, progress.as_ref())
        );

        if let Some(custom_session) = session.downstream_session.as_custom_mut() {
            if let Some(downstream_custom_message_writer) = downstream_custom_message_writer {
                match custom_session.restore_custom_message_writer(downstream_custom_message_writer)
                {
                    Ok(_) => { /* continue */ }
                    Err(e) => {
                        return (false, Some(e));
                    }
                }
            }
            if let Some(downstream_custom_message_reader) = downstream_custom_message_reader {
                match custom_session.restore_custom_message_reader(downstream_custom_message_reader)
                {
                    Ok(_) => { /* continue */ }
                    Err(e) => {
                        return (false, Some(e));
                    }
                }
            }
        }

        match ret {
            Ok((downstream_can_reuse, _upstream)) => (downstream_can_reuse, None),
            Err(e) => {
                let upstream_read_timeout =
                    e.esource == ErrorSource::Upstream && matches!(e.etype, ReadTimedout);
                let downstream_error = e.esource == ErrorSource::Downstream;
                // On application level upstream read timeouts, send RST_STREAM CANCEL,
                // we know we have not received END_STREAM at this point since we read timed out.
                // Also cancel the upstream stream when downstream goes away/resets so the
                // upstream peer can release the stream promptly.
                // TODO: implement for write timeouts?
                if upstream_read_timeout || downstream_error {
                    client_body.send_reset(h2::Reason::CANCEL);
                    if upstream_read_timeout {
                        // Mark the underlying H2 connection for shutdown so it's not used
                        // for new streams in case it is hung.
                        client_session.conn.mark_shutdown();
                    }
                }
                (false, Some(e))
            }
        }
    }

    pub(crate) async fn proxy_to_h2_upstream(
        &self,
        session: &mut Session<DS>,
        client_session: &mut Http2Session,
        reused: bool,
        peer: &HttpPeer,
        ctx: &mut <SV as ProxyHttp<DS>>::CTX,
    ) -> (bool, Option<Box<Error>>)
    where
        SV: ProxyHttp<DS> + Send + Sync,
        <SV as ProxyHttp<DS>>::CTX: Send + Sync,
    {
        #[cfg(windows)]
        let raw = client_session.fd() as std::os::windows::io::RawSocket;
        #[cfg(unix)]
        let raw = client_session.fd();

        if let Err(e) = self
            .inner
            .connected_to_upstream(session, reused, peer, raw, client_session.digest(), ctx)
            .await
        {
            return (false, Some(e));
        }

        let (server_session_reuse, error) = self
            .proxy_down_to_up(session, client_session, peer, ctx)
            .await;

        // Record upstream response body bytes received (HTTP/2 DATA payload).
        let upstream_bytes_total = client_session.body_bytes_received();
        session.set_upstream_body_bytes_received(upstream_bytes_total);

        // Note: upstream_write_pending_time is not tracked for HTTP/2 (multiplexed streams).

        (server_session_reuse, error)
    }

    #[allow(clippy::too_many_arguments)]
    async fn process_upstream_tasks_h2(
        &self,
        session: &mut Session<DS>,
        ctx: &mut <SV as ProxyHttp<DS>>::CTX,
        initial_task: HttpTask,
        rx: &mut mpsc::Receiver<HttpTask>,
        serve_from_cache: &mut ServeFromCache,
        range_body_filter: &mut proxy_cache::range_filter::RangeBodyFilter,
        response_state: &mut ResponseStateMachine,
    ) -> Result<Option<bool>>
    where
        SV: ProxyHttp<DS> + Send + Sync,
        <SV as ProxyHttp<DS>>::CTX: Send + Sync,
    {
        if serve_from_cache.should_discard_upstream() {
            // Serving the cached response and discarding the upstream one; nothing
            // is written downstream this round, so return None and let the caller
            // continue.
            return Ok(None);
        }

        // Batch: pull as many tasks as we can from rx
        let mut tasks = Vec::with_capacity(TASK_BUFFER_SIZE);
        tasks.push(initial_task);
        // tokio::task::unconstrained because now_or_never may yield None when the future is ready
        while let Some(maybe_task) = tokio::task::unconstrained(rx.recv()).now_or_never() {
            if let Some(t) = maybe_task {
                tasks.push(t);
            } else {
                break; // upstream closed
            }
        }

        /* run filters before sending to downstream */
        let mut filtered_tasks = Vec::with_capacity(TASK_BUFFER_SIZE);
        for mut t in tasks {
            if self.revalidate_or_stale(session, &mut t, ctx).await {
                serve_from_cache.enable();
                response_state.enable_cached_response();
                // skip downstream filtering entirely as the 304 will not be sent
                break;
            }
            #[cfg(feature = "upstream_modules")]
            if let HttpTask::Header(header, end_of_stream) = &t {
                self.inner
                    .adjust_upstream_modules(session, header, *end_of_stream, ctx)
                    .await?;
            }
            #[cfg(feature = "upstream_modules")]
            session.upstream_modules_filter_task(&mut t).await?;
            session.upstream_compression.response_filter(&mut t);
            // check error and abort
            // otherwise the error is surfaced via write_response_tasks()
            if !serve_from_cache.should_send_to_downstream() {
                if let HttpTask::Failed(e) = t {
                    return Err(e);
                }
            }
            // streamscope: `ahead` is how the trailer arm writes a body it ended (see
            // `h2_response_filter`) before the trailer block that ended it.
            let filtered = self
                .h2_response_filter(
                    session,
                    t,
                    ctx,
                    serve_from_cache,
                    range_body_filter,
                    false,
                    &mut filtered_tasks,
                )
                .await?;
            filtered_tasks.push(filtered);
            if serve_from_cache.is_miss_header() {
                response_state.enable_cached_response();
            }
        }

        if !serve_from_cache.should_send_to_downstream() {
            // TODO: need to derive response_done from filtered_tasks in case downstream failed already
            return Ok(None);
        }

        // streamscope sink mode: the downstream response was finished early
        // (`Session::finish_downstream_response_early`, END_STREAM already sent).
        // The tasks above already ran through all filters so the app keeps
        // accumulating the upstream body; write nothing further downstream.
        // Upstream failures still abort (checked before `is_end`, which is also
        // true for `Failed`); the response is done at upstream end-of-stream.
        if session.downstream_finished_early() {
            let mut response_done = false;
            for t in filtered_tasks {
                if let HttpTask::Failed(e) = t {
                    return Err(e);
                }
                response_done |= t.is_end();
            }
            return Ok(Some(response_done));
        }

        // streamscope RESPMOD: hold the response header until the body is inspected
        // (no-op unless a response_filter requested it). Must run just before the
        // write, so the body filter has already set any override header this batch.
        session.handle_held_response_header(&mut filtered_tasks);

        let response_done = session.write_response_tasks(filtered_tasks).await?;

        Ok(Some(response_done))
    }

    // returns whether server (downstream) session can be reused
    #[allow(clippy::too_many_arguments)]
    async fn bidirection_down_to_up(
        &self,
        session: &mut Session<DS>,
        client_body: &mut h2::SendStream<bytes::Bytes>,
        mut rx: mpsc::Receiver<HttpTask>,
        ctx: &mut <SV as ProxyHttp<DS>>::CTX,
        write_timeout: Option<Duration>,
        downstream_custom_message_writer: &mut Option<Box<dyn CustomMessageWrite>>,
        downstream_custom_message_reader: &mut Option<
            Box<dyn futures::Stream<Item = Result<Bytes>> + Unpin + Send + Sync + 'static>,
        >,
        pipe_state: Arc<AtomicU8>,
        progress: Option<&RequestBodyProgress>,
        header_ended_stream: bool,
    ) -> Result<bool>
    where
        SV: ProxyHttp<DS> + Send + Sync,
        <SV as ProxyHttp<DS>>::CTX: Send + Sync,
    {
        // setup custom message forwarding, if downstream supports it
        let (
            mut downstream_custom_read,
            mut downstream_custom_write,
            downstream_custom_message_custom_forwarding,
            mut downstream_custom_message_inject_rx,
        ) = if downstream_custom_message_writer.is_some() {
            let (inject_tx, inject_rx) = mpsc::channel::<Bytes>(CUSTOM_MESSAGE_QUEUE_SIZE);
            (true, true, Some(inject_tx), Some(inject_rx))
        } else {
            (false, false, None, None)
        };

        if let Some(custom_forwarding) = downstream_custom_message_custom_forwarding {
            // Custom handles are owned by the caller so an early error here still
            // lets the caller restore them before retrying another upstream.
            self.inner
                .custom_forwarding(session, ctx, None, custom_forwarding)
                .await?;
        }

        let mut downstream_state = DownstreamStateMachine::new(session.as_mut().is_body_done());

        let buffer = session.as_mut().get_retry_buffer();

        // A body a filter already CONSUMED — a proxy that adapts a WHOLE request before
        // forwarding it, the ICAP REQMOD ordering `proxy_h1`'s pre-loop also serves. The
        // select loop never polls a downstream reader that is already finished, so the
        // filters get their one end-of-stream call here, and what they release is
        // written by the loop below, one flow-control grant at a time beside the
        // response — never in one write here, where a large release would hold the
        // response pipe, renew no read timeout and turn an early answer into an error.
        //
        // Not a body whose END_STREAM already went out (`header_ended_stream`: on the
        // request HEADERS or on an empty DATA frame — DATA after it is a stream error),
        // nor one a previous attempt consumed and the retry buffer could not keep: that
        // body is lost, and ending the stream would forward it as complete and empty.
        // A body the client cut short is the consuming filter's to refuse — its read
        // returned the error — as on `proxy_h1`: what the filter releases is what goes.
        let consumed = buffer.is_none()
            && !header_ended_stream
            && downstream_state.is_done()
            && !session.as_ref().retry_buffer_truncated();
        let mut release: Option<Bytes> = None;
        if consumed {
            let mut data = None;
            session
                .downstream_modules_ctx
                .request_body_filter(&mut data, true)
                .await?;
            self.inner
                .request_body_filter(session, &mut data, true, ctx)
                .await?;
            release = Some(data.unwrap_or_default());
        }

        // retry, send buffer if it exists
        if let Some(buffer) = buffer {
            self.send_body_to2(
                session,
                Some(buffer),
                downstream_state.is_done(),
                client_body,
                ctx,
                write_timeout,
                progress,
            )
            .await?;
        }

        let mut response_state = ResponseStateMachine::new();

        // these two below can be wrapped into an internal ctx
        // use cache when upstream revalidates (or TODO: error)
        let mut serve_from_cache = ServeFromCache::new();
        let mut range_body_filter = proxy_cache::range_filter::RangeBodyFilter::new();

        let mut next_upstream_task: Option<HttpTask> = None;

        /* duplex mode
         * see the Same function for h1 for more comments
         */
        while !downstream_state.is_done()
            || !response_state.is_done()
            || downstream_custom_read && !downstream_state.is_errored()
            || downstream_custom_write
        {
            // Use optional futures to allow using optional channels in select branches
            let custom_inject_rx_recv: OptionFuture<_> = downstream_custom_message_inject_rx
                .as_mut()
                .map(|rx| rx.recv())
                .into();
            let custom_reader_next: OptionFuture<_> = downstream_custom_message_reader
                .as_mut()
                .map(|reader| reader.next())
                .into();

            // partial read support, this check will also be false if cache is disabled.
            let support_cache_partial_read =
                session.cache.support_streaming_partial_write() == Some(true);
            let upgraded = session.was_upgraded();

            // Similar logic in h1 need to reserve capacity first to avoid deadlock
            // But we don't need to do the same because the h2 client_body pipe is unbounded (never block)
            tokio::select! {
                // NOTE: cannot avoid this copy since h2 owns the buf
                body = session.downstream_session.read_body_or_idle(downstream_state.is_done()), if downstream_state.can_poll() => {
                    debug!("downstream event");
                    let body = match body {
                        Ok(b) => b,
                        Err(e) => {
                            let wait_for_cache_fill = (!serve_from_cache.is_on() && support_cache_partial_read)
                                || serve_from_cache.is_miss();
                            // streamscope sink mode: the client already received its
                            // (synthetic, early-finished) response — a downstream
                            // RST_STREAM/cancel must not abort the upstream drain.
                            // Same continuation as the cache-fill branch.
                            let early_finished = session.downstream_finished_early();
                            if wait_for_cache_fill || early_finished {
                                // ignore downstream error so that upstream can continue to write cache
                                downstream_state.to_errored();
                                let log_ctx = if early_finished {
                                    ProxyWarnLogContext::DownstreamEarlyFinish
                                } else {
                                    ProxyWarnLogContext::DownstreamCache
                                };
                                if !self.inner.suppress_proxy_warn_log(
                                    session,
                                    ctx,
                                    &e,
                                    log_ctx,
                                ) {
                                    if early_finished {
                                        // Expected: the stream already ended with
                                        // END_STREAM; the client leaving is normal.
                                        debug!(
                                            "Downstream closed after early finish; draining upstream: {}, {}",
                                            e,
                                            self.inner.request_summary(session, ctx)
                                        );
                                    } else {
                                        warn!(
                                            "Downstream Error ignored during caching: {}, {}",
                                            e,
                                            self.inner.request_summary(session, ctx)
                                        );
                                    }
                                }
                                // This will not be treated as a final error, but we should signal to
                                // downstream session regardless
                                session.downstream_session.on_proxy_failure(e);
                                continue;
                           } else {
                                return Err(e.into_down());
                           }
                        }
                    };
                    let is_body_done = session.is_body_done();
                    match self.send_body_to2(session, body, is_body_done, client_body, ctx, write_timeout, progress).await {
                        Ok(request_done) =>  {
                            downstream_state.maybe_finished(request_done);
                        },
                        Err(e) if e.esource == ErrorSource::Downstream => {
                            // Downstream reset/errored while the upstream write was blocked
                            // (e.g. on upstream flow control). Same policy as the read error
                            // handling above: ignore the downstream error if the upstream
                            // response is being admitted to cache, otherwise fail so the
                            // downstream stream handles are dropped promptly.
                            let wait_for_cache_fill = (!serve_from_cache.is_on() && support_cache_partial_read)
                                || serve_from_cache.is_miss();
                            if !wait_for_cache_fill {
                                return Err(e);
                            }
                            // ignore downstream error so that upstream can continue to write cache
                            downstream_state.to_errored();
                            if !self.inner.suppress_proxy_warn_log(
                                session,
                                ctx,
                                &e,
                                ProxyWarnLogContext::DownstreamCache,
                            ) {
                                warn!(
                                    "Downstream Error ignored during caching: {}, {}",
                                    e,
                                    self.inner.request_summary(session, ctx)
                                );
                            }
                            // This will not be treated as a final error, but we should signal to
                            // downstream session anyway.
                            session.downstream_session.on_proxy_failure(e);
                        },
                        Err(e) => {
                            // mark request done, attempt to drain receive
                            warn!("Upstream h2 body send error: {e}");
                            // upstream is what actually errored but we don't want to continue
                            // polling the downstream body
                            downstream_state.to_errored();
                        }
                    };
                },

                // A consumed body's release: one flow-control grant per iteration, so the
                // response keeps flowing beside it and every grant the upstream accepted
                // renews the read timeout. A failed write is handled as the body read's is
                // above: the request is done, and the response is still drained.
                released = release_one_grant(client_body, &mut release, write_timeout), if release.is_some() => {
                    match released {
                        Ok(ended) => {
                            if let Some(progress) = progress {
                                progress.accepted();
                            }
                            if ended {
                                release = None;
                            }
                        }
                        Err(e) => {
                            warn!("Upstream h2 body send error: {e}");
                            release = None;
                            downstream_state.to_errored();
                        }
                    }
                },

                // Handle buffered upstream task from previous iteration
                task = async { next_upstream_task.take() }, if next_upstream_task.is_some() => {
                    debug!("buffered upstream event: {:?}", task);
                    if let Some(t) = task {
                        let Some(response_done) = self.process_upstream_tasks_h2(
                            session,
                            ctx,
                            t,
                            &mut rx,
                            &mut serve_from_cache,
                            &mut range_body_filter,
                            &mut response_state,
                        ).await? else {
                            // nothing sent downstream e.g. serve_from_cache
                            continue;
                        };
                        if session.was_upgraded() {
                            return Error::e_explain(H2Error, "upgraded while proxying to h2 session");
                        }
                        response_state.maybe_set_upstream_done(response_done);
                    } else {
                        debug!("empty upstream event");
                        response_state.maybe_set_upstream_done(true);
                    }
                },

                task = rx.recv(), if !response_state.upstream_done() && next_upstream_task.is_none() => {
                    debug!("upstream event: {:?}", task);
                    if let Some(t) = task {
                        let Some(response_done) = self.process_upstream_tasks_h2(
                            session,
                            ctx,
                            t,
                            &mut rx,
                            &mut serve_from_cache,
                            &mut range_body_filter,
                            &mut response_state,
                        ).await? else {
                            // nothing sent downstream e.g. serve_from_cache
                            continue;
                        };
                        if session.was_upgraded() {
                            // it is very weird if the downstream session decides to upgrade
                            // since the client h2 session cannot, return an error on this case
                            return Error::e_explain(H2Error, "upgraded while proxying to h2 session");
                        }
                        response_state.maybe_set_upstream_done(response_done);
                    } else {
                        debug!("empty upstream event");
                        response_state.maybe_set_upstream_done(true);
                    }
                },

                task = serve_from_cache.next_http_task(&mut session.cache, &mut range_body_filter, upgraded),
                    if !response_state.cached_done()
                        && !downstream_state.is_errored()
                        && serve_from_cache.is_on()
                        && !session.has_pending_downstream_tasks() => { // backpressure: don't queue if pending writes

                    // streamscope: `ahead` carries a body the trailer arm ended, which
                    // goes out before the task that ended it. A cached response replays
                    // no trailers, so this stays empty — it is passed, not assumed empty.
                    let mut tasks = Vec::with_capacity(1);
                    let task = self.h2_response_filter(session, task?, ctx,
                        &mut serve_from_cache,
                        &mut range_body_filter, true, &mut tasks).await?;
                    debug!("serve_from_cache task {task:?}");
                    tasks.push(task);

                    if session.downstream_session.supports_proxy_task_api() {
                        for task in tasks {
                            session.send_downstream_proxy_task(task).await?;
                        }
                    } else {
                        match session.write_response_tasks(tasks).await {
                            Ok(b) => response_state.maybe_set_cache_done(b),
                            Err(e) => if serve_from_cache.is_miss() {
                                // give up writing to downstream but wait for upstream cache write to finish
                                downstream_state.to_errored();
                                response_state.maybe_set_cache_done(true);
                                if !self.inner.suppress_proxy_warn_log(
                                    session,
                                    ctx,
                                    &e,
                                    ProxyWarnLogContext::DownstreamCache,
                                ) {
                                    warn!(
                                        "Downstream Error ignored during caching: {}, {}",
                                        e,
                                        self.inner.request_summary(session, ctx)
                                    );
                                }
                                // This will not be treated as a final error, but we should signal to
                                // downstream session regardless
                                session.downstream_session.on_proxy_failure(e);
                                continue;
                            } else {
                                return Err(e);
                            }
                        }
                        // A storage error can disable cache between cached_done
                        // being set and here; see the same guard in proxy_h1.rs.
                        if response_state.cached_done() && session.cache.enabled() {
                            if let Err(e) = session.cache.finish_hit_handler().await {
                                warn!("Error during finish_hit_handler: {}", e);
                            }
                        }
                    }
                }

                // Write queued downstream proxy tasks while also polling for upstream tasks.
                // This allows cache writes to continue even when downstream is stalled.
                //
                // "Gate" branch: ready(()) resolves immediately, so the guard controls
                // whether we enter. This is not a busy-loop because every path through
                // the inner select either (a) drains all pending tasks via
                // write_downstream_proxy_tasks (making the guard false), (b) observes a
                // downstream write error (making downstream_state errored and the guard false),
                // (c) stores an upstream task in next_upstream_task (making the guard false), or
                // (d) blocks on real I/O inside the nested select.
                _ = std::future::ready(()),
                    if !downstream_state.is_errored()
                        && session.has_pending_downstream_tasks()
                        && next_upstream_task.is_none() => {
                    tokio::select! {
                        // Try to write downstream proxy tasks (cancel-safe)
                        write_result = session.write_downstream_proxy_tasks() => {
                            match write_result {
                                Ok(end) => {
                                    response_state.maybe_set_cache_done(end);
                                    // See disabled() guard comment above.
                                    // See enabled() guard comment above.
                                    if response_state.cached_done() && session.cache.enabled() {
                                        if let Err(e) = session.cache.finish_hit_handler().await {
                                            warn!("Error during finish_hit_handler: {}", e);
                                        }
                                    }
                                }
                                Err(e) => if serve_from_cache.is_miss() {
                                    // give up writing to downstream but wait for upstream cache write to finish
                                    downstream_state.to_errored();
                                    response_state.maybe_set_cache_done(true);
                                    if !self.inner.suppress_proxy_warn_log(
                                        session,
                                        ctx,
                                        &e,
                                        ProxyWarnLogContext::DownstreamCache,
                                    ) {
                                        warn!(
                                            "Downstream write error ignored during caching: {}, {}",
                                            e,
                                            self.inner.request_summary(session, ctx)
                                        );
                                    }
                                    session.downstream_session.on_proxy_failure(e);
                                } else {
                                    return Err(e);
                                }
                            }
                        }

                        // Also poll for upstream tasks - if we get one, cancel the write and handle it.
                        upstream_task = rx.recv(), if !response_state.upstream_done() && serve_from_cache.is_on() && next_upstream_task.is_none() => {
                            if let Some(t) = upstream_task {
                                next_upstream_task = Some(t);
                                continue;
                            } else {
                                response_state.maybe_set_upstream_done(true);
                            }
                        }
                    }
                }
                data = custom_reader_next, if downstream_custom_read && !downstream_state.is_errored()  => {
                    let Some(data) = data.flatten() else {

                        downstream_custom_read = false;
                        continue;
                    };

                    let data = match data {
                        Ok(data) => data,
                        Err(err) =>  {
                            warn!("downstream_custom_message_reader got error: {err}");
                            downstream_custom_read = false;
                            continue;
                        },
                    };

                    self.inner
                        .downstream_custom_message_proxy_filter(session, data, ctx, true) // true, because it's the last hop for downstream proxying
                        .await?;
                },

                data = custom_inject_rx_recv, if downstream_custom_write => {
                    match data.flatten() {
                        Some(data) => {
                            if let Some(ref mut custom_writer) = downstream_custom_message_writer {
                                custom_writer.write_custom_message(data).await?
                            }
                        },
                        None => {
                            downstream_custom_write = false;
                            if let Some(ref mut custom_writer) = downstream_custom_message_writer {
                                custom_writer.finish_custom().await?;
                            }
                        },
                    }
                },

                else => {
                    break;
                }
            }
        }

        // streamscope sink mode: the early-finished synthetic response already
        // ended this h2 stream (END_STREAM); don't run the finish tail again.
        // Sibling streams on the connection are unaffected.
        let mut reuse_downstream =
            !downstream_state.is_errored() && !session.downstream_finished_early();
        if reuse_downstream {
            match session.as_mut().finish_body().await {
                Ok(_) => {
                    debug!("finished sending body to downstream");
                }
                Err(e) => {
                    error!("Error finish sending body to downstream: {}", e);
                    reuse_downstream = false;
                }
            }
        }
        // Signal the upstream half that the downstream half completed cleanly before
        // dropping rx, so a resulting task-pipe closure is treated as benign.
        pipe_state.store(PipeState::DownstreamComplete as u8, Ordering::Release);
        Ok(reuse_downstream)
    }

    /// streamscope: give [`ProxyHttp::response_body_filter`] its end-of-stream before an
    /// HTTP/2 response's trailer block, and carry back whatever it releases.
    ///
    /// An h2 response that ends in trailers carries END_STREAM on the trailer HEADERS
    /// frame, so [`check_response_end_or_error`](pingora_core::protocols::http::v2::client::Http2Session::check_response_end_or_error)
    /// answers `false` for every DATA frame and the upstream half emits no
    /// `HttpTask::Body(_, true)`. A filter that withholds a body and releases it at
    /// end-of-stream — a RESPMOD content scan — would never reach its release, so the
    /// response is delivered as a head with no bytes at all.
    ///
    /// A `Trailer` task is exactly the case where the end-of-stream is still owed: a body
    /// that ended with END_STREAM on a DATA frame has no trailers to read, so the upstream
    /// half sends `Trailer` only when no body task carried the end.
    ///
    /// The released bytes are returned as a task the caller writes AHEAD of the trailers,
    /// carrying `false` for the end — the trailer task that follows is the end of the
    /// response — so a gRPC `grpc-status` still reaches the client.
    ///
    /// Called from the `Trailer` arm of [`Self::h2_response_filter`], which is past the
    /// upstream filters and past the cache-admission return: a task the downstream half
    /// never sees must not reach the app's body filter either.
    async fn end_response_body_before_trailers(
        &self,
        session: &mut Session<DS>,
        ctx: &mut <SV as ProxyHttp<DS>>::CTX,
    ) -> Result<Option<HttpTask>>
    where
        SV: ProxyHttp<DS> + Send + Sync,
        <SV as ProxyHttp<DS>>::CTX: Send + Sync,
    {
        let mut body = None;
        if let Some(duration) = self
            .inner
            .response_body_filter(session, &mut body, true, ctx)
            .await?
        {
            trace!("delaying downstream response for {duration:?}");
            time::sleep(duration).await;
        }
        Ok(body.map(|b| HttpTask::Body(Some(b), false)))
    }

    // reason: the driver's per-task state, plus `ahead` — splitting it into a struct would
    // touch every caller of an upstream function for no behavioural gain.
    #[allow(clippy::too_many_arguments)]
    async fn h2_response_filter(
        &self,
        session: &mut Session<DS>,
        mut task: HttpTask,
        ctx: &mut <SV as ProxyHttp<DS>>::CTX,
        serve_from_cache: &mut ServeFromCache,
        range_body_filter: &mut RangeBodyFilter,
        from_cache: bool, // are the task from cache already
        // streamscope: tasks to write BEFORE the filtered one. A trailer block ends a
        // body the filter had withheld, and those bytes precede it on the wire.
        ahead: &mut Vec<HttpTask>,
    ) -> Result<HttpTask>
    where
        SV: ProxyHttp<DS> + Send + Sync,
        <SV as ProxyHttp<DS>>::CTX: Send + Sync,
    {
        if !from_cache {
            if let Some(duration) = self.upstream_filter(session, &mut task, ctx).await? {
                trace!("delaying upstream response for {duration:?}");
                time::sleep(duration).await;
            }

            // cache the original response before any downstream transformation
            // requests that bypassed cache still need to run filters to see if the response has become cacheable
            if session.cache.enabled() || session.cache.bypassing() {
                if let Err(e) = self
                    .cache_http_task(session, &task, ctx, serve_from_cache)
                    .await
                {
                    session.cache.disable(NoCacheReason::StorageError);
                    if serve_from_cache.is_miss_body() {
                        // if the response stream cache body during miss but write fails, it has to
                        // give up the entire request
                        return Err(e);
                    } else {
                        // otherwise, continue processing the response
                        warn!(
                            "Fail to cache response: {}, {}",
                            e,
                            self.inner.request_summary(session, ctx)
                        );
                    }
                }
            }
            // skip the downstream filtering if these tasks are just for cache admission
            if !serve_from_cache.should_send_to_downstream() {
                return Ok(task);
            }
        } // else: cached/local response, no need to trigger upstream filters and caching

        // normally max file size is tracked in cache_http_task filters (when cache enabled),
        // we will track it in these filters before sending to downstream on specific conditions
        // when cache is disabled
        let track_max_cache_size = matches!(
            session.cache.phase(),
            CachePhase::Disabled(NoCacheReason::PredictedResponseTooLarge)
        );

        let res = match task {
            HttpTask::Header(mut header, eos) => {
                /* Downstream revalidation, only needed when cache is on because otherwise origin
                 * will handle it */
                if session.upstream_headers_mutated_for_cache() {
                    self.downstream_response_conditional_filter(
                        serve_from_cache,
                        session,
                        &mut header,
                        ctx,
                    );
                    if !session.ignore_downstream_range {
                        let range_type = self.inner.range_header_filter(session, &mut header, ctx);
                        range_body_filter.set(range_type);
                    }
                }

                self.inner
                    .response_filter(session, &mut header, ctx)
                    .await?;
                /* Downgrade the version so that write_response_header won't panic */
                header.set_version(Version::HTTP_11);

                // these status codes / method cannot have body, so no need to add chunked encoding
                let no_body = session.req_header().method == "HEAD"
                    || matches!(header.status.as_u16(), 204 | 304);

                /* Add chunked header to tell downstream to use chunked encoding
                 * during the absent of content-length in h2 */
                if !no_body
                    && !header.status.is_informational()
                    && header.headers.get(http::header::CONTENT_LENGTH).is_none()
                {
                    header.insert_header(http::header::TRANSFER_ENCODING, "chunked")?;
                }
                Ok(HttpTask::Header(header, eos))
            }
            HttpTask::Body(data, eos) => {
                if track_max_cache_size {
                    session
                        .cache
                        .track_body_bytes_for_max_file_size(data.as_ref().map_or(0, |d| d.len()));
                }

                let mut data = range_body_filter.filter_body(data);
                if let Some(duration) = self
                    .inner
                    .response_body_filter(session, &mut data, eos, ctx)
                    .await?
                {
                    trace!("delaying downstream response for {duration:?}");
                    time::sleep(duration).await;
                }
                Ok(HttpTask::Body(data, eos))
            }
            HttpTask::UpgradedBody(..) => {
                // An h2 session should not be able to send an h2 upgraded response body,
                // and logically that is impossible unless there is a bug in the client v2 session
                panic!("Unexpected UpgradedBody task while proxy h2");
            }
            HttpTask::Trailer(mut trailers) => {
                // streamscope: this block is the response's end-of-stream, and the body
                // filter was never given one (see `end_response_body_before_trailers`).
                if let Some(released) = self.end_response_body_before_trailers(session, ctx).await?
                {
                    ahead.push(released);
                }
                let trailer_buffer = match trailers.as_mut() {
                    Some(trailers) => {
                        debug!("Parsing response trailers..");
                        match self
                            .inner
                            .response_trailer_filter(session, trailers, ctx)
                            .await
                        {
                            Ok(buf) => buf,
                            Err(e) => {
                                error!(
                                    "Encountered error while filtering upstream trailers {:?}",
                                    e
                                );
                                None
                            }
                        }
                    }
                    _ => None,
                };
                // if we have a trailer buffer write it to the downstream response body
                if let Some(buffer) = trailer_buffer {
                    // write_body will not write additional bytes after reaching the content-length
                    // for gRPC H2 -> H1 this is not a problem but may be a problem for non gRPC code
                    // https://http2.github.io/http2-spec/#malformed
                    Ok(HttpTask::Body(Some(buffer), true))
                } else {
                    Ok(HttpTask::Trailer(trailers))
                }
            }
            HttpTask::Done => Ok(task),
            HttpTask::Failed(_) => Ok(task), // Do nothing just pass the error down
        };
        // On end, check if the response (based on file size) can be considered cacheable again
        if let Ok(task) = res.as_ref() {
            if track_max_cache_size
                && task.is_end()
                && !matches!(task, HttpTask::Failed(_))
                && !session.cache.exceeded_max_file_size()
            {
                session.cache.response_became_cacheable();
            }
        }
        res
    }

    /// Filter one request body chunk and write it upstream, recording on `progress` a
    /// chunk the upstream accepted.
    #[allow(clippy::too_many_arguments)]
    async fn send_body_to2(
        &self,
        session: &mut Session<DS>,
        mut data: Option<Bytes>,
        end_of_body: bool,
        client_body: &mut h2::SendStream<bytes::Bytes>,
        ctx: &mut <SV as ProxyHttp<DS>>::CTX,
        write_timeout: Option<Duration>,
        progress: Option<&RequestBodyProgress>,
    ) -> Result<bool>
    where
        SV: ProxyHttp<DS> + Send + Sync,
        <SV as ProxyHttp<DS>>::CTX: Send + Sync,
    {
        session
            .downstream_modules_ctx
            .request_body_filter(&mut data, end_of_body)
            .await?;

        self.inner
            .request_body_filter(session, &mut data, end_of_body, ctx)
            .await?;

        /* it is normal to get 0 bytes because of multi-chunk parsing or request_body_filter.
         * Although there is no harm writing empty byte to h2, unlike h1, we ignore it
         * for consistency */
        if !end_of_body && data.as_ref().is_some_and(|d| d.is_empty()) {
            return Ok(false);
        }

        let (data, end) = match data {
            Some(data) => {
                debug!("Write {} bytes body to h2 upstream", data.len());
                (data, end_of_body)
            }
            None => {
                debug!("Read downstream body done");
                /* send a standalone END_STREAM flag */
                (Bytes::new(), true)
            }
        };

        /* For H2 downstreams, race the upstream write against downstream stream
         * closure. A write blocked on upstream flow control would otherwise keep the
         * downstream stream handles referenced while a downstream RST_STREAM goes
         * unobserved, pinning the downstream connection window credit until the
         * write completes. */
        if let Some(stream_close) = session.downstream_session.watch_h2_stream_close() {
            tokio::select! {
                biased;
                res = write_body(client_body, data, end, write_timeout) => {
                    res.map_err(|e| e.into_up())?;
                }
                close_result = stream_close => {
                    return match close_result {
                        Ok(reason) => Error::e_explain(
                            H2Error,
                            format!("downstream H2 stream closed (reason: {reason}) while writing body to upstream"),
                        ),
                        Err(e) => Err(e),
                    }
                    .map_err(|e| e.into_down());
                }
            }
        } else {
            write_body(client_body, data, end, write_timeout)
                .await
                .map_err(|e| e.into_up())?;
        }
        if let Some(progress) = progress {
            progress.accepted();
        }

        Ok(end_of_body)
    }
}

/// Write one flow-control grant of a released request body, ending the stream with its
/// last byte — or, for a release that is empty, a standalone END_STREAM. The wait for the
/// grant is bounded by `write_timeout`, as [`write_body`]'s is. Returns whether the stream
/// was ended. Pends forever on no release, so a select branch can hold it disabled.
///
/// Cancel-safe: the only await is the grant, and a grant not yet spent stays assigned to
/// the stream for the next call.
async fn release_one_grant(
    writer: &mut h2::SendStream<Bytes>,
    release: &mut Option<Bytes>,
    write_timeout: Option<Duration>,
) -> Result<bool> {
    let Some(remaining) = release.as_mut() else {
        return std::future::pending().await;
    };
    if remaining.is_empty() {
        writer
            .send_data(Bytes::new(), true)
            .or_err(WriteError, "while ending h2 request body")?;
        return Ok(true);
    }
    writer.reserve_capacity(remaining.len());
    let grant = async {
        match std::future::poll_fn(|cx| writer.poll_capacity(cx)).await {
            None => Error::e_explain(H2Error, "cannot reserve capacity"),
            Some(ready) => ready.or_err(H2Error, "while waiting for capacity"),
        }
    };
    let granted = match write_timeout {
        Some(t) => match tokio::time::timeout(t, grant).await {
            Ok(granted) => granted?,
            Err(_) => Error::e_explain(
                WriteTimedout,
                format!("while writing h2 request body, timeout: {t:?}"),
            )?,
        },
        None => grant.await?,
    };
    let chunk = remaining.split_to(granted.min(remaining.len()));
    let ended = remaining.is_empty();
    writer
        .send_data(chunk, ended)
        .or_err(WriteError, "while writing h2 request body")?;
    Ok(ended)
}

/// When the upstream last accepted a request body chunk, so that an upstream read timeout
/// bounds a silence rather than the time the request takes to send.
///
/// The h2 response is read concurrently with the request body, so a read timeout armed
/// per read would cut every upload that takes longer than it to send, whatever its rate —
/// the head read of an origin that answers after the body, and the body or trailer read of
/// one that answered early. The h1 path re-arms its reads the same way: its duplex
/// `select!` rebuilds the response read after every request chunk it writes.
///
/// Only a chunk the upstream ACCEPTED renews it: a chunk the request body filter
/// swallowed, a write still blocked on flow control and a write that failed do not. So an
/// origin that stops reading the body is cut by whichever of the read and write timeouts
/// ends first, and a client that stops sending is cut by the read timeout, counted from
/// its last chunk. Like the h1 path, and like nginx's `proxy_read_timeout`, it bounds a
/// silence and not a total: a body that keeps trickling keeps renewing it.
pub(crate) struct RequestBodyProgress {
    start: std::time::Instant,
    /// Nanoseconds after `start` of the last accepted chunk; `0` before the first.
    last: AtomicU64,
}

impl RequestBodyProgress {
    pub(crate) fn new() -> Self {
        Self {
            start: std::time::Instant::now(),
            last: AtomicU64::new(0),
        }
    }

    pub(crate) fn accepted(&self) {
        let at = u64::try_from(self.start.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.last.store(at, Ordering::Relaxed);
    }

    /// How long since the last accepted chunk, or since this request's reads began.
    fn idle(&self) -> Duration {
        let last = Duration::from_nanos(self.last.load(Ordering::Relaxed));
        self.start.elapsed().saturating_sub(last)
    }
}

/// Restores the session's own read timeout however a renewed read ends — a cancelled
/// read (the other half of the duplex failed) included.
struct ReadTimeoutRestore<'a> {
    client: &'a mut Http2Session,
    read_timeout: Duration,
}

impl Drop for ReadTimeoutRestore<'_> {
    fn drop(&mut self) {
        self.client.read_timeout = Some(self.read_timeout);
    }
}

/// Run one upstream read under the session's read timeout counted from the later of the
/// read's start and the last request body chunk the upstream accepted. The h2 client's
/// reads (head, body, trailers) resume after a timeout without losing what is pending, so
/// a timeout the body has since renewed re-arms the read for what remains of it. Without a
/// `progress` (no request body, or no read timeout) it is the plain read.
async fn read_renewed<T>(
    client: &mut Http2Session,
    progress: Option<&RequestBodyProgress>,
    mut read: impl AsyncFnMut(&mut Http2Session) -> Result<T>,
) -> Result<T> {
    let (Some(progress), Some(read_timeout)) = (progress, client.read_timeout) else {
        return read(client).await;
    };
    let restore = ReadTimeoutRestore {
        client,
        read_timeout,
    };
    loop {
        match read(restore.client).await {
            Err(e) if matches!(e.etype, ReadTimedout) => {
                let idle = progress.idle();
                if idle >= read_timeout {
                    return Err(e);
                }
                restore.client.read_timeout = Some(read_timeout - idle);
            }
            other => return other,
        }
    }
}

/* Read response header, body and trailer from h2 upstream and send them to tx */
pub(crate) async fn pipe_up_to_down_response(
    client: &mut Http2Session,
    tx: mpsc::Sender<HttpTask>,
    pipe_state: Arc<AtomicU8>,
    progress: Option<&RequestBodyProgress>,
) -> Result<()> {
    read_renewed(client, progress, async |c: &mut Http2Session| {
        c.read_response_header().await
    })
    .await
    .map_err(|e| e.into_up())?; // should we send the error as an HttpTask?

    let resp_header = Box::new(client.response_header().expect("just read").clone());

    match client.check_response_end_or_error() {
        Ok(eos) => {
            // XXX: the h2 crate won't check for content-length underflow
            // if a header frame with END_STREAM is sent without data frames
            // As stated by RFC, "204 or 304 responses contain no content,
            // as does the response to a HEAD request"
            // https://datatracker.ietf.org/doc/html/rfc9113#section-8.1.1
            let req_header = client.request_header().expect("must have sent req");
            if eos
                && req_header.method != Method::HEAD
                && resp_header.status != StatusCode::NO_CONTENT
                && resp_header.status != StatusCode::NOT_MODIFIED
                // RFC technically allows for leading zeroes
                // https://datatracker.ietf.org/doc/html/rfc9110#name-content-length
                && resp_header
                    .headers
                    .get(CONTENT_LENGTH)
                    .is_some_and(|cl| cl.as_bytes().iter().any(|b| *b != b'0'))
            {
                let _ = tx
                    .send(HttpTask::Failed(
                        Error::explain(H2Error, "non-zero content-length on EOS headers frame")
                            .into_up(),
                    ))
                    .await;
                return Ok(());
            }
            tx.send(HttpTask::Header(resp_header, eos))
                .await
                .or_err(InternalError, "sending h2 headers to pipe")?;
        }
        Err(e) => {
            // If upstream errored, then push error to downstream and then quit
            // Don't care if send fails (which means downstream already gone)
            // we were still able to retrieve the headers, so try sending
            let _ = tx.send(HttpTask::Header(resp_header, false)).await;
            let _ = tx.send(HttpTask::Failed(e.into_up())).await;
            return Ok(());
        }
    }

    // Read body from H2 upstream, racing each read against tx.closed().
    //
    // When proxying an H2 upstream response with Content-Length to an H1 downstream,
    // bidirection_down_to_up() may determine the response is complete (all Content-Length
    // bytes written) and exit before the H2 stream signals END_STREAM. This drops the
    // receiving end (rx) of the channel. Without this race, read_response_body() would
    // block until the H2 stream eventually ends (e.g. via trailers or read_timeout),
    // while the downstream side (which could be H1) is in theory already done.
    loop {
        let chunk = tokio::select! {
            biased;
            body = read_renewed(client, progress, async |c: &mut Http2Session| c.read_response_body().await) => {
                body.map_err(|e| e.into_up()).transpose()
            }
            _ = tx.closed() => None,
        };
        let Some(chunk) = chunk else {
            break;
        };
        let data = match chunk {
            Ok(d) => d,
            Err(e) => {
                // Push the error to downstream and then quit
                let _ = tx.send(HttpTask::Failed(e.into_up())).await;
                // Downstream should consume all remaining data and handle the error
                return Ok(());
            }
        };
        match client.check_response_end_or_error() {
            Ok(eos) => {
                let empty = data.is_empty();
                if empty && !eos {
                    /* it is normal to get 0 bytes because of multi-chunk
                     * don't write 0 bytes to downstream since it will be
                     * misread as the terminating chunk */
                    continue;
                }
                // A send failure is benign only when the downstream half signaled it
                // completed (e.g. an H1 downstream finished by Content-Length before the
                // H2 stream signaled end-of-stream): stop reading the upstream stream.
                // Otherwise the closure is unexpected, so surface the original error.
                let send_result = tx.send(HttpTask::Body(Some(data), eos)).await;
                if send_result.is_err()
                    && PipeState::is_downstream_complete(pipe_state.load(Ordering::Acquire))
                {
                    return Ok(());
                }
                send_result.or_err(InternalError, "sending h2 body to pipe")?;
            }
            Err(e) => {
                // Similar to above, push the error to downstream and then quit
                let _ = tx.send(HttpTask::Failed(e.into_up())).await;
                return Ok(());
            }
        }
    }

    // If the channel is already closed, the downstream half is finished. This
    // skips trailers/done, but the downstream half has already finished so there
    // is nothing more to send. Benign only if the downstream half signaled
    // completion; otherwise the closure is unexpected, so surface it.
    if tx.is_closed() {
        if PipeState::is_downstream_complete(pipe_state.load(Ordering::Acquire)) {
            return Ok(());
        }
        return Error::e_explain(
            InternalError,
            "h2 task pipe closed unexpectedly before trailers",
        );
    }

    // attempt to get trailers, racing against channel close
    let trailers = tokio::select! {
        biased;
        t = read_renewed(client, progress, async |c: &mut Http2Session| c.read_trailers().await) => {
            match t {
                Ok(t) => t,
                Err(e) => {
                    let _ = tx.send(HttpTask::Failed(e.into_up())).await;
                    return Ok(());
                }
            }
        }
        _ = tx.closed() => {
            // Benign only if the downstream half signaled completion; otherwise
            // the closure is unexpected, so surface it.
            if PipeState::is_downstream_complete(pipe_state.load(Ordering::Acquire)) {
                return Ok(());
            }
            return Error::e_explain(InternalError, "h2 task pipe closed unexpectedly while reading trailers");
        }
    };

    let trailers = trailers.map(Box::new);

    if trailers.is_some() {
        // Benign only if the downstream signaled completion, same as the body sends above.
        let send_result = tx.send(HttpTask::Trailer(trailers)).await;
        if send_result.is_err()
            && PipeState::is_downstream_complete(pipe_state.load(Ordering::Acquire))
        {
            return Ok(());
        }
        send_result.or_err(InternalError, "sending h2 trailer to pipe")?;
    }

    let send_result = tx.send(HttpTask::Done).await;
    if send_result.is_err() && PipeState::is_downstream_complete(pipe_state.load(Ordering::Acquire))
    {
        debug!("h2 to h1 channel closed!");
        return Ok(());
    }
    send_result.or_err(InternalError, "sending h2 done to pipe")?;

    Ok(())
}

#[test]
fn test_update_h2_scheme_authority() {
    fn update(header: &mut RequestHeader, raw_host: &[u8], tls: bool) -> Result<()> {
        let path_and_query = h2_path_and_query(header)?;
        update_h2_scheme_authority(header, raw_host, tls, path_and_query)
    }

    let parts = http::request::Builder::new()
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let mut header = RequestHeader::from(parts);
    update(&mut header, b"example.com", true).unwrap();
    assert_eq!("example.com", header.uri.authority().unwrap());
    let err = update(&mut header, b"user@example.com", true).unwrap_err();
    assert_eq!(err.etype(), &InvalidHTTPHeader);
    update(&mut header, b"example.com:456", true).unwrap();
    assert_eq!("example.com:456", header.uri.authority().unwrap());
    update(&mut header, b"example.com:", true).unwrap();
    assert_eq!("example.com:", header.uri.authority().unwrap());
    let err = update(&mut header, b"example.com:123:345", true).unwrap_err();
    assert_eq!(err.etype(), &InvalidHTTPHeader);
    update(&mut header, b"[::1]", true).unwrap();
    assert_eq!("[::1]", header.uri.authority().unwrap());

    // verify scheme
    update(&mut header, b"example.com", true).unwrap();
    assert_eq!("https://example.com", header.uri);
    update(&mut header, b"example.com", false).unwrap();
    assert_eq!("http://example.com", header.uri);

    // H1 absolute-form is decomposed into H2 pseudo-header components.
    let mut header = RequestHeader::build("GET", b"http://example.com/path?q=1", None).unwrap();
    update(&mut header, b"example.com", false).unwrap();
    assert_eq!(header.uri.path_and_query().unwrap().as_str(), "/path?q=1");

    let mut header = RequestHeader::build(
        "GET",
        b"http://example.com/caf%C3%A9?q=r%C3%A9sum%C3%A9",
        None,
    )
    .unwrap();
    update(&mut header, b"example.com", false).unwrap();
    assert_eq!(
        header.uri.path_and_query().unwrap().as_str(),
        "/caf%C3%A9?q=r%C3%A9sum%C3%A9"
    );

    let mut header = RequestHeader::build("GET", b"http://example.com?only=query", None).unwrap();
    update(&mut header, b"example.com", false).unwrap();
    assert_eq!(
        header.uri.path_and_query().unwrap().as_str(),
        "/?only=query"
    );

    let mut header = RequestHeader::build("GET", b"http://example.com", None).unwrap();
    update(&mut header, b"example.com", false).unwrap();
    assert_eq!(header.uri.path_and_query().unwrap().as_str(), "/");

    // Origin-form remains unchanged.
    let mut header = RequestHeader::build("GET", b"/path?q=1", None).unwrap();
    update(&mut header, b"example.com", false).unwrap();
    assert_eq!(header.uri.path_and_query().unwrap().as_str(), "/path?q=1");

    let mut header = RequestHeader::build("GET", b"http:/\\/\\other.example/admin", None).unwrap();
    let err = update(&mut header, b"example.com", false).unwrap_err();
    assert_eq!(err.etype(), &InvalidHTTPHeader);
    assert_eq!(
        err.context.as_ref().map(|context| context.as_str()),
        Some("ambiguous HTTP absolute-form request target")
    );

    let raw_target = b"http://example.com/\xff";
    let mut header = RequestHeader::build("GET", raw_target, None).unwrap();
    let err = update(&mut header, b"example.com", false).unwrap_err();
    assert_eq!(err.etype(), &InvalidHTTPHeader);
    assert_eq!(
        err.context.as_ref().map(|context| context.as_str()),
        Some("non-UTF-8 request target cannot be forwarded over HTTP/2")
    );
    assert_eq!(header.raw_path(), raw_target);
}

#[test]
fn test_h2_path_is_rooted_for_targets_with_no_authority() {
    // Targets with no absolute-form authority carry no absolute path, so :path is rooted
    // rather than forwarding bytes that are invalid there (RFC 9113 section 8.3.1).
    // Forwarding them would also concatenate against the authority, rendering as
    // "http://example.comfoo/bar".
    for target in [&b"foo/bar"[..], b"myproto:opaque", b"foo?q=1"] {
        let mut header = RequestHeader::build("GET", target, None).unwrap();
        let label = String::from_utf8_lossy(target);
        // The H1 wire serializes these bytes; only the H2 rewrite below discards them.
        assert_eq!(target, header.raw_path(), "{label}");

        let path_and_query = h2_path_and_query(&header).unwrap();
        assert_eq!("/", path_and_query.as_str(), "{label}");

        update_h2_scheme_authority(&mut header, b"example.com", false, path_and_query).unwrap();
        assert_eq!("http://example.com/", header.uri.to_string(), "{label}");
        assert_eq!(
            Some("example.com"),
            header.uri.authority().map(|authority| authority.as_str()),
            "{label}"
        );
    }
}

#[cfg(test)]
mod trailered_response_tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A filter shaped like a RESPMOD content scan: withhold every chunk, release the
    /// whole body at end-of-stream. It is the shape that a missing end-of-stream costs
    /// the entire response body.
    struct WithholdUntilEnd {
        withheld: Mutex<Vec<u8>>,
        ends: AtomicUsize,
    }

    #[async_trait]
    impl ProxyHttp for WithholdUntilEnd {
        type CTX = ();

        fn new_ctx(&self) -> Self::CTX {}

        async fn upstream_peer(
            &self,
            _session: &mut Session,
            _ctx: &mut Self::CTX,
        ) -> Result<Box<HttpPeer>> {
            unreachable!("the test drives the downstream task batch directly")
        }

        async fn response_body_filter(
            &self,
            _session: &mut Session,
            body: &mut Option<Bytes>,
            end_of_stream: bool,
            _ctx: &mut Self::CTX,
        ) -> Result<Option<Duration>> {
            if let Some(chunk) = body.take() {
                self.withheld
                    .lock()
                    .expect("test mutex")
                    .extend_from_slice(&chunk);
            }
            if end_of_stream {
                self.ends.fetch_add(1, Ordering::Relaxed);
                let released = std::mem::take(&mut *self.withheld.lock().expect("test mutex"));
                if !released.is_empty() {
                    *body = Some(Bytes::from(released));
                }
            }
            Ok(None)
        }
    }

    async fn session_with_request() -> (tokio::io::DuplexStream, Session) {
        let (mut client, server) = tokio::io::duplex(8192);
        client
            .write_all(b"GET /rpc HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .expect("test request should be written");
        let mut session = Session::new_h1(Box::new(server) as pingora_core::protocols::Stream);
        session
            .read_request()
            .await
            .expect("test request should parse");
        (client, session)
    }

    /// Read the client's side to EOF. The caller drops the `Session` first, so the server
    /// half closes and this ends on a real end-of-file rather than on a deadline — a test
    /// that waits out a timeout hides the difference between "wrote nothing" and "is slow".
    async fn downstream_bytes(client: &mut tokio::io::DuplexStream) -> String {
        let mut out = Vec::new();
        let mut buf = [0u8; 1024];
        while let Ok(read) = client.read(&mut buf).await {
            if read == 0 {
                break;
            }
            out.extend_from_slice(&buf[..read]);
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// Runs one batch of upstream tasks through the downstream half and returns what the
    /// client was written, with the number of end-of-streams the body filter was given.
    async fn one_batch(tasks: Vec<HttpTask>) -> (String, usize) {
        let proxy = HttpProxy::new(
            WithholdUntilEnd {
                withheld: Mutex::new(Vec::new()),
                ends: AtomicUsize::new(0),
            },
            Arc::new(ServerConf::default()),
        );
        let (mut client, mut session) = session_with_request().await;

        let (tx, mut rx) = mpsc::channel(tasks.len());
        let mut tasks = tasks.into_iter();
        let initial = tasks.next().expect("a batch starts with a task");
        for task in tasks {
            tx.send(task).await.expect("test task queued");
        }
        drop(tx); // so the batch loop sees the end of the pipe rather than parking

        proxy
            .process_upstream_tasks_h2(
                &mut session,
                &mut (),
                initial,
                &mut rx,
                &mut ServeFromCache::new(),
                &mut RangeBodyFilter::new(),
                &mut ResponseStateMachine::new(),
            )
            .await
            .expect("the batch should reach the downstream");
        drop(session); // close the server half so the read below ends at EOF

        (
            downstream_bytes(&mut client).await,
            proxy.inner.ends.load(Ordering::Relaxed),
        )
    }

    fn head() -> HttpTask {
        HttpTask::Header(
            Box::new(ResponseHeader::build(200, None).expect("test response header")),
            false,
        )
    }

    /// The control: a response whose last DATA frame carries END_STREAM gives the body
    /// filter its end with that chunk, and the withheld body is released.
    #[tokio::test]
    async fn a_response_without_trailers_ends_the_body_filter_on_its_last_chunk() {
        let (wire, ends) = one_batch(vec![
            head(),
            HttpTask::Body(Some(Bytes::from_static(b"hello")), true),
            HttpTask::Done,
        ])
        .await;

        assert_eq!(ends, 1, "the last chunk must end the body filter");
        assert!(
            wire.contains("hello"),
            "the withheld body must reach the client: {wire:?}"
        );
    }

    /// A response that ends in trailers carries END_STREAM on the trailer block, so no
    /// body task carries the end. Without an end-of-stream before the trailers the
    /// withheld body is dropped and the client is served a head with no bytes.
    #[tokio::test]
    async fn a_trailered_response_ends_the_body_filter_before_its_trailers() {
        let (wire, ends) = one_batch(vec![
            head(),
            HttpTask::Body(Some(Bytes::from_static(b"hello")), false),
            HttpTask::Trailer(Some(Box::new(http::HeaderMap::new()))),
            HttpTask::Done,
        ])
        .await;

        assert!(
            wire.contains("hello"),
            "the withheld body must be released ahead of the trailers: {wire:?}"
        );
        assert_eq!(ends, 1, "the trailer block must end the body filter");
    }
}

#[cfg(test)]
mod request_body_progress_tests {
    use super::*;
    use pingora_core::connectors::http::v2::ConnectionRef;
    use pingora_core::protocols::Digest;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Wide against the pace below, so a loaded test runner cannot starve a renewal.
    const READ_TIMEOUT: Duration = Duration::from_millis(500);
    const PACE: Duration = Duration::from_millis(50);
    /// Three read timeouts of upload at `PACE`.
    const CHUNKS: usize = 30;
    const CHUNK: &[u8] = &[b'u'; 100];

    struct Forward;

    #[async_trait]
    impl ProxyHttp for Forward {
        type CTX = ();

        fn new_ctx(&self) -> Self::CTX {}

        async fn upstream_peer(
            &self,
            _session: &mut Session,
            _ctx: &mut Self::CTX,
        ) -> Result<Box<HttpPeer>> {
            unreachable!("the test hands proxy_down_to_up its upstream stream")
        }
    }

    /// When the origin sends its response head: after the whole request body (an origin
    /// that buffers the request), or at once with the body after it (a streaming RPC). The
    /// echoing origins answer after the body with the body they received — `SlowEcho`
    /// reading it a `PACE` per DATA frame, so a body larger than one flow-control window
    /// takes several of them to send.
    #[derive(Clone, Copy)]
    pub(super) enum Origin {
        HeadAfterBody,
        HeadFirst,
        Echo,
        SlowEcho,
    }

    /// An h2 stream to an origin that reads the whole request body before it ends its
    /// response, answering its head as `origin` says.
    pub(super) async fn stream_to(origin: Origin) -> Http2Session {
        let (client_io, server_io) = tokio::io::duplex(65536);
        tokio::spawn(async move {
            let mut conn = h2::server::handshake(server_io).await.unwrap();
            if let Some(Ok((request, mut respond))) = conn.accept().await {
                tokio::spawn(async move {
                    let head = || http::Response::builder().status(200).body(()).unwrap();
                    let mut send = match origin {
                        Origin::HeadFirst => Some(respond.send_response(head(), false).unwrap()),
                        _ => None,
                    };
                    let mut body = request.into_body();
                    let mut received = Vec::new();
                    while let Some(Ok(chunk)) = body.data().await {
                        if matches!(origin, Origin::SlowEcho) {
                            tokio::time::sleep(PACE).await;
                        }
                        let _ = body.flow_control().release_capacity(chunk.len());
                        received.extend_from_slice(&chunk);
                    }
                    let answer = match origin {
                        Origin::Echo | Origin::SlowEcho => Bytes::from(received),
                        Origin::HeadAfterBody | Origin::HeadFirst => Bytes::from_static(b"ok"),
                    };
                    let mut send = send
                        .take()
                        .unwrap_or_else(|| respond.send_response(head(), false).unwrap());
                    let _ = send.send_data(answer, true);
                });
            }
            while conn.accept().await.is_some() {}
        });
        let (send_req, connection) = h2::client::handshake(client_io).await.unwrap();
        let (closed_tx, closed_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            let _ = connection.await;
            let _ = closed_tx.send(true);
        });
        let conn = ConnectionRef::new(
            send_req,
            closed_rx,
            Arc::new(AtomicBool::new(false)),
            0,
            1,
            Digest::default(),
        );
        conn.spawn_stream().await.unwrap().expect("a stream slot")
    }

    /// Proxy one h1 upload of `CHUNKS` chunks, `PACE` apart — or, `stalled`, only half of
    /// them, the connection then left open — through `proxy_down_to_up` to `origin`, and
    /// return the proxy's error with what the client was answered.
    async fn upload(origin: Origin, stalled: bool) -> (Option<Box<Error>>, String) {
        let proxy = HttpProxy::new(Forward, Arc::new(ServerConf::default()));
        let (client, server) = tokio::io::duplex(65536);
        let (mut client_read, mut client_write) = tokio::io::split(client);
        client_write
            .write_all(
                format!(
                    "POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: {}\r\n\r\n",
                    CHUNK.len() * CHUNKS
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut session = Session::new_h1(Box::new(server) as pingora_core::protocols::Stream);
        session
            .read_request()
            .await
            .expect("the request head parses");
        let sending = if stalled { CHUNKS / 2 } else { CHUNKS };
        let writer = tokio::spawn(async move {
            for _ in 0..sending {
                tokio::time::sleep(PACE).await;
                client_write.write_all(CHUNK).await.unwrap();
            }
            client_write // held open: a stalled client neither sends nor closes
        });
        let mut h2s = stream_to(origin).await;
        let mut peer = HttpPeer::new("127.0.0.1:1", false, String::new());
        peer.options.read_timeout = Some(READ_TIMEOUT);
        peer.options.write_timeout = Some(READ_TIMEOUT);
        let (_, error) = proxy
            .proxy_down_to_up(&mut session, &mut h2s, &peer, &mut ())
            .await;
        let _client_write = writer.await.unwrap();
        drop(session);
        let mut answer = Vec::new();
        let _ = client_read.read_to_end(&mut answer).await;
        (error, String::from_utf8_lossy(&answer).into_owned())
    }

    /// An origin that answers only once it has the whole body is waited for while the body
    /// still moves, for three read timeouts.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_upload_longer_than_the_read_timeout_gets_a_head_sent_after_its_body() {
        let (error, answer) = upload(Origin::HeadAfterBody, false).await;
        assert!(error.is_none(), "{error:?}");
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        assert!(answer.contains("\r\n\r\n2\r\nok\r\n"), "{answer}");
    }

    /// An origin that sent its head at once and its body after the request's end — a
    /// streaming RPC — is waited for the same way: the body read is renewed too.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_upload_longer_than_the_read_timeout_gets_a_body_sent_after_it() {
        let (error, answer) = upload(Origin::HeadFirst, false).await;
        assert!(error.is_none(), "{error:?}");
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        assert!(answer.contains("\r\n\r\n2\r\nok\r\n"), "{answer}");
    }

    /// The positive control: an upload that stops is cut by the read timeout, counted from
    /// its last chunk, on both origin shapes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_upload_that_stops_is_cut_by_the_read_timeout() {
        for origin in [Origin::HeadAfterBody, Origin::HeadFirst] {
            let started = std::time::Instant::now();
            let (error, _) = upload(origin, true).await;
            let error = error.expect("a stalled upload is cut");
            assert!(matches!(error.etype, ReadTimedout), "{error:?}");
            assert!(
                started.elapsed() < PACE * (CHUNKS / 2) as u32 + READ_TIMEOUT * 4,
                "cut about a read timeout after the stall, not left hanging"
            );
        }
    }
}

#[cfg(test)]
mod consumed_request_body_tests {
    use super::request_body_progress_tests::{stream_to, Origin};
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const UPLOAD: &[u8] = b"upload-body!";
    /// The adaptation a REQMOD service hands back: the upload's length, so the forwarded
    /// `Content-Length` still frames it.
    const ADAPTED: &[u8] = b"ADAPTED-BODY";
    /// Four default flow-control windows: a release that takes many grants to send.
    const LARGE: usize = 256 * 1024;
    /// What a stream that is never given its body is cut at — well short of the time a
    /// `SlowEcho` origin takes to read a `LARGE` body (a `PACE` per 16 KiB DATA frame).
    const READ_TIMEOUT: Duration = Duration::from_millis(500);

    /// A proxy shaped like an ICAP REQMOD client: the body was read whole before the
    /// upstream was dialled, and its adaptation is released at the one end-of-stream.
    struct ReleaseAdapted;

    #[async_trait]
    impl ProxyHttp for ReleaseAdapted {
        type CTX = Option<Bytes>;

        fn new_ctx(&self) -> Self::CTX {
            None
        }

        async fn upstream_peer(
            &self,
            _session: &mut Session,
            _ctx: &mut Self::CTX,
        ) -> Result<Box<HttpPeer>> {
            unreachable!("the test hands proxy_down_to_up its upstream stream")
        }

        async fn request_body_filter(
            &self,
            _session: &mut Session,
            body: &mut Option<Bytes>,
            end_of_stream: bool,
            ctx: &mut Self::CTX,
        ) -> Result<()> {
            if end_of_stream {
                if let Some(adapted) = ctx.take() {
                    *body = Some(adapted);
                }
            }
            Ok(())
        }
    }

    /// Proxy one h1 request (`head`, then `body`) to an h2 `origin` after reading its whole
    /// body first, as `request_filter` does, with `ctx` the adaptation to release; return
    /// the proxy's error, the adaptation left unreleased, and what the client was answered.
    async fn consumed_then_proxied(
        origin: Origin,
        head: &str,
        body: &[u8],
        mut ctx: Option<Bytes>,
    ) -> (Option<Box<Error>>, Option<Bytes>, String) {
        let proxy = HttpProxy::new(ReleaseAdapted, Arc::new(ServerConf::default()));
        // Room for the whole request and answer, so neither side waits on the other.
        let (client, server) = tokio::io::duplex(4 * LARGE);
        let (mut client_read, mut client_write) = tokio::io::split(client);
        client_write.write_all(head.as_bytes()).await.unwrap();
        client_write.write_all(body).await.unwrap();
        let mut session = Session::new_h1(Box::new(server) as pingora_core::protocols::Stream);
        session
            .read_request()
            .await
            .expect("the request head parses");
        let mut consumed = Vec::new();
        while let Some(chunk) = session
            .read_request_body()
            .await
            .expect("the request body reads")
        {
            consumed.extend_from_slice(&chunk);
        }
        assert_eq!(consumed, body);
        assert!(session.as_mut().is_body_done());

        let mut h2s = stream_to(origin).await;
        let mut peer = HttpPeer::new("127.0.0.1:1", false, String::new());
        peer.options.read_timeout = Some(READ_TIMEOUT);
        peer.options.write_timeout = Some(READ_TIMEOUT);
        let (_, error) = proxy
            .proxy_down_to_up(&mut session, &mut h2s, &peer, &mut ctx)
            .await;
        drop(session);
        let mut answer = Vec::new();
        let _ = client_read.read_to_end(&mut answer).await;
        drop(client_write);
        (error, ctx, String::from_utf8_lossy(&answer).into_owned())
    }

    /// A body `request_filter` read whole, before the upstream was dialled, still reaches
    /// an h2 upstream — as the filter's adaptation, released at its end-of-stream — rather
    /// than leaving the stream with HEADERS and no DATA until its read timeout.
    #[tokio::test]
    async fn a_body_a_filter_consumed_is_released_to_an_h2_upstream() {
        let head = format!(
            "POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: {}\r\n\r\n",
            UPLOAD.len()
        );
        let (error, unreleased, answer) = consumed_then_proxied(
            Origin::Echo,
            &head,
            UPLOAD,
            Some(Bytes::from_static(ADAPTED)),
        )
        .await;
        assert!(error.is_none(), "{error:?}");
        assert!(
            unreleased.is_none(),
            "the filter must be given its end-of-stream"
        );
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        assert!(
            answer.contains("ADAPTED-BODY"),
            "the origin must receive the adaptation: {answer}"
        );
    }

    /// A release larger than the flow-control window goes out grant by grant, each one
    /// renewing the read timeout: an origin that reads it slowly — for longer than the read
    /// timeout, but never silent for that long — gets all of it and answers. Written in one
    /// piece, the release would renew nothing until its last byte, and the head read would
    /// be cut while the body was still moving.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_large_release_renews_the_read_timeout_as_the_origin_accepts_it() {
        let upload = vec![b'u'; LARGE];
        // Not a hex digit, so the chunk-size lines of the client's answer cannot add any.
        let adapted = Bytes::from(vec![b'Z'; LARGE]);
        let head = format!(
            "POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: {LARGE}\r\n\r\n"
        );
        let started = std::time::Instant::now();
        let (error, unreleased, answer) =
            consumed_then_proxied(Origin::SlowEcho, &head, &upload, Some(adapted)).await;
        assert!(error.is_none(), "{error:?}");
        assert!(unreleased.is_none());
        assert!(
            started.elapsed() > READ_TIMEOUT,
            "the origin read for longer than one read timeout"
        );
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer:.200}");
        assert_eq!(
            answer.bytes().filter(|b| *b == b'Z').count(),
            LARGE,
            "the origin must receive the whole release"
        );
    }

    /// The control: a bodyless request, whose END_STREAM went out with its header, is
    /// given no release after it — the filter is not asked for one, so no DATA can follow
    /// the end of the stream — and is answered.
    #[tokio::test]
    async fn a_bodyless_request_sends_no_data_after_its_header_ended_the_stream() {
        let head = "GET /page HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (error, unreleased, answer) =
            consumed_then_proxied(Origin::Echo, head, b"", Some(Bytes::from_static(ADAPTED))).await;
        assert!(error.is_none(), "{error:?}");
        assert_eq!(
            unreleased.as_deref(),
            Some(ADAPTED),
            "a bodyless request releases nothing"
        );
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    }
}
