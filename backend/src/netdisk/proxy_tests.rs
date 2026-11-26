//! Loopback transport evidence: no Baidu credentials, endpoints or files.
use super::*;
use crate::common::{ProxyConfig, ProxyFallbackManager, ProxyType};
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{Response, StatusCode},
    Router,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

struct Server {
    address: std::net::SocketAddr,
    task: JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn serve(router: Router) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    Server { address, task }
}
fn proxy(address: std::net::SocketAddr, transfer_only: bool) -> ProxyConfig {
    ProxyConfig {
        proxy_type: ProxyType::Http,
        host: address.ip().to_string(),
        port: address.port(),
        transfer_only,
        ..Default::default()
    }
}
fn user(uid: u64) -> crate::auth::UserAuth {
    crate::auth::UserAuth::new(
        uid,
        format!("synthetic-{uid}"),
        format!("synthetic-cookie-{uid}"),
    )
}

#[tokio::test]
async fn actual_create_and_share_api_methods_bypass_proxy() {
    type Calls = Arc<std::sync::Mutex<Vec<(String, String, String)>>>;
    async fn metadata(State(calls): State<Calls>, req: Request) -> Response<Body> {
        let method = req.method().to_string();
        let path = req.uri().path().to_string();
        let body = to_bytes(req.into_body(), 8192).await.unwrap();
        calls
            .lock()
            .unwrap()
            .push((method, path, String::from_utf8(body.to_vec()).unwrap()));
        Response::new(Body::from(
            serde_json::json!({
                "errno": 0, "error_code": 0, "fs_id": 42,
                "uploadid": "synthetic-upload", "list": [],
                "link": "https://pan.baidu.com/s/1synthetic", "shareid": 42, "pwd": "0",
                "host": "synthetic.pcs.baidu.com", "expire": 60,
                "urls": [{"url": "http://127.0.0.1/synthetic-data", "encrypt": 0}]
            })
            .to_string(),
        ))
    }
    let calls: Calls = Arc::new(Default::default());
    let origin = serve(Router::new().fallback(metadata).with_state(calls.clone())).await;
    let hits = Arc::new(AtomicUsize::new(0));
    let tunnel = serve(Router::new().fallback(forward).with_state(hits.clone())).await;
    for kind in [ProxyType::Http, ProxyType::Socks5] {
        let mut cfg = proxy(tunnel.address, true);
        cfg.proxy_type = kind;
        let mut account = user(101);
        account.bdstoken = Some("synthetic-bdstoken".into());
        let mut client = NetdiskClient::new_with_proxy(account, Some(&cfg), None).unwrap();
        client.control_test_origin = Some(format!("http://{}", origin.address).parse().unwrap());
        let paths = vec!["/synthetic-control-only.txt".to_string()];
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            assert!(client
                .create_file(&paths[0], "[]", "synthetic-upload", 12, "0", "1")
                .await
                .unwrap()
                .is_success());
            assert_eq!(
                client.create_folder("/synthetic-dir").await.unwrap().errno,
                0
            );
            assert_eq!(
                client
                    .precreate(&paths[0], 12, "[]", "1")
                    .await
                    .unwrap()
                    .errno,
                0
            );
            assert_eq!(client.get_file_list("/", 1, 10).await.unwrap().errno, 0);
            assert_eq!(
                client.locate_upload().await.unwrap(),
                vec!["synthetic.pcs.baidu.com"]
            );
            assert_eq!(
                client
                    .get_locate_download_url(&paths[0])
                    .await
                    .unwrap()
                    .len(),
                1
            );
            assert!(client
                .share_set(&paths, 7, "test")
                .await
                .unwrap()
                .is_success());
            assert!(client.share_cancel(&[42]).await.unwrap().is_success());
            assert!(client.share_mexpire(42, 7).await.unwrap().is_success());
            assert!(client.share_list(1).await.unwrap().is_success());
            assert!(client.share_surl_info(42).await.unwrap().is_success());
            assert!(client.delete_files(&paths).await.unwrap().success);
            for (path, form, randsk) in [
                ("/apaas/1.0/share/list", None, None),
                (
                    "/apaas/1.0/share/transfer",
                    Some(vec![("path", "synthetic-target".into())]),
                    None,
                ),
                (
                    "/share/transfer",
                    Some(vec![("path", "synthetic-target".into())]),
                    Some("synthetic-randsk"),
                ),
            ] {
                let body = client
                    .send_share_request(crate::netdisk::share::ShareHttpRequest {
                        url: format!("https://pan.baidu.com{path}"),
                        referer: "https://pan.baidu.com/".into(),
                        form,
                        cookie_randsk: randsk,
                        error_context: "synthetic metadata request",
                    })
                    .await
                    .unwrap();
                assert_eq!(
                    serde_json::from_str::<serde_json::Value>(&body).unwrap()["errno"],
                    0
                );
            }
        })
        .await
        .expect("control API unexpectedly attempted the configured proxy");
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "a metadata API used the transfer proxy"
        );
    }
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 30);
    for path in [
        "/api/create",
        "/api/precreate",
        "/share/pset",
        "/share/cancel",
        "/share/mexpire",
        "/share/record",
        "/share/surlinfoinrecord",
        "/api/filemanager",
        "/apaas/1.0/share/list",
        "/apaas/1.0/share/transfer",
        "/share/transfer",
    ] {
        assert!(
            calls.iter().any(|(_, observed, _)| observed == path),
            "missing API {path}"
        );
    }
    assert!(
        calls
            .iter()
            .filter(|(_, path, body)| path == "/api/create"
                && body.contains("uploadid=synthetic-upload"))
            .count()
            == 2
    );
    assert!(
        calls
            .iter()
            .filter(|(_, path, body)| path == "/share/pset" && body.contains("path_list="))
            .count()
            == 2
    );
    eprintln!("control_api_audit: direct_requests=30 proxy_requests=0 modes=HTTP,SOCKS5");
}

async fn echo_origin(req: Request) -> Response<Body> {
    if req.uri().path() == "/cookies" {
        return Response::new(Body::from(
            req.headers()
                .get("cookie")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string(),
        ));
    }
    if req.uri().path() == "/redirect" {
        return Response::builder()
            .status(302)
            .header("location", "/data")
            .body(Body::empty())
            .unwrap();
    }
    if req.uri().path() == "/slow-step-2" {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    if req.headers().get("range").is_some() {
        return Response::builder()
            .status(206)
            .header("content-range", "bytes 4-9/10")
            .body(Body::from("456789"))
            .unwrap();
    }
    if req.method() == "POST" {
        let bytes = to_bytes(req.into_body(), 4096).await.unwrap();
        return Response::new(Body::from(bytes));
    }
    Response::new(Body::from("0123456789"))
}

async fn forward(State(hits): State<Arc<AtomicUsize>>, req: Request) -> Response<Body> {
    hits.fetch_add(1, Ordering::SeqCst);
    // Diagnostic probe must really use this proxy, and a rejected CONNECT is failure.
    if req.method() == "CONNECT" {
        return Response::builder()
            .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
            .body(Body::empty())
            .unwrap();
    }
    let (parts, body) = req.into_parts();
    let body = to_bytes(body, 4096).await.unwrap();
    let mut headers = parts.headers;
    headers.remove("proxy-authorization");
    let mut request = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .request(
            reqwest::Method::from_bytes(parts.method.as_str().as_bytes()).unwrap(),
            parts.uri.to_string(),
        );
    for (name, value) in &headers {
        request = request.header(name.as_str(), value.as_bytes());
    }
    let response = request.body(body).send().await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.bytes().await.unwrap();
    let mut result = Response::builder().status(status.as_u16());
    for (name, value) in &headers {
        result = result.header(name.as_str(), value.as_bytes());
    }
    result.body(Body::from(bytes)).unwrap()
}

#[tokio::test]
async fn http_control_direct_transfer_range_redirect_upload_and_diagnostic() {
    let origin = serve(Router::new().fallback(echo_origin)).await;
    let hits = Arc::new(AtomicUsize::new(0));
    let tunnel = serve(Router::new().fallback(forward).with_state(hits.clone())).await;
    let config = proxy(tunnel.address, true);
    let client = NetdiskClient::new_with_proxy(user(1), Some(&config), None).unwrap();
    let base = format!("http://{}", origin.address);
    for path in [
        "/login",
        "/warmup",
        "/list",
        "/locatedownload",
        "/precreate",
        "/merge",
        "/cloud_dl",
    ] {
        assert_eq!(
            client
                .client
                .get(format!("{base}{path}"))
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
    }
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "control endpoints must bypass the proxy"
    );
    let download =
        crate::downloader::DownloadEngine::build_download_client(Some(&config), false).unwrap();
    let response = download
        .get(format!("{base}/redirect"))
        .header("Range", "bytes=4-9")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 206);
    assert_eq!(response.headers()["content-range"], "bytes 4-9/10");
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"456789");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "redirect and Range both pass through proxy"
    );
    for _ in 0..2 {
        let form = reqwest::multipart::Form::new().part(
            "file",
            reqwest::multipart::Part::bytes(b"synthetic-file-data".to_vec()),
        );
        let response = client
            .send_upload_chunk(&format!("{base}/chunk"), form)
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert!(response.windows(19).any(|b| b == b"synthetic-file-data"));
    }
    assert_eq!(
        hits.load(Ordering::SeqCst),
        4,
        "upload and retransmit carry file bytes via proxy"
    );
    assert!(crate::common::probe_proxy(&config).await.is_err());
    assert_eq!(
        hits.load(Ordering::SeqCst),
        5,
        "diagnostic CONNECT also reaches proxy"
    );
}

#[tokio::test]
async fn legacy_config_roundtrip_no_proxy_and_scope_off() {
    let old: ProxyConfig = toml::from_str("proxy_type = 'none'").unwrap();
    assert!(!old.transfer_only);
    let origin = serve(Router::new().fallback(echo_origin)).await;
    let hits = Arc::new(AtomicUsize::new(0));
    let tunnel = serve(Router::new().fallback(forward).with_state(hits.clone())).await;
    let mut cfg = proxy(tunnel.address, false);
    for kind in [ProxyType::Http, ProxyType::Socks5] {
        cfg.proxy_type = kind;
        cfg.transfer_only = true;
        assert_eq!(
            toml::from_str::<ProxyConfig>(&toml::to_string(&cfg).unwrap()).unwrap(),
            cfg
        );
    }
    cfg.proxy_type = ProxyType::Http;
    cfg.transfer_only = false;
    let client = NetdiskClient::new_with_proxy(user(2), Some(&cfg), None).unwrap();
    client
        .client
        .get(format!("http://{}/list", origin.address))
        .send()
        .await
        .unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "scope off preserves legacy proxy behavior"
    );
    cfg.proxy_type = ProxyType::None;
    cfg.transfer_only = true;
    let client = NetdiskClient::new_with_proxy(user(2), Some(&cfg), None).unwrap();
    client
        .client
        .get(format!("http://{}/list", origin.address))
        .send()
        .await
        .unwrap();
    client
        .transfer_client
        .get(format!("http://{}/data", origin.address))
        .send()
        .await
        .unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "None never uses saved host/port"
    );

    cfg.username = Some("synthetic-proxy-user".into());
    cfg.password = Some("synthetic-proxy-password".into());
    assert!(!format!("{cfg:?}").contains("synthetic-proxy-"));
}

#[tokio::test]
async fn download_hot_update_changes_future_requests_without_invalidating_old_snapshot() {
    let origin = serve(Router::new().fallback(echo_origin)).await;
    let hits = Arc::new(AtomicUsize::new(0));
    let tunnel = serve(Router::new().fallback(forward).with_state(hits.clone())).await;
    let cfg = proxy(tunnel.address, true);
    let engine = crate::downloader::DownloadEngine::new_with_proxy(user(6), Some(&cfg), None);
    let old = engine.get_download_client();
    let url = format!("http://{}/data", origin.address);
    old.get(&url).send().await.unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    engine.update_proxy_and_rebuild_client(Some(&ProxyConfig::direct()));
    engine.get_download_client().get(&url).send().await.unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    old.get(&url).send().await.unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "an in-flight snapshot remains usable"
    );
    engine.update_proxy_and_rebuild_client(Some(&cfg));
    engine.get_download_client().get(&url).send().await.unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn failed_direct_control_does_not_pollute_health_and_fallback_is_respected() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unavailable = listener.local_addr().unwrap();
    drop(listener);
    let mut cfg = proxy(unavailable, true);
    cfg.allow_fallback = false;
    let mgr = Arc::new(ProxyFallbackManager::new());
    mgr.set_user_proxy_config(Some(cfg.clone())).await;
    let client = NetdiskClient::new_with_proxy(user(3), Some(&cfg), Some(mgr.clone())).unwrap();
    for _ in 0..4 {
        assert!(client
            .transfer_client
            .get("http://127.0.0.1:1/data")
            .send()
            .await
            .is_err());
        client.record_proxy_failure(&anyhow::anyhow!("connection refused"));
    }
    assert!(!mgr.is_fallen_back());
    cfg.allow_fallback = true;
    mgr.on_user_config_change(Some(&cfg)).await;
    let client = NetdiskClient::new_with_proxy(user(3), Some(&cfg), Some(mgr.clone())).unwrap();
    for _ in 0..4 {
        client.record_proxy_failure(&anyhow::anyhow!("connection refused"));
    }
    assert!(
        !mgr.is_fallen_back(),
        "control failures are not proxy failures"
    );
    for i in 0..3 {
        assert_eq!(mgr.record_failure(), i == 2);
    }
    let client = NetdiskClient::new_with_proxy(user(3), Some(&cfg), Some(mgr.clone())).unwrap();
    let origin = serve(Router::new().fallback(echo_origin)).await;
    client
        .transfer_client
        .get(format!("http://{}/data", origin.address))
        .send()
        .await
        .unwrap();
    assert_eq!(client.control_route(), "direct");
    mgr.on_user_config_change(None).await;
    for _ in 0..10 {
        assert!(!mgr.record_failure());
    }
    assert!(!mgr.is_fallen_back());
}

#[tokio::test]
async fn socks5_transports_only_file_data() {
    let origin = serve(Router::new().fallback(echo_origin)).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let observed = hits.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let observed = observed.clone();
            tokio::spawn(async move {
                let mut hello = [0; 2];
                stream.read_exact(&mut hello).await.unwrap();
                assert_eq!(hello[0], 5);
                let mut methods = vec![0; hello[1] as usize];
                stream.read_exact(&mut methods).await.unwrap();
                stream.write_all(&[5, 0]).await.unwrap();
                let mut request = [0; 4];
                stream.read_exact(&mut request).await.unwrap();
                let host = match request[3] {
                    1 => {
                        let mut ip = [0; 4];
                        stream.read_exact(&mut ip).await.unwrap();
                        std::net::Ipv4Addr::from(ip).to_string()
                    }
                    3 => {
                        let len = stream.read_u8().await.unwrap();
                        let mut name = vec![0; len as usize];
                        stream.read_exact(&mut name).await.unwrap();
                        String::from_utf8(name).unwrap()
                    }
                    _ => panic!("unexpected SOCKS address"),
                };
                let port = stream.read_u16().await.unwrap();
                let mut target = TcpStream::connect((host.as_str(), port)).await.unwrap();
                observed.fetch_add(1, Ordering::SeqCst);
                stream
                    .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                    .await
                    .unwrap();
                let _ = tokio::io::copy_bidirectional(&mut stream, &mut target).await;
            });
        }
    });
    let _server = Server { address, task };
    let mut cfg = proxy(address, true);
    cfg.proxy_type = ProxyType::Socks5;
    let client = NetdiskClient::new_with_proxy(user(4), Some(&cfg), None).unwrap();
    let url = format!("http://{}/data", origin.address);
    client.client.get(&url).send().await.unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    assert_eq!(
        client
            .transfer_client
            .get(&url)
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap()
            .as_ref(),
        b"0123456789"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn direct_ignores_environment_proxy_in_isolated_process() {
    if std::env::var_os("BAIDUPCS_ROUTE_TEST_CHILD").is_some() {
        let origin = serve(Router::new().fallback(echo_origin)).await;
        let client = NetdiskClient::new_with_proxy(
            user(5),
            Some(&proxy("127.0.0.1:1".parse().unwrap(), true)),
            None,
        )
        .unwrap();
        client
            .client
            .get(format!("http://{}/list", origin.address))
            .send()
            .await
            .unwrap();
        // Prove that environment auto discovery is active for an ordinary builder.
        assert!(reqwest::Client::new()
            .get(format!("http://{}/list", origin.address))
            .send()
            .await
            .is_err());
        return;
    }
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "netdisk::client::proxy_tests::direct_ignores_environment_proxy_in_isolated_process",
            "--nocapture",
        ])
        .env("BAIDUPCS_ROUTE_TEST_CHILD", "1")
        .env("HTTP_PROXY", "http://127.0.0.1:1")
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .env("ALL_PROXY", "http://127.0.0.1:1")
        .env("NO_PROXY", "")
        .env("http_proxy", "http://127.0.0.1:1")
        .env("no_proxy", "")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
}

#[tokio::test]
async fn account_cookie_jars_are_shared_between_routes_but_isolated_between_accounts() {
    let origin = serve(Router::new().fallback(echo_origin)).await;
    let hits = Arc::new(AtomicUsize::new(0));
    let tunnel = serve(Router::new().fallback(forward).with_state(hits)).await;
    let cfg = proxy(tunnel.address, true);
    let a = NetdiskClient::new_with_proxy(user(11), Some(&cfg), None).unwrap();
    let b = NetdiskClient::new_with_proxy(user(22), Some(&cfg), None).unwrap();
    let url = format!("http://{}/cookies", origin.address)
        .parse::<reqwest::Url>()
        .unwrap();
    a.cookie_jar
        .add_cookie_str("account=synthetic-a; Path=/", &url);
    b.cookie_jar
        .add_cookie_str("account=synthetic-b; Path=/", &url);
    for (client, expected) in [(&a, "account=synthetic-a"), (&b, "account=synthetic-b")] {
        for route in [&client.client, &client.transfer_client] {
            assert_eq!(
                route
                    .get(url.clone())
                    .send()
                    .await
                    .unwrap()
                    .text()
                    .await
                    .unwrap(),
                expected
            );
        }
    }
}

#[tokio::test]
async fn warmup_step_two_stall_is_bounded_and_logs_never_expose_cookies_or_queries() {
    #[derive(Clone)]
    struct Capture(Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    async fn cookie_response() -> Response<Body> {
        Response::builder()
            .header("set-cookie", "PANPSC=synthetic-secret-panpsc; Path=/")
            .body(Body::from("{\"bdstoken\":\"synthetic-secret-token\"}"))
            .unwrap()
    }
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let output = log.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || Capture(output.clone()))
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let origin = serve(
        Router::new()
            .route("/step-1", axum::routing::get(cookie_response))
            .fallback(echo_origin),
    )
    .await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let storage = Arc::new(tokio::sync::Mutex::new(None));
    let started = std::time::Instant::now();
    let result = bounded_warmup(std::time::Duration::from_millis(100), async {
        execute_warmup_request(
            &client,
            client.get(format!(
                "http://{}/step-1?sign=synthetic-secret-sign",
                origin.address
            )),
            "step-1",
            "direct",
            &storage,
        )
        .await?;
        execute_warmup_request(
            &client,
            client
                .get(format!(
                    "http://{}/slow-step-2?bduss=synthetic-secret-bduss",
                    origin.address
                ))
                .timeout(std::time::Duration::from_millis(30)),
            "step-2",
            "direct",
            &storage,
        )
        .await
    })
    .await;
    let error = result.unwrap_err().to_string();
    assert!(
        error.contains("step-2") && error.contains("timeout"),
        "{error}"
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    assert_eq!(
        storage.lock().await.as_deref(),
        Some("synthetic-secret-panpsc")
    );
    let logs = String::from_utf8(log.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("step-2"));
    assert!(
        !logs.contains("synthetic-secret"),
        "logs must contain names and lengths only"
    );
    assert!(!error.contains("synthetic-secret"));
}
