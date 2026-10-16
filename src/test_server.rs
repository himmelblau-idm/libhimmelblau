//! Scripted HTTP server shared by tests of flows that contact Entra ID.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use std::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

#[derive(Clone, Debug)]
pub(crate) struct Request {
    pub(crate) target: String,
    pub(crate) body: String,
}

pub(crate) struct Server {
    pub(crate) url: String,
    requests: Arc<Mutex<Vec<Request>>>,
    task: JoinHandle<()>,
}

impl Server {
    // Responses contain an optional $BASE placeholder for this server's ephemeral URL.
    pub(crate) async fn start(responses: Vec<String>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let base = url.clone();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let task = tokio::spawn(async move {
            let mut responses = responses.into_iter();
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let header_end = loop {
                    let mut buf = [0; 4096];
                    let count = stream.read(&mut buf).await.unwrap();
                    assert_ne!(count, 0, "incomplete HTTP headers");
                    bytes.extend_from_slice(&buf[..count]);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        break end + 4;
                    }
                };
                let headers = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
                let length: usize = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().unwrap())
                    })
                    .unwrap_or(0);
                while bytes.len() < header_end + length {
                    let mut buf = [0; 4096];
                    let count = stream.read(&mut buf).await.unwrap();
                    assert_ne!(count, 0, "incomplete HTTP body");
                    bytes.extend_from_slice(&buf[..count]);
                }
                captured.lock().unwrap().push(Request {
                    target: headers
                        .lines()
                        .next()
                        .unwrap()
                        .trim_end_matches(" HTTP/1.1")
                        .to_string(),
                    body: String::from_utf8(bytes[header_end..header_end + length].to_vec())
                        .unwrap(),
                });
                let response = responses
                    .next()
                    .unwrap_or_else(|| "500 Unexpected request\r\n\r\n".into())
                    .replace("$BASE", &base);
                let (status_headers, body) = response.split_once("\r\n\r\n").unwrap();
                let wire = format!("HTTP/1.1 {status_headers}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                stream.write_all(wire.as_bytes()).await.unwrap();
            }
        });
        Self {
            url,
            requests,
            task,
        }
    }

    pub(crate) fn client(&self) -> PublicClientApplication {
        let mut app = PublicClientApplication::new(
            "synthetic-client",
            Some(&self.url),
            #[cfg(feature = "set_timeout")]
            Duration::from_secs(3),
            #[cfg(feature = "ipvers")]
            &[],
        )
        .unwrap();
        app.app.client = isolated_client(&app.app.jar);
        app
    }

    pub(crate) fn requests(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(crate) fn json_response(body: &Value) -> String {
    format!("200 OK\r\nContent-Type: application/json\r\n\r\n{body}")
}

// Isolate fixtures from developer proxy settings without changing production behavior.
pub(crate) fn isolated_client(jar: &Arc<CookieStoreMutex>) -> Client {
    Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(3))
        .cookie_provider(jar.clone())
        .build()
        .unwrap()
}
