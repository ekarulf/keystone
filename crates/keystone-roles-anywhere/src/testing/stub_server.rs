//! A minimal HTTP/1.1 server for exercising the `CreateSession` transport.
//!
//! Written by hand rather than pulled from a crate so the tests observe the
//! exact bytes Keystone puts on the wire: the signature covers those bytes, and
//! a mocking library that normalizes headers would hide a mismatch. Plain HTTP
//! is enough — TLS is `reqwest`'s concern, not Keystone's.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};

/// One request as the server saw it.
#[derive(Debug, Clone)]
pub struct CapturedRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl CapturedRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    pub fn body_json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("request body is JSON")
    }
}

/// A canned response.
#[derive(Debug, Clone)]
pub struct StubResponse {
    pub status: u16,
    pub body: String,
    pub headers: Vec<(String, String)>,
}

impl StubResponse {
    pub fn ok(body: impl Into<String>) -> Self {
        Self {
            status: 200,
            body: body.into(),
            headers: Vec::new(),
        }
    }

    pub fn error(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            body: body.into(),
            headers: Vec::new(),
        }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }
}

/// A server that replies with a scripted sequence of responses.
pub struct StubServer {
    base_url: String,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    shutdown: Option<mpsc::Sender<()>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl StubServer {
    /// Start a server that answers each request with the next scripted
    /// response, repeating the last one if it runs out.
    pub fn start(responses: Vec<StubResponse>) -> Self {
        assert!(!responses.is_empty(), "a stub server needs a response");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let base_url = format!("http://{}", listener.local_addr().expect("local addr"));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (shutdown_tx, shutdown_rx) = mpsc::channel();

        let thread_requests = Arc::clone(&requests);
        let handle = std::thread::spawn(move || {
            serve(listener, responses, thread_requests, shutdown_rx);
        });

        Self {
            base_url,
            requests,
            shutdown: Some(shutdown_tx),
            handle: Some(handle),
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn requests(&self) -> Vec<CapturedRequest> {
        self.requests.lock().expect("requests lock").clone()
    }

    pub fn request_count(&self) -> usize {
        self.requests.lock().expect("requests lock").len()
    }
}

impl Drop for StubServer {
    fn drop(&mut self) {
        drop(self.shutdown.take());
        // Unblock the accept loop so the thread notices the shutdown signal.
        let _ = std::net::TcpStream::connect(self.base_url.trim_start_matches("http://"));
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn serve(
    listener: TcpListener,
    responses: Vec<StubResponse>,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    shutdown: Receiver<()>,
) {
    let mut served = 0usize;
    for stream in listener.incoming() {
        if shutdown.try_recv() != Err(mpsc::TryRecvError::Empty) {
            return;
        }
        let mut stream = match stream {
            Ok(stream) => stream,
            Err(_) => return,
        };
        let request = match read_request(&mut stream) {
            Some(request) => request,
            // The shutdown probe connects without sending anything.
            None => continue,
        };
        requests.lock().expect("requests lock").push(request);

        let response = &responses[served.min(responses.len() - 1)];
        served += 1;
        write_response(&mut stream, response);
    }
}

fn read_request(stream: &mut TcpStream) -> Option<CapturedRequest> {
    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));

    let mut request_line = String::new();
    if reader.read_line(&mut request_line).ok()? == 0 {
        return None;
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();

    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            break;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    let length: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    if length > 0 {
        reader.read_exact(&mut body).ok()?;
    }

    Some(CapturedRequest {
        method,
        path,
        headers,
        body,
    })
}

fn write_response(stream: &mut TcpStream, response: &StubResponse) {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        response.status,
        reason(response.status),
        response.body.len()
    );
    for (name, value) in &response.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(response.body.as_bytes());
    let _ = stream.flush();
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}
