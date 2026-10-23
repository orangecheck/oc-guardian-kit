//! The setup gate.
//!
//! Until DKG is done, fedimintd 0.11 serves an unauthenticated setup API on
//! its API port: whoever first calls `set_local_params` sets the guardian's
//! password. It also forgets local params whenever it restarts. So while a
//! guardian with `OC_GUARDIAN_SETUP_PASSWORD` has no consensus config, the
//! kit keeps fedimintd's API on loopback and answers the public API bind
//! itself, passing on a JSON-RPC call only if it carries that password.
//! `setup_status` and `invite_code` pass without one. Once DKG writes the
//! consensus config, the kit closes the gate and fedimintd takes the public
//! bind again.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::{json, Value};
use tracing::warn;

/// Methods anyone may call during setup: they read, and set nothing.
const OPEN_METHODS: &[&str] = &["setup_status", "invite_code"];
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 64 * 1024;

/// Whether the gate passes a JSON-RPC request on. Err carries the refusal.
pub fn decide(body: &Value, password: &str) -> Result<(), &'static str> {
    if !body.is_object() {
        return Err("send one JSON-RPC request at a time while this guardian is in setup");
    }
    let method = body["method"].as_str().ok_or("not a JSON-RPC request")?;
    if OPEN_METHODS.contains(&method) {
        return Ok(());
    }
    match body["params"][0]["auth"].as_str() {
        Some(auth) if same(auth.as_bytes(), password.as_bytes()) => Ok(()),
        _ => Err("this guardian is in setup: only its setup password may call that"),
    }
}

/// Byte equality whose time does not depend on where the inputs differ.
fn same(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A running gate. Dropping it does not stop it; call [`Gate::stop`].
pub struct Gate {
    stop: Arc<AtomicBool>,
    ready: Arc<AtomicBool>,
    handle: JoinHandle<()>,
    pub addr: std::net::SocketAddr,
}

impl Gate {
    /// While not ready, every call gets "this guardian is starting" and
    /// nothing reaches fedimintd: the kit is still setting local params.
    pub fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::SeqCst);
    }

    pub fn stop(self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = self.handle.join();
    }
}

/// Listen on `bind` and forward what passes to `upstream` (an http:// base).
/// The gate starts ready unless `ready` is false.
pub fn start(bind: &str, upstream: String, password: String, ready: bool) -> Result<Gate> {
    let listener =
        TcpListener::bind(bind).with_context(|| format!("binding the setup gate on {bind}"))?;
    listener
        .set_nonblocking(true)
        .context("setting the setup gate non-blocking")?;
    let addr = listener
        .local_addr()
        .context("reading the gate's address")?;
    let stop = Arc::new(AtomicBool::new(false));
    let ready = Arc::new(AtomicBool::new(ready));
    let (flag, is_ready) = (stop.clone(), ready.clone());
    let handle = std::thread::spawn(move || {
        while !flag.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let (up, pw) = (upstream.clone(), password.clone());
                    let open = is_ready.load(Ordering::SeqCst);
                    std::thread::spawn(move || {
                        if let Err(e) = serve(stream, &up, &pw, open) {
                            warn!(error = %e, "setup gate · dropped a request");
                        }
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(e) => {
                    warn!(error = %e, "setup gate · accept failed");
                    std::thread::sleep(Duration::from_millis(250));
                }
            }
        }
    });
    Ok(Gate {
        stop,
        ready,
        handle,
        addr,
    })
}

fn serve(mut stream: TcpStream, upstream: &str, password: &str, ready: bool) -> Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let verb = line.split_whitespace().next().unwrap_or("").to_string();
    let mut len = 0usize;
    let mut header_bytes = line.len();
    loop {
        let mut h = String::new();
        let n = reader.read_line(&mut h)?;
        header_bytes += n;
        if n == 0 || h == "\r\n" || h == "\n" || header_bytes > MAX_HEADER_BYTES {
            break;
        }
        if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
            len = v.trim().parse().unwrap_or(usize::MAX);
        }
    }
    if verb != "POST" {
        return respond(&mut stream, 405, "");
    }
    if len > MAX_BODY_BYTES {
        return respond(&mut stream, 413, "");
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body)?;
    let Ok(request) = serde_json::from_slice::<Value>(&body) else {
        let err =
            json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error"}});
        return respond(&mut stream, 400, &err.to_string());
    };
    if !ready {
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let err = json!({"jsonrpc":"2.0","id":id,"error":{"code":-32003,"message":"this guardian is starting"}});
        return respond(&mut stream, 200, &err.to_string());
    }
    if let Err(why) = decide(&request, password) {
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let err = json!({"jsonrpc":"2.0","id":id,"error":{"code":-32001,"message":why}});
        return respond(&mut stream, 200, &err.to_string());
    }
    let (status, text) = match ureq::post(upstream)
        .timeout(Duration::from_secs(30))
        .set("Content-Type", "application/json")
        .send_bytes(&body)
    {
        Ok(r) => (r.status(), r.into_string().unwrap_or_default()),
        Err(ureq::Error::Status(code, r)) => (code, r.into_string().unwrap_or_default()),
        Err(_) => {
            let err = json!({"jsonrpc":"2.0","id":request.get("id").cloned().unwrap_or(Value::Null),
                "error":{"code":-32002,"message":"fedimintd did not answer"}});
            (502, err.to_string())
        }
    };
    respond(&mut stream, status, &text)
}

fn respond(stream: &mut TcpStream, status: u16, body: &str) -> Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        502 => "Bad Gateway",
        _ => "Error",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    Ok(())
}

/// A free loopback port for fedimintd's API while the gate holds the public one.
pub fn free_loopback_port() -> Result<u16> {
    Ok(TcpListener::bind("127.0.0.1:0")
        .context("finding a free loopback port")?
        .local_addr()?
        .port())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::stub::{error, result, serve as stub};

    fn req(method: &str, auth: Option<&str>) -> Value {
        let mut w = json!({"params": null});
        if let Some(a) = auth {
            w["auth"] = json!(a);
        }
        json!({"jsonrpc":"2.0","id":7,"method":method,"params":[w]})
    }

    #[test]
    fn only_the_setup_password_passes_a_call_that_sets_anything() {
        for m in [
            "set_local_params",
            "add_peer_setup_code",
            "start_dkg",
            "get_setup_code",
        ] {
            assert!(decide(&req(m, None), "pw").is_err(), "{m} without auth");
            assert!(
                decide(&req(m, Some("other")), "pw").is_err(),
                "{m} wrong auth"
            );
            assert!(
                decide(&req(m, Some("pwx")), "pw").is_err(),
                "{m} longer auth"
            );
            assert!(decide(&req(m, Some("pw")), "pw").is_ok(), "{m} right auth");
        }
        assert!(decide(&req("setup_status", None), "pw").is_ok());
        assert!(decide(&req("invite_code", None), "pw").is_ok());
    }

    #[test]
    fn batches_and_non_requests_are_refused() {
        let batch = json!([req("setup_status", None), req("set_local_params", None)]);
        assert!(decide(&batch, "pw").is_err());
        assert!(decide(&json!({"params": []}), "pw").is_err());
        assert!(decide(&json!("set_local_params"), "pw").is_err());
    }

    fn post(addr: std::net::SocketAddr, body: &Value) -> (u16, Value) {
        match ureq::post(&format!("http://{addr}/"))
            .set("Content-Type", "application/json")
            .send_string(&body.to_string())
        {
            Ok(r) => (r.status(), r.into_json().unwrap_or(Value::Null)),
            Err(ureq::Error::Status(c, r)) => (c, r.into_json().unwrap_or(Value::Null)),
            Err(e) => panic!("{e}"),
        }
    }

    #[test]
    fn the_gate_forwards_what_passes_and_never_forwards_what_does_not() {
        let up = stub(Box::new(|_, m, _| match m {
            "setup_status" => result(json!("AwaitingLocalParams")),
            "set_local_params" => result(json!("code")),
            _ => error("unexpected"),
        }));
        let gate = start("127.0.0.1:0", up.base.clone(), "pw".into(), true).unwrap();

        let (_, r) = post(gate.addr, &req("setup_status", None));
        assert_eq!(r["result"], json!("AwaitingLocalParams"));

        let (_, r) = post(gate.addr, &req("set_local_params", Some("attacker")));
        assert_eq!(r["id"], json!(7));
        assert!(r["error"]["message"]
            .as_str()
            .unwrap()
            .contains("setup password"));
        assert!(!up
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|c| c.0 == "set_local_params"));

        let (_, r) = post(gate.addr, &req("set_local_params", Some("pw")));
        assert_eq!(r["result"], json!("code"));
        assert_eq!(
            up.calls.lock().unwrap().last().unwrap().0,
            "set_local_params"
        );

        let status = match ureq::get(&format!("http://{}/", gate.addr)).call() {
            Err(ureq::Error::Status(c, _)) => c,
            other => panic!("{other:?}"),
        };
        assert_eq!(status, 405);
        gate.stop();
    }

    #[test]
    fn a_gate_that_is_not_ready_answers_starting_and_forwards_nothing() {
        let up = stub(Box::new(|_, _, _| result(json!("AwaitingLocalParams"))));
        let gate = start("127.0.0.1:0", up.base.clone(), "pw".into(), false).unwrap();
        for r in [
            req("setup_status", None),
            req("set_local_params", Some("pw")),
        ] {
            let (_, body) = post(gate.addr, &r);
            assert_eq!(body["error"]["code"], json!(-32003));
        }
        assert!(up.calls.lock().unwrap().is_empty());
        gate.set_ready(true);
        let (_, body) = post(gate.addr, &req("setup_status", None));
        assert_eq!(body["result"], json!("AwaitingLocalParams"));
        gate.stop();
    }
}
