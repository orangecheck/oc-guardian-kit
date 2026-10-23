//! Liveness and setup phase of the wrapped fedimintd daemon.

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use tracing::info;

use crate::config::FedimintdRuntime;
use crate::run::probe_version;
use crate::run::resolve_binary;

/// Is fedimintd's API port answering at all? Any HTTP response (even an
/// upgrade-required / 4xx) means the port is bound + serving; only a
/// connection failure counts as down. Liveness only: an un-set-up guardian
/// answers too, so this never says DKG is done (see [`phase`]).
pub fn api_up(rt: &FedimintdRuntime) -> bool {
    let url = rt.local_api_base();
    let resp = ureq::get(&url).timeout(Duration::from_secs(3)).call();
    match resp {
        Ok(_) => true,
        // Reached the server but it returned an HTTP error → still "up".
        Err(ureq::Error::Status(_, _)) => true,
        // Transport error (connection refused, timeout) → down.
        Err(_) => false,
    }
}

/// Where a guardian is in setup, from fedimintd's `setup_status`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Nothing answered on the API port.
    Unreachable,
    /// Nobody has set local params: the first caller sets the password.
    AwaitingLocalParams,
    /// Local params are set; setup codes are being exchanged or DKG is running.
    Setup(String),
    /// DKG is complete and the federation is running consensus.
    ConsensusRunning,
}

impl Phase {
    fn from_status(raw: &str) -> Self {
        let s: String = raw
            .chars()
            .filter(|c| c.is_ascii_alphabetic())
            .collect::<String>()
            .to_ascii_lowercase();
        match s.as_str() {
            "awaitinglocalparams" => Phase::AwaitingLocalParams,
            "consensusrunning" | "consensusisrunning" => Phase::ConsensusRunning,
            _ => Phase::Setup(raw.to_string()),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Phase::Unreachable => "UNREACHABLE · nothing answers on the API port".into(),
            Phase::AwaitingLocalParams => {
                "SETUP · no local params yet: run `oc-guardian ceremony start`".into()
            }
            Phase::Setup(s) => format!("SETUP · {s}"),
            Phase::ConsensusRunning => "RUNNING · DKG complete, consensus is running".into(),
        }
    }
}

/// A JSON-RPC failure from fedimintd, or no answer at all.
#[derive(Debug)]
pub enum RpcError {
    Transport(String),
    Rpc(String),
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::Transport(m) => write!(f, "fedimintd did not answer: {m}"),
            RpcError::Rpc(m) => write!(f, "fedimintd refused: {m}"),
        }
    }
}

impl std::error::Error for RpcError {}

/// Call a fedimintd API method: JSON-RPC 2.0 over HTTP POST, the single
/// param wrapped as `{ params, auth? }` the way fedimintd's ApiRequest is.
pub fn rpc(base: &str, method: &str, inner: Value, auth: Option<&str>) -> Result<Value, RpcError> {
    let mut wrapper = json!({ "params": inner });
    if let Some(pw) = auth {
        wrapper["auth"] = json!(pw);
    }
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": [wrapper] });
    let resp = ureq::post(base)
        .timeout(Duration::from_secs(10))
        .set("Content-Type", "application/json")
        .send_string(&body.to_string());
    let text = match resp {
        Ok(r) => r.into_string(),
        Err(ureq::Error::Status(code, r)) => {
            let text = r.into_string().unwrap_or_default();
            if serde_json::from_str::<Value>(&text).is_err() {
                return Err(RpcError::Rpc(format!("HTTP {code} on {method}")));
            }
            Ok(text)
        }
        Err(e) => return Err(RpcError::Transport(e.to_string())),
    }
    .map_err(|e| RpcError::Transport(e.to_string()))?;
    let v: Value = serde_json::from_str(&text)
        .map_err(|_| RpcError::Rpc(format!("{method} did not answer JSON-RPC")))?;
    if let Some(err) = v.get("error") {
        let msg = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("error");
        return Err(RpcError::Rpc(format!("{method}: {msg}")));
    }
    v.get("result")
        .cloned()
        .ok_or_else(|| RpcError::Rpc(format!("{method} answered without a result")))
}

/// The guardian's phase, asked of fedimintd itself. A reply that is not a
/// `setup_status` answer is never taken as "running".
pub fn phase_at(base: &str) -> Result<Phase> {
    match rpc(base, "setup_status", Value::Null, None) {
        Ok(Value::String(s)) => Ok(Phase::from_status(&s)),
        Ok(other) => Err(anyhow!("setup_status answered {other}, not a phase")),
        Err(RpcError::Transport(_)) => Ok(Phase::Unreachable),
        Err(e) => Err(anyhow!(e)),
    }
}

pub fn phase(rt: &FedimintdRuntime) -> Result<Phase> {
    phase_at(&rt.local_api_base())
}

/// CLI entrypoint: print the daemon's status. `bin_hint` is the same
/// fedimintd binary path `fedimintd run --config` takes.
pub fn report(bin_hint: &str) -> Result<()> {
    let rt = FedimintdRuntime::from_env().context("resolving runtime from env")?;
    let bin = resolve_binary(bin_hint);
    let version = probe_version(&bin);
    let up = api_up(&rt);
    let phase = phase(&rt)
        .map(|p| p.describe())
        .unwrap_or_else(|e| format!("UNKNOWN · {e}"));
    info!(
        federation = %rt.federation_slug,
        operator = %rt.operator_id,
        version,
        api = %rt.api_url(),
        up,
        "fedimintd status"
    );
    println!(
        "fedimintd · federation={} · version={} · api={} · up={} · phase={}",
        rt.federation_slug,
        version,
        rt.api_url(),
        up,
        phase
    );
    Ok(())
}

#[cfg(test)]
pub(crate) mod stub {
    //! A one-thread HTTP server standing in for fedimintd's API port.

    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    /// (method, json-rpc method or "", body) → (status, body)
    pub type Handler = dyn Fn(&str, &str, &serde_json::Value) -> (u16, String) + Send + Sync;

    pub struct Stub {
        pub base: String,
        pub calls: Arc<Mutex<Vec<(String, serde_json::Value)>>>,
    }

    pub fn serve(handler: Box<Handler>) -> Stub {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let calls = Arc::new(Mutex::new(Vec::new()));
        let seen = calls.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    continue;
                }
                let verb = line.split_whitespace().next().unwrap_or("").to_string();
                let mut len = 0usize;
                loop {
                    let mut h = String::new();
                    reader.read_line(&mut h).unwrap();
                    if h == "\r\n" || h.is_empty() {
                        break;
                    }
                    if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0u8; len];
                reader.read_exact(&mut body).unwrap();
                let json: serde_json::Value =
                    serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
                let method = json["method"].as_str().unwrap_or("").to_string();
                if !method.is_empty() {
                    seen.lock()
                        .unwrap()
                        .push((method.clone(), json["params"][0].clone()));
                }
                let (status, out) = handler(&verb, &method, &json);
                let reason = if status == 200 { "OK" } else { "Error" };
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{out}",
                    out.len()
                );
            }
        });
        Stub { base, calls }
    }

    pub fn result(v: serde_json::Value) -> (u16, String) {
        (
            200,
            serde_json::json!({"jsonrpc":"2.0","id":1,"result":v}).to_string(),
        )
    }

    pub fn error(msg: &str) -> (u16, String) {
        (
            200,
            serde_json::json!({"jsonrpc":"2.0","id":1,"error":{"code":1024,"message":msg}})
                .to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::stub::{error, result, serve};
    use super::*;

    #[test]
    fn a_guardian_in_setup_is_not_running_though_it_answers_http() {
        // fedimintd during setup: 405 to a plain GET, a setup phase to setup_status.
        let s = serve(Box::new(|verb, method, _| match (verb, method) {
            ("GET", _) => (405, String::new()),
            (_, "setup_status") => result(json!("AwaitingLocalParams")),
            _ => error("unknown method"),
        }));
        assert_eq!(phase_at(&s.base).unwrap(), Phase::AwaitingLocalParams);
        let s = serve(Box::new(|_, _, _| result(json!("SharingConnectionCodes"))));
        assert_eq!(
            phase_at(&s.base).unwrap(),
            Phase::Setup("SharingConnectionCodes".into())
        );
    }

    #[test]
    fn running_only_when_fedimintd_says_consensus_is_running() {
        for raw in ["ConsensusIsRunning", "ConsensusRunning"] {
            let s = serve(Box::new(move |_, _, _| result(json!(raw))));
            assert_eq!(phase_at(&s.base).unwrap(), Phase::ConsensusRunning);
        }
    }

    #[test]
    fn a_server_that_is_not_fedimintd_is_never_running() {
        let s = serve(Box::new(|_, _, _| (405, "method not allowed".into())));
        assert!(phase_at(&s.base).is_err());
        let s = serve(Box::new(|_, _, _| result(json!({"status": "ok"}))));
        assert!(phase_at(&s.base).is_err());
    }

    #[test]
    fn nothing_listening_is_unreachable() {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        assert_eq!(
            phase_at(&format!("http://127.0.0.1:{port}")).unwrap(),
            Phase::Unreachable
        );
    }

    #[test]
    fn rpc_wraps_the_param_and_carries_auth_inside() {
        let s = serve(Box::new(|_, _, _| result(json!("code"))));
        rpc(
            &s.base,
            "set_local_params",
            json!({"name": "g0"}),
            Some("pw"),
        )
        .unwrap();
        let calls = s.calls.lock().unwrap();
        assert_eq!(calls[0].0, "set_local_params");
        assert_eq!(calls[0].1, json!({"params": {"name": "g0"}, "auth": "pw"}));
    }
}
