use anyhow::{Context, Result, bail, ensure};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{Message, protocol::WebSocketConfig},
};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_MESSAGE: usize = 4 * 1024 * 1024;
const MAX_PENDING: usize = 32;
type Reply = oneshot::Sender<Result<Value>>;
struct Command {
    method: &'static str,
    params: Value,
    session: Option<String>,
    reply: Reply,
}
struct Connection {
    commands: mpsc::Sender<Command>,
    _events: broadcast::Sender<Value>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.task.abort();
    }
}
#[derive(Clone)]
pub(super) struct Cdp(Arc<Connection>);
impl Cdp {
    pub async fn connect(endpoint: &str) -> Result<Self> {
        let url = url::Url::parse(endpoint)?;
        ensure!(
            url.scheme() == "ws"
                && url.host_str() == Some("127.0.0.1")
                && url.username().is_empty()
                && url.password().is_none()
                && url.path().starts_with("/devtools/browser/"),
            "CDP endpoint must be a local browser socket"
        );
        let config = WebSocketConfig::default()
            .max_message_size(Some(MAX_MESSAGE))
            .max_frame_size(Some(MAX_MESSAGE));
        let (mut socket, _) = tokio::time::timeout(
            COMMAND_TIMEOUT,
            connect_async_with_config(endpoint, Some(config), true),
        )
        .await
        .context("CDP connection timed out")??;
        let (commands, mut rx) = mpsc::channel::<Command>(MAX_PENDING);
        let (events, _) = broadcast::channel(128);
        let event_tx = events.clone();
        let task = tokio::spawn(async move {
            let mut pending = HashMap::<u64, Reply>::new();
            let mut next_id = 0u64;
            loop {
                tokio::select! {
                    command = rx.recv() => {
                        let Some(command) = command else { break };
                        pending.retain(|_, reply| !reply.is_closed());
                        if command.reply.is_closed() { continue; }
                        if pending.len() >= MAX_PENDING {
                            let _ = command.reply.send(Err(anyhow::anyhow!("CDP command limit reached")));
                            continue;
                        }
                        next_id += 1;
                        let mut message = json!({"id":next_id,"method":command.method,"params":command.params});
                        if let Some(session) = command.session { message["sessionId"] = session.into(); }
                        pending.insert(next_id, command.reply);
                        if !matches!(tokio::time::timeout(COMMAND_TIMEOUT, socket.send(Message::Text(message.to_string().into()))).await, Ok(Ok(()))) { break; }
                    }
                    frame = socket.next() => {
                        match frame {
                            Some(Ok(Message::Text(text))) => {
                                let Ok(mut value) = serde_json::from_str::<Value>(&text) else { break };
                                if let Some(id) = value["id"].as_u64() {
                                    if let Some(reply) = pending.remove(&id) {
                                        let result = if let Some(error) = value.get("error") {
                                            // Protocol messages contain diagnostics; never include command parameters.
                                            Err(anyhow::anyhow!("CDP {}: {}", error["code"], error["message"].as_str().unwrap_or("command failed")))
                                        } else { Ok(value["result"].take()) };
                                        let _ = reply.send(result);
                                    }
                                } else if value["method"].is_string() { let _ = event_tx.send(value); }
                            }
                            Some(Ok(Message::Ping(bytes))) => {
                                if !matches!(tokio::time::timeout(COMMAND_TIMEOUT, socket.send(Message::Pong(bytes))).await, Ok(Ok(()))) { break; }
                            }
                            Some(Ok(Message::Pong(_))) => {}
                            _ => break,
                        }
                    }
                }
            }
            // Dropping senders releases every waiting caller after disconnect.
        });
        Ok(Self(Arc::new(Connection {
            commands,
            _events: events,
            task,
        })))
    }
    pub async fn call(
        &self,
        session: Option<&str>,
        method: &'static str,
        params: Value,
    ) -> Result<Value> {
        let (reply, receive) = oneshot::channel();
        tokio::time::timeout(COMMAND_TIMEOUT, async {
            self.0
                .commands
                .send(Command {
                    method,
                    params,
                    session: session.map(str::to_owned),
                    reply,
                })
                .await
                .map_err(|_| anyhow::anyhow!("CDP disconnected"))?;
            receive.await.context("CDP disconnected before replying")?
        })
        .await
        .with_context(|| format!("CDP {method} timed out"))?
    }
    #[cfg(test)]
    pub fn events(&self) -> broadcast::Receiver<Value> {
        self.0._events.subscribe()
    }
    pub async fn new_page(&self) -> Result<Page> {
        let target = self
            .call(None, "Target.createTarget", json!({"url":"about:blank"}))
            .await?;
        let target = target["targetId"]
            .as_str()
            .context("CDP target ID missing")?
            .to_owned();
        let attached = self
            .call(
                None,
                "Target.attachToTarget",
                json!({"targetId":target,"flatten":true}),
            )
            .await?;
        let session = attached["sessionId"]
            .as_str()
            .context("CDP session ID missing")?
            .to_owned();
        let page = Page {
            cdp: self.clone(),
            target,
            session,
        };
        page.call("Page.enable", json!({})).await?;
        page.call("Runtime.enable", json!({})).await?;
        Ok(page)
    }
}
#[derive(Clone)]
pub(super) struct Page {
    cdp: Cdp,
    target: String,
    pub session: String,
}
impl Page {
    pub async fn call(&self, method: &'static str, params: Value) -> Result<Value> {
        self.cdp.call(Some(&self.session), method, params).await
    }
    pub async fn evaluate(&self, expression: &str) -> Result<Value> {
        let mut result = self
            .call(
                "Runtime.evaluate",
                json!({"expression":expression,"returnByValue":true,"awaitPromise":true}),
            )
            .await?;
        if result.get("exceptionDetails").is_some() {
            bail!("CDP JavaScript evaluation failed");
        }
        Ok(result["result"]["value"].take())
    }
    pub async fn close(&self) -> Result<()> {
        self.cdp
            .call(None, "Target.closeTarget", json!({"targetId":self.target}))
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use tokio_tungstenite::accept_async;

    #[tokio::test]
    async fn commands_match_ids_events_keep_sessions_and_errors_do_not_leak_params() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!(
            "ws://{}/devtools/browser/fixture",
            listener.local_addr().unwrap()
        );
        let server = tokio::spawn(async move {
            let mut socket = accept_async(listener.accept().await.unwrap().0)
                .await
                .unwrap();
            let mut requests = Vec::new();
            for _ in 0..2 {
                let message = socket.next().await.unwrap().unwrap();
                requests.push(serde_json::from_str::<Value>(message.to_text().unwrap()).unwrap());
            }
            socket
                .send(Message::Text(
                    json!({"method":"Page.loadEventFired","sessionId":"page-a","params":{}})
                        .to_string()
                        .into(),
                ))
                .await
                .unwrap();
            for request in requests.into_iter().rev() {
                let result = if request["method"] == "fixture.error" {
                    json!({"id":request["id"],"error":{"code":-32000,"message":"Execution context was destroyed"}})
                } else {
                    assert_eq!(request["sessionId"], "page-a");
                    json!({"id":request["id"],"result":{"answer":42}})
                };
                socket
                    .send(Message::Text(result.to_string().into()))
                    .await
                    .unwrap();
            }
        });
        let cdp = Cdp::connect(&endpoint).await.unwrap();
        let mut events = cdp.events();
        let (answer, error) = tokio::join!(
            cdp.call(Some("page-a"), "fixture.ok", json!({})),
            cdp.call(None, "fixture.error", json!({"secret":"never-print-this"})),
        );
        assert_eq!(answer.unwrap()["answer"], 42);
        let error = error.unwrap_err().to_string();
        assert!(error.contains("-32000"));
        assert!(!error.contains("never-print-this"));
        assert_eq!(events.recv().await.unwrap()["sessionId"], "page-a");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_request_cannot_consume_next_response_and_disconnect_releases_waiters() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!(
            "ws://{}/devtools/browser/fixture",
            listener.local_addr().unwrap()
        );
        let (seen_tx, seen_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut socket = accept_async(listener.accept().await.unwrap().0)
                .await
                .unwrap();
            let first = socket.next().await.unwrap().unwrap();
            let first: Value = serde_json::from_str(first.to_text().unwrap()).unwrap();
            seen_tx.send(()).unwrap();
            let second = socket.next().await.unwrap().unwrap();
            let second: Value = serde_json::from_str(second.to_text().unwrap()).unwrap();
            for (request, answer) in [(first, "old"), (second, "new")] {
                socket
                    .send(Message::Text(
                        json!({"id":request["id"],"result":{"answer":answer}})
                            .to_string()
                            .into(),
                    ))
                    .await
                    .unwrap();
            }
            let _ = socket.next().await;
            socket.close(None).await.unwrap();
        });
        let cdp = Cdp::connect(&endpoint).await.unwrap();
        let clone = cdp.clone();
        let cancelled =
            tokio::spawn(async move { clone.call(None, "fixture.cancel", json!({})).await });
        seen_rx.await.unwrap();
        cancelled.abort();
        let _ = cancelled.await;
        assert_eq!(
            cdp.call(None, "fixture.next", json!({})).await.unwrap()["answer"],
            "new"
        );
        assert!(
            cdp.call(None, "fixture.close", json!({}))
                .await
                .unwrap_err()
                .to_string()
                .contains("disconnected")
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn cdp_refuses_nonlocal_and_tls_endpoints() {
        for endpoint in [
            "wss://127.0.0.1/devtools/browser/x",
            "ws://example.com/devtools/browser/x",
            "ws://user@127.0.0.1/devtools/browser/x",
            "ws://127.0.0.1/other",
        ] {
            assert!(Cdp::connect(endpoint).await.is_err());
        }
    }
}
