use std::collections::HashMap;

use serde_json::json;

/// Per-severity channel routing. Defaults: Critical → telegram,
/// Warning → telegram, Info → none (timeline only).
pub fn default_routing() -> HashMap<String, Vec<String>> {
    let mut m = HashMap::new();
    m.insert("Critical".into(), vec!["telegram".into()]);
    m.insert("Warning".into(), vec!["telegram".into()]);
    m.insert("Info".into(), vec![]);
    m
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct NotifyConfig {
    pub webhook_url: String,
    pub slack_url: String,
    pub telegram_token: Option<String>,
    pub telegram_chat_id: Option<i64>,
    pub telegram_password: Option<String>,
    pub routing: HashMap<String, Vec<String>>,
}

impl Default for NotifyConfig {
    fn default() -> Self {
        NotifyConfig {
            webhook_url: String::new(),
            slack_url: String::new(),
            telegram_token: None,
            telegram_chat_id: None,
            telegram_password: None,
            routing: default_routing(),
        }
    }
}

/// Channels configured for a severity.
pub fn channels_for(cfg: &NotifyConfig, severity: &str) -> Vec<String> {
    cfg.routing.get(severity).cloned().unwrap_or_default()
}

/// Generic webhook payload — the full incident anatomy.
pub fn webhook_payload(incident_json: &serde_json::Value, ui_base_url: &str) -> String {
    serde_json::to_string(&json!({
        "type": "watchtower.incident",
        "severity": incident_json["severity"],
        "status": incident_json["status"],
        "headline": incident_json["headline"],
        "cause": incident_json["cause"],
        "affected": incident_json["affected"],
        "actions": incident_json["actions"],
        "timeline": incident_json["timeline"],
        "incident_id": incident_json["id"],
        "host_id": incident_json["host_id"],
        "url": format!("{}/#/incidents/{}", ui_base_url.trim_end_matches('/'), incident_json["id"]),
    }))
    .unwrap_or_else(|_| "{}".into())
}

/// Slack message text parses `&`, `<`, `>` — escape them so untrusted
/// content renders literally.
pub fn escape_slack(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Slack incoming-webhook payload (legacy attachments API).
pub fn slack_payload(incident_json: &serde_json::Value, ui_base_url: &str) -> String {
    let color = match incident_json["severity"].as_str() {
        Some("Critical") => "danger",
        Some("Warning") => "warning",
        _ => "good",
    };
    let timeline: Vec<String> = incident_json["timeline"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|e| {
                    let ts = e["ts"].as_i64().unwrap_or(0);
                    format!(
                        "- {} — {} ({})",
                        format_ts(ts),
                        escape_slack(e["summary"].as_str().unwrap_or("")),
                        escape_slack(e["kind"].as_str().unwrap_or(""))
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let text = format!(
        "{}\n{}\n{}",
        escape_slack(incident_json["headline"].as_str().unwrap_or("")),
        escape_slack(incident_json["cause"].as_str().unwrap_or("")),
        timeline.join("\n")
    );
    serde_json::to_string(&json!({
        "attachments": [{
            "color": color,
            "title": format!("[{}] {}", escape_slack(incident_json["severity"].as_str().unwrap_or("")), escape_slack(incident_json["headline"].as_str().unwrap_or(""))),
            "text": text,
            "footer": format!("watchtower · {}", escape_slack(ui_base_url.trim_end_matches('/'))),
        }]
    }))
    .unwrap_or_else(|_| "{}".into())
}

// ---------- Telegram ----------

/// Telegram bot delivery. Token comes from the TELEGRAM_BOT_TOKEN env line
/// (injected at config load); the chat id auto-resolves from the bot's
/// updates — the operator messages the bot once (e.g. /start) and the chat
/// is remembered (persisted in the `settings` table, so a restart does not
/// lose it).
pub struct TelegramClient {
    pub token: String,
    pub chat_id: std::sync::Mutex<Option<i64>>,
    pub password: Option<String>,
    /// Chat id last written to the database (persist is a no-op when equal).
    saved_chat: std::sync::Mutex<Option<i64>>,
}

impl TelegramClient {
    pub fn new(token: String, chat: Option<i64>) -> Self {
        TelegramClient::with_password(token, chat, None)
    }

    pub fn with_password(token: String, chat: Option<i64>, password: Option<String>) -> Self {
        TelegramClient {
            token,
            chat_id: std::sync::Mutex::new(chat),
            password,
            saved_chat: std::sync::Mutex::new(None),
        }
    }

    /// Settings key for the persisted chat. Scoped to the bot (the numeric
    /// id before ':' in the token) and to the registration mode, so a chat
    /// discovered WITHOUT a password is never trusted once a password is set.
    pub fn setting_key(&self) -> String {
        let bot_id = self.token.split(':').next().unwrap_or_default();
        let mode = if self.password.is_some() {
            "registered"
        } else {
            "discovered"
        };
        format!("telegram.chat.{bot_id}.{mode}")
    }
}

pub const TELEGRAM_API: &str = "https://api.telegram.org";

/// Telegram rejects messages longer than 4096 characters ("Bad Request:
/// message is too long") — long-running incidents must be trimmed.
pub const TELEGRAM_MAX_CHARS: usize = 4096;

/// Newest timeline entries listed in a Telegram message; older entries are
/// summarized in one line (the full timeline is in the UI).
pub const TELEGRAM_TIMELINE_MAX: usize = 10;

/// Incident → Telegram message text (plain text, no markdown). Always fits
/// Telegram's message size limit; the UI link is never cut off.
pub fn telegram_payload(incident_json: &serde_json::Value, ui_base_url: &str) -> String {
    let sev = incident_json["severity"].as_str().unwrap_or("?");
    let mut lines = vec![format!(
        "[{}] {}",
        sev.to_uppercase(),
        incident_json["headline"].as_str().unwrap_or("")
    )];
    if let Some(host) = incident_json["host_id"].as_str() {
        if !host.is_empty() {
            lines.push(format!("host: {}", host));
        }
    }
    if let Some(cause) = incident_json["cause"].as_str() {
        if !cause.is_empty() {
            lines.push(cause.to_string());
        }
    }
    if let Some(tl) = incident_json["timeline"].as_array() {
        // timeline is newest-first (ts DESC)
        for e in tl.iter().take(TELEGRAM_TIMELINE_MAX) {
            lines.push(format!(
                " - {} — {} ({})",
                format_ts(e["ts"].as_i64().unwrap_or(0)),
                e["summary"].as_str().unwrap_or(""),
                e["kind"].as_str().unwrap_or("")
            ));
        }
        if tl.len() > TELEGRAM_TIMELINE_MAX {
            lines.push(format!(
                " … and {} earlier event(s)",
                tl.len() - TELEGRAM_TIMELINE_MAX
            ));
        }
    }
    if let Some(actions) = incident_json["actions"].as_array() {
        for a in actions {
            lines.push(format!("> {}", a.as_str().unwrap_or("")));
        }
    }
    let link = format!(
        "{}/#/incidents/{}",
        ui_base_url.trim_end_matches('/'),
        incident_json["id"].as_str().unwrap_or("")
    );
    let body = truncate_chars(
        &lines.join("\n"),
        TELEGRAM_MAX_CHARS.saturating_sub(link.chars().count() + 1),
    );
    format!("{}\n{}", body, link)
}

/// Cut `s` to at most `max` characters, marking the cut with "…".
pub fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Describe a ureq failure WITHOUT the request URL: ureq's own Display
/// includes the URL, and Telegram URLs embed the bot token (Slack/webhook
/// URLs are secrets themselves). Telegram's error `description` ("Bad
/// Request: chat not found", "Forbidden: bot was blocked by the user", …)
/// is surfaced because it tells the operator what to fix.
pub fn describe_http_error(e: ureq::Error) -> String {
    match e {
        ureq::Error::Status(code, resp) => {
            let body = resp.into_string().unwrap_or_default();
            match serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v["description"].as_str().map(String::from))
            {
                Some(desc) => format!("http {code}: {desc}"),
                None => format!("http {code}"),
            }
        }
        ureq::Error::Transport(t) => match t.message() {
            Some(m) => format!("{}: {}", t.kind(), m),
            None => t.kind().to_string(),
        },
    }
}

/// scheme://host of a URL — safe to log (drops path, query and userinfo,
/// where tokens and webhook secrets live).
pub fn url_for_log(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority.rsplit('@').next().unwrap_or(authority);
    if scheme.is_empty() {
        host.to_string()
    } else {
        format!("{scheme}://{host}")
    }
}

/// Bot API method URL (contains the token — never log it).
pub fn telegram_method_url(api_base: &str, token: &str, method: &str) -> String {
    format!("{}/bot{}/{}", api_base.trim_end_matches('/'), token, method)
}

/// sendMessage JSON body.
pub fn telegram_message_body(chat_id: i64, text: &str) -> String {
    serde_json::json!({
        "chat_id": chat_id,
        "text": text,
        "disable_web_page_preview": true,
    })
    .to_string()
}

fn http_agent(timeout_secs: u64) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .build()
}

/// GET a Bot API method and return its `result` (errors carry Telegram's
/// description, never the URL).
fn telegram_get(url: &str, timeout_secs: u64) -> Result<serde_json::Value, String> {
    let body: serde_json::Value = http_agent(timeout_secs)
        .get(url)
        .call()
        .map_err(describe_http_error)?
        .into_json()
        .map_err(|e| e.to_string())?;
    if body["ok"].as_bool() == Some(false) {
        return Err(body["description"]
            .as_str()
            .unwrap_or("telegram error")
            .to_string());
    }
    Ok(body["result"].clone())
}

/// GET the bot's updates; return the first chat id found.
pub fn resolve_chat_id(api_base: &str, token: &str) -> Result<Option<i64>, String> {
    let updates = resolve_updates_sync(api_base, token, None, 0)?;
    Ok(resolve_chat_id_from_updates(&updates))
}

/// Send a text message to the bot's chat, resolving the chat if unknown.
/// Ok(false) = no chat registered yet (message the bot once).
pub fn telegram_send(client: &TelegramClient, api_base: &str, text: &str) -> Result<bool, String> {
    let known = {
        let guard = client.chat_id.lock().unwrap();
        *guard
    };
    let chat = match known {
        Some(c) => c,
        None => {
            if client.password.is_some() {
                // password-protected: only the registrar may register chats
                return Ok(false);
            }
            match resolve_chat_id(api_base, &client.token)? {
                Some(c) => {
                    eprintln!("telegram: resolved chat id {}", c);
                    *client.chat_id.lock().unwrap() = Some(c);
                    c
                }
                None => return Ok(false),
            }
        }
    };
    deliver(
        &telegram_method_url(api_base, &client.token, "sendMessage"),
        &telegram_message_body(chat, text),
    )?;
    Ok(true)
}

// ---------- Telegram registration handshake ----------

#[derive(Debug, PartialEq, Eq)]
pub enum RegStep {
    Noop,             // no password configured → legacy discovery
    AskPassword,      // reply: please send the password
    Register(String), // password accepted → register this chat
    Reject,           // awaiting + wrong password
    Ignore,           // nothing to do
}

/// True for `/start`, `/start@BotName` (group chats) and `/start <payload>`
/// (deep links).
pub fn is_start_command(text: &str) -> bool {
    let cmd = text.split_whitespace().next().unwrap_or_default();
    cmd == "/start" || cmd.starts_with("/start@")
}

/// Pure: one step of the registration state machine.
/// `awaiting` = the chat sent /start and is waiting for the password.
pub fn registrar_step(password: Option<&str>, chat: &str, text: &str, awaiting: bool) -> RegStep {
    let Some(pw) = password else {
        return RegStep::Noop;
    };
    let t = text.trim();
    if is_start_command(t) {
        return RegStep::AskPassword;
    }
    if awaiting && constant_time_eq(t, pw) {
        RegStep::Register(chat.to_string())
    } else if awaiting {
        RegStep::Reject
    } else {
        RegStep::Ignore
    }
}

/// Timing-safe string comparison.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Extract (chat_id, text) from a getUpdates entry; None for the bot's own
/// messages and non-message updates.
pub fn update_chat_and_text(update: &serde_json::Value) -> Option<(i64, String)> {
    let msg = update.get("message")?;
    if msg["from"]["is_bot"].as_bool().unwrap_or(false) {
        return None;
    }
    let chat = msg["chat"]["id"].as_i64()?;
    let text = msg["text"].as_str()?.to_string();
    Some((chat, text))
}

/// getUpdates result array (blocking). `offset` = first update to fetch
/// (last processed update_id + 1), so processed updates are confirmed and
/// never re-fetched; `long_poll_secs` > 0 holds the request open until an
/// update arrives (instant replies without hammering the API).
fn resolve_updates_sync(
    api_base: &str,
    token: &str,
    offset: Option<i64>,
    long_poll_secs: u64,
) -> Result<Vec<serde_json::Value>, String> {
    let mut url = telegram_method_url(api_base, token, "getUpdates");
    let mut sep = '?';
    if let Some(o) = offset {
        url.push_str(&format!("{sep}offset={o}"));
        sep = '&';
    }
    if long_poll_secs > 0 {
        url.push_str(&format!("{sep}timeout={long_poll_secs}"));
    }
    let result = telegram_get(&url, long_poll_secs + 10)?;
    Ok(result.as_array().cloned().unwrap_or_default())
}

/// Async getUpdates (the blocking ureq call runs in spawn_blocking — async
/// callers must not stall a worker).
pub async fn resolve_updates(
    api_base: &str,
    token: &str,
    offset: Option<i64>,
    long_poll_secs: u64,
) -> Result<Vec<serde_json::Value>, String> {
    let base = api_base.to_string();
    let token = token.to_string();
    tokio::task::spawn_blocking(move || resolve_updates_sync(&base, &token, offset, long_poll_secs))
        .await
        .map_err(|e| e.to_string())?
}

/// First chat id found across updates (message or my_chat_member).
pub fn resolve_chat_id_from_updates(updates: &[serde_json::Value]) -> Option<i64> {
    updates.iter().find_map(|u| {
        u["message"]["chat"]["id"]
            .as_i64()
            .or_else(|| u["my_chat_member"]["chat"]["id"].as_i64())
    })
}

/// Direct sendMessage to a specific chat. The blocking ureq call runs in
/// spawn_blocking (async callers must not stall a worker).
pub async fn send_to_chat(
    api_base: &str,
    token: &str,
    chat_id: i64,
    text: &str,
) -> Result<(), String> {
    let url = telegram_method_url(api_base, token, "sendMessage");
    let body = telegram_message_body(chat_id, text);
    tokio::task::spawn_blocking(move || deliver(&url, &body))
        .await
        .map_err(|e| e.to_string())?
}

/// Best-effort deleteMessage (used to remove the password the operator just
/// typed from the chat history).
async fn delete_message(api_base: &str, token: &str, chat_id: i64, message_id: i64) {
    let url = telegram_method_url(api_base, token, "deleteMessage");
    let body = serde_json::json!({ "chat_id": chat_id, "message_id": message_id }).to_string();
    let _ = tokio::task::spawn_blocking(move || deliver(&url, &body)).await;
}

/// Module-level client built once from the configured token. Token changes
/// require a restart (documented).
static TELEGRAM: std::sync::OnceLock<TelegramClient> = std::sync::OnceLock::new();

/// Log the missing-token misconfig once per process, not per incident.
static TELEGRAM_MISCONFIG_LOGGED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Log "no chat registered" once per process, not per incident.
static TELEGRAM_UNREGISTERED_LOGGED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub fn telegram_client(
    token: Option<&str>,
    pinned_chat: Option<i64>,
    password: Option<&str>,
) -> Option<&'static TelegramClient> {
    let token = token?;
    Some(TELEGRAM.get_or_init(|| {
        TelegramClient::with_password(token.to_string(), pinned_chat, password.map(String::from))
    }))
}

/// The configured client (None when no bot token is set).
pub fn configured_telegram(cfg: &NotifyConfig) -> Option<&'static TelegramClient> {
    telegram_client(
        cfg.telegram_token.as_deref(),
        cfg.telegram_chat_id,
        cfg.telegram_password.as_deref(),
    )
}

/// Persist the chat the client resolved or registered, so a restart keeps
/// delivering (Telegram only keeps updates for 24h — a lost chat id could
/// otherwise never be re-discovered). No-op when unchanged.
pub async fn persist_telegram_chat(pool: &sqlx::AnyPool, client: &TelegramClient) {
    let Some(chat) = *client.chat_id.lock().unwrap() else {
        return;
    };
    if *client.saved_chat.lock().unwrap() == Some(chat) {
        return;
    }
    match crate::db::set_setting(pool, &client.setting_key(), &chat.to_string()).await {
        Ok(()) => *client.saved_chat.lock().unwrap() = Some(chat),
        Err(e) => eprintln!("telegram: failed to persist chat id: {e}"),
    }
}

/// Restore a previously discovered/registered chat. A pinned
/// TELEGRAM_CHAT_ID always wins.
pub async fn restore_telegram_chat(pool: &sqlx::AnyPool, client: &TelegramClient) {
    if client.chat_id.lock().unwrap().is_some() {
        return;
    }
    match crate::db::get_setting(pool, &client.setting_key()).await {
        Ok(Some(v)) => match v.trim().parse::<i64>() {
            Ok(chat) => {
                *client.chat_id.lock().unwrap() = Some(chat);
                *client.saved_chat.lock().unwrap() = Some(chat);
                eprintln!("telegram: restored chat {chat}");
            }
            Err(_) => eprintln!("telegram: ignoring invalid persisted chat id {v:?}"),
        },
        Ok(None) => {}
        Err(e) => eprintln!("telegram: failed to read persisted chat id: {e}"),
    }
}

/// Timestamp → "YYYY-MM-DD HH:MM:SS" (UTC). No chrono — civil-from-days.
pub fn format_ts(ts: i64) -> String {
    let secs = ts / 1000;
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (h, min, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", y, m, d, h, min, s)
}

/// Deliver a payload to a channel; Ok on 2xx. Errors never contain the URL.
pub fn deliver(url: &str, payload: &str) -> Result<(), String> {
    let resp = http_agent(10)
        .post(url)
        .set("Content-Type", "application/json")
        .send_string(payload)
        .map_err(describe_http_error)?;
    if (200..300).contains(&resp.status()) {
        Ok(())
    } else {
        Err(format!("http {}", resp.status()))
    }
}

/// Send one incident to all channels configured for its severity.
/// Returns the (url, payload) pairs that failed delivery (for the retry queue).
pub async fn notify_incident(
    cfg: &NotifyConfig,
    incident_json: &serde_json::Value,
    ui_base_url: &str,
) -> Vec<(String, String)> {
    let severity = incident_json["severity"].as_str().unwrap_or("Info");
    let mut failed = Vec::new();
    let webhook = webhook_payload(incident_json, ui_base_url);
    let slack = slack_payload(incident_json, ui_base_url);
    for channel in channels_for(cfg, severity) {
        if channel == "telegram" {
            let Some(client) = configured_telegram(cfg) else {
                // telegram-only default routing + no token = silent
                // black hole; make the misconfig self-evident (once)
                if !TELEGRAM_MISCONFIG_LOGGED.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    eprintln!("telegram channel configured but TELEGRAM_BOT_TOKEN is not set");
                }
                continue;
            };
            let text = telegram_payload(incident_json, ui_base_url);
            let text2 = text.clone();
            let ok =
                tokio::task::spawn_blocking(move || telegram_send(client, TELEGRAM_API, &text2))
                    .await
                    .unwrap_or_else(|_| Err("join failed".into()));
            match ok {
                Ok(true) => {}
                Ok(false) => {
                    if !TELEGRAM_UNREGISTERED_LOGGED.swap(true, std::sync::atomic::Ordering::SeqCst)
                    {
                        if client.password.is_some() {
                            eprintln!("telegram: no chat registered yet — send /start to the bot, then the password");
                        } else {
                            eprintln!("telegram: no chat registered yet — send /start to the bot (or set TELEGRAM_CHAT_ID)");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("telegram send failed: {}", e);
                    // chat known → the retry queue re-sends the exact message
                    let chat = *client.chat_id.lock().unwrap();
                    if let Some(chat) = chat {
                        failed.push((
                            telegram_method_url(TELEGRAM_API, &client.token, "sendMessage"),
                            telegram_message_body(chat, &text),
                        ));
                    }
                }
            }
            continue;
        }
        let (url, payload) = match channel.as_str() {
            "webhook" => (cfg.webhook_url.clone(), webhook.clone()),
            "slack" => (cfg.slack_url.clone(), slack.clone()),
            other => {
                eprintln!("notify: unknown channel {:?} in routing — ignoring", other);
                continue;
            }
        };
        if url.is_empty() {
            eprintln!(
                "notify: {} channel routed for {} but its URL is not set",
                channel, severity
            );
            continue;
        }
        let url2 = url.clone();
        let payload2 = payload.clone();
        let ok = tokio::task::spawn_blocking(move || deliver(&url2, &payload2))
            .await
            .unwrap_or_else(|_| Err("join failed".into()));
        if let Err(e) = ok {
            eprintln!("notify {} failed: {}", channel, e);
            failed.push((url, payload));
        }
    }
    failed
}

/// In-memory retry queue: (url, payload, attempts). try_take POPS; retry()
/// re-queues or drops at max_attempts or max_len. A server restart loses the
/// queue (documented debt).
pub struct RetryQueue {
    max_attempts: u32,
    max_len: usize,
    items: std::collections::VecDeque<(String, String, u32)>,
}

impl Default for RetryQueue {
    fn default() -> Self {
        RetryQueue::new(3)
    }
}

impl RetryQueue {
    /// Hard cap on queue length — beyond it, new pushes are dropped loudly.
    const DEFAULT_MAX_LEN: usize = 256;

    pub fn new(max_attempts: u32) -> Self {
        RetryQueue {
            max_attempts,
            max_len: Self::DEFAULT_MAX_LEN,
            items: Default::default(),
        }
    }

    pub fn set_max_len(&mut self, max_len: usize) {
        self.max_len = max_len;
    }

    pub fn push(&mut self, url: String, payload: String) {
        if self.items.len() >= self.max_len {
            eprintln!(
                "notify queue full ({} items) — dropping new notification",
                self.max_len
            );
            return;
        }
        self.items.push_back((url, payload, 0));
    }

    /// Next item to retry with its attempt count. None when empty.
    pub fn try_take(&mut self) -> Option<(String, String, u32)> {
        self.items.pop_front()
    }

    /// Re-queue for another attempt (call on delivery failure); drops at
    /// max_attempts or when the queue is at max_len.
    pub fn retry(&mut self, url: String, payload: String, attempts: u32) {
        if attempts >= self.max_attempts {
            eprintln!(
                "notify retry exhausted for {} ({} attempts)",
                url_for_log(&url),
                attempts
            );
        } else if self.items.len() >= self.max_len {
            eprintln!(
                "notify queue full ({} items) — dropping retry for {}",
                self.max_len,
                url_for_log(&url)
            );
        } else {
            self.items.push_back((url, payload, attempts));
        }
    }
}

/// Retry undelivered notifications every 10s until dropped at max_attempts
/// or when the queue is at max_len.
pub fn spawn_retry_loop(state: crate::app::AppState) {
    tokio::spawn(crate::supervise::spawn_supervised("notify", move || {
        retry_loop(state.clone())
    }));
}

/// Telegram startup: restore the persisted chat, verify the token (getMe)
/// and log exactly what the operator still has to do, then start the
/// password registrar when one is configured.
pub async fn start_telegram(state: crate::app::AppState) {
    let Some(client) = configured_telegram(&state.notify) else {
        return;
    };
    restore_telegram_chat(&state.pool, client).await;
    let url = telegram_method_url(TELEGRAM_API, &client.token, "getMe");
    match tokio::task::spawn_blocking(move || telegram_get(&url, 10)).await {
        Ok(Ok(me)) => eprintln!(
            "telegram: bot @{} ready",
            me["username"].as_str().unwrap_or("?")
        ),
        Ok(Err(e)) => eprintln!(
            "telegram: bot token check failed ({e}) — notifications will not be delivered"
        ),
        Err(e) => eprintln!("telegram: bot token check failed ({e})"),
    }
    let chat = *client.chat_id.lock().unwrap();
    match (chat, client.password.is_some()) {
        (Some(c), _) => eprintln!("telegram: delivering to chat {c}"),
        (None, true) => eprintln!(
            "telegram: no chat registered — send /start to the bot, then the password"
        ),
        (None, false) => eprintln!(
            "telegram: no chat yet — the first chat to message the bot becomes the target (set TELEGRAM_BOT_PASSWORD or TELEGRAM_CHAT_ID to restrict)"
        ),
    }
    spawn_telegram_registrar(state);
}

/// Poll getUpdates, run the handshake, reply via sendMessage, and register
/// the chat in the shared client (persisted across restarts). getUpdates is
/// called with `offset`, which confirms processed updates, so each update is
/// handled exactly once.
pub fn spawn_telegram_registrar(state: crate::app::AppState) {
    if state.notify.telegram_chat_id.is_some() {
        return; // pinned chat — no handshake needed
    }
    let Some(token) = state.notify.telegram_token.clone() else {
        return;
    };
    let Some(password) = state.notify.telegram_password.clone() else {
        return; // legacy first-chat discovery — no handshake needed
    };
    let pool = state.pool.clone();
    tokio::spawn(crate::supervise::spawn_supervised(
        "telegram-registrar",
        move || registrar_loop(pool.clone(), token.clone(), password.clone()),
    ));
}

/// Wrong-password attempts a chat gets before the registrar ignores it
/// (until restart) — the password is the only thing guarding the channel.
const MAX_PASSWORD_ATTEMPTS: u32 = 5;

async fn registrar_loop(pool: sqlx::AnyPool, token: String, password: String) {
    let mut awaiting: std::collections::HashSet<i64> = Default::default();
    let mut failures: std::collections::HashMap<i64, u32> = Default::default();
    let mut offset: Option<i64> = None;
    loop {
        let updates = match resolve_updates(TELEGRAM_API, &token, offset, 25).await {
            Ok(u) => u,
            Err(e) => {
                eprintln!("telegram: getUpdates failed ({e}); retrying in 15s");
                tokio::time::sleep(std::time::Duration::from_secs(15)).await;
                continue;
            }
        };
        for u in &updates {
            let Some(update_id) = u["update_id"].as_i64() else {
                continue;
            };
            offset = Some(offset.map_or(update_id + 1, |o| o.max(update_id + 1)));
            let Some((chat, text)) = update_chat_and_text(u) else {
                continue;
            };
            if failures.get(&chat).copied().unwrap_or(0) >= MAX_PASSWORD_ATTEMPTS {
                continue;
            }
            let is_awaiting = awaiting.contains(&chat);
            match registrar_step(Some(&password), &chat.to_string(), &text, is_awaiting) {
                RegStep::AskPassword => {
                    awaiting.insert(chat);
                    let _ = send_to_chat(
                        TELEGRAM_API,
                        &token,
                        chat,
                        "Send the password to register this chat.",
                    )
                    .await;
                }
                RegStep::Register(_) => {
                    awaiting.remove(&chat);
                    failures.remove(&chat);
                    if let Some(message_id) = u["message"]["message_id"].as_i64() {
                        delete_message(TELEGRAM_API, &token, chat, message_id).await;
                    }
                    if let Some(client) = telegram_client(Some(&token), None, Some(&password)) {
                        *client.chat_id.lock().unwrap() = Some(chat);
                        persist_telegram_chat(&pool, client).await;
                    }
                    let _ = send_to_chat(
                        TELEGRAM_API,
                        &token,
                        chat,
                        "Chat registered — notifications will be sent here.",
                    )
                    .await;
                    eprintln!("telegram: chat {} registered", chat);
                }
                RegStep::Reject => {
                    let n = failures.entry(chat).or_insert(0);
                    *n += 1;
                    let reply = if *n >= MAX_PASSWORD_ATTEMPTS {
                        awaiting.remove(&chat);
                        eprintln!("telegram: chat {chat} locked out after {n} wrong passwords");
                        "Wrong password. Too many attempts — this chat is locked out."
                    } else {
                        "Wrong password."
                    };
                    let _ = send_to_chat(TELEGRAM_API, &token, chat, reply).await;
                }
                _ => {}
            }
        }
    }
}

async fn retry_loop(state: crate::app::AppState) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(10));
    ticker.tick().await;
    loop {
        ticker.tick().await;
        let item = {
            let mut queue = state.notify_queue.lock().unwrap();
            queue.try_take()
        };
        let Some((url, payload, attempts)) = item else {
            continue;
        };
        let url2 = url.clone();
        let payload2 = payload.clone();
        let ok = tokio::task::spawn_blocking(move || deliver(&url2, &payload2))
            .await
            .unwrap_or_else(|_| Err("join failed".into()));
        match ok {
            Ok(()) => {}
            Err(e) => {
                eprintln!(
                    "notify retry failed ({e}); requeueing {}",
                    url_for_log(&url)
                );
                state
                    .notify_queue
                    .lock()
                    .unwrap()
                    .retry(url, payload, attempts + 1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_incidents::incident_json;
    use crate::incidents::{Incident, IncidentEvent, IncidentStatus};
    use std::io::{Read, Write};

    fn sample_incident() -> Incident {
        Incident {
            id: "inc-1".into(),
            key: "rule:cfg:h-1".into(),
            host_id: "h-1".into(),
            severity: "Critical".into(),
            status: IncidentStatus::Open,
            headline: "myapp.service became unhealthy after a configuration change".into(),
            cause: "A configuration change was followed by a service failure within 300 seconds."
                .into(),
            actions: vec!["Roll back the config".into()],
            affected: vec!["h-1".into(), "svc:myapp.service".into()],
            created_at: 1000,
            updated_at: 1000,
            acked_at: None,
            resolved_at: None,
            timeline: vec![IncidentEvent {
                id: "e-1".into(),
                ts: 900,
                host_id: "h-1".into(),
                kind: "ServiceFailed".into(),
                severity: "Critical".into(),
                summary: "myapp failed".into(),
                evidence: vec![],
            }],
        }
    }

    #[test]
    fn webhook_payload_has_incident_anatomy() {
        let payload = webhook_payload(&incident_json(&sample_incident()), "http://ui/");
        let v: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(v["severity"], "Critical");
        assert_eq!(
            v["headline"],
            "myapp.service became unhealthy after a configuration change"
        );
        assert!(v["cause"]
            .as_str()
            .unwrap()
            .contains("configuration change"));
        assert!(!v["timeline"].as_array().unwrap().is_empty());
        assert!(!v["actions"].as_array().unwrap().is_empty());
        assert_eq!(v["affected"][1], "svc:myapp.service");
        assert!(v["url"].as_str().unwrap().contains("inc-1"));
    }

    #[test]
    fn slack_payload_has_severity_color() {
        let payload = slack_payload(&incident_json(&sample_incident()), "http://ui/");
        let v: serde_json::Value = serde_json::from_str(&payload).unwrap();
        let att = &v["attachments"][0];
        assert_eq!(att["color"], "danger");
        assert!(att["title"].as_str().unwrap().contains("myapp.service"));
        assert!(att["text"]
            .as_str()
            .unwrap()
            .contains("configuration change"));
        assert!(att["text"].as_str().unwrap().contains("myapp failed"));
    }

    #[test]
    fn routing_resolves_channels_per_severity() {
        let cfg = NotifyConfig {
            webhook_url: "http://w".into(),
            slack_url: "http://s".into(),
            telegram_token: None,
            telegram_chat_id: None,
            telegram_password: None,
            routing: default_routing(),
        };
        let c = channels_for(&cfg, "Critical");
        assert_eq!(c, vec!["telegram".to_string()]);
        let c = channels_for(&cfg, "Warning");
        assert_eq!(c, vec!["telegram".to_string()]);
        let c = channels_for(&cfg, "Info");
        assert!(c.is_empty());
    }

    #[test]
    fn format_ts_known_epoch() {
        assert_eq!(format_ts(1_000_000_000_000), "2001-09-09 01:46:40");
        assert_eq!(format_ts(1_758_000_000_000), "2025-09-16 05:20:00");
    }

    #[test]
    fn retry_queue_drops_after_max_attempts() {
        let mut q = RetryQueue::new(3);
        q.push("http://u".into(), "p".into());
        let (_, _, a1) = q.try_take().unwrap();
        q.retry("http://u".into(), "p".into(), a1 + 1);
        let (_, _, a2) = q.try_take().unwrap();
        q.retry("http://u".into(), "p".into(), a2 + 1);
        assert_eq!(a1, 0);
        assert_eq!(a2, 1);
        let (_, _, a3) = q.try_take().unwrap();
        q.retry("http://u".into(), "p".into(), a3 + 1); // attempts 3 >= max 3 → dropped
        assert!(q.try_take().is_none());
    }

    #[test]
    fn retry_queue_caps_length() {
        let mut q = RetryQueue::new(3);
        q.set_max_len(2);
        q.push("http://u1".into(), "p1".into());
        q.push("http://u2".into(), "p2".into());
        q.push("http://u3".into(), "p3".into()); // beyond cap → dropped
        let (url, _, _) = q.try_take().unwrap();
        assert_eq!(url, "http://u1", "oldest preserved");
        let (url, _, _) = q.try_take().unwrap();
        assert_eq!(url, "http://u2");
        assert!(q.try_take().is_none(), "the third was dropped at push");
    }

    #[test]
    fn slack_payload_escapes_special_chars() {
        let mut inc = sample_incident();
        inc.headline = "host <a&b> & \"quoted\"".into();
        let payload = slack_payload(&incident_json(&inc), "http://ui");
        let v: serde_json::Value = serde_json::from_str(&payload).unwrap();
        let text = v["attachments"][0]["title"].as_str().unwrap();
        assert!(text.contains("&lt;a&amp;b&gt;"), "escaped: {}", text);
        assert!(!text.contains("<a&b>"));
    }

    #[test]
    fn telegram_payload_has_incident_anatomy() {
        let text = telegram_payload(&incident_json(&sample_incident()), "http://ui");
        assert!(text.contains("[CRITICAL]"));
        assert!(text.contains("myapp.service became unhealthy"));
        assert!(text.contains("configuration change"));
        assert!(text.contains("myapp failed"));
        assert!(text.contains("http://ui/#/incidents/inc-1"));
        assert!(text.contains("Roll back the config"));
    }

    #[test]
    fn default_routing_is_single_telegram_channel() {
        let r = default_routing();
        assert_eq!(r.get("Critical").unwrap(), &vec!["telegram".to_string()]);
        assert_eq!(r.get("Warning").unwrap(), &vec!["telegram".to_string()]);
        assert!(r.get("Info").unwrap().is_empty());
    }

    #[test]
    fn telegram_send_posts_to_bot_api() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_millis(5000)))
                .unwrap();
            let mut buf = [0u8; 65536];
            let mut got = 0;
            let mut total = usize::MAX; // full request: headers + body
            loop {
                if got >= total {
                    break;
                }
                match stream.read(&mut buf[got..]) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        got += n;
                        if total == usize::MAX {
                            if let Some(end) = buf[..got].windows(4).position(|w| w == b"\r\n\r\n")
                            {
                                let head_end = end + 4;
                                let head = String::from_utf8_lossy(&buf[..end]);
                                let clen = head
                                    .lines()
                                    .find_map(|l| {
                                        let (name, value) = l.split_once(':')?;
                                        name.trim()
                                            .eq_ignore_ascii_case("content-length")
                                            .then(|| value.trim().parse::<usize>().unwrap_or(0))
                                    })
                                    .unwrap_or(0);
                                total = head_end + clen;
                            }
                        }
                    }
                }
            }
            let req = String::from_utf8_lossy(&buf[..got]).into_owned();
            let body = "{\"ok\":true,\"result\":{}}";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(resp.as_bytes()).unwrap();
            req
        });
        let base = format!("http://{}", addr);
        let client = TelegramClient::new("test-token".into(), Some(42)); // pre-seeded (auto-resolve covered elsewhere)
        let ok = telegram_send(&client, &base, "hello").unwrap();
        assert!(ok);
        let req = handle.join().unwrap();
        assert!(req.contains("/bottest-token/sendMessage"));
        assert!(req.contains("chat_id"));
        assert!(req.contains("hello"));
    }

    #[test]
    fn telegram_get_updates_resolves_chat_id() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_millis(5000)))
                .unwrap();
            let mut buf = [0u8; 65536];
            let mut got = 0;
            loop {
                match stream.read(&mut buf[got..]) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        got += n;
                        if buf[..got].windows(4).any(|w| w == b"\r\n\r\n") {
                            break; // full request read (headers terminator)
                        }
                    }
                }
            }
            let body = r#"{"ok":true,"result":[{"update_id":1,"message":{"chat":{"id":12345}}}]}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(resp.as_bytes()).unwrap();
        });
        let base = format!("http://{}", addr);
        let chat = resolve_chat_id(&base, "tok").unwrap();
        assert_eq!(chat, Some(12345));
        handle.join().unwrap();
    }

    #[test]
    fn telegram_pinned_chat_skips_get_updates() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_millis(200)))
                .unwrap();
            let mut buf = [0u8; 65536];
            let mut n = 0;
            loop {
                match stream.read(&mut buf[n..]) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        n += read;
                        let text = String::from_utf8_lossy(&buf[..n]);
                        if let Some(pos) = text.find("\r\n\r\n") {
                            let cl = text[..pos]
                                .lines()
                                .find_map(|l| l.strip_prefix("Content-Length:"))
                                .and_then(|v| v.trim().parse::<usize>().ok())
                                .unwrap_or(0);
                            if n >= pos + 4 + cl {
                                break;
                            }
                        }
                    }
                }
            }
            let text = String::from_utf8_lossy(&buf[..n]).into_owned();
            assert!(
                !text.contains("getUpdates"),
                "pinned chat must never call getUpdates, got: {}",
                text.lines().next().unwrap_or("")
            );
            let body = r#"{"ok":true,"result":{}}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(resp.as_bytes()).unwrap();
        });
        let base = format!("http://{}", addr);
        let client = TelegramClient::new("tok".into(), Some(999));
        let ok = telegram_send(&client, &base, "hello").unwrap();
        assert!(ok);
        assert_eq!(*client.chat_id.lock().unwrap(), Some(999));
        handle.join().unwrap();
    }

    #[test]
    fn telegram_send_resolves_chat_when_unknown() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_millis(5000)))
                    .unwrap();
                let mut buf = [0u8; 65536];
                let mut got = 0;
                let mut total = usize::MAX; // full request: headers + body
                loop {
                    if got >= total {
                        break;
                    }
                    match stream.read(&mut buf[got..]) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            got += n;
                            if total == usize::MAX {
                                if let Some(end) =
                                    buf[..got].windows(4).position(|w| w == b"\r\n\r\n")
                                {
                                    let head_end = end + 4;
                                    let head = String::from_utf8_lossy(&buf[..end]);
                                    let clen = head
                                        .lines()
                                        .find_map(|l| {
                                            let (name, value) = l.split_once(':')?;
                                            name.trim()
                                                .eq_ignore_ascii_case("content-length")
                                                .then(|| value.trim().parse::<usize>().unwrap_or(0))
                                        })
                                        .unwrap_or(0);
                                    total = head_end + clen;
                                }
                            }
                        }
                    }
                }
                let req = String::from_utf8_lossy(&buf[..got]).into_owned();
                let body = if req.starts_with("GET /bottok/getUpdates") {
                    r#"{"ok":true,"result":[{"update_id":1,"message":{"chat":{"id":12345}}}]}"#
                        .to_string()
                } else {
                    r#"{"ok":true,"result":{}}"#.to_string()
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(resp.as_bytes()).unwrap();
            }
        });
        let base = format!("http://{}", addr);
        let client = TelegramClient::new("tok".into(), None); // unknown chat → resolve path
        assert_eq!(*client.chat_id.lock().unwrap(), None);
        let ok = telegram_send(&client, &base, "hello").unwrap();
        assert!(ok);
        assert_eq!(
            *client.chat_id.lock().unwrap(),
            Some(12345),
            "chat resolved and cached"
        );
        handle.join().unwrap();
    }

    #[test]
    fn telegram_password_blocks_legacy_auto_resolve() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            // if getUpdates is ever requested this mock would answer — the
            // assertion below proves it was never reached. Bounded accept
            // loop: if no connection arrives, the thread exits instead of
            // blocking join() forever.
            for _ in 0..100 {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut buf = [0u8; 8192];
                        let _ = stream.read(&mut buf);
                        let body = r#"{"ok":true,"result":[{"update_id":1,"message":{"chat":{"id":1},"from":{"is_bot":false},"text":"/start"}}]}"#;
                        let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
                        let _ = stream.write_all(resp.as_bytes());
                        return;
                    }
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
                }
            }
        });
        let base = format!("http://{}", addr);
        let client = TelegramClient::with_password("tok".into(), None, Some("hunter2".into()));
        let ok = telegram_send(&client, &base, "hello").unwrap();
        assert!(
            !ok,
            "password set + no chat → must NOT resolve, just report unregistered"
        );
        assert_eq!(*client.chat_id.lock().unwrap(), None);
        handle.join().unwrap();
    }

    #[test]
    fn registrar_state_machine_handshake() {
        assert_eq!(
            registrar_step(None, "chat-1", "/start", false),
            RegStep::Noop
        );
        let pw = Some("hunter2".to_string());
        assert_eq!(
            registrar_step(pw.as_deref(), "chat-1", "/start", false),
            RegStep::AskPassword
        );
        assert_eq!(
            registrar_step(pw.as_deref(), "chat-1", "hunter2", true),
            RegStep::Register("chat-1".into())
        );
        assert_eq!(
            registrar_step(pw.as_deref(), "chat-1", "wrong", true),
            RegStep::Reject
        );
        assert_eq!(
            registrar_step(pw.as_deref(), "chat-1", "hunter2", false),
            RegStep::Ignore,
            "must /start first"
        );
        assert_eq!(
            registrar_step(pw.as_deref(), "chat-1", "hello", false),
            RegStep::Ignore
        );
    }

    #[test]
    fn registrar_extracts_chat_and_text_from_update() {
        let u: serde_json::Value = serde_json::from_str(
            r#"{"update_id":7,"message":{"chat":{"id":12345},"from":{"is_bot":false},"text":"/start"}}"#,
        )
        .unwrap();
        assert_eq!(
            update_chat_and_text(&u),
            Some((12345, "/start".to_string()))
        );
        let bot_msg: serde_json::Value = serde_json::from_str(
            r#"{"update_id":8,"message":{"chat":{"id":12345},"from":{"is_bot":true},"text":"/start"}}"#,
        )
        .unwrap();
        assert_eq!(
            update_chat_and_text(&bot_msg),
            None,
            "the bot's own messages are filtered"
        );
        let no_text: serde_json::Value = serde_json::from_str(
            r#"{"update_id":9,"message":{"chat":{"id":1},"from":{"is_bot":false}}}"#,
        )
        .unwrap();
        assert_eq!(update_chat_and_text(&no_text), None);
    }

    #[test]
    fn constant_time_eq_matches_and_mismatches() {
        assert!(constant_time_eq("hunter2", "hunter2"));
        assert!(!constant_time_eq("hunter2", "hunter3"));
        assert!(!constant_time_eq("a", "bb"));
    }
    #[test]
    fn telegram_payload_fits_message_limit_and_keeps_link() {
        let mut inc = incident_json(&sample_incident());
        let ev = inc["timeline"][0].clone();
        let mut tl = Vec::new();
        for i in 0..500 {
            let mut e = ev.clone();
            e["summary"] = serde_json::json!(format!("event {} {}", i, "x".repeat(80)));
            tl.push(e);
        }
        inc["timeline"] = serde_json::json!(tl);
        inc["cause"] = serde_json::json!("c".repeat(10_000));
        let text = telegram_payload(&inc, "http://ui");
        assert!(text.chars().count() <= TELEGRAM_MAX_CHARS);
        assert!(
            text.ends_with("http://ui/#/incidents/inc-1"),
            "link survives"
        );
    }

    #[test]
    fn telegram_payload_summarizes_long_timelines() {
        let mut inc = incident_json(&sample_incident());
        let ev = inc["timeline"][0].clone();
        inc["timeline"] = serde_json::json!(vec![ev; TELEGRAM_TIMELINE_MAX + 5]);
        let text = telegram_payload(&inc, "http://ui");
        assert!(text.contains("and 5 earlier event(s)"));
        assert!(text.contains("host: h-1"));
    }

    #[test]
    fn url_for_log_strips_secrets() {
        assert_eq!(
            url_for_log("https://api.telegram.org/bot123:SECRET/sendMessage"),
            "https://api.telegram.org"
        );
        assert_eq!(
            url_for_log("https://hooks.slack.com/services/T0/B0/XYZ"),
            "https://hooks.slack.com"
        );
        assert_eq!(url_for_log("http://user:pw@h:8080?x=1"), "http://h:8080");
    }

    #[test]
    fn start_command_variants() {
        assert!(is_start_command("/start"));
        assert!(is_start_command("/start@WatchtowerBot"));
        assert!(is_start_command("/start deeplink"));
        assert!(!is_start_command("/started"));
        assert!(!is_start_command("hunter2"));
        assert_eq!(
            registrar_step(Some("pw"), "1", "/start@WatchtowerBot", false),
            RegStep::AskPassword
        );
    }

    #[test]
    fn setting_key_is_scoped_to_bot_and_mode() {
        let open = TelegramClient::new("123:abc".into(), None);
        let locked = TelegramClient::with_password("123:abc".into(), None, Some("pw".into()));
        assert_eq!(open.setting_key(), "telegram.chat.123.discovered");
        assert_eq!(locked.setting_key(), "telegram.chat.123.registered");
    }

    #[test]
    fn telegram_errors_never_leak_the_token() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_millis(300)))
                .unwrap();
            let mut buf = [0u8; 65536];
            let _ = stream.read(&mut buf);
            let body =
                r#"{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}"#;
            let resp = format!(
                "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(resp.as_bytes()).unwrap();
        });
        let base = format!("http://{}", addr);
        let client = TelegramClient::new("123:SECRET".into(), Some(42));
        let err = telegram_send(&client, &base, "hello").unwrap_err();
        handle.join().unwrap();
        assert!(
            err.contains("chat not found"),
            "description surfaced: {err}"
        );
        assert!(!err.contains("SECRET"), "token leaked: {err}");
    }

    #[tokio::test]
    async fn telegram_chat_persists_and_restores() {
        crate::db::ensure_any_drivers();
        let pool = sqlx::any::AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        crate::db::init_schema(&pool).await.unwrap();
        let a = TelegramClient::with_password("7:x".into(), None, Some("pw".into()));
        *a.chat_id.lock().unwrap() = Some(555);
        persist_telegram_chat(&pool, &a).await;
        let b = TelegramClient::with_password("7:x".into(), None, Some("pw".into()));
        restore_telegram_chat(&pool, &b).await;
        assert_eq!(*b.chat_id.lock().unwrap(), Some(555));
        // a chat registered with a password is not reused without one (and
        // vice versa) — different mode, different key
        let c = TelegramClient::new("7:x".into(), None);
        restore_telegram_chat(&pool, &c).await;
        assert_eq!(*c.chat_id.lock().unwrap(), None);
        // a pinned chat always wins
        let d = TelegramClient::with_password("7:x".into(), Some(1), Some("pw".into()));
        restore_telegram_chat(&pool, &d).await;
        assert_eq!(*d.chat_id.lock().unwrap(), Some(1));
    }
}
