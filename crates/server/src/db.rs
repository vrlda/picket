use sqlx::Row;

/// Install the sqlx any-driver backends (sqlite, postgres). Idempotent.
/// Must run before any `AnyPool` connects, or sqlx panics ("no drivers
/// installed"). sqlx 0.8 does not auto-install on connect.
pub fn ensure_any_drivers() {
    sqlx::any::install_default_drivers();
}

/// Connect to the configured database. sqlite URLs get WAL journaling
/// (concurrent reader + writer without lock contention) and `mode=rwc` so
/// a missing db file is created on first run (preserves the old
/// `create_if_missing(true)` behavior, which the any driver does not set).
pub async fn connect(cfg: &crate::config::ServerConfig) -> Result<sqlx::AnyPool, sqlx::Error> {
    ensure_any_drivers();
    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(5)
        .connect(&with_create_flag(&cfg.db_url))
        .await?;
    if cfg.db_url.starts_with("sqlite:") {
        let _ = sqlx::query("PRAGMA journal_mode=WAL").execute(&pool).await;
    }
    Ok(pool)
}

/// SQL dialect guard: sqlite accepts INSERT OR IGNORE; postgres uses
/// ON CONFLICT DO NOTHING. Detects the backend from the pool's connect
/// options (sqlx 0.8 has no pool-level `any_kind()`; AnyKind is
/// deprecated and unused).
pub fn is_postgres(pool: &sqlx::AnyPool) -> bool {
    let options = pool.connect_options();
    let scheme = options.database_url.scheme();
    scheme == "postgres" || scheme == "postgresql"
}

fn with_create_flag(url: &str) -> String {
    if url.starts_with("sqlite:") && !url.contains(":memory:") && !url.contains("mode=") {
        if url.contains('?') {
            format!("{url}&mode=rwc")
        } else {
            format!("{url}?mode=rwc")
        }
    } else {
        url.to_string()
    }
}

/// Apply the schema. Idempotent — safe to run on every startup.
pub async fn init_schema(pool: &sqlx::AnyPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS hosts (
            host_id    TEXT PRIMARY KEY,
            first_seen BIGINT NOT NULL,
            last_seen  BIGINT NOT NULL,
            version    TEXT NOT NULL DEFAULT ''
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS events (
            id            TEXT PRIMARY KEY,
            ts            BIGINT NOT NULL,
            host_id       TEXT NOT NULL,
            key           TEXT NOT NULL,
            kind          TEXT NOT NULL,
            severity      TEXT NOT NULL,
            summary       TEXT NOT NULL,
            evidence_json TEXT NOT NULL DEFAULT '[]',
            created_at    BIGINT NOT NULL -- server ingest time; NEVER used for ordering
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_events_host_ts ON events (host_id, ts DESC)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_events_kind ON events (kind)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts)")
        .execute(pool)
        .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS incidents (
            id         TEXT PRIMARY KEY,
            key        TEXT NOT NULL,
            host_id    TEXT NOT NULL DEFAULT '',
            severity   TEXT NOT NULL,
            status     TEXT NOT NULL DEFAULT 'open',
            headline   TEXT NOT NULL,
            cause      TEXT NOT NULL DEFAULT '',
            actions_json TEXT NOT NULL DEFAULT '[]',
            affected_json TEXT NOT NULL DEFAULT '[]',
            created_at BIGINT NOT NULL,
            updated_at BIGINT NOT NULL,
            acked_at   BIGINT,
            resolved_at BIGINT
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_incidents_key ON incidents (key, status)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents (created_at DESC)")
        .execute(pool)
        .await?;
    sqlx::query(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_incidents_key_open ON incidents (key) WHERE status != 'resolved'",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS incident_events (
            incident_id TEXT NOT NULL,
            event_id    TEXT NOT NULL,
            PRIMARY KEY (incident_id, event_id)
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_incident_events_event ON incident_events (event_id)",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )",
    )
    .execute(pool)
    .await?;
    ensure_column(
        pool,
        "hosts",
        "queue_len",
        "ALTER TABLE hosts ADD COLUMN queue_len BIGINT NOT NULL DEFAULT 0",
    )
    .await?;
    Ok(())
}

/// Read a persisted server setting (small key/value state that must
/// survive restarts, e.g. the registered Telegram chat).
pub async fn get_setting(pool: &sqlx::AnyPool, key: &str) -> Result<Option<String>, sqlx::Error> {
    let row = sqlx::query_as::<_, (String,)>("SELECT value FROM settings WHERE key = $1")
        .bind(key)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|(v,)| v))
}

/// Upsert a persisted server setting.
pub async fn set_setting(pool: &sqlx::AnyPool, key: &str, value: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES ($1, $2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .bind(key)
    .bind(value)
    .execute(pool)
    .await?;
    Ok(())
}

/// Ensure a column exists. SQLite lacks ADD COLUMN IF NOT EXISTS, so it
/// walks PRAGMA table_info; postgres has the ANSI form.
async fn ensure_column(
    pool: &sqlx::AnyPool,
    table: &str,
    column: &str,
    ddl: &str,
) -> Result<(), sqlx::Error> {
    if is_postgres(pool) {
        sqlx::query(&format!(
            "ALTER TABLE {} ADD COLUMN IF NOT EXISTS {} BIGINT NOT NULL DEFAULT 0",
            table, column
        ))
        .execute(pool)
        .await?;
        return Ok(());
    }
    let rows = sqlx::query(&format!("PRAGMA table_info({})", table))
        .fetch_all(pool)
        .await?;
    if !rows.iter().any(|r| r.get::<String, _>("name") == column) {
        sqlx::query(ddl).execute(pool).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_pool() -> sqlx::AnyPool {
        ensure_any_drivers();
        sqlx::any::AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn schema_initializes_and_is_idempotent() {
        let pool = test_pool().await;
        init_schema(&pool).await.unwrap();
        init_schema(&pool).await.unwrap();
        let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM sqlite_master WHERE type='table'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(
            n >= 4,
            "hosts, events, incidents, incident_events tables exist"
        );
    }

    #[tokio::test]
    async fn settings_roundtrip_and_upsert() {
        let pool = test_pool().await;
        init_schema(&pool).await.unwrap();
        assert_eq!(get_setting(&pool, "k").await.unwrap(), None);
        set_setting(&pool, "k", "1").await.unwrap();
        set_setting(&pool, "k", "2").await.unwrap();
        assert_eq!(get_setting(&pool, "k").await.unwrap().as_deref(), Some("2"));
    }

    #[tokio::test]
    async fn schema_has_queue_len_column() {
        let pool = test_pool().await;
        init_schema(&pool).await.unwrap();
        let rows = sqlx::query("PRAGMA table_info(hosts)")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert!(rows
            .iter()
            .any(|r| r.get::<String, _>("name") == "queue_len"));
    }
}
