use figment::Figment;
use figment::providers::{Env, Format, Serialized, Toml};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

use super::ConfigError;

// ---------------------------------------------------------------------------
// DaemonConfig — the full runtime configuration
// ---------------------------------------------------------------------------

/// Complete daemon configuration. Loaded from layered sources:
/// 1. Built-in defaults (this struct's `Default` impl)
/// 2. `~/.agentsso/config/daemon.toml`
/// 3. Environment variables prefixed `AGENTSSO_` (double-underscore nesting)
/// 4. CLI flag overrides (highest precedence)
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct DaemonConfig {
    #[serde(default)]
    pub http: HttpConfig,
    #[serde(default)]
    pub paths: PathsConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub approval: ApprovalConfig,
    #[serde(default)]
    pub connections: ConnectionsConfig,
    /// Story 6.3 plugin loader configuration. Controls whether
    /// built-in connectors are auto-trusted, whether the
    /// first-load prompt fires for user-installed plugins, and
    /// where the loader looks for user-installed plugins.
    #[serde(default)]
    pub plugins: PluginsConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HttpConfig {
    #[serde(default = "default_bind_addr")]
    pub bind_addr: SocketAddr,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PathsConfig {
    #[serde(default = "default_home_dir")]
    pub home: PathBuf,
}

/// Operational log configuration (Story 5.4 — FR81, FR82, NFR45).
///
/// Tracks level + file path + retention for the operational log stream.
/// The audit log has its own retention field on [`AuditConfig`]; keeping
/// them separate preserves NFR45's isolation invariant.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Operational log file override. Absolute paths are honored
    /// verbatim; relative paths resolve against the current working
    /// directory at daemon start. `None` → `{paths.home}/logs/
    /// daemon.log`. Configurable via `[log] path = "..."` in TOML or
    /// `AGENTSSO_LOG__PATH=...` env.
    #[serde(default)]
    pub path: Option<PathBuf>,

    /// Days to retain rotated operational log files (`daemon.log.YYYY
    /// -MM-DD`). Clamped to `[1, 365]` by [`LogConfig::validated`].
    /// Defaults to 30.
    #[serde(default = "default_log_retention_days")]
    pub retention_days: u32,
}

impl LogConfig {
    /// Clamp `retention_days` into `[1, 365]`, warning on out-of-range
    /// values rather than failing load (the operational log is
    /// observability surface, not the daemon hot path — a misconfigured
    /// retention must never block boot).
    #[must_use]
    pub fn validated(mut self) -> Self {
        if self.retention_days < 1 {
            tracing::warn!(
                given = self.retention_days,
                "log.retention_days out of range; clamping to 1"
            );
            self.retention_days = 1;
        } else if self.retention_days > 365 {
            tracing::warn!(
                given = self.retention_days,
                "log.retention_days out of range; clamping to 365"
            );
            self.retention_days = 365;
        }
        self
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditConfig {
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
    #[serde(default = "default_max_file_bytes")]
    pub max_file_bytes: u64,
    /// Rolling-window rate anomaly detection for `agentsso audit --follow`
    /// (Story 5.2).
    #[serde(default)]
    pub anomaly: AnomalyConfig,
}

/// Rolling-window rate anomaly detection configuration for
/// `agentsso audit --follow` (Story 5.2).
///
/// The detector tracks per-service per-minute call rates for the last
/// 60 minutes, compares the current minute's rate to the average of
/// the preceding 59 minutes, and emits a hint when the multiplier
/// exceeds `baseline_multiplier`. A per-service cooldown prevents
/// the same hint from spamming across multiple consecutive minutes.
///
/// All field values are clamped into sane ranges at load time via
/// [`AnomalyConfig::validated`] so a misconfigured threshold cannot
/// produce a divide-by-zero or unbounded-hint-stream UX disaster.
///
/// Clamping emits a `tracing::warn!` on out-of-range values rather
/// than failing config load — the `audit --follow` command is a CLI
/// path, not the daemon's hot path, and a bad anomaly threshold must
/// never block operators from watching the audit log.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AnomalyConfig {
    /// Master switch. When `false`, the detector is a pass-through:
    /// `observe` returns `None` for every event and no hints are
    /// emitted. Defaults to `true`.
    #[serde(default = "default_anomaly_enabled")]
    pub enabled: bool,

    /// Multiplier threshold: current-minute rate must be at least
    /// this many times the rolling baseline to fire a hint. Default
    /// `10.0`. Clamped to `[1.0, 1000.0]`.
    #[serde(default = "default_baseline_multiplier")]
    pub baseline_multiplier: f64,

    /// Seconds the detector must observe before any hint fires.
    /// Protects against cold-start false positives where a single
    /// event looks like "infinity × baseline" because baseline is
    /// zero. Default `3600` (1 hour). Clamped to `[60, 86400]`.
    #[serde(default = "default_baseline_warmup_seconds")]
    pub baseline_warmup_seconds: u64,

    /// Seconds after a hint fires before another hint for the same
    /// service may fire. Prevents spamming when a single spike
    /// persists across multiple minutes. Default `300` (5 minutes).
    /// Clamped to `[0, 86400]`.
    #[serde(default = "default_cooldown_seconds")]
    pub cooldown_seconds: u64,

    /// Minimum divisor for the rolling-baseline computation.
    /// Smooths cold-start UX: when fewer than `min_samples` of the
    /// preceding 59 minutes have observed any events, the divisor
    /// falls back to `min_samples` instead of `count`, producing a
    /// lower baseline and a more conservative (smaller) multiplier.
    ///
    /// Default `3`, clamped to `[1, 59]`.
    ///
    /// Resolves D1 (baseline_rate divisor semantics) from the
    /// Story 5.2 code review. See `RateWindow::baseline_rate` for
    /// the hybrid algorithm.
    #[serde(default = "default_min_samples")]
    pub min_samples: u64,
}

impl AnomalyConfig {
    /// Clamp all fields into safe ranges and log a warning on any
    /// out-of-range value. Call from `DaemonConfig::load` or directly
    /// before passing to the detector.
    ///
    /// The clamp ranges match the documentation on each field:
    /// - `baseline_multiplier`: `[1.0, 1000.0]`
    /// - `baseline_warmup_seconds`: `[60, 86400]`
    /// - `cooldown_seconds`: `[0, 86400]`
    #[must_use]
    pub fn validated(mut self) -> Self {
        // baseline_multiplier: keep above 1.0 (below 1.0 would fire
        // hints on every event that doesn't exceed the baseline —
        // nonsensical) and below 1000.0 (a 1000× spike is already
        // deep in the pathological range; higher thresholds are
        // useless). NaN and negative values are clamped to the
        // lower bound.
        if !self.baseline_multiplier.is_finite() || self.baseline_multiplier < 1.0 {
            tracing::warn!(
                given = self.baseline_multiplier,
                "audit.anomaly.baseline_multiplier out of range; clamping to 1.0"
            );
            self.baseline_multiplier = 1.0;
        } else if self.baseline_multiplier > 1000.0 {
            tracing::warn!(
                given = self.baseline_multiplier,
                "audit.anomaly.baseline_multiplier out of range; clamping to 1000.0"
            );
            self.baseline_multiplier = 1000.0;
        }

        if self.baseline_warmup_seconds < 60 {
            tracing::warn!(
                given = self.baseline_warmup_seconds,
                "audit.anomaly.baseline_warmup_seconds out of range; clamping to 60"
            );
            self.baseline_warmup_seconds = 60;
        } else if self.baseline_warmup_seconds > 86400 {
            tracing::warn!(
                given = self.baseline_warmup_seconds,
                "audit.anomaly.baseline_warmup_seconds out of range; clamping to 86400"
            );
            self.baseline_warmup_seconds = 86400;
        }

        if self.cooldown_seconds > 86400 {
            tracing::warn!(
                given = self.cooldown_seconds,
                "audit.anomaly.cooldown_seconds out of range; clamping to 86400"
            );
            self.cooldown_seconds = 86400;
        }

        // P29: min_samples clamped to [1, 59]. Zero would collapse
        // the hybrid back to strict `count` divisor (fine but
        // disables the cold-start smoother); anything above 59 is
        // meaningless since we only sample 59 buckets.
        if self.min_samples < 1 {
            tracing::warn!(
                given = self.min_samples,
                "audit.anomaly.min_samples out of range; clamping to 1"
            );
            self.min_samples = 1;
        } else if self.min_samples > 59 {
            tracing::warn!(
                given = self.min_samples,
                "audit.anomaly.min_samples out of range; clamping to 59"
            );
            self.min_samples = 59;
        }

        self
    }
}

/// Connection-tracker configuration (Story 5.5 — FR83).
///
/// Controls the in-process `ConnTracker`'s idle-eviction window: how
/// long an entry sits in the tracker after its last request before
/// being eligible for sweep. Clamped into `[10, 3600]` seconds at load
/// time so a misconfigured value cannot produce a 0-second
/// always-empty table or an unbounded-memory leak.
///
/// Clamping emits `tracing::warn!` rather than failing config load —
/// the connection table is observability surface, not the daemon hot
/// path; a bad timeout must never block boot.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConnectionsConfig {
    /// Seconds after an agent's last request before its `ConnInfo`
    /// entry becomes eligible for sweep. Clamped to `[10, 3600]`.
    /// Default `300` (5 minutes) — matches the rolling-window math in
    /// `RateWindow` (per-minute buckets, 60 buckets total = 1 hour
    /// horizon; an entry idle for >5 min is "no longer connected" but
    /// still has meaningful baseline data for if it reappears).
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
}

impl ConnectionsConfig {
    /// Clamp `idle_timeout_secs` into `[10, 3600]`, warning on
    /// out-of-range values rather than failing load.
    #[must_use]
    pub fn validated(mut self) -> Self {
        if self.idle_timeout_secs < 10 {
            tracing::warn!(
                given = self.idle_timeout_secs,
                "connections.idle_timeout_secs out of range; clamping to 10"
            );
            self.idle_timeout_secs = 10;
        } else if self.idle_timeout_secs > 3600 {
            tracing::warn!(
                given = self.idle_timeout_secs,
                "connections.idle_timeout_secs out of range; clamping to 3600"
            );
            self.idle_timeout_secs = 3600;
        }
        self
    }
}

/// Story 6.3 plugin loader configuration.
///
/// Controls the [`permitlayer_plugins::loader`]'s behaviour at
/// daemon boot: whether built-in connectors (Gmail, Calendar,
/// Drive — embedded via `permitlayer-connectors`) skip the trust
/// prompt, whether the first-load WARN + interactive prompt fires
/// for unknown user-installed plugins, and where user-installed
/// plugins live on disk.
///
/// All fields are optional — a TOML config without a `[plugins]`
/// section parses cleanly and yields the documented defaults.
///
/// # Environment variable mapping
///
/// - `AGENTSSO_PLUGINS__AUTO_TRUST_BUILTINS=false` → audit-mode
///   (prompt fires even for built-ins).
/// - `AGENTSSO_PLUGINS__WARN_ON_FIRST_LOAD=false` → headless mode
///   (first-load WARN still fires but no interactive prompt).
/// - `AGENTSSO_PLUGINS__PLUGINS_DIR=/opt/permitlayer/plugins` →
///   override the default `{paths.home}/plugins` location (useful
///   for system-wide read-only plugin deployments).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PluginsConfig {
    /// When `true`, built-in connectors register as
    /// `TrustTier::Builtin` without consulting the prompter.
    /// When `false`, built-ins go through the prompt path
    /// alongside user-installed plugins — useful for
    /// audit-conscious operators who want to explicitly
    /// acknowledge every connector shipping with the binary.
    /// Default `true`.
    #[serde(default = "default_auto_trust_builtins")]
    pub auto_trust_builtins: bool,

    /// When `true`, user-installed plugins whose sha256 is not in
    /// `.trusted` trigger the interactive `TrustPromptReader`
    /// path. When `false`, they load as `TrustTier::WarnUser`
    /// without a prompt (the WARN log line still fires — set
    /// `false` for headless deployments). Default `true`.
    #[serde(default = "default_warn_on_first_load")]
    pub warn_on_first_load: bool,

    /// Absolute path to the plugins directory. `None` →
    /// `{paths.home}/plugins`. An explicit override lets
    /// operators point at a read-only system-wide plugin
    /// directory (e.g. `/opt/permitlayer/plugins`) without
    /// renaming `~/.agentsso/`. Default `None`.
    #[serde(default)]
    pub plugins_dir: Option<PathBuf>,
}

/// Approval-prompt configuration (Story 4.5).
///
/// Controls the `policy.approval_required` TTY prompt: how long the
/// daemon waits for an operator decision before denying as a timeout.
/// The effective value is clamped into `[1, 300]` seconds at startup
/// so a misconfigured value cannot produce a zero-second race or an
/// unbounded prompt hang.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApprovalConfig {
    #[serde(default = "default_approval_timeout_seconds")]
    pub timeout_seconds: u64,
}

// --- Defaults ---

#[allow(clippy::expect_used)] // Constant string parse is infallible.
fn default_bind_addr() -> SocketAddr {
    "127.0.0.1:3820".parse().expect("static invariant: default bind addr is valid")
}

fn default_home_dir() -> PathBuf {
    dirs::home_dir().map(|h| h.join(".agentsso")).unwrap_or_else(|| PathBuf::from(".agentsso"))
}

fn default_log_level() -> String {
    "info".to_owned()
}

/// Story 5.4 operational-log retention default (30 days).
///
/// Separate from [`default_retention_days`] (90 days) which applies to
/// the audit log — the two streams have different forensic-artifact
/// lifecycles. Operational logs are diagnostic debugging data with
/// relatively low long-term value; audit logs are compliance artifacts.
fn default_log_retention_days() -> u32 {
    30
}

fn default_retention_days() -> u32 {
    90
}

fn default_max_file_bytes() -> u64 {
    100 * 1024 * 1024 // 100MB
}

fn default_approval_timeout_seconds() -> u64 {
    30
}

// Story 5.2 `audit --follow` rate-anomaly detector defaults.
fn default_anomaly_enabled() -> bool {
    true
}

fn default_baseline_multiplier() -> f64 {
    10.0
}

fn default_baseline_warmup_seconds() -> u64 {
    3600
}

fn default_cooldown_seconds() -> u64 {
    300
}

fn default_min_samples() -> u64 {
    3
}

/// Story 6.3 plugin loader defaults.
fn default_auto_trust_builtins() -> bool {
    true
}

fn default_warn_on_first_load() -> bool {
    true
}

/// Story 5.5 connection-tracker idle-timeout default (5 minutes).
fn default_idle_timeout_secs() -> u64 {
    300
}

// DaemonConfig's Default is derived: all fields have their own Default impls.

impl Default for HttpConfig {
    fn default() -> Self {
        Self { bind_addr: default_bind_addr() }
    }
}

impl Default for PathsConfig {
    fn default() -> Self {
        Self { home: default_home_dir() }
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            path: None,
            retention_days: default_log_retention_days(),
        }
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            retention_days: default_retention_days(),
            max_file_bytes: default_max_file_bytes(),
            anomaly: AnomalyConfig::default(),
        }
    }
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            enabled: default_anomaly_enabled(),
            baseline_multiplier: default_baseline_multiplier(),
            baseline_warmup_seconds: default_baseline_warmup_seconds(),
            cooldown_seconds: default_cooldown_seconds(),
            min_samples: default_min_samples(),
        }
    }
}

impl Default for ApprovalConfig {
    fn default() -> Self {
        Self { timeout_seconds: default_approval_timeout_seconds() }
    }
}

impl Default for ConnectionsConfig {
    fn default() -> Self {
        Self { idle_timeout_secs: default_idle_timeout_secs() }
    }
}

impl Default for PluginsConfig {
    fn default() -> Self {
        Self {
            auto_trust_builtins: default_auto_trust_builtins(),
            warn_on_first_load: default_warn_on_first_load(),
            plugins_dir: None,
        }
    }
}

// ---------------------------------------------------------------------------
// CliOverrides — sparse struct for CLI flag merging
// ---------------------------------------------------------------------------

/// Sparse struct for CLI flag overrides. Only `Some` fields are merged into
/// the figment chain. Fields use `skip_serializing_if = "Option::is_none"` so
/// absent CLI flags don't overwrite lower-priority sources with `null`.
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct CliOverrides {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpOverrides>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log: Option<LogOverrides>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HttpOverrides {
    pub bind_addr: SocketAddr,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct LogOverrides {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_days: Option<u32>,
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

impl DaemonConfig {
    /// Load configuration from layered sources (AC #4):
    /// 1. Built-in defaults
    /// 2. `~/.agentsso/config/daemon.toml` (or `$AGENTSSO_PATHS__HOME/config/daemon.toml`)
    /// 3. `AGENTSSO_*` env vars (double-underscore nesting)
    /// 4. CLI flag overrides
    pub fn load(cli_overrides: &CliOverrides) -> Result<Self, ConfigError> {
        // Resolve the home directory: check env override first, then default.
        let home = std::env::var("AGENTSSO_PATHS__HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| default_home_dir());
        let toml_path = home.join("config").join("daemon.toml");

        let figment = Figment::from(Serialized::defaults(Self::default()))
            .merge(Toml::file(&toml_path))
            .merge(Env::prefixed("AGENTSSO_").split("__"))
            .merge(Serialized::defaults(cli_overrides));

        figment.extract().map_err(|e| ConfigError::from_figment(e, &toml_path))
    }

    /// Load with a custom TOML path (for testing or custom home dir).
    #[cfg(test)]
    pub fn load_with_path(
        toml_path: &std::path::Path,
        cli_overrides: &CliOverrides,
    ) -> Result<Self, ConfigError> {
        let figment = Figment::from(Serialized::defaults(Self::default()))
            .merge(Toml::file(toml_path))
            .merge(Env::prefixed("AGENTSSO_").split("__"))
            .merge(Serialized::defaults(cli_overrides));

        figment.extract().map_err(|e| ConfigError::from_figment(e, toml_path))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn default_config_produces_localhost_3820() {
        let config = DaemonConfig::default();
        assert_eq!(config.http.bind_addr, "127.0.0.1:3820".parse::<SocketAddr>().unwrap());
        assert_eq!(config.log.level, "info");
    }

    // --- Story 6.3 [plugins] section -----------------------------

    #[test]
    fn plugins_defaults() {
        // AC #14: DaemonConfig::default() yields the documented
        // plugin loader defaults.
        let config = DaemonConfig::default();
        assert!(config.plugins.auto_trust_builtins);
        assert!(config.plugins.warn_on_first_load);
        assert!(config.plugins.plugins_dir.is_none());
    }

    #[test]
    fn plugins_toml_override() {
        // AC #14: a TOML `[plugins]` section overrides the
        // defaults; other fields stay at their defaults.
        let dir = tempfile::TempDir::new().unwrap();
        let toml_path = dir.path().join("daemon.toml");
        {
            let mut f = std::fs::File::create(&toml_path).unwrap();
            writeln!(f, "[plugins]").unwrap();
            writeln!(f, "auto_trust_builtins = false").unwrap();
            writeln!(f, "warn_on_first_load = false").unwrap();
            writeln!(f, "plugins_dir = \"/opt/permitlayer/plugins\"").unwrap();
        }
        let config = DaemonConfig::load_with_path(&toml_path, &CliOverrides::default()).unwrap();
        assert!(!config.plugins.auto_trust_builtins);
        assert!(!config.plugins.warn_on_first_load);
        assert_eq!(
            config.plugins.plugins_dir.as_deref(),
            Some(std::path::Path::new("/opt/permitlayer/plugins"))
        );
        // Unrelated sections keep defaults.
        assert_eq!(config.http.bind_addr, "127.0.0.1:3820".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn plugins_partial_toml_override_preserves_other_defaults() {
        // A TOML with ONLY `auto_trust_builtins = false` must
        // keep `warn_on_first_load = true` + `plugins_dir = None`.
        let dir = tempfile::TempDir::new().unwrap();
        let toml_path = dir.path().join("daemon.toml");
        {
            let mut f = std::fs::File::create(&toml_path).unwrap();
            writeln!(f, "[plugins]").unwrap();
            writeln!(f, "auto_trust_builtins = false").unwrap();
        }
        let config = DaemonConfig::load_with_path(&toml_path, &CliOverrides::default()).unwrap();
        assert!(!config.plugins.auto_trust_builtins);
        assert!(config.plugins.warn_on_first_load, "unchanged field keeps default");
        assert!(config.plugins.plugins_dir.is_none());
    }

    #[test]
    fn toml_override_merges_correctly() {
        let dir = tempfile::TempDir::new().unwrap();
        let toml_path = dir.path().join("daemon.toml");
        {
            let mut f = std::fs::File::create(&toml_path).unwrap();
            writeln!(f, "[http]").unwrap();
            writeln!(f, "bind_addr = \"127.0.0.1:4000\"").unwrap();
        }

        let config = DaemonConfig::load_with_path(&toml_path, &CliOverrides::default()).unwrap();
        assert_eq!(config.http.bind_addr, "127.0.0.1:4000".parse::<SocketAddr>().unwrap());
        // Log level should still be default
        assert_eq!(config.log.level, "info");
    }

    // NOTE: env var override test (`AGENTSSO_HTTP__BIND_ADDR` takes precedence
    // over TOML) is in the integration tests (`daemon_lifecycle.rs`) because
    // `std::env::set_var` is unsafe in edition 2024 and the daemon crate uses
    // `#![forbid(unsafe_code)]`. Integration tests spawn a subprocess where we
    // can control env vars safely.

    #[test]
    fn cli_overrides_take_highest_precedence() {
        let dir = tempfile::TempDir::new().unwrap();
        let toml_path = dir.path().join("daemon.toml");
        {
            let mut f = std::fs::File::create(&toml_path).unwrap();
            writeln!(f, "[http]").unwrap();
            writeln!(f, "bind_addr = \"127.0.0.1:4000\"").unwrap();
        }

        let overrides = CliOverrides {
            http: Some(HttpOverrides { bind_addr: "127.0.0.1:6000".parse().unwrap() }),
            log: None,
        };
        let config = DaemonConfig::load_with_path(&toml_path, &overrides).unwrap();
        assert_eq!(config.http.bind_addr, "127.0.0.1:6000".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn invalid_toml_produces_config_error() {
        let dir = tempfile::TempDir::new().unwrap();
        let toml_path = dir.path().join("daemon.toml");
        {
            let mut f = std::fs::File::create(&toml_path).unwrap();
            // Invalid: bind_addr is not a valid socket address string
            writeln!(f, "[http]").unwrap();
            writeln!(f, "bind_addr = \"not-a-socket-addr\"").unwrap();
        }

        let result = DaemonConfig::load_with_path(&toml_path, &CliOverrides::default());
        let err = result.unwrap_err();
        assert_eq!(err.error_code, "config_invalid");
        assert!(err.config_path.is_some());
    }

    #[test]
    fn audit_config_loads_from_toml() {
        let dir = tempfile::TempDir::new().unwrap();
        let toml_path = dir.path().join("daemon.toml");
        {
            let mut f = std::fs::File::create(&toml_path).unwrap();
            writeln!(f, "[audit]").unwrap();
            writeln!(f, "retention_days = 30").unwrap();
            writeln!(f, "max_file_bytes = 52428800").unwrap();
        }

        let config = DaemonConfig::load_with_path(&toml_path, &CliOverrides::default()).unwrap();
        assert_eq!(config.audit.retention_days, 30);
        assert_eq!(config.audit.max_file_bytes, 52_428_800);
    }

    #[test]
    fn audit_config_defaults_when_section_absent() {
        let dir = tempfile::TempDir::new().unwrap();
        let toml_path = dir.path().join("daemon.toml");
        std::fs::write(&toml_path, "").unwrap();

        let config = DaemonConfig::load_with_path(&toml_path, &CliOverrides::default()).unwrap();
        assert_eq!(config.audit.retention_days, 90);
        assert_eq!(config.audit.max_file_bytes, 100 * 1024 * 1024);
    }

    #[test]
    fn missing_toml_file_loads_defaults() {
        let dir = tempfile::TempDir::new().unwrap();
        let toml_path = dir.path().join("nonexistent.toml");

        let config = DaemonConfig::load_with_path(&toml_path, &CliOverrides::default()).unwrap();
        assert_eq!(config.http.bind_addr, "127.0.0.1:3820".parse::<SocketAddr>().unwrap());
    }

    // ── Story 4.5: approval config ────────────────────────────────

    #[test]
    fn approval_config_defaults_to_30_seconds() {
        let config = DaemonConfig::default();
        assert_eq!(config.approval.timeout_seconds, 30);
    }

    #[test]
    fn approval_config_loads_from_toml() {
        let dir = tempfile::TempDir::new().unwrap();
        let toml_path = dir.path().join("daemon.toml");
        {
            let mut f = std::fs::File::create(&toml_path).unwrap();
            writeln!(f, "[approval]").unwrap();
            writeln!(f, "timeout_seconds = 120").unwrap();
        }
        let config = DaemonConfig::load_with_path(&toml_path, &CliOverrides::default()).unwrap();
        assert_eq!(config.approval.timeout_seconds, 120);
    }

    #[test]
    fn approval_config_defaults_when_section_absent() {
        let dir = tempfile::TempDir::new().unwrap();
        let toml_path = dir.path().join("daemon.toml");
        std::fs::write(&toml_path, "[http]\nbind_addr = \"127.0.0.1:3820\"\n").unwrap();
        let config = DaemonConfig::load_with_path(&toml_path, &CliOverrides::default()).unwrap();
        assert_eq!(config.approval.timeout_seconds, 30);
    }

    // ── Story 5.2: audit.anomaly config ────────────────────────────

    #[test]
    fn anomaly_config_defaults_match_spec() {
        let config = DaemonConfig::default();
        assert!(config.audit.anomaly.enabled);
        assert!((config.audit.anomaly.baseline_multiplier - 10.0).abs() < f64::EPSILON);
        assert_eq!(config.audit.anomaly.baseline_warmup_seconds, 3600);
        assert_eq!(config.audit.anomaly.cooldown_seconds, 300);
        // P29: min_samples defaults to 3 (hybrid divisor smoother).
        assert_eq!(config.audit.anomaly.min_samples, 3);
    }

    #[test]
    fn anomaly_config_loads_from_toml() {
        let dir = tempfile::TempDir::new().unwrap();
        let toml_path = dir.path().join("daemon.toml");
        {
            let mut f = std::fs::File::create(&toml_path).unwrap();
            writeln!(f, "[audit.anomaly]").unwrap();
            writeln!(f, "enabled = false").unwrap();
            writeln!(f, "baseline_multiplier = 20.0").unwrap();
            writeln!(f, "baseline_warmup_seconds = 1800").unwrap();
            writeln!(f, "cooldown_seconds = 60").unwrap();
        }
        let config = DaemonConfig::load_with_path(&toml_path, &CliOverrides::default()).unwrap();
        assert!(!config.audit.anomaly.enabled);
        assert!((config.audit.anomaly.baseline_multiplier - 20.0).abs() < f64::EPSILON);
        assert_eq!(config.audit.anomaly.baseline_warmup_seconds, 1800);
        assert_eq!(config.audit.anomaly.cooldown_seconds, 60);
    }

    #[test]
    fn anomaly_config_defaults_when_audit_section_absent() {
        let dir = tempfile::TempDir::new().unwrap();
        let toml_path = dir.path().join("daemon.toml");
        std::fs::write(&toml_path, "[http]\nbind_addr = \"127.0.0.1:3820\"\n").unwrap();
        let config = DaemonConfig::load_with_path(&toml_path, &CliOverrides::default()).unwrap();
        assert!(config.audit.anomaly.enabled);
        assert!((config.audit.anomaly.baseline_multiplier - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn anomaly_config_baseline_multiplier_clamps_to_1_lower() {
        let cfg =
            AnomalyConfig { baseline_multiplier: 0.5, ..AnomalyConfig::default() }.validated();
        assert!((cfg.baseline_multiplier - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn anomaly_config_baseline_multiplier_clamps_to_1000_upper() {
        let cfg =
            AnomalyConfig { baseline_multiplier: 5000.0, ..AnomalyConfig::default() }.validated();
        assert!((cfg.baseline_multiplier - 1000.0).abs() < f64::EPSILON);
    }

    #[test]
    fn anomaly_config_baseline_multiplier_clamps_nan_to_1() {
        let cfg =
            AnomalyConfig { baseline_multiplier: f64::NAN, ..AnomalyConfig::default() }.validated();
        assert!((cfg.baseline_multiplier - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn anomaly_config_warmup_seconds_clamps_to_60_lower() {
        let cfg =
            AnomalyConfig { baseline_warmup_seconds: 10, ..AnomalyConfig::default() }.validated();
        assert_eq!(cfg.baseline_warmup_seconds, 60);
    }

    #[test]
    fn anomaly_config_warmup_seconds_clamps_to_86400_upper() {
        let cfg = AnomalyConfig { baseline_warmup_seconds: 10_000_000, ..AnomalyConfig::default() }
            .validated();
        assert_eq!(cfg.baseline_warmup_seconds, 86400);
    }

    #[test]
    fn anomaly_config_cooldown_seconds_clamps_to_86400_upper() {
        let cfg =
            AnomalyConfig { cooldown_seconds: 10_000_000, ..AnomalyConfig::default() }.validated();
        assert_eq!(cfg.cooldown_seconds, 86400);
    }

    #[test]
    fn anomaly_config_cooldown_seconds_zero_is_valid() {
        // 0 means "no cooldown" — allow every spike through.
        let cfg = AnomalyConfig { cooldown_seconds: 0, ..AnomalyConfig::default() }.validated();
        assert_eq!(cfg.cooldown_seconds, 0);
    }

    #[test]
    fn anomaly_config_validated_passes_in_range_values() {
        let cfg = AnomalyConfig {
            enabled: true,
            baseline_multiplier: 15.0,
            baseline_warmup_seconds: 1800,
            cooldown_seconds: 600,
            min_samples: 5,
        }
        .validated();
        assert!(cfg.enabled);
        assert!((cfg.baseline_multiplier - 15.0).abs() < f64::EPSILON);
        assert_eq!(cfg.baseline_warmup_seconds, 1800);
        assert_eq!(cfg.cooldown_seconds, 600);
        assert_eq!(cfg.min_samples, 5);
    }

    #[test]
    fn anomaly_config_min_samples_clamps_to_1_lower() {
        let cfg = AnomalyConfig { min_samples: 0, ..AnomalyConfig::default() }.validated();
        assert_eq!(cfg.min_samples, 1);
    }

    #[test]
    fn anomaly_config_min_samples_clamps_to_59_upper() {
        let cfg = AnomalyConfig { min_samples: 100, ..AnomalyConfig::default() }.validated();
        assert_eq!(cfg.min_samples, 59);
    }

    // ── Story 5.4: operational log config ──────────────────────────

    #[test]
    fn log_config_default_retention_is_30() {
        let config = DaemonConfig::default();
        assert_eq!(config.log.retention_days, 30);
        assert!(config.log.path.is_none());
        assert_eq!(config.log.level, "info");
    }

    #[test]
    fn log_config_retention_clamps_below_1() {
        let cfg = LogConfig { retention_days: 0, ..LogConfig::default() }.validated();
        assert_eq!(cfg.retention_days, 1);
    }

    #[test]
    fn log_config_retention_clamps_above_365() {
        let cfg = LogConfig { retention_days: 1_000, ..LogConfig::default() }.validated();
        assert_eq!(cfg.retention_days, 365);
    }

    #[test]
    fn log_config_retention_in_range_preserved() {
        let cfg = LogConfig { retention_days: 14, ..LogConfig::default() }.validated();
        assert_eq!(cfg.retention_days, 14);
    }

    #[test]
    fn log_config_path_absolute_respected() {
        let dir = tempfile::TempDir::new().unwrap();
        let toml_path = dir.path().join("daemon.toml");
        {
            let mut f = std::fs::File::create(&toml_path).unwrap();
            writeln!(f, "[log]").unwrap();
            writeln!(f, "level = \"debug\"").unwrap();
            writeln!(f, "path = \"/var/log/agentsso/custom.log\"").unwrap();
            writeln!(f, "retention_days = 7").unwrap();
        }
        let config = DaemonConfig::load_with_path(&toml_path, &CliOverrides::default()).unwrap();
        assert_eq!(config.log.level, "debug");
        assert_eq!(config.log.path, Some(PathBuf::from("/var/log/agentsso/custom.log")));
        assert_eq!(config.log.retention_days, 7);
    }

    #[test]
    fn log_config_toml_round_trip_with_minimal_level_only() {
        let dir = tempfile::TempDir::new().unwrap();
        let toml_path = dir.path().join("daemon.toml");
        {
            let mut f = std::fs::File::create(&toml_path).unwrap();
            writeln!(f, "[log]").unwrap();
            writeln!(f, "level = \"info\"").unwrap();
        }
        // Backwards-compat: a pre-Story-5.4 config with only `level`
        // continues to load, with `path=None` and `retention_days=30`
        // defaults filled in.
        let config = DaemonConfig::load_with_path(&toml_path, &CliOverrides::default()).unwrap();
        assert_eq!(config.log.level, "info");
        assert!(config.log.path.is_none());
        assert_eq!(config.log.retention_days, 30);
    }

    // ── Story 5.5: connection-tracker config ──────────────────────────

    #[test]
    fn connections_config_default_idle_timeout_is_300() {
        let config = DaemonConfig::default();
        assert_eq!(config.connections.idle_timeout_secs, 300);
    }

    #[test]
    fn connections_config_idle_timeout_clamps_below_10() {
        let cfg = ConnectionsConfig { idle_timeout_secs: 5 }.validated();
        assert_eq!(cfg.idle_timeout_secs, 10);
    }

    #[test]
    fn connections_config_idle_timeout_clamps_above_3600() {
        let cfg = ConnectionsConfig { idle_timeout_secs: 10_000 }.validated();
        assert_eq!(cfg.idle_timeout_secs, 3600);
    }

    #[test]
    fn connections_config_idle_timeout_in_range_preserved() {
        let cfg = ConnectionsConfig { idle_timeout_secs: 600 }.validated();
        assert_eq!(cfg.idle_timeout_secs, 600);
    }

    #[test]
    fn connections_config_loads_from_toml() {
        let dir = tempfile::TempDir::new().unwrap();
        let toml_path = dir.path().join("daemon.toml");
        {
            let mut f = std::fs::File::create(&toml_path).unwrap();
            writeln!(f, "[connections]").unwrap();
            writeln!(f, "idle_timeout_secs = 600").unwrap();
        }
        let config = DaemonConfig::load_with_path(&toml_path, &CliOverrides::default()).unwrap();
        assert_eq!(config.connections.idle_timeout_secs, 600);
    }

    #[test]
    fn connections_config_defaults_when_section_absent() {
        let dir = tempfile::TempDir::new().unwrap();
        let toml_path = dir.path().join("daemon.toml");
        // Pre-Story-5.5 config (no `[connections]` section) must continue
        // to load with the 300s default — backwards-compatibility.
        std::fs::write(&toml_path, "[http]\nbind_addr = \"127.0.0.1:3820\"\n").unwrap();
        let config = DaemonConfig::load_with_path(&toml_path, &CliOverrides::default()).unwrap();
        assert_eq!(config.connections.idle_timeout_secs, 300);
    }

    #[test]
    fn anomaly_config_min_samples_loads_from_toml() {
        let dir = tempfile::TempDir::new().unwrap();
        let toml_path = dir.path().join("daemon.toml");
        {
            let mut f = std::fs::File::create(&toml_path).unwrap();
            writeln!(f, "[audit.anomaly]").unwrap();
            writeln!(f, "min_samples = 7").unwrap();
        }
        let config = DaemonConfig::load_with_path(&toml_path, &CliOverrides::default()).unwrap();
        assert_eq!(config.audit.anomaly.min_samples, 7);
    }
}
