use crate::{app_traffic, settings::BackgroundSettings, tray};
use dissimulation_core::{
    AlertSeverity, Availability, ExposureLevel, NetworkSnapshot, ServiceInfo,
};
use serde::Serialize;
use std::{
    collections::{HashMap, HashSet},
    sync::{
        Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_notification::NotificationExt;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum LifecycleState {
    Startup,
    Initializing,
    BackgroundMonitoring,
    InterfaceOpen,
    InterfaceHidden,
    #[allow(dead_code)] // réservé au futur flux Polkit, déjà exposé dans le cycle de vie
    AuthorizationRequest,
    ShuttingDown,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeStatus {
    pub lifecycle: LifecycleState,
    pub scan_running: bool,
    pub last_analyzed_at_epoch_ms: Option<u128>,
}

struct RuntimeData {
    settings: BackgroundSettings,
    snapshot: Option<NetworkSnapshot>,
    lifecycle: LifecycleState,
    scan_running: bool,
    last_scan_completed_at: Option<Instant>,
    last_application_traffic_sample_at: Option<Instant>,
    last_notifications: HashMap<String, Instant>,
}

pub struct AppState {
    runtime: Mutex<RuntimeData>,
    scan_lock: Mutex<()>,
    wake_monitor: Condvar,
    stopping: AtomicBool,
    quit_requested: AtomicBool,
    monitor_thread: Mutex<Option<JoinHandle<()>>>,
    pub tray_items: Mutex<Option<tray::TraySummaryItems>>,
}

impl AppState {
    pub fn new(settings: BackgroundSettings) -> Self {
        Self {
            runtime: Mutex::new(RuntimeData {
                settings,
                snapshot: None,
                lifecycle: LifecycleState::Startup,
                scan_running: false,
                last_scan_completed_at: None,
                last_application_traffic_sample_at: None,
                last_notifications: HashMap::new(),
            }),
            scan_lock: Mutex::new(()),
            wake_monitor: Condvar::new(),
            stopping: AtomicBool::new(false),
            quit_requested: AtomicBool::new(false),
            monitor_thread: Mutex::new(None),
            tray_items: Mutex::new(None),
        }
    }

    pub fn settings(&self) -> BackgroundSettings {
        self.runtime
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .settings
            .clone()
    }

    pub fn replace_settings(&self, settings: BackgroundSettings) {
        self.runtime
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .settings = settings;
        self.wake_monitor.notify_all();
    }

    pub fn status(&self) -> RuntimeStatus {
        let runtime = self
            .runtime
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        RuntimeStatus {
            lifecycle: runtime.lifecycle,
            scan_running: runtime.scan_running,
            last_analyzed_at_epoch_ms: runtime
                .snapshot
                .as_ref()
                .map(|snapshot| snapshot.analyzed_at_epoch_ms),
        }
    }

    pub fn set_lifecycle(&self, lifecycle: LifecycleState) {
        self.runtime
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .lifecycle = lifecycle;
    }

    pub fn request_quit(&self) {
        self.quit_requested.store(true, Ordering::Release);
        self.prepare_shutdown();
    }

    pub fn quit_requested(&self) -> bool {
        self.quit_requested.load(Ordering::Acquire)
    }

    fn prepare_shutdown(&self) {
        self.stopping.store(true, Ordering::Release);
        self.set_lifecycle(LifecycleState::ShuttingDown);
        self.wake_monitor.notify_all();
    }
}

pub fn set_lifecycle(app: &AppHandle, lifecycle: LifecycleState) {
    if let Some(state) = app.try_state::<AppState>() {
        state.set_lifecycle(lifecycle);
        let _ = app.emit("runtime-status-updated", state.status());
    }
}

pub fn restore_window_lifecycle(app: &AppHandle) {
    let lifecycle = app
        .get_webview_window("main")
        .and_then(|window| window.is_visible().ok())
        .map(|visible| {
            if visible {
                LifecycleState::InterfaceOpen
            } else {
                LifecycleState::InterfaceHidden
            }
        })
        .unwrap_or(LifecycleState::BackgroundMonitoring);
    set_lifecycle(app, lifecycle);
}

pub fn scan(app: &AppHandle) -> NetworkSnapshot {
    let state = app.state::<AppState>();
    let _scan_guard = state
        .scan_lock
        .lock()
        .unwrap_or_else(|error| error.into_inner());

    perform_scan(app, &state)
}

pub fn latest_or_scan(app: &AppHandle) -> NetworkSnapshot {
    let state = app.state::<AppState>();
    let _scan_guard = state
        .scan_lock
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if let Some(snapshot) = state
        .runtime
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .snapshot
        .clone()
    {
        return snapshot;
    }

    perform_scan(app, &state)
}

fn perform_scan(app: &AppHandle, state: &AppState) -> NetworkSnapshot {
    {
        let mut runtime = state
            .runtime
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        runtime.scan_running = true;
    }
    let _ = app.emit("runtime-status-updated", state.status());

    let snapshot = dissimulation_core::scan_network_exposure();
    let (previous, settings) = {
        let mut runtime = state
            .runtime
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let previous = runtime.snapshot.replace(snapshot.clone());
        runtime.scan_running = false;
        runtime.last_scan_completed_at = Some(Instant::now());
        (previous, runtime.settings.clone())
    };
    state.wake_monitor.notify_all();

    tray::update(app, &snapshot);
    if let Some(previous) = previous.as_ref() {
        notify_important_changes(app, &state, previous, &snapshot, &settings);
    }
    restore_window_lifecycle(app);
    let _ = app.emit("snapshot-updated", snapshot.clone());
    let _ = app.emit("runtime-status-updated", state.status());
    snapshot
}

pub fn start_monitor(app: AppHandle) -> Result<(), String> {
    let state = app.state::<AppState>();
    let mut slot = state
        .monitor_thread
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if slot.is_some() {
        return Ok(());
    }

    let thread_app = app.clone();
    let handle = std::thread::Builder::new()
        .name("dissimulation-monitor".to_string())
        .spawn(move || monitor_loop(thread_app))
        .map_err(|_| "Impossible de démarrer la surveillance en arrière-plan.".to_string())?;
    *slot = Some(handle);
    Ok(())
}

fn monitor_loop(app: AppHandle) {
    loop {
        let state = app.state::<AppState>();
        if state.stopping.load(Ordering::Acquire) {
            break;
        }

        let runtime = state
            .runtime
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let scan_interval = Duration::from_secs(runtime.settings.scan_interval_minutes * 60);
        let scan_wait = runtime
            .last_scan_completed_at
            .map(|last_scan| scan_interval.saturating_sub(last_scan.elapsed()))
            .unwrap_or(Duration::ZERO);
        let traffic_wait = if runtime.settings.application_traffic_monitoring {
            let interval =
                Duration::from_secs(runtime.settings.application_traffic_interval_minutes * 60);
            runtime
                .last_application_traffic_sample_at
                .map(|last_sample| interval.saturating_sub(last_sample.elapsed()))
                .unwrap_or(Duration::ZERO)
        } else {
            Duration::MAX
        };
        let wait_duration = scan_wait.min(traffic_wait);

        if wait_duration.is_zero() {
            drop(runtime);
            scan_if_due(&app);
            sample_application_traffic_if_due(&app);
        } else {
            let wait_result = state
                .wake_monitor
                .wait_timeout(runtime, wait_duration)
                .unwrap_or_else(|error| error.into_inner());
            drop(wait_result);
        }
    }
}

fn sample_application_traffic_if_due(app: &AppHandle) {
    let state = app.state::<AppState>();
    let settings = {
        let mut runtime = state
            .runtime
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if !runtime.settings.application_traffic_monitoring {
            return;
        }
        let interval =
            Duration::from_secs(runtime.settings.application_traffic_interval_minutes * 60);
        let is_due = runtime
            .last_application_traffic_sample_at
            .map(|last_sample| last_sample.elapsed() >= interval)
            .unwrap_or(true);
        if !is_due || state.stopping.load(Ordering::Acquire) {
            return;
        }
        runtime.last_application_traffic_sample_at = Some(Instant::now());
        runtime.settings.clone()
    };

    let _ = app_traffic::capture_and_store(
        app,
        "any",
        settings.application_traffic_sample_seconds,
        settings.traffic_history_days,
    );
}

fn scan_if_due(app: &AppHandle) {
    let state = app.state::<AppState>();
    let _scan_guard = state
        .scan_lock
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let is_due = {
        let runtime = state
            .runtime
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let interval = Duration::from_secs(runtime.settings.scan_interval_minutes * 60);
        runtime
            .last_scan_completed_at
            .map(|last_scan| last_scan.elapsed() >= interval)
            .unwrap_or(true)
    };
    if is_due && !state.stopping.load(Ordering::Acquire) {
        perform_scan(app, &state);
    }
}

pub fn shutdown(app: &AppHandle) {
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    state.prepare_shutdown();

    let handle = state
        .monitor_thread
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .take();
    if let Some(handle) = handle {
        let _ = handle.join();
    }
}

pub fn signal_shutdown(app: &AppHandle) {
    if let Some(state) = app.try_state::<AppState>() {
        state.prepare_shutdown();
    }
}

pub fn notify_profile_failure(app: &AppHandle, detail: &str) {
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    let should_notify = {
        let mut runtime = state
            .runtime
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if !runtime.settings.notifications_enabled || !runtime.settings.notify_profile_failure {
            false
        } else {
            let cooldown = Duration::from_secs(runtime.settings.notification_cooldown_minutes * 60);
            let allowed = runtime
                .last_notifications
                .get("profile-failure")
                .map(|instant| instant.elapsed() >= cooldown)
                .unwrap_or(true);
            if allowed {
                runtime
                    .last_notifications
                    .insert("profile-failure".to_string(), Instant::now());
            }
            allowed
        }
    };
    if should_notify {
        let concise: String = detail.chars().take(180).collect();
        let _ = app
            .notification()
            .builder()
            .title("Échec d'application d'un profil")
            .body(concise)
            .show();
    }
}

#[derive(Debug)]
struct ChangeNotification {
    key: &'static str,
    title: &'static str,
    body: String,
}

fn notify_important_changes(
    app: &AppHandle,
    state: &AppState,
    previous: &NetworkSnapshot,
    current: &NetworkSnapshot,
    settings: &BackgroundSettings,
) {
    if !settings.notifications_enabled {
        return;
    }

    let mut changes = Vec::new();

    if settings.notify_new_ports {
        let previous_ports = exposed_port_keys(previous);
        let new_count = exposed_port_keys(current)
            .difference(&previous_ports)
            .count();
        if new_count > 0 {
            changes.push(ChangeNotification {
                key: "new-port",
                title: "Nouvelle exposition réseau détectée",
                body: format!(
                    "{new_count} nouveau{} port{} en écoute sur une interface réseau.",
                    if new_count > 1 { "x" } else { "" },
                    if new_count > 1 { "s" } else { "" }
                ),
            });
        }
    }

    if settings.notify_firewall_disabled
        && previous.firewall.enabled == Some(true)
        && current.firewall.enabled == Some(false)
    {
        changes.push(ChangeNotification {
            key: "firewall-disabled",
            title: "État du pare-feu modifié",
            body: "UFW était actif et apparaît maintenant désactivé.".to_string(),
        });
    }

    if settings.notify_mac_change && mac_changed(previous, current) {
        changes.push(ChangeNotification {
            key: "mac-changed",
            title: "Adresse MAC modifiée",
            body: "L'adresse MAC observée d'une interface a changé depuis la dernière analyse."
                .to_string(),
        });
    }

    if settings.notify_service_restart && service_restarted(&previous.services, &current.services) {
        changes.push(ChangeNotification {
            key: "service-restarted",
            title: "Service réseau redevenu actif",
            body: "Un service précédemment arrêté apparaît maintenant actif.".to_string(),
        });
    }

    let cooldown = Duration::from_secs(settings.notification_cooldown_minutes * 60);
    for change in changes {
        let should_notify = {
            let mut runtime = state
                .runtime
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let allowed = runtime
                .last_notifications
                .get(change.key)
                .map(|instant| instant.elapsed() >= cooldown)
                .unwrap_or(true);
            if allowed {
                runtime
                    .last_notifications
                    .insert(change.key.to_string(), Instant::now());
            }
            allowed
        };

        if should_notify {
            let _ = app
                .notification()
                .builder()
                .title(change.title)
                .body(change.body)
                .show();
        }
    }
}

fn exposed_port_keys(snapshot: &NetworkSnapshot) -> HashSet<String> {
    snapshot
        .ports
        .iter()
        .filter(|port| {
            matches!(
                port.exposure,
                ExposureLevel::AllInterfaces | ExposureLevel::SpecificInterface
            )
        })
        .map(|port| format!("{:?}:{}:{}", port.protocol, port.local_address, port.port))
        .collect()
}

fn mac_changed(previous: &NetworkSnapshot, current: &NetworkSnapshot) -> bool {
    current.interfaces.iter().any(|interface| {
        interface.eligible_for_randomization
            && previous
                .interfaces
                .iter()
                .find(|old| old.name == interface.name)
                .is_some_and(|old| {
                    old.current_mac.is_some()
                        && interface.current_mac.is_some()
                        && old.current_mac != interface.current_mac
                })
    })
}

fn service_restarted(previous: &[ServiceInfo], current: &[ServiceInfo]) -> bool {
    current.iter().any(|service| {
        service.active_state == "active"
            && previous
                .iter()
                .find(|old| old.unit == service.unit)
                .is_some_and(|old| old.active_state != "active")
    })
}

pub fn tray_status(snapshot: &NetworkSnapshot) -> tray::GeneralStatus {
    let sockets_unavailable = snapshot
        .sources
        .iter()
        .find(|source| source.source == "Sockets")
        .is_some_and(|source| source.availability == Availability::Unavailable);
    if sockets_unavailable {
        return tray::GeneralStatus::Unavailable;
    }
    if snapshot.firewall.enabled == Some(false)
        || snapshot
            .alerts
            .iter()
            .any(|alert| alert.severity == AlertSeverity::Important)
    {
        return tray::GeneralStatus::Important;
    }
    if !exposed_port_keys(snapshot).is_empty()
        || snapshot
            .alerts
            .iter()
            .any(|alert| alert.severity == AlertSeverity::Warning)
    {
        return tray::GeneralStatus::Warning;
    }
    tray::GeneralStatus::NoAlert
}

#[cfg(test)]
mod tests {
    use super::{service_restarted, tray_status};
    use crate::tray::GeneralStatus;
    use dissimulation_core::{
        Alert, AlertSeverity, AlertTarget, Availability, FirewallState, NetworkSnapshot, PingState,
        ServiceInfo, SourceStatus,
    };

    fn service(state: &str) -> ServiceInfo {
        ServiceInfo {
            unit: "example.service".to_string(),
            description: None,
            purpose: None,
            active_state: state.to_string(),
            enabled: None,
            protected: false,
            manageable: false,
        }
    }

    #[test]
    fn service_transition_is_detected_once_it_becomes_active() {
        assert!(service_restarted(
            &[service("inactive")],
            &[service("active")]
        ));
        assert!(!service_restarted(
            &[service("active")],
            &[service("active")]
        ));
    }

    fn snapshot() -> NetworkSnapshot {
        NetworkSnapshot {
            analyzed_at_epoch_ms: 0,
            ports: Vec::new(),
            services: Vec::new(),
            docker_ports: Vec::new(),
            interfaces: Vec::new(),
            firewall: FirewallState {
                installed: true,
                enabled: Some(true),
                status: "actif".to_string(),
                ..FirewallState::default()
            },
            ping: PingState {
                ipv4_echo: None,
                ipv6_echo: None,
                note: String::new(),
            },
            discovery: Vec::new(),
            alerts: Vec::new(),
            sources: vec![SourceStatus {
                source: "Sockets".to_string(),
                availability: Availability::Available,
                detail: String::new(),
            }],
        }
    }

    #[test]
    fn tray_color_follows_factual_severity() {
        let mut current = snapshot();
        assert_eq!(tray_status(&current), GeneralStatus::NoAlert);

        current.alerts.push(Alert {
            severity: AlertSeverity::Warning,
            title: String::new(),
            message: String::new(),
            target: AlertTarget::Ports,
        });
        assert_eq!(tray_status(&current), GeneralStatus::Warning);

        current.firewall.enabled = Some(false);
        assert_eq!(tray_status(&current), GeneralStatus::Important);

        current.sources[0].availability = Availability::Unavailable;
        assert_eq!(tray_status(&current), GeneralStatus::Unavailable);
    }
}
