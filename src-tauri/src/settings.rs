use serde::{Deserialize, Serialize};
use std::{fs, io, path::PathBuf};
use tauri::{AppHandle, Manager};

const SETTINGS_FILE: &str = "background-settings.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase")]
pub struct BackgroundSettings {
    pub autostart_enabled: bool,
    pub scan_interval_minutes: u64,
    pub application_traffic_monitoring: bool,
    pub application_traffic_interval_minutes: u64,
    pub application_traffic_sample_seconds: u64,
    pub traffic_history_days: u16,
    pub notifications_enabled: bool,
    pub notify_new_ports: bool,
    pub notify_firewall_disabled: bool,
    pub notify_mac_change: bool,
    pub notify_profile_failure: bool,
    pub notify_service_restart: bool,
    pub notification_cooldown_minutes: u64,
}

impl Default for BackgroundSettings {
    fn default() -> Self {
        Self {
            autostart_enabled: false,
            scan_interval_minutes: 15,
            application_traffic_monitoring: true,
            application_traffic_interval_minutes: 15,
            application_traffic_sample_seconds: 4,
            traffic_history_days: 30,
            notifications_enabled: true,
            notify_new_ports: true,
            notify_firewall_disabled: true,
            notify_mac_change: true,
            notify_profile_failure: true,
            notify_service_restart: true,
            notification_cooldown_minutes: 30,
        }
    }
}

impl BackgroundSettings {
    pub fn sanitized(mut self) -> Self {
        self.scan_interval_minutes = self.scan_interval_minutes.clamp(1, 1_440);
        self.application_traffic_interval_minutes =
            self.application_traffic_interval_minutes.clamp(5, 1_440);
        self.application_traffic_sample_seconds =
            self.application_traffic_sample_seconds.clamp(2, 15);
        self.traffic_history_days = self.traffic_history_days.clamp(1, 90);
        self.notification_cooldown_minutes = self.notification_cooldown_minutes.clamp(1, 1_440);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
pub struct PersistedSettings {
    pub background: BackgroundSettings,
    pub first_launch_completed: bool,
}

fn settings_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_config_dir()
        .map(|directory| directory.join(SETTINGS_FILE))
        .map_err(|_| "Le dossier de configuration utilisateur est indisponible.".to_string())
}

pub fn load(app: &AppHandle) -> PersistedSettings {
    let Ok(path) = settings_path(app) else {
        return PersistedSettings::default();
    };
    let Ok(content) = fs::read_to_string(path) else {
        return PersistedSettings::default();
    };

    serde_json::from_str::<PersistedSettings>(&content)
        .map(|mut settings| {
            settings.background = settings.background.sanitized();
            settings
        })
        .unwrap_or_default()
}

pub fn save(app: &AppHandle, settings: &PersistedSettings) -> Result<(), String> {
    let path = settings_path(app)?;
    let parent = path
        .parent()
        .ok_or_else(|| "Le chemin de configuration utilisateur est invalide.".to_string())?;
    fs::create_dir_all(parent)
        .map_err(|_| "Impossible de créer le dossier de configuration utilisateur.".to_string())?;

    let temporary = path.with_extension("json.tmp");
    let serialized = serde_json::to_vec_pretty(settings)
        .map_err(|_| "Impossible de préparer les paramètres.".to_string())?;

    if let Err(error) = fs::write(&temporary, serialized) {
        return Err(format_io_error(error));
    }

    if let Err(error) = fs::rename(&temporary, &path) {
        let _ = fs::remove_file(&temporary);
        return Err(format_io_error(error));
    }

    Ok(())
}

fn format_io_error(_error: io::Error) -> String {
    "Impossible d'enregistrer les paramètres utilisateur.".to_string()
}

#[cfg(test)]
mod tests {
    use super::BackgroundSettings;

    #[test]
    fn monitoring_intervals_are_bounded() {
        let settings = BackgroundSettings {
            scan_interval_minutes: 0,
            application_traffic_interval_minutes: 1,
            application_traffic_sample_seconds: 60,
            traffic_history_days: 0,
            notification_cooldown_minutes: u64::MAX,
            ..BackgroundSettings::default()
        }
        .sanitized();

        assert_eq!(settings.scan_interval_minutes, 1);
        assert_eq!(settings.application_traffic_interval_minutes, 5);
        assert_eq!(settings.application_traffic_sample_seconds, 15);
        assert_eq!(settings.traffic_history_days, 1);
        assert_eq!(settings.notification_cooldown_minutes, 1_440);
    }
}
