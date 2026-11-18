use crate::{
    privileged::{self, ActionOutcome, SystemAction},
    traffic,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs, io,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use tauri::{AppHandle, Manager};

const RULES_FILE: &str = "application-network-blocks.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationBlockRule {
    pub id: String,
    pub application_name: String,
    pub executable: Option<String>,
    pub cgroup_path: String,
    pub pid: u32,
    pub process_start_time: u64,
    pub created_at_epoch_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkApplication {
    pub id: String,
    pub name: String,
    pub executable: Option<String>,
    pub cgroup_path: String,
    pub pid: u32,
    pub process_start_time: u64,
    pub connection_count: usize,
    pub blocked_rule_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkApplicationInventory {
    pub available: bool,
    pub detail: String,
    pub applications: Vec<NetworkApplication>,
    pub block_rules: Vec<ApplicationBlockRule>,
}

#[tauri::command(async)]
pub fn get_network_applications(app: AppHandle) -> Result<NetworkApplicationInventory, String> {
    let rules = load_rules(&app)?;
    if !Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        return Ok(NetworkApplicationInventory {
            available: false,
            detail: "Le blocage précis nécessite la hiérarchie unifiée cgroup v2.".into(),
            applications: Vec::new(),
            block_rules: rules,
        });
    }
    if !Path::new("/usr/sbin/nft").exists() && !Path::new("/usr/bin/nft").exists() {
        return Ok(NetworkApplicationInventory {
            available: false,
            detail:
                "nftables n'est pas installé ; le coupe-réseau par application est indisponible."
                    .into(),
            applications: Vec::new(),
            block_rules: rules,
        });
    }

    let sessions = traffic::collect_traffic_sessions()?;
    let mut applications: HashMap<String, NetworkApplication> = HashMap::new();
    for session in sessions
        .into_iter()
        .filter(|session| !session.is_listener && session.remote_port != 0)
    {
        let (Some(pid), Some(process_start_time), Some(cgroup_path), Some(name)) = (
            session.pid,
            session.process_start_time,
            session.cgroup_path,
            session.process_name,
        ) else {
            continue;
        };
        if pid == std::process::id() {
            continue;
        }
        let key = cgroup_path.clone();
        let blocked_rule_id = rules
            .iter()
            .find(|rule| rule.cgroup_path == cgroup_path)
            .map(|rule| rule.id.clone());
        applications
            .entry(key.clone())
            .and_modify(|application| application.connection_count += 1)
            .or_insert(NetworkApplication {
                id: key,
                name,
                executable: session.executable,
                cgroup_path,
                pid,
                process_start_time,
                connection_count: 1,
                blocked_rule_id,
            });
    }
    let mut applications: Vec<_> = applications.into_values().collect();
    applications.sort_by(|left, right| {
        right
            .connection_count
            .cmp(&left.connection_count)
            .then_with(|| left.name.cmp(&right.name))
    });

    Ok(NetworkApplicationInventory {
        available: true,
        detail:
            "Le blocage vise le cgroup v2 exact de l'application et couvre ses flux TCP/UDP IPv4 et IPv6, même lorsque HTTPS ou QUIC chiffre leur contenu."
                .into(),
        applications,
        block_rules: rules,
    })
}

#[tauri::command(async)]
pub fn block_application_network(
    app: AppHandle,
    pid: u32,
    process_start_time: u64,
) -> Result<ActionOutcome, String> {
    let inventory = get_network_applications(app.clone())?;
    if !inventory.available {
        return Err(inventory.detail);
    }
    let application = inventory
        .applications
        .into_iter()
        .find(|application| {
            application.pid == pid && application.process_start_time == process_start_time
        })
        .ok_or_else(|| {
            "L'application a changé ou n'a plus de connexion active. Actualisez la liste."
                .to_string()
        })?;
    if application.blocked_rule_id.is_some() {
        return Err("Cette application possède déjà une règle de blocage.".into());
    }

    let rule = ApplicationBlockRule {
        id: format!("app-{pid}-{process_start_time}-{}", now_epoch_ms()),
        application_name: application.name,
        executable: application.executable,
        cgroup_path: application.cgroup_path,
        pid,
        process_start_time,
        created_at_epoch_ms: now_epoch_ms(),
    };
    let mut rules = load_rules(&app)?;
    rules.push(rule.clone());
    save_rules(&app, &rules)?;

    let action = SystemAction::BlockApplicationNetwork {
        rule_id: rule.id.clone(),
        pid,
        process_start_time,
    };
    match privileged::run_action(&app, &action) {
        Ok(outcome) => Ok(outcome),
        Err(error) => {
            rules.retain(|candidate| candidate.id != rule.id);
            let _ = save_rules(&app, &rules);
            Err(error)
        }
    }
}

#[tauri::command(async)]
pub fn unblock_application_network(
    app: AppHandle,
    rule_id: String,
) -> Result<ActionOutcome, String> {
    let mut rules = load_rules(&app)?;
    if !rules.iter().any(|rule| rule.id == rule_id) {
        return Err("Cette règle d'application n'appartient pas à Dissimulation.".into());
    }
    let action = SystemAction::UnblockApplicationNetwork {
        rule_id: rule_id.clone(),
    };
    let outcome = privileged::run_action(&app, &action)?;
    rules.retain(|rule| rule.id != rule_id);
    save_rules(&app, &rules)?;
    Ok(outcome)
}

pub(crate) fn clear_registry(app: &AppHandle) -> Result<(), String> {
    save_rules(app, &[])
}

fn load_rules(app: &AppHandle) -> Result<Vec<ApplicationBlockRule>, String> {
    let path = rules_path(app)?;
    let Ok(content) = fs::read(path) else {
        return Ok(Vec::new());
    };
    serde_json::from_slice(&content)
        .map_err(|_| "Le registre des blocages d'applications est illisible.".to_string())
}

fn save_rules(app: &AppHandle, rules: &[ApplicationBlockRule]) -> Result<(), String> {
    let path = rules_path(app)?;
    let parent = path
        .parent()
        .ok_or_else(|| "Le chemin du registre est invalide.".to_string())?;
    fs::create_dir_all(parent)
        .map_err(|_| "Impossible de créer le dossier de configuration.".to_string())?;
    let temporary = path.with_extension("json.tmp");
    let serialized = serde_json::to_vec_pretty(rules)
        .map_err(|_| "Impossible de préparer le registre des blocages.".to_string())?;
    fs::write(&temporary, serialized).map_err(format_io_error)?;
    if let Err(error) = fs::rename(&temporary, &path) {
        let _ = fs::remove_file(&temporary);
        return Err(format_io_error(error));
    }
    Ok(())
}

fn rules_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_config_dir()
        .map(|directory| directory.join(RULES_FILE))
        .map_err(|_| "Le dossier de configuration utilisateur est indisponible.".to_string())
}

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default()
}

fn format_io_error(_error: io::Error) -> String {
    "Impossible d'enregistrer le registre des blocages d'applications.".to_string()
}
