use crate::privileged::{self, ActionOutcome, BlockRule, SystemAction};
use serde::Serialize;
use std::{
    collections::BTreeSet,
    fs,
    net::{IpAddr, ToSocketAddrs},
    path::PathBuf,
};
use tauri::{AppHandle, Manager};

const FILTERS_FILE: &str = "block-rules.json";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedFilterTarget {
    pub kind: String,
    pub normalized_target: String,
    pub addresses: Vec<String>,
    pub detail: String,
}

#[tauri::command]
pub fn get_block_rules(app: AppHandle) -> Vec<BlockRule> {
    load(&app)
}

#[tauri::command(async)]
pub fn resolve_filter_target(target: String, port: u16) -> Result<ResolvedFilterTarget, String> {
    resolve_target(&target, port)
}

#[tauri::command(async)]
pub fn add_block_rule(app: AppHandle, mut rule: BlockRule) -> Result<ActionOutcome, String> {
    let mut rules = load(&app);
    if rules.iter().any(|existing| existing.id == rule.id) {
        return Err("Cet identifiant de filtre existe déjà.".into());
    }
    let resolved = resolve_target(&rule.remote_address, rule.port)?;
    rule.remote_address = resolved.normalized_target;
    rule.resolved_addresses = if resolved.kind == "domain" {
        resolved.addresses
    } else {
        Vec::new()
    };
    ensure_writable(&app, &rules)?;
    let outcome = privileged::run_action(&app, &SystemAction::AddBlockRule { rule: rule.clone() })?;
    rules.push(rule);
    save(&app, &rules).map_err(|error| {
        format!(
            "La règle UFW a été ajoutée, mais son index local n'a pas pu être enregistré. {error}"
        )
    })?;
    Ok(outcome)
}

pub(crate) fn clear_registry(app: &AppHandle) -> Result<(), String> {
    save(app, &[])
}

fn resolve_target(target: &str, port: u16) -> Result<ResolvedFilterTarget, String> {
    if port == 0 {
        return Err("Le port doit être compris entre 1 et 65535.".into());
    }
    let normalized = target.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized == "any" {
        return Ok(ResolvedFilterTarget {
            kind: "any".into(),
            normalized_target: normalized,
            addresses: Vec::new(),
            detail: "Toutes les adresses correspondent à cette cible.".into(),
        });
    }
    if normalized.parse::<IpAddr>().is_ok() {
        return Ok(ResolvedFilterTarget {
            kind: "address".into(),
            addresses: vec![normalized.clone()],
            normalized_target: normalized,
            detail: "Adresse IP littérale.".into(),
        });
    }
    if valid_cidr(&normalized) {
        return Ok(ResolvedFilterTarget {
            kind: "cidr".into(),
            addresses: vec![normalized.clone()],
            normalized_target: normalized,
            detail: "Plage réseau CIDR.".into(),
        });
    }
    validate_domain(&normalized)?;
    let addresses: BTreeSet<_> = (normalized.as_str(), port)
        .to_socket_addrs()
        .map_err(|_| {
            "Le nom de domaine n'a renvoyé aucune adresse IP via le DNS système.".to_string()
        })?
        .map(|address| address.ip().to_string())
        .take(32)
        .collect();
    if addresses.is_empty() {
        return Err("Le nom de domaine n'a renvoyé aucune adresse IPv4 ou IPv6.".into());
    }
    let addresses: Vec<_> = addresses.into_iter().collect();
    Ok(ResolvedFilterTarget {
        kind: "domain".into(),
        normalized_target: normalized.clone(),
        detail: format!(
            "Le domaine {normalized} sera bloqué sur {} adresse{} actuellement résolue{} ; la règle ne suivra pas automatiquement les changements DNS.",
            addresses.len(),
            if addresses.len() > 1 { "s" } else { "" },
            if addresses.len() > 1 { "s" } else { "" }
        ),
        addresses,
    })
}

fn valid_cidr(value: &str) -> bool {
    let Some((address, prefix)) = value.split_once('/') else {
        return false;
    };
    let Ok(address) = address.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    prefix <= if address.is_ipv4() { 32 } else { 128 }
}

fn validate_domain(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 253
        || !value.contains('.')
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        })
    {
        return Err("La cible doit être « any », une IP, un CIDR ou un nom de domaine DNS valide. Utilisez la forme punycode pour un domaine internationalisé.".into());
    }
    Ok(())
}

#[tauri::command(async)]
pub fn remove_block_rule(app: AppHandle, rule_id: String) -> Result<ActionOutcome, String> {
    let mut rules = load(&app);
    if !rules.iter().any(|rule| rule.id == rule_id) {
        return Err("Ce filtre n'est pas enregistré par Dissimulation.".into());
    }
    ensure_writable(&app, &rules)?;
    let outcome = privileged::run_action(
        &app,
        &SystemAction::RemoveBlockRule {
            rule_id: rule_id.clone(),
        },
    )?;
    rules.retain(|rule| rule.id != rule_id);
    save(&app, &rules).map_err(|error| {
        format!(
            "La règle UFW a été supprimée, mais son index local n'a pas pu être mis à jour. {error}"
        )
    })?;
    Ok(outcome)
}

fn path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_config_dir()
        .map(|directory| directory.join(FILTERS_FILE))
        .map_err(|_| "Le dossier de configuration utilisateur est indisponible.".into())
}

fn load(app: &AppHandle) -> Vec<BlockRule> {
    let Ok(path) = path(app) else {
        return Vec::new();
    };
    let Ok(content) = fs::read_to_string(path) else {
        return Vec::new();
    };
    serde_json::from_str(&content).unwrap_or_default()
}

fn ensure_writable(app: &AppHandle, rules: &[BlockRule]) -> Result<(), String> {
    let path = path(app)?;
    let parent = path
        .parent()
        .ok_or_else(|| "Le chemin de configuration utilisateur est invalide.".to_string())?;
    fs::create_dir_all(parent)
        .map_err(|_| "Impossible de préparer le registre local des filtres.".to_string())?;
    let probe = path.with_extension("json.probe");
    let serialized = serde_json::to_vec(rules)
        .map_err(|_| "Impossible de préparer le registre local des filtres.".to_string())?;
    fs::write(&probe, serialized).map_err(|_| {
        "Le registre local des filtres n'est pas accessible en écriture.".to_string()
    })?;
    fs::remove_file(probe)
        .map_err(|_| "Impossible de nettoyer le test du registre local des filtres.".to_string())
}

fn save(app: &AppHandle, rules: &[BlockRule]) -> Result<(), String> {
    let path = path(app)?;
    let parent = path
        .parent()
        .ok_or_else(|| "Le chemin de configuration utilisateur est invalide.".to_string())?;
    fs::create_dir_all(parent)
        .map_err(|_| "Impossible de créer le dossier de configuration utilisateur.".to_string())?;
    let temporary = path.with_extension("json.tmp");
    let serialized = serde_json::to_vec_pretty(rules)
        .map_err(|_| "Impossible de préparer le registre local des filtres.".to_string())?;
    fs::write(&temporary, serialized)
        .map_err(|_| "Impossible d'enregistrer le registre local des filtres.".to_string())?;
    fs::rename(&temporary, &path)
        .map_err(|_| "Impossible d'installer le registre local des filtres.".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ip_cidr_and_dns_names_without_urls() {
        assert_eq!(resolve_target("192.0.2.1", 443).unwrap().kind, "address");
        assert_eq!(resolve_target("2001:db8::/64", 443).unwrap().kind, "cidr");
        assert!(validate_domain("api.example.org").is_ok());
        assert!(validate_domain("https://example.org/path").is_err());
        assert!(validate_domain("-invalid.example").is_err());
    }
}
