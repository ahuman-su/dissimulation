use crate::{
    app_control, filters,
    runtime::{self, AppState, LifecycleState},
};
use serde::{Deserialize, Serialize};
use std::{
    env, fs,
    io::{BufRead, BufReader, Read, Write},
    net::IpAddr,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};
use tauri::{AppHandle, Emitter, Manager};

const PROGRESS_PREFIX: &str = "DISSIMULATION_PROGRESS\t";

const NETWORK_MANAGER_CONFIG: &str =
    "/etc/NetworkManager/conf.d/90-dissimulation-mac-randomization.conf";
const IPV4_ECHO_CONFIG: &str = "/etc/sysctl.d/90-dissimulation-icmp.conf";
const LLMNR_CONFIG: &str = "/etc/systemd/resolved.conf.d/90-dissimulation-llmnr.conf";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BlockRule {
    pub id: String,
    pub name: String,
    pub direction: String,
    pub protocol: String,
    pub remote_address: String,
    pub port: u16,
    #[serde(default)]
    pub resolved_addresses: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum SystemAction {
    SetMacMode {
        interface: String,
        mode: String,
    },
    ManageService {
        unit: String,
        action: String,
    },
    ApplyFirewallBaseline {
        preserve_ssh: bool,
    },
    SetIpv4Echo {
        enabled: bool,
    },
    AddBlockRule {
        rule: BlockRule,
    },
    RemoveBlockRule {
        rule_id: String,
    },
    ApplyProfile {
        profile: String,
        options: Vec<String>,
    },
    BlockApplicationNetwork {
        rule_id: String,
        pid: u32,
        process_start_time: u64,
    },
    UnblockApplicationNetwork {
        rule_id: String,
    },
    InspectFirewall,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionProgress {
    pub operation: String,
    pub current: usize,
    pub total: usize,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionOutcome {
    pub title: String,
    pub message: String,
    pub changed: bool,
    pub reconnect_performed: bool,
}

#[tauri::command(async)]
pub fn execute_system_action(
    app: AppHandle,
    action: SystemAction,
) -> Result<ActionOutcome, String> {
    let reset_filter_registry = matches!(
        &action,
        SystemAction::ApplyProfile { profile, options }
            if profile == "restore" && options.iter().any(|option| option == "firewall-default")
    );
    let reset_application_registry = matches!(
        &action,
        SystemAction::ApplyProfile { profile, options }
            if profile == "restore" && options.iter().any(|option| option == "app-blocks")
    );
    let outcome = run_action(&app, &action)?;
    if reset_filter_registry {
        filters::clear_registry(&app).map_err(|error| {
            format!("Les réglages système ont été réinitialisés, mais le registre local des filtres n'a pas pu être vidé. {error}")
        })?;
    }
    if reset_application_registry {
        app_control::clear_registry(&app).map_err(|error| {
            format!("Les règles système ont été retirées, mais le registre local des applications bloquées n'a pas pu être vidé. {error}")
        })?;
    }
    Ok(outcome)
}

#[tauri::command(async)]
pub fn inspect_firewall_with_authorization(
    app: AppHandle,
) -> Result<dissimulation_core::FirewallState, String> {
    run_helper(&app, &SystemAction::InspectFirewall)
}

pub(crate) fn run_action(app: &AppHandle, action: &SystemAction) -> Result<ActionOutcome, String> {
    run_helper(app, action)
}

fn run_helper<T>(app: &AppHandle, action: &SystemAction) -> Result<T, String>
where
    T: serde::de::DeserializeOwned,
{
    let notify_profile_failure = matches!(action, SystemAction::ApplyProfile { .. });
    let executable = std::env::current_exe()
        .map_err(|_| "Impossible de localiser l'exécutable de Dissimulation.".to_string())?;
    let payload = serde_json::to_string(action)
        .map_err(|_| "Impossible de préparer l'action système.".to_string())?;
    if let Some(state) = app.try_state::<AppState>() {
        state.set_lifecycle(LifecycleState::AuthorizationRequest);
    }
    let execution: Result<(std::process::ExitStatus, String, Option<String>), String> = (|| {
        let mut child = Command::new("/usr/bin/pkexec")
            .arg(executable)
            .arg("--privileged-helper")
            .arg(payload)
            .env("LC_ALL", "C")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| {
                "Polkit (pkexec) n'est pas disponible. Installez le paquet policykit-1.".to_string()
            })?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "La sortie du composant privilégié est indisponible.".to_string())?;
        let mut response = None;
        for line in BufReader::new(stdout).lines() {
            let line =
                line.map_err(|_| "La réponse du composant privilégié est illisible.".to_string())?;
            if let Some(payload) = line.strip_prefix(PROGRESS_PREFIX) {
                if let Ok(progress) = serde_json::from_str::<ActionProgress>(payload) {
                    let _ = app.emit("system-action-progress", progress);
                }
            } else if !line.trim().is_empty() {
                response = Some(line);
            }
        }
        let status = child.wait().map_err(|_| {
            "Le composant privilégié ne s'est pas terminé correctement.".to_string()
        })?;
        let mut detail = String::new();
        if let Some(mut stderr) = child.stderr.take() {
            let _ = stderr.read_to_string(&mut detail);
        }
        Ok((status, detail, response))
    })();
    runtime::restore_window_lifecycle(app);

    let (status, detail, response) = execution?;
    if !status.success() {
        let detail = detail.trim().to_string();
        let error = if status.code() == Some(126) {
            "La fenêtre Polkit a été fermée ou annulée. Aucun changement n'a été appliqué et aucun mot de passe n'a été conservé."
                .to_string()
        } else if status.code() == Some(127) {
            "Polkit n'a pas pu obtenir l'autorisation. Vérifiez qu'un agent d'authentification est actif dans la session Ubuntu, puis réessayez."
                .to_string()
        } else if detail.is_empty() {
            "La modification système a échoué sans modifier les paramètres utilisateur de l'application."
                .to_string()
        } else {
            detail
        };
        if notify_profile_failure {
            runtime::notify_profile_failure(app, &error);
        }
        return Err(error);
    }
    let response = response
        .ok_or_else(|| "Le composant privilégié n'a renvoyé aucune réponse.".to_string())?;
    serde_json::from_str(response.trim())
        .map_err(|_| "Le composant privilégié a renvoyé une réponse invalide.".to_string())
}

pub fn run_from_arguments() -> i32 {
    let payload = match std::env::args().nth(2) {
        Some(payload) => payload,
        None => {
            eprintln!("Action privilégiée absente.");
            return 2;
        }
    };
    if payload.len() > 8_192 {
        eprintln!("Action privilégiée trop volumineuse.");
        return 2;
    }
    if !is_root() {
        eprintln!("Cette action doit être autorisée par Polkit.");
        return 3;
    }
    let action = match serde_json::from_str::<SystemAction>(&payload) {
        Ok(action) => action,
        Err(_) => {
            eprintln!("Action privilégiée invalide.");
            return 4;
        }
    };

    let result = match action {
        SystemAction::InspectFirewall => {
            write_helper_progress(ActionProgress {
                operation: "inspectFirewall".into(),
                current: 1,
                total: 2,
                label: "Lecture détaillée de l'état et des règles UFW".into(),
            });
            let state = dissimulation_core::collectors::inspect_firewall_state();
            write_helper_progress(ActionProgress {
                operation: "inspectFirewall".into(),
                current: 2,
                total: 2,
                label: "Lecture UFW terminée".into(),
            });
            serde_json::to_string(&state)
                .map_err(|_| "Impossible de sérialiser l'état du pare-feu.".to_string())
        }
        action => {
            apply_action_with_progress(action, &mut write_helper_progress).and_then(|outcome| {
                serde_json::to_string(&outcome)
                    .map_err(|_| "Impossible de sérialiser le résultat de l'action.".to_string())
            })
        }
    };

    match result {
        Ok(serialized) => {
            println!("{serialized}");
            0
        }
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

fn write_helper_progress(progress: ActionProgress) {
    if let Ok(serialized) = serde_json::to_string(&progress) {
        println!("{PROGRESS_PREFIX}{serialized}");
        let _ = std::io::stdout().flush();
    }
}

fn is_root() -> bool {
    run_output("/usr/bin/id", &["-u"])
        .is_ok_and(|output| output.status.success() && text_stdout(&output).trim() == "0")
}

fn apply_action_with_progress(
    action: SystemAction,
    on_progress: &mut impl FnMut(ActionProgress),
) -> Result<ActionOutcome, String> {
    if let SystemAction::ApplyProfile { profile, options } = &action {
        return apply_profile(profile, options, on_progress);
    }

    let operation = action_progress_operation(&action).to_string();
    on_progress(ActionProgress {
        operation: operation.clone(),
        current: 1,
        total: 2,
        label: action_progress_label(&action).into(),
    });
    let outcome = match action {
        SystemAction::SetMacMode { interface, mode } => set_mac_mode(&interface, &mode, true),
        SystemAction::ManageService { unit, action } => manage_service(&unit, &action),
        SystemAction::ApplyFirewallBaseline { preserve_ssh } => {
            apply_firewall_baseline(preserve_ssh)
        }
        SystemAction::SetIpv4Echo { enabled } => set_ipv4_echo(enabled),
        SystemAction::AddBlockRule { rule } => add_block_rule(&rule),
        SystemAction::RemoveBlockRule { rule_id } => remove_block_rule(&rule_id),
        SystemAction::ApplyProfile { .. } => unreachable!(),
        SystemAction::BlockApplicationNetwork {
            rule_id,
            pid,
            process_start_time,
        } => block_application_network(&rule_id, pid, process_start_time),
        SystemAction::UnblockApplicationNetwork { rule_id } => {
            unblock_application_network(&rule_id)
        }
        SystemAction::InspectFirewall => {
            Err("Action de lecture envoyée au mauvais traitement.".into())
        }
    };
    if outcome.is_ok() {
        on_progress(ActionProgress {
            operation,
            current: 2,
            total: 2,
            label: "Finalisation et vérification du résultat".into(),
        });
    }
    outcome
}

fn action_progress_operation(action: &SystemAction) -> &'static str {
    match action {
        SystemAction::SetMacMode { .. } => "setMacMode",
        SystemAction::ManageService { .. } => "manageService",
        SystemAction::ApplyFirewallBaseline { .. } => "applyFirewallBaseline",
        SystemAction::SetIpv4Echo { .. } => "setIpv4Echo",
        SystemAction::AddBlockRule { .. } => "addBlockRule",
        SystemAction::RemoveBlockRule { .. } => "removeBlockRule",
        SystemAction::ApplyProfile { .. } => "applyProfile",
        SystemAction::BlockApplicationNetwork { .. } => "blockApplicationNetwork",
        SystemAction::UnblockApplicationNetwork { .. } => "unblockApplicationNetwork",
        SystemAction::InspectFirewall => "inspectFirewall",
    }
}

fn action_progress_label(action: &SystemAction) -> &'static str {
    match action {
        SystemAction::SetMacMode { .. } => "Enregistrement du mode MAC dans NetworkManager",
        SystemAction::ManageService { .. } => "Exécution de la commande systemd confirmée",
        SystemAction::ApplyFirewallBaseline { .. } => "Application de la politique générale UFW",
        SystemAction::SetIpv4Echo { .. } => "Application du réglage ICMP IPv4",
        SystemAction::AddBlockRule { .. } => "Ajout des règles de filtrage UFW",
        SystemAction::RemoveBlockRule { .. } => "Suppression des règles de filtrage UFW",
        SystemAction::ApplyProfile { .. } => "Application du profil",
        SystemAction::BlockApplicationNetwork { .. } => {
            "Création de la règle nftables pour l'application"
        }
        SystemAction::UnblockApplicationNetwork { .. } => {
            "Suppression de la règle nftables de l'application"
        }
        SystemAction::InspectFirewall => "Lecture détaillée du pare-feu UFW",
    }
}

fn set_mac_mode(interface: &str, mode: &str, reconnect: bool) -> Result<ActionOutcome, String> {
    validate_interface(interface)?;
    let nm_mode = validate_mac_mode(mode)?;
    let active_uuid = successful_stdout(
        "/usr/bin/nmcli",
        &["-g", "GENERAL.CON-UUID", "device", "show", interface],
        "NetworkManager n'a pas pu identifier la connexion Wi-Fi active.",
    )?
    .trim()
    .to_string();

    persist_global_mac_mode(nm_mode)?;
    let has_active_profile = !active_uuid.is_empty() && active_uuid != "--";
    if has_active_profile {
        run_checked(
            "/usr/bin/nmcli",
            &[
                "connection",
                "modify",
                &active_uuid,
                "802-11-wireless.cloned-mac-address",
                nm_mode,
            ],
            "Le profil Wi-Fi actuellement connecté n'a pas pu être mis à jour.",
        )?;
    }
    let _ = run_output("/usr/bin/nmcli", &["general", "reload"]);

    let mut reconnect_performed = false;
    if reconnect && has_active_profile {
        run_checked(
            "/usr/bin/nmcli",
            &["device", "disconnect", interface],
            "Le mode est enregistré, mais la déconnexion Wi-Fi a échoué.",
        )?;
        run_checked(
            "/usr/bin/nmcli",
            &["connection", "up", &active_uuid, "ifname", interface],
            "Le mode est enregistré, mais la reconnexion Wi-Fi a échoué. Reconnectez-vous depuis le panneau réseau.",
        )?;
        reconnect_performed = true;
    }

    Ok(ActionOutcome {
        title: "Mode MAC enregistré".into(),
        message: if has_active_profile {
            format!(
                "Mode {mode} enregistré dans le profil Wi-Fi actuellement connecté et comme valeur persistante par défaut pour les prochains réseaux."
            )
        } else {
            format!(
                "Mode {mode} enregistré comme valeur persistante par défaut pour les prochains réseaux ; aucun profil Wi-Fi actif n'a été modifié."
            )
        },
        changed: true,
        reconnect_performed,
    })
}

fn persist_global_mac_mode(mode: &str) -> Result<(), String> {
    let content = format!(
        "# Géré par Dissimulation\n[device]\nwifi.scan-rand-mac-address=yes\n\n[connection]\nwifi.cloned-mac-address={mode}\n"
    );
    atomic_write(Path::new(NETWORK_MANAGER_CONFIG), content.as_bytes())
}

fn wifi_connection_uuids() -> Result<Vec<String>, String> {
    let output = successful_stdout(
        "/usr/bin/nmcli",
        &["-t", "-f", "UUID,TYPE", "connection", "show"],
        "NetworkManager n'a pas pu lister les profils Wi-Fi.",
    )?;
    Ok(output
        .lines()
        .filter_map(|line| line.rsplit_once(':'))
        .filter(|(_, kind)| matches!(*kind, "wifi" | "802-11-wireless"))
        .map(|(uuid, _)| uuid.to_string())
        .filter(|uuid| valid_uuid(uuid))
        .collect())
}

fn validate_interface(interface: &str) -> Result<(), String> {
    if interface.is_empty()
        || interface.len() > 32
        || !interface
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_.-".contains(character))
        || !Path::new("/sys/class/net")
            .join(interface)
            .join("wireless")
            .exists()
    {
        return Err("L'interface Wi-Fi demandée n'est pas valide.".into());
    }
    Ok(())
}

fn validate_mac_mode(mode: &str) -> Result<&'static str, String> {
    match mode {
        "hardware" => Ok("permanent"),
        "stable" => Ok("stable"),
        "random" => Ok("random"),
        "preserve" => Ok("preserve"),
        _ => Err("Le mode de randomisation MAC n'est pas autorisé.".into()),
    }
}

fn manage_service(unit: &str, action: &str) -> Result<ActionOutcome, String> {
    if !manageable_unit(unit) {
        return Err(
            "Cette unité n'appartient pas à la liste fermée des services réseau gérables.".into(),
        );
    }
    let command = match action {
        "start" | "stop" | "enable" | "disable" => action,
        _ => return Err("Action systemd non autorisée.".into()),
    };
    run_checked(
        "/usr/bin/systemctl",
        &[command, unit],
        "systemd a refusé la modification du service.",
    )?;
    Ok(ActionOutcome {
        title: "Service mis à jour".into(),
        message: format!("Action {command} appliquée à {unit}."),
        changed: true,
        reconnect_performed: false,
    })
}

fn manageable_unit(unit: &str) -> bool {
    dissimulation_core::collectors::is_manageable_network_service(unit)
}

fn apply_firewall_baseline(preserve_ssh: bool) -> Result<ActionOutcome, String> {
    if run_output("/usr/bin/systemctl", &["is-active", "nftables.service"])
        .is_ok_and(|output| output.status.success())
    {
        return Err("Le service nftables natif est actif. Dissimulation refuse de le mélanger automatiquement avec UFW.".into());
    }
    ufw_checked(&["default", "deny", "incoming"])?;
    ufw_checked(&["default", "allow", "outgoing"])?;
    if preserve_ssh {
        ufw_checked(&["allow", "OpenSSH", "comment", "Dissimulation:preserve-ssh"])?;
    }
    ufw_checked(&["--force", "enable"])?;
    Ok(ActionOutcome {
        title: "Politique UFW appliquée".into(),
        message: if preserve_ssh {
            "UFW est actif, les connexions entrantes sont refusées par défaut et le profil OpenSSH a été préservé."
                .into()
        } else {
            "UFW est actif, les connexions entrantes sont refusées et les sorties sont autorisées par défaut."
                .into()
        },
        changed: true,
        reconnect_performed: false,
    })
}

fn set_ipv4_echo(enabled: bool) -> Result<ActionOutcome, String> {
    let ignored = if enabled { "0" } else { "1" };
    atomic_write(
        Path::new(IPV4_ECHO_CONFIG),
        format!("# Géré par Dissimulation\nnet.ipv4.icmp_echo_ignore_all={ignored}\n").as_bytes(),
    )?;
    run_checked(
        "/usr/sbin/sysctl",
        &["-w", &format!("net.ipv4.icmp_echo_ignore_all={ignored}")],
        "Le noyau a refusé le réglage ICMP Echo IPv4.",
    )?;
    Ok(ActionOutcome {
        title: "Réponse Echo IPv4 mise à jour".into(),
        message: if enabled {
            "Les réponses ICMP Echo IPv4 sont activées et le réglage persistera au redémarrage."
                .into()
        } else {
            "Les réponses ICMP Echo IPv4 sont désactivées et le réglage persistera au redémarrage."
                .into()
        },
        changed: true,
        reconnect_performed: false,
    })
}

fn add_block_rule(rule: &BlockRule) -> Result<ActionOutcome, String> {
    validate_block_rule(rule)?;
    if run_output("/usr/bin/systemctl", &["is-active", "nftables.service"])
        .is_ok_and(|output| output.status.success())
    {
        return Err(
            "Le service nftables natif est actif. Le filtre UFW n'a pas été ajouté.".into(),
        );
    }
    let status = successful_stdout(
        "/usr/sbin/ufw",
        &["status"],
        "UFW n'a pas pu confirmer son état.",
    )?;
    if !status.lines().any(|line| line.trim() == "Status: active") {
        return Err("UFW doit être actif avant d'ajouter un filtre. Appliquez d'abord la politique dans la page Pare-feu.".into());
    }
    let comment = format!("Dissimulation:{}", rule.id);
    let port = rule.port.to_string();
    let targets = block_rule_targets(rule)?;
    for target in &targets {
        let mut arguments = vec!["deny", direction_arg(&rule.direction)?];
        if rule.protocol != "any" {
            arguments.extend(["proto", rule.protocol.as_str()]);
        }
        if rule.direction == "incoming" {
            arguments.extend(["from", target, "to", "any", "port", &port]);
        } else {
            arguments.extend(["from", "any", "to", target, "port", &port]);
        }
        arguments.extend(["comment", &comment]);
        if let Err(error) = ufw_checked(&arguments) {
            let _ = remove_owned_ufw_rules(&comment);
            return Err(error);
        }
    }
    Ok(ActionOutcome {
        title: "Filtre de blocage ajouté".into(),
        message: format!(
            "La règle « {} » est enregistrée dans UFW pour {} cible{} IP.",
            rule.name,
            targets.len(),
            if targets.len() > 1 { "s" } else { "" }
        ),
        changed: true,
        reconnect_performed: false,
    })
}

fn remove_block_rule(rule_id: &str) -> Result<ActionOutcome, String> {
    validate_rule_id(rule_id)?;
    let marker = format!("Dissimulation:{rule_id}");
    let removed = remove_owned_ufw_rules(&marker)?;
    if removed == 0 {
        return Ok(ActionOutcome {
            title: "Filtre déjà absent".into(),
            message: "Aucune règle UFW portant cet identifiant Dissimulation n'est active.".into(),
            changed: false,
            reconnect_performed: false,
        });
    }
    Ok(ActionOutcome {
        title: "Filtre supprimé".into(),
        message: format!(
            "{} règle{} UFW portant uniquement le marqueur de ce filtre ont été supprimées.",
            removed,
            if removed > 1 { "s" } else { "" }
        ),
        changed: true,
        reconnect_performed: false,
    })
}

fn block_rule_targets(rule: &BlockRule) -> Result<Vec<&str>, String> {
    if validate_ip_or_cidr(&rule.remote_address).is_ok() {
        if !rule.resolved_addresses.is_empty() {
            return Err("Une cible IP ou CIDR ne doit pas fournir d'adresses DNS résolues.".into());
        }
        return Ok(vec![rule.remote_address.as_str()]);
    }
    validate_domain(&rule.remote_address)?;
    if rule.resolved_addresses.is_empty() || rule.resolved_addresses.len() > 32 {
        return Err("Le domaine doit fournir entre 1 et 32 adresses IP résolues.".into());
    }
    if rule
        .resolved_addresses
        .iter()
        .any(|address| address.parse::<IpAddr>().is_err())
    {
        return Err("Une adresse DNS résolue est invalide.".into());
    }
    Ok(rule.resolved_addresses.iter().map(String::as_str).collect())
}

fn remove_owned_ufw_rules(marker: &str) -> Result<usize, String> {
    let status = successful_stdout(
        "/usr/sbin/ufw",
        &["status", "numbered"],
        "UFW n'a pas pu lister les règles.",
    )?;
    let mut numbers: Vec<u32> = status
        .lines()
        .filter_map(|line| {
            if !line.contains(marker) {
                return None;
            }
            let end = line.find(']')?;
            line.get(1..end)?.trim().parse().ok()
        })
        .collect();
    numbers.sort_unstable_by(|left, right| right.cmp(left));
    numbers.dedup();
    for number in &numbers {
        ufw_checked(&["--force", "delete", &number.to_string()])?;
    }
    Ok(numbers.len())
}

const APPLICATION_TABLE: &str = "dissimulation_app_control";
const APPLICATION_CHAIN: &str = "output";

fn block_application_network(
    rule_id: &str,
    pid: u32,
    expected_start_time: u64,
) -> Result<ActionOutcome, String> {
    validate_rule_id(rule_id)?;
    if pid < 2 || expected_start_time == 0 {
        return Err("La cible de l'application est invalide.".into());
    }
    let caller_uid = polkit_caller_uid()?;
    let process_directory = PathBuf::from(format!("/proc/{pid}"));
    let metadata = fs::metadata(&process_directory)
        .map_err(|_| "L'application n'est plus active. Actualisez la liste.".to_string())?;
    if metadata.uid() != caller_uid {
        return Err(
            "Dissimulation refuse de bloquer un processus appartenant à un autre utilisateur."
                .into(),
        );
    }
    if process_start_time(pid) != Some(expected_start_time) {
        return Err(
            "Le PID a été réutilisé ou l'application a redémarré. Actualisez la liste.".into(),
        );
    }
    let cgroup_path = process_cgroup_path(pid)?;
    let expected_user_slice = format!("user-{caller_uid}.slice");
    if !cgroup_path
        .split('/')
        .any(|component| component == expected_user_slice)
    {
        return Err("Le processus n'appartient pas au cgroup de la session utilisateur.".into());
    }
    let components: Vec<_> = cgroup_path
        .split('/')
        .filter(|component| !component.is_empty())
        .collect();
    if components.is_empty() || components.len() > 64 {
        return Err("Le cgroup de l'application est invalide.".into());
    }
    let cgroup_directory = Path::new("/sys/fs/cgroup").join(cgroup_path.trim_start_matches('/'));
    fs::metadata(&cgroup_directory)
        .map_err(|_| "Le cgroup de l'application n'existe plus.".to_string())?;

    let nft = nft_program()?;
    ensure_application_chain(nft)?;
    let marker = format!("Dissimulation:app:{rule_id}");
    if application_rule_handle(nft, &marker)?.is_some() {
        return Ok(ActionOutcome {
            title: "Communication déjà bloquée".into(),
            message: "La règle nftables de cette application était déjà active.".into(),
            changed: false,
            reconnect_performed: false,
        });
    }

    let mut arguments = vec![
        "add".to_string(),
        "rule".to_string(),
        "inet".to_string(),
        APPLICATION_TABLE.to_string(),
        APPLICATION_CHAIN.to_string(),
    ];
    for (index, component) in components.iter().enumerate() {
        arguments.extend([
            "socket".to_string(),
            "cgroupv2".to_string(),
            "level".to_string(),
            (index + 1).to_string(),
            nft_quoted(component)?,
        ]);
    }
    arguments.extend([
        "meta".to_string(),
        "l4proto".to_string(),
        "{ tcp, udp }".to_string(),
        "counter".to_string(),
        "reject".to_string(),
        "comment".to_string(),
        nft_quoted(&marker)?,
    ]);
    let argument_refs: Vec<_> = arguments.iter().map(String::as_str).collect();
    run_checked(
        nft,
        &argument_refs,
        "nftables n'a pas pu bloquer l'application.",
    )?;

    Ok(ActionOutcome {
        title: "Communication de l'application bloquée".into(),
        message: "Les flux TCP/UDP IPv4 et IPv6 associés au cgroup exact de l'application sont maintenant rejetés, y compris HTTPS et QUIC chiffrés."
            .into(),
        changed: true,
        reconnect_performed: false,
    })
}

fn nft_quoted(value: &str) -> Result<String, String> {
    if value.is_empty() || value.len() > 255 || value.chars().any(char::is_control) {
        return Err("Un composant du cgroup ne peut pas être représenté dans nftables.".into());
    }
    Ok(format!(
        "\"{}\"",
        value.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

fn unblock_application_network(rule_id: &str) -> Result<ActionOutcome, String> {
    validate_rule_id(rule_id)?;
    let nft = nft_program()?;
    let marker = format!("Dissimulation:app:{rule_id}");
    let Some(handle) = application_rule_handle(nft, &marker)? else {
        return Ok(ActionOutcome {
            title: "Blocage déjà absent".into(),
            message: "Aucune règle nftables portant cet identifiant Dissimulation n'est active."
                .into(),
            changed: false,
            reconnect_performed: false,
        });
    };
    run_checked(
        nft,
        &[
            "delete",
            "rule",
            "inet",
            APPLICATION_TABLE,
            APPLICATION_CHAIN,
            "handle",
            &handle.to_string(),
        ],
        "nftables n'a pas pu retirer le blocage de l'application.",
    )?;
    Ok(ActionOutcome {
        title: "Communication de l'application rétablie".into(),
        message: "La règle nftables créée par Dissimulation a été retirée.".into(),
        changed: true,
        reconnect_performed: false,
    })
}

fn ensure_application_chain(nft: &str) -> Result<(), String> {
    if !run_output(nft, &["list", "table", "inet", APPLICATION_TABLE])
        .is_ok_and(|output| output.status.success())
    {
        let output = run_output(nft, &["add", "table", "inet", APPLICATION_TABLE])?;
        if !output.status.success() && !text_stderr(&output).contains("File exists") {
            return Err("nftables n'a pas pu créer la table isolée de Dissimulation.".into());
        }
    }
    if !run_output(
        nft,
        &[
            "list",
            "chain",
            "inet",
            APPLICATION_TABLE,
            APPLICATION_CHAIN,
        ],
    )
    .is_ok_and(|output| output.status.success())
    {
        let output = run_output(
            nft,
            &[
                "add",
                "chain",
                "inet",
                APPLICATION_TABLE,
                APPLICATION_CHAIN,
                "{ type filter hook output priority 10; policy accept; }",
            ],
        )?;
        if !output.status.success() && !text_stderr(&output).contains("File exists") {
            return Err(format!(
                "nftables n'a pas pu créer la chaîne de sortie. {}",
                text_stderr(&output).trim()
            ));
        }
    }
    Ok(())
}

fn application_rule_handle(nft: &str, marker: &str) -> Result<Option<u64>, String> {
    let output = run_output(
        nft,
        &[
            "-a",
            "list",
            "chain",
            "inet",
            APPLICATION_TABLE,
            APPLICATION_CHAIN,
        ],
    )?;
    if !output.status.success() {
        return Ok(None);
    }
    let exact_marker = format!("comment \"{marker}\"");
    Ok(text_stdout(&output).lines().find_map(|line| {
        if !line.contains(&exact_marker) {
            return None;
        }
        line.rsplit_once("# handle ")?.1.trim().parse().ok()
    }))
}

fn nft_program() -> Result<&'static str, String> {
    ["/usr/sbin/nft", "/usr/bin/nft"]
        .into_iter()
        .find(|path| Path::new(path).exists())
        .ok_or_else(|| "nftables n'est pas installé.".to_string())
}

fn polkit_caller_uid() -> Result<u32, String> {
    let uid = env::var("PKEXEC_UID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(|| "L'identité de l'utilisateur Polkit est absente.".to_string())?;
    if uid == 0 {
        return Err("Le coupe-réseau par application doit être demandé depuis une session utilisateur non root."
            .into());
    }
    Ok(uid)
}

fn process_cgroup_path(pid: u32) -> Result<String, String> {
    fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .ok()
        .and_then(|content| {
            content
                .lines()
                .find_map(|line| line.strip_prefix("0::"))
                .map(str::to_string)
        })
        .filter(|path| path.starts_with('/') && path.len() > 1 && path.len() <= 1_024)
        .ok_or_else(|| "Le cgroup v2 de l'application est indisponible.".to_string())
}

fn process_start_time(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let closing_parenthesis = stat.rfind(')')?;
    stat.get(closing_parenthesis + 1..)?
        .split_whitespace()
        .nth(19)
        .and_then(|value| value.parse().ok())
}

fn validate_block_rule(rule: &BlockRule) -> Result<(), String> {
    validate_rule_id(&rule.id)?;
    if rule.name.trim().is_empty()
        || rule.name.chars().count() > 80
        || rule.name.contains(['\n', '\r'])
    {
        return Err("Le nom du filtre est invalide.".into());
    }
    direction_arg(&rule.direction)?;
    if !matches!(rule.protocol.as_str(), "tcp" | "udp" | "any") {
        return Err("Le protocole du filtre est invalide.".into());
    }
    if validate_ip_or_cidr(&rule.remote_address).is_err() {
        validate_domain(&rule.remote_address)?;
    }
    let _ = block_rule_targets(rule)?;
    if rule.port == 0 {
        return Err("Le port doit être compris entre 1 et 65535.".into());
    }
    Ok(())
}

fn validate_rule_id(rule_id: &str) -> Result<(), String> {
    if rule_id.len() < 8
        || rule_id.len() > 64
        || !rule_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
    {
        return Err("L'identifiant du filtre est invalide.".into());
    }
    Ok(())
}

fn direction_arg(direction: &str) -> Result<&'static str, String> {
    match direction {
        "incoming" => Ok("in"),
        "outgoing" => Ok("out"),
        _ => Err("La direction du filtre est invalide.".into()),
    }
}

fn validate_ip_or_cidr(value: &str) -> Result<(), String> {
    if value == "any" {
        return Ok(());
    }
    let (address, prefix) = value
        .split_once('/')
        .map(|(address, prefix)| (address, Some(prefix)))
        .unwrap_or((value, None));
    let address = address.parse::<IpAddr>().map_err(|_| {
        "L'adresse distante doit être une adresse IP, un CIDR ou « any ».".to_string()
    })?;
    if let Some(prefix) = prefix {
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| "Le préfixe CIDR est invalide.".to_string())?;
        let maximum = if address.is_ipv4() { 32 } else { 128 };
        if prefix > maximum {
            return Err("Le préfixe CIDR dépasse la taille de l'adresse.".into());
        }
    }
    Ok(())
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
        return Err("Le nom de domaine du filtre est invalide.".into());
    }
    Ok(())
}

fn apply_profile(
    profile: &str,
    options: &[String],
    on_progress: &mut impl FnMut(ActionProgress),
) -> Result<ActionOutcome, String> {
    let allowed: &[&str] = match profile {
        "public" => &["firewall", "icmp4", "avahi", "llmnr", "wifi-random"],
        "home" => &["firewall", "avahi", "wifi-stable"],
        "development" => &["firewall", "icmp4-enable", "avahi", "wifi-stable"],
        "restore" => &[
            "wifi-default",
            "firewall-default",
            "icmp4-default",
            "llmnr-default",
            "services-default",
            "app-blocks",
        ],
        _ => return Err("Profil de sécurité inconnu.".into()),
    };
    if options.is_empty()
        || options
            .iter()
            .any(|option| !allowed.contains(&option.as_str()))
    {
        return Err("Une option du profil n'est pas autorisée.".into());
    }

    let mut applied = 0usize;
    for (index, option) in options.iter().enumerate() {
        on_progress(ActionProgress {
            operation: "applyProfile".into(),
            current: index + 1,
            total: options.len(),
            label: profile_step_label(option).into(),
        });
        match option.as_str() {
            "firewall" => {
                apply_firewall_baseline(ssh_service_active())?;
            }
            "icmp4" => {
                set_ipv4_echo(false)?;
            }
            "icmp4-enable" => {
                set_ipv4_echo(true)?;
            }
            "avahi" if profile == "public" => {
                let _ = manage_service("avahi-daemon.service", "stop")?;
                let _ = manage_service("avahi-daemon.service", "disable")?;
            }
            "avahi" => {
                let _ = manage_service("avahi-daemon.service", "enable")?;
                let _ = manage_service("avahi-daemon.service", "start")?;
            }
            "llmnr" => disable_llmnr()?,
            "wifi-random" => set_all_wifi_mac_mode("random")?,
            "wifi-stable" => set_all_wifi_mac_mode("stable")?,
            "wifi-default" => restore_wifi_defaults()?,
            "firewall-default" => restore_ufw_defaults()?,
            "icmp4-default" => restore_ipv4_echo_default()?,
            "llmnr-default" => restore_llmnr_default()?,
            "services-default" => restore_service_presets()?,
            "app-blocks" => remove_application_block_table()?,
            _ => return Err("Option de profil non implémentée.".into()),
        }
        applied += 1;
    }
    on_progress(ActionProgress {
        operation: "applyProfile".into(),
        current: options.len(),
        total: options.len(),
        label: "Finalisation du profil".into(),
    });

    Ok(ActionOutcome {
        title: if profile == "restore" {
            "Réglages Ubuntu restaurés".into()
        } else {
            format!("Profil {profile} appliqué")
        },
        message: format!(
            "{applied} option{} appliquée{} avec une autorisation Polkit ponctuelle.",
            if applied > 1 { "s" } else { "" },
            if applied > 1 { "s" } else { "" }
        ),
        changed: applied > 0,
        reconnect_performed: false,
    })
}

fn profile_step_label(option: &str) -> &'static str {
    match option {
        "firewall" => "Configuration du pare-feu UFW",
        "icmp4" => "Désactivation des réponses ping IPv4",
        "icmp4-enable" => "Activation des réponses ping IPv4",
        "avahi" => "Mise à jour de la découverte Avahi",
        "llmnr" => "Désactivation de la résolution LLMNR",
        "wifi-random" => "Application des adresses MAC aléatoires",
        "wifi-stable" => "Application des pseudonymes MAC stables",
        "wifi-default" => "Restauration des réglages MAC NetworkManager",
        "firewall-default" => "Réinitialisation complète du pare-feu UFW",
        "icmp4-default" => "Restauration du réglage ping IPv4",
        "llmnr-default" => "Restauration du réglage LLMNR",
        "services-default" => "Réapplication des presets systemd",
        "app-blocks" => "Suppression des blocages d'applications",
        _ => "Application de l'étape",
    }
}

fn restore_wifi_defaults() -> Result<(), String> {
    let active = active_wifi_connections()?;
    remove_managed_file(Path::new(NETWORK_MANAGER_CONFIG))?;
    for uuid in wifi_connection_uuids()? {
        run_checked(
            "/usr/bin/nmcli",
            &[
                "connection",
                "modify",
                &uuid,
                "802-11-wireless.cloned-mac-address",
                "",
            ],
            "Un profil Wi-Fi n'a pas pu revenir au réglage NetworkManager par défaut.",
        )?;
    }
    let _ = run_output("/usr/bin/nmcli", &["general", "reload"]);
    for (interface, uuid) in active {
        run_checked(
            "/usr/bin/nmcli",
            &["device", "disconnect", &interface],
            "Les réglages Wi-Fi sont restaurés, mais la déconnexion a échoué.",
        )?;
        run_checked(
            "/usr/bin/nmcli",
            &["connection", "up", &uuid, "ifname", &interface],
            "Les réglages Wi-Fi sont restaurés, mais la reconnexion a échoué.",
        )?;
    }
    Ok(())
}

fn restore_ufw_defaults() -> Result<(), String> {
    ufw_checked(&["--force", "reset"])
}

fn restore_ipv4_echo_default() -> Result<(), String> {
    remove_managed_file(Path::new(IPV4_ECHO_CONFIG))?;
    run_checked(
        "/usr/sbin/sysctl",
        &["-w", "net.ipv4.icmp_echo_ignore_all=0"],
        "Le fichier ICMP a été retiré, mais la valeur noyau par défaut n'a pas pu être restaurée.",
    )
}

fn restore_llmnr_default() -> Result<(), String> {
    remove_managed_file(Path::new(LLMNR_CONFIG))?;
    if unit_exists("systemd-resolved.service") {
        run_checked(
            "/usr/bin/systemctl",
            &["restart", "systemd-resolved.service"],
            "Le réglage LLMNR a été retiré, mais systemd-resolved n'a pas pu être relancé.",
        )?;
    }
    Ok(())
}

fn restore_service_presets() -> Result<(), String> {
    for unit in [
        "avahi-daemon.service",
        "cups.service",
        "cups-browsed.service",
        "ssh.service",
        "sshd.service",
        "smbd.service",
        "nmbd.service",
        "nfs-server.service",
    ] {
        if unit_exists(unit) {
            run_checked(
                "/usr/bin/systemctl",
                &["preset", unit],
                "Le preset fournisseur d'un service réseau n'a pas pu être restauré.",
            )?;
        }
    }
    Ok(())
}

fn remove_application_block_table() -> Result<(), String> {
    let nft = nft_program()?;
    let output = run_output(nft, &["list", "table", "inet", APPLICATION_TABLE])?;
    if output.status.success() {
        run_checked(
            nft,
            &["delete", "table", "inet", APPLICATION_TABLE],
            "La table nftables applicative de Dissimulation n'a pas pu être retirée.",
        )?;
    }
    Ok(())
}

fn unit_exists(unit: &str) -> bool {
    run_output(
        "/usr/bin/systemctl",
        &[
            "show",
            unit,
            "--property=LoadState",
            "--value",
            "--no-pager",
        ],
    )
    .is_ok_and(|output| output.status.success() && text_stdout(&output).trim() != "not-found")
}

fn remove_managed_file(path: &Path) -> Result<bool, String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(format!(
            "Impossible de retirer le fichier géré {}.",
            path.display()
        )),
    }
}

fn set_all_wifi_mac_mode(mode: &str) -> Result<(), String> {
    let nm_mode = validate_mac_mode(mode)?;
    persist_global_mac_mode(nm_mode)?;
    for uuid in wifi_connection_uuids()? {
        run_checked(
            "/usr/bin/nmcli",
            &[
                "connection",
                "modify",
                &uuid,
                "802-11-wireless.cloned-mac-address",
                nm_mode,
            ],
            "Un profil Wi-Fi n'a pas pu être mis à jour.",
        )?;
    }
    let _ = run_output("/usr/bin/nmcli", &["general", "reload"]);
    for (interface, uuid) in active_wifi_connections()? {
        run_checked(
            "/usr/bin/nmcli",
            &["device", "disconnect", &interface],
            "Le mode MAC est enregistré, mais une interface Wi-Fi n'a pas pu être déconnectée.",
        )?;
        run_checked(
            "/usr/bin/nmcli",
            &["connection", "up", &uuid, "ifname", &interface],
            "Le mode MAC est enregistré, mais une interface Wi-Fi n'a pas pu être reconnectée.",
        )?;
    }
    Ok(())
}

fn active_wifi_connections() -> Result<Vec<(String, String)>, String> {
    let mut active = Vec::new();
    let entries = fs::read_dir("/sys/class/net")
        .map_err(|_| "Impossible d'inventorier les interfaces Wi-Fi.".to_string())?;
    for entry in entries.flatten() {
        let interface = entry.file_name().to_string_lossy().into_owned();
        if !entry.path().join("wireless").exists() || validate_interface(&interface).is_err() {
            continue;
        }
        let uuid = successful_stdout(
            "/usr/bin/nmcli",
            &["-g", "GENERAL.CON-UUID", "device", "show", &interface],
            "NetworkManager n'a pas pu consulter une interface Wi-Fi.",
        )?
        .trim()
        .to_string();
        if valid_uuid(&uuid) {
            active.push((interface, uuid));
        }
    }
    Ok(active)
}

fn disable_llmnr() -> Result<(), String> {
    atomic_write(
        Path::new(LLMNR_CONFIG),
        b"# Gere par Dissimulation\n[Resolve]\nLLMNR=no\n",
    )?;
    run_checked(
        "/usr/bin/systemctl",
        &["restart", "systemd-resolved.service"],
        "Le réglage LLMNR est enregistré, mais systemd-resolved n'a pas pu être relancé.",
    )
}

fn ssh_service_active() -> bool {
    ["ssh.service", "sshd.service"].iter().any(|unit| {
        run_output("/usr/bin/systemctl", &["is-active", unit])
            .is_ok_and(|output| output.status.success())
    })
}

fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value
            .chars()
            .all(|character| character.is_ascii_hexdigit() || character == '-')
}

fn atomic_write(path: &Path, content: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "Chemin système invalide.".to_string())?;
    fs::create_dir_all(parent).map_err(|_| format!("Impossible de créer {}.", parent.display()))?;
    let temporary = temporary_path(path);
    let _ = fs::remove_file(&temporary);
    let write_result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|_| "Impossible de créer le fichier système temporaire.".to_string())?;
        file.set_permissions(fs::Permissions::from_mode(0o644))
            .map_err(|_| "Impossible de fixer les permissions du fichier système.".to_string())?;
        file.write_all(content)
            .and_then(|_| file.sync_all())
            .map_err(|_| "Impossible d'écrire le réglage système.".to_string())?;
        fs::rename(&temporary, path)
            .map_err(|_| "Impossible d'installer le réglage système.".to_string())?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut temporary = path.as_os_str().to_os_string();
    temporary.push(format!(".tmp.{}", std::process::id()));
    PathBuf::from(temporary)
}

fn ufw_checked(arguments: &[&str]) -> Result<(), String> {
    run_checked(
        "/usr/sbin/ufw",
        arguments,
        "UFW a refusé la modification demandée.",
    )
}

fn run_checked(program: &str, arguments: &[&str], fallback: &str) -> Result<(), String> {
    let output = run_output(program, arguments)?;
    if output.status.success() {
        Ok(())
    } else {
        let detail = text_stderr(&output);
        Err(if detail.trim().is_empty() {
            fallback.to_string()
        } else {
            format!("{fallback} {}", detail.trim())
        })
    }
}

fn successful_stdout(program: &str, arguments: &[&str], fallback: &str) -> Result<String, String> {
    let output = run_output(program, arguments)?;
    if output.status.success() {
        Ok(text_stdout(&output))
    } else {
        let detail = text_stderr(&output);
        Err(if detail.trim().is_empty() {
            fallback.to_string()
        } else {
            format!("{fallback} {}", detail.trim())
        })
    }
}

fn run_output(program: &str, arguments: &[&str]) -> Result<Output, String> {
    Command::new(program)
        .args(arguments)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .output()
        .map_err(|_| {
            format!(
                "La commande système {} est indisponible.",
                Path::new(program)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
            )
        })
}

fn text_stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn text_stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_rules_require_resolved_ips_for_domains() {
        let mut base = BlockRule {
            id: "rule-12345678".into(),
            name: "Test".into(),
            direction: "outgoing".into(),
            protocol: "tcp".into(),
            remote_address: "example.com".into(),
            port: 443,
            resolved_addresses: Vec::new(),
        };
        assert!(validate_block_rule(&base).is_err());
        base.resolved_addresses = vec!["93.184.216.34".into(), "2001:db8::1".into()];
        assert!(validate_block_rule(&base).is_ok());
        assert!(validate_ip_or_cidr("192.0.2.0/33").is_err());
        assert!(validate_ip_or_cidr("2001:db8::/64").is_ok());
    }

    #[test]
    fn ui_action_fields_use_camel_case() {
        let action: SystemAction =
            serde_json::from_str(r#"{"type":"applyFirewallBaseline","preserveSsh":true}"#).unwrap();
        assert!(matches!(
            action,
            SystemAction::ApplyFirewallBaseline { preserve_ssh: true }
        ));
    }

    #[test]
    fn progress_events_identify_each_ui_operation() {
        let action = SystemAction::SetIpv4Echo { enabled: false };
        assert_eq!(action_progress_operation(&action), "setIpv4Echo");
        assert!(!action_progress_label(&action).is_empty());

        let serialized = serde_json::to_value(ActionProgress {
            operation: action_progress_operation(&action).into(),
            current: 1,
            total: 2,
            label: action_progress_label(&action).into(),
        })
        .unwrap();
        assert_eq!(serialized["operation"], "setIpv4Echo");
        assert_eq!(serialized["current"], 1);
    }

    #[test]
    fn helper_only_accepts_wifi_interfaces_and_known_mac_modes() {
        assert!(validate_interface("../eth0").is_err());
        assert_eq!(validate_mac_mode("random").unwrap(), "random");
        assert!(validate_mac_mode("custom").is_err());
    }

    #[test]
    fn service_allowlist_excludes_critical_units() {
        assert!(manageable_unit("avahi-daemon.service"));
        assert!(manageable_unit("apache2.service"));
        assert!(!manageable_unit("NetworkManager.service"));
        assert!(!manageable_unit("display-manager.service"));
    }

    #[test]
    fn nft_cgroup_components_are_quoted_as_names() {
        assert_eq!(
            nft_quoted("app-org.mozilla.firefox.scope").unwrap(),
            "\"app-org.mozilla.firefox.scope\""
        );
        assert!(nft_quoted("bad\ncomponent").is_err());
    }
}
