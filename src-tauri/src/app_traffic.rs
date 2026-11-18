use crate::traffic::{self, PacketMetadata, TrafficSession};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs, io,
    path::PathBuf,
    sync::{Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};
use tauri::{AppHandle, Manager};

const HISTORY_FILE: &str = "application-traffic-history.json";
const UNKNOWN_APPLICATION_ID: &str = "__unattributed__";

static HISTORY_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static CAPTURE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationTrafficBucket {
    pub bucket_start_epoch_ms: u64,
    pub application_id: String,
    pub application_name: String,
    pub executable: Option<String>,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationTrafficHistory {
    pub available: bool,
    pub detail: String,
    pub retention_days: u16,
    pub entries: Vec<ApplicationTrafficBucket>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationTrafficSampleResult {
    pub available: bool,
    pub detail: String,
    pub captured_packets: usize,
    pub attributed_packets: usize,
}

#[derive(Debug, Clone)]
struct ApplicationIdentity {
    id: String,
    name: String,
    executable: Option<String>,
}

#[tauri::command(async)]
pub fn get_application_traffic_history(
    app: AppHandle,
    days: u16,
) -> Result<ApplicationTrafficHistory, String> {
    let days = days.clamp(1, 90);
    let entries = load_history(&app)?;
    let cutoff = now_epoch_ms().saturating_sub(u64::from(days) * 86_400_000);
    let filtered: Vec<_> = entries
        .into_iter()
        .filter(|entry| entry.bucket_start_epoch_ms >= cutoff)
        .collect();
    let tshark_available = tshark_available();
    Ok(ApplicationTrafficHistory {
        available: tshark_available,
        detail: if !tshark_available {
            "TShark n'est pas installé ; l'historique par application ne peut pas être alimenté."
                .into()
        } else if filtered.is_empty() {
            "Aucun échantillon attribuable n'est encore enregistré pour cette période.".into()
        } else {
            "Historique local agrégé par heure. Aucun contenu de paquet n'est conservé.".into()
        },
        retention_days: days,
        entries: filtered,
    })
}

#[tauri::command(async)]
pub fn sample_application_traffic(
    app: AppHandle,
    interface: String,
) -> Result<ApplicationTrafficSampleResult, String> {
    let settings = app.state::<crate::runtime::AppState>().settings();
    capture_and_store(
        &app,
        &interface,
        settings.application_traffic_sample_seconds,
        settings.traffic_history_days,
    )
}

pub(crate) fn capture_and_store(
    app: &AppHandle,
    interface: &str,
    duration_seconds: u64,
    retention_days: u16,
) -> Result<ApplicationTrafficSampleResult, String> {
    let capture_lock = CAPTURE_LOCK.get_or_init(|| Mutex::new(()));
    let _capture_guard = capture_lock
        .try_lock()
        .map_err(|_| "Un échantillon de trafic est déjà en cours.".to_string())?;
    let before = traffic::collect_traffic_sessions().unwrap_or_default();
    let sample = traffic::capture_packets(interface, duration_seconds, 2_000, 96)?;
    if !sample.available {
        return Ok(ApplicationTrafficSampleResult {
            available: false,
            detail: sample.detail,
            captured_packets: 0,
            attributed_packets: 0,
        });
    }
    let after = traffic::collect_traffic_sessions().unwrap_or_default();
    let sessions = merge_sessions(before, after);
    let (buckets, attributed_packets) = aggregate_packets(&sample.packets, &sessions);
    if !buckets.is_empty() {
        merge_and_save_history(app, buckets, retention_days)?;
    }

    Ok(ApplicationTrafficSampleResult {
        available: true,
        detail: format!(
            "{} paquet{} sur {} attribué{} à une application visible. Les tailles des paquets chiffrés sont comptabilisées ; l'échantillon dure {} seconde{} et aucun contenu n'est conservé.",
            attributed_packets,
            if attributed_packets > 1 { "s" } else { "" },
            sample.packets.len(),
            if attributed_packets > 1 { "s" } else { "" },
            duration_seconds,
            if duration_seconds > 1 { "s" } else { "" }
        ),
        captured_packets: sample.packets.len(),
        attributed_packets,
    })
}

fn aggregate_packets(
    packets: &[PacketMetadata],
    sessions: &[TrafficSession],
) -> (Vec<ApplicationTrafficBucket>, usize) {
    let mut buckets: HashMap<(u64, String), ApplicationTrafficBucket> = HashMap::new();
    let mut attributed = 0usize;

    for packet in packets {
        let association = associate_packet(packet, sessions);
        let (identity, sent) = match association {
            Some(value) => {
                attributed += 1;
                value
            }
            None => (
                ApplicationIdentity {
                    id: UNKNOWN_APPLICATION_ID.into(),
                    name: "Non attribué".into(),
                    executable: None,
                },
                true,
            ),
        };
        let timestamp = u64::try_from(packet.captured_at_epoch_ms).unwrap_or(u64::MAX);
        let hour = timestamp / 3_600_000 * 3_600_000;
        let length = u64::from(packet.length.unwrap_or_default());
        let entry = buckets
            .entry((hour, identity.id.clone()))
            .or_insert_with(|| ApplicationTrafficBucket {
                bucket_start_epoch_ms: hour,
                application_id: identity.id,
                application_name: identity.name,
                executable: identity.executable,
                packets_sent: 0,
                packets_received: 0,
                bytes_sent: 0,
                bytes_received: 0,
            });
        if sent {
            entry.packets_sent += 1;
            entry.bytes_sent = entry.bytes_sent.saturating_add(length);
        } else {
            entry.packets_received += 1;
            entry.bytes_received = entry.bytes_received.saturating_add(length);
        }
    }

    let mut values: Vec<_> = buckets.into_values().collect();
    values.sort_by(|left, right| {
        left.bucket_start_epoch_ms
            .cmp(&right.bucket_start_epoch_ms)
            .then_with(|| left.application_name.cmp(&right.application_name))
    });
    (values, attributed)
}

fn associate_packet(
    packet: &PacketMetadata,
    sessions: &[TrafficSession],
) -> Option<(ApplicationIdentity, bool)> {
    let source_port = packet.source_port?;
    let destination_port = packet.destination_port?;
    let mut fallback = None;

    for session in sessions {
        if session.is_listener
            || session.protocol != packet.transport_protocol
            || session.process_name.is_none()
        {
            continue;
        }
        let outbound = endpoint_matches(
            &packet.source_address,
            source_port,
            &session.local_address,
            session.local_port,
        );
        let inbound = endpoint_matches(
            &packet.destination_address,
            destination_port,
            &session.local_address,
            session.local_port,
        );
        if !outbound && !inbound {
            continue;
        }

        let (remote_address, remote_port) = if outbound {
            (&packet.destination_address, destination_port)
        } else {
            (&packet.source_address, source_port)
        };
        let identity = session_identity(session)?;
        if session.remote_port == 0 || is_wildcard(&session.remote_address) {
            fallback.get_or_insert((identity, outbound));
            continue;
        }
        if endpoint_matches(
            remote_address,
            remote_port,
            &session.remote_address,
            session.remote_port,
        ) {
            return Some((identity, outbound));
        }
    }
    fallback
}

fn session_identity(session: &TrafficSession) -> Option<ApplicationIdentity> {
    let name = session.process_name.clone()?;
    let cgroup_application = session.cgroup_path.as_deref().and_then(|path| {
        path.split('/')
            .rev()
            .find(|component| component.starts_with("app-") && component.ends_with(".scope"))
    });
    let id = cgroup_application
        .map(|value| format!("cgroup:{value}"))
        .or_else(|| {
            session
                .executable
                .as_ref()
                .map(|value| format!("exe:{value}"))
        })
        .unwrap_or_else(|| format!("process:{name}"));
    Some(ApplicationIdentity {
        id,
        name,
        executable: session.executable.clone(),
    })
}

fn endpoint_matches(packet_address: &str, packet_port: u16, address: &str, port: u16) -> bool {
    packet_port == port && normalize_address(packet_address) == normalize_address(address)
}

fn normalize_address(value: &str) -> &str {
    value
        .trim_matches(['[', ']'])
        .split_once('%')
        .map(|(address, _)| address)
        .unwrap_or(value.trim_matches(['[', ']']))
}

fn is_wildcard(value: &str) -> bool {
    matches!(value, "*" | "0.0.0.0" | "::")
}

fn merge_sessions(before: Vec<TrafficSession>, after: Vec<TrafficSession>) -> Vec<TrafficSession> {
    let mut seen = HashSet::new();
    before
        .into_iter()
        .chain(after)
        .filter(|session| seen.insert(session.id.clone()))
        .collect()
}

fn merge_and_save_history(
    app: &AppHandle,
    additions: Vec<ApplicationTrafficBucket>,
    retention_days: u16,
) -> Result<(), String> {
    let lock = HISTORY_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock().unwrap_or_else(|error| error.into_inner());
    let mut entries = load_history_unlocked(app)?;
    let cutoff = now_epoch_ms().saturating_sub(u64::from(retention_days.clamp(1, 90)) * 86_400_000);
    entries.retain(|entry| entry.bucket_start_epoch_ms >= cutoff);

    for addition in additions {
        if let Some(existing) = entries.iter_mut().find(|entry| {
            entry.bucket_start_epoch_ms == addition.bucket_start_epoch_ms
                && entry.application_id == addition.application_id
        }) {
            existing.packets_sent = existing.packets_sent.saturating_add(addition.packets_sent);
            existing.packets_received = existing
                .packets_received
                .saturating_add(addition.packets_received);
            existing.bytes_sent = existing.bytes_sent.saturating_add(addition.bytes_sent);
            existing.bytes_received = existing
                .bytes_received
                .saturating_add(addition.bytes_received);
        } else {
            entries.push(addition);
        }
    }
    entries.sort_by_key(|entry| entry.bucket_start_epoch_ms);
    save_history_unlocked(app, &entries)
}

fn load_history(app: &AppHandle) -> Result<Vec<ApplicationTrafficBucket>, String> {
    let lock = HISTORY_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock().unwrap_or_else(|error| error.into_inner());
    load_history_unlocked(app)
}

fn load_history_unlocked(app: &AppHandle) -> Result<Vec<ApplicationTrafficBucket>, String> {
    let path = history_path(app)?;
    let Ok(content) = fs::read(path) else {
        return Ok(Vec::new());
    };
    serde_json::from_slice(&content)
        .map_err(|_| "L'historique du trafic par application est illisible.".to_string())
}

fn save_history_unlocked(
    app: &AppHandle,
    entries: &[ApplicationTrafficBucket],
) -> Result<(), String> {
    let path = history_path(app)?;
    let parent = path
        .parent()
        .ok_or_else(|| "Le chemin de l'historique est invalide.".to_string())?;
    fs::create_dir_all(parent)
        .map_err(|_| "Impossible de créer le dossier de l'historique.".to_string())?;
    let temporary = path.with_extension("json.tmp");
    let serialized = serde_json::to_vec(entries)
        .map_err(|_| "Impossible de préparer l'historique du trafic.".to_string())?;
    fs::write(&temporary, serialized).map_err(format_io_error)?;
    if let Err(error) = fs::rename(&temporary, &path) {
        let _ = fs::remove_file(&temporary);
        return Err(format_io_error(error));
    }
    Ok(())
}

fn history_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map(|directory| directory.join(HISTORY_FILE))
        .map_err(|_| "Le dossier de données utilisateur est indisponible.".to_string())
}

fn tshark_available() -> bool {
    ["/usr/bin/tshark", "/usr/sbin/tshark"]
        .iter()
        .any(|path| std::path::Path::new(path).exists())
}

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default()
}

fn format_io_error(_error: io::Error) -> String {
    "Impossible d'enregistrer l'historique du trafic.".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> TrafficSession {
        TrafficSession {
            id: "tcp-test".into(),
            protocol: "tcp".into(),
            state: "ESTAB".into(),
            local_address: "192.0.2.10".into(),
            local_port: 51_234,
            remote_address: "198.51.100.8".into(),
            remote_port: 443,
            process_name: Some("firefox".into()),
            pid: Some(42),
            executable: Some("/usr/lib/firefox/firefox".into()),
            cgroup_path: Some("/user.slice/user-1000.slice/app-firefox.scope".into()),
            process_start_time: Some(123),
            is_listener: false,
        }
    }

    #[test]
    fn attributes_both_directions_to_a_socket() {
        let packets = vec![
            PacketMetadata {
                captured_at_epoch_ms: 3_600_123,
                source_address: "192.0.2.10".into(),
                source_port: Some(51_234),
                destination_address: "198.51.100.8".into(),
                destination_port: Some(443),
                protocol: "TLS".into(),
                transport_protocol: "tcp".into(),
                length: Some(100),
                request_summary: None,
            },
            PacketMetadata {
                captured_at_epoch_ms: 3_600_456,
                source_address: "198.51.100.8".into(),
                source_port: Some(443),
                destination_address: "192.0.2.10".into(),
                destination_port: Some(51_234),
                protocol: "TLS".into(),
                transport_protocol: "tcp".into(),
                length: Some(200),
                request_summary: None,
            },
        ];
        let (buckets, attributed) = aggregate_packets(&packets, &[session()]);
        assert_eq!(attributed, 2);
        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets[0].packets_sent, 1);
        assert_eq!(buckets[0].bytes_received, 200);
    }

    #[test]
    fn keeps_unattributed_packets_explicit() {
        let packet = PacketMetadata {
            captured_at_epoch_ms: 3_600_123,
            source_address: "203.0.113.1".into(),
            source_port: Some(1234),
            destination_address: "203.0.113.2".into(),
            destination_port: Some(53),
            protocol: "DNS".into(),
            transport_protocol: "udp".into(),
            length: Some(72),
            request_summary: None,
        };
        let (buckets, attributed) = aggregate_packets(&[packet], &[]);
        assert_eq!(attributed, 0);
        assert_eq!(buckets[0].application_name, "Non attribué");
    }
}
