use serde::Serialize;
use std::{
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TrafficSession {
    pub id: String,
    pub protocol: String,
    pub state: String,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub process_name: Option<String>,
    pub pid: Option<u32>,
    pub executable: Option<String>,
    pub cgroup_path: Option<String>,
    pub process_start_time: Option<u64>,
    pub is_listener: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PacketMetadata {
    pub captured_at_epoch_ms: u128,
    pub source_address: String,
    pub source_port: Option<u16>,
    pub destination_address: String,
    pub destination_port: Option<u16>,
    pub protocol: String,
    pub transport_protocol: String,
    pub length: Option<u32>,
    pub request_summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PacketSample {
    pub available: bool,
    pub detail: String,
    pub packets: Vec<PacketMetadata>,
}

#[tauri::command(async)]
pub fn get_traffic_sessions() -> Result<Vec<TrafficSession>, String> {
    collect_traffic_sessions()
}

pub(crate) fn collect_traffic_sessions() -> Result<Vec<TrafficSession>, String> {
    let output = Command::new("ss")
        .args(["-H", "-tunaep"])
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .output()
        .map_err(|_| "La commande ss n'est pas disponible.".to_string())?;
    if !output.status.success() {
        return Err("Les sessions TCP/UDP ne sont pas accessibles.".into());
    }
    let mut sessions = parse_ss_sessions(&String::from_utf8_lossy(&output.stdout));
    for session in &mut sessions {
        let Some(pid) = session.pid else {
            continue;
        };
        session.executable = std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|path| path.to_string_lossy().into_owned());
        session.cgroup_path = process_cgroup_path(pid);
        session.process_start_time = process_start_time(pid);
    }
    Ok(sessions)
}

#[tauri::command(async)]
pub fn capture_packet_sample(interface: String) -> Result<PacketSample, String> {
    capture_packets(&interface, 4, 100, 256)
}

pub(crate) fn capture_packets(
    interface: &str,
    duration_seconds: u64,
    packet_limit: u32,
    snapshot_bytes: u32,
) -> Result<PacketSample, String> {
    validate_capture_interface(&interface)?;
    let duration = format!("duration:{}", duration_seconds.clamp(1, 15));
    let packet_limit = packet_limit.clamp(1, 5_000).to_string();
    let snapshot_bytes = snapshot_bytes.clamp(64, 512).to_string();
    let output = match Command::new("tshark")
        .args([
            "-n",
            "-p",
            "-i",
            &interface,
            "-a",
            &duration,
            "-c",
            &packet_limit,
            "-s",
            &snapshot_bytes,
            "-f",
            "tcp or udp",
            "-T",
            "fields",
            "-E",
            "separator=/t",
            "-E",
            "occurrence=f",
            "-e",
            "frame.time_epoch",
            "-e",
            "ip.src",
            "-e",
            "ipv6.src",
            "-e",
            "tcp.srcport",
            "-e",
            "udp.srcport",
            "-e",
            "ip.dst",
            "-e",
            "ipv6.dst",
            "-e",
            "tcp.dstport",
            "-e",
            "udp.dstport",
            "-e",
            "_ws.col.Protocol",
            "-e",
            "frame.len",
            "-e",
            "dns.qry.name",
            "-e",
            "http.request.method",
            "-e",
            "http.host",
            "-e",
            "http.request.uri",
            "-e",
            "tls.handshake.extensions_server_name",
        ])
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .output()
    {
        Ok(output) => output,
        Err(_) => {
            return Ok(PacketSample {
                available: false,
                detail: "TShark n'est pas installé. Les sessions restent visibles via ss, sans capture de paquets."
                    .into(),
                packets: Vec::new(),
            });
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = if stderr.to_ascii_lowercase().contains("permission")
            || stderr.to_ascii_lowercase().contains("cap_net")
            || stderr.to_ascii_lowercase().contains("capture")
        {
            "Capture refusée par Ubuntu. Configurez dumpcap pour le groupe wireshark puis rouvrez la session ; l'application ne lance jamais TShark en root."
                .to_string()
        } else {
            let concise = stderr.lines().last().unwrap_or_default().trim();
            if concise.is_empty() {
                "La capture courte n'a pas pu aboutir.".into()
            } else {
                format!("La capture courte a échoué : {}", truncate(concise, 220))
            }
        };
        return Ok(PacketSample {
            available: false,
            detail,
            packets: Vec::new(),
        });
    }

    let packets = parse_tshark_fields(&String::from_utf8_lossy(&output.stdout));
    Ok(PacketSample {
        available: true,
        detail: format!(
            "{} paquet{} TCP/UDP observé{} pendant au plus {} seconde{} ; seuls les en-têtes et métadonnées sont affichés.",
            packets.len(),
            if packets.len() > 1 { "s" } else { "" },
            if packets.len() > 1 { "s" } else { "" },
            duration_seconds,
            if duration_seconds > 1 { "s" } else { "" }
        ),
        packets,
    })
}

fn validate_capture_interface(interface: &str) -> Result<(), String> {
    if interface == "any" {
        return Ok(());
    }
    if interface.is_empty()
        || interface.len() > 32
        || !interface
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_.-".contains(character))
        || !Path::new("/sys/class/net").join(interface).exists()
    {
        return Err("L'interface de capture est invalide.".into());
    }
    Ok(())
}

fn parse_ss_sessions(output: &str) -> Vec<TrafficSession> {
    output
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 6 {
                return None;
            }
            let protocol = fields[0].to_ascii_lowercase();
            if !matches!(protocol.as_str(), "tcp" | "udp") {
                return None;
            }
            let state = fields[1].to_ascii_uppercase();
            let (local_address, local_port) = parse_endpoint(fields[4])?;
            let (remote_address, remote_port) = parse_endpoint(fields[5])?;
            let process_field = fields.get(6..).unwrap_or_default().join(" ");
            let pid = parse_marker_number(&process_field, "pid=");
            let process_name = parse_process_name(&process_field);
            let is_listener = matches!(state.as_str(), "LISTEN" | "UNCONN")
                && matches!(remote_address.as_str(), "*" | "0.0.0.0" | "::");
            Some(TrafficSession {
                id: format!(
                    "{protocol}-{local_address}-{local_port}-{remote_address}-{remote_port}-{}",
                    pid.unwrap_or_default()
                ),
                protocol,
                state,
                local_address,
                local_port,
                remote_address,
                remote_port,
                process_name,
                pid,
                executable: None,
                cgroup_path: None,
                process_start_time: None,
                is_listener,
            })
        })
        .collect()
}

fn parse_endpoint(value: &str) -> Option<(String, u16)> {
    let (address, port) = value.rsplit_once(':')?;
    let address = address.trim_matches(['[', ']']).to_string();
    let port = if port == "*" { 0 } else { port.parse().ok()? };
    Some((address, port))
}

fn parse_marker_number(value: &str, marker: &str) -> Option<u32> {
    let start = value.find(marker)? + marker.len();
    value[start..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .ok()
}

fn parse_process_name(value: &str) -> Option<String> {
    let start = value.find("((\"")? + 3;
    let end = value[start..].find('"')? + start;
    Some(value[start..end].to_string())
}

fn parse_tshark_fields(output: &str) -> Vec<PacketMetadata> {
    output
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split('\t').collect();
            if fields.len() < 16 {
                return None;
            }
            let source_address = first_nonempty(&[fields[1], fields[2]]).to_string();
            let destination_address = first_nonempty(&[fields[5], fields[6]]).to_string();
            if source_address.is_empty() || destination_address.is_empty() {
                return None;
            }
            let is_tcp = !fields[3].is_empty() || !fields[7].is_empty();
            let source_port = first_nonempty(&[fields[3], fields[4]]).parse().ok();
            let destination_port = first_nonempty(&[fields[7], fields[8]]).parse().ok();
            let request_summary = request_summary(&fields);
            Some(PacketMetadata {
                captured_at_epoch_ms: fields[0]
                    .parse::<f64>()
                    .ok()
                    .map(|value| (value * 1_000.0) as u128)
                    .unwrap_or_else(now_epoch_ms),
                source_address,
                source_port,
                destination_address,
                destination_port,
                protocol: fields[9].to_string(),
                transport_protocol: if is_tcp { "tcp" } else { "udp" }.to_string(),
                length: fields[10].parse().ok(),
                request_summary,
            })
        })
        .collect()
}

pub(crate) fn process_cgroup_path(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .filter(|path| path.starts_with('/') && path.len() > 1 && path.len() <= 1_024)
        .map(str::to_string)
}

pub(crate) fn process_start_time(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let closing_parenthesis = stat.rfind(')')?;
    stat.get(closing_parenthesis + 1..)?
        .split_whitespace()
        .nth(19)
        .and_then(|value| value.parse().ok())
}

fn request_summary(fields: &[&str]) -> Option<String> {
    if !fields[11].is_empty() {
        return Some(format!("DNS : {}", truncate(fields[11], 220)));
    }
    if !fields[12].is_empty() {
        let method = truncate(fields[12], 16);
        let host = truncate(fields[13], 160);
        let uri = sanitize_http_uri(fields[14]);
        return Some(format!("HTTP {method} {host}{uri}"));
    }
    if !fields[15].is_empty() {
        return Some(format!("TLS SNI : {}", truncate(fields[15], 220)));
    }
    None
}

fn sanitize_http_uri(value: &str) -> String {
    let path = value.split(['?', '#']).next().unwrap_or_default();
    let mut sanitized = truncate(path, 180);
    if value.contains('?') {
        sanitized.push_str("?[paramètres masqués]");
    }
    sanitized
}

fn first_nonempty<'a>(values: &[&'a str]) -> &'a str {
    values
        .iter()
        .copied()
        .find(|value| !value.is_empty())
        .unwrap_or("")
}

fn now_epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}

fn truncate(value: &str, maximum: usize) -> String {
    value.chars().take(maximum).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tcp_and_udp_sessions() {
        let output = "tcp ESTAB 0 0 192.0.2.10:49152 198.51.100.8:443 users:((\"firefox\",pid=4242,fd=7))\nudp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:* users:((\"avahi-daemon\",pid=500,fd=12))";
        let sessions = parse_ss_sessions(output);
        assert_eq!(sessions.len(), 2);
        assert_eq!(sessions[0].remote_port, 443);
        assert_eq!(sessions[0].pid, Some(4242));
        assert!(sessions[1].is_listener);
    }

    #[test]
    fn parses_packet_metadata_without_payload() {
        let line = "1700000000.125\t192.0.2.10\t\t53000\t\t1.1.1.1\t\t443\t\tTLSv1.3\t128\t\t\t\t\texample.org";
        let packets = parse_tshark_fields(line);
        assert_eq!(packets.len(), 1);
        assert_eq!(
            packets[0].request_summary.as_deref(),
            Some("TLS SNI : example.org")
        );
    }

    #[test]
    fn redacts_http_query_parameters() {
        assert_eq!(
            sanitize_http_uri("/login?token=secret&user=test"),
            "/login?[paramètres masqués]"
        );
    }
}
