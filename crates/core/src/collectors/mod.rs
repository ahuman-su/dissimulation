use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs,
    os::unix::fs::MetadataExt,
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::Value;

use crate::{
    exposure::{classify_endpoint, parse_endpoint},
    models::*,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandResult {
    pub success: bool,
    pub stdout: String,
}

pub trait CommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<CommandResult, String>;
}

pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<CommandResult, String> {
        Command::new(program)
            .args(args)
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .output()
            .map(|output| CommandResult {
                success: output.status.success(),
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            })
            .map_err(|_| format!("La source {program} n'est pas disponible."))
    }
}

pub fn scan_network_exposure() -> NetworkSnapshot {
    scan_with(&SystemCommandRunner)
}

pub fn inspect_firewall_state() -> FirewallState {
    collect_firewall(&SystemCommandRunner).0
}

pub fn scan_with(runner: &dyn CommandRunner) -> NetworkSnapshot {
    let (interfaces, interface_source) = collect_interfaces(runner);
    let (mut docker_ports, docker_source) = collect_docker_ports(runner);
    docker_ports.sort_by_key(|entry| (entry.host_port, entry.container_port));

    let (mut ports, sockets_source) = collect_ports(runner, &interfaces);
    correlate_docker(&mut ports, &docker_ports);
    ports.sort_by_key(|entry| (entry.port, protocol_order(entry.protocol)));

    let (services, systemd_source) = collect_services(runner, &ports);
    let (firewall, firewall_source) = collect_firewall(runner);
    let ping = collect_ping_state();
    let discovery = collect_discovery(runner);
    let alerts = build_alerts(&ports, &docker_ports, &firewall);

    NetworkSnapshot {
        analyzed_at_epoch_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis())
            .unwrap_or_default(),
        ports,
        services,
        docker_ports,
        interfaces,
        firewall,
        ping,
        discovery,
        alerts,
        sources: vec![
            sockets_source,
            interface_source,
            firewall_source,
            docker_source,
            systemd_source,
        ],
    }
}

fn protocol_order(protocol: TransportProtocol) -> u8 {
    match protocol {
        TransportProtocol::Tcp => 0,
        TransportProtocol::Udp => 1,
    }
}

fn collect_interfaces(runner: &dyn CommandRunner) -> (Vec<NetworkInterface>, SourceStatus) {
    let mut addresses: HashMap<String, Vec<String>> = HashMap::new();
    let ip_available = match runner.run("ip", &["-o", "address", "show"]) {
        Ok(result) => {
            if result.success {
                for line in result.stdout.lines() {
                    let fields: Vec<_> = line.split_whitespace().collect();
                    if fields.len() >= 4 && matches!(fields[2], "inet" | "inet6") {
                        addresses
                            .entry(fields[1].trim_end_matches(':').to_string())
                            .or_default()
                            .push(fields[3].to_string());
                    }
                }
                true
            } else {
                false
            }
        }
        Err(_) => false,
    };

    let nm_devices = collect_nm_devices(runner);
    let mut interfaces = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let kind = detect_interface_kind(&name);
            let current_mac = read_trimmed(entry.path().join("address"));
            let operstate =
                read_trimmed(entry.path().join("operstate")).unwrap_or_else(|| "inconnu".into());
            let nm = nm_devices.get(&name);
            let hardware_mac = nm
                .and_then(|device| device.permanent_mac.clone())
                .or_else(|| current_mac.clone());
            let mac_mode = nm
                .and_then(|device| device.connection.as_deref())
                .and_then(|connection| collect_mac_mode(runner, connection))
                .unwrap_or(MacMode::Unknown);

            interfaces.push(NetworkInterface {
                name: name.clone(),
                kind,
                addresses: addresses.remove(&name).unwrap_or_default(),
                hardware_mac,
                current_mac: nm
                    .and_then(|device| device.current_mac.clone())
                    .or(current_mac),
                active_connection: nm.and_then(|device| device.connection.clone()),
                mac_mode,
                operstate,
                eligible_for_randomization: kind == InterfaceKind::Wifi,
            });
        }
    }
    interfaces.sort_by(|left, right| left.name.cmp(&right.name));

    let availability = if interfaces.is_empty() {
        Availability::Unavailable
    } else if ip_available && !nm_devices.is_empty() {
        Availability::Available
    } else {
        Availability::Partial
    };
    let detail = match availability {
        Availability::Available => "Interfaces, adresses et NetworkManager consultés.",
        Availability::Partial => {
            "Interfaces détectées ; certaines métadonnées ne sont pas accessibles."
        }
        Availability::Unavailable => "Aucune interface n'a pu être inventoriée.",
    };

    (
        interfaces,
        SourceStatus {
            source: "Interfaces".into(),
            availability,
            detail: detail.into(),
        },
    )
}

fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn detect_interface_kind(name: &str) -> InterfaceKind {
    if name == "lo" {
        InterfaceKind::Loopback
    } else if Path::new("/sys/class/net")
        .join(name)
        .join("wireless")
        .exists()
        || name.starts_with("wl")
    {
        InterfaceKind::Wifi
    } else if name == "docker0" || name.starts_with("br-") || name.starts_with("veth") {
        InterfaceKind::Docker
    } else if fs::canonicalize(Path::new("/sys/class/net").join(name))
        .ok()
        .is_some_and(|path| path.to_string_lossy().contains("/virtual/"))
        || matches!(
            name,
            name if name.starts_with("virbr")
                || name.starts_with("tun")
                || name.starts_with("tap")
                || name.starts_with("wg")
        )
    {
        InterfaceKind::Virtual
    } else if name.starts_with("en") || name.starts_with("eth") {
        InterfaceKind::Ethernet
    } else {
        InterfaceKind::Unknown
    }
}

#[derive(Debug, Default)]
struct NmDevice {
    connection: Option<String>,
    current_mac: Option<String>,
    permanent_mac: Option<String>,
}

fn collect_nm_devices(runner: &dyn CommandRunner) -> HashMap<String, NmDevice> {
    let Ok(result) = runner.run(
        "nmcli",
        &[
            "-t",
            "-f",
            "GENERAL.DEVICE,GENERAL.CONNECTION,GENERAL.HWADDR,GENERAL.PERM-HWADDR",
            "device",
            "show",
        ],
    ) else {
        return HashMap::new();
    };
    if !result.success {
        return HashMap::new();
    }

    parse_nmcli_devices(&result.stdout)
}

fn parse_nmcli_devices(output: &str) -> HashMap<String, NmDevice> {
    let mut devices = HashMap::new();
    let mut current_name: Option<String> = None;
    let mut current = NmDevice::default();

    for line in output.lines().chain(std::iter::once("")) {
        if line.is_empty() {
            if let Some(name) = current_name.take() {
                devices.insert(name, current);
                current = NmDevice::default();
            }
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = unescape_nmcli(value);
        match key {
            "GENERAL.DEVICE" => current_name = Some(value),
            "GENERAL.CONNECTION" if value != "--" => current.connection = Some(value),
            "GENERAL.HWADDR" if value != "--" => current.current_mac = Some(value),
            "GENERAL.PERM-HWADDR" if value != "--" => current.permanent_mac = Some(value),
            _ => {}
        }
    }
    devices
}

fn unescape_nmcli(value: &str) -> String {
    value.replace("\\:", ":").replace("\\\\", "\\")
}

fn collect_mac_mode(runner: &dyn CommandRunner, connection: &str) -> Option<MacMode> {
    let result = runner
        .run(
            "nmcli",
            &[
                "-g",
                "802-11-wireless.cloned-mac-address,802-3-ethernet.cloned-mac-address",
                "connection",
                "show",
                connection,
            ],
        )
        .ok()?;
    if !result.success {
        return None;
    }
    let value = result
        .stdout
        .lines()
        .find(|line| !line.trim().is_empty())?
        .trim();
    Some(match value {
        "permanent" => MacMode::Hardware,
        "stable" | "stable-ssid" => MacMode::Stable,
        "random" => MacMode::Random,
        "preserve" => MacMode::Preserve,
        _ => MacMode::Unknown,
    })
}

fn collect_ports(
    runner: &dyn CommandRunner,
    interfaces: &[NetworkInterface],
) -> (Vec<PortInfo>, SourceStatus) {
    let result = runner.run("ss", &["-H", "-lntup"]);
    let Ok(result) = result else {
        return (
            Vec::new(),
            SourceStatus {
                source: "Sockets".into(),
                availability: Availability::Unavailable,
                detail: "La commande ss n'est pas disponible.".into(),
            },
        );
    };
    if !result.success {
        return (
            Vec::new(),
            SourceStatus {
                source: "Sockets".into(),
                availability: Availability::Unavailable,
                detail: "Les sockets n'ont pas pu être consultés.".into(),
            },
        );
    }

    let ports = parse_ss_output(&result.stdout, interfaces);
    (
        ports,
        SourceStatus {
            source: "Sockets".into(),
            availability: Availability::Available,
            detail: "Sockets TCP et UDP consultés sans privilèges.".into(),
        },
    )
}

pub fn parse_ss_output(output: &str, interfaces: &[NetworkInterface]) -> Vec<PortInfo> {
    output
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 6 {
                return None;
            }
            let protocol = match fields[0].to_ascii_lowercase().as_str() {
                value if value.starts_with("tcp") => TransportProtocol::Tcp,
                value if value.starts_with("udp") => TransportProtocol::Udp,
                _ => return None,
            };
            let endpoint = parse_endpoint(fields[4])?;
            let process_field = fields.get(6).copied().unwrap_or_default();
            let pid = parse_pid(process_field);
            let process_name = parse_process_name(process_field);
            let (exposure, interface_name, interface_kind, explanation) =
                classify_endpoint(&endpoint, interfaces);
            let (user, command, systemd_service) =
                pid.map(enrich_pid).unwrap_or((None, None, None));

            Some(PortInfo {
                id: format!(
                    "{}-{}-{}-{}",
                    match protocol {
                        TransportProtocol::Tcp => "tcp",
                        TransportProtocol::Udp => "udp",
                    },
                    endpoint.address,
                    endpoint.port,
                    pid.map(|value| value.to_string())
                        .unwrap_or_else(|| "unknown".into())
                ),
                protocol,
                local_address: endpoint.address,
                port: endpoint.port,
                state: fields[1].to_ascii_uppercase(),
                ip_version: endpoint.version,
                pid,
                process_name,
                user,
                command,
                systemd_service,
                docker_container: None,
                interface_name,
                interface_kind,
                exposure,
                explanation,
            })
        })
        .collect()
}

fn parse_pid(value: &str) -> Option<u32> {
    let start = value.find("pid=")? + 4;
    let digits: String = value[start..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

fn parse_process_name(value: &str) -> Option<String> {
    let start = value.find("((\"")? + 3;
    let end = value[start..].find('"')? + start;
    Some(value[start..end].to_string())
}

fn enrich_pid(pid: u32) -> (Option<String>, Option<String>, Option<String>) {
    let proc_path = Path::new("/proc").join(pid.to_string());
    let user = fs::metadata(&proc_path)
        .ok()
        .and_then(|metadata| username_for_uid(metadata.uid()));
    let command = fs::read(proc_path.join("cmdline")).ok().and_then(|bytes| {
        let parts = bytes
            .split(|byte| *byte == 0)
            .filter(|part| !part.is_empty())
            .map(|part| String::from_utf8_lossy(part).into_owned())
            .collect::<Vec<_>>();
        let joined = sanitize_command_parts(&parts);
        (!joined.is_empty()).then_some(joined)
    });
    let systemd_service = read_trimmed(proc_path.join("cgroup")).and_then(|content| {
        content
            .split(['/', '\n'])
            .find(|part| valid_systemd_service(part))
            .map(str::to_string)
    });
    (user, command, systemd_service)
}

fn sanitize_command_parts(parts: &[String]) -> String {
    let mut redact_next = false;
    parts
        .iter()
        .map(|part| {
            if redact_next {
                redact_next = false;
                return "[valeur sensible masquée]".into();
            }

            let lowercase = part.to_ascii_lowercase();
            let sensitive = [
                "password",
                "passwd",
                "token",
                "secret",
                "credential",
                "api-key",
                "apikey",
                "private-key",
                "authorization",
                "cookie",
            ]
            .iter()
            .any(|marker| lowercase.contains(marker));

            if sensitive {
                if let Some((name, _)) = part.split_once('=') {
                    return format!("{name}=[valeur sensible masquée]");
                }
                if part.starts_with('-') {
                    redact_next = true;
                    return part.clone();
                }
                return "[valeur sensible masquée]".into();
            }

            if let Some(scheme) = part.find("://") {
                let authority = &part[scheme + 3..];
                if authority
                    .split('/')
                    .next()
                    .is_some_and(|value| value.contains('@'))
                {
                    return "[URL avec identifiants masquée]".into();
                }
            }

            part.clone()
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn username_for_uid(uid: u32) -> Option<String> {
    let passwd = fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        fields.next()?;
        let candidate_uid = fields.next()?.parse::<u32>().ok()?;
        (candidate_uid == uid).then(|| name.to_string())
    })
}

fn valid_systemd_service(value: &str) -> bool {
    value.ends_with(".service")
        && !value.is_empty()
        && value.len() <= 256
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric()
                || matches!(character, '.' | '_' | '-' | '@' | '\\' | ':')
        })
}

fn collect_docker_ports(runner: &dyn CommandRunner) -> (Vec<DockerPort>, SourceStatus) {
    let result = runner.run(
        "docker",
        &["container", "ls", "--no-trunc", "--format", "{{json .}}"],
    );
    let Ok(result) = result else {
        return (
            Vec::new(),
            SourceStatus {
                source: "Docker".into(),
                availability: Availability::Unavailable,
                detail: "Docker n'est pas installé ou n'est pas accessible.".into(),
            },
        );
    };
    if !result.success {
        return (
            Vec::new(),
            SourceStatus {
                source: "Docker".into(),
                availability: Availability::Unavailable,
                detail: "Le démon Docker n'est pas accessible à l'utilisateur courant.".into(),
            },
        );
    }

    (
        parse_docker_output(&result.stdout),
        SourceStatus {
            source: "Docker".into(),
            availability: Availability::Available,
            detail: "Publications de ports Docker consultées.".into(),
        },
    )
}

pub fn parse_docker_output(output: &str) -> Vec<DockerPort> {
    let mut entries = Vec::new();
    for line in output.lines() {
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let id = json_string(&value, &["ID", "Id"]);
        let name = json_string(&value, &["Names", "Name"]);
        let image = json_string(&value, &["Image"]);
        let ports = json_string(&value, &["Ports"]);
        for publication in ports.split(',').map(str::trim) {
            let Some((host, container)) = publication.split_once("->") else {
                continue;
            };
            let Some(endpoint) = parse_endpoint(host) else {
                continue;
            };
            let Some((container_port, protocol_text)) = container.split_once('/') else {
                continue;
            };
            let Ok(container_port) = container_port.parse::<u16>() else {
                continue;
            };
            let protocol = if protocol_text.eq_ignore_ascii_case("udp") {
                TransportProtocol::Udp
            } else {
                TransportProtocol::Tcp
            };
            let exposure = if endpoint.address == "127.0.0.1" || endpoint.address == "::1" {
                ExposureLevel::LocalOnly
            } else if matches!(endpoint.address.as_str(), "0.0.0.0" | "::" | "*") {
                ExposureLevel::AllInterfaces
            } else {
                ExposureLevel::SpecificInterface
            };
            let suggestion = (exposure == ExposureLevel::AllInterfaces).then(|| {
                format!(
                    "127.0.0.1:{}:{}/{}",
                    endpoint.port,
                    container_port,
                    match protocol {
                        TransportProtocol::Tcp => "tcp",
                        TransportProtocol::Udp => "udp",
                    }
                )
            });
            entries.push(DockerPort {
                container_id: id.clone(),
                container_name: name.clone(),
                image: image.clone(),
                publish_address: endpoint.address,
                host_port: endpoint.port,
                container_port,
                protocol,
                exposure,
                safer_binding_suggestion: suggestion,
            });
        }
    }
    entries
}

fn json_string(value: &Value, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .unwrap_or_default()
        .to_string()
}

fn correlate_docker(ports: &mut [PortInfo], docker_ports: &[DockerPort]) {
    for port in ports {
        if let Some(publication) = docker_ports.iter().find(|publication| {
            publication.host_port == port.port && publication.protocol == port.protocol
        }) {
            port.docker_container = Some(publication.container_name.clone());
        }
    }
}

fn collect_services(
    runner: &dyn CommandRunner,
    ports: &[PortInfo],
) -> (Vec<ServiceInfo>, SourceStatus) {
    let mut units: BTreeSet<_> = ports
        .iter()
        .filter_map(|port| port.systemd_service.clone())
        .collect();
    units.extend(
        [
            "avahi-daemon.service",
            "cups.service",
            "cups-browsed.service",
            "ssh.service",
            "sshd.service",
            "smbd.service",
            "nmbd.service",
            "nfs-server.service",
            "apache2.service",
            "nginx.service",
        ]
        .into_iter()
        .map(str::to_string),
    );
    if let Ok(result) = runner.run(
        "systemctl",
        &[
            "list-unit-files",
            "--type=service",
            "--no-legend",
            "--no-pager",
        ],
    ) {
        if result.success {
            units.extend(result.stdout.lines().filter_map(|line| {
                let unit = line.split_whitespace().next()?;
                network_service_purpose(unit).map(|_| unit.to_string())
            }));
        }
    }
    let mut services = Vec::new();
    let mut failures = 0;
    for unit in units {
        match runner.run(
            "systemctl",
            &[
                "show",
                &unit,
                "--property=LoadState,Description,ActiveState,UnitFileState",
                "--no-pager",
            ],
        ) {
            Ok(result)
                if result.success
                    && !result
                        .stdout
                        .lines()
                        .any(|line| line.trim() == "LoadState=not-found") =>
            {
                services.push(parse_systemd_service(&unit, &result.stdout))
            }
            Ok(result) if result.success => {}
            _ => failures += 1,
        }
    }
    let availability = if failures == 0 {
        Availability::Available
    } else if services.is_empty() {
        Availability::Unavailable
    } else {
        Availability::Partial
    };
    (
        services,
        SourceStatus {
            source: "systemd".into(),
            availability,
            detail: if failures == 0 {
                "Services réseau installés et unités associées aux sockets consultés dynamiquement."
                    .into()
            } else {
                "Certaines unités associées ne sont pas accessibles.".into()
            },
        },
    )
}

pub fn parse_systemd_service(unit: &str, output: &str) -> ServiceInfo {
    let properties: BTreeMap<_, _> = output
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect();
    let unit_file_state = properties.get("UnitFileState").copied().unwrap_or_default();
    ServiceInfo {
        unit: unit.into(),
        description: properties
            .get("Description")
            .filter(|value| !value.is_empty())
            .map(|value| (*value).to_string()),
        purpose: network_service_purpose(unit).map(str::to_string),
        active_state: properties
            .get("ActiveState")
            .copied()
            .unwrap_or("unknown")
            .into(),
        enabled: match unit_file_state {
            "enabled" | "enabled-runtime" => Some(true),
            "disabled" | "masked" => Some(false),
            _ => None,
        },
        protected: is_protected_unit(unit),
        manageable: is_manageable_network_service(unit),
    }
}

pub fn is_manageable_network_service(unit: &str) -> bool {
    matches!(
        unit,
        "avahi-daemon.service"
            | "cups.service"
            | "cups-browsed.service"
            | "ssh.service"
            | "sshd.service"
            | "smbd.service"
            | "nmbd.service"
            | "samba.service"
            | "nfs-server.service"
            | "rpcbind.service"
            | "apache2.service"
            | "httpd.service"
            | "nginx.service"
            | "caddy.service"
            | "lighttpd.service"
            | "vsftpd.service"
            | "proftpd.service"
            | "mosquitto.service"
            | "redis-server.service"
            | "mariadb.service"
            | "mysql.service"
            | "postgresql.service"
            | "mongod.service"
            | "xrdp.service"
    )
}

fn network_service_purpose(unit: &str) -> Option<&'static str> {
    let purpose = match unit {
        "apache2.service" | "httpd.service" => {
            "Serveur HTTP Apache : publie des sites, fichiers ou API sur le réseau via HTTP/HTTPS."
        }
        "nginx.service" => {
            "Serveur web et proxy inverse : reçoit des requêtes HTTP/HTTPS et peut les transmettre à d'autres applications."
        }
        "caddy.service" | "lighttpd.service" => {
            "Serveur web : publie des pages, fichiers ou applications via HTTP/HTTPS."
        }
        "ssh.service" | "sshd.service" => {
            "Serveur d'accès distant chiffré : permet une connexion en ligne de commande et des transferts de fichiers."
        }
        "avahi-daemon.service" => {
            "Découverte locale mDNS/DNS-SD : annonce et trouve automatiquement des machines et services sur le réseau local."
        }
        "cups.service" | "cups-browsed.service" => {
            "Système d'impression CUPS : gère les imprimantes et peut les découvrir ou les partager sur le réseau."
        }
        "smbd.service" | "nmbd.service" | "samba.service" => {
            "Partage Samba/SMB : fournit des fichiers ou imprimantes aux machines Linux, Windows et macOS."
        }
        "nfs-server.service" | "rpcbind.service" => {
            "Partage NFS/RPC : rend des dossiers accessibles à d'autres machines Unix/Linux du réseau."
        }
        "vsftpd.service" | "proftpd.service" => {
            "Serveur FTP : permet le transfert de fichiers ; le chiffrement dépend de sa configuration."
        }
        "mosquitto.service" => {
            "Courtier MQTT : relaie des messages entre applications et objets connectés."
        }
        "redis-server.service" => {
            "Serveur Redis : fournit un stockage de données en mémoire accessible par des applications réseau."
        }
        "mariadb.service" | "mysql.service" | "postgresql.service" | "mongod.service" => {
            "Serveur de base de données : accepte les connexions des applications selon ses adresses d'écoute et ses règles d'accès."
        }
        "xrdp.service" => {
            "Bureau à distance RDP : permet d'ouvrir une session graphique depuis une autre machine."
        }
        "docker.service" | "podman.service" => {
            "Moteur de conteneurs : peut publier sur l'hôte les ports réseau des conteneurs."
        }
        _ => return None,
    };
    Some(purpose)
}

fn is_protected_unit(unit: &str) -> bool {
    matches!(
        unit,
        "dbus.service"
            | "systemd-logind.service"
            | "systemd-networkd.service"
            | "NetworkManager.service"
            | "polkit.service"
            | "systemd-resolved.service"
    )
}

fn collect_firewall(runner: &dyn CommandRunner) -> (FirewallState, SourceStatus) {
    let ufw_program = if Path::new("/usr/sbin/ufw").exists() {
        "/usr/sbin/ufw"
    } else {
        "ufw"
    };
    let ufw = runner.run(ufw_program, &["status", "verbose"]);
    let nftables_active = runner
        .run("systemctl", &["is-active", "nftables.service"])
        .is_ok_and(|result| result.success && result.stdout.trim() == "active");

    let Ok(result) = ufw else {
        let state = FirewallState {
            native_nftables_detected: nftables_active,
            ..FirewallState::default()
        };
        return (
            state,
            SourceStatus {
                source: "UFW".into(),
                availability: Availability::Unavailable,
                detail: "UFW n'est pas installé.".into(),
            },
        );
    };
    if !result.success {
        let state = FirewallState {
            installed: true,
            status: "État non lisible sans privilèges".into(),
            native_nftables_detected: nftables_active,
            warning: nftables_active.then(|| {
                "Le service nftables natif est actif ; ne pas le mélanger automatiquement avec UFW."
                    .into()
            }),
            ..FirewallState::default()
        };
        return (
            state,
            SourceStatus {
                source: "UFW".into(),
                availability: Availability::Partial,
                detail: "UFW est installé, mais son état n'est pas lisible sans privilèges.".into(),
            },
        );
    }

    let mut state = parse_ufw_status(&result.stdout);
    state.native_nftables_detected = nftables_active;
    if nftables_active {
        state.warning = Some(
            "Le service nftables natif est actif ; vérifiez la coexistence avec UFW avant toute modification."
                .into(),
        );
    }
    (
        state,
        SourceStatus {
            source: "UFW".into(),
            availability: Availability::Available,
            detail: "État et règles UFW consultés.".into(),
        },
    )
}

pub fn parse_ufw_status(output: &str) -> FirewallState {
    let mut state = FirewallState {
        installed: true,
        ..FirewallState::default()
    };
    let mut in_rules = false;
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(status) = trimmed.strip_prefix("Status:") {
            let status = status.trim();
            state.enabled = Some(status.eq_ignore_ascii_case("active"));
            state.status = if status.eq_ignore_ascii_case("active") {
                "Actif".into()
            } else {
                "Inactif".into()
            };
        } else if let Some(defaults) = trimmed.strip_prefix("Default:") {
            for entry in defaults.split(',').map(str::trim) {
                if let Some((policy, direction)) = entry.split_once(' ') {
                    if direction.contains("incoming") {
                        state.default_incoming = Some(policy.into());
                    } else if direction.contains("outgoing") {
                        state.default_outgoing = Some(policy.into());
                    }
                }
            }
        } else if trimmed.starts_with("--") {
            in_rules = true;
        } else if in_rules && !trimmed.is_empty() {
            let columns: Vec<_> = trimmed.split_whitespace().collect();
            let action_index = columns.iter().position(|column| {
                matches!(
                    column.to_ascii_uppercase().as_str(),
                    "ALLOW" | "DENY" | "REJECT" | "LIMIT"
                )
            });
            if let Some(action_index) = action_index.filter(|index| *index > 0) {
                let v6 = trimmed.contains("(v6)");
                let direction_offset = columns
                    .get(action_index + 1)
                    .is_some_and(|value| matches!(*value, "IN" | "OUT"))
                    as usize;
                let source_start = action_index + 1 + direction_offset;
                state.rules.push(FirewallRule {
                    target: columns[..action_index]
                        .iter()
                        .copied()
                        .filter(|column| *column != "(v6)")
                        .collect::<Vec<_>>()
                        .join(" "),
                    action: columns[action_index..source_start].join(" "),
                    source: columns[source_start..]
                        .iter()
                        .copied()
                        .filter(|column| *column != "(v6)")
                        .collect::<Vec<_>>()
                        .join(" "),
                    ip_version: Some(if v6 { IpVersion::V6 } else { IpVersion::V4 }),
                });
            }
        }
    }
    state
}

fn collect_ping_state() -> PingState {
    let ipv4_echo =
        read_boolean_sysctl("/proc/sys/net/ipv4/icmp_echo_ignore_all").map(|ignored| !ignored);
    let ipv6_echo =
        read_boolean_sysctl("/proc/sys/net/ipv6/icmp/echo_ignore_all").map(|ignored| !ignored);
    PingState {
        ipv4_echo,
        ipv6_echo,
        note: "Ne pas répondre à Echo n'équivaut ni à bloquer tout ICMP, ni à devenir invisible. ICMPv6 reste indispensable à plusieurs fonctions IPv6.".into(),
    }
}

fn read_boolean_sysctl(path: &str) -> Option<bool> {
    read_trimmed(path).and_then(|value| match value.as_str() {
        "0" => Some(false),
        "1" => Some(true),
        _ => None,
    })
}

fn collect_discovery(runner: &dyn CommandRunner) -> Vec<DiscoveryService> {
    let definitions = [
        (
            "mdns",
            "Avahi / mDNS",
            "Annonce et découvre des appareils et services sur le réseau local.",
            &["avahi-daemon.service"][..],
        ),
        (
            "llmnr",
            "LLMNR",
            "Résolution de noms sur le lien local, gérée notamment par systemd-resolved.",
            &["systemd-resolved.service"][..],
        ),
        (
            "sharing",
            "Partage de fichiers",
            "Services SMB ou NFS qui peuvent publier des dossiers sur le réseau.",
            &["smbd.service", "nmbd.service", "nfs-server.service"][..],
        ),
        (
            "printing",
            "Impression réseau",
            "CUPS peut publier ou accepter des travaux d'impression sur le réseau.",
            &["cups.service", "cups-browsed.service"][..],
        ),
        (
            "ssh",
            "SSH",
            "Accès distant chiffré à la machine.",
            &["ssh.service", "sshd.service"][..],
        ),
        (
            "web",
            "Serveurs web",
            "Serveurs HTTP courants détectés comme unités système.",
            &["apache2.service", "nginx.service", "caddy.service"][..],
        ),
    ];

    definitions
        .into_iter()
        .map(|(key, name, description, units)| {
            if key == "llmnr" {
                let active = runner
                    .run("resolvectl", &["status"])
                    .ok()
                    .filter(|result| result.success)
                    .and_then(|result| parse_llmnr_status(&result.stdout));
                return DiscoveryService {
                    key: key.into(),
                    name: name.into(),
                    description: description.into(),
                    active,
                    units: units.iter().map(|unit| (*unit).into()).collect(),
                };
            }
            let mut observed = false;
            let mut active = false;
            for unit in units {
                if let Ok(result) = runner.run("systemctl", &["is-active", unit]) {
                    observed = true;
                    active |= result.success && result.stdout.trim() == "active";
                }
            }
            DiscoveryService {
                key: key.into(),
                name: name.into(),
                description: description.into(),
                active: observed.then_some(active),
                units: units.iter().map(|unit| (*unit).into()).collect(),
            }
        })
        .collect()
}

fn parse_llmnr_status(output: &str) -> Option<bool> {
    let protocols = output
        .lines()
        .find_map(|line| line.trim().strip_prefix("Protocols:"))?;
    if protocols.split_whitespace().any(|value| value == "+LLMNR") {
        Some(true)
    } else if protocols.split_whitespace().any(|value| value == "-LLMNR") {
        Some(false)
    } else {
        None
    }
}

fn build_alerts(
    ports: &[PortInfo],
    docker_ports: &[DockerPort],
    firewall: &FirewallState,
) -> Vec<Alert> {
    let mut alerts = Vec::new();
    let all_interfaces = ports
        .iter()
        .filter(|port| port.exposure == ExposureLevel::AllInterfaces)
        .count();
    if all_interfaces > 0 {
        alerts.push(Alert {
            severity: AlertSeverity::Important,
            title: format!(
                "{all_interfaces} écoute{} sur toutes les interfaces",
                if all_interfaces > 1 { "s" } else { "" }
            ),
            message: "Ces services sont potentiellement joignables depuis d'autres réseaux. Le pare-feu et le routage déterminent l'accès réel.".into(),
            target: AlertTarget::Ports,
        });
    }
    if firewall.enabled == Some(false) {
        alerts.push(Alert {
            severity: AlertSeverity::Warning,
            title: "UFW est inactif".into(),
            message: "Cela ne prouve pas l'absence d'un autre pare-feu, mais aucune politique UFW active n'a été détectée.".into(),
            target: AlertTarget::Firewall,
        });
    }
    if docker_ports
        .iter()
        .any(|port| port.exposure == ExposureLevel::AllInterfaces)
    {
        alerts.push(Alert {
            severity: AlertSeverity::Warning,
            title: "Port Docker publié sur toutes les interfaces".into(),
            message: "Les ports Docker peuvent contourner les attentes liées à UFW. Vérifiez les règles Docker et nftables.".into(),
            target: AlertTarget::Ports,
        });
    }
    if firewall.native_nftables_detected {
        alerts.push(Alert {
            severity: AlertSeverity::Warning,
            title: "nftables natif détecté".into(),
            message: "Vérifiez la coexistence entre les règles nftables natives et UFW avant toute modification.".into(),
            target: AlertTarget::Firewall,
        });
    }
    if alerts.is_empty() {
        alerts.push(Alert {
            severity: AlertSeverity::Info,
            title: "Aucune alerte importante dans les données visibles".into(),
            message: "Ce résultat ne garantit pas que la machine soit invisible ou inaccessible."
                .into(),
            target: AlertTarget::Ports,
        });
    }
    alerts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_process_metadata_from_ss() {
        let ports = parse_ss_output(
            "tcp LISTEN 0 4096 127.0.0.1:631 0.0.0.0:* users:((\"cupsd\",pid=42,fd=7))",
            &[],
        );
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].pid, Some(42));
        assert_eq!(ports[0].process_name.as_deref(), Some("cupsd"));
        assert_eq!(ports[0].exposure, ExposureLevel::LocalOnly);
    }

    #[test]
    fn removes_common_secrets_from_process_commands() {
        let parts = vec![
            "server".into(),
            "--port".into(),
            "3000".into(),
            "--token=abc123".into(),
            "--password".into(),
            "hunter2".into(),
            "https://user:pass@example.test/path".into(),
        ];
        let sanitized = sanitize_command_parts(&parts);
        assert!(sanitized.contains("--port 3000"));
        assert!(sanitized.contains("--token=[valeur sensible masquée]"));
        assert!(!sanitized.contains("abc123"));
        assert!(!sanitized.contains("hunter2"));
        assert!(!sanitized.contains("user:pass"));
    }

    #[test]
    fn parses_docker_ipv4_ipv6_and_suggestion() {
        let output = r#"{"ID":"abc","Names":"web","Image":"nginx","Ports":"0.0.0.0:3000->80/tcp, [::]:3000->80/tcp, 127.0.0.1:5353->53/udp"}"#;
        let ports = parse_docker_output(output);
        assert_eq!(ports.len(), 3);
        assert_eq!(ports[0].exposure, ExposureLevel::AllInterfaces);
        assert_eq!(
            ports[0].safer_binding_suggestion.as_deref(),
            Some("127.0.0.1:3000:80/tcp")
        );
        assert_eq!(ports[2].exposure, ExposureLevel::LocalOnly);
        assert_eq!(ports[2].protocol, TransportProtocol::Udp);
    }

    #[test]
    fn parses_ufw_defaults_and_v6_rules() {
        let state = parse_ufw_status(
            "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n\nTo Action From\n-- ------ ----\n22/tcp ALLOW IN 192.168.1.0/24\n443/tcp (v6) ALLOW Anywhere (v6)\n",
        );
        assert_eq!(state.enabled, Some(true));
        assert_eq!(state.default_incoming.as_deref(), Some("deny"));
        assert_eq!(state.default_outgoing.as_deref(), Some("allow"));
        assert_eq!(state.rules.len(), 2);
        assert_eq!(state.rules[0].action, "ALLOW IN");
        assert_eq!(state.rules[1].target, "443/tcp");
        assert_eq!(state.rules[1].action, "ALLOW");
        assert_eq!(state.rules[1].ip_version, Some(IpVersion::V6));
    }

    #[test]
    fn parses_llmnr_without_confusing_it_with_resolved_activity() {
        assert_eq!(
            parse_llmnr_status("Global\n       Protocols: -LLMNR -mDNS -DNSOverTLS\n"),
            Some(false)
        );
        assert_eq!(
            parse_llmnr_status("Global\n       Protocols: +LLMNR -mDNS\n"),
            Some(true)
        );
    }

    #[test]
    fn parses_systemd_properties_and_protects_essential_unit() {
        let service = parse_systemd_service(
            "NetworkManager.service",
            "Description=Network Manager\nActiveState=active\nUnitFileState=enabled\n",
        );
        assert_eq!(service.enabled, Some(true));
        assert!(service.protected);

        let apache = parse_systemd_service(
            "apache2.service",
            "Description=The Apache HTTP Server\nActiveState=active\nUnitFileState=enabled\n",
        );
        assert!(apache.manageable);
        assert!(
            apache
                .purpose
                .as_deref()
                .is_some_and(|text| text.contains("Serveur HTTP Apache"))
        );
    }
}
