use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NetworkSnapshot {
    pub analyzed_at_epoch_ms: u128,
    pub ports: Vec<PortInfo>,
    pub services: Vec<ServiceInfo>,
    pub docker_ports: Vec<DockerPort>,
    pub interfaces: Vec<NetworkInterface>,
    pub firewall: FirewallState,
    pub ping: PingState,
    pub discovery: Vec<DiscoveryService>,
    pub alerts: Vec<Alert>,
    pub sources: Vec<SourceStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PortInfo {
    pub id: String,
    pub protocol: TransportProtocol,
    pub local_address: String,
    pub port: u16,
    pub state: String,
    pub ip_version: IpVersion,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub user: Option<String>,
    pub command: Option<String>,
    pub systemd_service: Option<String>,
    pub docker_container: Option<String>,
    pub interface_name: Option<String>,
    pub interface_kind: Option<InterfaceKind>,
    pub exposure: ExposureLevel,
    pub explanation: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum IpVersion {
    #[serde(rename = "IPv4")]
    V4,
    #[serde(rename = "IPv6")]
    V6,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum ExposureLevel {
    LocalOnly,
    VirtualNetwork,
    SpecificInterface,
    AllInterfaces,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum InterfaceKind {
    Loopback,
    Wifi,
    Ethernet,
    Docker,
    Virtual,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NetworkInterface {
    pub name: String,
    pub kind: InterfaceKind,
    pub addresses: Vec<String>,
    pub hardware_mac: Option<String>,
    pub current_mac: Option<String>,
    pub active_connection: Option<String>,
    pub mac_mode: MacMode,
    pub operstate: String,
    pub eligible_for_randomization: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum MacMode {
    Hardware,
    Stable,
    Random,
    Preserve,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DockerPort {
    pub container_id: String,
    pub container_name: String,
    pub image: String,
    pub publish_address: String,
    pub host_port: u16,
    pub container_port: u16,
    pub protocol: TransportProtocol,
    pub exposure: ExposureLevel,
    pub safer_binding_suggestion: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceInfo {
    pub unit: String,
    pub description: Option<String>,
    pub purpose: Option<String>,
    pub active_state: String,
    pub enabled: Option<bool>,
    pub protected: bool,
    pub manageable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FirewallState {
    pub installed: bool,
    pub enabled: Option<bool>,
    pub status: String,
    pub default_incoming: Option<String>,
    pub default_outgoing: Option<String>,
    pub rules: Vec<FirewallRule>,
    pub native_nftables_detected: bool,
    pub warning: Option<String>,
}

impl Default for FirewallState {
    fn default() -> Self {
        Self {
            installed: false,
            enabled: None,
            status: "Indisponible".into(),
            default_incoming: None,
            default_outgoing: None,
            rules: Vec::new(),
            native_nftables_detected: false,
            warning: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FirewallRule {
    pub target: String,
    pub action: String,
    pub source: String,
    pub ip_version: Option<IpVersion>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PingState {
    pub ipv4_echo: Option<bool>,
    pub ipv6_echo: Option<bool>,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryService {
    pub key: String,
    pub name: String,
    pub description: String,
    pub active: Option<bool>,
    pub units: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Alert {
    pub severity: AlertSeverity,
    pub title: String,
    pub message: String,
    pub target: AlertTarget,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AlertTarget {
    Ports,
    Firewall,
    Interfaces,
    Services,
    Traffic,
    Filters,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    Info,
    Warning,
    Important,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SourceStatus {
    pub source: String,
    pub availability: Availability,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Availability {
    Available,
    Partial,
    Unavailable,
}
