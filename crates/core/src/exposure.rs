use std::net::IpAddr;

use crate::models::{ExposureLevel, InterfaceKind, IpVersion, NetworkInterface};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub address: String,
    pub port: u16,
    pub version: IpVersion,
    pub zone: Option<String>,
}

pub fn parse_endpoint(raw: &str) -> Option<Endpoint> {
    let raw = raw.trim();
    let (host, port_text) = if let Some(rest) = raw.strip_prefix('[') {
        let close = rest.find(']')?;
        let host = &rest[..close];
        let port = rest[close + 1..].strip_prefix(':')?;
        (host, port)
    } else {
        raw.rsplit_once(':')?
    };

    let port = port_text.parse::<u16>().ok()?;
    let host = host.trim_matches(|character| character == '[' || character == ']');
    let (address, zone) = host
        .split_once('%')
        .map(|(address, zone)| (address, Some(zone.to_string())))
        .unwrap_or((host, None));

    let version = if address.contains(':') {
        IpVersion::V6
    } else {
        IpVersion::V4
    };

    Some(Endpoint {
        address: address.to_string(),
        port,
        version,
        zone,
    })
}

pub fn classify_endpoint(
    endpoint: &Endpoint,
    interfaces: &[NetworkInterface],
) -> (ExposureLevel, Option<String>, Option<InterfaceKind>, String) {
    let address = endpoint.address.as_str();

    if matches!(address, "127.0.0.1" | "::1")
        || address
            .parse::<IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
    {
        return (
            ExposureLevel::LocalOnly,
            Some("lo".into()),
            Some(InterfaceKind::Loopback),
            "Ce socket n'accepte que les connexions provenant de cette machine.".into(),
        );
    }

    if matches!(address, "0.0.0.0" | "::" | "*") {
        return (
            ExposureLevel::AllInterfaces,
            None,
            None,
            format!(
                "Ce socket écoute sur toutes les interfaces {}. Son accessibilité réelle dépend du pare-feu et du routage.",
                match endpoint.version {
                    IpVersion::V4 => "IPv4",
                    IpVersion::V6 => "IPv6",
                }
            ),
        );
    }

    let matching_interface = endpoint
        .zone
        .as_ref()
        .and_then(|zone| interfaces.iter().find(|interface| &interface.name == zone))
        .or_else(|| {
            interfaces.iter().find(|interface| {
                interface
                    .addresses
                    .iter()
                    .any(|candidate| candidate.split('/').next().is_some_and(|ip| ip == address))
            })
        });

    if let Some(interface) = matching_interface {
        if matches!(
            interface.kind,
            InterfaceKind::Docker | InterfaceKind::Virtual
        ) {
            return (
                ExposureLevel::VirtualNetwork,
                Some(interface.name.clone()),
                Some(interface.kind),
                format!(
                    "Ce socket est lié au réseau virtuel {}. Il peut être joignable par des conteneurs ou machines virtuelles.",
                    interface.name
                ),
            );
        }

        return (
            ExposureLevel::SpecificInterface,
            Some(interface.name.clone()),
            Some(interface.kind),
            format!(
                "Ce socket écoute sur l'adresse de l'interface {}. Son accessibilité dépend du réseau et du pare-feu.",
                interface.name
            ),
        );
    }

    (
        ExposureLevel::Unknown,
        endpoint.zone.clone(),
        None,
        "L'adresse est spécifique, mais son interface n'a pas pu être identifiée.".into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{MacMode, NetworkInterface};

    fn interface(name: &str, kind: InterfaceKind, addresses: &[&str]) -> NetworkInterface {
        NetworkInterface {
            name: name.into(),
            kind,
            addresses: addresses.iter().map(|address| (*address).into()).collect(),
            hardware_mac: None,
            current_mac: None,
            active_connection: None,
            mac_mode: MacMode::Unknown,
            operstate: "up".into(),
            eligible_for_randomization: false,
        }
    }

    #[test]
    fn parses_ipv4_ipv6_and_zone_endpoints() {
        assert_eq!(
            parse_endpoint("127.0.0.1:631"),
            Some(Endpoint {
                address: "127.0.0.1".into(),
                port: 631,
                version: IpVersion::V4,
                zone: None,
            })
        );
        assert_eq!(parse_endpoint("[::]:443").unwrap().version, IpVersion::V6);
        assert_eq!(
            parse_endpoint("[fe80::1%wlp2s0]:5353").unwrap().zone,
            Some("wlp2s0".into())
        );
        assert!(parse_endpoint("127.0.0.1:*").is_none());
    }

    #[test]
    fn classifies_loopback_wildcard_physical_and_docker() {
        let interfaces = vec![
            interface("wlp2s0", InterfaceKind::Wifi, &["192.168.1.20/24"]),
            interface("docker0", InterfaceKind::Docker, &["172.17.0.1/16"]),
        ];

        let local = parse_endpoint("127.0.0.1:80").unwrap();
        assert_eq!(
            classify_endpoint(&local, &interfaces).0,
            ExposureLevel::LocalOnly
        );

        let wildcard = parse_endpoint("[::]:443").unwrap();
        assert_eq!(
            classify_endpoint(&wildcard, &interfaces).0,
            ExposureLevel::AllInterfaces
        );

        let wifi = parse_endpoint("192.168.1.20:22").unwrap();
        assert_eq!(
            classify_endpoint(&wifi, &interfaces).0,
            ExposureLevel::SpecificInterface
        );

        let docker = parse_endpoint("172.17.0.1:8080").unwrap();
        assert_eq!(
            classify_endpoint(&docker, &interfaces).0,
            ExposureLevel::VirtualNetwork
        );
    }
}
