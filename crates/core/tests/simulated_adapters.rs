use std::collections::HashMap;

use dissimulation_core::{
    ExposureLevel, IpVersion,
    collectors::{
        CommandResult, CommandRunner, parse_docker_output, parse_systemd_service, parse_ufw_status,
    },
};

#[derive(Default)]
struct SimulatedRunner {
    commands: HashMap<String, CommandResult>,
}

impl CommandRunner for SimulatedRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<CommandResult, String> {
        let executable = program.rsplit('/').next().unwrap_or(program);
        self.commands
            .get(&format!("{executable} {}", args.join(" ")))
            .cloned()
            .ok_or_else(|| "commande simulée absente".into())
    }
}

#[test]
fn network_manager_adapter_accepts_an_unavailable_simulation() {
    let runner = SimulatedRunner::default();
    let result = runner.run("nmcli", &["device", "show"]);
    assert!(result.is_err());
}

#[test]
fn systemd_adapter_parses_inactive_and_disabled_service() {
    let service = parse_systemd_service(
        "demo.service",
        "Description=Demo server\nActiveState=inactive\nUnitFileState=disabled\n",
    );
    assert_eq!(service.active_state, "inactive");
    assert_eq!(service.enabled, Some(false));
    assert!(!service.protected);
}

#[test]
fn ufw_adapter_handles_absence_and_dual_stack_rules() {
    let absent = SimulatedRunner::default();
    assert!(absent.run("ufw", &["status", "verbose"]).is_err());

    let state = parse_ufw_status(
        "Status: active\nDefault: deny (incoming), allow (outgoing)\n-- ------ ----\n53/udp ALLOW 192.168.0.0/16\n53/udp (v6) ALLOW Anywhere (v6)\n",
    );
    assert_eq!(state.rules[0].ip_version, Some(IpVersion::V4));
    assert_eq!(state.rules[1].ip_version, Some(IpVersion::V6));
}

#[test]
fn docker_adapter_distinguishes_localhost_and_wildcard() {
    let ports = parse_docker_output(
        r#"{"ID":"1","Names":"api","Image":"demo","Ports":"127.0.0.1:3000->3000/tcp, 0.0.0.0:8080->80/tcp"}"#,
    );
    assert_eq!(ports[0].exposure, ExposureLevel::LocalOnly);
    assert_eq!(ports[1].exposure, ExposureLevel::AllInterfaces);
}
