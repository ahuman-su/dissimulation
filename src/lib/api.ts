import { invoke, isTauri } from '@tauri-apps/api/core';
import { demoSnapshot } from './demo';
import type {
  ActionOutcome,
  ApplicationTrafficHistory,
  ApplicationTrafficSampleResult,
  BlockRule,
  FirewallState,
  NetworkSnapshot,
  NetworkApplicationInventory,
  PacketSample,
  ResolvedFilterTarget,
  SystemAction,
  TrafficSession
} from './types';

export interface BackgroundSettings {
  autostartEnabled: boolean;
  scanIntervalMinutes: number;
  applicationTrafficMonitoring: boolean;
  applicationTrafficIntervalMinutes: number;
  applicationTrafficSampleSeconds: number;
  trafficHistoryDays: number;
  notificationsEnabled: boolean;
  notifyNewPorts: boolean;
  notifyFirewallDisabled: boolean;
  notifyMacChange: boolean;
  notifyProfileFailure: boolean;
  notifyServiceRestart: boolean;
  notificationCooldownMinutes: number;
}

export type LifecycleState =
  | 'startup'
  | 'initializing'
  | 'backgroundMonitoring'
  | 'interfaceOpen'
  | 'interfaceHidden'
  | 'authorizationRequest'
  | 'shuttingDown';

export interface RuntimeStatus {
  lifecycle: LifecycleState;
  scanRunning: boolean;
  lastAnalyzedAtEpochMs: number | null;
}

export const defaultBackgroundSettings: BackgroundSettings = {
  autostartEnabled: false,
  scanIntervalMinutes: 15,
  applicationTrafficMonitoring: true,
  applicationTrafficIntervalMinutes: 15,
  applicationTrafficSampleSeconds: 4,
  trafficHistoryDays: 30,
  notificationsEnabled: true,
  notifyNewPorts: true,
  notifyFirewallDisabled: true,
  notifyMacChange: true,
  notifyProfileFailure: true,
  notifyServiceRestart: true,
  notificationCooldownMinutes: 30
};

export interface ScanResult {
  snapshot: NetworkSnapshot;
  demo: boolean;
}

export async function scanNetworkExposure(): Promise<ScanResult> {
  if (!isTauri()) {
    await new Promise((resolve) => window.setTimeout(resolve, 260));
    return { snapshot: { ...demoSnapshot, analyzedAtEpochMs: Date.now() }, demo: true };
  }

  const snapshot = await invoke<NetworkSnapshot>('scan_network_exposure');
  return { snapshot, demo: false };
}

export async function getInitialNetworkExposure(): Promise<ScanResult> {
  if (!isTauri()) return scanNetworkExposure();
  const snapshot = await invoke<NetworkSnapshot>('get_initial_network_exposure');
  return { snapshot, demo: false };
}

export async function getBackgroundSettings(): Promise<BackgroundSettings> {
  if (!isTauri()) return { ...defaultBackgroundSettings };
  return invoke<BackgroundSettings>('get_background_settings');
}

export async function updateBackgroundSettings(
  settings: BackgroundSettings
): Promise<BackgroundSettings> {
  if (!isTauri()) return settings;
  return invoke<BackgroundSettings>('update_background_settings', { settings });
}

export async function getRuntimeStatus(): Promise<RuntimeStatus> {
  if (!isTauri()) {
    return {
      lifecycle: 'interfaceOpen',
      scanRunning: false,
      lastAnalyzedAtEpochMs: Date.now()
    };
  }
  return invoke<RuntimeStatus>('get_runtime_status');
}

export async function quitCompletely(): Promise<void> {
  if (!isTauri()) return;
  await invoke('quit_completely');
}

export async function executeSystemAction(action: SystemAction): Promise<ActionOutcome> {
  if (!isTauri()) {
    throw new Error("Les modifications système nécessitent l'application de bureau.");
  }
  return invoke<ActionOutcome>('execute_system_action', { action });
}

export async function inspectFirewallWithAuthorization(): Promise<FirewallState> {
  if (!isTauri()) return demoSnapshot.firewall;
  return invoke<FirewallState>('inspect_firewall_with_authorization');
}

export async function getTrafficSessions(): Promise<TrafficSession[]> {
  if (!isTauri()) {
    return [
      {
        id: 'demo-session',
        protocol: 'tcp',
        state: 'ESTAB',
        localAddress: '192.168.1.42',
        localPort: 49152,
        remoteAddress: '203.0.113.8',
        remotePort: 443,
        processName: 'firefox',
        pid: 2481,
        executable: '/usr/lib/firefox/firefox',
        cgroupPath: '/user.slice/user-1000.slice/app-firefox.scope',
        processStartTime: 123456,
        isListener: false
      }
    ];
  }
  return invoke<TrafficSession[]>('get_traffic_sessions');
}

export async function capturePacketSample(interfaceName: string): Promise<PacketSample> {
  if (!isTauri()) {
    return {
      available: true,
      detail: 'Exemple de métadonnées — aucune capture réelle dans le navigateur.',
      packets: [
        {
          capturedAtEpochMs: Date.now(),
          sourceAddress: '192.168.1.42',
          sourcePort: 53000,
          destinationAddress: '1.1.1.1',
          destinationPort: 53,
          protocol: 'DNS',
          transportProtocol: 'udp',
          length: 74,
          requestSummary: 'DNS : example.org'
        }
      ]
    };
  }
  return invoke<PacketSample>('capture_packet_sample', { interface: interfaceName });
}

export async function getApplicationTrafficHistory(
  days: number
): Promise<ApplicationTrafficHistory> {
  if (!isTauri()) {
    const now = Date.now();
    const hour = 3_600_000;
    return {
      available: true,
      detail: 'Données de démonstration agrégées par heure.',
      retentionDays: days,
      entries: Array.from({ length: Math.min(days * 4, 24) }, (_, index) => ({
        bucketStartEpochMs: now - (Math.min(days * 4, 24) - index) * hour,
        applicationId: index % 3 === 0 ? 'demo:curl' : 'demo:firefox',
        applicationName: index % 3 === 0 ? 'curl' : 'firefox',
        executable: index % 3 === 0 ? '/usr/bin/curl' : '/usr/lib/firefox/firefox',
        packetsSent: 40 + ((index * 17) % 90),
        packetsReceived: 25 + ((index * 11) % 70),
        bytesSent: 12_000 + index * 1_500,
        bytesReceived: 8_000 + index * 900
      }))
    };
  }
  return invoke<ApplicationTrafficHistory>('get_application_traffic_history', { days });
}

export async function sampleApplicationTraffic(
  interfaceName: string
): Promise<ApplicationTrafficSampleResult> {
  if (!isTauri()) {
    return {
      available: true,
      detail: "Échantillon de démonstration attribué à l'application Firefox.",
      capturedPackets: 120,
      attributedPackets: 105
    };
  }
  return invoke<ApplicationTrafficSampleResult>('sample_application_traffic', {
    interface: interfaceName
  });
}

export async function getNetworkApplications(): Promise<NetworkApplicationInventory> {
  if (!isTauri()) {
    return {
      available: true,
      detail: 'Inventaire de démonstration cgroup v2.',
      applications: [
        {
          id: 'demo-firefox',
          name: 'firefox',
          executable: '/usr/lib/firefox/firefox',
          cgroupPath: '/user.slice/user-1000.slice/app-firefox.scope',
          pid: 2481,
          processStartTime: 123456,
          connectionCount: 6,
          blockedRuleId: null
        }
      ],
      blockRules: []
    };
  }
  return invoke<NetworkApplicationInventory>('get_network_applications');
}

export async function blockApplicationNetwork(
  pid: number,
  processStartTime: number
): Promise<ActionOutcome> {
  if (!isTauri()) throw new Error("Le blocage nécessite l'application de bureau.");
  return invoke<ActionOutcome>('block_application_network', { pid, processStartTime });
}

export async function unblockApplicationNetwork(ruleId: string): Promise<ActionOutcome> {
  if (!isTauri()) throw new Error("Le blocage nécessite l'application de bureau.");
  return invoke<ActionOutcome>('unblock_application_network', { ruleId });
}

export async function getBlockRules(): Promise<BlockRule[]> {
  if (!isTauri()) return [];
  return invoke<BlockRule[]>('get_block_rules');
}

export async function resolveFilterTarget(
  target: string,
  port: number
): Promise<ResolvedFilterTarget> {
  if (!isTauri()) {
    const normalized = target.trim().toLowerCase();
    const kind: ResolvedFilterTarget['kind'] = normalized === 'any'
      ? 'any'
      : normalized.includes('/')
        ? 'cidr'
        : /^[0-9a-f:.]+$/i.test(normalized)
          ? 'address'
          : 'domain';
    return {
      kind,
      normalizedTarget: normalized,
      addresses: kind === 'domain' ? ['93.184.216.34'] : [normalized],
      detail: 'Résolution de démonstration.'
    };
  }
  return invoke<ResolvedFilterTarget>('resolve_filter_target', { target, port });
}

export async function addBlockRule(rule: BlockRule): Promise<ActionOutcome> {
  if (!isTauri()) throw new Error("Les filtres UFW nécessitent l'application de bureau.");
  return invoke<ActionOutcome>('add_block_rule', { rule });
}

export async function removeBlockRule(ruleId: string): Promise<ActionOutcome> {
  if (!isTauri()) throw new Error("Les filtres UFW nécessitent l'application de bureau.");
  return invoke<ActionOutcome>('remove_block_rule', { ruleId });
}
