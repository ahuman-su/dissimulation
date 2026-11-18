export type Page =
  | 'dashboard'
  | 'traffic'
  | 'filters'
  | 'ports'
  | 'services'
  | 'interfaces'
  | 'firewall'
  | 'profiles'
  | 'history'
  | 'settings';

export type ExposureLevel =
  | 'localOnly'
  | 'virtualNetwork'
  | 'specificInterface'
  | 'allInterfaces'
  | 'unknown';

export type InterfaceKind = 'loopback' | 'wifi' | 'ethernet' | 'docker' | 'virtual' | 'unknown';
export type MacMode = 'hardware' | 'stable' | 'random' | 'preserve' | 'unknown';
export type Availability = 'available' | 'partial' | 'unavailable';

export interface PortInfo {
  id: string;
  protocol: 'tcp' | 'udp';
  localAddress: string;
  port: number;
  state: string;
  ipVersion: 'IPv4' | 'IPv6';
  pid: number | null;
  processName: string | null;
  user: string | null;
  command: string | null;
  systemdService: string | null;
  dockerContainer: string | null;
  interfaceName: string | null;
  interfaceKind: InterfaceKind | null;
  exposure: ExposureLevel;
  explanation: string;
}

export interface NetworkInterface {
  name: string;
  kind: InterfaceKind;
  addresses: string[];
  hardwareMac: string | null;
  currentMac: string | null;
  activeConnection: string | null;
  macMode: MacMode;
  operstate: string;
  eligibleForRandomization: boolean;
}

export interface DockerPort {
  containerId: string;
  containerName: string;
  image: string;
  publishAddress: string;
  hostPort: number;
  containerPort: number;
  protocol: 'tcp' | 'udp';
  exposure: ExposureLevel;
  saferBindingSuggestion: string | null;
}

export interface ServiceInfo {
  unit: string;
  description: string | null;
  purpose: string | null;
  activeState: string;
  enabled: boolean | null;
  protected: boolean;
  manageable: boolean;
}

export interface FirewallRule {
  target: string;
  action: string;
  source: string;
  ipVersion: 'IPv4' | 'IPv6' | null;
}

export interface FirewallState {
  installed: boolean;
  enabled: boolean | null;
  status: string;
  defaultIncoming: string | null;
  defaultOutgoing: string | null;
  rules: FirewallRule[];
  nativeNftablesDetected: boolean;
  warning: string | null;
}

export interface DiscoveryService {
  key: string;
  name: string;
  description: string;
  active: boolean | null;
  units: string[];
}

export interface NetworkSnapshot {
  analyzedAtEpochMs: number;
  ports: PortInfo[];
  services: ServiceInfo[];
  dockerPorts: DockerPort[];
  interfaces: NetworkInterface[];
  firewall: FirewallState;
  ping: {
    ipv4Echo: boolean | null;
    ipv6Echo: boolean | null;
    note: string;
  };
  discovery: DiscoveryService[];
  alerts: Array<{
    severity: 'info' | 'warning' | 'important';
    title: string;
    message: string;
    target: Extract<Page, 'ports' | 'firewall' | 'interfaces' | 'services' | 'traffic' | 'filters'>;
  }>;
  sources: Array<{
    source: string;
    availability: Availability;
    detail: string;
  }>;
}

export interface HistoryEntry {
  date: number;
  action: string;
  previousValue: string;
  newValue: string;
  result: string;
  restorable: boolean;
}

export interface PlannedAction {
  id: string;
  title: string;
  target: string;
  currentValue: string;
  newValue: string;
  impact: string;
  warning: string | null;
  operations: string[];
  requiresAuthorization: boolean;
  reversible: boolean;
  systemAction: SystemAction;
}

export type SystemAction =
  | { type: 'setMacMode'; interface: string; mode: MacMode }
  | { type: 'manageService'; unit: string; action: 'start' | 'stop' | 'enable' | 'disable' }
  | { type: 'applyFirewallBaseline'; preserveSsh: boolean }
  | { type: 'setIpv4Echo'; enabled: boolean }
  | { type: 'applyProfile'; profile: 'public' | 'home' | 'development' | 'restore'; options: string[] }
  | { type: 'addBlockRule'; rule: BlockRule }
  | { type: 'removeBlockRule'; ruleId: string };

export interface ActionOutcome {
  title: string;
  message: string;
  changed: boolean;
  reconnectPerformed: boolean;
}

export interface ActionProgress {
  operation: string;
  current: number;
  total: number;
  label: string;
}

export interface TrafficSession {
  id: string;
  protocol: 'tcp' | 'udp';
  state: string;
  localAddress: string;
  localPort: number;
  remoteAddress: string;
  remotePort: number;
  processName: string | null;
  pid: number | null;
  executable: string | null;
  cgroupPath: string | null;
  processStartTime: number | null;
  isListener: boolean;
}

export interface PacketMetadata {
  capturedAtEpochMs: number;
  sourceAddress: string;
  sourcePort: number | null;
  destinationAddress: string;
  destinationPort: number | null;
  protocol: string;
  transportProtocol: 'tcp' | 'udp';
  length: number | null;
  requestSummary: string | null;
}

export interface PacketSample {
  available: boolean;
  detail: string;
  packets: PacketMetadata[];
}

export interface ApplicationTrafficBucket {
  bucketStartEpochMs: number;
  applicationId: string;
  applicationName: string;
  executable: string | null;
  packetsSent: number;
  packetsReceived: number;
  bytesSent: number;
  bytesReceived: number;
}

export interface ApplicationTrafficHistory {
  available: boolean;
  detail: string;
  retentionDays: number;
  entries: ApplicationTrafficBucket[];
}

export interface ApplicationTrafficSampleResult {
  available: boolean;
  detail: string;
  capturedPackets: number;
  attributedPackets: number;
}

export interface ApplicationBlockRule {
  id: string;
  applicationName: string;
  executable: string | null;
  cgroupPath: string;
  pid: number;
  processStartTime: number;
  createdAtEpochMs: number;
}

export interface NetworkApplication {
  id: string;
  name: string;
  executable: string | null;
  cgroupPath: string;
  pid: number;
  processStartTime: number;
  connectionCount: number;
  blockedRuleId: string | null;
}

export interface NetworkApplicationInventory {
  available: boolean;
  detail: string;
  applications: NetworkApplication[];
  blockRules: ApplicationBlockRule[];
}

export interface BlockRule {
  id: string;
  name: string;
  direction: 'incoming' | 'outgoing';
  protocol: 'tcp' | 'udp' | 'any';
  remoteAddress: string;
  port: number;
  resolvedAddresses: string[];
}

export interface ResolvedFilterTarget {
  kind: 'any' | 'address' | 'cidr' | 'domain';
  normalizedTarget: string;
  addresses: string[];
  detail: string;
}
