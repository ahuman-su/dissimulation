import type { NetworkSnapshot } from './types';

export const demoSnapshot: NetworkSnapshot = {
  analyzedAtEpochMs: Date.now(),
  ports: [
    {
      id: 'tcp-0.0.0.0-3000-2481',
      protocol: 'tcp',
      localAddress: '0.0.0.0',
      port: 3000,
      state: 'LISTEN',
      ipVersion: 'IPv4',
      pid: 2481,
      processName: 'node',
      user: 'utilisateur',
      command: 'node server.js',
      systemdService: null,
      dockerContainer: 'api-dev',
      interfaceName: null,
      interfaceKind: null,
      exposure: 'allInterfaces',
      explanation:
        "Ce socket écoute sur toutes les interfaces IPv4. Son accessibilité réelle dépend du pare-feu et du routage."
    },
    {
      id: 'tcp-127.0.0.1-631-712',
      protocol: 'tcp',
      localAddress: '127.0.0.1',
      port: 631,
      state: 'LISTEN',
      ipVersion: 'IPv4',
      pid: 712,
      processName: 'cupsd',
      user: 'root',
      command: '/usr/sbin/cupsd -l',
      systemdService: 'cups.service',
      dockerContainer: null,
      interfaceName: 'lo',
      interfaceKind: 'loopback',
      exposure: 'localOnly',
      explanation: "Ce socket n'accepte que les connexions provenant de cette machine."
    },
    {
      id: 'udp-172.17.0.1-5353-unknown',
      protocol: 'udp',
      localAddress: '172.17.0.1',
      port: 5353,
      state: 'UNCONN',
      ipVersion: 'IPv4',
      pid: null,
      processName: null,
      user: null,
      command: null,
      systemdService: null,
      dockerContainer: null,
      interfaceName: 'docker0',
      interfaceKind: 'docker',
      exposure: 'virtualNetwork',
      explanation:
        'Ce socket est lié au réseau virtuel docker0. Il peut être joignable par des conteneurs ou machines virtuelles.'
    }
  ],
  services: [
    {
      unit: 'cups.service',
      description: 'CUPS Scheduler',
      purpose: 'Système d’impression CUPS : gère les imprimantes et peut les découvrir ou les partager sur le réseau.',
      activeState: 'active',
      enabled: true,
      protected: false,
      manageable: true
    }
  ],
  dockerPorts: [
    {
      containerId: 'ab12cd34ef56',
      containerName: 'api-dev',
      image: 'example/api:dev',
      publishAddress: '0.0.0.0',
      hostPort: 3000,
      containerPort: 3000,
      protocol: 'tcp',
      exposure: 'allInterfaces',
      saferBindingSuggestion: '127.0.0.1:3000:3000/tcp'
    }
  ],
  interfaces: [
    {
      name: 'wlp2s0',
      kind: 'wifi',
      addresses: ['192.168.1.42/24', 'fe80::20c:29ff:feaa:1/64'],
      hardwareMac: '00:11:22:33:44:55',
      currentMac: '4a:72:18:93:bc:10',
      activeConnection: 'Maison',
      macMode: 'stable',
      operstate: 'up',
      eligibleForRandomization: true
    },
    {
      name: 'docker0',
      kind: 'docker',
      addresses: ['172.17.0.1/16'],
      hardwareMac: '02:42:d1:5f:10:00',
      currentMac: '02:42:d1:5f:10:00',
      activeConnection: null,
      macMode: 'unknown',
      operstate: 'down',
      eligibleForRandomization: false
    }
  ],
  firewall: {
    installed: true,
    enabled: true,
    status: 'Actif',
    defaultIncoming: 'deny',
    defaultOutgoing: 'allow',
    rules: [{ target: '22/tcp', action: 'ALLOW', source: '192.168.1.0/24', ipVersion: 'IPv4' }],
    nativeNftablesDetected: false,
    warning: null
  },
  ping: {
    ipv4Echo: true,
    ipv6Echo: true,
    note: "Ne pas répondre à Echo n'équivaut ni à bloquer tout ICMP, ni à devenir invisible. ICMPv6 reste indispensable à plusieurs fonctions IPv6."
  },
  discovery: [
    {
      key: 'mdns',
      name: 'Avahi / mDNS',
      description: 'Annonce et découvre des appareils et services sur le réseau local.',
      active: true,
      units: ['avahi-daemon.service']
    },
    {
      key: 'ssh',
      name: 'SSH',
      description: 'Accès distant chiffré à la machine.',
      active: false,
      units: ['ssh.service', 'sshd.service']
    }
  ],
  alerts: [
    {
      severity: 'important',
      title: '1 écoute sur toutes les interfaces',
      message:
        "Ce service est potentiellement joignable depuis d'autres réseaux. Le pare-feu et le routage déterminent l'accès réel.",
      target: 'ports'
    },
    {
      severity: 'warning',
      title: 'Port Docker publié sur toutes les interfaces',
      message: 'Les ports Docker peuvent contourner les attentes liées à UFW.',
      target: 'ports'
    }
  ],
  sources: [
    { source: 'Sockets', availability: 'available', detail: 'Données de démonstration.' },
    { source: 'Interfaces', availability: 'available', detail: 'Données de démonstration.' },
    { source: 'UFW', availability: 'available', detail: 'Données de démonstration.' },
    { source: 'Docker', availability: 'available', detail: 'Données de démonstration.' }
  ]
};
