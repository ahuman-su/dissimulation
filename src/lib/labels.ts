import type { ExposureLevel, InterfaceKind, MacMode } from './types';

export const exposureLabels: Record<ExposureLevel, string> = {
  localOnly: 'Local uniquement',
  virtualNetwork: 'Réseau virtuel',
  specificInterface: 'Interface précise',
  allInterfaces: 'Toutes interfaces',
  unknown: 'Inconnu'
};

export const interfaceLabels: Record<InterfaceKind, string> = {
  loopback: 'Boucle locale',
  wifi: 'Wi-Fi',
  ethernet: 'Ethernet',
  docker: 'Docker',
  virtual: 'Virtuelle',
  unknown: 'Type inconnu'
};

export const macModeLabels: Record<MacMode, string> = {
  hardware: 'Adresse matérielle',
  stable: 'Pseudonyme stable par réseau',
  random: 'Adresse aléatoire',
  preserve: 'Ne pas modifier',
  unknown: 'Mode inconnu'
};

export function triState(value: boolean | null, yes = 'Actif', no = 'Inactif'): string {
  return value === null ? 'Inconnu' : value ? yes : no;
}

