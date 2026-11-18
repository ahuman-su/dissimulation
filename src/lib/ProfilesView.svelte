<script lang="ts">
  import ActionPreview from './ActionPreview.svelte';
  import Badge from './Badge.svelte';
  import { executeSystemAction } from './api';
  import type { ActionOutcome, NetworkSnapshot, PlannedAction } from './types';

  export let snapshot: NetworkSnapshot;
  export let onApplied: (action: PlannedAction, outcome: ActionOutcome) => void | Promise<void>;

  interface ProfileChange {
    id: string;
    label: string;
    operation: string;
  }

  interface Profile {
    id: string;
    name: string;
    tone: 'danger' | 'safe' | 'info';
    subtitle: string;
    warning: string;
    changes: ProfileChange[];
    reversible: boolean;
  }

  const profiles: Profile[] = [
    {
      id: 'public',
      name: 'Public',
      tone: 'danger',
      subtitle: 'Exposition minimale sur un réseau non fiable',
      warning: 'Les services de découverte et la réponse Echo IPv4 pourront devenir indisponibles. La connexion Wi-Fi pourra être interrompue brièvement.',
      reversible: true,
      changes: [
        { id: 'firewall', label: 'Activer UFW avec connexions entrantes refusées et sortantes autorisées', operation: 'Ufw.ApplyPolicy(incoming="deny", outgoing="allow")' },
        { id: 'icmp4', label: 'Désactiver la réponse ICMP Echo IPv4', operation: 'Ipv4Echo.Set(enabled=false, persistent=true)' },
        { id: 'avahi', label: 'Arrêter et désactiver Avahi/mDNS', operation: 'SystemdUnitState(unit="avahi-daemon.service", action="stop-and-disable")' },
        { id: 'llmnr', label: 'Désactiver LLMNR dans systemd-resolved', operation: 'Resolved.SetLlmnr(enabled=false, persistent=true)' },
        { id: 'wifi-random', label: 'Utiliser une adresse MAC aléatoire sur tous les profils Wi-Fi', operation: 'NetworkManager.SetAllWifiMacMode(mode="random", futureConnections=true)' }
      ]
    },
    {
      id: 'home',
      name: 'Domicile',
      tone: 'safe',
      subtitle: 'Services locaux explicitement choisis',
      warning: 'Avahi sera démarré et activé si cette option reste cochée. Vérifiez qu’il est utile sur votre réseau domestique.',
      reversible: true,
      changes: [
        { id: 'firewall', label: 'Activer UFW avec connexions entrantes refusées par défaut', operation: 'Ufw.ApplyPolicy(incoming="deny", outgoing="allow")' },
        { id: 'avahi', label: 'Démarrer et activer Avahi/mDNS', operation: 'SystemdUnitState(unit="avahi-daemon.service", action="start-and-enable")' },
        { id: 'wifi-stable', label: 'Utiliser un pseudonyme MAC stable par réseau Wi-Fi', operation: 'NetworkManager.SetAllWifiMacMode(mode="stable", futureConnections=true)' }
      ]
    },
    {
      id: 'development',
      name: 'Développement',
      tone: 'info',
      subtitle: 'Environnement local et conteneurs maîtrisés',
      warning: "Ce profil garde un comportement réseau pratique pour le développement. Les publications Docker ne sont jamais recréées automatiquement.",
      reversible: true,
      changes: [
        { id: 'firewall', label: 'Activer UFW avec refus entrant par défaut', operation: 'Ufw.ApplyPolicy(incoming="deny", outgoing="allow")' },
        { id: 'icmp4-enable', label: 'Conserver les réponses ICMP Echo IPv4 pour le diagnostic', operation: 'Ipv4Echo.Set(enabled=true, persistent=true)' },
        { id: 'avahi', label: 'Démarrer et activer Avahi/mDNS pour la découverte locale', operation: 'SystemdUnitState(unit="avahi-daemon.service", action="start-and-enable")' },
        { id: 'wifi-stable', label: 'Utiliser un pseudonyme MAC stable par réseau Wi-Fi', operation: 'NetworkManager.SetAllWifiMacMode(mode="stable", futureConnections=true)' }
      ]
    },
    {
      id: 'restore',
      name: 'Réglages Ubuntu',
      tone: 'info',
      subtitle: 'Revenir aux valeurs d’installation Ubuntu des composants gérés',
      warning: "Réinitialisation importante : UFW sera remis à zéro et toutes ses règles, y compris les règles personnelles, seront supprimées. Les presets systemd fournisseur seront réappliqués. Dissimulation ne touche pas aux autres composants Ubuntu. La reconnexion Wi-Fi peut être interrompue brièvement.",
      reversible: false,
      changes: [
        { id: 'wifi-default', label: 'Retirer le défaut MAC Dissimulation et remettre les profils Wi-Fi sur le comportement NetworkManager non défini (« preserve » par défaut)', operation: 'NetworkManager.ClearOwnedMacDefaults(reconnect=true)' },
        { id: 'firewall-default', label: 'Réinitialiser complètement UFW : supprimer toutes ses règles, remettre deny entrant / allow sortant et le désactiver', operation: 'Ufw.ResetToInstallationDefaults(deleteAllRules=true)' },
        { id: 'icmp4-default', label: 'Retirer le fichier sysctl Dissimulation et réactiver ICMP Echo IPv4', operation: 'Ipv4Echo.RemoveOwnedOverride(default=true)' },
        { id: 'llmnr-default', label: 'Retirer la surcharge LLMNR créée par Dissimulation', operation: 'Resolved.RemoveOwnedLlmnrOverride()' },
        { id: 'services-default', label: 'Réappliquer les presets fournisseur systemd aux services réseau gérés, sans les démarrer ou arrêter immédiatement', operation: 'Systemd.RestoreVendorPresets(manageableUnitsOnly=true)' },
        { id: 'app-blocks', label: 'Supprimer la table nftables de blocage par application créée par Dissimulation', operation: 'Nftables.DeleteOwnedApplicationTable()' }
      ]
    }
  ];

  let selected: Record<string, boolean[]> = Object.fromEntries(
    profiles.map((profile) => [profile.id, profile.changes.map(() => true)])
  );
  let preview: PlannedAction | null = null;
  let appliedMessage: string | null = null;

  function toggleChange(profile: Profile, index: number, value: boolean) {
    selected = {
      ...selected,
      [profile.id]: selected[profile.id].map((current, position) => position === index ? value : current)
    };
  }

  function chosenChanges(profile: Profile): ProfileChange[] {
    return profile.changes.filter((_, index) => selected[profile.id][index]);
  }

  function plan(profile: Profile) {
    const changes = chosenChanges(profile);
    const exposed = snapshot.ports.filter((port) => port.exposure === 'allInterfaces' || port.exposure === 'specificInterface').length;
    preview = {
      id: `profile:${profile.id}`,
      title: profile.id === 'restore' ? 'Restaurer les réglages Ubuntu gérés' : `Activer le profil ${profile.name}`,
      target: `${changes.length} modification${changes.length > 1 ? 's' : ''} sélectionnée${changes.length > 1 ? 's' : ''}`,
      currentValue: `${exposed} port${exposed > 1 ? 's' : ''} potentiellement exposé${exposed > 1 ? 's' : ''} · UFW ${snapshot.firewall.status}`,
      newValue: profile.id === 'restore' ? `${changes.length} surcharge${changes.length > 1 ? 's' : ''} Dissimulation retirée${changes.length > 1 ? 's' : ''}` : `Profil ${profile.name} avec ${changes.length} option${changes.length > 1 ? 's' : ''}`,
      impact: profile.subtitle,
      warning: profile.warning,
      operations: changes.map((change) => change.operation),
      requiresAuthorization: true,
      reversible: profile.reversible,
      systemAction: {
        type: 'applyProfile',
        profile: profile.id as 'public' | 'home' | 'development' | 'restore',
        options: changes.map((change) => change.id)
      }
    };
  }

  async function confirmPreview() {
    if (!preview) return;
    const planned = preview;
    const outcome = await executeSystemAction(planned.systemAction);
    await onApplied(planned, outcome);
    appliedMessage = outcome.message;
    preview = null;
  }
</script>

<section aria-labelledby="profiles-title">
  <div class="page-heading"><div><p class="eyebrow">Configurations contrôlées</p><h2 id="profiles-title">Profils</h2><p>Personnalisez les options, examinez les opérations exactes puis appliquez le profil en une autorisation Polkit.</p></div><Badge tone="safe">Actions actives</Badge></div>
  <div class="notice info"><strong>Les options système sont actives</strong><p>Chaque profil utilise une liste fermée d'opérations. Les conteneurs ne sont jamais recréés et les réglages non sélectionnés restent intacts.</p></div>
  <article class="panel profile-comparison">
    <div class="panel-title"><div><p class="eyebrow">Différences principales</p><h3>Choisir le profil adapté</h3></div></div>
    <div class="table-wrap"><table><thead><tr><th>Profil</th><th>Usage</th><th>Découverte locale</th><th>Ping IPv4</th><th>MAC Wi-Fi</th><th>Pare-feu</th></tr></thead><tbody>
      <tr><td><strong>Public</strong></td><td>Wi-Fi inconnu, hôtel, gare</td><td>Avahi et LLMNR désactivés</td><td>Désactivé</td><td>Aléatoire à chaque connexion</td><td>UFW actif, entrant refusé</td></tr>
      <tr><td><strong>Domicile</strong></td><td>Réseau privé de confiance</td><td>Avahi activé</td><td>Inchangé</td><td>Pseudonyme stable par réseau</td><td>UFW actif, entrant refusé</td></tr>
      <tr><td><strong>Développement</strong></td><td>Diagnostic, services locaux, conteneurs</td><td>Avahi activé</td><td>Activé</td><td>Pseudonyme stable par réseau</td><td>UFW actif ; publications Docker inchangées</td></tr>
      <tr><td><strong>Réglages Ubuntu</strong></td><td>Réinitialiser les composants gérés</td><td>Surcharge retirée, presets fournisseur</td><td>Activé</td><td>Réglage explicite retiré</td><td>UFW entièrement remis à zéro et désactivé</td></tr>
    </tbody></table></div>
  </article>
  {#if appliedMessage}<div class="notice info" role="status"><strong>Profil appliqué</strong><p>{appliedMessage}</p></div>{/if}

  <div class="profile-grid">
    {#each profiles as profile}
      <article class="panel profile-card">
        <div class="profile-header"><span class="profile-icon {profile.tone}" aria-hidden="true">⬡</span><div><h3>{profile.name}</h3><p>{profile.subtitle}</p></div></div>
        <h4>Options du profil</h4>
        <ul class="profile-options">
          {#each profile.changes as change, index}<li><label><input type="checkbox" checked={selected[profile.id][index]} onchange={(event) => toggleChange(profile, index, event.currentTarget.checked)} /><span>{change.label}</span></label></li>{/each}
        </ul>
        <button class="secondary-button" disabled={chosenChanges(profile).length === 0} onclick={() => plan(profile)}>Examiner {chosenChanges(profile).length} option{chosenChanges(profile).length > 1 ? 's' : ''}</button>
      </article>
    {/each}
  </div>
</section>

{#if preview}<ActionPreview action={preview} onCancel={() => (preview = null)} onConfirm={confirmPreview} />{/if}
