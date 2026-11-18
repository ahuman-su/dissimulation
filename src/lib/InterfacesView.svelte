<script lang="ts">
  import ActionPreview from './ActionPreview.svelte';
  import Badge from './Badge.svelte';
  import { executeSystemAction } from './api';
  import { interfaceLabels, macModeLabels } from './labels';
  import type { ActionOutcome, MacMode, NetworkInterface, NetworkSnapshot, PlannedAction } from './types';

  export let snapshot: NetworkSnapshot;
  export let onApplied: (action: PlannedAction, outcome: ActionOutcome) => void | Promise<void>;

  let preview: PlannedAction | null = null;
  let appliedMessage: string | null = null;
  let selectedModes: Record<string, MacMode> = {};

  function selectedMode(item: NetworkInterface): MacMode {
    const selected = selectedModes[item.name] ?? item.macMode;
    return selected === 'unknown' ? 'preserve' : selected;
  }

  function changeMode(interfaceName: string, mode: MacMode) {
    selectedModes = { ...selectedModes, [interfaceName]: mode };
  }

  function plan(item: NetworkInterface) {
    const mode = selectedMode(item);
    preview = {
      id: `mac:${item.name}:${mode}`,
      title: `Définir le mode MAC Wi-Fi « ${macModeLabels[mode]} »`,
      target: `Profil Wi-Fi actif et futurs réseaux · reconnexion de ${item.name}`,
      currentValue: macModeLabels[item.macMode],
      newValue: macModeLabels[mode],
      impact: "NetworkManager enregistrera ce mode dans le profil actuellement connecté et comme défaut persistant des prochains réseaux, puis reconnectera cette interface. Les autres profils existants restent inchangés.",
      warning: "La connexion peut être interrompue momentanément. DHCP, portails captifs et contrôles d'accès basés sur la MAC peuvent être perturbés.",
      operations: [
        `NetworkManager.SetActiveWifiProfile(mode="${mode}", persistent=true)`,
        `NetworkManager.SetDefaultForFutureWifi(mode="${mode}")`,
        `NetworkManager.Reconnect(interface="${item.name}", confirmation=true)`
      ],
      requiresAuthorization: true,
      reversible: true,
      systemAction: { type: 'setMacMode', interface: item.name, mode }
    };
  }

  async function confirmPreview() {
    if (!preview) return;
    const action = preview;
    const outcome = await executeSystemAction(action.systemAction);
    await onApplied(action, outcome);
    appliedMessage = outcome.message;
    preview = null;
  }
</script>

<section aria-labelledby="interfaces-title">
  <div class="page-heading"><div><p class="eyebrow">NetworkManager et noyau</p><h2 id="interfaces-title">Interfaces réseau</h2><p>Le choix écrase la valeur du profil Wi-Fi actuellement connecté, persiste après redémarrage et devient le défaut des futurs réseaux. Les autres profils existants ne sont pas modifiés.</p></div><Badge tone="safe">Choix persistants</Badge></div>
  <div class="notice warning"><strong>Une modification de MAC peut couper momentanément le réseau</strong><p>Une reconnexion peut être nécessaire. DHCP, portails captifs et règles d'accès basées sur la MAC peuvent être perturbés.</p></div>
  {#if appliedMessage}<div class="notice info" role="status"><strong>Modification appliquée</strong><p>{appliedMessage}</p></div>{/if}

  <div class="interface-cards">
    {#each snapshot.interfaces as item}
      <article class="panel interface-card">
        <div class="panel-title"><div class="service-main"><span class="service-symbol" aria-hidden="true">{item.kind === 'wifi' ? '⌁' : item.kind === 'loopback' ? '↻' : '↔'}</span><div><h3>{item.name}</h3><span>{interfaceLabels[item.kind]}</span></div></div><Badge tone={item.operstate === 'up' ? 'safe' : 'neutral'}>{item.operstate}</Badge></div>
        <dl class="detail-list compact">
          <div><dt>Connexion active</dt><dd>{item.activeConnection ?? 'Aucune'}</dd></div>
          <div><dt>Adresse matérielle</dt><dd class="mono">{item.hardwareMac ?? 'Indisponible'}</dd></div>
          <div><dt>Adresse utilisée</dt><dd class="mono">{item.currentMac ?? 'Indisponible'}</dd></div>
          <div><dt>Randomisation</dt><dd><Badge tone={item.macMode === 'stable' || item.macMode === 'random' ? 'safe' : 'neutral'}>{macModeLabels[item.macMode]}</Badge></dd></div>
        </dl>
        <div class="address-list"><span>Adresses</span>{#each item.addresses as address}<code>{address}</code>{:else}<small>Aucune adresse détectée</small>{/each}</div>
        {#if item.eligibleForRandomization}
          <div class="inline-action-control">
            <label><span>Mode souhaité</span><select value={selectedMode(item)} onchange={(event) => changeMode(item.name, event.currentTarget.value as MacMode)}><option value="hardware">Adresse matérielle</option><option value="stable">Pseudonyme stable par réseau</option><option value="random">Adresse aléatoire</option><option value="preserve">Ne pas modifier</option></select></label>
            <button class="primary-button" onclick={() => plan(item)}>{selectedMode(item) === item.macMode ? 'Réappliquer' : 'Enregistrer et appliquer'}</button>
          </div>
        {:else}<p class="microcopy">La randomisation n'est pas proposée pour cette interface {item.kind === 'loopback' || item.kind === 'docker' || item.kind === 'virtual' ? 'virtuelle ou interne' : 'non reconnue'}.</p>{/if}
      </article>
    {/each}
  </div>
</section>

{#if preview}<ActionPreview action={preview} onCancel={() => (preview = null)} onConfirm={confirmPreview} />{/if}
