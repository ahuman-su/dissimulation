<script lang="ts">
  import ActionPreview from './ActionPreview.svelte';
  import Badge from './Badge.svelte';
  import { executeSystemAction } from './api';
  import type { ActionOutcome, NetworkSnapshot, PlannedAction, ServiceInfo } from './types';

  export let snapshot: NetworkSnapshot;
  export let onApplied: (action: PlannedAction, outcome: ActionOutcome) => void | Promise<void>;
  export let onRefresh: () => Promise<void>;

  let preview: PlannedAction | null = null;
  let appliedMessage: string | null = null;
  let refreshing = false;

  type ServiceAction = 'start' | 'stop' | 'enable' | 'disable';

  const labels: Record<ServiceAction, string> = {
    start: 'Démarrer',
    stop: 'Arrêter',
    enable: 'Activer au démarrage',
    disable: 'Désactiver au démarrage'
  };

  function plan(service: ServiceInfo, action: ServiceAction) {
    const changesRuntime = action === 'start' || action === 'stop';
    const next = action === 'start' || action === 'enable' ? 'activé' : 'désactivé';
    const current = changesRuntime
      ? service.activeState
      : service.enabled === null
        ? 'démarrage inconnu'
        : service.enabled
          ? 'démarrage automatique activé'
          : 'démarrage automatique désactivé';
    preview = {
      id: `systemd:${action}:${service.unit}`,
      title: `${labels[action]} ${service.description ?? service.unit}`,
      target: `Unité systemd : ${service.unit}`,
      currentValue: current,
      newValue: changesRuntime ? next : `démarrage automatique ${next}`,
      impact: changesRuntime
        ? "L'état du service changera immédiatement et peut modifier l'exposition réseau."
        : "Le comportement de l'unité lors des prochaines ouvertures de session ou démarrages sera modifié.",
      warning:
        action === 'stop' || action === 'disable'
          ? "L'arrêt d'un service peut interrompre une fonction réseau attendue. L'unité sera refusée si elle est protégée."
          : null,
      operations: [`SystemdUnitState(unit="${service.unit}", action="${action}")`],
      requiresAuthorization: true,
      reversible: true,
      systemAction: { type: 'manageService', unit: service.unit, action }
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

  async function refresh() {
    refreshing = true;
    try {
      await onRefresh();
    } finally {
      refreshing = false;
    }
  }
</script>

<section aria-labelledby="services-title">
  <div class="page-heading"><div><p class="eyebrow">Inventaire systemd dynamique</p><h2 id="services-title">Services réseau</h2><p>Les services installés connus et les unités associées aux ports sont redétectés à chaque analyse.</p></div><button class="secondary-button" onclick={refresh} disabled={refreshing}>{refreshing ? 'Actualisation…' : 'Actualiser les services'}</button></div>

  {#if appliedMessage}<div class="notice info" role="status"><strong>Modification appliquée</strong><p>{appliedMessage}</p></div>{/if}

  <div class="card-list">
    {#each snapshot.services as service}
      <article class="service-card">
        <div class="service-main"><span class="service-symbol" aria-hidden="true">◇</span><div><h3>{service.description ?? service.unit}</h3><code>{service.unit}</code>{#if service.purpose}<p class="service-purpose">{service.purpose}</p>{/if}</div></div>
        <div class="service-state"><Badge tone={service.activeState === 'active' ? 'safe' : 'neutral'}>{service.activeState}</Badge><span>Démarrage : {service.enabled === null ? 'inconnu' : service.enabled ? 'activé' : 'désactivé'}</span>{#if service.protected}<Badge tone="warn">Unité protégée</Badge>{:else if !service.manageable}<Badge tone="neutral">Observation seule</Badge>{/if}</div>
        <div class="disabled-actions" aria-label={`Actions pour ${service.unit}`}>
          <button disabled={service.activeState === 'active' || !service.manageable} onclick={() => plan(service, 'start')}>Démarrer</button>
          <button disabled={service.activeState !== 'active' || service.protected || !service.manageable} title={service.protected ? 'Action refusée pour une unité essentielle' : undefined} onclick={() => plan(service, 'stop')}>Arrêter</button>
          <button disabled={service.enabled === true || !service.manageable} onclick={() => plan(service, 'enable')}>Activer</button>
          <button disabled={service.enabled === false || service.protected || !service.manageable} title={service.protected ? 'Action refusée pour une unité essentielle' : undefined} onclick={() => plan(service, 'disable')}>Désactiver</button>
        </div>
      </article>
    {:else}
      <div class="panel empty-state"><span aria-hidden="true">◇</span><h3>Aucun service réseau détecté</h3><p>Lancez une nouvelle analyse après l'installation ou l'activation d'un service.</p></div>
    {/each}
  </div>

  <div class="section-heading"><div><p class="eyebrow">Présence sur le réseau local</p><h3>Mécanismes de découverte</h3></div></div>
  <div class="discovery-grid">
    {#each snapshot.discovery as service}
      <article class="panel discovery-card"><div class="panel-title"><h3>{service.name}</h3><Badge tone={service.active === true ? 'info' : service.active === false ? 'neutral' : 'warn'}>{service.active === null ? 'Inconnu' : service.active ? 'Actif' : 'Inactif'}</Badge></div><p>{service.description}</p><small>{service.units.join(' · ')}</small></article>
    {/each}
  </div>
  <div class="notice info"><strong>Descriptions factuelles</strong><p>Les résumés expliquent le rôle général du logiciel à partir de références encyclopédiques. L'exposition réelle dépend toujours des ports, adresses d'écoute et règles du pare-feu.</p></div>
</section>

{#if preview}<ActionPreview action={preview} onCancel={() => (preview = null)} onConfirm={confirmPreview} />{/if}
