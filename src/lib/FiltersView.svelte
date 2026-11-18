<script lang="ts">
  import { onMount } from 'svelte';
  import ActionPreview from './ActionPreview.svelte';
  import Badge from './Badge.svelte';
  import ProgressIndicator from './ProgressIndicator.svelte';
  import { addBlockRule, getBlockRules, removeBlockRule, resolveFilterTarget } from './api';
  import type { ActionOutcome, ActionProgress, BlockRule, NetworkSnapshot, PlannedAction } from './types';

  export let snapshot: NetworkSnapshot;
  export let onChanged: (outcome: ActionOutcome, title: string) => void | Promise<void>;

  let rules: BlockRule[] = [];
  let name = '';
  let direction: BlockRule['direction'] = 'outgoing';
  let protocol: BlockRule['protocol'] = 'tcp';
  let remoteAddress = 'any';
  let port = 443;
  let acknowledgeBroad = false;
  let preview: PlannedAction | null = null;
  let pendingRule: BlockRule | null = null;
  let success: string | null = null;
  let loadError: string | null = null;
  let resolving = false;
  const resolutionProgress: ActionProgress = {
    operation: 'resolveFilterTarget',
    current: 0,
    total: 0,
    label: 'Résolution de la cible avec le DNS système'
  };

  $: blockedByFirewall = !snapshot.firewall.installed || snapshot.firewall.enabled !== true || snapshot.firewall.nativeNftablesDetected;
  $: broad = remoteAddress.trim() === 'any';
  $: formValid = name.trim().length > 0 && name.trim().length <= 80 && port >= 1 && port <= 65535 && (!broad || acknowledgeBroad);

  function newId(): string {
    return globalThis.crypto?.randomUUID?.() ?? `rule-${Date.now()}-${Math.floor(Math.random() * 1_000_000)}`;
  }

  async function loadRules() {
    try {
      rules = await getBlockRules();
      loadError = null;
    } catch (reason) {
      loadError = reason instanceof Error ? reason.message : String(reason);
    }
  }

  async function planAdd() {
    resolving = true;
    loadError = null;
    try {
      const resolved = await resolveFilterTarget(remoteAddress, port);
      const rule: BlockRule = {
        id: newId(),
        name: name.trim(),
        direction,
        protocol,
        remoteAddress: resolved.normalizedTarget,
        port,
        resolvedAddresses: resolved.kind === 'domain' ? resolved.addresses : []
      };
      pendingRule = rule;
      const domainWarning = resolved.kind === 'domain'
        ? `${resolved.detail} Le DNS chiffré ou ECH n’empêche pas cette règle : UFW bloque les IP résolues, pas le contenu HTTPS.`
        : null;
      preview = {
        id: `filter:add:${rule.id}`,
        title: `Ajouter le filtre « ${rule.name} »`,
        target: `UFW · trafic ${direction === 'incoming' ? 'entrant' : 'sortant'}`,
        currentValue: 'Trafic non bloqué par cette règle',
        newValue: resolved.kind === 'domain'
          ? `${protocol.toUpperCase()} ${resolved.normalizedTarget}:${port} bloqué sur ${resolved.addresses.join(', ')}`
          : `${protocol.toUpperCase()} ${resolved.normalizedTarget}:${port} bloqué`,
        impact: 'Les nouveaux paquets correspondant à la direction, au protocole, aux adresses résolues et au port seront refusés par UFW.',
        warning: broad ? 'La cible « any » est large et peut interrompre toutes les communications correspondantes à ce port.' : domainWarning,
        operations: resolved.kind === 'domain'
          ? resolved.addresses.map((address) => `Ufw.Deny(direction="${direction}", protocol="${protocol}", remote="${address}", port=${port}, domain="${resolved.normalizedTarget}", id="${rule.id}")`)
          : [`Ufw.Deny(direction="${direction}", protocol="${protocol}", remote="${resolved.normalizedTarget}", port=${port}, id="${rule.id}")`],
        requiresAuthorization: true,
        reversible: true,
        systemAction: { type: 'addBlockRule', rule }
      };
    } catch (reason) {
      loadError = reason instanceof Error ? reason.message : String(reason);
    } finally {
      resolving = false;
    }
  }

  function planRemove(rule: BlockRule) {
    pendingRule = null;
    preview = {
      id: `filter:remove:${rule.id}`,
      title: `Supprimer le filtre « ${rule.name} »`,
      target: `Règle UFW marquée Dissimulation:${rule.id}`,
      currentValue: `${rule.protocol.toUpperCase()} ${rule.remoteAddress}:${rule.port} bloqué`,
      newValue: 'Filtre Dissimulation absent',
      impact: 'Le trafic correspondant ne sera plus bloqué par cette règle. Les autres règles UFW restent intactes.',
      warning: null,
      operations: [`Ufw.DeleteOwnedRule(id="${rule.id}")`],
      requiresAuthorization: true,
      reversible: true,
      systemAction: { type: 'removeBlockRule', ruleId: rule.id }
    };
  }

  async function confirmPreview() {
    if (!preview) return;
    const planned = preview;
    const outcome = pendingRule
      ? await addBlockRule(pendingRule)
      : await removeBlockRule((planned.systemAction as { type: 'removeBlockRule'; ruleId: string }).ruleId);
    await loadRules();
    await onChanged(outcome, planned.title);
    success = outcome.message;
    if (pendingRule) {
      name = '';
      acknowledgeBroad = false;
    }
    pendingRule = null;
    preview = null;
  }

  onMount(() => void loadRules());
</script>

<section aria-labelledby="filters-title">
  <div class="page-heading"><div><p class="eyebrow">Blocage UFW structuré</p><h2 id="filters-title">Filtres de blocage</h2><p>Bloquez un flux par direction, protocole, adresse IP ou CIDR distant et port, sans accepter de commande libre.</p></div><Badge tone={blockedByFirewall ? 'warn' : 'safe'}>{blockedByFirewall ? 'Indisponible' : 'Actif'}</Badge></div>

  <div class="notice warning"><strong>Un domaine est résolu, pas lu dans le contenu HTTPS</strong><p>Les noms de domaine sont maintenant acceptés : Dissimulation les résout avec le DNS système puis bloque les adresses IP obtenues. Une règle ne suit pas automatiquement les futurs changements DNS, CDN ou équilibrage de charge. Le contenu HTTPS reste chiffré et ECH peut aussi masquer le nom TLS.</p></div>
  {#if snapshot.firewall.nativeNftablesDetected}<div class="notice danger"><strong>nftables natif détecté</strong><p>Dissimulation refuse d'ajouter automatiquement des règles UFW afin de ne pas mélanger deux gestionnaires.</p></div>{/if}
  {#if snapshot.firewall.enabled !== true && !snapshot.firewall.nativeNftablesDetected}<div class="notice warning"><strong>UFW doit être actif</strong><p>Appliquez d'abord la politique générale dans la page Pare-feu ; une règle enregistrée dans un pare-feu inactif ne bloquerait rien.</p></div>{/if}
  {#if loadError}<div class="notice danger" role="alert"><strong>Registre indisponible</strong><p>{loadError}</p></div>{/if}
  {#if success}<div class="notice info" role="status"><strong>Filtre mis à jour</strong><p>{success}</p></div>{/if}

  <div class="filter-layout">
    <article class="panel filter-editor">
      <div class="panel-title"><div><p class="eyebrow">Nouvelle règle</p><h3>Définir le trafic à refuser</h3></div></div>
      <div class="form-grid">
        <label><span>Nom</span><input bind:value={name} maxlength="80" placeholder="Bloquer l’API de test" /></label>
        <label><span>Direction</span><select bind:value={direction}><option value="outgoing">Sortant</option><option value="incoming">Entrant</option></select></label>
        <label><span>Protocole</span><select bind:value={protocol}><option value="tcp">TCP</option><option value="udp">UDP</option><option value="any">TCP et UDP</option></select></label>
        <label><span>Domaine, IP ou CIDR distant</span><input bind:value={remoteAddress} placeholder="example.org, 203.0.113.0/24 ou any" /></label>
        <label><span>Port</span><input type="number" bind:value={port} min="1" max="65535" /></label>
      </div>
      {#if broad}<label class="acknowledge"><input type="checkbox" bind:checked={acknowledgeBroad} /><span>Je confirme que « any » bloque toutes les adresses pour ce port et cette direction.</span></label>{/if}
      <button class="primary-button" disabled={!formValid || blockedByFirewall || resolving} onclick={() => void planAdd()}>{resolving ? 'Résolution DNS…' : 'Examiner la règle'}</button>
      {#if resolving}<ProgressIndicator progress={resolutionProgress} ariaLabel="Résolution DNS de la cible" />{/if}
    </article>

    <article class="panel">
      <div class="panel-title"><div><p class="eyebrow">Règles possédées</p><h3>Filtres Dissimulation</h3></div><Badge tone="neutral">{rules.length}</Badge></div>
      <div class="owned-rule-list">{#each rules as rule}<div><div><strong>{rule.name}</strong><p>{rule.direction === 'incoming' ? 'Entrant' : 'Sortant'} · {rule.protocol.toUpperCase()} · <span class="mono">{rule.remoteAddress}:{rule.port}</span>{#if rule.resolvedAddresses.length}<small>IP bloquées : {rule.resolvedAddresses.join(' · ')}</small>{/if}</p></div><button class="danger-button small" onclick={() => planRemove(rule)}>Supprimer</button></div>{:else}<p class="empty-inline">Aucun filtre ajouté par Dissimulation.</p>{/each}</div>
    </article>
  </div>
</section>

{#if preview}<ActionPreview action={preview} onCancel={() => { preview = null; pendingRule = null; }} onConfirm={confirmPreview} />{/if}
