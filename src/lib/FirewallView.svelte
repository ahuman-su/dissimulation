<script lang="ts">
  import { isTauri } from '@tauri-apps/api/core';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { onMount } from 'svelte';
  import ActionPreview from './ActionPreview.svelte';
  import Badge from './Badge.svelte';
  import ProgressIndicator from './ProgressIndicator.svelte';
  import { executeSystemAction, inspectFirewallWithAuthorization } from './api';
  import { triState } from './labels';
  import type { ActionOutcome, ActionProgress, FirewallState, NetworkSnapshot, PlannedAction } from './types';

  export let snapshot: NetworkSnapshot;
  export let onApplied: (action: PlannedAction, outcome: ActionOutcome) => void | Promise<void>;

  let preview: PlannedAction | null = null;
  let appliedMessage: string | null = null;
  let authorizedFirewall: FirewallState | null = null;
  let readingFirewall = false;
  let firewallReadError: string | null = null;
  let firewallProgress: ActionProgress | null = null;

  $: firewall = authorizedFirewall ?? snapshot.firewall;

  $: sshDetected = snapshot.ports.some((port) => port.port === 22 || port.systemdService === 'ssh.service' || port.systemdService === 'sshd.service') || snapshot.services.some((service) => (service.unit === 'ssh.service' || service.unit === 'sshd.service') && service.activeState === 'active');

  function planFirewall() {
    preview = {
      id: 'ufw:default-deny-incoming',
      title: 'Appliquer la politique UFW recommandée',
      target: 'Pare-feu de l’hôte',
      currentValue: `UFW ${firewall.status} · entrant ${firewall.defaultIncoming ?? 'inconnu'} · sortant ${firewall.defaultOutgoing ?? 'inconnu'}`,
      newValue: 'UFW actif · entrant refusé · sortant autorisé',
      impact: 'Les nouvelles connexions entrantes non explicitement autorisées seront refusées.',
      warning: sshDetected
        ? 'Une écoute SSH active a été détectée. Une règle autorisant votre accès devra être confirmée avant activation pour éviter une perte de connexion.'
        : "Vérifiez les services locaux nécessaires avant l'application réelle.",
      operations: [
        'Ufw.SetDefault(direction="incoming", policy="deny")',
        'Ufw.SetDefault(direction="outgoing", policy="allow")',
        'Ufw.Enable(preserveConfirmedSsh=true)'
      ],
      requiresAuthorization: true,
      reversible: true,
      systemAction: { type: 'applyFirewallBaseline', preserveSsh: sshDetected }
    };
  }

  function planIpv4Echo() {
    if (snapshot.ping.ipv4Echo === null) return;
    const responds = snapshot.ping.ipv4Echo;
    preview = {
      id: `icmp4:${responds ? 'disable' : 'enable'}-echo`,
      title: `${responds ? 'Désactiver' : 'Activer'} les réponses ICMP Echo IPv4`,
      target: 'Paramètre noyau IPv4',
      currentValue: responds ? 'Répond aux requêtes Echo IPv4' : 'Ne répond pas aux requêtes Echo IPv4',
      newValue: responds ? 'Ne répondra plus aux requêtes Echo IPv4' : 'Répondra aux requêtes Echo IPv4',
      impact: responds
        ? 'Certains diagnostics réseau IPv4 deviendront moins pratiques.'
        : 'La machine répondra de nouveau aux diagnostics Echo IPv4.',
      warning: "Ce réglage ne bloque pas tout ICMP et ne rend pas la machine invisible. Il ne modifie pas ICMPv6.",
      operations: [`Ipv4Echo.Set(enabled=${!responds})`],
      requiresAuthorization: true,
      reversible: true,
      systemAction: { type: 'setIpv4Echo', enabled: !responds }
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

  async function readFirewallWithAuthorization() {
    readingFirewall = true;
    firewallReadError = null;
    firewallProgress = { operation: 'inspectFirewall', current: 0, total: 2, label: "En attente de l’autorisation Ubuntu" };
    try {
      authorizedFirewall = await inspectFirewallWithAuthorization();
    } catch (reason) {
      firewallReadError = reason instanceof Error ? reason.message : String(reason);
    } finally {
      readingFirewall = false;
    }
  }

  onMount(() => {
    let unlisten: UnlistenFn | null = null;
    let disposed = false;
    if (isTauri()) {
      void listen<ActionProgress>('system-action-progress', (event) => {
        if (readingFirewall && event.payload.operation === 'inspectFirewall') firewallProgress = event.payload;
      }).then((registered) => {
        if (disposed) registered();
        else unlisten = registered;
      });
    }
    return () => {
      disposed = true;
      unlisten?.();
    };
  });
</script>

<section aria-labelledby="firewall-title">
  <div class="page-heading"><div><p class="eyebrow">Filtrage de l'hôte</p><h2 id="firewall-title">Pare-feu et ping</h2><p>Examinez les changements puis appliquez-les avec une autorisation Polkit ponctuelle.</p></div><Badge tone={firewall.enabled === true ? 'safe' : firewall.enabled === false ? 'danger' : 'warn'}>{firewall.status}</Badge></div>

  {#if firewall.warning}<div class="notice warning"><strong>Configuration à vérifier</strong><p>{firewall.warning}</p></div>{/if}
  {#if firewallReadError}<div class="notice danger" role="alert"><strong>Lecture privilégiée impossible</strong><p>{firewallReadError}</p></div>{/if}
  {#if appliedMessage}<div class="notice info" role="status"><strong>Modification appliquée</strong><p>{appliedMessage}</p></div>{/if}

  <div class="firewall-grid">
    <article class="panel">
      <div class="panel-title"><div><p class="eyebrow">UFW</p><h3>Politique générale</h3></div><span class="big-status {firewall.enabled === true ? 'on' : ''}" aria-hidden="true">⬡</span></div>
      <dl class="detail-list">
        <div><dt>Installé</dt><dd>{firewall.installed ? 'Oui' : 'Non'}</dd></div>
        <div><dt>État</dt><dd>{firewall.status}</dd></div>
        <div><dt>Connexions entrantes</dt><dd><Badge tone={firewall.defaultIncoming === 'deny' ? 'safe' : 'warn'}>{firewall.defaultIncoming ?? 'Inconnu'}</Badge></dd></div>
        <div><dt>Connexions sortantes</dt><dd>{firewall.defaultOutgoing ?? 'Inconnu'}</dd></div>
        <div><dt>nftables natif</dt><dd>{firewall.nativeNftablesDetected ? 'Service actif' : 'Non détecté'}</dd></div>
      </dl>
      <button class="primary-button" disabled={!firewall.installed || firewall.nativeNftablesDetected} title={firewall.nativeNftablesDetected ? 'Action bloquée pour ne pas mélanger automatiquement UFW et nftables' : undefined} onclick={planFirewall}>Prévisualiser « refuser entrant, autoriser sortant »</button>
      <p class="microcopy">{sshDetected ? 'SSH détecté : sa préservation sera exigée dans la confirmation.' : 'Aucune écoute SSH active visible dans cet instantané.'}</p>
    </article>

    <article class="panel">
      <div class="panel-title"><div><p class="eyebrow">Diagnostic réseau</p><h3>Réponses aux requêtes Echo</h3></div></div>
      <div class="ping-row"><span class="ip-chip">4</span><div><strong>ICMP Echo IPv4</strong><p>Réponses aux demandes d'écho classiques.</p></div><Badge tone={snapshot.ping.ipv4Echo === false ? 'safe' : 'neutral'}>{triState(snapshot.ping.ipv4Echo, 'Répond', 'Ne répond pas')}</Badge></div>
      <div class="ping-row"><span class="ip-chip six">6</span><div><strong>ICMPv6 Echo</strong><p>Echo uniquement ; les messages IPv6 essentiels doivent être préservés.</p></div><Badge tone="info">{triState(snapshot.ping.ipv6Echo, 'Répond', 'Ne répond pas')}</Badge></div>
      <div class="notice info compact-notice"><strong>Trois notions différentes</strong><p>Ne pas répondre au ping n'est pas bloquer tout ICMP et ne rend pas la machine invisible.</p></div>
      <button class="secondary-button" disabled={snapshot.ping.ipv4Echo === null} onclick={planIpv4Echo}>{snapshot.ping.ipv4Echo === false ? 'Prévisualiser la réactivation IPv4' : 'Prévisualiser la désactivation IPv4'}</button>
    </article>
  </div>

  <article class="panel rules-panel">
    <div class="panel-title"><div><p class="eyebrow">Règles actives</p><h3>Autorisations UFW visibles</h3></div><div class="panel-actions"><Badge tone="neutral">{firewall.rules.length}</Badge><button class="secondary-button" onclick={readFirewallWithAuthorization} disabled={readingFirewall}>{readingFirewall ? 'Autorisation…' : 'Lire avec autorisation'}</button></div></div>
    {#if firewallProgress}<ProgressIndicator progress={firewallProgress} ariaLabel="Progression de la lecture UFW" />{/if}
    <div class="table-wrap">
      <table><thead><tr><th>Service ou port</th><th>Action</th><th>Source</th><th>Famille</th></tr></thead><tbody>
        {#each firewall.rules as rule}<tr><td><strong>{rule.target}</strong></td><td><Badge tone={rule.action.toLowerCase().includes('allow') ? 'warn' : 'safe'}>{rule.action}</Badge></td><td class="mono">{rule.source}</td><td>{rule.ipVersion ?? 'Inconnue'}</td></tr>{:else}<tr><td colspan="4" class="empty">Aucune règle UFW active n'a été renvoyée. Utilisez « Lire avec autorisation » si l'état normal est limité.</td></tr>{/each}
      </tbody></table>
    </div>
  </article>
</section>

{#if preview}<ActionPreview action={preview} onCancel={() => (preview = null)} onConfirm={confirmPreview} />{/if}
