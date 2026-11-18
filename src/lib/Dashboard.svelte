<script lang="ts">
  import Badge from './Badge.svelte';
  import { exposureLabels, macModeLabels, triState } from './labels';
  import type { NetworkSnapshot, Page } from './types';

  export let snapshot: NetworkSnapshot;
  export let navigate: (page: Page) => void;

  $: allInterfaces = snapshot.ports.filter((port) => port.exposure === 'allInterfaces').length;
  $: specificInterfaces = snapshot.ports.filter((port) => port.exposure === 'specificInterface').length;
  $: localOnly = snapshot.ports.filter((port) => port.exposure === 'localOnly').length;
</script>

<section aria-labelledby="overview-title">
  <div class="intro-row">
    <div>
      <p class="eyebrow">Vue d'ensemble</p>
      <h2 id="overview-title">Votre surface réseau, sans faux sentiment de sécurité</h2>
      <p>Une photographie des écoutes visibles sur cette machine. L'accessibilité réelle dépend aussi du réseau et de ses équipements.</p>
    </div>
    <div class="confidence-note"><span aria-hidden="true">◎</span><div><strong>Analyse locale</strong><small>Aucun trafic réseau généré</small></div></div>
  </div>

  <div class="stats-grid">
    <button class="stat-card" onclick={() => navigate('ports')}>
      <span class="stat-icon blue" aria-hidden="true">⇄</span><span><strong>{snapshot.ports.length}</strong><small>Ports en écoute</small></span><b aria-hidden="true">›</b>
    </button>
    <button class="stat-card" onclick={() => navigate('ports')}>
      <span class="stat-icon coral" aria-hidden="true">⌁</span><span><strong>{allInterfaces + specificInterfaces}</strong><small>Potentiellement exposés</small></span><b aria-hidden="true">›</b>
    </button>
    <button class="stat-card" onclick={() => navigate('ports')}>
      <span class="stat-icon green" aria-hidden="true">⌂</span><span><strong>{localOnly}</strong><small>Local uniquement</small></span><b aria-hidden="true">›</b>
    </button>
    <button class="stat-card" onclick={() => navigate('firewall')}>
      <span class="stat-icon violet" aria-hidden="true">⬡</span><span><strong class="word">{snapshot.firewall.status}</strong><small>Pare-feu UFW</small></span><b aria-hidden="true">›</b>
    </button>
  </div>

  <div class="dashboard-grid">
    <article class="panel alerts-panel">
      <div class="panel-title"><div><p class="eyebrow">À examiner</p><h3>Alertes importantes</h3></div><Badge tone={snapshot.alerts.some((alert) => alert.severity === 'important') ? 'danger' : 'safe'}>{snapshot.alerts.length}</Badge></div>
      <div class="alert-list">
        {#each snapshot.alerts as alert}
          <button class="alert-item {alert.severity}" onclick={() => navigate(alert.target)} aria-label={`${alert.title} — ouvrir ${alert.target}`}>
            <span class="alert-dot" aria-hidden="true"></span>
            <div><strong>{alert.title}</strong><p>{alert.message}</p></div>
            <span class="alert-arrow" aria-hidden="true">›</span>
          </button>
        {/each}
      </div>
      <button class="text-button" onclick={() => navigate('ports')}>Examiner les ports <span aria-hidden="true">→</span></button>
    </article>

    <article class="panel posture-panel">
      <div class="panel-title"><div><p class="eyebrow">État actuel</p><h3>Posture rapide</h3></div></div>
      <dl class="posture-list">
        <div><dt>Réponse ICMP Echo IPv4</dt><dd><Badge tone={snapshot.ping.ipv4Echo === false ? 'safe' : 'neutral'}>{triState(snapshot.ping.ipv4Echo, 'Répond', 'Ne répond pas')}</Badge></dd></div>
        <div><dt>Réponse ICMPv6 Echo</dt><dd><Badge tone="info">{triState(snapshot.ping.ipv6Echo, 'Répond', 'Ne répond pas')}</Badge></dd></div>
        <div><dt>Politique entrante UFW</dt><dd><Badge tone={snapshot.firewall.defaultIncoming === 'deny' ? 'safe' : 'warn'}>{snapshot.firewall.defaultIncoming ?? 'Inconnue'}</Badge></dd></div>
        <div><dt>Publications Docker</dt><dd><Badge tone={snapshot.dockerPorts.length ? 'warn' : 'safe'}>{snapshot.dockerPorts.length}</Badge></dd></div>
      </dl>
      <p class="microcopy">{snapshot.ping.note}</p>
    </article>
  </div>

  <article class="panel interfaces-preview">
    <div class="panel-title"><div><p class="eyebrow">Confidentialité du lien</p><h3>Interfaces réseau</h3></div><button class="text-button" onclick={() => navigate('interfaces')}>Voir tout →</button></div>
    <div class="interface-strip">
      {#each snapshot.interfaces.filter((item) => item.kind !== 'loopback').slice(0, 4) as item}
        <div class="interface-mini">
          <span class="interface-symbol" aria-hidden="true">{item.kind === 'wifi' ? '⌁' : item.kind === 'docker' ? '◇' : '↔'}</span>
          <div><strong>{item.name}</strong><small>{item.activeConnection ?? item.operstate}</small></div>
          <div class="align-right"><Badge tone={item.macMode === 'random' || item.macMode === 'stable' ? 'safe' : 'neutral'}>{macModeLabels[item.macMode]}</Badge><small>{item.addresses[0] ?? 'Sans adresse'}</small></div>
        </div>
      {:else}
        <p class="empty">Aucune interface réseau n'a pu être affichée.</p>
      {/each}
    </div>
  </article>

  <p class="legend-line"><strong>Lecture des niveaux :</strong> {exposureLabels.localOnly} · {exposureLabels.virtualNetwork} · {exposureLabels.specificInterface} · {exposureLabels.allInterfaces}</p>
</section>
