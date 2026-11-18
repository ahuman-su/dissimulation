<script lang="ts">
  import { isTauri } from '@tauri-apps/api/core';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { onMount } from 'svelte';
  import {
    blockApplicationNetwork,
    getApplicationTrafficHistory,
    getNetworkApplications,
    sampleApplicationTraffic,
    unblockApplicationNetwork
  } from './api';
  import Badge from './Badge.svelte';
  import ProgressIndicator from './ProgressIndicator.svelte';
  import type {
    ActionProgress,
    ApplicationTrafficBucket,
    ApplicationTrafficHistory,
    NetworkApplication,
    NetworkApplicationInventory,
    NetworkSnapshot
  } from './types';

  export let snapshot: NetworkSnapshot;

  interface ApplicationTotal {
    id: string;
    name: string;
    packets: number;
    bytes: number;
  }

  interface TimelinePoint {
    key: string;
    timestamp: number;
    values: Record<string, number>;
    total: number;
  }

  const colors = ['#39d98a', '#62b7ff', '#c59cff', '#ffb454', '#ff746c'];
  let rangeDays = 1;
  let trafficDirection: 'sent' | 'received' | 'total' = 'sent';
  let captureInterface = 'any';
  let history: ApplicationTrafficHistory | null = null;
  let inventory: NetworkApplicationInventory | null = null;
  let loading = true;
  let sampling = false;
  let busyRule: string | null = null;
  let actionProgress: ActionProgress | null = null;
  let message: { tone: 'info' | 'warning' | 'danger'; title: string; detail: string } | null = null;
  const historyProgress: ActionProgress = {
    operation: 'loadApplicationTraffic',
    current: 0,
    total: 0,
    label: "Lecture de l'historique et des applications réseau"
  };
  const sampleProgress: ActionProgress = {
    operation: 'sampleApplicationTraffic',
    current: 0,
    total: 0,
    label: 'Échantillonnage TShark et attribution aux applications'
  };

  $: applicationTotals = buildApplicationTotals(history?.entries ?? [], trafficDirection);
  $: unattributedPackets = applicationTotals.find((application) => application.id === '__unattributed__')?.packets ?? 0;
  $: topApplications = applicationTotals.filter((application) => application.id !== '__unattributed__').slice(0, 5);
  $: timeline = buildTimeline(history?.entries ?? [], rangeDays, topApplications, trafficDirection);
  $: timelineMaximum = Math.max(1, ...timeline.map((point) => point.total));
  $: applicationMaximum = Math.max(1, ...topApplications.map((application) => application.packets));

  function packetValue(entry: ApplicationTrafficBucket, direction: 'sent' | 'received' | 'total') {
    if (direction === 'sent') return entry.packetsSent;
    if (direction === 'received') return entry.packetsReceived;
    return entry.packetsSent + entry.packetsReceived;
  }

  function buildApplicationTotals(entries: ApplicationTrafficBucket[], direction: 'sent' | 'received' | 'total'): ApplicationTotal[] {
    const totals = new Map<string, ApplicationTotal>();
    for (const entry of entries) {
      const current = totals.get(entry.applicationId) ?? {
        id: entry.applicationId,
        name: entry.applicationName,
        packets: 0,
        bytes: 0
      };
      current.packets += packetValue(entry, direction);
      current.bytes += direction === 'sent' ? entry.bytesSent : direction === 'received' ? entry.bytesReceived : entry.bytesSent + entry.bytesReceived;
      totals.set(entry.applicationId, current);
    }
    return [...totals.values()].sort((left, right) => right.packets - left.packets);
  }

  function buildTimeline(
    entries: ApplicationTrafficBucket[],
    days: number,
    applications: ApplicationTotal[],
    direction: 'sent' | 'received' | 'total'
  ): TimelinePoint[] {
    const selected = new Set(applications.map((application) => application.id));
    const points = new Map<string, TimelinePoint>();
    for (const entry of entries) {
      if (!selected.has(entry.applicationId)) continue;
      const date = new Date(entry.bucketStartEpochMs);
      const key = days === 1
        ? `${date.getFullYear()}-${date.getMonth()}-${date.getDate()}-${date.getHours()}`
        : `${date.getFullYear()}-${date.getMonth()}-${date.getDate()}`;
      const timestamp = days === 1
        ? new Date(date.getFullYear(), date.getMonth(), date.getDate(), date.getHours()).getTime()
        : new Date(date.getFullYear(), date.getMonth(), date.getDate()).getTime();
      const point = points.get(key) ?? { key, timestamp, values: {}, total: 0 };
      const packets = packetValue(entry, direction);
      point.values[entry.applicationId] = (point.values[entry.applicationId] ?? 0) + packets;
      point.total += packets;
      points.set(key, point);
    }
    return [...points.values()].sort((left, right) => left.timestamp - right.timestamp);
  }

  function timelineLabel(timestamp: number) {
    const date = new Date(timestamp);
    return rangeDays === 1
      ? date.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' })
      : date.toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit' });
  }

  function formatBytes(bytes: number) {
    if (bytes >= 1_000_000) return `${(bytes / 1_000_000).toFixed(1)} Mo`;
    if (bytes >= 1_000) return `${(bytes / 1_000).toFixed(1)} ko`;
    return `${bytes} o`;
  }

  async function load(silent = false) {
    if (!silent) loading = true;
    try {
      [history, inventory] = await Promise.all([
        getApplicationTrafficHistory(rangeDays),
        getNetworkApplications()
      ]);
      if (message?.tone === 'danger') message = null;
    } catch (reason) {
      message = {
        tone: 'danger',
        title: 'Analyse par application indisponible',
        detail: reason instanceof Error ? reason.message : String(reason)
      };
    } finally {
      loading = false;
    }
  }

  async function changeRange(days: number) {
    rangeDays = days;
    await load();
  }

  async function sampleNow() {
    sampling = true;
    message = null;
    try {
      const result = await sampleApplicationTraffic(captureInterface);
      message = {
        tone: result.available ? 'info' : 'warning',
        title: result.available ? 'Échantillon enregistré' : 'Capture indisponible',
        detail: result.detail
      };
      history = await getApplicationTrafficHistory(rangeDays);
      inventory = await getNetworkApplications();
    } catch (reason) {
      message = {
        tone: 'danger',
        title: "Échec de l'échantillon",
        detail: reason instanceof Error ? reason.message : String(reason)
      };
    } finally {
      sampling = false;
    }
  }

  async function block(application: NetworkApplication) {
    const accepted = window.confirm(
      `Couper Internet pour « ${application.name} » ?\n\nTous les flux TCP/UDP du cgroup affiché seront rejetés, y compris HTTPS et QUIC chiffrés ainsi que les autres processus de ce même groupe. Une autorisation Polkit sera demandée.`
    );
    if (!accepted) return;
    busyRule = application.id;
    actionProgress = { operation: 'blockApplicationNetwork', current: 0, total: 2, label: "En attente de l’autorisation Ubuntu" };
    try {
      const outcome = await blockApplicationNetwork(application.pid, application.processStartTime);
      message = { tone: 'info', title: outcome.title, detail: outcome.message };
      actionProgress = { operation: 'blockApplicationNetwork', current: 0, total: 0, label: 'Actualisation de la liste des applications' };
      inventory = await getNetworkApplications();
    } catch (reason) {
      message = {
        tone: 'danger',
        title: 'Blocage refusé',
        detail: reason instanceof Error ? reason.message : String(reason)
      };
    } finally {
      busyRule = null;
    }
  }

  async function unblock(ruleId: string) {
    busyRule = ruleId;
    actionProgress = { operation: 'unblockApplicationNetwork', current: 0, total: 2, label: "En attente de l’autorisation Ubuntu" };
    try {
      const outcome = await unblockApplicationNetwork(ruleId);
      message = { tone: 'info', title: outcome.title, detail: outcome.message };
      actionProgress = { operation: 'unblockApplicationNetwork', current: 0, total: 0, label: 'Actualisation de la liste des applications' };
      inventory = await getNetworkApplications();
    } catch (reason) {
      message = {
        tone: 'danger',
        title: 'Rétablissement impossible',
        detail: reason instanceof Error ? reason.message : String(reason)
      };
    } finally {
      busyRule = null;
    }
  }

  onMount(() => {
    let unlisten: UnlistenFn | null = null;
    let disposed = false;
    if (isTauri()) {
      void listen<ActionProgress>('system-action-progress', (event) => {
        if (busyRule && event.payload.operation === actionProgress?.operation) actionProgress = event.payload;
      }).then((registered) => {
        if (disposed) registered();
        else unlisten = registered;
      });
    }
    void load();
    const timer = window.setInterval(() => void load(true), 5_000);
    return () => {
      disposed = true;
      unlisten?.();
      window.clearInterval(timer);
    };
  });
</script>

<div class="application-traffic-section">
  <div class="section-heading app-section-heading">
    <div><p class="eyebrow">Historique local</p><h3>Paquets par application</h3><p>Échantillons courts agrégés par heure ou par jour. Les paquets chiffrés et leurs tailles sont inclus sans stocker leur contenu.</p></div>
    <div class="chart-options">
      <div class="range-buttons" aria-label="Direction du trafic">
        <button class:active={trafficDirection === 'sent'} onclick={() => (trafficDirection = 'sent')}>Envoyés</button>
        <button class:active={trafficDirection === 'received'} onclick={() => (trafficDirection = 'received')}>Reçus</button>
        <button class:active={trafficDirection === 'total'} onclick={() => (trafficDirection = 'total')}>Tous</button>
      </div>
      <div class="range-buttons" aria-label="Période du graphique">
        <button class:active={rangeDays === 1} onclick={() => changeRange(1)}>24 h</button>
        <button class:active={rangeDays === 7} onclick={() => changeRange(7)}>7 j</button>
        <button class:active={rangeDays === 30} onclick={() => changeRange(30)}>30 j</button>
      </div>
    </div>
  </div>

  {#if message}<div class="notice {message.tone}" role="status"><strong>{message.title}</strong><p>{message.detail}</p></div>{/if}

  <div class="capture-controls app-sample-controls">
    <label><span>Interface de l'échantillon</span><select bind:value={captureInterface}><option value="any">Toutes les interfaces</option>{#each snapshot.interfaces as item}<option value={item.name}>{item.name}</option>{/each}</select></label>
    <button class="primary-button" onclick={sampleNow} disabled={sampling}>{sampling ? 'Analyse en cours…' : 'Échantillonner maintenant'}</button>
  </div>
  {#if sampling}
    <ProgressIndicator progress={sampleProgress} ariaLabel="Échantillonnage du trafic par application" />
  {:else if loading}
    <ProgressIndicator progress={historyProgress} ariaLabel="Chargement du trafic par application" />
  {/if}

  <div class="traffic-chart-grid" aria-busy={loading}>
    <article class="panel chart-panel">
      <div class="panel-title"><div><p class="eyebrow">Répartition temporelle</p><h3>{rangeDays === 1 ? 'Paquets selon les heures' : 'Paquets selon les jours'} · {trafficDirection === 'sent' ? 'envoyés' : trafficDirection === 'received' ? 'reçus' : 'tous'}</h3></div><Badge tone="neutral">{unattributedPackets ? `${unattributedPackets.toLocaleString('fr-FR')} non attribués` : 'Top 5'}</Badge></div>
      {#if timeline.length}
        <div class="stacked-chart" aria-label="Histogramme du nombre de paquets par application et période">
          {#each timeline as point}
            <div class="stacked-column" title={`${timelineLabel(point.timestamp)} : ${point.total} paquets`}>
              <div class="stacked-bar">
                {#each topApplications as application, index}
                  {@const value = point.values[application.id] ?? 0}
                  {#if value > 0}<span style={`height: ${(value / timelineMaximum) * 100}%; background: ${colors[index]}`} aria-hidden="true"></span>{/if}
                {/each}
              </div>
              <small>{timelineLabel(point.timestamp)}</small>
            </div>
          {/each}
        </div>
        <div class="chart-legend">{#each topApplications as application, index}<span><i style={`background: ${colors[index]}`}></i>{application.name}</span>{/each}</div>
      {:else}<p class="empty-inline">{history?.detail ?? 'Chargement de l’historique…'}</p>{/if}
    </article>

    <article class="panel chart-panel">
      <div class="panel-title"><div><p class="eyebrow">Classement</p><h3>Applications les plus actives</h3></div></div>
      <div class="application-ranking">
        {#each topApplications as application, index}
          <div><div class="ranking-label"><span><i style={`background: ${colors[index]}`}></i><strong>{application.name}</strong></span><span>{application.packets.toLocaleString('fr-FR')} paquets · {formatBytes(application.bytes)}</span></div><div class="ranking-track"><span style={`width: ${(application.packets / applicationMaximum) * 100}%; background: ${colors[index]}`}></span></div></div>
        {:else}<p class="empty-inline">Aucune donnée enregistrée sur cette période.</p>{/each}
      </div>
    </article>
  </div>

  <article class="panel application-control-panel">
    <div class="panel-title"><div><p class="eyebrow">Contrôle nftables + cgroup v2</p><h3>Couper Internet pour une application</h3><p>Le blocage est précis au groupe de processus courant et n'ajoute aucun service privilégié permanent.</p></div><Badge tone={inventory?.available ? 'safe' : 'warn'}>{inventory?.available ? 'Disponible' : 'Indisponible'}</Badge></div>
    {#if inventory}<div class="notice info compact-notice"><strong>Portée du contrôle</strong><p>{inventory.detail} Le chiffrement ne contourne pas le blocage, car nftables agit avant l'interprétation du contenu. Les protocoles bruts comme ICMP ne sont pas concernés.</p></div>{/if}
    {#if busyRule && actionProgress}<ProgressIndicator progress={actionProgress} ariaLabel="Progression du blocage de l’application" />{/if}
    <div class="table-wrap"><table><thead><tr><th>Application</th><th>Connexions</th><th>Groupe contrôlé</th><th>État</th><th>Action</th></tr></thead><tbody>
      {#each inventory?.applications ?? [] as application}
        <tr><td><strong>{application.name}</strong><small>PID {application.pid}{#if application.executable} · {application.executable}{/if}</small></td><td>{application.connectionCount}</td><td class="mono app-cgroup">{application.cgroupPath}</td><td><Badge tone={application.blockedRuleId ? 'danger' : 'safe'}>{application.blockedRuleId ? 'Bloquée' : 'Autorisée'}</Badge></td><td>{#if application.blockedRuleId}<button class="secondary-button" onclick={() => unblock(application.blockedRuleId!)} disabled={busyRule !== null}>{busyRule === application.blockedRuleId ? 'Autorisation…' : 'Rétablir'}</button>{:else}<button class="danger-button small" onclick={() => block(application)} disabled={!inventory?.available || busyRule !== null}>{busyRule === application.id ? 'Autorisation…' : 'Couper Internet'}</button>{/if}</td></tr>
      {:else}<tr><td colspan="5" class="empty">Aucune application avec une connexion TCP/UDP attribuable n'est visible.</td></tr>{/each}
    </tbody></table></div>

    {#if inventory?.blockRules.length}
      <div class="active-app-blocks"><strong>Blocages enregistrés</strong>{#each inventory.blockRules as rule}<div><span><b>{rule.applicationName}</b><small>{rule.cgroupPath}</small></span><button class="secondary-button" onclick={() => unblock(rule.id)} disabled={busyRule !== null}>{busyRule === rule.id ? 'Autorisation…' : 'Retirer le blocage'}</button></div>{/each}</div>
    {/if}
  </article>
</div>
