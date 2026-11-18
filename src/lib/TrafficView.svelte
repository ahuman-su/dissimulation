<script lang="ts">
  import { onMount } from 'svelte';
  import { capturePacketSample, getTrafficSessions } from './api';
  import ApplicationTrafficView from './ApplicationTrafficView.svelte';
  import Badge from './Badge.svelte';
  import ProgressIndicator from './ProgressIndicator.svelte';
  import type { ActionProgress, NetworkSnapshot, PacketMetadata, PacketSample, TrafficSession } from './types';

  export let snapshot: NetworkSnapshot;

  let sessions: TrafficSession[] = [];
  let loading = true;
  let error: string | null = null;
  let protocol = 'all';
  let search = '';
  let includeListeners = false;
  let captureInterface = 'any';
  let capturing = false;
  let sample: PacketSample | null = null;
  const sessionsProgress: ActionProgress = {
    operation: 'getTrafficSessions',
    current: 0,
    total: 0,
    label: 'Lecture des sessions TCP et UDP avec ss'
  };
  const captureProgress: ActionProgress = {
    operation: 'capturePacketSample',
    current: 0,
    total: 0,
    label: 'Capture TShark en cours pendant quelques secondes'
  };

  $: filtered = sessions.filter((session) => {
    if (!includeListeners && session.isListener) return false;
    if (protocol !== 'all' && session.protocol !== protocol) return false;
    const haystack = `${session.localAddress}:${session.localPort} ${session.remoteAddress}:${session.remotePort} ${session.processName ?? ''}`.toLowerCase();
    return haystack.includes(search.toLowerCase());
  });

  async function refresh(silent = false) {
    if (!silent) loading = true;
    try {
      sessions = await getTrafficSessions();
      error = null;
    } catch (reason) {
      error = reason instanceof Error ? reason.message : String(reason);
    } finally {
      loading = false;
    }
  }

  async function capture() {
    capturing = true;
    sample = null;
    try {
      sample = await capturePacketSample(captureInterface);
    } catch (reason) {
      sample = { available: false, detail: reason instanceof Error ? reason.message : String(reason), packets: [] };
    } finally {
      capturing = false;
    }
  }

  function packetSummary(packet: PacketMetadata) {
    if (packet.requestSummary) return packet.requestSummary;
    const encrypted = /tls|quic|https/i.test(packet.protocol)
      || packet.sourcePort === 443
      || packet.destinationPort === 443;
    return encrypted
      ? 'Contenu chiffré · taille comptabilisée'
      : 'En-tête TCP/UDP · taille comptabilisée';
  }

  onMount(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(true), 2_000);
    return () => window.clearInterval(timer);
  });
</script>

<section aria-labelledby="traffic-title">
  <div class="page-heading"><div><p class="eyebrow">Sessions et métadonnées</p><h2 id="traffic-title">Trafic réseau</h2><p>Sessions TCP/UDP actualisées sans capture permanente, avec un échantillon TShark court à la demande.</p></div><Badge tone="info">Actualisation 2 s</Badge></div>

  <div class="notice info"><strong>Les paquets chiffrés sont bien pris en compte</strong><p>HTTPS, QUIC et les autres protocoles chiffrés restent opaques sans clés, mais leur direction, leurs adresses, leurs ports et leur taille sont mesurés et inclus dans les graphiques. Le blocage d'application agit sur TCP/UDP sous la couche de chiffrement. L'échantillon visible reste limité à 100 paquets, 4 secondes et 256 octets lus par paquet.</p></div>
  <ApplicationTrafficView {snapshot} />
  {#if error}<div class="notice danger" role="alert"><strong>Sessions indisponibles</strong><p>{error}</p></div>{/if}
  {#if loading}<ProgressIndicator progress={sessionsProgress} ariaLabel="Lecture des sessions réseau" />{/if}

  <div class="filterbar traffic-filterbar">
    <label class="search-field"><span aria-hidden="true">⌕</span><span class="sr-only">Filtrer les sessions</span><input bind:value={search} placeholder="Adresse, port ou processus" /></label>
    <label><span class="sr-only">Protocole</span><select bind:value={protocol}><option value="all">TCP et UDP</option><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
    <label class="check-control"><input type="checkbox" bind:checked={includeListeners} /> Inclure les écoutes</label>
    <button class="secondary-button" onclick={() => refresh()} disabled={loading}>{loading ? 'Lecture…' : 'Actualiser'}</button>
  </div>

  <article class="panel rules-panel">
    <div class="panel-title"><div><p class="eyebrow">Vue instantanée</p><h3>Sessions TCP/UDP</h3></div><Badge tone="neutral">{filtered.length}</Badge></div>
    <div class="table-wrap"><table><thead><tr><th>Protocole</th><th>État</th><th>Extrémité locale</th><th>Extrémité distante</th><th>Processus</th></tr></thead><tbody>
      {#each filtered as session}
        <tr><td><Badge tone={session.protocol === 'tcp' ? 'info' : 'neutral'}>{session.protocol.toUpperCase()}</Badge></td><td>{session.state}</td><td class="mono">{session.localAddress}:{session.localPort || '*'}</td><td class="mono">{session.remoteAddress}:{session.remotePort || '*'}</td><td>{session.processName ?? 'Non visible'}{#if session.pid}<small>PID {session.pid}</small>{/if}</td></tr>
      {:else}<tr><td colspan="5" class="empty">Aucune session ne correspond au filtre actuel.</td></tr>{/each}
    </tbody></table></div>
  </article>

  <article class="panel capture-panel">
    <div class="panel-title"><div><p class="eyebrow">Capture explicite</p><h3>Échantillon de requêtes</h3><p>DNS, HTTP non chiffré et nom de serveur TLS lorsqu'ils sont visibles.</p></div></div>
    <div class="capture-controls"><label><span>Interface</span><select bind:value={captureInterface}><option value="any">Toutes les interfaces</option>{#each snapshot.interfaces as item}<option value={item.name}>{item.name}</option>{/each}</select></label><button class="primary-button" onclick={capture} disabled={capturing}>{capturing ? 'Capture pendant 4 s…' : 'Capturer un échantillon'}</button></div>
    {#if capturing}<ProgressIndicator progress={captureProgress} ariaLabel="Capture des paquets réseau" />{/if}
    {#if sample}
      <div class="notice {sample.available ? 'info' : 'warning'}" role="status"><strong>{sample.available ? 'Capture terminée' : 'Capture indisponible'}</strong><p>{sample.detail}</p></div>
      {#if sample.packets.length}
        <div class="table-wrap"><table><thead><tr><th>Heure</th><th>Source</th><th>Destination</th><th>Protocole</th><th>Métadonnée visible</th><th>Taille comptée</th></tr></thead><tbody>{#each sample.packets as packet}<tr><td>{new Date(packet.capturedAtEpochMs).toLocaleTimeString('fr-FR')}</td><td class="mono">{packet.sourceAddress}:{packet.sourcePort ?? '*'}</td><td class="mono">{packet.destinationAddress}:{packet.destinationPort ?? '*'}</td><td>{packet.protocol}</td><td>{packetSummary(packet)}</td><td>{packet.length ?? '—'} o</td></tr>{/each}</tbody></table></div>
      {/if}
    {/if}
  </article>
</section>
