<script lang="ts">
  import Badge from './Badge.svelte';
  import { exposureLabels } from './labels';
  import type { ExposureLevel, NetworkSnapshot, PortInfo } from './types';

  export let snapshot: NetworkSnapshot;

  let search = '';
  let protocol = 'all';
  let exposure: 'all' | ExposureLevel = 'all';
  let interfaceFilter = 'all';
  let sortKey: 'port' | 'protocol' | 'process' | 'interface' | 'exposure' = 'port';
  let ascending = true;
  let selected: PortInfo | null = null;

  function tone(level: ExposureLevel): 'safe' | 'warn' | 'danger' | 'neutral' | 'info' {
    if (level === 'localOnly') return 'safe';
    if (level === 'allInterfaces') return 'danger';
    if (level === 'specificInterface') return 'warn';
    if (level === 'virtualNetwork') return 'info';
    return 'neutral';
  }

  function sortBy(key: typeof sortKey) {
    if (sortKey === key) ascending = !ascending;
    else {
      sortKey = key;
      ascending = true;
    }
  }

  $: filtered = snapshot.ports
    .filter((port) => protocol === 'all' || port.protocol === protocol)
    .filter((port) => exposure === 'all' || port.exposure === exposure)
    .filter((port) =>
      interfaceFilter === 'all'
        ? true
        : interfaceFilter === 'allInterfaces'
          ? port.exposure === 'allInterfaces'
          : port.interfaceName === interfaceFilter
    )
    .filter((port) => {
      const haystack = `${port.port} ${port.localAddress} ${port.processName ?? ''} ${port.interfaceName ?? ''}`.toLowerCase();
      return haystack.includes(search.trim().toLowerCase());
    })
    .sort((a, b) => {
      const left = sortKey === 'port' ? a.port : sortKey === 'process' ? a.processName ?? '' : sortKey === 'interface' ? a.interfaceName ?? '' : a[sortKey];
      const right = sortKey === 'port' ? b.port : sortKey === 'process' ? b.processName ?? '' : sortKey === 'interface' ? b.interfaceName ?? '' : b[sortKey];
      return (left < right ? -1 : left > right ? 1 : 0) * (ascending ? 1 : -1);
    });

  $: if (selected && !snapshot.ports.some((port) => port.id === selected?.id)) selected = null;
</script>

<section aria-labelledby="ports-title">
  <div class="page-heading">
    <div><p class="eyebrow">Analyse des sockets</p><h2 id="ports-title">Ports en écoute</h2><p>Un port ouvert n'est pas, à lui seul, la preuve d'un risque ou d'un programme malveillant.</p></div>
    <Badge tone="neutral">{filtered.length} sur {snapshot.ports.length}</Badge>
  </div>

  <div class="filterbar" role="search">
    <label class="search-field"><span class="sr-only">Rechercher</span><span aria-hidden="true">⌕</span><input bind:value={search} placeholder="Port, processus, adresse, interface…" /></label>
    <label><span class="sr-only">Protocole</span><select bind:value={protocol}><option value="all">Tous protocoles</option><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
    <label><span class="sr-only">Exposition</span><select bind:value={exposure}><option value="all">Tous les niveaux</option><option value="localOnly">Local uniquement</option><option value="virtualNetwork">Réseau virtuel</option><option value="specificInterface">Interface précise</option><option value="allInterfaces">Toutes interfaces</option><option value="unknown">Inconnu</option></select></label>
    <label><span class="sr-only">Interface</span><select bind:value={interfaceFilter}><option value="all">Toutes interfaces réseau</option><option value="allInterfaces">Écoutes génériques</option>{#each snapshot.interfaces as item}<option value={item.name}>{item.name}</option>{/each}</select></label>
  </div>

  <div class="ports-layout" class:has-detail={selected !== null}>
    <div class="table-wrap">
      <table>
        <thead><tr><th><button onclick={() => sortBy('protocol')}>Protocole</button></th><th>Adresse locale</th><th><button onclick={() => sortBy('port')}>Port</button></th><th><button onclick={() => sortBy('process')}>Processus</button></th><th><button onclick={() => sortBy('interface')}>Interface</button></th><th><button onclick={() => sortBy('exposure')}>Exposition</button></th><th><span class="sr-only">Détails</span></th></tr></thead>
        <tbody>
          {#each filtered as port}
            <tr class:selected={selected?.id === port.id}>
              <td><Badge tone="neutral">{port.protocol.toUpperCase()}</Badge><small>{port.ipVersion}</small></td>
              <td class="mono">{port.ipVersion === 'IPv6' ? `[${port.localAddress}]` : port.localAddress}</td>
              <td><strong>{port.port}</strong></td>
              <td><strong>{port.processName ?? 'Non visible'}</strong><small>{port.pid ? `PID ${port.pid}` : 'PID indisponible'}</small></td>
              <td>{port.interfaceName ?? (port.exposure === 'allInterfaces' ? 'Toutes' : '—')}</td>
              <td><Badge tone={tone(port.exposure)}>{exposureLabels[port.exposure]}</Badge></td>
              <td><button class="icon-button" aria-label={`Voir les détails du port ${port.port}`} onclick={() => (selected = port)}>›</button></td>
            </tr>
          {:else}
            <tr><td colspan="7" class="empty">Aucun port ne correspond à ces filtres.</td></tr>
          {/each}
        </tbody>
      </table>
    </div>

    {#if selected}
      <aside class="detail-panel" aria-label={`Détails du port ${selected.port}`}>
        <button class="close-button" aria-label="Fermer le panneau" onclick={() => (selected = null)}>×</button>
        <p class="eyebrow">Détail de l'écoute</p>
        <h3>{selected.processName ?? 'Processus non visible'} <span>:{selected.port}</span></h3>
        <Badge tone={tone(selected.exposure)}>{exposureLabels[selected.exposure]}</Badge>
        <p class="explanation">{selected.explanation}</p>
        <dl class="detail-list">
          <div><dt>Protocole</dt><dd>{selected.protocol.toUpperCase()} · {selected.ipVersion}</dd></div>
          <div><dt>Adresse</dt><dd class="mono">{selected.localAddress}:{selected.port}</dd></div>
          <div><dt>État</dt><dd>{selected.state}</dd></div>
          <div><dt>PID</dt><dd>{selected.pid ?? 'Indisponible'}</dd></div>
          <div><dt>Utilisateur</dt><dd>{selected.user ?? 'Indisponible'}</dd></div>
          <div><dt>Interface</dt><dd>{selected.interfaceName ?? 'Toutes ou inconnue'}</dd></div>
          <div><dt>Unité systemd</dt><dd>{selected.systemdService ?? 'Non associée'}</dd></div>
          <div><dt>Conteneur</dt><dd>{selected.dockerContainer ?? 'Non associé'}</dd></div>
        </dl>
        {#if selected.command}<div class="code-box"><span>Commande observée</span><code>{selected.command}</code></div>{/if}
        {#if selected.dockerContainer}
          {@const publication = snapshot.dockerPorts.find((item) => item.containerName === selected?.dockerContainer && item.hostPort === selected?.port)}
          {#if publication?.saferBindingSuggestion}<div class="notice warning"><strong>Suggestion Docker</strong><p>Si l'accès distant n'est pas requis, envisagez <code>{publication.saferBindingSuggestion}</code>. Aucun conteneur ne sera modifié automatiquement.</p></div>{/if}
        {/if}
      </aside>
    {/if}
  </div>
</section>
