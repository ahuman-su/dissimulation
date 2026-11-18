<script lang="ts">
  import Badge from './Badge.svelte';
  import type { HistoryEntry, NetworkSnapshot } from './types';

  export let history: HistoryEntry[];
  export let snapshot: NetworkSnapshot;
  export let maskSensitive: boolean;

  function redactedReport(): NetworkSnapshot {
    if (!maskSensitive) return snapshot;
    const redactAddress = (value: string) => {
      if (value === '127.0.0.1' || value === '::1' || value === '0.0.0.0' || value === '::' || value === '*') return value;
      return '[adresse masquée]';
    };
    return {
      ...snapshot,
      ports: snapshot.ports.map((port) => ({ ...port, localAddress: redactAddress(port.localAddress), user: port.user ? '[utilisateur masqué]' : null })),
      interfaces: snapshot.interfaces.map((item) => ({ ...item, addresses: item.addresses.map(() => '[adresse masquée]'), hardwareMac: item.hardwareMac ? '[MAC masquée]' : null, currentMac: item.currentMac ? '[MAC masquée]' : null })),
      firewall: { ...snapshot.firewall, rules: snapshot.firewall.rules.map((rule) => ({ ...rule, source: redactAddress(rule.source) })) }
    };
  }

  function exportJson() {
    const blob = new Blob([JSON.stringify(redactedReport(), null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `dissimulation-${new Date(snapshot.analyzedAtEpochMs).toISOString().slice(0, 10)}.json`;
    link.click();
    URL.revokeObjectURL(url);
  }
</script>

<section aria-labelledby="history-title">
  <div class="page-heading"><div><p class="eyebrow">Audit local</p><h2 id="history-title">Historique et rapports</h2><p>Le journal ne conserve aucun mot de passe, jeton, clé privée ou contenu réseau.</p></div><button class="primary-button" onclick={exportJson}>Exporter JSON</button></div>
  <div class="notice {maskSensitive ? 'info' : 'warning'}"><strong>{maskSensitive ? 'Données sensibles masquées' : 'Rapport non masqué'}</strong><p>{maskSensitive ? "Les utilisateurs, adresses IP non génériques et adresses MAC seront remplacés dans l'export." : "L'export contiendra les utilisateurs, IP et MAC observés. Activez le masquage dans Paramètres si le rapport doit être partagé."}</p></div>
  <article class="panel rules-panel">
    <div class="panel-title"><div><p class="eyebrow">Cette session</p><h3>Journal des opérations</h3></div><Badge tone="neutral">{history.length}</Badge></div>
    <div class="table-wrap"><table><thead><tr><th>Date</th><th>Action</th><th>Ancienne valeur</th><th>Nouvelle valeur</th><th>Résultat</th><th>Restauration</th></tr></thead><tbody>
      {#each history as entry}<tr><td>{new Date(entry.date).toLocaleString('fr-FR')}</td><td><strong>{entry.action}</strong></td><td>{entry.previousValue}</td><td>{entry.newValue}</td><td><Badge tone="safe">{entry.result}</Badge></td><td>{entry.restorable ? 'Disponible' : 'Non automatisée'}</td></tr>{:else}<tr><td colspan="6" class="empty">Aucune action confirmée. Les analyses seules ne sont pas enregistrées comme des changements de configuration.</td></tr>{/each}
    </tbody></table></div>
  </article>
</section>
