<script lang="ts">
  import type { Page } from './types';

  export let active: Page;
  export let onSelect: (page: Page) => void;

  const entries: Array<{ page: Page; label: string; glyph: string }> = [
    { page: 'dashboard', label: 'Tableau de bord', glyph: '⌂' },
    { page: 'traffic', label: 'Trafic', glyph: '≋' },
    { page: 'filters', label: 'Filtres', glyph: '⊘' },
    { page: 'ports', label: 'Ports', glyph: '⇄' },
    { page: 'services', label: 'Services', glyph: '◇' },
    { page: 'interfaces', label: 'Interfaces réseau', glyph: '⌁' },
    { page: 'firewall', label: 'Pare-feu', glyph: '⬡' },
    { page: 'profiles', label: 'Profils', glyph: '◫' },
    { page: 'history', label: 'Historique', glyph: '↶' },
    { page: 'settings', label: 'Paramètres', glyph: '⚙' }
  ];
</script>

<aside class="sidebar">
  <div class="brand" aria-label="Dissimulation">
    <img src="/shield.svg" alt="" />
    <div><strong>Dissimulation</strong><span>Exposition réseau</span></div>
  </div>
  <nav aria-label="Navigation principale">
    {#each entries as entry}
      <button
        class:active={active === entry.page}
        aria-current={active === entry.page ? 'page' : undefined}
        onclick={() => onSelect(entry.page)}
      >
        <span class="nav-glyph" aria-hidden="true">{entry.glyph}</span>
        <span>{entry.label}</span>
      </button>
    {/each}
  </nav>
  <div class="readonly"><span aria-hidden="true">●</span><div><strong>Contrôle local</strong><small>Polkit uniquement à la demande</small></div></div>
</aside>
