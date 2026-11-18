<script lang="ts">
  import { isTauri } from '@tauri-apps/api/core';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { onMount } from 'svelte';
  import { getInitialNetworkExposure, scanNetworkExposure } from './lib/api';
  import Dashboard from './lib/Dashboard.svelte';
  import FiltersView from './lib/FiltersView.svelte';
  import FirewallView from './lib/FirewallView.svelte';
  import HistoryView from './lib/HistoryView.svelte';
  import InterfacesView from './lib/InterfacesView.svelte';
  import PortsView from './lib/PortsView.svelte';
  import ProgressIndicator from './lib/ProgressIndicator.svelte';
  import ProfilesView from './lib/ProfilesView.svelte';
  import ServicesView from './lib/ServicesView.svelte';
  import SettingsView from './lib/SettingsView.svelte';
  import Sidebar from './lib/Sidebar.svelte';
  import TrafficView from './lib/TrafficView.svelte';
  import type { ActionOutcome, ActionProgress, HistoryEntry, NetworkSnapshot, Page, PlannedAction } from './lib/types';

  let activePage: Page = 'dashboard';
  let snapshot: NetworkSnapshot | null = null;
  let scanning = false;
  let error: string | null = null;
  let demo = false;
  let maskSensitive = true;
  let history: HistoryEntry[] = [];
  const scanProgress: ActionProgress = {
    operation: 'scanNetworkExposure',
    current: 0,
    total: 0,
    label: 'Analyse des interfaces, ports, services et réglages réseau'
  };

  const titles: Record<Page, string> = {
    dashboard: 'Tableau de bord',
    traffic: 'Trafic réseau',
    filters: 'Filtres de blocage',
    ports: 'Ports',
    services: 'Services',
    interfaces: 'Interfaces réseau',
    firewall: 'Pare-feu',
    profiles: 'Profils',
    history: 'Historique',
    settings: 'Paramètres'
  };

  async function scan() {
    scanning = true;
    error = null;
    try {
      const result = await scanNetworkExposure();
      snapshot = result.snapshot;
      demo = result.demo;
    } catch {
      error = "L'analyse locale n'a pas pu aboutir. Relancez l'application ou vérifiez que les outils système sont disponibles.";
    } finally {
      scanning = false;
    }
  }

  async function initialScan() {
    scanning = true;
    error = null;
    try {
      const result = await getInitialNetworkExposure();
      snapshot = result.snapshot;
      demo = result.demo;
    } catch {
      error = "L'analyse locale n'a pas pu aboutir. Relancez l'application ou vérifiez que les outils système sont disponibles.";
    } finally {
      scanning = false;
    }
  }

  async function recordApplied(action: PlannedAction, outcome: ActionOutcome) {
    history = [
      {
        date: Date.now(),
        action: action.title,
        previousValue: action.currentValue,
        newValue: action.newValue,
        result: outcome.message,
        restorable: false
      },
      ...history
    ];
    await scan();
  }

  async function recordFilterChange(outcome: ActionOutcome, title: string) {
    history = [{ date: Date.now(), action: title, previousValue: 'Règles UFW', newValue: 'Règles mises à jour', result: outcome.message, restorable: false }, ...history];
    await scan();
  }

  onMount(() => {
    const unlisteners: UnlistenFn[] = [];
    let disposed = false;

    if (isTauri()) {
      void Promise.all([
        listen<NetworkSnapshot>('snapshot-updated', (event) => {
          snapshot = event.payload;
          demo = false;
          error = null;
        }),
        listen<Page>('navigate', (event) => {
          if (event.payload in titles) activePage = event.payload;
        })
      ]).then((registered) => {
        if (disposed) registered.forEach((unlisten) => unlisten());
        else unlisteners.push(...registered);
      });
    }

    void initialScan();
    return () => {
      disposed = true;
      unlisteners.forEach((unlisten) => unlisten());
    };
  });
</script>

<svelte:head><title>{titles[activePage]} · Dissimulation</title></svelte:head>
<a class="skip-link" href="#main-content">Aller au contenu principal</a>

<div class="app-shell">
  <Sidebar active={activePage} onSelect={(page) => (activePage = page)} />
  <div class="app-column">
    <header class="topbar">
      <div><span class="mobile-brand">Dissimulation · </span><strong>{titles[activePage]}</strong>{#if demo}<span class="demo-pill">Démonstration</span>{/if}</div>
      <div class="top-actions">
        {#if snapshot}<span class="last-scan"><span aria-hidden="true">●</span> Analysé {new Date(snapshot.analyzedAtEpochMs).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' })}</span>{/if}
        <button class="scan-button" onclick={scan} disabled={scanning}><span class:spinning={scanning} aria-hidden="true">↻</span>{scanning ? 'Analyse…' : 'Analyser'}</button>
      </div>
    </header>

    <main id="main-content" tabindex="-1">
      {#if scanning}<ProgressIndicator progress={scanProgress} ariaLabel="Analyse réseau en cours" />{/if}
      {#if error}
        <div class="notice danger" role="alert"><strong>Analyse indisponible</strong><p>{error}</p><button class="secondary-button" onclick={scan}>Réessayer</button></div>
      {:else if !snapshot}
        <div class="loading-state" aria-live="polite"><span class="loader" aria-hidden="true"></span><h2>Analyse locale en cours</h2><p>Consultation des sockets, interfaces et réglages visibles…</p></div>
      {:else}
        {#if demo}<div class="demo-banner"><span aria-hidden="true">i</span><p><strong>Aperçu navigateur.</strong> Lancez <code>npm run tauri dev</code> pour analyser cette machine.</p></div>{/if}
        {#if activePage === 'dashboard'}<Dashboard {snapshot} navigate={(page) => (activePage = page)} />
        {:else if activePage === 'traffic'}<TrafficView {snapshot} />
        {:else if activePage === 'filters'}<FiltersView {snapshot} onChanged={recordFilterChange} />
        {:else if activePage === 'ports'}<PortsView {snapshot} />
        {:else if activePage === 'services'}<ServicesView {snapshot} onApplied={recordApplied} onRefresh={scan} />
        {:else if activePage === 'interfaces'}<InterfacesView {snapshot} onApplied={recordApplied} />
        {:else if activePage === 'firewall'}<FirewallView {snapshot} onApplied={recordApplied} />
        {:else if activePage === 'profiles'}<ProfilesView {snapshot} onApplied={recordApplied} />
        {:else if activePage === 'history'}<HistoryView {history} {snapshot} {maskSensitive} />
        {:else}<SettingsView {snapshot} {maskSensitive} onMaskChange={(value) => (maskSensitive = value)} />{/if}
      {/if}
    </main>
  </div>
</div>
