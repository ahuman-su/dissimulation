<script lang="ts">
  import { isTauri } from '@tauri-apps/api/core';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { onMount } from 'svelte';
  import {
    defaultBackgroundSettings,
    getBackgroundSettings,
    getRuntimeStatus,
    quitCompletely,
    updateBackgroundSettings,
    type BackgroundSettings,
    type LifecycleState,
    type RuntimeStatus
  } from './api';
  import Badge from './Badge.svelte';
  import ProgressIndicator from './ProgressIndicator.svelte';
  import type { ActionProgress, NetworkSnapshot } from './types';

  export let snapshot: NetworkSnapshot;
  export let maskSensitive: boolean;
  export let onMaskChange: (value: boolean) => void;

  let background: BackgroundSettings = { ...defaultBackgroundSettings };
  let runtimeStatus: RuntimeStatus | null = null;
  let loading = true;
  let saving = false;
  let settingsError: string | null = null;
  let saved = false;
  const saveProgress: ActionProgress = {
    operation: 'updateBackgroundSettings',
    current: 0,
    total: 0,
    label: "Enregistrement des paramètres et de l'autostart XDG"
  };

  const lifecycleLabels: Record<LifecycleState, string> = {
    startup: 'Démarrage',
    initializing: 'Initialisation',
    backgroundMonitoring: 'Surveillance en arrière-plan',
    interfaceOpen: 'Interface ouverte',
    interfaceHidden: 'Interface masquée',
    authorizationRequest: "Demande d'autorisation",
    shuttingDown: 'Arrêt complet'
  };

  async function persist(next: BackgroundSettings) {
    background = next;
    saving = true;
    saved = false;
    settingsError = null;
    try {
      background = await updateBackgroundSettings(next);
      saved = true;
      window.setTimeout(() => (saved = false), 1800);
    } catch {
      settingsError = "Le réglage n'a pas pu être enregistré. L'état précédent a été conservé.";
      background = await getBackgroundSettings().catch(() => background);
    } finally {
      saving = false;
    }
  }

  function setBoolean(key: keyof BackgroundSettings, value: boolean) {
    void persist({ ...background, [key]: value });
  }

  function setNumber(key: keyof BackgroundSettings, value: number) {
    void persist({ ...background, [key]: value });
  }

  async function confirmQuit() {
    if (
      window.confirm(
        "Quitter complètement Dissimulation ? La surveillance en arrière-plan sera arrêtée."
      )
    ) {
      await quitCompletely();
    }
  }

  onMount(() => {
    let unlisten: UnlistenFn | null = null;
    let disposed = false;
    void Promise.all([getBackgroundSettings(), getRuntimeStatus()])
      .then(([loadedSettings, status]) => {
        background = loadedSettings;
        runtimeStatus = status;
      })
      .catch(() => {
        settingsError = "Les paramètres d'arrière-plan sont momentanément indisponibles.";
      })
      .finally(() => (loading = false));

    if (isTauri()) {
      void listen<RuntimeStatus>('runtime-status-updated', (event) => {
        runtimeStatus = event.payload;
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

<section aria-labelledby="settings-title">
  <div class="page-heading">
    <div>
      <p class="eyebrow">Comportement de l'application</p>
      <h2 id="settings-title">Paramètres</h2>
      <p>La surveillance reste active lorsque la fenêtre est masquée, sans privilèges administrateur permanents.</p>
    </div>
    <Badge tone={runtimeStatus?.lifecycle === 'shuttingDown' ? 'warn' : 'safe'}>
      {runtimeStatus ? lifecycleLabels[runtimeStatus.lifecycle] : 'Initialisation'}
    </Badge>
  </div>

  {#if settingsError}<div class="notice danger" role="alert"><strong>Paramètres non enregistrés</strong><p>{settingsError}</p></div>{/if}
  {#if saved}<p class="settings-saved" role="status">Paramètres enregistrés.</p>{/if}
  {#if saving}<ProgressIndicator progress={saveProgress} ariaLabel="Enregistrement des paramètres" />{/if}

  <div class="settings-grid" aria-busy={loading || saving}>
    <article class="panel settings-card">
      <div><h3>Lancement automatique</h3><p>Lance l'application après l'ouverture de la session graphique, avec la fenêtre masquée.</p></div>
      <label class="switch-label"><input type="checkbox" checked={background.autostartEnabled} disabled={loading || saving} onchange={(event) => setBoolean('autostartEnabled', event.currentTarget.checked)} /><span>{background.autostartEnabled ? 'Activé' : 'Désactivé'}</span></label>
    </article>

    <article class="panel settings-card">
      <div><h3>Fréquence de surveillance</h3><p>Une analyse locale est lancée à cet intervalle, et immédiatement sur demande.</p></div>
      <label class="settings-select"><span>Intervalle</span><select value={background.scanIntervalMinutes} disabled={loading || saving} onchange={(event) => setNumber('scanIntervalMinutes', Number(event.currentTarget.value))}><option value={5}>5 minutes</option><option value={15}>15 minutes</option><option value={30}>30 minutes</option><option value={60}>1 heure</option><option value={240}>4 heures</option></select></label>
    </article>

    <article class="panel settings-card">
      <div><h3>Trafic par application</h3><p>Alimente les graphiques avec des captures TShark courtes, sans conserver le contenu.</p></div>
      <label class="switch-label"><input type="checkbox" checked={background.applicationTrafficMonitoring} disabled={loading || saving} onchange={(event) => setBoolean('applicationTrafficMonitoring', event.currentTarget.checked)} /><span>{background.applicationTrafficMonitoring ? 'Activé' : 'Désactivé'}</span></label>
    </article>

    <article class="panel settings-card">
      <div><h3>Fréquence du trafic</h3><p>Intervalle entre deux échantillons en arrière-plan ; aucune capture continue.</p></div>
      <label class="settings-select"><span>Intervalle</span><select value={background.applicationTrafficIntervalMinutes} disabled={!background.applicationTrafficMonitoring || loading || saving} onchange={(event) => setNumber('applicationTrafficIntervalMinutes', Number(event.currentTarget.value))}><option value={5}>5 minutes</option><option value={15}>15 minutes</option><option value={30}>30 minutes</option><option value={60}>1 heure</option></select></label>
    </article>

    <article class="panel settings-card">
      <div><h3>Durée d'un échantillon</h3><p>Une durée courte réduit la charge ; une durée longue améliore l'attribution des flux brefs.</p></div>
      <label class="settings-select"><span>Durée</span><select value={background.applicationTrafficSampleSeconds} disabled={!background.applicationTrafficMonitoring || loading || saving} onchange={(event) => setNumber('applicationTrafficSampleSeconds', Number(event.currentTarget.value))}><option value={2}>2 secondes</option><option value={4}>4 secondes</option><option value={8}>8 secondes</option><option value={15}>15 secondes</option></select></label>
    </article>

    <article class="panel settings-card">
      <div><h3>Conservation des statistiques</h3><p>Les compteurs horaires restent uniquement dans les données locales de l'application.</p></div>
      <label class="settings-select"><span>Durée</span><select value={background.trafficHistoryDays} disabled={loading || saving} onchange={(event) => setNumber('trafficHistoryDays', Number(event.currentTarget.value))}><option value={7}>7 jours</option><option value={30}>30 jours</option><option value={60}>60 jours</option><option value={90}>90 jours</option></select></label>
    </article>

    <article class="panel settings-card">
      <div><h3>Actions système contrôlées</h3><p>Chaque écriture est prévisualisée puis exécutée par un helper éphémère après autorisation Polkit.</p></div>
      <label class="switch-label"><input type="checkbox" checked disabled /><span>Activées</span></label>
    </article>

    <article class="panel settings-card">
      <div><h3>Masquer les données dans les rapports</h3><p>Remplace utilisateurs, IP non génériques et adresses MAC dans l'export.</p></div>
      <label class="switch-label"><input type="checkbox" checked={maskSensitive} onchange={(event) => onMaskChange(event.currentTarget.checked)} /><span>{maskSensitive ? 'Activé' : 'Désactivé'}</span></label>
    </article>
  </div>

  <article class="panel notification-panel">
    <div class="panel-title">
      <div><p class="eyebrow">Changements importants uniquement</p><h3>Notifications système</h3><p>Les événements identiques sont temporisés pour éviter les alertes répétitives.</p></div>
      <label class="switch-label"><input type="checkbox" checked={background.notificationsEnabled} disabled={loading || saving} onchange={(event) => setBoolean('notificationsEnabled', event.currentTarget.checked)} /><span>{background.notificationsEnabled ? 'Activées' : 'Désactivées'}</span></label>
    </div>
    <div class="notification-options">
      <label><input type="checkbox" checked={background.notifyNewPorts} disabled={!background.notificationsEnabled || loading || saving} onchange={(event) => setBoolean('notifyNewPorts', event.currentTarget.checked)} /><span><strong>Nouveau port exposé</strong><small>Nouvelle écoute sur une interface réseau.</small></span></label>
      <label><input type="checkbox" checked={background.notifyFirewallDisabled} disabled={!background.notificationsEnabled || loading || saving} onchange={(event) => setBoolean('notifyFirewallDisabled', event.currentTarget.checked)} /><span><strong>Pare-feu désactivé</strong><small>Transition observée depuis un état actif.</small></span></label>
      <label><input type="checkbox" checked={background.notifyMacChange} disabled={!background.notificationsEnabled || loading || saving} onchange={(event) => setBoolean('notifyMacChange', event.currentTarget.checked)} /><span><strong>Adresse MAC modifiée</strong><small>Changement inattendu entre deux analyses.</small></span></label>
      <label><input type="checkbox" checked={background.notifyProfileFailure} disabled={!background.notificationsEnabled || loading || saving} onchange={(event) => setBoolean('notifyProfileFailure', event.currentTarget.checked)} /><span><strong>Échec d'un profil</strong><small>Échec signalé sans conserver l'autorisation administrateur.</small></span></label>
      <label><input type="checkbox" checked={background.notifyServiceRestart} disabled={!background.notificationsEnabled || loading || saving} onchange={(event) => setBoolean('notifyServiceRestart', event.currentTarget.checked)} /><span><strong>Service redevenu actif</strong><small>Un service auparavant arrêté est de nouveau actif.</small></span></label>
      <label class="cooldown-option"><span><strong>Temporisation</strong><small>Délai minimal entre deux alertes du même type.</small></span><select value={background.notificationCooldownMinutes} disabled={!background.notificationsEnabled || loading || saving} onchange={(event) => setNumber('notificationCooldownMinutes', Number(event.currentTarget.value))}><option value={15}>15 min</option><option value={30}>30 min</option><option value={60}>1 h</option><option value={240}>4 h</option></select></label>
    </div>
  </article>

  <article class="panel source-panel">
    <div class="panel-title"><div><p class="eyebrow">Transparence de l'analyse</p><h3>Sources de données</h3></div></div>
    <div class="source-list">
      {#each snapshot.sources as source}<div><span class="source-dot {source.availability}" aria-hidden="true"></span><div><strong>{source.source}</strong><p>{source.detail}</p></div><Badge tone={source.availability === 'available' ? 'safe' : source.availability === 'partial' ? 'warn' : 'neutral'}>{source.availability === 'available' ? 'Disponible' : source.availability === 'partial' ? 'Partiel' : 'Indisponible'}</Badge></div>{/each}
    </div>
  </article>

  <div class="notice info"><strong>Respect de la vie privée</strong><p>L'analyse s'exécute localement. Les captures TShark sont courtes et espacées ; seuls des compteurs horaires par application sont conservés. Aucun contenu de paquet, résultat ou mot de passe administrateur n'est transmis.</p></div>

  <article class="panel quit-panel"><div><h3>Arrêt complet</h3><p>Libère le tray et arrête la surveillance. Les configurations système déjà appliquées ne sont pas modifiées.</p></div><button class="danger-button" onclick={confirmQuit}>Quitter complètement</button></article>
</section>
