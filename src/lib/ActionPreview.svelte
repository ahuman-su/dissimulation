<script lang="ts">
  import { isTauri } from '@tauri-apps/api/core';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { onMount } from 'svelte';
  import ProgressIndicator from './ProgressIndicator.svelte';
  import type { ActionProgress, PlannedAction } from './types';

  export let action: PlannedAction;
  export let onCancel: () => void;
  export let onConfirm: () => void | Promise<void>;

  let busy = false;
  let error: string | null = null;
  let progress: ActionProgress | null = null;
  let finalizationTimer: number | null = null;

  async function confirm() {
    if (finalizationTimer !== null) window.clearTimeout(finalizationTimer);
    busy = true;
    error = null;
    progress = {
      operation: action.systemAction.type,
      current: 0,
      total: action.systemAction.type === 'applyProfile' ? action.systemAction.options.length : 2,
      label: action.requiresAuthorization
        ? "En attente de l’autorisation Ubuntu"
        : "Préparation de l’action"
    };
    try {
      await onConfirm();
    } catch (reason) {
      error = reason instanceof Error ? reason.message : String(reason);
    } finally {
      busy = false;
    }
  }

  function handleKeydown(event: KeyboardEvent) {
    if (event.key === 'Escape' && !busy) onCancel();
  }

  onMount(() => {
    let unlisten: UnlistenFn | null = null;
    let disposed = false;
    if (isTauri()) {
      void listen<ActionProgress>('system-action-progress', (event) => {
        if (busy && event.payload.operation === action.systemAction.type) {
          progress = event.payload;
          if (event.payload.total > 0 && event.payload.current >= event.payload.total) {
            if (finalizationTimer !== null) window.clearTimeout(finalizationTimer);
            finalizationTimer = window.setTimeout(() => {
              if (busy && progress?.operation === event.payload.operation && progress.current >= progress.total) {
                progress = {
                  operation: event.payload.operation,
                  current: 0,
                  total: 0,
                  label: 'Actualisation des données après application'
                };
              }
              finalizationTimer = null;
            }, 300);
          }
        }
      }).then((registered) => {
        if (disposed) registered();
        else unlisten = registered;
      });
    }
    return () => {
      disposed = true;
      if (finalizationTimer !== null) window.clearTimeout(finalizationTimer);
      unlisten?.();
    };
  });
</script>

<svelte:window onkeydown={handleKeydown} />

<div class="modal-backdrop" role="presentation" onclick={(event) => event.target === event.currentTarget && !busy && onCancel()}>
  <dialog class="action-dialog" open aria-modal="true" aria-labelledby="action-dialog-title">
    <div class="action-dialog-header">
      <div><p class="eyebrow">Prévisualisation obligatoire</p><h2 id="action-dialog-title">{action.title}</h2><p>{action.target}</p></div>
      <button class="close-button action-dialog-close" aria-label="Fermer la prévisualisation" onclick={onCancel} disabled={busy}>×</button>
    </div>

    <dl class="change-preview">
      <div><dt>État actuel</dt><dd>{action.currentValue}</dd></div>
      <div><dt>Nouvel état</dt><dd>{action.newValue}</dd></div>
      <div><dt>Impact attendu</dt><dd>{action.impact}</dd></div>
      <div><dt>Retour arrière</dt><dd>{action.reversible ? 'Possible par une action inverse ; non automatisé' : 'Sans objet'}</dd></div>
    </dl>

    {#if action.warning}<div class="notice warning"><strong>Avertissement</strong><p>{action.warning}</p></div>{/if}

    <div class="operation-preview">
      <span>Opérations prévues</span>
      {#each action.operations as operation}<code>{operation}</code>{/each}
    </div>

    <div class="notice info compact-notice">
      <strong>{action.requiresAuthorization ? 'Autorisation Polkit ponctuelle' : 'Action utilisateur'}</strong>
      <p>{action.requiresAuthorization ? "Ubuntu demandera une autorisation uniquement pour cette modification. Dissimulation ne reçoit et ne conserve jamais le mot de passe." : "L'action sera exécutée avec les droits de l'utilisateur courant."}</p>
    </div>

    {#if busy && progress}
      <ProgressIndicator {progress} />
    {/if}

    {#if error}<div class="notice danger" role="alert"><strong>Modification non appliquée</strong><p>{error}</p></div>{/if}

    <div class="dialog-actions">
      <button class="secondary-button" onclick={onCancel} disabled={busy}>Annuler</button>
      <button class="primary-button" onclick={confirm} disabled={busy}>{busy ? 'Autorisation…' : 'Confirmer et appliquer'}</button>
    </div>
  </dialog>
</div>
