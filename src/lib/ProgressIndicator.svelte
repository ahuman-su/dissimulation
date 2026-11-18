<script lang="ts">
  import type { ActionProgress } from './types';

  export let progress: ActionProgress;
  export let ariaLabel = "Progression de l'action";

  $: indeterminate = progress.current <= 0 || progress.total <= 0;
  $: percentage = progress.total > 0
    ? Math.min(100, Math.max(0, (progress.current / progress.total) * 100))
    : 0;
</script>

<div class="action-progress" aria-live="polite">
  <div><strong>{progress.label}</strong><span>{indeterminate ? 'En cours' : `${progress.current}/${progress.total}`}</span></div>
  <div
    class="progress-track"
    role="progressbar"
    aria-label={ariaLabel}
    aria-valuemin="0"
    aria-valuemax={indeterminate ? undefined : progress.total}
    aria-valuenow={indeterminate ? undefined : progress.current}
  >
    {#if indeterminate}<span class="indeterminate"></span>{:else}<span style={`width: ${percentage}%`}></span>{/if}
  </div>
</div>
