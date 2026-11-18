<script lang="ts">
  export let tone: 'safe' | 'warn' | 'danger' | 'neutral' | 'info' = 'neutral';
</script>

<span class="badge {tone}"><slot /></span>

