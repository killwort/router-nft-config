<template>
<div :class="isLoading?$style.loading:$style.loaded">
    <slot />
</div>
</template>

<script setup>
const props=defineProps(['isLoading']);
</script>

<style module>
.loading{
  
}
.loaded{
  
}
</style>
