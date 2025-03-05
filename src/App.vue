<script setup>
import NftState from "./NftState.vue";
import {ref} from "vue";

const mode = ref('NftState')
const modes = {NftState};
</script>

<template>
  <div :class="$style.layout">
    <div :class="$style.navbar">
      <button @click="mode='NftState'">State/control</button>
    </div>
    <div :class="$style.content">
      <Suspense>
        <component :is="modes[mode]"/>
      </Suspense>
    </div>
  </div>
</template>

<style module>

.layout {
  display: flex;
  flex-direction: column;
  width: 100%;
}

.navbar {
  display: flex;
  flex-direction: row;
}
.content{
  
}

@media (min-width: 1024px) {
}
</style>
