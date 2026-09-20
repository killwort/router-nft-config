<script setup>
import NftState from "./NftState.vue";
import {ref, watch} from "vue";
import AppState from "@/AppState.vue";

const mode = ref(localStorage.getItem('mode')||'NftState')
const modes = {NftState, AppState};

watch(mode, s=>localStorage.setItem('mode',s));
</script>

<template>
  <div :class="$style.layout">
    <div :class="$style.navbar">
      <button @click="mode='NftState'">Правила хостов</button>
      <button @click="mode='AppState'">Правила приложений</button>
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
