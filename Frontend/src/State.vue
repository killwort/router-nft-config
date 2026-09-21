<template>
  <div>
    <label><input type="checkbox" v-model="showHidden"/>Показать спрятанные</label>
    &nbsp;
    <label><input type="checkbox" v-model="showOffline"/>Показать оффлайн</label>
    <div :class="$style.devices">
      <Device v-for="(dev,i) in state" :key="i" :device="dev" :showDisplayControls="showHidden" @mustReload="reload"/>
    </div>
  </div>
</template>

<script setup>
import conf from "@/config";
import {ref, watch} from "vue";
import Device from "@/Device.vue";

const showHidden = ref(false);
const showOffline = ref(false);
const state = ref({});
watch(showHidden, async () => await reload());
watch(showOffline, async () => await reload());
await reload();

async function reload() {
  var data = await fetch(conf.server + 'state?includeHidden=' + showHidden.value);
  state.value = (await data.json()).filter(x => x.isOnline || showOffline.value);
}
</script>
<style module>
.devices {
  display: grid;
  padding: 0;
  list-style: none;
  width: 100%;
  grid-template-columns: repeat(1, 1fr);
}

@media (min-width: 750px) {
  .devices {
    grid-template-columns: repeat(2, 1fr);
  }
}

@media (min-width: 1250px) {
  .devices {
    grid-template-columns: repeat(3, 1fr);
  }
}

@media (min-width: 1750px) {
  .devices {
    grid-template-columns: repeat(4, 1fr);
  }
}

@media (min-width: 2250px) {
  .devices {
    grid-template-columns: repeat(3, 1fr);
  }
}
</style>
