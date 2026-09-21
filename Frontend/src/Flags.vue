<script setup>
import {ref} from "vue";
import conf from "@/config";

const data = ref({});
await reload();

async function reload() {
  var xdata = await fetch(conf.server + 'defines');
  data.value = (await xdata.json());
}

async function setFlag(flag, value) {
  await fetch(conf.server + 'flag/' + flag + '/' + (value ? 'set' : 'unset'));
  await reload();
}
</script>

<template>
  <div>
    <div v-for="(val,flag) in data.flags" :key="flag" @click.stop.prevent="setFlag(flag, !val)">
      <span :class="$style.set" v-if="val">✓</span>
      <span :class="$style.unset" v-else>&times;</span>
      {{ flag }}
    </div>
  </div>
</template>

<style module>
.marker{
  font-size: 125%;
  font-weight: bold;
}
.set {
  composes: marker;
  color: #0f0;
}

.unset {
  composes: marker;
  color: #f00;
}
</style>