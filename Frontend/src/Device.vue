<script setup>
import conf from "@/config";
import EditHost from "@/EditHost.vue";
import {ref} from "vue";

const props = defineProps({device: Object, showDisplayControls: Boolean});
const emits = defineEmits(["mustReload"]);
const isEditing = ref(false);

function prettyMac(str) {
  return str.replace(/[0-9A-F]{2,2}/ig, '$&:').replace(/:$/, '');
}

async function show() {
  await fetch(conf.server + 'unhide/' + props.device.macAddress);
  emits('mustReload');
}

async function hide() {
  await fetch(conf.server + 'hide/' + props.device.macAddress);
  emits('mustReload');
}

function editFinished(v) {
  if (v === true) {
    emits('mustReload');
  }
  isEditing.value = false;
}
</script>

<template>
  <div :class="$style.device">
    <EditHost :device="device" v-if="isEditing" @close="editFinished"/>
    <p :class="$style.name">
      <span :class="$style[device.isOnline?'online':'offline']"></span>
      <template v-if="device.isKnown">
        <strong :class="$style.knownHost">{{ device.name }}</strong>
      </template>
      <template v-else>{{ device.hostname }}</template>

      <a :class="$style.label" href="#" @click.stop.prevent="isEditing=true">✎</a>
      <template v-if="showDisplayControls">
        <a href="#" :class="$style.hidden" title="Спрятать" v-if="device.isHidden"
           @click.stop.prevent="show">СПРЯТАН</a>
        <a href="#" :class="$style.visible" title="Показать" v-else @click.stop.prevent="hide">ВИДЕН</a>
      </template>
    </p>
    <p v-if="device.groups.length">
      Группы:
      <code v-for="g in device.groups" :key="g" :class="$style.label">{{ g }}</code>
    </p>
    <p>
      <code :class="$style.label" :title="device.macAddressInfo">{{ prettyMac(device.macAddress) }}</code>
      <code v-for="ip in device.ipAddress" :key="ip" :class="$style.label">{{ ip }}</code>
    </p>
    <router-link v-if="device.hasProcessReport" :to="`/processes/${device.macAddress}`">Отчёт по процессам</router-link>
  </div>
</template>

<style module>
.device {
  margin: 0.25em;
  padding: 0.25em .5em;
  border: 1px solid #ccc;
  background: #eee;
}

.name {
}

.knownHost {
  font-weight: bold;
}

.onlineMarker {
  display: inline-block;
  font-size: 0.7em;
  width: 1em;
  height: 1em;
  box-shadow: inset 0 0 5px rgba(0, 0, 0, 0.5);
  border-radius: 999px;
  margin: 0 5px 0 0;
}

.online {
  composes: onlineMarker;
  background: #0f0;
}

.offline {
  composes: onlineMarker;
  background: #f00;
}

.label {
  display: inline-block;
  padding: 0px 5px;
  margin: 0 5px;
  background: #aaa;
  font-weight: bold;
  font-size: 0.7em;
  border-radius: 5px;
}

.label:first-child {
  margin-left: 0;
}

.hidden {
  composes: label;
  color: #f00 !important;
}


.visible {
  composes: label;
  color: #0f0 !important;
}
</style>