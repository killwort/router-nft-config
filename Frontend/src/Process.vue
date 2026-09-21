<script setup>
import {ref} from "vue";
import Timeline from "@/Timeline.vue";
import conf from "@/config";

var props = defineProps({exeName: String, data: Object});
const emits = defineEmits(["mustReload"]);
var expanded = ref(false);


async function allow() {
  await fetch(conf.server + 'process/allow', {
    headers: {"Content-Type": "application/json"},
    method: "POST",
    body: JSON.stringify(props.exeName)
  });
  await fetch(conf.server + 'process/allow', {
    headers: {"Content-Type": "application/json"},
    method: "POST",
    body: JSON.stringify(props.data.fullPath)
  });
  emits("mustReload");
}

async function forbid(name) {
  await fetch(conf.server + 'process/forbid', {
    headers: {"Content-Type": "application/json"},
    method: "POST",
    body: JSON.stringify(name)
  });
  emits("mustReload");
}
</script>

<template>
  <div :class="$style.wrapper">
    <div @click="expanded=!expanded" :class="$style[data.isForbidden?'forbidden':'normal']">{{ exeName }}</div>
    <div v-if="expanded" :class="$style.data">
      <a href="#" v-if="data.isForbidden" @click.stop.prevent="allow">Разрешить</a>
      <template v-else>
        <a href="#" @click.stop.prevent="forbid(exeName)">Запретить по имени файла</a>
        &nbsp;
        <a href="#" @click.stop.prevent="forbid(data.fullPath)">Запретить по полному пути</a>
        <br/>
      </template>
      {{ data.fullPath }}
      <br/>
      <Timeline :dates="data.hours"/>
    </div>
  </div>
</template>

<style module>
.wrapper{
  border: 1px solid #ccc;
  margin: 3px 0;
}
.header{
  cursor: pointer;
  margin-bottom: 5px;
  border-bottom: 1px solid #ccc;
  padding: 0 5px;
}
.header:last-child{
  margin-bottom: 0;
  border-bottom: none;
}
.normal {
  composes: header;
}

.forbidden {
  composes: header;
  color: #f00;
}
.data{
  padding: 0 5px;
}
</style>