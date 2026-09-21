<script setup>
import Process from "@/Process.vue";
import {useRoute} from "vue-router";
import {ref} from "vue";
import conf from "@/config";

var macAddress = ref(useRoute().params.macAddress);
var data = ref({});
var config = ref({});
await reload();

async function reload() {
  var forbidden=await (await fetch(conf.server + 'process/forbidden')).json(); 
  var xdata = await fetch(conf.server + 'process/' + macAddress.value);
  xdata = await xdata.json();
  var tdata = {};

  for (var slot in xdata) {
    if (!xdata[slot]) {
      continue;
    }
    for (var p in xdata[slot].processes) {
      var fullPath = xdata[slot].processes[p];
      var exeName = fullPath.split(/[/\\]/);
      exeName = exeName[exeName.length - 1];
      if (!tdata[exeName]) {
        tdata[exeName] = {
          fullPath: fullPath, 
          hours: [],
          isForbidden: isForbidden(fullPath, exeName, forbidden)
        };
      }
      tdata[exeName].hours.push(xdata[slot].hour);
    }
  }
  data.value = tdata;
}
function isForbidden(fullPath, exeName, forbidden) {
  return !!forbidden.find(x=>x.toLowerCase()===exeName.toLowerCase() || x.toLowerCase()===fullPath.toLowerCase());
}
</script>

<template>
  <div>
    <Process v-for="(p,name) in data" :key="name" :exeName="name" :data="p" @mustReload="reload"/>
  </div>
</template>

<style module>

</style>