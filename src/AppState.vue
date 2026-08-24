<script setup>
import {ref} from "vue";
import conf from '@/config';

var blocks = ref(await loadBlocks());

async function loadBlocks() {
  var data = await (await fetch(conf.server + 'dnsblocks')).text();
  data = data.split('------');
  data = {
    possibleApps: data[0].split('\n').filter(x => !!x),
    blocked: data[1].split('\n').filter(x => !!x),
    blockedAll: data[2].split('\n').filter(x => !!x),
  }
  var rv = [];
  for (var d of data.possibleApps) {
    rv.push({
      app: d,
      blocked: data.blocked.indexOf(d) !== -1,
      blockedAll: data.blockedAll.indexOf(d) !== -1
    });
  }
  return rv;
}

async function enable(app) {
  await fetch(conf.server + 'dnsunblock?' + app.app);
  blocks.value = await loadBlocks();
}

async function enableAll(app) {
  await fetch(conf.server + 'dnsunblockall?' + app.app);
  blocks.value = await loadBlocks();
}

async function disable(app) {
  await fetch(conf.server + 'dnsblock?' + app.app);
  blocks.value = await loadBlocks();
}

async function disableAll(app) {
  await fetch(conf.server + 'dnsblockall?' + app.app);
  blocks.value = await loadBlocks();
}
</script>

<template>
  <div :class="$style.table">
    <div></div>
    <div>Разрешено детям</div>
    <div>Разрешено всем</div>
    <div v-for="app in blocks" :key="app.app" :class="$style.row">
      {{ app.app }}:
      <label>
        <button v-if="app.blocked" :class="$style.enableButton" @click="enable(app)"></button>
        <button v-else :class="$style.disableButton" @click="disable(app)"></button>
      </label>

      <label>
        <button v-if="app.blockedAll" :class="$style.enableButton" @click="enableAll(app)"></button>
        <button v-else :class="$style.disableButton" @click="disableAll(app)"></button>
      </label>

    </div>
  </div>
</template>

<style module>
.table {
  display: grid;
  grid-template-columns: repeat(3, max-content);
  grid-gap: 10px;
}

.row {
  display: contents;
}

.switchButton {
  outline: none;
  border: 1px solid #070;
  margin: 1px;
  border-radius: 35px;
  width: 35px;
  height: 20px;
  display: block;
  margin: 0 auto;
  transition: all ease .33s;
  position: relative;
}

.switchButton:after {
  content: 'ВЫКЛ      ВКЛ';
  display: block;
  margin: 0 -10px 0 -41px;
  color: gray;
}

.switchButton:before {
  content: ' ';
  display: block;
  border-radius: 35px;
  width: 16px;
  height: 16px;
  background: rgba(255, 255, 255, .6);
  border: 1px solid black;
  position: absolute;
  transition: all ease .33s;
  top: 1px;
}

.enableButton {
  composes: switchButton;
  color: #f00;
  background-color: #500;
  border-color: #700;
}

.enableButton:before {
  left: 1px;
}

.disableButton {
  composes: switchButton;
  color: #0f0;
  background-color: #050;
  border-color: #070;
}

.disableButton:before {
  left: 16px;
}
</style>