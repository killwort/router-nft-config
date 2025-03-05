<template>
  <label><input type="checkbox" v-model="showOffline"/> Показать известные устройства не в сети</label>
  <label><input type="checkbox" v-model="showHidden"/> Показать не блокируемые устройства</label>
  <ul :class="$style.devices">
    <li v-for="arpItem in arpCache.items" :key="arpItem.ip"
        :class="(arpItem.l3Blocks||arpItem.l2Blocks)?$style.hardBlock:arpItem.dnsBlocks?$style.softBlock:$style.noBlock">
      <div :class="$style[arpItem.knownDevice?.class||'_9_unknown']"></div>
      <h3 :class="$style.name">
        <strong v-if="arpItem.knownDevice">{{ arpItem.knownDevice.name }}</strong>
        <template v-else>
          {{ arpItem.mac }}
        </template>
      </h3>
      <p :class="$style.address">
        <template v-if="arpItem.ip">{{ arpItem.ip }}</template>
        <template v-else>Не в сети</template>
      </p>
      <div :class="$style.leases" v-if="!arpItem.knownDevice">
        <p v-for="lease in arpItem.leases">{{ lease.host }} = {{ lease.dclass }}</p>
      </div>
      <div :class="$style.buttons1" v-if="!arpItem.knownDevice?.noBlock">
        <label>YouTube
          <button v-if="arpItem.dnsBlocks" :class="$style.enableButton" @click="exemptDns(arpItem)"></button>
          <button v-else :class="$style.disableButton" @click="blockDns(arpItem)"></button>
        </label>
      </div>
      <div :class="$style.buttons2" v-if="!arpItem.knownDevice?.noBlock">
        <label>
          Интернет
          <button v-if="arpItem.l2Blocks" :class="$style.enableButton" @click="unblockL2(arpItem)">
          </button>
          <button v-else :class="$style.disableButton" @click="blockL2(arpItem)"></button>
        </label>
      </div>
    </li>
  </ul>
</template>

<script setup>
import conf from "./config.json";
import groupBy from "lodash/groupBy";
import uniqBy from "lodash/uniqBy";
import flatMap from "lodash/flatMap";
import some from "lodash/some";
import {reactive, ref, watch} from "vue";

const showHidden = ref(false);
const showOffline = ref(false);
let arpCache = reactive({items: await reload()});


watch(showHidden, async () => arpCache.items = await reload());
watch(showOffline, async () => arpCache.items = await reload());

async function exemptDns(arpRecord) {
  //await fetch(conf.server + 'add-dns-exempt?' + arpRecord.mac);
  await fetch(conf.server + 'add-to-set?dnsunblock/' + arpRecord.mac);
  arpCache.items = await reload();
}

async function blockDns(arpRecord) {
  //await Promise.all(arpRecord.relatedPortRedirects.map(r => fetch(conf.server + 'delete-rule?' + r.table + '/' + r.chain + '/' + r.handle)));
  await fetch(conf.server + 'remove-from-set?dnsunblock/' + arpRecord.mac);
  arpCache.items = await reload();
}

async function blockL2(arpRecord) {
  await fetch(conf.server + 'add-to-set?macblock/' + arpRecord.mac);
  await fetch(conf.server + 'add-to-set?ipblock/' + arpRecord.ip);
  arpCache.items = await reload();
}

async function blockL3(arpRecord) {
  await fetch(conf.server + 'add-to-set?ipblock/' + arpRecord.ip);
  arpCache.items = await reload();
}

async function unblockL2(arpRecord) {
  await fetch(conf.server + 'remove-from-set?macblock/' + arpRecord.mac);
  await fetch(conf.server + 'remove-from-set?ipblock/' + arpRecord.ip);
  arpCache.items = await reload();
}

async function unblockL3(arpRecord) {
  await fetch(conf.server + 'remove-from-set?ipblock/' + arpRecord.ip);
  arpCache.items = await reload();
}

async function reload() {
  const [arpCache, leases, ruleset] = await Promise.all([
    fetch(conf.server + 'arp-cache').then(x => x.text()).then(x => parseArp(x)),
    fetch(conf.server + 'leases').then(x => x.json()),
    fetch(conf.server + 'list-ruleset').then(x => x.json())
  ]);

  const tables = {};
  const allChains = [];
  ruleset.nftables.forEach(item => {
    if (item.table) {
      item.table.chains = {};
      item.table.sets = {};
      tables[item.table.name] = item.table;
    } else if (item.chain) {
      item.chain.rules = [];
      tables[item.chain.table].chains[item.chain.name] = item.chain;
      if (tables[item.chain.table].family == 'ip')
        allChains.push(item.chain);
    } else if (item.rule) {
      tables[item.rule.table].chains[item.rule.chain].rules.push(item.rule);
    } else if (item.set) {
      if (!item.set.elem) {
        item.set.elem = [];
      }
      tables[item.set.table].sets[item.set.name] = item.set;
    }
  });
  const tablesByType = groupBy(allChains, c => c.type);
  Object.keys(conf.knownDevices).filter(kd => !some(arpCache, i => i.mac == kd)).forEach(kd => arpCache.push({
    ip: '',
    mac: kd
  }));

  for (var i = 0; i < arpCache.length; i++) {
    arpCache[i].leases = uniqBy(leases.filter(l => l != null && (l.host || l.dclass) && l.mac === arpCache[i].mac), l => l.host + l.dclass);
    arpCache[i].knownDevice = conf.knownDevices[arpCache[i].mac];
    arpCache[i].relatedPortRedirects = flatMap((tablesByType.nat || []).filter(c => c.hook == 'prerouting'), c => c.rules).filter(isRelated(arpCache[i]));
    arpCache[i].relatedFilters = flatMap((tablesByType.filter || []).filter(c => c.hook == 'input' || c.hook == 'output' || c.hook == 'forward'), c => c.rules).filter(isRelated(arpCache[i]));
    arpCache[i].dnsBlocks = tables.nat.sets.dnsunblock?.elem.indexOf(arpCache[i].mac) == -1;
    arpCache[i].l3Blocks = tables.nat.sets.ipblock?.elem.indexOf(arpCache[i].ip) !== -1;
    arpCache[i].l2Blocks = tables.nat.sets.macblock?.elem.indexOf(arpCache[i].mac) !== -1;
  }
  arpCache.sort((a, b) => {
    if (a.knownDevice && b.knownDevice) {
      var rv = a.knownDevice.class.localeCompare(b.knownDevice.class);
      if (rv === 0) return (a.host || '').localeCompare(b.host);
      return rv;
    }
    if (a.knownDevice) return -1;
    if (b.knownDevice) return 1;
    return (a.host || '').localeCompare(b.host);
  });
  return arpCache.filter(x => (showHidden.value || !x.knownDevice?.noBlock) && (showOffline.value || x.ip || (!x.dnsBlocks || x.l2Blocks || x.l3Blocks)));
}

function isL2Expr(expr) {
  return expr.match?.left?.payload?.protocol == 'ether';
}

function isL3Expr(expr) {
  return expr.match?.left?.payload?.protocol == 'ip';
}

function isRelated(arpRec) {
  return rule => some(rule.expr,
      expr => {
        if (expr.match && (expr.match.left?.payload?.field == 'saddr' || expr.match.left?.payload?.field == 'daddr')) {
          switch (expr.match.left?.payload?.protocol) {
            case 'ether':
              return (expr.match.right == arpRec.mac && expr.match.op == '==') || (expr.match.right != arpRec.mac && expr.match.op == '!=')
              break;
            case 'ip':
              return (expr.match.right == arpRec.ip && expr.match.op == '==') || (expr.match.right != arpRec.ip && expr.match.op == '!=')
              break;
          }
        }
        return false;
      });
}

function parseArp(src) {
  return src.split('\n').map(l => {
    const parts = l.replace(/\s+/, ' ').split(' ');
    return {
      ip: parts[0],
      mac: parts[4]
    };
  }).filter(x => !!x.ip);
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


.devices > li {
  display: grid;
  grid-template-areas: "i n b1" "i a b2" ". l .";
  padding: 1em;
  margin: 2px;
  border: 1px solid #ccc;
  flex: 0 0 auto;
  border-radius: 3px;
  grid-template-columns: max-content 1fr 90px;
}

.name {
  grid-area: n;
}

.address {
  grid-area: a;
}

.leases {
  grid-area: l;
}

.filler {
  flex: 1 1 auto;
}

.hardBlock {
  background: rgba(128, 0, 0, .5);
}

.softBlock {
  background: rgba(0, 128, 0, .5);
}

.noBlock {
  background: rgba(128, 128, 0, .5);
}

.devicon {
  grid-area: i;
  font-size: 48px;
  display: block;
  width: 48px;
  height: 48px;
  margin: 0.33em 1em 0.33em 0;
  background-size: 48px 48px;
  background-position: center center;
  background-repeat: no-repeat;
}

._1_phone {
  composes: devicon;
  background-image: url('assets/_1_phone.svg');
}

._9_tv {
  composes: devicon;
  background-image: url('assets/_9_tv.svg');
}

._2_laptop {
  composes: devicon;
  background-image: url('assets/_2_laptop.svg');
}

._2_pc {
  composes: devicon;
  background-image: url('assets/_2_pc.svg');
}

._9_printer {
  composes: devicon;
  background-image: url('assets/_9_printer.svg');
}

._9_netdev {
  composes: devicon;
  background-image: url('assets/_9_netdev.svg');
}

._9_unknown {
  composes: devicon;
  background-image: url('assets/_9_unknown.svg');
}

.buttons {
  grid-area: b;
  display: flex;
  text-align: center;
  margin: 0 0 0 0;
}

.buttons1 {
  composes: buttons;
  grid-area: b1;
}

.buttons2 {
  composes: buttons;
  grid-area: b2;
}

.buttons > * {
  display: block;
  flex: 1 1 auto;
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
