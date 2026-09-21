<script setup>
import {defineProps, ref} from "vue";
import conf from "@/config";

const props = defineProps({device: Object});
const emit = defineEmits(['close']);
const name = ref(props.device.name || '');
const groups = ref(props.device.groups?.slice() || []);

async function save() {
  await fetch(conf.server + 'host/' + props.device.macAddress, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({
      name: name.value,
      groups: groups.value
    })});
  emit('close', true);
}
</script>
<template>
  <div :class="$style.wrapper">
    <div :class="$style.dialog">
      <h3>Правка устройства</h3>
      <div>
        <input type="text" v-model="name" placeholder="Название"/>
      </div>
      <div>
        <div v-for="(group,i) in groups" :key="i">
          <input type="text" v-model="groups[i]"/>
          <button @click="groups.splice(i,1)">Удалить</button>
        </div>
        <button @click="groups.push('')">Добавить группу</button>
      </div>
      <button @click="save">Сохранить</button>
      <button @click="$emit('close')">Отмена</button>
    </div>
  </div>
</template>
<style module="devicons" src="./devicons.css"/>
<style module>
.wrapper {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, .33);
  z-index: 1000;
}

.dialog {
  background: #ccc;
  padding: 1em;
}
</style>