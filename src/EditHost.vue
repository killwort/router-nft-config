<script setup>
import {defineProps, ref} from "vue";
import config from "@/config";

const props = defineProps(["host"]);
const emit = defineEmits(['close']);
const editedHost = ref(Object.assign({
  name: '',
  class: '',
  groups: [],
  noBlock: false
},props.host.knownDevice));

async function save() {
  await config.save(props.host.mac, editedHost.value);
  emit('close', true);
}
</script>
<template>
  <div :class="$style.wrapper">
    <div :class="$style.dialog">
      <h3>Edit host</h3>
      <div>
        <input type="text" v-model="editedHost.name" placeholder="Название"/>
      </div>
      <div>
        <span :class="devicons[editedHost.class]"></span>
        <select v-model="editedHost.class">
          <option value="_1_phone">Телефон</option>
          <option value="_2_pc">Компьютер</option>
          <option value="_2_laptop">Ноутбук</option>
          <option value="_9_printer">Принтер</option>
          <option value="_9_netdev">Сетевое устройство</option>
          <option value="_9_TV">TV</option>
        </select>
      </div>      
      <div>
        <label><input type="checkbox" v-model="editedHost.noBlock"/> Не блокируемый хост</label>
      </div>
      <div>
        <div v-for="(group,i) in editedHost.groups" :key="i">
          <input type="text" v-model="editedHost.groups[i]"/><button @click="editedHost.groups.splice(i,1)">Удалить</button>
        </div>
        <button @click="editedHost.groups.push('')">Добавить группу</button>
      </div>
      <button @click="save">Сохранить</button>
      <button @click="$emit('close')">Отмена</button>
    </div>
  </div>
</template>
<style module="devicons" src="./devicons.css" />
<style module>
.wrapper {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  position: absolute;
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