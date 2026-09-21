<script setup>
  import {useRouter} from "vue-router";

  useRouter().push(localStorage.getItem('mode') || 'State');
</script>

<template>
<div></div>
</template>
