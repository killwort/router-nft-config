<script setup>
</script>

<template>
  <div :class="$style.layout">
    <div :class="$style.navbar">
      <router-link to="/state">Сеть</router-link>
      <router-link to="/flags">Флаги</router-link>
    </div>
    <div :class="$style.content">
      <Suspense timeout="0">
        <router-view/>
        <template #fallback>
          <div :class="$style.loading"></div>
        </template>
      </Suspense>
    </div>
  </div>
</template>

<style module>

.layout {
  display: flex;
  flex-direction: column;
  width: 100%;
}

.navbar {
  display: flex;
  flex-direction: row;
}

.content {

}

.loading {
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

@media (min-width: 1024px) {
}
</style>
