<script setup>
import {computed} from 'vue';

const props = defineProps({
  dates: {
    type: Array,
    required: true
  }
});

const HOUR = 60 * 60 * 1000;

const timeline = computed(() => {
  if (!props.dates.length)
    return [];

  const active = new Set(
      props.dates.map(x => Math.floor(new Date(x).getTime() / HOUR))
  );

  const min = Math.min(...active);
  const max = Math.max(...active);

  const result = [];

  for (let hour = min; hour <= max; hour++) {
    const isActive = active.has(hour);

    result.push({
      hour,
      active: isActive,
      start: isActive && !active.has(hour - 1),
      end: isActive && !active.has(hour + 1),
      date: new Date(hour * HOUR)
    });
  }

  return result;
});

const minDate = computed(() =>
    timeline.value.length ? timeline.value[0].date : null
);

const maxDate = computed(() =>
    timeline.value.length ? timeline.value.at(-1).date : null
);

function formatDate(date) {
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit'
  });
}
</script>

<template>
  <div v-if="timeline.length" :class="$style['timeline-wrapper']">
    <span :class="$style['timeline-date']">
      {{ formatDate(minDate) }}
    </span>

    <div :class="$style.timeline">
      <div
          v-for="item in timeline"
          :key="item.hour"
          :class="{
            [$style['timeline-hour']]:true,
          [$style.active]: item.active,
          [$style.start]: item.start,
          [$style.end]: item.end
        }"
          :title="formatDate(item.date)"
      />
    </div>

    <span :class="$style['timeline-date']">
      {{ formatDate(maxDate) }}
    </span>
  </div>
</template>

<style module>
.timeline-wrapper {
  display: flex;
  align-items: center;
  gap: 8px;
}

.timeline {
  display: flex;
  align-items: center;
}

.timeline-hour {
  width: 10px;
  height: 10px;
  box-sizing: border-box;

  border: 1px solid #ccc;
}

.timeline-hour.active {
  background: #1976d2;
  border-color: #1976d2;
}

/* Левая сторона последовательности */
.timeline-hour.active.start {
  border-top-left-radius: 4px;
  border-bottom-left-radius: 4px;
}

/* Правая сторона последовательности */
.timeline-hour.active.end {
  border-top-right-radius: 4px;
  border-bottom-right-radius: 4px;
}

.timeline-date {
  white-space: nowrap;
  font-size: 12px;
}
</style>