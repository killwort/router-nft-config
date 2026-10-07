<script setup>
import { computed } from 'vue';

const props = defineProps({
  dates: {
    type: Array,
    required: true
  }
});

const hours = Array.from({ length: 24 }, (_, i) => i);

function dateKey(date) {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, '0');
  const d = String(date.getDate()).padStart(2, '0');

  return `${y}-${m}-${d}`;
}

function startOfDay(date) {
  return new Date(
      date.getFullYear(),
      date.getMonth(),
      date.getDate()
  );
}

function addDays(date, days) {
  const result = new Date(date);
  result.setDate(result.getDate() + days);
  return result;
}

const rows = computed(() => {
  if (!props.dates.length)
    return [];

  /*
   * Конвертируем входные ISO даты в локальные date/hour.
   *
   * Например:
   * 2026-10-06T22:00:00Z
   *
   * в UTC+3 попадёт в:
   * 2026-10-07, hour=1
   */
  const parsed = props.dates.map(x => new Date(x));

  const active = new Set(
      parsed.map(date => `${dateKey(date)}:${date.getHours()}`)
  );

  const minDate = startOfDay(
      new Date(Math.min(...parsed.map(x => x.getTime())))
  );

  const maxDate = startOfDay(
      new Date(Math.max(...parsed.map(x => x.getTime())))
  );

  const result = [];

  for (
      let day = minDate;
      day <= maxDate;
      day = addDays(day, 1)
  ) {
    const key = dateKey(day);

    const cells = hours.map(hour => {
      const isActive = active.has(`${key}:${hour}`);

      const previousActive =
          hour > 0 &&
          active.has(`${key}:${hour - 1}`);

      const nextActive =
          hour < 23 &&
          active.has(`${key}:${hour + 1}`);

      const date = new Date(
          day.getFullYear(),
          day.getMonth(),
          day.getDate(),
          hour
      );

      return {
        hour,
        date,
        active: isActive,

        // Скругляем только край непрерывного участка
        start: isActive && !previousActive,
        end: isActive && !nextActive
      };
    });

    result.push({
      key,
      date: new Date(day),
      cells
    });
  }

  return result;
});

function formatDay(date) {
  return date.toLocaleDateString(undefined, {
    day: '2-digit',
    month: '2-digit'
  });
}

function formatDateTime(date) {
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
  <div v-if="rows.length" class="timeline">
    <!-- header -->
    <div class="day-header"></div>

    <div
        v-for="hour in hours"
        :key="hour"
        class="hour-header"
    >
      {{ hour }}
    </div>

    <!-- days -->
    <template v-for="row in rows" :key="row.key">
      <div
          class="day-label"
          :title="row.date.toLocaleDateString()"
      >
        {{ formatDay(row.date) }}
      </div>

      <div
          v-for="cell in row.cells"
          :key="cell.hour"
          class="hour-cell"
          :class="{
          active: cell.active,
          start: cell.start,
          end: cell.end
        }"
          :title="formatDateTime(cell.date)"
      />
    </template>
  </div>
</template>

<style scoped>
.timeline {
  display: grid;

  /*
   * Первая колонка — дата,
   * остальные 24 — часы.
   */
  grid-template-columns: max-content repeat(24, 10px);

  align-items: center;

  column-gap: 0;
  row-gap: 3px;

  width: max-content;
}

/* Верхний левый угол */
.day-header {
  width: 52px;
}

/* 0..23 */
.hour-header {
  width: 10px;

  font-size: 8px;
  line-height: 10px;
  text-align: center;

  color: #777;

  /*
   * Цифры 10..23 шире клетки,
   * разрешаем им выходить за её границы.
   */
  overflow: visible;
  white-space: nowrap;
}

/* Дата слева */
.day-label {
  padding-right: 7px;

  font-size: 11px;
  line-height: 10px;

  white-space: nowrap;
  text-align: right;
}

/* Один час */
.hour-cell {
  width: 10px;
  height: 10px;

  box-sizing: border-box;
}

/* Активный час */
.hour-cell.active {
  background: #1976d2;
}

/* Начало непрерывного участка */
.hour-cell.active.start {
  border-top-left-radius: 4px;
  border-bottom-left-radius: 4px;
}

/* Конец непрерывного участка */
.hour-cell.active.end {
  border-top-right-radius: 4px;
  border-bottom-right-radius: 4px;
}
</style>