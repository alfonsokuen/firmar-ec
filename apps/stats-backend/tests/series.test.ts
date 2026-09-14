import { describe, expect, test } from 'vitest';
import {
  WINDOW,
  bumpCount,
  combinedKey,
  dayStr,
  ecCivil,
  eventCombinedKeys,
  hourStr,
  isGranularity,
  minuteStr,
  monthStr,
  parseCounts,
  periodsFor,
  serializeCounts,
  weekStartStr,
} from '../src/services/series.js';

/**
 * series.test.ts — pure date-bucketing + storage codec for the usage series.
 *
 * The subtle part is the time zone: buckets must land on the Ecuador-local
 * (UTC−5) calendar day, not UTC, so a counter read at night doesn't roll over
 * to "tomorrow" before midnight in Quito. Epochs below are written in UTC and
 * the expected bucket is the EC-local day.
 */

// EC-local 2026-06-22 12:00 → 17:00Z.
const EC_NOON_JUN22 = Date.UTC(2026, 5, 22, 17, 0, 0);

describe('ecCivil — UTC−5 day boundary', () => {
  test('late UTC evening is still the same EC day', () => {
    // 2026-06-22 02:00Z → EC 2026-06-21 21:00 → day belongs to the 21st.
    expect(dayStr(ecCivil(Date.UTC(2026, 5, 22, 2, 0, 0)))).toBe('2026-06-21');
  });
  test('UTC morning maps to the EC day', () => {
    expect(dayStr(ecCivil(Date.UTC(2026, 5, 22, 10, 0, 0)))).toBe('2026-06-22');
  });
  test('monthStr follows the EC day', () => {
    // 2026-07-01 03:00Z → EC 2026-06-30 → month 2026-06.
    expect(monthStr(ecCivil(Date.UTC(2026, 6, 1, 3, 0, 0)))).toBe('2026-06');
  });
});

describe('weekStartStr — ISO Monday in EC time', () => {
  test('always returns a Monday', () => {
    const monday = weekStartStr(EC_NOON_JUN22);
    const [y, m, d] = monday.split('-').map(Number);
    expect(new Date(Date.UTC(y, m - 1, d)).getUTCDay()).toBe(1);
  });
  test('stable across days within the same EC week', () => {
    const a = weekStartStr(Date.UTC(2026, 5, 23, 17, 0, 0)); // Tue EC
    const b = weekStartStr(Date.UTC(2026, 5, 25, 17, 0, 0)); // Thu EC
    expect(a).toBe(b);
  });
});

describe('periodsFor — window length, order, boundaries', () => {
  test('day: 30 ascending consecutive days ending today', () => {
    const p = periodsFor('day', EC_NOON_JUN22);
    expect(p).toHaveLength(WINDOW.day);
    expect(p[p.length - 1]).toBe('2026-06-22');
    for (let i = 1; i < p.length; i++) {
      const [py, pm, pd] = p[i - 1].split('-').map(Number);
      const [cy, cm, cd] = p[i].split('-').map(Number);
      const diff = (Date.UTC(cy, cm - 1, cd) - Date.UTC(py, pm - 1, pd)) / 86_400_000;
      expect(diff).toBe(1);
    }
  });

  test('week: 12 Mondays, 7 days apart, newest last', () => {
    const p = periodsFor('week', EC_NOON_JUN22);
    expect(p).toHaveLength(WINDOW.week);
    expect(p[p.length - 1]).toBe(weekStartStr(EC_NOON_JUN22));
    for (const wk of p) {
      const [y, m, d] = wk.split('-').map(Number);
      expect(new Date(Date.UTC(y, m - 1, d)).getUTCDay()).toBe(1);
    }
  });

  test('month: 12 months crossing the year boundary', () => {
    const feb = Date.UTC(2026, 1, 15, 17, 0, 0); // EC 2026-02-15
    const p = periodsFor('month', feb);
    expect(p).toHaveLength(WINDOW.month);
    expect(p[0]).toBe('2025-03');
    expect(p[p.length - 1]).toBe('2026-02');
  });

  test('year: last 5 years ending this year', () => {
    const p = periodsFor('year', EC_NOON_JUN22);
    expect(p).toEqual(['2022', '2023', '2024', '2025', '2026']);
  });
});

describe('boundary wrap (the off-by-one class this code is most exposed to)', () => {
  // EC 2027-01-01 12:00 → 17:00Z. 2027-01-01 is a Friday → its Monday is 2026-12-28.
  const JAN1_2027 = Date.UTC(2027, 0, 1, 17, 0, 0);

  test('weekStartStr resolves early-January to the previous-year Monday', () => {
    expect(weekStartStr(JAN1_2027)).toBe('2026-12-28');
  });

  test('periodsFor(week) ending at a year boundary stays all-Mondays, 7 apart', () => {
    const wk = periodsFor('week', JAN1_2027);
    expect(wk).toHaveLength(WINDOW.week);
    expect(wk[wk.length - 1]).toBe('2026-12-28');
    for (let i = 1; i < wk.length; i++) {
      const [py, pm, pd] = wk[i - 1].split('-').map(Number);
      const [cy, cm, cd] = wk[i].split('-').map(Number);
      expect((Date.UTC(cy, cm - 1, cd) - Date.UTC(py, pm - 1, pd)) / 86_400_000).toBe(7);
    }
  });

  test('periodsFor(day) crosses month+year boundary with 30 consecutive days', () => {
    const jan5 = Date.UTC(2027, 0, 5, 17, 0, 0); // EC 2027-01-05
    const days = periodsFor('day', jan5);
    expect(days).toHaveLength(WINDOW.day);
    expect(days[days.length - 1]).toBe('2027-01-05');
    expect(days[0]).toBe('2026-12-07'); // 29 days earlier, back into the prior year
    for (let i = 1; i < days.length; i++) {
      const [py, pm, pd] = days[i - 1].split('-').map(Number);
      const [cy, cm, cd] = days[i].split('-').map(Number);
      expect((Date.UTC(cy, cm - 1, cd) - Date.UTC(py, pm - 1, pd)) / 86_400_000).toBe(1);
    }
  });
});

describe('combined storage codec', () => {
  test('parseCounts is tolerant of null and garbage', () => {
    expect(parseCounts(null)).toEqual({ sign: 0, verify: 0, cert: 0, install: 0, lote: 0 });
    expect(parseCounts('not json')).toEqual({
      sign: 0,
      verify: 0,
      cert: 0,
      install: 0,
      lote: 0,
    });
    expect(parseCounts('{"s":3,"v":1,"c":2,"i":4,"l":5}')).toEqual({
      sign: 3,
      verify: 1,
      cert: 2,
      install: 4,
      lote: 5,
    });
    // negatives clamp to 0, floats floor, missing fields → 0
    expect(parseCounts('{"s":-5,"v":1.9}')).toEqual({
      sign: 0,
      verify: 1,
      cert: 0,
      install: 0,
      lote: 0,
    });
  });
  // 2026-08-24 — `install` (`i`) se añadió después de que ya hubiera series
  // guardadas. Este test fija la promesa del comentario de parseCounts: los
  // valores antiguos, sin `i`, se leen sin migración y sin perder sus contadores.
  test('parseCounts reads pre-install values written before the `i` field existed', () => {
    expect(parseCounts('{"s":12,"v":5,"c":1}')).toEqual({
      sign: 12,
      verify: 5,
      cert: 1,
      install: 0,
      lote: 0,
    });
  });
  // 2026-09-10 — mismo caso para `lote` (`l`), el quinto campo.
  test('parseCounts reads pre-lote values written before the `l` field existed', () => {
    expect(parseCounts('{"s":12,"v":5,"c":1,"i":2}')).toEqual({
      sign: 12,
      verify: 5,
      cert: 1,
      install: 2,
      lote: 0,
    });
  });
  test('serialize/parse round-trips', () => {
    const c = { sign: 7, verify: 4, cert: 2, install: 3, lote: 6 };
    expect(parseCounts(serializeCounts(c))).toEqual(c);
  });
  test('bumpCount increments one type immutably', () => {
    const a = { sign: 1, verify: 2, cert: 3, install: 0, lote: 0 };
    expect(bumpCount(a, 'verify')).toEqual({ sign: 1, verify: 3, cert: 3, install: 0, lote: 0 });
    expect(a).toEqual({ sign: 1, verify: 2, cert: 3, install: 0, lote: 0 }); // original untouched
  });
  test('bumpCount increments lote immutably', () => {
    const a = { sign: 1, verify: 2, cert: 3, install: 0, lote: 4 };
    expect(bumpCount(a, 'lote')).toEqual({ sign: 1, verify: 2, cert: 3, install: 0, lote: 5 });
  });
});

describe('minute & hour (EC-local, with read windows)', () => {
  test('minuteStr/hourStr land on the EC-local clock, not UTC', () => {
    // 2026-06-22 02:00Z → EC 2026-06-21 21:00.
    const ms = Date.UTC(2026, 5, 22, 2, 0, 0);
    expect(minuteStr(ms)).toBe('2026-06-21T21:00');
    expect(hourStr(ms)).toBe('2026-06-21T21');
  });
  test('periodsFor(minute): 30 buckets, 1 minute apart, newest last', () => {
    const at = Date.UTC(2026, 5, 22, 17, 35, 40); // EC 12:35:40 → floors to 12:35
    const p = periodsFor('minute', at);
    expect(p).toHaveLength(WINDOW.minute);
    expect(p[p.length - 1]).toBe('2026-06-22T12:35');
    expect(p[0]).toBe('2026-06-22T12:06'); // 29 minutes earlier
  });
  test('periodsFor(hour): 24 buckets, 1 hour apart, newest last', () => {
    const at = Date.UTC(2026, 5, 22, 17, 42, 0); // EC 12:42 → hour 12
    const p = periodsFor('hour', at);
    expect(p).toHaveLength(WINDOW.hour);
    expect(p[p.length - 1]).toBe('2026-06-22T12');
    expect(p[0]).toBe('2026-06-21T13'); // 23 hours earlier, crosses midnight
  });
});

describe('key shapes', () => {
  test('combinedKey by granularity', () => {
    expect(combinedKey('minute', '2026-06-22T12:35')).toBe('b:i:2026-06-22T12:35');
    expect(combinedKey('hour', '2026-06-22T12')).toBe('b:h:2026-06-22T12');
    expect(combinedKey('day', '2026-06-22')).toBe('b:d:2026-06-22');
    expect(combinedKey('week', '2026-06-22')).toBe('b:w:2026-06-22');
    expect(combinedKey('month', '2026-06')).toBe('b:m:2026-06');
    expect(combinedKey('year', '2026')).toBe('b:y:2026');
  });
  test('eventCombinedKeys: one key per granularity for an event', () => {
    const keys = eventCombinedKeys(EC_NOON_JUN22);
    expect(keys.map((k) => k.g)).toEqual(['minute', 'hour', 'day', 'week', 'month', 'year']);
    expect(keys.map((k) => k.key)).toEqual([
      'b:i:2026-06-22T12:00',
      'b:h:2026-06-22T12',
      'b:d:2026-06-22',
      `b:w:${weekStartStr(EC_NOON_JUN22)}`,
      'b:m:2026-06',
      'b:y:2026',
    ]);
  });
});

describe('isGranularity', () => {
  test('accepts the six valid values', () => {
    for (const g of ['minute', 'hour', 'day', 'week', 'month', 'year'])
      expect(isGranularity(g)).toBe(true);
  });
  test('rejects anything else', () => {
    for (const g of ['second', 'decade', '', 'DAY', null, undefined, 7])
      expect(isGranularity(g)).toBe(false);
  });
});
