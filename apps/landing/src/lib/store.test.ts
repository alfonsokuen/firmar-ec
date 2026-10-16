import { describe, expect, it } from 'vitest';
import { storeLink } from './store.ts';

describe('storeLink', () => {
  it('solo lleva utm_source + utm_medium (sin utm_campaign ni utm_content)', () => {
    const link = storeLink('header');
    expect(link).toBe('https://tienda.firmar.ec/?utm_source=landing&utm_medium=header');
    expect(link).not.toContain('utm_campaign');
    expect(link).not.toContain('utm_content');
  });
});
