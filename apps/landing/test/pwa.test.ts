import { describe, expect, it } from 'vitest';
import { signUrl } from '../src/lib/pwa.ts';

describe('signing navigation', () => {
  it('opens the signing route without an intermediate landing redirect', () => {
    expect(signUrl()).toBe('https://app.firmar.ec/#/firmar');
  });

  it('keeps encoded and repeated query parameters separate from hash routing', () => {
    const search = '?utm_campaign=Google%20Ads%20%2F%20Quito&tag=uno&tag=dos&empty=';
    const result = new URL(signUrl(search));
    expect(result.search).toBe(search);
    expect(result.searchParams.getAll('tag')).toEqual(['uno', 'dos']);
    expect(result.searchParams.get('utm_campaign')).toBe('Google Ads / Quito');
    expect(result.hash).toBe('#/firmar');
    expect(result.origin).toBe('https://app.firmar.ec');
  });
});
