import { describe, expect, it } from 'vitest';
import { storeLink } from './store.ts';

describe('storeLink', () => {
  it('sin pagePath: mantiene el comportamiento actual (solo utm_source + utm_medium)', () => {
    const link = storeLink('header');
    expect(link).toBe('https://tienda.firmar.ec/?utm_source=landing&utm_medium=header');
  });

  it('con pagePath simple: añade utm_campaign y utm_content con la ruta', () => {
    const link = storeLink('hero', '/guias/firma-electronica-pdf');
    expect(link).toBe(
      'https://tienda.firmar.ec/?utm_source=landing&utm_medium=hero&utm_campaign=organic_landing&utm_content=%2Fguias%2Ffirma-electronica-pdf',
    );
  });

  it('con pagePath con query string: utm_content excluye la query, URL-encoded', () => {
    const link = storeLink('footer', '/guias/firma-electronica-pdf?ref=x');
    expect(link).toBe(
      'https://tienda.firmar.ec/?utm_source=landing&utm_medium=footer&utm_campaign=organic_landing&utm_content=%2Fguias%2Ffirma-electronica-pdf',
    );
  });
});
