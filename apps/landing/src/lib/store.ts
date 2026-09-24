/**
 * URL de la tienda de certificados (tienda.firmar.ec) para los CTA cruzados
 * firma→tienda. Overridable en build con PUBLIC_STORE_URL (p.ej. apuntar a QA);
 * default = tienda pública. Normalizada sin barra final para componer rutas.
 * (Vite tipa `import.meta.env` con índice de string → acceso directo válido,
 * igual que `PUBLIC_CF_BEACON_TOKEN` en Analytics.astro.)
 */
export const STORE_URL = (import.meta.env.PUBLIC_STORE_URL ?? 'https://tienda.firmar.ec').replace(
  /\/+$/,
  '',
);

/**
 * Enlace a la tienda con atribución UTM (origen = landing). `medium` = superficie
 * (header/hero/footer/certnotice). `pagePath` (opcional) = ruta de la página de
 * origen del clic — permite atribuir en GA4 de tienda.firmar.ec qué guía produjo
 * la venta. Se normaliza sin query string (Astro.url.pathname ya no la trae, pero
 * por si acaso). Sin `pagePath`, comportamiento idéntico al anterior.
 */
export function storeLink(medium: string, pagePath?: string): string {
  const base = `${STORE_URL}/?utm_source=landing&utm_medium=${encodeURIComponent(medium)}`;
  if (!pagePath) return base;
  const queryIndex = pagePath.indexOf('?');
  const path = queryIndex === -1 ? pagePath : pagePath.slice(0, queryIndex);
  return `${base}&utm_campaign=organic_landing&utm_content=${encodeURIComponent(path)}`;
}
