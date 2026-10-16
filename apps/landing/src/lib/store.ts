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
 * Enlace a la tienda con atribución UTM mínima (origen = landing). `medium` =
 * superficie (header/hero/footer/certnotice). Sin utm_campaign/utm_content: la URL
 * se queda corta y legible (la atribución por guía se vio como ruido para el usuario).
 */
export function storeLink(medium: string): string {
  return `${STORE_URL}/?utm_source=landing&utm_medium=${encodeURIComponent(medium)}`;
}
