import { type Lang, type UIKey, defaultLang, ui } from './ui.ts';

export function getLangFromUrl(url: URL): Lang {
  const [, maybeLang] = url.pathname.split('/');
  if (maybeLang === 'en') return 'en';
  return 'es';
}

export function useTranslations(lang: Lang) {
  return function t(key: UIKey): string {
    return (
      (ui[lang] as Record<string, string>)[key] ??
      (ui[defaultLang] as Record<string, string>)[key] ??
      key
    );
  };
}

// All paths carry a trailing slash to match Astro's `trailingSlash: 'always'`
// and the directory-format output Caddy serves. Without the slash, every
// canonical/hreflang/nav URL 308-redirects to the slashed version (SEO fix
// 2026-05-23). `home` and `/firmar` /`/verificar` (PWA redirects) keep their
// shape; the latter are handled by Caddy redir rules, not served by the landing.
export const ROUTE_MAP: Record<string, { es: string; en: string }> = {
  home: { es: '/', en: '/en/' },
  'metodologia-verificacion': {
    es: '/metodologia-verificacion/',
    en: '/en/verification-methodology/',
  },
  firmar: { es: '/firmar', en: '/en/sign' },
  verificar: { es: '/verificar', en: '/en/verify' },
  seguridad: { es: '/seguridad/', en: '/en/security/' },
  compatibilidad: { es: '/compatibilidad/', en: '/en/compatibility/' },
  faq: { es: '/faq/', en: '/en/faq/' },
  acerca: { es: '/acerca/', en: '/en/about/' },
  contacto: { es: '/contacto/', en: '/en/contact/' },
  glosario: { es: '/glosario/', en: '/en/glossary/' },
  privacidad: { es: '/privacidad/', en: '/en/privacy/' },
  terminos: { es: '/terminos/', en: '/en/terms/' },
  patrocinar: { es: '/patrocinar/', en: '/en/sponsor/' },
  'firmar-documentos-en-linea': {
    es: '/firmar-documentos-en-linea/',
    en: '/en/sign-documents-online/',
  },
  'firma-electronica-ecuador': {
    es: '/firma-electronica-ecuador/',
    en: '/en/electronic-signature-ecuador/',
  },
  'que-es-firma-pades': { es: '/que-es-firma-pades/', en: '/en/what-is-pades-signature/' },
  'como-firmar-con-certificado-bce': {
    es: '/como-firmar-con-certificado-bce/',
    en: '/en/how-to-sign-with-bce-certificate/',
  },
  'como-firmar-con-certificado-uanataca': {
    es: '/como-firmar-con-certificado-uanataca/',
    en: '/en/how-to-sign-with-uanataca-certificate/',
  },
  'como-firmar-con-certificado-security-data': {
    es: '/como-firmar-con-certificado-security-data/',
    en: '/en/how-to-sign-with-security-data-certificate/',
  },
  'como-firmar-con-certificado-argosdata': {
    es: '/como-firmar-con-certificado-argosdata/',
    en: '/en/how-to-sign-with-argosdata-certificate/',
  },
  'como-firmar-con-certificado-consejo-judicatura': {
    es: '/como-firmar-con-certificado-consejo-judicatura/',
    en: '/en/how-to-sign-with-consejo-judicatura-certificate/',
  },
  // F3.5 T25: removed pending F3.5 ship — see _drafts/como-funciona-wa.astro.
  'comparativos-firmaec': { es: '/comparativos/firmaec/', en: '/en/comparisons/firmaec/' },
  'alternativa-firmaec': { es: '/alternativa-firmaec/', en: '/en/firmaec-alternative/' },
  'verificar-firma-pdf': { es: '/verificar-firma-pdf/', en: '/en/verify-pdf-signature/' },
  'validar-certificado': { es: '/validar-certificado/', en: '/en/validate-certificate/' },
  'como-firmar-pdf': { es: '/como-firmar-pdf/', en: '/en/how-to-sign-pdf/' },
  'firmar-pdf-desde-el-celular': {
    es: '/firmar-pdf-desde-el-celular/',
    en: '/en/sign-pdf-from-phone/',
  },
  'firmar-pdf-online-gratis-sin-instalar-programas': {
    es: '/firmar-pdf-online-gratis-sin-instalar-programas/',
    en: '/en/sign-pdf-online-free-without-installing/',
  },
  'firmar-pdf-sin-subirlo-al-servidor': {
    es: '/firmar-pdf-sin-subirlo-al-servidor/',
    en: '/en/sign-pdf-without-uploading-to-a-server/',
  },
  'firmar-varios-pdf-a-la-vez': {
    es: '/firmar-varios-pdf-a-la-vez/',
    en: '/en/sign-multiple-pdfs-at-once/',
  },
  'sello-de-tiempo-tsa-firma-pdf': {
    es: '/sello-de-tiempo-tsa-firma-pdf/',
    en: '/en/pdf-signature-timestamp-tsa/',
  },
  'como-obtener-certificado': {
    es: '/como-obtener-certificado-firma-electronica/',
    en: '/en/how-to-get-an-electronic-certificate/',
  },
  'firma-electronica-empresas': {
    es: '/firma-electronica-para-empresas/',
    en: '/en/electronic-signature-for-companies/',
  },
  'renovar-certificado': {
    es: '/renovar-certificado-firma-electronica/',
    en: '/en/renew-electronic-signature-certificate/',
  },
  'firma-electronica-sri': {
    es: '/firma-electronica-facturacion-sri/',
    en: '/en/electronic-signature-sri-invoicing/',
  },
  'comparativos-adobe-sign': { es: '/comparativos/adobe-sign/', en: '/en/comparisons/adobe-sign/' },
  'comparativa-emisores-ecuador': {
    es: '/comparativa-emisores-ecuador/',
    en: '/en/certificate-issuers-ecuador/',
  },
  'que-es-firma-electronica': {
    es: '/que-es-firma-electronica/',
    en: '/en/what-is-electronic-signature/',
  },
  'firma-electronica-vs-firma-digital': {
    es: '/firma-electronica-vs-firma-digital/',
    en: '/en/electronic-signature-vs-digital-signature/',
  },
  precios: { es: '/precios/', en: '/en/pricing/' },
  estadisticas: { es: '/estadisticas/', en: '/en/statistics/' },
};

export function getHreflangsForRoute(
  routeKey: string,
  baseUrl = 'https://firmar.ec',
): { es: string; en: string } | null {
  const m = ROUTE_MAP[routeKey];
  if (!m) return null;
  return { es: `${baseUrl}${m.es}`, en: `${baseUrl}${m.en}` };
}

export function getCurrentRouteKey(url: URL): string | null {
  const path = url.pathname.replace(/^\/en\//, '/').replace(/\/$/, '') || '/';
  for (const [key, val] of Object.entries(ROUTE_MAP)) {
    const esPath = val.es.replace(/\/$/, '') || '/';
    if (esPath === path) return key;
  }
  return null;
}

export function localizedUrl(routeKey: string, lang: Lang): string {
  const m = ROUTE_MAP[routeKey];
  if (!m) return lang === 'es' ? '/' : '/en/';
  return m[lang];
}
