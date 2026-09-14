/** The app uses hash routing; query parameters must stay before the hash. */
export function signUrl(search = ''): string {
  const url = new URL('https://app.firmar.ec/');
  url.search = search;
  url.hash = '/firmar';
  return url.href;
}
