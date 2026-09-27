export interface TopicLink {
  href: string;
  anchor: string;
}

function normalizePath(path: string): string {
  return `${path.replace(/\/+$/, '')}/`;
}

/** Select build-time links, discarding malformed data and unknown or unsafe destinations. */
export function selectTopicLinks(
  data: unknown,
  pathname: string,
  knownRoutes: ReadonlySet<string>,
): TopicLink[] {
  if (!data || typeof data !== 'object' || Array.isArray(data)) return [];
  const entry = Object.entries(data).find(
    ([path]) => normalizePath(path) === normalizePath(pathname),
  );
  if (!entry || !Array.isArray(entry[1])) return [];

  return entry[1].filter((link): link is TopicLink => {
    if (!link || typeof link !== 'object') return false;
    const { href, anchor } = link;
    if (typeof href !== 'string' || typeof anchor !== 'string' || !anchor.trim()) return false;
    // Backslashes and control characters can turn apparently local URLs into host URLs.
    // biome-ignore lint/suspicious/noControlCharactersInRegex: explicitly reject URL control characters.
    if (!href.startsWith('/') || href.startsWith('//') || /[\\\s\u0000-\u001f\u007f]/.test(href)) {
      return false;
    }
    const destination = new URL(href, 'https://firmar.ec');
    return knownRoutes.has(normalizePath(destination.pathname));
  });
}
