// Post-build guard: every Spanish page in the generated sitemap must be
// listed in public/llms.txt, so the LLM-facing index never drifts when new
// pages ship (it went stale for 46 days after /compatibilidad/ was created).
// English pages are curated by hand (only key ones are listed) and are not
// enforced. Add a URL to EXCEPTIONS only with a reason.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

const EXCEPTIONS = new Set([
  'https://firmar.ec/', // home is the file itself; no self-entry needed
]);

// Whole SECTIONS whose individual pages are not enforced. Use only when the
// pages are created by an automated process, so requiring them in the same
// commit would deadlock it.
const EXCEPTION_PREFIXES = [
  // Answer pages are written by the GEO engine (idkpublicitaria), one net-new
  // file per PR. `llms.txt` is maintained by that engine's OWN remediation
  // cycle, in a separate PR: demanding the entry in the same commit would fail
  // the build of every forged page and nothing would ever publish. The hub
  // `/respuestas/` is NOT exempt — it is a stable section of the site and must
  // stay listed in llms.txt, which is what keeps the section itself visible.
  'https://firmar.ec/respuestas/',
];

/** A URL is exempt if it is listed verbatim, or if it hangs BELOW an exempt
 *  section — the section index itself is never exempt by its own prefix.
 *  Exported so a test can pin BOTH directions: widening this (dropping the
 *  `url !== p`, or adding a broader prefix) would keep the build green by
 *  construction, because a wider exemption can never produce a `missing`. */
export const isExempt = (url) =>
  EXCEPTIONS.has(url) || EXCEPTION_PREFIXES.some((p) => url.startsWith(p) && url !== p);

/** Run the guard over `dist`. A function so the pure `isExempt` above can be
 *  imported by a test without executing the check (a top-level script would
 *  fire it and exit the test process). */
export function main() {
  const sitemap = readFileSync(join(ROOT, 'dist/sitemap-0.xml'), 'utf8');
  const llms = readFileSync(join(ROOT, 'public/llms.txt'), 'utf8');

  const urls = [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]);
  const esUrls = urls.filter((u) => !u.startsWith('https://firmar.ec/en/'));

  const missing = esUrls.filter((u) => !isExempt(u) && !llms.includes(u));

  if (missing.length > 0) {
    console.error('ERROR: pages in sitemap but missing from public/llms.txt:');
    for (const u of missing) console.error(`  - ${u}`);
    console.error('Add them to public/llms.txt (or to EXCEPTIONS with a reason).');
    return 1;
  }
  console.log(`check-llms OK: ${esUrls.length} ES sitemap URLs covered by llms.txt`);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main());
}
