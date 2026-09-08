// Post-build guard: every page under /respuestas/ must RENDER what it declares.
//
// WHY
// ---
// These pages are written by a bot (idkpublicitaria, `answer_page` artifact),
// not by hand. In idkmanager-web the previous GEO remediation seam
// (`src/data/geo-faq.json` -> `GeoFaq.astro`) shipped FAQPage JSON-LD while
// rendering NOTHING: seven GEO questions were live with zero visible text, and
// the same content gap kept reappearing three times with that schema already
// served. A generative engine does not cite text nobody can see.
//
// It matters more here. firmar.ec is a YMYL property: these answers talk about
// legal validity, certificates and SRI procedures. A page that declares an
// answer and does not paint it is not just a wasted slot — it publishes a
// FAQPage asserting something no reader can check against the page itself.
//
// Checking the BUILT html is the whole point: a check over the `.md` would go
// green even if the template stopped rendering the h1, the answer or the
// accordion, which is exactly the failure that does most damage and shows
// least. `check-faq-visibility.mjs` already enforces FAQPage<->visible text
// site-wide; this one adds the structure specific to an answer page.
//
// FAIL-CLOSED
// -----------
// If the collection has entries and none could be verified (frontmatter the
// parser refuses, missing pages in dist, missing hub) the build FAILS. A guard
// that cannot find what it watches is broken, not satisfied.
//
// The frontmatter parser is deliberately narrow: it accepts ONLY the canonical
// form emitted by the engine (`domain/answerPage.ts::renderAnswerPageMarkdown`),
// so a hand-written file and a bot-written one cannot drift in shape without
// the build saying so.
//
// Ported from the twin guard in idkmanager-web: SAME CONTRACT and same parsing
// rules, but not byte-identical — this copy is a post-build script (the
// convention here) rather than an Astro integration, walks the collection
// recursively, and is covered by `test/guards.test.ts`. If the engine changes
// the frontmatter contract, both copies change with it.
import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { dirname, join, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const DIST = join(ROOT, 'dist');
const CONTENT_DIR = join(ROOT, 'src', 'content', 'respuestas');

/** Entities Astro emits when escaping text. `&amp;` goes LAST: decoding it
 *  first would turn `&amp;quot;` into `"` instead of `&quot;`. */
const ENTITIES = [
  [/&quot;/g, '"'],
  [/&#(?:39|x27);/gi, "'"],
  [/&lt;/g, '<'],
  [/&gt;/g, '>'],
  [/&nbsp;/g, ' '],
  [/&#(\d+);/g, null], // generic numeric, resolved separately
  [/&amp;/g, '&'],
];

/** Decode the HTML entities Astro produces and collapse whitespace. */
export function decodeText(raw) {
  let out = String(raw);
  for (const [re, rep] of ENTITIES) {
    out =
      rep === null
        ? out.replace(re, (_, n) => String.fromCodePoint(Number(n)))
        : out.replace(re, rep);
  }
  return out.replace(/\s+/g, ' ').trim();
}

/** Visible text: drop `<script>`, `<style>` and every tag. */
function visibleText(html) {
  return decodeText(
    html
      .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ')
      .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ')
      .replace(/<[^>]+>/g, ' '),
  );
}

/** Every FAQPage node across the `application/ld+json` blocks of the page. */
function faqPageNodes(html) {
  const nodes = [];
  const blocks = html.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g);
  for (const [, raw] of blocks) {
    let data;
    try {
      data = JSON.parse(raw);
    } catch {
      continue; // another block; the one we care about parses
    }
    for (const node of Array.isArray(data) ? data : [data]) {
      if (node?.['@type'] === 'FAQPage') nodes.push(node);
    }
  }
  return nodes;
}

/**
 * Verify ONE answer page against its frontmatter.
 *
 * @param {string} html Built html of `dist/respuestas/<slug>/index.html`.
 * @param {{slug: string, question: string, answer: string, faq: unknown[], hubHtml: string}} entry
 * @returns {{ok: true} | {ok: false, reason: string}}
 */
export function checkAnswerHtml(html, entry) {
  const h1s = [...html.matchAll(/<h1\b[^>]*>([\s\S]*?)<\/h1>/gi)];
  if (h1s.length !== 1) {
    return { ok: false, reason: `expected exactly 1 <h1>, found ${h1s.length}` };
  }
  const h1 = decodeText(h1s[0][1].replace(/<[^>]+>/g, ' '));
  const question = decodeText(entry.question);
  if (h1 !== question) {
    return { ok: false, reason: `<h1> says "${h1}" but the declared question is "${question}"` };
  }

  // ABOVE, not "somewhere". The body repeats the answer under "## La respuesta
  // corta", so requiring it anywhere on the page would go green even if the
  // template stopped painting the header paragraph. Measured on the twin guard:
  // it passed with that paragraph deleted. So it is checked against the html
  // BEFORE the first <h2>, which is the direct-answer zone.
  const answer = decodeText(entry.answer);
  const firstH2 = html.search(/<h2\b/i);
  const header = visibleText(firstH2 === -1 ? html : html.slice(0, firstH2));
  if (!header.includes(answer)) {
    return {
      ok: false,
      reason:
        'the declared answer is not VISIBLE above the first section ' +
        '(a FAQPage with no text in sight is exactly what this guard exists to prevent)',
    };
  }

  const faqNodes = faqPageNodes(html);
  if (faqNodes.length !== 1) {
    return { ok: false, reason: `expected exactly 1 FAQPage JSON-LD, found ${faqNodes.length}` };
  }
  const mainEntity = Array.isArray(faqNodes[0].mainEntity) ? faqNodes[0].mainEntity : [];
  if (mainEntity.length !== entry.faq.length) {
    return {
      ok: false,
      reason: `the FAQPage declares ${mainEntity.length} questions and the frontmatter has ${entry.faq.length}`,
    };
  }

  // A real `href`, not the bare URL: the hub's ItemList JSON-LD already carries
  // the absolute URL, so searching for the plain string went green with the
  // visible link broken. What stops a page from being orphaned is the link, not
  // the structured data.
  if (!entry.hubHtml.includes(`href="/respuestas/${entry.slug}/"`)) {
    return { ok: false, reason: `the /respuestas/ hub does not link /respuestas/${entry.slug}/` };
  }

  return { ok: true };
}

/**
 * Minimal frontmatter parser. Accepts ONLY the canonical form the engine emits:
 * one scalar per line with the value quoted as JSON, and `faq`/`relatedSlugs`
 * as two-level lists.
 *
 * @returns {{question: string, answer: string, faq: {q: string, a: string}[]} | null}
 *   `null` when the file is not understood; the caller treats that as FAILURE.
 */
export function parseAnswerFrontmatter(source) {
  const m = source.match(/^---\n([\s\S]*?)\n---\n/);
  if (!m) return null;
  /** @type {Record<string, string>} */
  const scalars = {};
  /** @type {{q: string, a: string}[]} */
  const faq = [];
  for (const line of m[1].split('\n')) {
    if (line.trim() === '' || /^[a-zA-Z]+:$/.test(line.trim())) continue;
    const scalar = line.match(/^([a-zA-Z]+): (.+)$/);
    if (scalar) {
      try {
        scalars[scalar[1]] = JSON.parse(scalar[2]);
      } catch {
        return null; // unquoted scalar: not the canonical form
      }
      continue;
    }
    const q = line.match(/^ {2}- q: (.+)$/);
    if (q) {
      try {
        faq.push({ q: JSON.parse(q[1]), a: '' });
      } catch {
        return null;
      }
      continue;
    }
    const a = line.match(/^ {4}a: (.+)$/);
    if (a) {
      if (faq.length === 0) return null;
      try {
        faq[faq.length - 1].a = JSON.parse(a[1]);
      } catch {
        return null;
      }
      continue;
    }
    if (/^ {2}- /.test(line)) continue; // relatedSlugs / evidenceClaims
    return null; // a line the parser does not understand: fail-closed
  }
  if (typeof scalars.question !== 'string' || typeof scalars.answer !== 'string') return null;
  if (faq.length === 0 || faq.some((item) => !item.q || !item.a)) return null;
  return { question: scalars.question, answer: scalars.answer, faq };
}

/** Run the guard over `dist`. Kept as a function so the pure helpers above can
 *  be imported by a test WITHOUT running the check (importing a top-level
 *  script would fire it and exit the test process). */
export function main() {
  if (!existsSync(CONTENT_DIR)) {
    console.log('check-answer-pages OK: no `respuestas` collection — nothing to verify');
    return 0;
  }

  // `recursive` porque la colección declara `pattern: '**/*.md'`: un
  // `respuestas/foo/bar.md` se publicaría y un readdir de un solo nivel no
  // lo vería (y el fail-closed tampoco saltaría, porque `verified` seguiría
  // siendo >=1 por los demás). Hoy no es alcanzable por el bot —
  // `isValidAnswerSlug` rechaza cualquier slug con `/`— pero el guarda no
  // debe depender de eso.
  const files = readdirSync(CONTENT_DIR, { recursive: true })
    .map((f) => String(f).split(sep).join('/'))
    .filter((f) => f.endsWith('.md'));
  if (files.length === 0) {
    console.log('check-answer-pages OK: `respuestas` collection is empty — nothing to verify');
    return 0;
  }

  const hubPath = join(DIST, 'respuestas', 'index.html');
  if (!existsSync(hubPath)) {
    console.error(
      'ERROR: there are answers in the collection but /respuestas/ was not generated — ' +
        'without the hub they are born orphaned and only the sitemap sees them',
    );
    return 1;
  }
  const hubHtml = readFileSync(hubPath, 'utf8');

  const problems = [];
  let verified = 0;
  for (const file of files) {
    const slug = file.replace(/\.md$/, '');
    const frontmatter = parseAnswerFrontmatter(readFileSync(join(CONTENT_DIR, file), 'utf8'));
    if (!frontmatter) {
      problems.push(
        `${slug}: frontmatter outside the canonical form (JSON-quoted scalars, faq as a ` +
          'two-level list) — the parser cannot verify anything',
      );
      continue;
    }
    const pagePath = join(DIST, 'respuestas', slug, 'index.html');
    if (!existsSync(pagePath)) {
      problems.push(`${slug}: the .md exists but /respuestas/${slug}/ was not generated`);
      continue;
    }
    const result = checkAnswerHtml(readFileSync(pagePath, 'utf8'), {
      slug,
      question: frontmatter.question,
      answer: frontmatter.answer,
      faq: frontmatter.faq,
      hubHtml,
    });
    if (result.ok) verified += 1;
    else problems.push(`${slug}: ${result.reason}`);
  }

  if (problems.length > 0) {
    console.error('ERROR: answer pages that do not render what they declare:');
    for (const p of problems) console.error(`  - ${p}`);
    return 1;
  }

  if (verified === 0) {
    // Fail-closed: reaching here with no problems AND no verifications means the
    // loop saw nothing. A green like that proves nothing.
    console.error('ERROR: there are .md files in the collection but no page was verified');
    return 1;
  }

  console.log(
    `check-answer-pages OK: visible answer and coherent FAQPage in ${verified}/${files.length} pages`,
  );
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main());
}
