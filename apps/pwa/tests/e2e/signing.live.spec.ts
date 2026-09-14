import { test } from '@playwright/test';

test.beforeEach(async ({ context, baseURL }) => {
  const origin = new URL(baseURL!).origin;
  await context.route('**/*', async (route) => {
    const url = new URL(route.request().url());
    // Exercise the deployed UI and real local signing worker without adding
    // synthetic usage. Batch spec installs its own event assertions on top.
    if (url.pathname.startsWith('/api/stats')) {
      await route.fulfill({ status: 204 });
    } else if (url.origin !== origin) {
      await route.abort('blockedbyclient');
    } else {
      await route.continue();
    }
  });
});

// One source of truth for local and post-deploy signing flows. Config selects
// real signing, wrong PIN and ZIP only; no TSA/revocation/issuance claims.
import './firma.spec';
import './firmar-lote.spec';
