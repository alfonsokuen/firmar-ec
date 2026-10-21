import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { Plugin } from 'vite';
import { defineConfig } from 'vitest/config';
import { appVersionDefine } from './apps/pwa/appVersion.ts';

function rawAssetPlugin(): Plugin {
  return {
    name: 'raw-asset',
    load(id: string) {
      if (!id.endsWith('?raw')) return undefined;
      const filePath = resolve(id.slice(0, -4));
      const content = readFileSync(filePath, 'utf-8');
      return `export default ${JSON.stringify(content)};`;
    },
  };
}

export default defineConfig({
  // apps/pwa/src/lib/version.ts lee __APP_VERSION__ (inyectado desde
  // apps/pwa/package.json) al cargar; esta suite raíz también corre sus specs.
  define: appVersionDefine(),
  plugins: [rawAssetPlugin()],
  resolve: {
    alias: {
      '@firma-ec/tsl-ec': resolve(__dirname, 'packages/tsl-ec/src/index.ts'),
      '@firma-ec/crypto-core': resolve(__dirname, 'packages/crypto-core/src/index.ts'),
      '@firma-ec/tsa-client': resolve(__dirname, 'packages/tsa-client/src/index.ts'),
      '@firma-ec/tsa-trust': resolve(__dirname, 'packages/tsa-trust/src/index.ts'),
      '@firma-ec/pdf-sign': resolve(__dirname, 'packages/pdf-sign/src/index.ts'),
      '@firma-ec/dss-pdf': resolve(__dirname, 'packages/dss-pdf/src/index.ts'),
      '@firma-ec/ltv-validation': resolve(__dirname, 'packages/ltv-validation/src/index.ts'),
      '@firma-ec/verifier': resolve(__dirname, 'packages/verifier/src/index.ts'),
      '@firma-ec/signer': resolve(__dirname, 'packages/signer/src/index.ts'),
      '@firma-ec/inbox-crypto': resolve(__dirname, 'packages/inbox-crypto/src/index.ts'),
      '@firma-ec/ui-kit': resolve(__dirname, 'packages/ui-kit/src/index.ts'),
    },
  },
  test: {
    globals: false,
    environment: 'node',
    include: ['**/*.{test,spec}.{ts,js}'],
    exclude: [
      '**/node_modules/**',
      '**/dist/**',
      '**/.astro/**',
      '**/e2e/**',
      // Los worktrees de Claude Code son checkouts sin `node_modules`: vitest
      // recogia sus specs y fallaba al resolver cada import (pkijs, pdf-lib,
      // node-forge...). 72 de 73 ficheros en rojo venian de aqui, no del codigo.
      // `biome.json` ya los ignoraba; esta config no.
      '**/.claude/worktrees/**',
      // Los specs del Service Worker corren con Playwright y su propio
      // config (`apps/pwa/playwright.sw.config.ts`, script `test:e2e:sw`):
      // necesitan un SW real, que `vite dev` no emite. Vitest los recogia
      // por la extension `.spec.ts` y fallaba con «Playwright Test did not
      // expect test.describe() to be called here».
      'apps/pwa/tests/sw/**',
      // Svelte 5 rune modules (`*.svelte.ts`) need `@sveltejs/vite-plugin-svelte`
      // to compile `$state`/`$derived` — this shared root config stays
      // framework-agnostic (every other package here is plain TS), so specs
      // that import a rune module run instead via the package-local config:
      //   pnpm --filter @firma-ec/pwa exec vitest run
      // See apps/pwa/vitest.config.ts for the rationale.
      'apps/pwa/src/lib/guiado/voice.test.ts',
      'apps/pwa/src/lib/swUpdate.test.ts',
      'apps/pwa/src/lib/batch/loteI18nCoverage.test.ts',
    ],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov', 'html'],
      exclude: [
        '**/node_modules/**',
        '**/dist/**',
        '**/*.config.{ts,js,mjs}',
        '**/tests/**',
        '**/types/**',
        '**/.astro/**',
      ],
      thresholds: {
        lines: 80,
        functions: 80,
        branches: 75,
        statements: 80,
      },
    },
    reporters: ['default'],
  },
});
