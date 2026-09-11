import { defineConfig, devices } from '@playwright/test';

const target = new URL(process.env.PWA_E2E_BASE_URL ?? 'https://app.firmar.ec');
const local = ['localhost', '127.0.0.1'].includes(target.hostname);
if (
  !(local
    ? ['http:', 'https:'].includes(target.protocol)
    : target.protocol === 'https:' && target.hostname === 'app.firmar.ec') ||
  target.username ||
  target.password ||
  target.pathname !== '/' ||
  target.search ||
  target.hash
) {
  throw new Error('PWA_E2E_BASE_URL must be https://app.firmar.ec or a localhost HTTP(S) origin');
}

// Post-deploy only. No webServer, no retries hiding intermittent failures.
export default defineConfig({
  testDir: './tests/e2e',
  testMatch: /signing\.live\.spec\.ts$/,
  globalSetup: './tests/e2e/global-setup.ts',
  grep: /golden path|PIN incorrecto|camino completo/,
  workers: 1,
  retries: 0,
  forbidOnly: true,
  timeout: 150_000,
  expect: { timeout: 15_000 },
  reporter: [['list'], ['html', { outputFolder: 'playwright-report/live-signing', open: 'never' }]],
  outputDir: 'test-results/live-signing',
  use: {
    baseURL: target.origin,
    serviceWorkers: 'block',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    acceptDownloads: true,
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'mobile', use: { ...devices['Pixel 7'] } },
  ],
});
