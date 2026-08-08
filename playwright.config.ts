import { defineConfig } from '@playwright/test';

/**
 * E2E accessibility gate. Tests run against the production build served by
 * `vite preview`, so what passes here is what actually ships to Pages.
 * The build runs as part of the webServer command, so a run always tests the
 * current source rather than whatever bundle happens to be sitting in dist/.
 */
export default defineConfig({
  testDir: 'e2e',
  timeout: 120_000,
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  webServer: {
    // Build first: `vite preview` only serves the existing dist/, so without
    // this a broken build leaves the last good bundle in place and the suite
    // passes green against source that no longer compiles.
    command: 'npm run build && npm run preview -- --port 4643 --strictPort',
    url: 'http://localhost:4643/crypto-lab-gg20-wallet/',
    reuseExistingServer: !process.env.CI,
    timeout: 180_000,
  },
  projects: [{ name: 'chromium', use: { channel: undefined } }],
  use: {
    baseURL: 'http://localhost:4643/crypto-lab-gg20-wallet/',
    colorScheme: 'dark',
  },
});
