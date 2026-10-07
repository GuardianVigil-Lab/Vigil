import { defineConfig, devices } from '@playwright/test';

/**
 * Vigil Containerized Playwright Configuration
 * Hardened for headless execution inside container environments.
 */
export default defineConfig({
  testDir: process.env.VIGIL_E2E_DIR || '/tools/vigil/engine/e2e/core_journeys',
  timeout: 30000,
  expect: {
    timeout: 5000,
  },
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 2 : undefined,
  reporter: [
    ['list'],
    ['json', { outputFile: process.env.VIGIL_REPORTS_DIR ? `${process.env.VIGIL_REPORTS_DIR}/raw/playwright.json` : '/workspace/reports/raw/playwright.json' }],
  ],
  use: {
    baseURL: process.env.TARGET_URL || 'http://127.0.0.1:3000',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    headless: true,
    launchOptions: {
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--no-zygote',
        '--single-process',
      ],
    },
  },
  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
      },
    },
  ],
});
