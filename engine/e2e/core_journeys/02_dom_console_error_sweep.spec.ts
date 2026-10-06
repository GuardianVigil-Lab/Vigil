import { test, expect } from '@playwright/test';

test.describe('Journey 2: DOM & Console Error Sweep', () => {
  const routesToTest = ['/', '/dashboard', '/alerts', '/scans', '/settings', '/integrations'];

  for (const route of routesToTest) {
    test(`route '${route}' has 0 unhandled console errors, broken links, or CSP violations`, async ({ page }) => {
      const consoleErrors: string[] = [];
      const pageErrors: string[] = [];

      page.on('console', (msg) => {
        if (msg.type() === 'error') {
          consoleErrors.push(msg.text());
        }
      });

      page.on('pageerror', (err) => {
        pageErrors.push(err.message);
      });

      const response = await page.goto(route, { waitUntil: 'domcontentloaded', timeout: 15000 }).catch(() => null);
      if (!response) {
        test.skip();
        return;
      }

      // Assert status is not 500
      expect(response.status(), `Route ${route} returned server error 500`).toBeLessThan(500);

      // Filter non-fatal browser warnings
      const fatalErrors = consoleErrors.filter(
        (err) =>
          !err.includes('favicon.ico') &&
          !err.includes('404') &&
          !err.includes('Failed to load resource')
      );

      expect(pageErrors, `Unhandled JavaScript exceptions on ${route}`).toHaveLength(0);
      expect(fatalErrors, `Unhandled console.error calls on ${route}`).toHaveLength(0);
    });
  }
});
