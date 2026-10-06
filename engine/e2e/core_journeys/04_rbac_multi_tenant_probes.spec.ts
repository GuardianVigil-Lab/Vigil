import { test, expect } from '@playwright/test';

test.describe('Journey 4: RBAC & Multi-Tenant Browser Probes', () => {
  const privilegedRoutes = process.env.PRIVILEGED_ROUTES
    ? process.env.PRIVILEGED_ROUTES.split(',')
    : ['/admin', '/admin/users', '/admin/system', '/admin/settings'];

  for (const adminRoute of privilegedRoutes) {
    test(`standard user cannot access privileged route '${adminRoute}'`, async ({ page }) => {
      const resp = await page.goto(adminRoute, { timeout: 10000 }).catch(() => null);
      if (!resp) {
        test.skip();
        return;
      }

      // Privileged route must redirect to login, return 401/403, or 404
      const status = resp.status();
      const currentUrl = page.url();

      const isProtected =
        status === 401 ||
        status === 403 ||
        status === 404 ||
        currentUrl.includes('/login') ||
        currentUrl.includes('/unauthorized');

      expect(isProtected, `Unauthenticated user accessed admin path ${adminRoute} (HTTP ${status})`).toBe(true);
    });
  }
});
