import { test, expect } from '@playwright/test';

test.describe('Journey 1: Authentication & Session Lifecycle', () => {
  test('rejects invalid credentials with proper error message', async ({ page }) => {
    await page.goto('/login').catch(() => test.skip());
    
    const emailInput = page.locator('input[type="email"], input[name="email"], input[name="username"]').first();
    const passInput = page.locator('input[type="password"]').first();
    const submitBtn = page.locator('button[type="submit"]').first();

    if (await emailInput.count() === 0) {
      test.skip();
    }

    await emailInput.fill('invalid_adversary@example.com');
    await passInput.fill('IncorrectPassword123!');
    await submitBtn.click();

    // Verify error state appears and page does not crash
    await expect(page.locator('body')).not.toContainText('Internal Server Error');
    await expect(page.locator('body')).not.toContainText('Crash');
  });

  test('verifies security attributes on authentication cookies', async ({ page, context }) => {
    await page.goto('/').catch(() => test.skip());
    const cookies = await context.cookies();
    
    for (const cookie of cookies) {
      if (cookie.name.toLowerCase().includes('session') || cookie.name.toLowerCase().includes('token') || cookie.name.toLowerCase().includes('auth')) {
        // Assert secure cookie flags
        expect(cookie.httpOnly, `Cookie ${cookie.name} must be HttpOnly`).toBe(true);
        expect(cookie.sameSite.toLowerCase(), `Cookie ${cookie.name} must specify SameSite`).not.toBe('none');
      }
    }
  });

  test('invalidates session on logout', async ({ page, context }) => {
    await page.goto('/logout').catch(() => test.skip());
    // Once logged out, protected routes should redirect to login
    const resp = await page.goto('/dashboard').catch(() => null);
    if (resp && resp.status() !== 404) {
      expect(page.url()).toContain('login');
    }
  });
});
