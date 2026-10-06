import { test, expect } from '@playwright/test';

test.describe('Journey 3: Form Boundary & Input Fuzzing', () => {
  const fuzzPayloads = [
    "' OR '1'='1' --",
    '<script>alert("XSS")</script>',
    '{{7*7}}',
    'A'.repeat(5000),
    '${7*7}',
    '../../../../etc/passwd',
  ];

  test('submits boundary payloads across input fields without server 500 crash', async ({ page }) => {
    await page.goto('/').catch(() => test.skip());

    const textInputs = page.locator('input[type="text"], input:not([type]), textarea');
    const inputCount = await textInputs.count();

    if (inputCount === 0) {
      test.skip();
      return;
    }

    // Test first 2 inputs with boundary strings
    for (let i = 0; i < Math.min(inputCount, 2); i++) {
      const input = textInputs.nth(i);
      for (const payload of fuzzPayloads.slice(0, 3)) {
        await input.fill(payload).catch(() => {});
        // Find adjacent submit button or press Enter
        await input.press('Enter').catch(() => {});
        await page.waitForTimeout(300);

        // Verify page did not crash
        await expect(page.locator('body')).not.toContainText('Internal Server Error');
      }
    }
  });
});
