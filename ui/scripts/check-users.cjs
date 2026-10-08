// Run against an isolated backend: USERS_TEST_API=http://127.0.0.1:18001 node scripts/check-users.cjs
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const api = process.env.USERS_TEST_API;
if (!api) throw new Error('Set USERS_TEST_API to an isolated backend with the default seeded admin.');
(async () => {
  const browser = await chromium.launch();
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    // Forward UI requests to the actual test backend; no mock success responses.
    await page.route(/\/((auth\/(login|me|logout))|users)(\/[^?]*)?(\?.*)?$/, async route => {
      const url = new URL(route.request().url());
      if (url.port === '3000') return route.continue();
      const response = await route.fetch({ url: api + url.pathname + url.search });
      await route.fulfill({ response });
    });
    await page.goto('http://localhost:3000/login');
    await page.getByLabel('Email', { exact: true }).fill('admin@controltower.local');
    await page.getByLabel('Password', { exact: true }).fill('Admin@1234');
    await page.getByRole('button', { name: 'Sign in', exact: true }).click();
    await page.waitForURL('**/dashboard');
    await page.goto('http://localhost:3000/settings');
    await page.getByRole('button', { name: 'Users & Roles', exact: true }).click();
    await page.getByRole('combobox', { name: 'Role for admin@controltower.local' }).waitFor();
    assert(await page.getByRole('combobox', { name: 'Role for admin@controltower.local' }).isDisabled());
    assert(await page.getByRole('switch', { name: 'Account active for admin@controltower.local' }).isDisabled());
    assert.equal(await page.getByText('Auth Lead', { exact: true }).count(), 0);
    const email = `browser-${Date.now()}@example.com`;
    async function fillNew() {
      await page.getByRole('button', { name: 'Create user', exact: true }).click();
      await page.getByLabel('Name', { exact: true }).fill('Browser Test');
      await page.getByLabel('Email', { exact: true }).fill(email);
      await page.locator('input[name="password"]').fill('Test-only-123');
      await page.getByLabel('Role', { exact: true }).selectOption('DEVOPS_ENGINEER');
      await page.getByRole('button', { name: 'Create account', exact: true }).click();
    }
    await fillNew();
    await page.getByText('Created Browser Test. The account is ready to sign in.', { exact: true }).waitFor();
    await page.getByRole('combobox', { name: `Role for ${email}`, exact: true }).selectOption('CYBER_MANAGER');
    await page.getByText('Browser Test is now a Cyber Manager.', { exact: true }).waitFor();
    await page.reload();
    await page.getByRole('button', { name: 'Users & Roles', exact: true }).click();
    await page.getByRole('combobox', { name: `Role for ${email}`, exact: true }).waitFor();
    assert.equal(await page.getByRole('combobox', { name: `Role for ${email}`, exact: true }).inputValue(), 'CYBER_MANAGER');
    await page.getByRole('switch', { name: `Account active for ${email}` }).click();
    await page.getByText('Browser Test deactivated.', { exact: true }).waitFor();
    await page.getByRole('button', { name: 'Refresh', exact: true }).click();
    await page.getByRole('switch', { name: `Account active for ${email}` }).waitFor();
    assert.equal(await page.getByRole('switch', { name: `Account active for ${email}` }).getAttribute('aria-checked'), 'false');
    await fillNew();
    await page.locator('section [role=alert]').filter({ hasText: /already registered/i }).waitFor();
    await page.waitForFunction(() => document.activeElement?.getAttribute('role') === 'alert');
    await page.getByRole('button', { name: 'Cancel', exact: true }).click();
    await page.getByRole('switch', { name: `Account active for ${email}` }).click();
    await page.getByText('Browser Test activated.', { exact: true }).waitFor();
    await page.screenshot({ path: '/tmp/users-settings-connected.png', fullPage: true });
    console.log('PASS real-backend browser flow: create, role persistence after reload, deactivate/reactivate, duplicate error, self-account controls.');
    // Check real non-admin session cannot see management controls.
    const response = await page.request.post(api + '/auth/login', { data: { email, password: 'Test-only-123' } });
    const login = await response.json();
    assert.equal(response.status(), 200);
    await page.evaluate(token => sessionStorage.setItem('sct_token', token), login.token);
    await page.reload();
    await page.getByRole('button', { name: 'watsonx.ai', exact: true }).waitFor();
    assert.equal(await page.getByRole('button', { name: 'Users & Roles', exact: true }).count(), 0);
    console.log('PASS Cyber Manager cannot access user-management navigation.');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
