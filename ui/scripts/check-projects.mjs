// Run against a fresh, isolated backend only. Creates test users and projects there.
import { chromium } from 'playwright';
import assert from 'node:assert/strict';
const api = process.env.PROJECTS_TEST_API;
if (!api) throw new Error('Set PROJECTS_TEST_API to an isolated backend.');
(async () => {
  const browser = await chromium.launch();
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
    let page = await context.newPage();
    await context.route(url => url.pathname.startsWith('/auth/') || url.pathname.startsWith('/projects') || url.pathname === '/users' || url.pathname.startsWith('/users/') || url.pathname === '/stats' || url.pathname === '/scans' || url.pathname.startsWith('/run/'), async route => {
      const url = new URL(route.request().url());
      if (url.port === '3000') return route.continue();
      const response = await route.fetch({ url: api + url.pathname + url.search });
      await route.fulfill({ response });
    });
    const loginResult = await page.request.post(api + '/auth/login', { data: { email: 'admin@controltower.local', password: 'Admin@1234' } });
    assert.equal(loginResult.status(), 200);
    const superLogin = await loginResult.json();
    assert.equal(superLogin.user.role, 'SUPER_ADMIN');
    const headers = { Authorization: 'Bearer ' + superLogin.token };
    const suffix = Date.now();
    const accounts = [];
    for (const role of ['ADMIN', 'DEVOPS_ENGINEER', 'CYBER_MANAGER']) {
      const data = { email: `${role.toLowerCase()}-${suffix}@example.com`, name: role + ' Test', password: 'Project-test-123', role };
      const response = await page.request.post(api + '/users', { headers, data });
      assert.equal(response.status(), 201);
      accounts.push({ ...(await response.json()), password: data.password });
    }
    async function login(email, password) {
      await page.close();
      page = await context.newPage();
      await page.goto('http://localhost:3000/login');
      await page.getByLabel('Email', { exact: true }).fill(email);
      await page.getByLabel('Password', { exact: true }).fill(password);
      await page.getByRole('button', { name: 'Sign in', exact: true }).click();
      await page.waitForURL('**/dashboard');
      await page.goto('http://localhost:3000/settings');
      await page.getByRole('heading', { name: /^(Projects|Access restricted)$/ }).waitFor();
    }
    await login('admin@controltower.local', 'Admin@1234');
    const projectName = 'Assigned Project ' + suffix;
    const otherName = 'Private Project ' + suffix;
    await page.getByRole('button', { name: '+ New project', exact: true }).click();
    await page.getByLabel('Project name', { exact: true }).fill(projectName);
    await page.getByLabel('Description (optional)').fill('Assigned access integration check');
    await page.getByRole('button', { name: 'Create project', exact: true }).click();
    const editor = page.getByRole('form', { name: 'Members of ' + projectName });
    await editor.getByRole('checkbox').first().waitFor();
    for (const account of accounts) await editor.locator('label').filter({ hasText: account.email }).getByRole('checkbox').check();
    await editor.getByRole('button', { name: 'Save assignments' }).click();
    await editor.getByText('Project assignments saved.', { exact: true }).waitFor();
    await page.getByRole('button', { name: '+ New project', exact: true }).click();
    await page.getByLabel('Project name', { exact: true }).fill(otherName);
    await page.getByRole('button', { name: 'Create project', exact: true }).click();
    await page.getByRole('heading', { name: otherName, exact: true }).waitFor();
    await page.reload();
    await page.getByRole('heading', { name: projectName, exact: true }).waitFor();
    await page.getByRole('heading', { name: otherName, exact: true }).waitFor();
    await page.screenshot({ path: '/tmp/projects-super-admin.png', fullPage: true });
    const projectsResponse = await page.request.get(api + '/projects', { headers });
    const projects = await projectsResponse.json();
    const assigned = projects.find(p => p.name === projectName);
    const other = projects.find(p => p.name === otherName);
    for (const account of accounts) {
      await login(account.email, account.password);
      if (account.role === 'DEVOPS_ENGINEER') {
        await page.getByRole('heading', { name: 'Access restricted' }).waitFor();
      } else {
        await page.getByRole('heading', { name: projectName, exact: true }).waitFor();
        assert.equal(await page.getByRole('heading', { name: otherName, exact: true }).count(), 0);
        assert.equal(await page.getByRole('button', { name: '+ New project', exact: true }).count(), 0);
        assert.equal(await page.getByRole('button', { name: 'Users & Roles', exact: true }).count(), 0);
      }
      await page.goto('http://localhost:3000/dashboard');
      await page.getByLabel('Project', { exact: true }).waitFor();
      await page.waitForFunction(() => !document.querySelector('#dashboard-project').disabled);
      const values = await page.locator('#dashboard-project option').evaluateAll(options => options.map(o => o.value));
      assert(values.includes(assigned.id)); assert(!values.includes(other.id));
      if (account.role !== 'CYBER_MANAGER') {
        await page.goto('http://localhost:3000/new-scan');
        await page.waitForFunction(() => document.querySelector('#scan-project') && !document.querySelector('#scan-project').disabled);
        const options = await page.locator('#scan-project option').evaluateAll(options => options.map(o => o.value));
        assert(options.includes(assigned.id)); assert(!options.includes(other.id));
      }
      console.log(`PASS ${account.role}: assigned projects only; no project creation or global user management.`);
    }
    // Revocation is reflected after reload and does not grant access by a stale selector.
    await page.request.put(api + `/projects/${assigned.id}/members`, { headers, data: { user_ids: [] } });
    await page.goto('http://localhost:3000/dashboard');
    await page.getByText('No projects assigned. Contact your super admin.', { exact: true }).waitFor();
    console.log('PASS project creation, saved membership, super-admin visibility, and revocation.');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
