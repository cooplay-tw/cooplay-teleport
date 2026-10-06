// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Credentials arrive only on stdin and stay in memory. No HAR, traces,
// screenshots, browser profiles, URLs with tokens, or response bodies are saved.
import { createRequire } from 'node:module';
import { createHmac } from 'node:crypto';
const require = createRequire(import.meta.url);
const { chromium } = require('../../node_modules/.pnpm/playwright@1.62.1/node_modules/playwright');
let input = '';
for await (const chunk of process.stdin) input += chunk;
const cfg = JSON.parse(input);
const result = { checks: {}, passed: false };
let lastPage, lastOtpPeriod;
let browser, stage = 'launch isolated browser';
function check(name, ok) {
  result.checks[name] = !!ok;
  if (!ok) throw new Error('check failed');
}
function otp() {
  const count = Buffer.alloc(8);
  count.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const digest = createHmac('sha1', Buffer.from(cfg.otp, 'base64')).update(count).digest();
  return String((digest.readUInt32BE(digest[19] & 15) & 0x7fffffff) % 1000000).padStart(6, '0');
}
async function login(negative = false) {
  const context = await browser.newContext();
  const page = await context.newPage();
  lastPage = page;
  await page.goto(cfg.proxy + '/web/login');
  await page.getByRole('button', { name: /keycloak/i }).click();
  await page.locator('#username').fill('web-user');
  await page.locator('#password').fill(negative ? cfg.password + '-wrong' : cfg.password);
  await Promise.all([page.waitForNavigation({ waitUntil: 'domcontentloaded' }), page.locator('#kc-login').click()]);
  if (negative) {
    await page.locator('#password').waitFor({ state: 'visible' });
    check('browser_wrong_password_denied', page.url().startsWith(cfg.issuer));
    await page.locator('#password').fill(cfg.password);
    await Promise.all([page.waitForNavigation({ waitUntil: 'domcontentloaded' }), page.locator('#kc-login').click()]);
  }
  await page.locator('#otp').waitFor({ state: 'visible' });
  check('browser_requires_mfa', true);
  if (negative) {
    await page.locator('#otp').fill(otp() === '000000' ? '111111' : '000000');
    await Promise.all([page.waitForNavigation({ waitUntil: 'domcontentloaded' }), page.locator('#kc-login').click()]);
    await page.locator('#otp').waitFor({ state: 'visible' });
    check('browser_wrong_otp_denied', page.url().startsWith(cfg.issuer));
  }
  if (lastOtpPeriod === Math.floor(Date.now() / 30000)) {
    await new Promise(resolve => setTimeout(resolve, 30100 - Date.now() % 30000));
  }
  lastOtpPeriod = Math.floor(Date.now() / 30000);
  await page.locator('#otp').fill(otp());
  await Promise.all([page.waitForNavigation({ waitUntil: 'domcontentloaded' }), page.locator('#kc-login').click()]);
  await page.getByRole('button', { name: 'User Menu', exact: true }).waitFor({ state: 'visible', timeout: 30000 });
  check('normal_browser_ui_authenticated', page.url().startsWith(cfg.proxy + '/web/'));
  const token = await page.evaluate(() => JSON.parse(localStorage.getItem('grv_teleport_token')).accessToken);
  return { context, page, token };
}
try {
  browser = await chromium.launch({ ...(cfg.browser ? { executablePath: cfg.browser } : {}), headless: true,
    args: ['--ignore-certificate-errors-spki-list=' + cfg.spki, '--disable-background-networking'] });
  result.browser_version = browser.version();
  stage = 'full UI login and MFA';
  const one = await login(true), two = await login();
  // Copy a valid session before logout: deleting local browser storage alone
  // cannot satisfy the following server-side revocation check.
  const copied = await browser.newContext({ storageState: await one.context.storageState() });
  const request = (context, token) => context.request.get(cfg.proxy + '/v1/webapi/sites', {
    headers: { Authorization: 'Bearer ' + token },
  });
  // API probes verify the generated CA via NODE_EXTRA_CA_CERTS. Chrome
  // navigation pins the generated leaf SPKI; no system trust store changes.
  check('copied_web_session_initially_valid', (await request(copied, one.token)).status() === 200);
  stage = 'native Web UI logout';
  await one.page.getByRole('button', { name: 'User Menu', exact: true }).click();
  await one.page.getByText('Logout', { exact: true }).click();
  await one.page.waitForURL('**/web/login**');
  let status;
  for (let retry = 0; retry < 40; retry++) {
    status = (await request(copied, one.token)).status();
    if ([401, 403].includes(status)) break;
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  check('web_logout_invalidates_copied_session', [401, 403].includes(status));
  check('web_independent_login_survives', (await request(two.context, two.token)).status() === 200);
  result.passed = true;
} catch (error) {
  result.failed_step = stage;
  result.error_type = error.constructor.name;
  result.failed_operation = error.message.split('\n')[0].slice(0, 120);
  if (lastPage) {
    result.failed_path = new URL(lastPage.url()).pathname;
    result.headings = await lastPage.locator('h1,h2').allTextContents();
    result.fields = await lastPage.locator('input').evaluateAll(nodes => nodes.map(n => ({id:n.id,name:n.name,type:n.type,invalid:n.getAttribute('aria-invalid')})));
    result.form_errors = await lastPage.locator('#input-error, #input-error-otp-code, .pf-v5-c-alert__title, [role=alert]').allTextContents();
  }
} finally {
  if (browser) await browser.close();
  process.stdout.write(JSON.stringify(result));
}
process.exitCode = result.passed ? 0 : 1;
