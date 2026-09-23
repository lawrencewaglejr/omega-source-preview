#!/usr/bin/env node
'use strict';

// Run: node --test tests/test-onboarding-ui.js
// Exercise the shipped setup state machine and request boundaries without an appliance.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const {CONFIG_FIELDS, validateConfig, validatePassword, verificationRows, pollJob, createSetupApp} = require('../onboarding/static/app.js');
const defaults = JSON.parse(fs.readFileSync(path.join(__dirname, '../image/rootfs-overlay/etc/omega/dashboard-setup.json.example'), 'utf8'));
const html = fs.readFileSync(path.join(__dirname, '../onboarding/static/index.html'), 'utf8');
const jobId = 'a'.repeat(32);
const password = 'owner-dashboard-test-password';

class Element {
  constructor(attributes = '') {
    this.attributes = {};
    for (const match of attributes.matchAll(/([\w-]+)="([^"]*)"/g)) this.attributes[match[1]] = match[2];
    this.value = this.attributes.value || '';
    this.disabled = /\bdisabled\b/.test(attributes);
    this.checked = /\bchecked\b/.test(attributes);
    this.textContent = '';
    this.children = [];
    this.listeners = {};
    this.dataset = {};
    for (const [key, value] of Object.entries(this.attributes)) if (key.startsWith('data-')) this.dataset[key.slice(5).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())] = value;
    const classes = new Set((this.attributes.class || '').split(' '));
    this.classList = {contains: value => classes.has(value), toggle: (value, force) => {
      const enabled = force === undefined ? !classes.has(value) : force;
      if (enabled) classes.add(value); else classes.delete(value);
    }};
  }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this.children = items; this.textContent = ''; }
  addEventListener(name, callback) { this.listeners[name] = callback; }
  setAttribute(name, value) { this.attributes[name] = value; }
  removeAttribute(name) { delete this.attributes[name]; }
  focus() { this.focused = true; }
  select() { this.selected = true; }
  scrollIntoView() {}
  fire(name) { return this.listeners[name]?.({preventDefault() {}}); }
}
function documentFixture() {
  const nodes = [...html.matchAll(/<(input|textarea|select|button|section|[a-z0-9-]+)\b([^>]*)>/g)].map(match => Object.assign(new Element(match[2]), {tag: match[1]}));
  const ids = new Map(nodes.filter(node => node.attributes.id).map(node => [node.attributes.id, node]));
  const headings = new Map(nodes.filter(node => node.dataset.step !== undefined).map(node => [node.dataset.step, new Element()]));
  const document = {
    querySelector(selector) {
      const heading = selector.match(/^\[data-step="(\d+)"\] h1$/);
      const node = heading ? headings.get(heading[1]) : ids.get(selector.replace(/^#/, ''));
      assert.ok(node, 'Selector exists in the shipped HTML: ' + selector);
      return node;
    },
    querySelectorAll(selector) {
      if (selector === 'input, textarea, select, button') return nodes.filter(node => ['input', 'textarea', 'select', 'button'].includes(node.tag));
      if (selector === '[data-step]') return nodes.filter(node => node.dataset.step !== undefined);
      if (selector === '[data-step-link]') return nodes.filter(node => node.dataset.stepLink !== undefined);
      if (selector === '[data-back], [data-step-link]') return nodes.filter(node => node.dataset.stepLink !== undefined || node.dataset.back !== undefined);
      if (selector === '[name="manager-mode"]') return nodes.filter(node => node.attributes.name === 'manager-mode');
      throw new Error('Unexpected selector: ' + selector);
    },
    createElement() { return new Element(); },
  };
  return {document, get: id => ids.get(id), headings};
}
const textOf = element => [element.textContent, ...element.children.map(textOf)].join(' ');
function harness({authenticated = true, phase = 'unconfigured', demo = false, manager = {}, handler} = {}) {
  const dom = documentFixture();
  const calls = [];
  const status = {authenticated, phase, demo, defaults: structuredClone(defaults), csrf: 'csrf-test-token', manager, verification: null};
  const fetch = async (url, options) => {
    const call = {url, ...options, parsed: options.body === undefined ? undefined : JSON.parse(options.body)};
    calls.push(call);
    const result = handler ? await handler(call, status) : undefined;
    const payload = result || (url === '/api/status' ? status : {error: 'Unexpected request'});
    if (payload instanceof Error) throw payload;
    return {ok: !payload.httpError, status: payload.httpError || 200, json: async () => payload};
  };
  const app = createSetupApp({document: dom.document, fetch, setTimeout: () => 1, clearTimeout() {}, pollOptions: {wait: async () => {}}});
  return {app, status, calls, ...dom};
}
function fillPassword(get) { get('owner-password').value = password; get('owner-confirm').value = password; }
function fillManager(get) {
  get('manager-host').value = 'manager.example.test'; get('manager-user').value = 'omega-reader';
  get('manager-port').value = '22'; get('host-key').value = 'ssh-ed25519 VERIFIED-PUBLIC-KEY';
}

test('UI uses the nine actual appliance configuration keys and numeric defaults', () => {
  assert.deepEqual(Object.keys(CONFIG_FIELDS).sort(), Object.keys(defaults).sort());
  assert.deepEqual(validateConfig(defaults), defaults);
});

test('numeric settings reject fractions and values outside the appliance limits', () => {
  for (const [key, values] of Object.entries({OMEGA_AI_THREADS: [0, 9, 1.5, NaN], OMEGA_RETENTION_DAYS: [0, 3651], OMEGA_MAX_EVENTS: [0, 50000001]})) {
    for (const value of values) assert.throws(() => validateConfig({...defaults, [key]: value}), /whole number/);
  }
});

test('source paths require absolute paths but local manager heartbeat can be empty', () => {
  assert.throws(() => validateConfig({...defaults, OMEGA_SURICATA_EVE: 'relative.json'}), /absolute paths/);
  assert.throws(() => validateConfig({...defaults, OMEGA_WAZUH_ARCHIVES: '/tmp/log\nfile'}), /absolute paths/);
  assert.equal(validateConfig({...defaults, OMEGA_WAZUH_SYNC_STATUS: ''}).OMEGA_WAZUH_SYNC_STATUS, '');
});

test('password validation matches the appliance and rejects mismatched confirmation', () => {
  validatePassword(password, password);
  for (const value of ['short', ' leading-password-12345', 'trailing-password-12345 ', 'control-character\npassword', 'x'.repeat(1025)]) assert.throws(() => validatePassword(value, value), /16 to 1,024/);
  assert.throws(() => validatePassword(password, 'something-else-valid'), /do not match/);
  assert.throws(() => validatePassword('🔒'.repeat(8), '🔒'.repeat(8)), /16 to 1,024/);
  validatePassword('🔒'.repeat(16), '🔒'.repeat(16));
  validatePassword('🔒'.repeat(1024), '🔒'.repeat(1024));
  assert.throws(() => validatePassword('🔒'.repeat(1025), '🔒'.repeat(1025)), /16 to 1,024/);
});

test('unauthenticated status keeps configuration hidden and preview has explicit labeling', async () => {
  const {app, get} = harness({authenticated: false, demo: true});
  await app.start();
  assert.equal(app.state.step, 0);
  assert.equal(app.state.initialized, false);
  assert.equal(get('demo-notice').classList.contains('hidden'), false);
  assert.equal(get('connection-badge').textContent, 'Preview');
  assert.match(html, /Preview — no appliance changes/);
  assert.match(html, /OMEGA-PREVIEW/);
});

test('pairing sends the code once and later mutations use the returned CSRF token', async () => {
  const {app, get, calls} = harness({authenticated: false, handler: (call, status) => {
    if (call.url === '/api/pair') { status.authenticated = true; return {csrf: 'csrf-test-token'}; }
    if (call.url === '/api/manager/identity') return {public_key: 'ssh-ed25519 appliance-key'};
  }});
  await app.start(); get('pair-code').value = 'one-time-code'; await app.run(app.pair);
  assert.equal(app.state.step, 1);
  assert.equal(get('pair-code').value, '');
  await app.api('/api/manager/identity', {});
  const paired = calls.find(call => call.url === '/api/pair');
  assert.deepEqual(paired.parsed, {code: 'one-time-code'});
  assert.equal(paired.headers['X-OMEGA-CSRF'], undefined);
  const identity = calls.at(-1);
  assert.equal(identity.headers['X-OMEGA-CSRF'], 'csrf-test-token');
  assert.equal(identity.headers['Content-Type'], 'application/json');
  assert.equal(identity.credentials, 'same-origin');
});

test('direct manager inputs begin blank and require tested connectivity', async () => {
  const {app, get} = harness(); await app.start();
  assert.equal(get('manager-host').value, ''); assert.equal(get('manager-user').value, ''); assert.equal(get('host-key').value, '');
  get('prerequisites').checked = true;
  assert.throws(app.sourcesContinue, /Save and test/);
  assert.equal(app.state.step, 1);
});

test('local manager selection clears the remote heartbeat and still requires prerequisites', async () => {
  const {app, get} = harness(); await app.start(); app.setMode('local');
  assert.equal(get('wazuh-sync-path').value, '');
  assert.equal(get('wazuh-alerts-path').value, '/var/ossec/logs/alerts/alerts.json');
  assert.throws(app.sourcesContinue, /Confirm that owner access/);
  get('prerequisites').checked = true; app.sourcesContinue(); assert.equal(app.state.step, 2);
  app.setMode('mirror'); assert.equal(get('wazuh-sync-path').value, defaults.OMEGA_WAZUH_SYNC_STATUS);
});

test('saved manager settings with a pending transfer do not enable continuation', async () => {
  const {app, get} = harness({handler: (call, status) => {
    if (call.url === '/api/manager/configure') return {job_id: jobId};
    if (call.url.startsWith('/api/jobs/')) { status.manager = {configured: true, ready: false, message: 'Archives are unavailable.'}; return {state: 'complete', result: status.manager}; }
  }});
  await app.start(); fillManager(get);
  await app.run(app.connectManager);
  assert.match(get('manager-status').textContent, /saved.*pending.*Archives are unavailable/);
  assert.equal(get('recheck-manager').disabled, false);
  get('prerequisites').checked = true; assert.throws(app.sourcesContinue, /Save and test/);
});

test('read-only manager recheck accepts an eventual transfer without changing fields or replaying writes', async () => {
  const {app, get, status, calls} = harness({handler: (call, status) => {
    if (call.url === '/api/manager/configure') return {job_id: jobId};
    if (call.url.startsWith('/api/jobs/')) { status.manager = {configured: true, ready: false}; return {state: 'complete', result: status.manager}; }
  }});
  await app.start(); fillManager(get); await app.run(app.connectManager);
  status.manager = {configured: true, ready: true, message: 'Both manager logs were transferred successfully.'};
  await app.run(() => app.refreshStatus());
  assert.equal(get('manager-host').value, 'manager.example.test');
  assert.equal(get('host-key').value, 'ssh-ed25519 VERIFIED-PUBLIC-KEY');
  assert.match(get('manager-status').textContent, /transferred successfully/);
  get('prerequisites').checked = true; app.sourcesContinue(); assert.equal(app.state.step, 2);
  assert.equal(calls.filter(call => call.url === '/api/manager/configure').length, 1);
  assert.equal(calls.at(-1).method, 'GET');
});

test('editing verified manager fields invalidates connection acceptance', async () => {
  const {app, get} = harness({handler: (call, status) => {
    if (call.url === '/api/manager/configure') return {job_id: jobId};
    if (call.url.startsWith('/api/jobs/')) { status.manager = {configured: true, ready: true}; return {state: 'complete', result: status.manager}; }
  }});
  await app.start(); fillManager(get); await app.connectManager(); get('prerequisites').checked = true;
  get('manager-host').value = 'another.example.test'; get('manager-host').fire('input');
  assert.throws(app.sourcesContinue, /Save and test/);
});

test('readiness gaps never enable applying setup', async () => {
  const {app, get} = harness({handler: call => call.url === '/api/check' ? {job_id: jobId} : call.url.startsWith('/api/jobs/') ? {state: 'complete', result: {ok: false, checks: [{name: 'Source access', status: 'gap', detail: 'No readable Suricata events.'}]}} : undefined});
  await app.start(); await app.run(app.check);
  assert.equal(app.state.checked, null); assert.equal(get('apply-setup').disabled, true);
  assert.match(textOf(get('check-results')), /No readable Suricata events/);
});

test('an ok flag without explicit passing evidence does not satisfy readiness', async () => {
  const {app, get} = harness(); await app.start();
  assert.equal(app.renderChecks({ok: true}), false);
  assert.equal(app.renderChecks({ok: true, checks: [{name: 'Unknown', status: 'ready'}]}), false);
  assert.equal(get('apply-setup').disabled, true);
});

test('editing checked configuration requires another readiness check', async () => {
  const {app, get} = harness({handler: call => call.url === '/api/check' ? {job_id: jobId} : call.url.startsWith('/api/jobs/') ? {state: 'complete', result: {ok: true, checks: [{name: 'Storage', status: 'pass', detail: 'Ready.'}]}} : undefined});
  await app.start(); await app.run(app.check);
  assert.equal(get('apply-setup').disabled, false);
  get('retention-days').value = '30'; get('retention-days').fire('input');
  assert.equal(get('apply-setup').disabled, true); assert.equal(app.state.checked, null);
});

test('failed configuration does not advance and clears both password fields', async () => {
  const {app, get, calls} = harness({handler: call => call.url === '/api/configure' ? {job_id: jobId} : call.url.startsWith('/api/jobs/') ? {state: 'failed', error: 'Private state could not be written.'} : undefined});
  await app.start(); fillPassword(get); app.preferencesContinue(); app.state.checked = JSON.stringify(app.readConfig());
  await app.run(app.apply);
  assert.equal(app.state.phase, 'unconfigured'); assert.equal(app.state.step, 3);
  assert.equal(get('owner-password').value, ''); assert.equal(get('owner-confirm').value, '');
  assert.match(get('global-error').textContent, /could not be written/);
  assert.equal(calls.filter(call => call.url === '/api/configure').length, 1);
});

test('a lost write response triggers read-only recovery without replaying configuration', async () => {
  const {app, get, calls} = harness({handler: call => { if (call.url === '/api/configure') throw new TypeError('Connection lost'); }});
  await app.start(); fillPassword(get); app.preferencesContinue(); app.state.checked = JSON.stringify(app.readConfig());
  await app.run(app.apply);
  assert.equal(calls.filter(call => call.url === '/api/configure').length, 1);
  assert.equal(calls.at(-1).url, '/api/status');
  assert.equal(app.state.phase, 'unconfigured'); assert.equal(get('owner-password').value, '');
});

test('successful configuration requires a separate explicit activation', async () => {
  const {app, get, calls} = harness({handler: (call, status) => {
    if (call.url === '/api/configure') return {job_id: jobId};
    if (call.url.startsWith('/api/jobs/')) { status.phase = 'configured'; return {state: 'complete', result: {ok: true, phase: 'configured'}}; }
  }});
  await app.start(); fillPassword(get); app.preferencesContinue(); app.state.checked = JSON.stringify(app.readConfig());
  await app.run(app.apply);
  assert.equal(app.state.step, 4); assert.equal(app.state.phase, 'configured');
  assert.equal(get('activate').disabled, false); assert.equal(get('verify').disabled, true);
  assert.equal(calls.some(call => call.url === '/api/activate'), false);
  const write = calls.find(call => call.url === '/api/configure');
  assert.deepEqual(write.parsed.config, defaults); assert.equal(write.parsed.password, password);
  assert.equal(get('owner-password').value, '');
});

test('activation failure leaves verification unavailable', async () => {
  const {app, get} = harness({phase: 'configured', handler: call => call.url === '/api/activate' ? {job_id: jobId} : call.url.startsWith('/api/jobs/') ? {state: 'complete', result: {ok: false, detail: 'AI service did not start.'}} : undefined});
  await app.start(); await app.run(app.activate);
  assert.equal(app.state.phase, 'configured'); assert.equal(get('verify').disabled, true);
  assert.match(get('global-error').textContent, /AI service did not start/);
});

test('polling recovers transient reads without replaying writes', async () => {
  let calls = 0;
  const messages = [];
  const result = await pollJob(async () => {
    calls++;
    if (calls === 1) { const error = new Error('Offline'); error.network = true; throw error; }
    if (calls === 2) { const error = new Error('Unavailable'); error.status = 503; throw error; }
    return {state: 'complete', result: {ok: true}};
  }, jobId, message => messages.push(message), {wait: async () => {}});
  assert.equal(calls, 3); assert.equal(result.ok, true); assert.ok(messages.every(message => message.includes('Reconnecting')));
});

test('polling permits a fourteen-minute local AI response', async () => {
  let elapsed = 0;
  const result = await pollJob(async () => elapsed < 14 * 60 * 1000 ? {state: 'pending'} : {state: 'complete', result: {ok: true}}, jobId, () => {}, {now: () => elapsed, wait: async ms => { elapsed += ms; }});
  assert.equal(result.ok, true); assert.equal(elapsed, 14 * 60 * 1000);
});

test('polling remains bounded at sixteen minutes', async () => {
  let elapsed = 0;
  await assert.rejects(pollJob(async () => ({state: 'pending'}), jobId, () => {}, {now: () => elapsed, wait: async ms => { elapsed += ms; }}), /within 16 minutes/);
  assert.equal(elapsed, 16 * 60 * 1000);
});

test('permanent polling failures and expired sessions stop immediately', async () => {
  for (const status of [401, 403, 404]) {
    let count = 0;
    await assert.rejects(pollJob(async () => { count++; const error = new Error('Session unavailable'); error.status = status; throw error; }, jobId, () => {}, {wait: async () => {}}), /Session unavailable/);
    assert.equal(count, 1);
  }
  await assert.rejects(pollJob(async () => ({state: 'failed', error: 'Model failed.'}), jobId), /Model failed/);
});

test('unverified source rows remain gaps even when overall ok is true', async () => {
  const {app, get} = harness({phase: 'active'}); await app.start();
  app.renderVerification({ok: true, sources: {suricata: {status: 'pass', detail: 'New event.'}}, ai: {status: 'pass', detail: 'Answer.'}});
  assert.match(get('verification-summary').textContent, /found gaps/);
  assert.equal(verificationRows({ok: true}).every(row => row.status === 'gap'), true);
  assert.equal(verificationRows(null, true).every(row => row.status === 'pending'), true);
});

test('fresh verification does not preserve old passing rows while awaiting results', async () => {
  const old = {ok: true, sources: Object.fromEntries(['suricata', 'pihole', 'wazuh'].map(key => [key, {status: 'pass', detail: 'Old result'}])), ai: {status: 'pass', detail: 'Old answer'}};
  const {app, status, get} = harness({phase: 'active', handler: call => {
    if (call.url === '/api/verify') return {job_id: jobId};
    if (call.url.startsWith('/api/jobs/')) return {state: 'failed', error: 'New verification failed.'};
  }});
  status.verification = old; await app.start(); await app.run(app.verify);
  assert.equal(app.state.verification, null);
  assert.doesNotMatch(textOf(get('verification-results')), /Old result|Old answer/);
  assert.doesNotMatch(get('verification-summary').textContent, /were verified/);
});

test('preview verification labels simulated outcomes and never claims live evidence', async () => {
  const row = {status: 'pass', detail: 'Simulated result.'};
  const {app, get} = harness({phase: 'active', demo: true}); await app.start();
  app.renderVerification({ok: true, sources: {suricata: row, pihole: row, wazuh: row}, ai: row});
  assert.match(get('verification-summary').textContent, /simulated results/);
  assert.match(textOf(get('verification-results')), /Simulated/);
  assert.doesNotMatch(textOf(get('verification-results')), /Verified/);
});

test('reloading resumes an existing verify job without submitting another operation', async () => {
  const row = {status: 'pass', detail: 'Fresh result.'};
  const {app, status, get, calls} = harness({phase: 'active', handler: call => call.url.startsWith('/api/jobs/') ? {state: 'complete', result: {ok: true, sources: {suricata: row, pihole: row, wazuh: row}, ai: row}} : undefined});
  status.operations = {[jobId]: 'verify'}; await app.start();
  assert.equal(app.state.step, 4); assert.match(get('verification-summary').textContent, /were verified/);
  assert.equal(calls.every(call => call.method === 'GET'), true);
});

test('server-provided details are text nodes and do not create executable markup', async () => {
  const {app, get} = harness(); await app.start();
  const hostile = '<img src=x onerror=alert(1)>';
  app.renderChecks({ok: false, checks: [{name: hostile, status: 'gap', detail: hostile}]});
  assert.match(textOf(get('check-results')), /<img src=x onerror=alert\(1\)>/);
  assert.equal(get('check-results').children[0].children[1].children[0].textContent, hostile);
});

test('review omits the password value and UI never writes browser storage', async () => {
  const {app, get} = harness(); await app.start(); fillPassword(get); app.renderReview();
  assert.doesNotMatch(textOf(get('review-summary')), new RegExp(password));
  const source = fs.readFileSync(path.join(__dirname, '../onboarding/static/app.js'), 'utf8');
  assert.doesNotMatch(source, /localStorage|sessionStorage|innerHTML/);
  assert.match(html, /autocomplete="new-password"/);
  assert.match(html, /href="http:\/\/127\.0\.0\.1:8089\/"/);
});
