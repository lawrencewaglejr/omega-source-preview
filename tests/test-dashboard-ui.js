#!/usr/bin/env node
'use strict';

// Run: node --test tests/test-dashboard-ui.js
// Exercise the real UI notification code without requesting OS permissions.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const staticDir = path.join(__dirname, '..', 'dashboard', 'static');
const appSource = fs.readFileSync(path.join(staticDir, 'app.js'), 'utf8');
const html = fs.readFileSync(path.join(staticDir, 'index.html'), 'utf8');

class Element {
  constructor() {
    this.children = [];
    this.value = '';
    this.textContent = '';
    this.style = {};
    this.dataset = {};
    const classes = new Set();
    this.classList = {
      add: (...names) => names.forEach(name => classes.add(name)),
      remove: (...names) => names.forEach(name => classes.delete(name)),
      contains: name => classes.has(name),
      toggle: (name, force) => {
        const include = force === undefined ? !classes.has(name) : force;
        if (include) classes.add(name); else classes.delete(name);
        return include;
      },
    };
  }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  addEventListener() {}
  setAttribute() {}
  close() {}
  reset() {}
}

function ui({permission = 'granted', optedIn = true, supported = true} = {}) {
  const elements = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(match => [match[1], new Element()]));
  const select = selector => {
    const element = elements.get(selector.replace(/^#/, ''));
    assert.ok(element, `UI selector must exist in index.html: ${selector}`);
    return element;
  };
  const deliveries = [];
  class Notification {
    constructor(title, options) { deliveries.push({title, ...options}); }
  }
  Notification.permission = permission;
  const storage = new Map(optedIn ? [['omega-browser-notifications', 'on']] : []);
  const context = vm.createContext({
    document: {querySelector: select, querySelectorAll: () => [], createElement: () => new Element()},
    window: {addEventListener() {}, ...(supported ? {Notification} : {})},
    Notification,
    localStorage: {
      getItem: key => storage.get(key) ?? null,
      setItem: (key, value) => storage.set(key, value),
      removeItem: key => storage.delete(key),
    },
    location: {hash: '#notifications'},
    history: {replaceState() {}},
    // Bootstrap stays pending; the tests drive rendering with API fixtures.
    fetch: () => new Promise(() => {}),
    AbortController,
    setTimeout(callback, delay) { if(delay <= 2000) queueMicrotask(callback); return 1; },
    clearTimeout() {},
    setInterval() {},
  });
  vm.runInContext(appSource, context, {filename: 'dashboard/static/app.js'});
  select('#device-toast').classList.add('hidden');
  return {render: data => context.renderDiscovery(data), deliveries, select, context};
}

test('AI polling retrieves the answer after a temporary connection loss', async () => {
  const {context} = ui();
  let calls = 0;
  context.api = async () => {
    calls++;
    if(calls === 1) return {state:'pending'};
    if(calls === 2) {const error = new Error('offline'); error.network = true; throw error;}
    return {state:'complete', answer:'Evidence checked.'};
  };
  const progress = [];
  const answer = await context.waitForExplanation('test-job', value => progress.push(value));
  assert.equal(answer.answer, 'Evidence checked.');
  assert.equal(calls, 3);
  assert.ok(progress.some(value => value.includes('Reconnecting')));
});

test('AI polling waits for a slow local answer beyond four minutes', async () => {
  const {context} = ui();
  let elapsed = 0;
  context.Date = class extends Date { static now() { return elapsed; } };
  context.setTimeout = (callback, delay) => { elapsed += delay; queueMicrotask(callback); return 1; };
  const completionTime = 14 * 60 * 1000;
  let lastProgress = '';
  context.api = async path => {
    assert.equal(path, '/api/assistant/jobs/slow-job');
    return elapsed < completionTime
      ? {state:'pending'}
      : {state:'complete', answer:'The combined evidence is ready.'};
  };
  const answer = await context.waitForExplanation('slow-job', value => { lastProgress = value; });
  assert.equal(answer.answer, 'The combined evidence is ready.');
  assert.ok(elapsed > 4 * 60 * 1000 && elapsed < 15 * 60 * 1000);
  assert.match(lastProgress, /preparing your answer locally/);
});

test('AI polling remains bounded when the job never completes', async () => {
  const {context} = ui();
  let elapsed = 0;
  context.Date = class extends Date { static now() { return elapsed; } };
  context.setTimeout = (callback, delay) => { elapsed += delay; queueMicrotask(callback); return 1; };
  context.api = async () => ({state:'pending'});
  await assert.rejects(context.waitForExplanation('stalled-job', () => {}), /could not retrieve the answer in time/);
  assert.equal(elapsed, 16 * 60 * 1000);
});

test('a connected AI model does not enable full reports in demo mode', () => {
  const {context, select} = ui();
  vm.runInContext('snapshot = {demo:true};', context);
  context.renderAIStatus({ready:true,state:'ready',message:'Local model available.'});
  assert.equal(select('#generate-report').disabled, true);
  assert.match(select('#full-report-state').textContent, /connected live appliance/);
});

test('completed evidence export discloses unavailable AI analysis', async () => {
  const {context, select} = ui();
  vm.runInContext('reportJobId = "report-test";', context);
  context.api = async () => ({state:'complete',ai_available:false});
  await context.waitForReport('report-test');
  assert.match(select('#full-report-state').textContent,/AI could not complete/);
  assert.equal(select('#download-full-report').classList.contains('hidden'),false);
});

test('Pi-hole row backlog and stale manager sync are visible', () => {
  const {context, select} = ui();
  context.renderSources({sources:[{id:'pihole',available:true,events:20,backlog_rows:80,caught_up:false},{id:'wazuh_alerts',available:true,events:40,sync_current:false}]});
  const textOf = element => [element.textContent,...element.children.map(textOf)].join(' ');
  assert.match(textOf(select('#telemetry-sources')),/80 records awaiting collection/);
  assert.match(textOf(select('#telemetry-sources')),/Sync interrupted/);
});

test('AI model failures stop polling and surface their explanation', async () => {
  const {context} = ui();
  context.api = async () => ({state:'failed', error:'The local model timed out.'});
  await assert.rejects(context.waitForExplanation('test-job', () => {}), /local model timed out/);
});

test('browser network failures become actionable connection errors', async () => {
  const {context} = ui();
  vm.runInContext('fetch = async () => { throw new TypeError("NetworkError when attempting to fetch resource."); };', context);
  await assert.rejects(context.api('/api/assistant', {question:'test'}), error => {
    assert.equal(error.network, true);
    assert.match(error.message, /connection to OMEGA was interrupted/);
    return true;
  });
});

function event(index, read = false) {
  return {
    id: index.toString(16).padStart(24, '0'),
    type: 'new_device',
    device_id: `02:00:00:00:00:${index.toString(16).padStart(2, '0')}`,
    display_name: `Device ${index}`,
    hostname: `device-${index}`,
    ip: `192.168.50.${index}`,
    created_at: `2026-09-11T12:00:${index.toString().padStart(2, '0')}+00:00`,
    read,
  };
}

function snapshot(events = [], options = {}) {
  return {
    available: true,
    baseline_established: true,
    notice: 'Device observations do not confirm online status.',
    updated: '2026-09-11T12:01:00+00:00',
    source: 'dhcp_leases',
    demo: false,
    devices: events.map(item => ({
      id: item.device_id, mac: item.device_id, ip: item.ip,
      display_name: item.display_name, hostname: item.hostname,
      device_type: 'Unknown', role: 'Unclassified',
      first_seen: item.created_at, last_seen: item.created_at,
      observed_in_latest_lease: true,
    })),
    events,
    unread_count: events.filter(item => !item.read).length,
    ...options,
  };
}

test('initial snapshot keeps existing unread notifications in the inbox without desktop alerts', () => {
  const app = ui();
  app.render(snapshot([event(1)]));
  assert.equal(app.deliveries.length, 0);
  assert.equal(app.select('#notification-list').children.length, 1);
  assert.equal(app.select('#device-toast').classList.contains('hidden'), true);
});

test('a new durable event triggers one desktop alert and repeated snapshots do not duplicate it', () => {
  const app = ui();
  app.render(snapshot([event(1)]));
  const update = snapshot([event(2), event(1)]);
  app.render(update);
  assert.equal(app.deliveries.length, 1);
  assert.equal(app.deliveries[0].tag, event(2).id);
  assert.equal(app.select('#device-toast').classList.contains('hidden'), false);
  const newestRow = app.select('#notification-list').children[0];
  assert.match(newestRow.children[1].children[0].textContent, /Device 2$/);
  app.render(snapshot([event(2), event(1)]));
  assert.equal(app.deliveries.length, 1);
  assert.equal(app.select('#notification-list').children[0], newestRow,
    'unchanged polling should preserve the existing notification controls');
});

test('demo events never trigger desktop alerts, including arrivals after initial render', () => {
  const app = ui();
  app.render(snapshot([], {demo: true, source: 'sample_data'}));
  app.render(snapshot([event(1)], {demo: true, source: 'sample_data'}));
  assert.equal(app.deliveries.length, 0);
  assert.equal(app.select('#notification-list').children.length, 1);
});

test('fresh durable events survive a source outage without being lost or duplicated on recovery', () => {
  const app = ui();
  app.render(snapshot([event(1)]));
  app.render(snapshot([event(2), event(1)], {available: false, notice: 'Source unavailable; showing saved observations.'}));
  assert.equal(app.deliveries.length, 1, 'a saved new event can be delivered even while its source is unavailable');
  assert.equal(app.deliveries[0].tag, event(2).id);
  app.render(snapshot([event(2), event(1)]));
  assert.equal(app.deliveries.length, 1, 'source recovery must not repeat the saved notification');
});

test('desktop delivery requires both browser permission and OMEGA opt-in', () => {
  for (const options of [{permission: 'denied'}, {permission: 'default'}, {optedIn: false}, {supported: false}]) {
    const app = ui(options);
    app.render(snapshot());
    app.render(snapshot([event(1)]));
    assert.equal(app.deliveries.length, 0, JSON.stringify(options));
    assert.equal(app.select('#notification-list').children.length, 1, 'the dashboard inbox stays available');
  }
});

test('already reviewed new records do not generate desktop alerts', () => {
  const app = ui();
  app.render(snapshot());
  app.render(snapshot([event(1, true)]));
  assert.equal(app.deliveries.length, 0);
  assert.equal(app.select('#read-notifications').disabled, true);
});
