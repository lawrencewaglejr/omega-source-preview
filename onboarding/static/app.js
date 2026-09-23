'use strict';

const CONFIG_FIELDS = Object.freeze({
  OMEGA_AI_MODEL: 'ai-model', OMEGA_AI_THREADS: 'ai-threads',
  OMEGA_SURICATA_EVE: 'suricata-path', OMEGA_PIHOLE_DATABASE: 'pihole-path',
  OMEGA_WAZUH_ALERTS: 'wazuh-alerts-path', OMEGA_WAZUH_ARCHIVES: 'wazuh-archives-path',
  OMEGA_WAZUH_SYNC_STATUS: 'wazuh-sync-path', OMEGA_RETENTION_DAYS: 'retention-days',
  OMEGA_MAX_EVENTS: 'max-events',
});
const NUMBER_LIMITS = Object.freeze({OMEGA_AI_THREADS: [1, 8], OMEGA_RETENTION_DAYS: [1, 3650], OMEGA_MAX_EVENTS: [1, 50000000]});
const SOURCE_NAMES = Object.freeze({suricata: 'Suricata · network events', pihole: 'Pi-hole · DNS events', wazuh: 'Wazuh · alerts and archives'});

function validateConfig(config) {
  for (const [key, [min, max]] of Object.entries(NUMBER_LIMITS)) {
    if (!Number.isInteger(config[key]) || config[key] < min || config[key] > max) {
      throw new Error(`${key === 'OMEGA_AI_THREADS' ? 'CPU threads' : key === 'OMEGA_RETENTION_DAYS' ? 'Retention days' : 'Retained events'} must be a whole number between ${min.toLocaleString()} and ${max.toLocaleString()}.`);
    }
  }
  if (!config.OMEGA_AI_MODEL || config.OMEGA_AI_MODEL.length > 128 || /\s/.test(config.OMEGA_AI_MODEL)) throw new Error('Enter the installed AI model name without spaces.');
  for (const key of Object.keys(CONFIG_FIELDS).filter(key => !NUMBER_LIMITS[key] && key !== 'OMEGA_AI_MODEL')) {
    const value = config[key];
    if (key === 'OMEGA_WAZUH_SYNC_STATUS' && value === '') continue;
    if (typeof value !== 'string' || !value.startsWith('/') || /[\u0000-\u001f\u007f]/.test(value)) throw new Error('Source paths must be absolute paths on the appliance.');
  }
  return config;
}

function validatePassword(password, confirm) {
  const length = Array.from(password).length;
  if (length < 16 || length > 1024 || password !== password.trim() || /[\u0000-\u001f\u007f]/.test(password)) {
    throw new Error('Use a password of 16 to 1,024 characters, without control characters or spaces at the beginning or end.');
  }
  if (password !== confirm) throw new Error('The passwords do not match.');
}

function verificationRows(result, pending = false) {
  return [...Object.entries(SOURCE_NAMES).map(([key, name]) => ({name, data: result?.sources?.[key]})), {name: 'Local AI · completed answer', data: result?.ai}].map(({name, data}) => ({
    name, status: ['pass', 'gap', 'fail'].includes(data?.status) ? data.status : pending ? 'pending' : 'gap',
    detail: typeof data?.detail === 'string' ? data.detail : pending ? 'Waiting for a result from this verification.' : 'This result has not been verified.',
  }));
}

async function pollJob(api, jobId, onProgress = () => {}, options = {}) {
  if (typeof jobId !== 'string' || !/^[0-9a-f]{32}$/.test(jobId)) throw new Error('The appliance did not return a valid operation. Refresh setup to recover its current status.');
  const now = options.now || Date.now;
  const wait = options.wait || (ms => new Promise(resolve => setTimeout(resolve, ms)));
  const timeout = options.timeout || 16 * 60 * 1000;
  const started = now();
  while (now() - started < timeout) {
    try {
      const job = await api('/api/jobs/' + jobId);
      if (job.state === 'complete') {
        if (!job.result || typeof job.result !== 'object') throw new Error('The appliance returned no result. Refresh setup to recover its current status.');
        return job.result;
      }
      if (job.state === 'failed') throw new Error(job.error || 'The operation failed. Check the appliance and try again.');
      if (job.state !== 'pending') throw new Error('The operation returned an unknown status. Refresh setup before retrying.');
      onProgress('Working on your appliance. You can keep this page open while the operation completes.');
    } catch (error) {
      if (!error.network && !(error.status >= 500)) throw error;
      onProgress('Reconnecting to your appliance… The operation may still be running. Keep your SSH tunnel open.');
    }
    await wait(Math.min(2000, timeout - (now() - started)));
  }
  throw new Error('The result could not be retrieved within 16 minutes. The operation may still be running. Refresh this page to recover its status before retrying.');
}

function createSetupApp(environment = {}) {
  const doc = environment.document || document;
  const fetcher = environment.fetch || fetch;
  const timer = environment.setTimeout || setTimeout;
  const clearTimer = environment.clearTimeout || clearTimeout;
  const $ = selector => doc.querySelector(selector);
  const $$ = selector => [...doc.querySelectorAll(selector)];
  const state = {authenticated: false, demo: false, phase: 'unconfigured', step: 0, furthest: 0, csrf: '', busy: false,
    defaults: null, initialized: false, mode: 'remote', manager: {}, managerSignature: null, checked: null, verification: null, verificationInvalidated: false};
  const hide = (selector, hidden) => $(selector).classList.toggle('hidden', hidden);
  const text = (selector, value) => { $(selector).textContent = value; };

  async function api(path, body) {
    const controller = new AbortController();
    const timeout = timer(() => controller.abort(), 15000);
    try {
      const options = {method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', cache: 'no-store', signal: controller.signal, headers: {'Accept': 'application/json'}};
      if (body !== undefined) {
        options.headers['Content-Type'] = 'application/json';
        if (path !== '/api/pair') options.headers['X-OMEGA-CSRF'] = state.csrf;
        options.body = JSON.stringify(body);
      }
      const response = await fetcher(path, options);
      let data;
      try { data = await response.json(); } catch (_) { throw new Error('The appliance returned an unreadable response. Check the setup connection.'); }
      if (!response.ok) {
        const error = new Error(data.error || 'The appliance could not complete the request.');
        error.status = response.status;
        throw error;
      }
      return data;
    } catch (error) {
      if (error.name === 'AbortError' || error instanceof TypeError) {
        const networkError = new Error('The connection to your appliance was interrupted. Keep your SSH tunnel open, then retry.');
        networkError.network = true;
        throw networkError;
      }
      throw error;
    } finally { clearTimer(timeout); }
  }

  function updateButtons() {
    for (const button of $$('[data-step-link]')) {
      const step = Number(button.dataset.stepLink);
      const available = state.authenticated && state.phase === 'unconfigured' && step > 0 && step <= state.furthest && step < 4;
      button.disabled = state.busy || (step !== state.step && !available);
      if (step === state.step) button.setAttribute('aria-current', 'step'); else button.removeAttribute('aria-current');
      button.classList.toggle('complete', step < state.step);
    }
    $('#apply-setup').disabled = state.busy || state.phase !== 'unconfigured' || state.checked !== configSignature();
    $('#activate').disabled = state.busy || state.phase !== 'configured';
    $('#verify').disabled = state.busy || state.phase !== 'active';
    const editable = !state.busy && state.phase === 'unconfigured';
    $('#create-identity').disabled = !editable;
    $('#connect-manager').disabled = !editable;
    $('#recheck-manager').disabled = state.busy || !state.manager.configured;
  }

  function go(step, focus = true) {
    state.step = step;
    state.furthest = Math.max(state.furthest, step);
    $$('[data-step]').forEach(section => section.classList.toggle('hidden', Number(section.dataset.step) !== step));
    updateButtons();
    if (focus) $(`[data-step="${step}"] h1`).focus();
  }

  function readConfig() {
    return Object.fromEntries(Object.entries(CONFIG_FIELDS).map(([key, id]) => [key, NUMBER_LIMITS[key] ? Number($('#' + id).value) : $('#' + id).value.trim()]));
  }
  function configSignature() { return JSON.stringify(readConfig()); }
  function managerSignature() { return JSON.stringify(readManager()); }
  function readManager() { return {host: $('#manager-host').value.trim(), user: $('#manager-user').value.trim(), port: Number($('#manager-port').value), host_key: $('#host-key').value.trim()}; }
  function invalidate() {
    state.checked = null;
    text('#check-results', 'Settings changed. Run the appliance check again before applying.');
    updateButtons();
  }
  function setMode(mode, applyPaths = true) {
    state.mode = mode;
    for (const name of ['remote', 'local', 'mirror']) hide('#manager-' + name, name !== mode);
    if (applyPaths && state.defaults) {
      const local = mode === 'local';
      $('#wazuh-alerts-path').value = local ? '/var/ossec/logs/alerts/alerts.json' : state.defaults.OMEGA_WAZUH_ALERTS;
      $('#wazuh-archives-path').value = local ? '/var/ossec/logs/archives/archives.json' : state.defaults.OMEGA_WAZUH_ARCHIVES;
      $('#wazuh-sync-path').value = local ? '' : state.defaults.OMEGA_WAZUH_SYNC_STATUS;
      invalidate();
    }
  }

  function renderManager() {
    const manager = state.manager;
    text('#manager-status', manager.message || (manager.configured ? 'Manager settings are saved. Connection readiness still needs checking.' : 'Manager connection has not been checked.'));
    if (manager.public_key) renderIdentity(manager);
  }
  function renderIdentity(result) {
    if (!result.public_key || typeof result.public_key !== 'string') throw new Error('No public key was returned by the appliance.');
    $('#public-key').value = result.public_key;
    text('#identity-fingerprint', result.fingerprint || 'Public key generated on your appliance.');
    text('#create-identity', 'Show appliance identity');
    hide('#identity-output', false);
  }

  function resultElement(row) {
    const container = doc.createElement('div');
    const status = ['pass', 'gap', 'fail', 'pending'].includes(row.status) ? row.status : 'gap';
    container.className = 'check-result ' + status;
    const icon = doc.createElement('span'); icon.className = 'result-icon'; icon.setAttribute('aria-hidden', 'true'); icon.textContent = status === 'pass' ? '✓' : status === 'pending' ? '·' : '!';
    const body = doc.createElement('div');
    const heading = doc.createElement('h3'); heading.textContent = row.name || 'Appliance check';
    const detail = doc.createElement('p'); detail.textContent = row.detail || 'No details were returned.';
    const label = doc.createElement('span'); label.className = 'result-label'; label.textContent = status === 'pass' ? (state.demo ? 'Simulated' : 'Verified') : status === 'pending' ? 'Pending' : 'Needs attention';
    body.append(heading, detail); container.append(icon, body, label); return container;
  }
  function renderChecks(result) {
    const rows = Array.isArray(result.checks) && result.checks.length ? result.checks : [{name: 'Appliance check', status: 'gap', detail: 'No readiness evidence was returned. Run the check again.'}];
    $('#check-results').replaceChildren(...rows.map(resultElement));
    return result.ok === true && rows.every(row => row.status === 'pass');
  }
  function renderVerification(result, pending = false) {
    const rows = verificationRows(result, pending);
    $('#verification-results').replaceChildren(...rows.map(resultElement));
    const complete = result?.ok === true && rows.every(row => row.status === 'pass');
    text('#verification-summary', pending ? 'Verification is running. New source events and the AI answer are still pending.' : complete ? (state.demo ? 'Preview verification complete. These are simulated results; no live source or model was checked.' : 'Fresh events from all three sources and a local AI answer were verified during this check.') : result ? 'OMEGA is active, but verification found gaps. Review the details, resolve them, and run verification again.' : state.phase === 'active' ? 'Ready to check. Source activity and AI have not yet been verified.' : 'Waiting for activation.');
  }
  function renderActivation() {
    const active = state.phase === 'active';
    text('#activation-title', active ? (state.demo ? 'Preview activation complete.' : 'OMEGA services are active.') : 'Settings saved. Ready to activate.');
    text('#activation-detail', active ? 'Service startup is complete. Check fresh source events and the local AI before considering setup verified.' : 'Activation starts the dashboard and creates a collection baseline. It does not import earlier events.');
    hide('#activate', active);
    renderVerification(state.verification);
  }
  function appendDefinition(list, name, value) {
    const dt = doc.createElement('dt'); dt.textContent = name;
    const dd = doc.createElement('dd'); dd.textContent = String(value); list.append(dt, dd);
  }
  function renderReview() {
    const config = readConfig();
    const list = $('#review-summary'); list.replaceChildren();
    const modeDescription = state.mode === 'remote' ? 'Direct SSH pull from your separate manager' : state.mode === 'local' ? 'Existing manager on this appliance' : 'Existing log mirror and transfer service';
    const entries = [['Wazuh connection', modeDescription], ['Dashboard password', 'Provided · saved only when you apply setup'], ['Local AI model', config.OMEGA_AI_MODEL], ['CPU threads', config.OMEGA_AI_THREADS], ['Evidence age limit', config.OMEGA_RETENTION_DAYS.toLocaleString() + ' days'], ['Event limit', config.OMEGA_MAX_EVENTS.toLocaleString()], ['Collection begins', 'New events after activation'], ['Optional family protection', 'Not active']];
    entries.forEach(([key, value]) => appendDefinition(list, key, value));
    const paths = $('#review-paths'); paths.replaceChildren();
    [['Suricata', 'OMEGA_SURICATA_EVE'], ['Pi-hole', 'OMEGA_PIHOLE_DATABASE'], ['Wazuh alerts', 'OMEGA_WAZUH_ALERTS'], ['Wazuh archives', 'OMEGA_WAZUH_ARCHIVES'], ['Sync heartbeat', 'OMEGA_WAZUH_SYNC_STATUS']].forEach(([name, key]) => appendDefinition(paths, name, config[key] || 'Not used for the local manager'));
  }

  async function refreshStatus(initial = false) {
    const status = await api('/api/status');
    state.authenticated = status.authenticated === true;
    state.demo = status.demo === true;
    state.csrf = status.csrf || state.csrf;
    hide('#demo-notice', !state.demo);
    text('#connection-badge', state.demo ? 'Preview' : state.authenticated ? 'Paired · local connection' : 'Pairing required');
    if (!state.authenticated) { go(0, false); return status; }
    state.phase = status.phase || 'unconfigured';
    state.manager = status.manager || {};
    state.verification = state.verificationInvalidated ? null : status.verification || null;
    if (!state.initialized) {
      if (!status.defaults || Object.keys(CONFIG_FIELDS).some(key => !(key in status.defaults))) throw new Error('Setup defaults are incomplete. Check the appliance installation.');
      state.defaults = status.defaults;
      for (const [key, id] of Object.entries(CONFIG_FIELDS)) $('#' + id).value = status.defaults[key];
      state.initialized = true;
      setMode('remote', false);
    }
    renderManager(); renderActivation();
    if (state.phase !== 'unconfigured') go(4, initial);
    else if (initial || state.step === 0) go(1, initial);
    updateButtons();
    return status;
  }

  async function run(action) {
    if (state.busy) return;
    hide('#global-error', true);
    state.busy = true;
    const controls = $$('input, textarea, select, button');
    const disabled = controls.map(element => element.disabled);
    controls.forEach(element => { element.disabled = true; });
    try { return await action(); }
    catch (error) {
      text('#global-error', error.message || 'Setup could not complete this step.'); hide('#global-error', false);
      $('#global-error').scrollIntoView({block: 'nearest'});
      // GET-only recovery is safe even when a POST response was lost. Never repeat a write automatically.
      try { await refreshStatus(); } catch (_) { /* Preserve the original actionable error. */ }
    } finally {
      state.busy = false;
      controls.forEach((element, index) => { element.disabled = disabled[index]; });
      hide('#activity', true);
      updateButtons();
    }
  }
  function progress(message) { text('#activity', message); hide('#activity', false); }
  async function waitForOperation(id, message) {
    progress(message);
    return pollJob(api, id, detail => progress(detail.startsWith('Reconnecting') ? detail : message), environment.pollOptions);
  }
  async function operation(path, body, message) {
    progress(message);
    const job = await api(path, body);
    return waitForOperation(job.job_id, message);
  }

  async function pair() {
    const result = await api('/api/pair', {code: $('#pair-code').value.trim()});
    state.csrf = result.csrf || '';
    $('#pair-code').value = '';
    await refreshStatus(true);
  }
  function sourcesContinue() {
    if (!$('#prerequisites').checked) throw new Error('Confirm that owner access, network provisioning, and sensor installation are complete before continuing.');
    if (state.mode === 'remote' && (!state.manager.configured || !state.manager.ready || (state.managerSignature !== null && state.managerSignature !== managerSignature()))) {
      throw new Error('Save and test the Wazuh manager connection before continuing, or select your existing local manager or mirror.');
    }
    if (state.mode === 'local' && $('#wazuh-sync-path').value.trim()) throw new Error('A local manager does not use a remote sync heartbeat. Clear that field under Advanced source paths.');
    go(2);
  }
  function preferencesContinue() {
    validateConfig(readConfig());
    validatePassword($('#owner-password').value, $('#owner-confirm').value);
    renderReview(); go(3);
  }
  async function connectManager() {
    const config = readManager();
    if (!config.host || !config.user || !config.host_key || !Number.isInteger(config.port) || config.port < 1 || config.port > 65535) throw new Error('Complete the manager address, reader account, SSH port, and verified host public key.');
    state.checked = null;
    const result = await operation('/api/manager/configure', config, 'Saving the restricted manager connection and testing a direct log transfer…');
    if (result.configured === true) state.managerSignature = managerSignature();
    await refreshStatus();
    if (result.configured !== true) throw new Error(result.message || 'The manager settings were not saved. Review its reader access, host key, and JSON log availability.');
    if (state.manager.ready !== true) {
      text('#manager-status', 'Manager settings are saved; a successful transfer is still pending. ' + (state.manager.message || result.message || 'Check reader access, host verification, and JSON log availability.') + ' Use Recheck manager connection to check again.');
      return;
    }
    renderManager();
  }
  async function check() {
    const config = validateConfig(readConfig());
    state.checked = null;
    const signature = JSON.stringify(config);
    const result = await operation('/api/check', {config}, 'Checking source access, private settings, installed AI files, and available storage…');
    if (renderChecks(result) && configSignature() === signature) state.checked = signature;
    updateButtons();
  }
  function clearPassword() { $('#owner-password').value = ''; $('#owner-confirm').value = ''; }
  async function apply() {
    if (state.checked !== configSignature()) throw new Error('Run the appliance check with these settings before applying setup.');
    const config = validateConfig(readConfig());
    const password = $('#owner-password').value;
    const password_confirm = $('#owner-confirm').value;
    validatePassword(password, password_confirm);
    try {
      const result = await operation('/api/configure', {config, password, password_confirm}, 'Saving your private dashboard settings. Activation comes next…');
      if (result.ok !== true) throw new Error(result.detail || 'The appliance did not confirm that setup was saved.');
      state.checked = null;
      await refreshStatus();
      if (!['configured', 'active'].includes(state.phase)) throw new Error('Setup completion could not be confirmed. Check the appliance before retrying.');
      go(4);
    } finally { clearPassword(); }
  }
  async function activate() {
    const result = await operation('/api/activate', {}, 'Starting the dashboard and local AI services…');
    await refreshStatus();
    if (result.ok !== true || state.phase !== 'active') throw new Error(result.detail || 'Services have not reached the active state. Review the appliance service status, then retry activation.');
    renderActivation();
  }
  async function verify() {
    state.verificationInvalidated = true;
    state.verification = null;
    renderVerification(null, true);
    try {
      const result = await operation('/api/verify', {}, 'Verifying fresh source records and waiting for a local AI answer. This can take up to 16 minutes…');
      state.verificationInvalidated = false;
      state.verification = result;
      renderVerification(result);
    } catch (error) {
      renderVerification({ok: false, sources: {}, ai: {status: 'gap', detail: 'The verification result was not retrieved. Refresh setup to recover any running operation.'}});
      throw error;
    }
  }
  async function resumeOperation(id, action) {
    if (action === 'verify') { state.verificationInvalidated = true; go(4, false); renderVerification(null, true); }
    else if (action === 'configure' || action === 'activate') go(4, false);
    else if (action === 'manager/configure') go(1, false);
    const result = await waitForOperation(id, action === 'verify' ? 'Resuming verification of fresh source records and a local AI answer…' : 'Recovering the setup operation already running on your appliance…');
    await refreshStatus();
    if (action === 'verify') { state.verificationInvalidated = false; state.verification = result; renderVerification(result); }
    if (action === 'check') {
      state.checked = null;
      text('#check-results', 'The previous readiness check finished. Review your settings and run it again to apply setup in this browser.');
    }
    if ((action === 'configure' || action === 'activate') && result.ok !== true) throw new Error(result.detail || 'The appliance operation needs attention.');
  }

  function listen(selector, event, action) { $(selector).addEventListener(event, eventObject => { eventObject.preventDefault(); void run(action); }); }
  function bind() {
    listen('#pair-form', 'submit', pair);
    listen('#sources-form', 'submit', sourcesContinue);
    listen('#preferences-form', 'submit', preferencesContinue);
    listen('#create-identity', 'click', async () => renderIdentity(await api('/api/manager/identity', {})));
    listen('#connect-manager', 'click', connectManager);
    listen('#recheck-manager', 'click', async () => { await refreshStatus(); });
    listen('#check-setup', 'click', check);
    listen('#apply-setup', 'click', apply);
    listen('#activate', 'click', activate);
    listen('#verify', 'click', verify);
    listen('#copy-key', 'click', async () => {
      const clipboard = environment.clipboard || (typeof navigator !== 'undefined' ? navigator.clipboard : null);
      try { if (!clipboard) throw new Error('Unavailable'); await clipboard.writeText($('#public-key').value); text('#copy-status', 'Public key copied.'); }
      catch (_) { $('#public-key').focus(); $('#public-key').select(); text('#copy-status', 'Key selected. Copy it with your browser or keyboard.'); }
    });
    for (const control of $$('[name="manager-mode"]')) control.addEventListener('change', () => { if (control.checked) setMode(control.value); });
    for (const control of $$('[data-back], [data-step-link]')) control.addEventListener('click', () => {
      if (state.busy || state.phase !== 'unconfigured') return;
      const step = Number(control.dataset.back ?? control.dataset.stepLink);
      if (step > 0 && step < 4 && step <= state.furthest) { if (step === 3) renderReview(); go(step); }
    });
    for (const id of Object.values(CONFIG_FIELDS)) $('#' + id).addEventListener('input', invalidate);
    for (const id of ['manager-host', 'manager-user', 'manager-port', 'host-key']) $('#' + id).addEventListener('input', () => {
      // A configured server connection cannot validate newly edited connection fields.
      if (state.manager.configured && state.managerSignature === null) state.managerSignature = '__edited__';
      text('#manager-status', 'Connection details changed. Save and test them before continuing.'); invalidate();
    });
  }
  async function start() {
    bind();
    await run(async () => {
      const status = await refreshStatus(true);
      const running = Object.entries(status.operations || {});
      if (running.length) await resumeOperation(...running[0]);
    });
  }
  return {start, state, api, run, pair, sourcesContinue, preferencesContinue, connectManager, check, apply, activate, verify, refreshStatus, resumeOperation, readConfig, setMode, renderChecks, renderVerification, renderReview, updateButtons};
}

if (typeof module !== 'undefined' && module.exports) module.exports = {CONFIG_FIELDS, validateConfig, validatePassword, verificationRows, pollJob, createSetupApp};
if (typeof document !== 'undefined') createSetupApp().start();
