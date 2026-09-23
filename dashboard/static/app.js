const $ = (selector) => document.querySelector(selector);
let snapshot = null;
let activePage = 'overview';
let authenticated = false;
let discovery = null;
let devicePolling = false;
let notificationBaseline = false;
let notifiedIds = new Set();
let asking = false;
let aiReady = false;
let renderedDeviceKey = '';
let renderedNotificationKey = '';
let reportBusy = false;
let reportJobId = '';
let reportDownloadId = '';
const titles = {overview:'Overview', alerts:'Alerts', health:'System health', assistant:'OMEGA AI', reports:'Reports', settings:'Settings', devices:'Devices', notifications:'Notifications', family:'Parental controls', about:'About OMEGA'};
const number = value => new Intl.NumberFormat().format(value);
const priorities = {1:'High', 2:'Medium', 3:'Low'};
const priorityClass = value => value === 1 ? 'high' : value === 3 ? 'low' : '';
const sensorNames = {suricata:'Suricata', wazuh:'Wazuh', wazuh_alerts:'Wazuh alerts', wazuh_archives:'Wazuh event archive', pihole:'Pi-hole'};
const sensorName = value => sensorNames[value] || value || 'Sensor';
function text(selector, value) { $(selector).textContent = value; }
function node(tag, className, content) { const element = document.createElement(tag); element.className = className; if(content !== undefined) element.textContent = content; return element; }
async function api(path, body) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 20000);
  try {
    const response = await fetch(path, {signal:controller.signal, ...(body === undefined ? {} : {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)})});
    const result = await response.json();
    if(!response.ok) {
      if(response.status === 401) showLogin();
      const error = new Error(result.error || 'OMEGA could not complete this request.'); error.status = response.status; throw error;
    }
    return result;
  } catch(error) {
    if(error instanceof TypeError || error.name === 'AbortError') {
      const failure = new Error('The connection to OMEGA was interrupted. Check that the dashboard and any secure connection are still running.'); failure.network = true; throw failure;
    }
    throw error;
  } finally {clearTimeout(timeout);}
}
async function waitForExplanation(id, progress) {
  const started = Date.now();
  while(Date.now() - started < 960000) {
    try {
      const result = await api(`/api/assistant/jobs/${encodeURIComponent(id)}`);
      if(result.state === 'complete') return result;
      if(result.state === 'failed') throw new Error(result.error || 'OMEGA could not prepare this answer.');
      progress(`OMEGA is preparing your answer locally… ${Math.floor((Date.now() - started) / 1000)}s. You can browse other dashboard sections while it works.`);
    } catch(error) {
      if(!error.network) throw error;
      progress('Reconnecting to OMEGA… Your answer continues processing in the background.');
    }
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
  throw new Error('OMEGA could not retrieve the answer in time. Check the connection and try again.');
}

function showLogin() { authenticated = false; notificationBaseline = false; reportJobId = ''; reportDownloadId = ''; reportBusy = false; $('#download-full-report').classList.add('hidden'); try {sessionStorage.removeItem('omega-report-job');} catch {} $('#device-label-dialog').close(); $('#device-label-form').reset(); $('#shell').classList.add('hidden'); $('#login').classList.remove('hidden'); }
function showPage(page) {
  activePage = titles[page] ? page : 'overview';
  document.querySelectorAll('[data-view]').forEach(view => view.classList.toggle('hidden', view.dataset.view !== activePage));
  document.querySelectorAll('[data-page]').forEach(button => { button.classList.toggle('active', button.dataset.page === activePage); button.setAttribute('aria-current', button.dataset.page === activePage ? 'page' : 'false'); });
  text('#page-label', titles[activePage]);
  history.replaceState(null, '', `#${activePage}`);
}
function alertRow(alert) {
  const row = node('article', 'alert-row');
  row.append(node('div', `priority-icon ${priorityClass(alert.severity)}`, alert.severity === 3 ? 'i' : '!'));
  const detail = node('div', 'alert-detail');
  const source = node('div', 'alert-source-line');
  source.append(node('span', 'source-chip', sensorName(alert.sensor || 'suricata')));
  if(alert.rule_level !== undefined && alert.rule_level !== null) source.append(node('span', '', `Rule level ${alert.rule_level}`));
  if(alert.rule_id) source.append(node('span', '', `Rule ${alert.rule_id}`));
  detail.append(source);
  detail.append(node('div', 'alert-title', alert.signature));
  const meta = node('div', 'alert-meta');
  const parsed = new Date(alert.timestamp);
  const address = [alert.source, alert.destination].filter(value => value && value !== 'unknown').join(' → ');
  const agent = typeof alert.agent === 'string' ? alert.agent : alert.agent?.name;
  meta.append(node('span', '', [alert.hostname || agent, address].filter(Boolean).join(' · ') || 'Device context unavailable'), node('span', '', Number.isNaN(parsed.getTime()) ? 'Time unavailable' : parsed.toLocaleString([], {month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'})));
  if(alert.category) meta.append(node('span', '', alert.category));
  detail.append(meta);
  if(activePage === 'alerts') {
    const explain = node('button', 'text-button', 'Explain this detection →');
    explain.addEventListener('click', () => { showPage('assistant'); $('#question').value = `Explain alert ${alert.id}: ${alert.signature}. What should I check next?`; $('#question').focus(); });
    detail.append(explain);
  }
  row.append(detail, node('span', `priority ${priorityClass(alert.severity)}`, priorities[alert.severity] || 'Unclassified'));
  return row;
}
function renderAlerts() {
  if(!snapshot) return;
  const query = $('#search').value.toLowerCase();
  const severity = $('#severity').value;
  const source = $('#alert-source').value;
  const alerts = snapshot.alerts.filter(alert => (severity === 'all' || String(alert.severity) === severity) && (source === 'all' || (alert.sensor || 'suricata') === source) && [alert.signature, alert.source, alert.destination, alert.category, alert.hostname, typeof alert.agent === 'string' ? alert.agent : alert.agent?.name, alert.rule_id, alert.sensor].join(' ').toLowerCase().includes(query));
  const all = $('#all-alerts'); all.replaceChildren();
  alerts.forEach(alert => all.append(alertRow(alert)));
  if(!alerts.length) all.append(node('div', 'empty', snapshot.available ? 'No alerts match this view.' : 'Alerts are unavailable while telemetry is disconnected.'));
  const recent = $('#recent-alerts'); recent.replaceChildren();
  snapshot.alerts.slice(0,4).forEach(alert => recent.append(alertRow(alert)));
  if(!snapshot.alerts.length) recent.append(node('div', 'empty', snapshot.available ? 'No alerts in the current sample.' : 'Waiting for sensor telemetry.'));
  text('#alert-coverage', `${number(alerts.length)} shown in this view · ${number(snapshot.alerts.length)} recent detections loaded${snapshot.alert_count !== undefined ? ` · ${number(snapshot.alert_count)} detections collected` : ''}. The full report contains the retained evidence and its collection limits. Priorities are normalized across sources; Wazuh rule levels are shown separately.`);
}
function telemetrySources(data) {
  if(Array.isArray(data.sources)) return data.sources;
  return [{id:'suricata',label:'Suricata',available:data.available,events:data.events,alerts:data.alert_count,dns:data.dns,updated:data.updated,notice:data.notice}, {id:'wazuh_alerts',label:'Wazuh alerts',available:false,notice:'Wazuh event collection is not connected.'}, {id:'pihole',label:'Pi-hole',available:false,notice:'DNS event collection is not connected.'}];
}
function renderSources(data) {
  const sources = telemetrySources(data);
  const connected = sources.filter(source => source.available).length;
  const coverage = data.coverage || {};
  const limitations = Array.isArray(coverage.limitations) ? coverage.limitations : [];
  const summary = `${connected} of ${sources.length} event streams available. ${coverage.collection_started ? `New events since ${displayTime(coverage.collection_started)}. ` : ''}${coverage.stored_events !== undefined ? `${number(coverage.stored_events)} events retained. ` : ''}${limitations.join(' ')}`;
  text('#source-coverage-summary', summary);
  text('#report-source-summary', summary);
  const cards = $('#telemetry-sources'); const reportSources = $('#report-source-list'); cards.replaceChildren(); reportSources.replaceChildren();
  sources.forEach(source => {
    const catchingUp = Number(source.backlog_bytes) > 0 || Number(source.backlog_rows) > 0 || source.caught_up === false;
    const state = !source.available ? 'Unavailable' : source.sync_current === false ? 'Sync interrupted' : catchingUp ? 'Catching up' : 'Collecting';
    const card = node('article', 'telemetry-source');
    const heading = node('div', 'source-heading'); heading.append(node('h3', '', source.label || sensorName(source.id)), node('span', `state ${source.available ? '' : 'off'}`, state)); card.append(heading);
    card.append(node('strong', 'source-event-count', source.events !== undefined ? number(source.events) : '—'), node('small', '', 'events collected'));
    const counts = [source.alerts !== undefined ? `${number(source.alerts)} detections` : '', source.dns !== undefined ? `${number(source.dns)} DNS events` : ''].filter(Boolean);
    if(counts.length) card.append(node('p', 'source-count-detail', counts.join(' · ')));
    card.append(node('p', 'source-notice', source.notice || (source.available ? 'Event collection is connected.' : 'Connect this source to include its evidence.')));
    if(source.updated) card.append(node('small', 'source-freshness', `Latest event ${displayTime(source.updated)}`));
    if(Number(source.backlog_bytes) > 0) card.append(node('small', 'source-freshness', `${number(Math.ceil(source.backlog_bytes / 1024))} KiB awaiting collection`));
    if(Number(source.backlog_rows) > 0) card.append(node('small', 'source-freshness', `${number(source.backlog_rows)} records awaiting collection`));
    if(source.compressed_files_unread) card.append(node('small', 'source-freshness', `${number(source.compressed_files_unread)} compressed files not yet read`));
    cards.append(card);
    const item = node('div', 'report-source-item'); item.append(node('strong', '', source.label || sensorName(source.id)), node('span', `state ${source.available ? '' : 'off'}`, state), node('p', '', source.notice || (source.available ? `${number(source.events || 0)} retained events available for the report.` : 'This source’s data will be identified as missing in the report.'))); reportSources.append(item);
  });
}
function renderCorrelations(data) {
  const list = $('#correlation-list'); list.replaceChildren();
  const correlations = data.correlations || data.analysis?.correlations || [];
  correlations.slice(0, 4).forEach(item => {
    const row = node('article', 'correlation-row');
    row.append(node('span', 'correlation-mark', '⋈'));
    const body = node('div', ''); body.append(node('h3', '', item.title || 'Related activity'), node('p', '', item.summary || 'Review these observations together.'));
    body.append(node('small', '', [(item.sources || []).map(sensorName).join(' + '), item.event_count !== undefined ? `${number(item.event_count)} related events` : '', item.first_seen ? displayTime(item.first_seen) : ''].filter(Boolean).join(' · ')));
    const explain = node('button', 'text-button', 'Review connection →');
    explain.addEventListener('click', () => {showPage('assistant'); $('#question').value = `Review correlation ${item.id || ''}: ${item.title || 'Related activity'}. Explain the evidence, uncertainties, and what to check next.`; $('#question').focus();});
    body.append(explain); row.append(body); list.append(row);
  });
  if(!correlations.length) list.append(node('div', 'empty', 'No cross-source connections are available in this snapshot. Generate a report to assess the collected evidence and missing coverage.'));
}
function render(data) {
  snapshot = data;
  const online = data.services.filter(service => service.state === 'active').length;
  const reachable = data.services.filter(service => service.state === 'reachable').length;
  const priority = data.alerts.filter(alert => alert.severity <= 2).length;
  text('#device', data.device); text('#mode', data.demo ? '◉ Demo preview' : '◉ Live appliance');
  const notices = [data.notice];
  if(data.truncated) notices.push('Some source data has not been included. Review the collection limits below.');
  if(data.invalid) notices.push(`${number(data.invalid)} malformed records were skipped.`);
  text('#notice', notices.filter(Boolean).join(' ')); $('#notice').classList.toggle('hidden', !notices.some(Boolean));
  text('#headline', !data.available ? 'Your sensor needs attention' : data.stale ? 'Your sensor data needs a freshness check' : online < data.services.length ? (online + reachable === data.services.length ? 'Some application health checks are incomplete' : 'Some services need attention') : priority ? 'Your network, with a few things to review' : 'Your security services are online');
  text('#summary', !data.available ? 'OMEGA cannot currently read its security telemetry.' : `${online} of ${data.services.length} system services active.${reachable ? ` ${reachable} separately managed endpoint reachable; application health unverified.` : ''} ${priority} medium or high-priority detections in the recent view. Source availability is shown below.`);
  text('#events', data.available ? number(data.events) : '—'); text('#dns', data.available ? number(data.dns) : '—'); text('#alert-count', data.available ? number(data.alert_count || 0) : '—'); text('#nav-count', data.alerts.length); text('#service-count', `${online} / ${data.services.length}`);
  const services = $('#overview-services'); const health = $('#health-services'); services.replaceChildren(); health.replaceChildren();
  data.services.forEach(service => {
    const item = node('div', 'service-item'); item.append(node('strong', '', service.label), node('span', `state ${service.state === 'active' ? '' : 'off'}`, service.state === 'active' ? 'Online' : service.state)); services.append(item);
    const row = node('div', ''); const label = node('div', ''); label.append(node('h2', '', service.label), node('small', '', service.name)); if(service.detail) label.append(node('p', '', service.detail)); row.append(label, node('span', `state ${service.state === 'active' ? '' : 'off'}`, service.state)); health.append(row);
  });
  text('#disk-label', `${data.disk_percent}% of the system disk is used`); $('#disk').value = data.disk_percent;
  text('#telemetry-quality', !data.available ? data.notice : `${number(data.events)} readable events; ${data.invalid} malformed records skipped. Last event: ${data.updated || 'not available'}.`);
  text('#data-source', `${data.demo ? 'Sample events · preview mode' : 'Live event collection'} · ${telemetrySources(data).map(source => `${source.label || sensorName(source.id)}: ${source.available ? 'available' : 'unavailable'}`).join(' · ')}`);
  renderAIStatus(data.ai_status);
  text('#updated', `Snapshot refreshed ${new Date(data.generated).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'})}`);
  const share = data.available && data.events ? Math.min(100, Math.round(data.dns / data.events * 100)) : 0;
  text('#dns-share', data.available ? `${share}%` : '—');
  $('#dns-bar').style.width = `${share}%`;
  text('#dns-legend', data.available ? number(data.dns) : '—');
  text('#other-legend', data.available ? number(Math.max(0, data.events - data.dns)) : '—');
  text('#review-heading', !data.available ? 'Check your sensor connection' : priority ? `${priority} detections worth a closer look` : 'Take a look at your latest activity');
  renderSources(data); renderCorrelations(data); renderAlerts();
}
async function refresh() {
  document.querySelectorAll('.refresh').forEach(button => button.disabled = true);
  try { render(await api('/api/overview')); $('#error').classList.add('hidden'); }
  catch(error) { text('#error', error.message); $('#error').classList.remove('hidden'); }
  finally { document.querySelectorAll('.refresh').forEach(button => button.disabled = false); }
}
document.querySelectorAll('[data-page], [data-go]').forEach(button => button.addEventListener('click', () => { showPage(button.dataset.page || button.dataset.go); renderAlerts(); }));
window.addEventListener('hashchange', () => {showPage(location.hash.slice(1)); renderAlerts();});
document.querySelectorAll('.refresh').forEach(button => button.addEventListener('click', refresh));
$('#search').addEventListener('input', renderAlerts); $('#severity').addEventListener('change', renderAlerts); $('#alert-source').addEventListener('change', renderAlerts);
document.querySelectorAll('[data-question]').forEach(button => button.addEventListener('click', () => {$('#question').value = button.dataset.question; $('#question').focus();}));
$('#login-form').addEventListener('submit', async event => {
  event.preventDefault(); text('#login-error', '');
  try { await api('/api/login', {password:$('#password').value}); $('#password').value = ''; $('#login').classList.add('hidden'); $('#shell').classList.remove('hidden'); authenticated = true; await Promise.all([refresh(), refreshDevices(), refreshProtection()]); resumeReport(); }
  catch(error) {text('#login-error', error.message);}
});
$('#logout').addEventListener('click', async () => {try {await api('/api/logout', {}); showLogin();} catch(error) {text('#error', error.message); $('#error').classList.remove('hidden');}});
$('#ask-form').addEventListener('submit', async event => {
  event.preventDefault(); const question = $('#question').value.trim(); if(!question) return;
  const conversation = $('#conversation'); conversation.append(node('div', 'message user', question));
  const answer = node('div', 'message assistant', 'Reading the current evidence…'); conversation.append(answer);
  asking = true; $('#ask-button').disabled = true;
  try { const job = await api('/api/assistant', {question}); const result = await waitForExplanation(job.id, message => {answer.textContent = message;}); answer.textContent = result.answer; answer.append(node('small', '', `Evidence snapshot: ${new Date(result.generated).toLocaleString()} · ${result.evidence.length} alert references supplied`)); }
  catch(error) {answer.className = 'message error'; answer.textContent = error.message;}
  finally {asking = false; $('#ask-button').disabled = !aiReady; answer.scrollIntoView({behavior:'smooth',block:'nearest'});}
});
$('#download-report').addEventListener('click', async () => {
  try {
    const response = await fetch('/api/report'); if(!response.ok) throw new Error('Report could not be downloaded. Please sign in again.');
    const blob = await response.blob(); const url = URL.createObjectURL(blob); const link = node('a', ''); link.href = url; link.download = `omega-report-${new Date().toISOString().slice(0,10)}.txt`; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); text('#report-state', 'Report downloaded');
  } catch(error) {text('#report-state', error.message);}
});
function reportState(message) {text('#full-report-state', message); $('#full-report-state').classList.toggle('processing', reportBusy);}
async function waitForReport(id) {
  const started = Date.now();
  while(reportJobId === id && Date.now() - started < 1200000) {
    try {
      const result = await api(`/api/reports/${encodeURIComponent(id)}`);
      if(reportJobId !== id) return;
      if(result.state === 'complete') {
        reportDownloadId = id; reportBusy = false; reportJobId = '';
        try {sessionStorage.removeItem('omega-report-job');} catch {}
        $('#download-full-report').classList.remove('hidden');
        reportState(`Your report is ready${result.generated ? ` · ${displayTime(result.generated)}` : ''}. ${result.ai_available === false ? 'The local AI could not complete its assessment; the report records that limitation. ' : ''}Download the ZIP to open the assessment and complete retained event export.`);
        return;
      }
      if(result.state === 'failed') {const error = new Error(result.error || 'OMEGA could not prepare the report.'); error.reportFailed = true; throw error;}
      const progress = typeof result.progress === 'string' ? result.progress : 'Combining the available evidence and preparing the local AI assessment';
      reportState(`${progress}… ${Math.floor((Date.now() - started) / 1000)}s. You can browse other sections while the report is prepared.`);
    } catch(error) {
      if(!error.network) throw error;
      reportState('Reconnecting to OMEGA… Report preparation continues on the appliance.');
    }
    await new Promise(resolve => setTimeout(resolve, 3000));
  }
  if(reportJobId === id) throw new Error('The report is still taking longer than expected. Refresh this page to reconnect to its progress.');
}
async function trackReport(id) {
  reportBusy = true; reportJobId = id; $('#generate-report').disabled = true;
  try {await waitForReport(id);}
  catch(error) {reportBusy = false; if(error.reportFailed || error.status === 404 || error.status === 401) {reportJobId = ''; try {sessionStorage.removeItem('omega-report-job');} catch {}} reportState(error.message);}
  finally {reportBusy = false; $('#generate-report').disabled = !aiReady; $('#full-report-state').classList.remove('processing');}
}
$('#generate-report').addEventListener('click', async () => {
  if(reportBusy) return;
  reportBusy = true; $('#generate-report').disabled = true; $('#download-full-report').classList.add('hidden'); reportDownloadId = '';
  reportState('Starting your full report…');
  try {
    const job = await api('/api/reports', {});
    try {sessionStorage.setItem('omega-report-job', job.id);} catch {}
    await trackReport(job.id);
  } catch(error) {reportBusy = false; reportState(error.message); $('#generate-report').disabled = !aiReady;}
});
$('#download-full-report').addEventListener('click', async () => {
  if(!reportDownloadId) return;
  $('#download-full-report').disabled = true; reportState('Preparing your report download…');
  try {
    const id = reportDownloadId;
    const result = await api(`/api/reports/${encodeURIComponent(id)}`);
    if(result.state !== 'complete') throw new Error('The completed report is unavailable. Generate a new report.');
    const link = node('a', '');
    link.href = `/api/reports/${encodeURIComponent(id)}/download`; link.download = `omega-full-report-${new Date().toISOString().slice(0,10)}.zip`; link.click();
    reportState('Download started. Check your browser’s downloads for the ZIP with the readable AI assessment and retained event export.');
  } catch(error) {reportState(error.message || 'The report download was interrupted. Try downloading again.');}
  finally {$('#download-full-report').disabled = false;}
});
function resumeReport() {
  try {const id = sessionStorage.getItem('omega-report-job'); if(id && !reportBusy) trackReport(id);} catch {}
}

function renderAIStatus(status) {
  const info = status || {state:'unavailable', ready:false, message:'AI status could not be checked.'};
  const names = {disabled_demo:'Preview mode · AI disabled', not_configured:'Choose a local model', unavailable:'Local AI service unavailable', model_missing:'Configured model not installed', ready:'Local model available'};
  aiReady = info.ready;
  text('#ai-status-heading', names[info.state] || 'AI connection needs attention');
  text('#ai-status-detail', info.message + (info.ready && snapshot?.demo ? ' This preview uses sample network data.' : ''));
  text('#ai-settings', `${info.model ? `${info.model} · ` : ''}${info.message}`);
  text('#ai-overview-state', names[info.state] || 'AI unavailable');
  text('#ai-description', info.ready ? (snapshot?.demo ? 'Your local model is connected. Ask about the sample network below; this preview is not monitoring your home.' : 'Ask about the current sensor evidence. The local model’s response is checked when you send a question.') : info.message);
  $('#ask-button').disabled = !info.ready || asking;
  const reportConnected = snapshot && !snapshot.demo && snapshot.coverage;
  $('#generate-report').disabled = !info.ready || reportBusy || !reportConnected;
  if(!reportBusy && !reportDownloadId) reportState(!reportConnected ? 'Full reports are available on the connected live appliance. This preview offers a quick snapshot below.' : info.ready ? 'Ready to generate. The report is prepared locally; large collections and AI analysis can take several minutes.' : 'A connected local model is required for the AI report. You can still download a quick snapshot below.');
}
function displayTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Unavailable' : date.toLocaleString([], {month:'short', day:'numeric', hour:'2-digit', minute:'2-digit'});
}
function renderDevices() {
  if(!discovery) return;
  const query = $('#device-search').value.trim().toLowerCase();
  const list = $('#device-list');
  const key = JSON.stringify([query, discovery.available, discovery.source, discovery.devices]);
  if(key === renderedDeviceKey) return;
  renderedDeviceKey = key; list.replaceChildren();
  const rows = discovery.devices.filter(device => [device.display_name, device.hostname, device.ip, ...(device.addresses || []), device.id, device.device_type, device.role, device.vendor].join(' ').toLowerCase().includes(query));
  rows.forEach(device => {
    const card = node('article', 'panel device-card');
    const top = node('div', 'device-card-top');
    const scanObserved = device.scan_last_seen && device.scan_reachable;
    top.append(node('span', 'device-mark', '▣'), node('span', 'badge', !discovery.available ? 'Saved observation' : scanObserved ? 'Seen in network scan' : discovery.source === 'pihole_network' ? (device.recently_observed ? 'Recently observed' : 'Previously recorded') : device.observed_in_latest_lease ? 'In latest lease file' : 'Previously recorded'));
    card.append(top, node('h2', '', device.display_name || device.hostname || 'Unnamed device'), node('p', '', device.device_type || device.role || 'Unknown type'));
    const details = node('dl', '');
    const addresses = [...new Set([device.ip, ...(device.addresses || [])].filter(Boolean))];
    const fields = [['Hostname', device.hostname || 'Not supplied'], ['IP addresses', addresses.join(', ') || 'Not supplied'], ['MAC address', device.id]];
    if(device.hostname_source) fields.push(['Name source', device.hostname_source]);
    if(device.vendor) fields.push(['Vendor', device.vendor]);
    fields.push(['First observed', displayTime(device.first_seen)], [discovery.source === 'pihole_network' ? 'Last observed by Pi-hole' : discovery.source === 'network_scan' ? 'Last observation' : 'Last in lease file', displayTime(device.last_seen)]);
    if(device.scan_last_seen) fields.push(['Network scan', `${displayTime(device.scan_last_seen)} · ${device.scan_reachable ? 'Responded then' : 'No response recorded'}`]);
    fields.forEach(([key, value]) => details.append(node('dt', '', key), node('dd', '', value)));
    card.append(details);
    if(device.scan_last_seen) {
      const openServices = (device.scan_services || []).filter(service => service.state === 'open');
      const services = openServices.map(service => `${service.name || 'Service'} (${service.port}/${service.protocol || 'tcp'})`).join(', ');
      card.append(node('p', 'device-scan-detail', openServices.length ? `Open services observed: ${services}.` : 'No open services were identified among the ports checked.'));
    }
    if(device.scan_notice) card.append(node('p', 'device-scan-detail', device.scan_notice));
    const edit = node('button', 'text-button', 'Edit name & type →');
    edit.addEventListener('click', () => openDeviceLabel(device));
    card.append(edit); list.append(card);
  });
  if(!rows.length) list.append(node('div', 'panel empty', !discovery.available ? 'Connect a device source to start discovery.' : query ? 'No devices match your search.' : 'No devices in the current discovery source.'));
}
function browserNotificationsEnabled() {
  try {return localStorage.getItem('omega-browser-notifications') === 'on';} catch {return false;}
}
function renderBrowserNotifications() {
  const button = $('#enable-notifications');
  if(!('Notification' in window)) {button.disabled = true; text('#browser-notification-state', 'This browser does not support desktop notifications. Your dashboard inbox still works.'); return;}
  const enabled = Notification.permission === 'granted' && browserNotificationsEnabled();
  button.disabled = Notification.permission === 'denied';
  button.textContent = Notification.permission === 'denied' ? 'Blocked in this browser' : enabled ? 'Turn off browser alerts' : 'Enable browser notifications';
  text('#browser-notification-state', enabled ? 'Browser notifications are enabled while this dashboard is running. Demo events do not trigger desktop alerts.' : Notification.permission === 'denied' ? 'Browser permission is blocked. You can review all notifications in the dashboard.' : 'Dashboard notifications are on. Enable browser alerts to be notified while the dashboard is open.');
}
function renderDiscovery(data) {
  discovery = data;
  const unread = data.unread_count || 0;
  text('#notification-count', unread); text('#notification-shortcut', `Notifications · ${unread}`);
  text('#device-total', data.devices.length); text('#device-observed', data.devices.filter(device => data.source === 'pihole_network' ? device.recently_observed : data.source === 'network_scan' ? device.scan_reachable : device.observed_in_latest_lease).length); text('#device-observed-label', data.source === 'pihole_network' ? 'Recently observed by Pi-hole' : data.source === 'network_scan' ? 'Responded during the scan' : 'In the latest lease file'); text('#device-unread', unread);
  const sourceText = `${data.notice || 'Device source connected. Discovery checks every 10 seconds.'}${data.updated ? ` Last check: ${displayTime(data.updated)}.` : ''}`;
  text('#discovery-status', sourceText); text('#notification-source-state', sourceText);
  text('#device-overview-heading', data.available ? `${data.devices.length} known devices · ${unread} new-device ${unread === 1 ? 'notification' : 'notifications'}` : 'Connect device discovery');
  text('#device-overview-description', data.demo ? 'Explore sample hostnames, device labels, and the notification inbox.' : data.available ? 'New observations are recorded after the initial baseline. Device records do not confirm online status.' : data.notice);
  renderDevices(); renderBrowserNotifications();
  const list = $('#notification-list');
  const notificationKey = JSON.stringify([data.demo, data.events]);
  if(notificationKey !== renderedNotificationKey) {
  renderedNotificationKey = notificationKey; list.replaceChildren();
  data.events.forEach(event => {
    const row = node('article', `notification-row ${event.read ? '' : 'unread'}`);
    row.append(node('span', 'device-mark', '◇'));
    const body = node('div', 'notification-body');
    body.append(node('h2', '', `New device observed: ${event.display_name || event.hostname || event.ip || 'Unnamed device'}`), node('p', '', `${event.hostname || 'No hostname supplied'} · ${event.ip || ''}`), node('small', 'notification-time', `${data.demo ? 'Sample event · ' : ''}${displayTime(event.created_at)}`));
    row.append(body);
    if(!event.read) {
      const review = node('button', 'text-button', 'Mark reviewed');
      review.addEventListener('click', () => acknowledgeNotifications(event.id)); row.append(review);
    } else row.append(node('span', 'badge', 'Reviewed'));
    list.append(row);
  });
  if(!data.events.length) list.append(node('div', 'empty', 'No new-device notifications. Existing devices establish the initial baseline.'));
  }
  $('#read-notifications').disabled = !unread;
  const fresh = data.events.filter(event => !notifiedIds.has(event.id) && !event.read);
  if(notificationBaseline && !data.demo && fresh.length) {
    text('#device-toast', `${fresh.length} new ${fresh.length === 1 ? 'device was' : 'devices were'} observed. Open Notifications to review.`);
    $('#device-toast').classList.remove('hidden');
    if('Notification' in window && Notification.permission === 'granted' && browserNotificationsEnabled()) {
      fresh.forEach(event => {try {new Notification('OMEGA: new device discovered', {body:'Open your OMEGA dashboard to review this device.', tag:event.id});} catch {text('#browser-notification-state', 'Desktop delivery was unavailable. The notification is saved in your dashboard.');}});
    }
  }
  notificationBaseline = true;
  notifiedIds = new Set(data.events.map(event => event.id));
}
async function refreshDevices() {
  if(devicePolling || !authenticated) return;
  devicePolling = true;
  try {renderDiscovery(await api('/api/devices'));}
  catch(error) {text('#discovery-status', `Device checks unavailable: ${error.message}`); text('#notification-source-state', `Device checks unavailable: ${error.message}`); text('#device-overview-heading', 'Device discovery disconnected'); text('#device-overview-description', 'Device information may be stale. Reconnect to resume inbox updates.'); if(discovery) {discovery.available = false; renderDevices();}}
  finally {devicePolling = false;}
}
async function acknowledgeNotifications(id = null) {
  try {renderDiscovery(await api('/api/notifications/acknowledge', {id})); $('#device-toast').classList.add('hidden');}
  catch(error) {text('#notification-source-state', error.message);}
}
function openDeviceLabel(device) {
  $('#label-device-id').value = device.id;
  $('#device-label-name').value = device.display_name || device.hostname || '';
  $('#device-label-type').value = ['Unknown','Laptop','Tablet','Phone','Desktop','TV','Console','Router','Appliance','Other'].includes(device.device_type) ? device.device_type : 'Unknown';
  text('#label-device-heading', `Label ${device.hostname || device.ip}`);
  text('#label-device-status', '');
  $('#device-label-dialog').showModal();
}
$('#device-search').addEventListener('input', renderDevices);
document.querySelectorAll('.discovery-refresh').forEach(button => button.addEventListener('click', refreshDevices));
$('#read-notifications').addEventListener('click', () => acknowledgeNotifications());
$('#enable-notifications').addEventListener('click', async () => {
  if(!('Notification' in window)) return;
  if(Notification.permission === 'granted' && browserNotificationsEnabled()) {
    try {localStorage.removeItem('omega-browser-notifications');} catch {}
  } else {
    try {if(await Notification.requestPermission() === 'granted') localStorage.setItem('omega-browser-notifications', 'on');}
    catch {text('#browser-notification-state', 'Browser notifications could not be enabled. The dashboard inbox remains available.'); return;}
  }
  renderBrowserNotifications();
});
$('#check-ai').addEventListener('click', async () => {
  $('#check-ai').disabled = true;
  try {renderAIStatus(await api('/api/ai/status'));}
  catch(error) {renderAIStatus({state:'unavailable', ready:false, message:error.message});}
  finally {$('#check-ai').disabled = false;}
});
$('#cancel-device-label').addEventListener('click', () => $('#device-label-dialog').close());
$('#device-label-form').addEventListener('submit', async event => {
  event.preventDefault(); $('#save-device-label').disabled = true;
  try {
    const result = await api('/api/devices/label', {id:$('#label-device-id').value, display_name:$('#device-label-name').value.trim(), device_type:$('#device-label-type').value});
    renderDiscovery(result); $('#device-label-dialog').close();
  } catch(error) {text('#label-device-status', error.message);}
  finally {$('#save-device-label').disabled = false;}
});

function renderProtection(data) {
  $('#adult-filter').checked = data.preferences.adult_filter;
  $('#message-review').checked = data.preferences.message_review;
  $('#save-protection').disabled = !data.available;
  text('#protection-status', `${data.preferences.updated ? `Preferences saved ${displayTime(data.preferences.updated)}. ` : ''}${data.demo ? 'Demo preferences reset on restart. ' : ''}${data.notice}`);
}
async function refreshProtection() {
  try {renderProtection(await api('/api/protection/setup'));}
  catch(error) {text('#protection-status', error.message); $('#save-protection').disabled = true;}
}
$('#protection-form').addEventListener('submit', async event => {
  event.preventDefault(); $('#save-protection').disabled = true;
  try {renderProtection(await api('/api/protection/setup', {adult_filter:$('#adult-filter').checked, message_review:$('#message-review').checked}));}
  catch(error) {text('#protection-status', `Not saved: ${error.message}`); $('#save-protection').disabled = !authenticated;}
});

async function start() {
  showPage(location.hash.slice(1));
  try {const session = await api('/api/session'); if(session.authenticated) {authenticated = true; $('#shell').classList.remove('hidden'); $('#logout').classList.toggle('hidden', session.demo); await Promise.all([refresh(), refreshDevices(), refreshProtection()]); resumeReport();} else showLogin();}
  catch(error) {showLogin(); text('#login-error', error.message);}
}
start();
setInterval(() => { if(authenticated) refreshDevices(); }, 5000);
