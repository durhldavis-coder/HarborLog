let token = localStorage.getItem('harborlog_token') || null;
let currentUser = JSON.parse(localStorage.getItem('harborlog_user') || 'null');

const loginSection = document.getElementById('login-section');
const dashboardSection = document.getElementById('dashboard-section');
const adminPanel = document.getElementById('admin-panel');
const crewPanel = document.getElementById('crew-panel');
const statusEl = document.getElementById('status');
const userInfoEl = document.getElementById('user-info');

function setStatus(message, isError = false) {
  statusEl.textContent = message;
  statusEl.classList.toggle('error', isError);
}

function utcToday() { return new Date().toISOString().slice(0, 10); }
function dtLocalToIso(v) { return v ? new Date(v).toISOString() : null; }
function isoToLocal(v) {
  if (!v) return '';
  const d = new Date(v);
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}

async function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result).split(',')[1] || '');
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

async function apiFetch(url, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (!(options.body instanceof FormData)) headers['Content-Type'] = 'application/json';
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(url, { ...options, headers });
  if (response.status === 204) return null;
  const type = response.headers.get('content-type') || '';
  const body = type.includes('application/json') ? await response.json() : await response.text();
  if (!response.ok) throw new Error(body.error || body || 'Request failed');
  return body;
}

function showPanel() {
  if (!token || !currentUser) {
    loginSection.classList.remove('hidden');
    dashboardSection.classList.add('hidden');
    return;
  }
  loginSection.classList.add('hidden');
  dashboardSection.classList.remove('hidden');
  userInfoEl.textContent = `Signed in as ${currentUser.username} (${currentUser.role})`;

  if (currentUser.role === 'ADMIN') {
    adminPanel.classList.remove('hidden');
    crewPanel.classList.add('hidden');
    loadAdminData();
  } else {
    crewPanel.classList.remove('hidden');
    adminPanel.classList.add('hidden');
    document.getElementById('ops-report-day').value = utcToday();
    setCrewView('new');
    loadCrewData();
  }
}

document.getElementById('login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const data = await apiFetch('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        username: document.getElementById('username').value.trim(),
        password: document.getElementById('password').value,
      }),
    });
    token = data.token;
    currentUser = data.user;
    localStorage.setItem('harborlog_token', token);
    localStorage.setItem('harborlog_user', JSON.stringify(currentUser));
    setStatus('Login successful.');
    showPanel();
  } catch (error) { setStatus(error.message, true); }
});

document.getElementById('logout-btn').addEventListener('click', () => {
  token = null; currentUser = null;
  localStorage.removeItem('harborlog_token');
  localStorage.removeItem('harborlog_user');
  setStatus('Logged out.');
  showPanel();
});

async function loadAdminOpsReports() {
  try {
    const rows = await apiFetch('/api/admin/daily-ops-reports');
    document.getElementById('admin-ops-list').innerHTML = rows.map((r) => `<li>${r.report_day} — ${r.vessel_name}<br/>Status: ${r.status}<br/>POB: ${r.pob}<br/><small>Crew: ${r.crew_username} | ID: ${r.id}</small></li>`).join('') || '<li>No daily ops reports yet.</li>';
  } catch (error) { setStatus(error.message, true); }
}

document.getElementById('refresh-admin-ops')?.addEventListener('click', () => loadAdminOpsReports());

async function loadAdminData() {
  try {
    const [vessels, users, assignments] = await Promise.all([
      apiFetch('/api/admin/vessels'), apiFetch('/api/admin/users'), apiFetch('/api/admin/assignments'),
    ]);
    document.getElementById('vessels-list').innerHTML = vessels.map((v) => `<li>${v.name}<br/><small>ID: ${v.id}</small></li>`).join('') || '<li>No vessels yet.</li>';
    document.getElementById('users-list').innerHTML = users.map((u) => `<li>${u.username} (${u.role})<br/><small>ID: ${u.id}</small></li>`).join('') || '<li>No users found.</li>';
    document.getElementById('assignments-list').innerHTML = assignments.map((a) => `<li>${a.username} → ${a.vessel_name}</li>`).join('') || '<li>No assignments yet.</li>';
    document.getElementById('assign-user').innerHTML = users.filter((u) => u.role === 'CREW').map((u) => `<option value="${u.id}">${u.username}</option>`).join('');
    document.getElementById('assign-vessel').innerHTML = vessels.map((v) => `<option value="${v.id}">${v.name}</option>`).join('');
    loadAdminOpsReports();
  } catch (error) { setStatus(error.message, true); }
}

document.getElementById('vessel-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try { await apiFetch('/api/admin/vessels', { method: 'POST', body: JSON.stringify({ name: document.getElementById('vessel-name').value.trim() }) });
    document.getElementById('vessel-name').value = ''; setStatus('Vessel created.'); loadAdminData();
  } catch (error) { setStatus(error.message, true); }
});

document.getElementById('user-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    await apiFetch('/api/admin/users', { method: 'POST', body: JSON.stringify({ username: document.getElementById('new-username').value.trim(), password: document.getElementById('new-password').value, role: document.getElementById('new-role').value }) });
    event.target.reset(); setStatus('User created.'); loadAdminData();
  } catch (error) { setStatus(error.message, true); }
});

document.getElementById('assign-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    await apiFetch('/api/admin/assignments', { method: 'POST', body: JSON.stringify({ user_id: document.getElementById('assign-user').value, vessel_id: document.getElementById('assign-vessel').value }) });
    setStatus('Assignment saved.'); loadAdminData();
  } catch (error) { setStatus(error.message, true); }
});

function setCrewView(view) {
  const views = { new: 'crew-new-entry', timeline: 'crew-timeline', summary: 'crew-summary', report: 'crew-ops-report' };
  const nav = { new: 'nav-new-entry', timeline: 'nav-timeline', summary: 'nav-summary', report: 'nav-report' };
  Object.keys(views).forEach((k) => {
    document.getElementById(views[k]).classList.toggle('hidden', k !== view);
    document.getElementById(nav[k]).classList.toggle('active', k === view);
  });
  if (view === 'report') loadDailyOpsReport();
}

document.getElementById('nav-new-entry').addEventListener('click', () => setCrewView('new'));
document.getElementById('nav-timeline').addEventListener('click', () => setCrewView('timeline'));
document.getElementById('nav-summary').addEventListener('click', () => setCrewView('summary'));
document.getElementById('nav-report').addEventListener('click', () => setCrewView('report'));
document.getElementById('ops-report-day').addEventListener('change', () => loadDailyOpsReport());

async function loadCrewData() {
  try {
    const vessel = await apiFetch('/api/crew/assigned-vessel');
    document.getElementById('assigned-vessel').textContent = `${vessel.name} (ID: ${vessel.id})`;
    document.getElementById('entry-vessel').value = vessel.name;
  } catch (error) {
    document.getElementById('assigned-vessel').textContent = error.message;
    document.getElementById('entry-vessel').value = 'No vessel assigned';
  }
  await Promise.all([loadTimeline(), loadDailySummary(), loadDailyOpsReport()]);
}

async function loadTimeline() {
  try {
    const entries = await apiFetch('/api/crew/entries');
    document.getElementById('timeline-list').innerHTML = entries.map((e) => `<li><strong>${new Date(e.timestamp).toLocaleString()}</strong> — ${e.vessel_name}<br/><em>${e.category}</em><br/>${e.notes}<br/><small>ID: ${e.id}</small></li>`).join('') || '<li>No entries yet.</li>';
  } catch (error) { setStatus(error.message, true); }
}

async function loadDailySummary() {
  try {
    const days = await apiFetch('/api/crew/entries/daily-summary');
    document.getElementById('summary-days').innerHTML = days.map((d) => `<div class="summary-day"><strong>${d.day}</strong> — ${d.vessel_name} (${d.count} entries)<ul>${d.entries.map((e) => `<li>${new Date(e.timestamp).toLocaleTimeString()} [${e.category}] ${e.notes}</li>`).join('')}</ul></div>`).join('') || '<p class="muted">No daily entries available.</p>';
    document.getElementById('summary-day-picker').innerHTML = days.map((d) => `<option value="${d.day}">${d.day} (${d.count})</option>`).join('');
    document.getElementById('export-day-btn').disabled = days.length === 0;
  } catch (error) { setStatus(error.message, true); }
}

function fillOpsForm(source) {
  document.getElementById('position-type').value = source.position_type || 'LatLon';
  document.getElementById('position-text').value = source.position_text || '';
  document.getElementById('ops-status').value = source.status || '';
  document.getElementById('status-notes').value = source.status_notes || '';
  document.getElementById('destination-location').value = source.destination_location || '';
  document.getElementById('eta').value = isoToLocal(source.eta);
  document.getElementById('wind').value = source.wind || '';
  document.getElementById('seas').value = source.seas || '';
  document.getElementById('visibility').value = source.visibility || '';
  document.getElementById('fuel-onboard').value = source.fuel_onboard ?? '';
  document.getElementById('fuel-used-24h').value = source.fuel_used_24h ?? '';
  document.getElementById('ops-water-onboard').value = source.water_onboard ?? '';
  document.getElementById('lube-oil-onboard').value = source.lube_oil_onboard ?? '';
  document.getElementById('fuel-ticket-number').value = source.fuel_ticket_number || '';
  document.getElementById('ops-pob').value = source.pob ?? '';
  document.getElementById('next-crew-change-date').value = source.next_crew_change_date || '';
  document.getElementById('ops-jsa-count').value = source.jsa_count ?? '';
  document.getElementById('jsa-breakdown').value = source.jsa_breakdown || '';
}

function renderTicketLink(targetId, data) {
  const el = document.getElementById(targetId);
  if (data.fuel_ticket_url && data.fuel_ticket_number) {
    el.innerHTML = `Fuel Ticket: <a href="${data.fuel_ticket_url}&token=${encodeURIComponent(token)}" target="_blank" rel="noopener">${data.fuel_ticket_number} (PDF)</a>`;
  } else {
    el.textContent = 'Fuel Ticket: none attached';
  }
}

function renderOmView(data) {
  document.getElementById('om-view').textContent = data.text || 'No report for selected day.';
  renderTicketLink('om-ticket-link', data);
}

function renderOfficeView(data) {
  document.getElementById('office-view').textContent = data.text || 'No report for selected day.';
  renderTicketLink('office-ticket-link', data);
}

async function loadDailyOpsReport() {
  try {
    const day = document.getElementById('ops-report-day').value || utcToday();
    const data = await apiFetch(`/api/crew/daily-ops-report?day=${encodeURIComponent(day)}`);
    document.getElementById('ops-report-day').value = data.report_date;
    if (data.report) fillOpsForm(data.report); else if (data.last_report) fillOpsForm(data.last_report); else fillOpsForm({});
    renderOmView(await apiFetch(`/api/crew/daily-ops-report/view?view=om&day=${encodeURIComponent(day)}`));
    renderOfficeView(await apiFetch(`/api/crew/daily-ops-report/view?view=office&day=${encodeURIComponent(day)}`));
  } catch (error) { setStatus(error.message, true); }
}

document.getElementById('entry-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    await apiFetch('/api/crew/entries', { method: 'POST', body: JSON.stringify({ category: document.getElementById('entry-category').value, notes: document.getElementById('entry-notes').value.trim() }) });
    document.getElementById('entry-notes').value = '';
    setStatus('Entry logged.');
    await Promise.all([loadTimeline(), loadDailySummary()]);
  } catch (error) { setStatus(error.message, true); }
});

document.getElementById('daily-ops-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const attachFile = document.getElementById('fuel-ticket-attachment').files[0];
  if (attachFile) {
    const lower = attachFile.name.toLowerCase();
    const mime = (attachFile.type || '').toLowerCase();
    if (!lower.endsWith('.pdf') || (mime && mime !== 'application/pdf')) {
      setStatus('Fuel ticket attachment must be a PDF file.', true);
      return;
    }
  }
  const attachment = attachFile ? { filename: attachFile.name, content_base64: await fileToBase64(attachFile) } : null;
  const payload = {
    report_date: document.getElementById('ops-report-day').value,
    position_type: document.getElementById('position-type').value,
    position_text: document.getElementById('position-text').value.trim(),
    status: document.getElementById('ops-status').value.trim(),
    status_notes: document.getElementById('status-notes').value.trim(),
    destination_location: document.getElementById('destination-location').value.trim(),
    eta: dtLocalToIso(document.getElementById('eta').value),
    wind: document.getElementById('wind').value.trim(),
    seas: document.getElementById('seas').value.trim(),
    visibility: document.getElementById('visibility').value.trim(),
    fuel_onboard: Number(document.getElementById('fuel-onboard').value),
    fuel_used_24h: Number(document.getElementById('fuel-used-24h').value),
    water_onboard: Number(document.getElementById('ops-water-onboard').value),
    lube_oil_onboard: Number(document.getElementById('lube-oil-onboard').value),
    fuel_ticket_number: document.getElementById('fuel-ticket-number').value.trim(),
    fuel_ticket_attachment: attachment,
    pob: Number(document.getElementById('ops-pob').value),
    next_crew_change_date: document.getElementById('next-crew-change-date').value || null,
    jsa_count: document.getElementById('ops-jsa-count').value === '' ? null : Number(document.getElementById('ops-jsa-count').value),
    jsa_breakdown: document.getElementById('jsa-breakdown').value.trim() || null,
  };
  try {
    await apiFetch('/api/crew/daily-ops-report', { method: 'POST', body: JSON.stringify(payload) });
    setStatus('Midnight Daily Ops Report saved.');
    document.getElementById('fuel-ticket-attachment').value = '';
    await loadDailyOpsReport();
  } catch (error) { setStatus(error.message, true); }
});

document.getElementById('export-day-btn').addEventListener('click', () => {
  const day = document.getElementById('summary-day-picker').value;
  if (!day || !token) return;
  window.open(`/api/crew/entries/export.pdf?day=${encodeURIComponent(day)}&token=${encodeURIComponent(token)}`, '_blank');
});
document.getElementById('export-ops-om-pdf-btn').addEventListener('click', () => {
  const day = document.getElementById('ops-report-day').value || utcToday();
  if (!token) return;
  window.open(`/api/crew/daily-ops-report/export.pdf?view=om&day=${encodeURIComponent(day)}&token=${encodeURIComponent(token)}`, '_blank');
});
document.getElementById('export-ops-office-pdf-btn').addEventListener('click', () => {
  const day = document.getElementById('ops-report-day').value || utcToday();
  if (!token) return;
  window.open(`/api/crew/daily-ops-report/export.pdf?view=office&day=${encodeURIComponent(day)}&token=${encodeURIComponent(token)}`, '_blank');
});

showPanel();
