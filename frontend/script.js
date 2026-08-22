// ─────────────────────────────────────────────
// AEGISGUARD®  Unified PQC Scanner Script
// Aegis Quantum™ Frontend + Aegis Quantum Backend
// ─────────────────────────────────────────────

const BACKEND_URL = window.location.origin;

// ─────────────────────────────────────────────
// AUTH SYSTEM
// ─────────────────────────────────────────────
let authToken = localStorage.getItem('aegis_token') || null;
let authUser  = localStorage.getItem('aegis_user')  || null;
let authProfile = null;

function getAuthHeaders() {
  if (!authToken) return {};
  return { 'Authorization': 'Bearer ' + authToken };
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function showAuthError(msg) {
  const e = document.getElementById('authError');
  if (!e) return;
  e.textContent = msg;
  e.style.display = 'block';
  const s = document.getElementById('authSuccess');
  if (s) s.style.display = 'none';
}

function showAuthSuccess(msg) {
  const s = document.getElementById('authSuccess');
  if (!s) return;
  s.textContent = msg;
  s.style.display = 'block';
  const e = document.getElementById('authError');
  if (e) e.style.display = 'none';
}

function clearAuthMessages() {
  const e = document.getElementById('authError');
  const s = document.getElementById('authSuccess');
  if (e) e.style.display = 'none';
  if (s) s.style.display = 'none';
}

function toggleAuthForm(mode) {
  clearAuthMessages();
  const loginTab = document.getElementById('authLoginTab');
  const registerTab = document.getElementById('authRegisterTab');
  if (mode === 'register') {
    document.getElementById('loginForm').style.display = 'none';
    document.getElementById('registerForm').style.display = 'block';
    loginTab?.classList.remove('active');
    registerTab?.classList.add('active');
  } else {
    document.getElementById('loginForm').style.display = 'block';
    document.getElementById('registerForm').style.display = 'none';
    registerTab?.classList.remove('active');
    loginTab?.classList.add('active');
  }
}

function showAuthModal(mode = 'login') {
  toggleAuthForm(mode);
  document.getElementById('authGate').style.display = 'flex';
}

function hideAuthModal() {
  if (!authToken) return;
  document.getElementById('authGate').style.display = 'none';
}

async function fetchAuthProfile() {
  if (!authToken) return null;
  const r = await fetch(BACKEND_URL + '/auth/me', { headers: getAuthHeaders() });
  if (!r.ok) {
    throw new Error('Session expired');
  }
  const authResponse = await r.json();
  console.log('AUTH:', authResponse);
  return authResponse;
}

function clearAuthState() {
  authToken = null;
  authUser = null;
  authProfile = null;
  localStorage.removeItem('aegis_token');
  localStorage.removeItem('aegis_user');
}

async function verifyAuthSession() {
  if (!authToken) return false;
  try {
    authProfile = await fetchAuthProfile();
    authUser = authProfile?.username || authUser;
    if (authUser) localStorage.setItem('aegis_user', authUser);
    return true;
  } catch {
    clearAuthState();
    return false;
  }
}

function toggleUserMenu() {
  const menu = document.getElementById('userMenu');
  if (!menu) return;
  menu.classList.toggle('open');
}

async function viewProfile() {
  try {
    if (!authProfile) authProfile = await fetchAuthProfile();
    const p = authProfile || {};
    alert(`Profile\n\nUsername: ${p.username || '—'}\nEmail: ${p.email || '—'}\nOrganization: ${p.org_name || '—'}\nScans: ${p.scan_count ?? 0}`);
  } catch (e) {
    showAuthError('Unable to load profile: ' + e.message);
  }
}

function updateAuthUI() {
  const area = document.getElementById('authArea');
  const historyLoginMsg = document.getElementById('historyLoginMsg');
  const historyContent = document.getElementById('historyContent');
  const gate = document.getElementById('authGate');
  if (!area || !historyLoginMsg || !historyContent || !gate) return;

  if (authToken && authUser) {
    const letter = (authUser[0] || 'U').toUpperCase();
    area.innerHTML = `
      <div class="user-chip" id="userChip">
        <button class="user-chip-btn" onclick="toggleUserMenu()">
          <span class="user-avatar">${escapeHtml(letter)}</span>
          <span>${escapeHtml(authUser)}</span>
          <span>▾</span>
        </button>
        <div class="user-menu" id="userMenu">
          <button class="user-menu-item" onclick="viewProfile()">Profile</button>
          <button class="user-menu-item" onclick="doLogout()">Sign out</button>
        </div>
      </div>`;
    historyLoginMsg.style.display = 'none';
    historyContent.style.display = 'block';
    gate.style.display = 'none';
  } else {
    area.innerHTML = `<span id="authBtn" onclick="showAuthModal('login')" style="cursor:pointer;padding:6px 14px;background:var(--teal);color:#fff;border-radius:4px;font-size:13px;font-family:'IBM Plex Mono',monospace">Login</span>`;
    historyLoginMsg.style.display = 'block';
    historyContent.style.display = 'none';
    gate.style.display = 'flex';
  }
}

async function doLogin() {
  const user = document.getElementById('loginUser').value.trim();
  const pass = document.getElementById('loginPass').value;
  if (!user || !pass) return showAuthError('Username and password required');
  try {
    const r = await fetch(BACKEND_URL+'/auth/login', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({username:user, password:pass})
    });
    const d = await r.json();
    if (!r.ok) return showAuthError(d.detail || 'Login failed');
    authToken = d.access_token; authUser = d.username;
    localStorage.setItem('aegis_token', authToken);
    localStorage.setItem('aegis_user', authUser);
    await verifyAuthSession();
    showAuthSuccess('Login successful. Redirecting to dashboard...');
    updateAuthUI();
    loadHistory();
  } catch(e) { showAuthError('Connection error: '+e.message); }
}

async function doRegister() {
  const user = document.getElementById('regUser').value.trim();
  const email = document.getElementById('regEmail').value.trim();
  const name = document.getElementById('regName').value.trim();
  const org = document.getElementById('regOrg').value.trim();
  const pass = document.getElementById('regPass').value;
  if (!user || !email || !pass) return showAuthError('Username, email, and password required');
  try {
    const r = await fetch(BACKEND_URL+'/auth/register', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({username:user, email:email, password:pass, full_name:name, org_name:org})
    });
    const d = await r.json();
    if (!r.ok) return showAuthError(d.detail || 'Registration failed');
    authToken = d.access_token; authUser = d.username;
    localStorage.setItem('aegis_token', authToken);
    localStorage.setItem('aegis_user', authUser);
    await verifyAuthSession();
    showAuthSuccess('Registration complete. You are now signed in.');
    updateAuthUI();
    loadHistory();
  } catch(e) { showAuthError('Connection error: '+e.message); }
}

function doLogout() {
  clearAuthState();
  updateAuthUI();
  showAuthModal('login');
}

// ─────────────────────────────────────────────
// SCAN HISTORY
// ─────────────────────────────────────────────
async function loadHistory() {
  if (!authToken) return;
  try {
    const r = await fetch(BACKEND_URL+'/history/?limit=50', {headers: getAuthHeaders()});
    if (r.status===401) { doLogout(); return; }
    const d = await r.json();
    console.log('HISTORY:', d);
    const tbody = document.getElementById('historyTableBody');
    const empty = document.getElementById('historyEmpty');
    const stats = document.getElementById('historyStats');
    if (!d.scans || d.scans.length===0) {
      tbody.innerHTML=''; empty.style.display='block'; stats.innerHTML='';
      return;
    }
    empty.style.display='none';
    // Stats
    const totalScans = d.total;
    const pqcSafe = d.scans.filter(s=>s.pqc_safe).length;
    const avgScore = Math.round(d.scans.reduce((a,s)=>a+s.score,0)/d.scans.length);
    stats.innerHTML = `
      <div style="background:var(--card);border:1px solid var(--border);padding:12px 20px;border-radius:6px;text-align:center;flex:1;min-width:120px">
        <div style="font-size:24px;font-weight:700;color:var(--teal)">${totalScans}</div>
        <div style="font-size:11px;color:var(--text2)">Total Scans</div>
      </div>
      <div style="background:var(--card);border:1px solid var(--border);padding:12px 20px;border-radius:6px;text-align:center;flex:1;min-width:120px">
        <div style="font-size:24px;font-weight:700;color:var(--green)">${pqcSafe}</div>
        <div style="font-size:11px;color:var(--text2)">PQC Safe</div>
      </div>
      <div style="background:var(--card);border:1px solid var(--border);padding:12px 20px;border-radius:6px;text-align:center;flex:1;min-width:120px">
        <div style="font-size:24px;font-weight:700;color:var(--purple)">${avgScore}/100</div>
        <div style="font-size:11px;color:var(--text2)">Avg Score</div>
      </div>`;
    // Table
    tbody.innerHTML = d.scans.map(s => `<tr>
      <td style="font-size:11px">${formatDate(s.created_at)}</td>
      <td><strong>${s.target}</strong></td>
      <td>${s.port}</td>
      <td><span style="color:${s.score>=70?'var(--green)':s.score>=40?'var(--yellow)':'var(--red)'}">${s.score}</span></td>
      <td><span style="font-weight:700;color:${s.grade<='B'?'var(--green)':s.grade<='C'?'var(--yellow)':'var(--red)'}">${s.grade}</span></td>
      <td>${s.pqc_safe?'<span style="color:var(--green)">✓ Safe</span>':'<span style="color:var(--red)">✗ Vuln</span>'}</td>
      <td style="font-size:11px">${s.tls_version||'—'}</td>
      <td>
        <span onclick="viewHistoryScan(${s.id})" style="cursor:pointer;color:var(--teal);font-size:11px;text-decoration:underline">View</span>
        <span onclick="deleteHistoryScan(${s.id})" style="cursor:pointer;color:var(--red);font-size:11px;margin-left:8px">✕</span>
      </td>
    </tr>`).join('');
  } catch(e) { console.error('History load error:', e); }
}

async function viewHistoryScan(id) {
  try {
    const r = await fetch(BACKEND_URL+'/history/'+id, {headers: getAuthHeaders()});
    const d = await r.json();
    if (d.scan_data) {
      // Load into the single scan view
      switchTab('scan', document.querySelector('.tab-bar .tab'));
      const host = d.scan_data?.raw_tls?.host || d.target || 'unknown';
      const scanPort = d.scan_data?.raw_tls?.port || d.port || 443;
      render(host, scanPort, d.mode || 'history', d.scan_data);
    }
  } catch(e) { console.error(e); }
}

async function deleteHistoryScan(id) {
  if (!confirm('Delete this scan from history?')) return;
  try {
    await fetch(BACKEND_URL+'/history/'+id, {method:'DELETE', headers: getAuthHeaders()});
    loadHistory();
  } catch(e) { console.error(e); }
}

async function clearHistory() {
  if (!confirm('Clear ALL scan history? This cannot be undone.')) return;
  try {
    await fetch(BACKEND_URL+'/history/', {method:'DELETE', headers: getAuthHeaders()});
    loadHistory();
  } catch(e) { console.error(e); }
}

async function bootstrapAuth() {
  await verifyAuthSession();
  updateAuthUI();
  if (authToken) loadHistory();
}

function bindAuthForms() {
  const loginForm = document.getElementById('loginForm');
  const registerForm = document.getElementById('registerForm');
  if (loginForm) {
    loginForm.addEventListener('submit', function (e) {
      e.preventDefault();
      doLogin();
    });
  }
  if (registerForm) {
    registerForm.addEventListener('submit', function (e) {
      e.preventDefault();
      doRegister();
    });
  }
}

function resetLiveView() {
  const results = document.getElementById('results');
  const loader = document.getElementById('loader');
  const scanLog = document.getElementById('scanLog');
  if (loader) loader.style.display = 'none';
  if (results) results.style.display = 'none';
  if (scanLog) scanLog.innerHTML = '';
}

document.addEventListener('click', (event) => {
  const chip = document.getElementById('userChip');
  const menu = document.getElementById('userMenu');
  if (!chip || !menu) return;
  if (!chip.contains(event.target)) {
    menu.classList.remove('open');
  }
});

window.addEventListener('DOMContentLoaded', () => {
  bindAuthForms();
  if (!window.__app_initialized) {
    window.__app_initialized = true;
    bootstrapAuth();
  }
});

document.getElementById('currentDate').textContent =
  new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });

// ─────────────────────────────────────────────
// ALGO DATABASE
// ─────────────────────────────────────────────
const ALGOS = [
  { id:'mlkem512',    label:'ML-KEM-512',        type:'KEM',        nist:'approved',   lvl:1, qs:true,  std:'FIPS 203',          ks:'800B pk',              rec:'IoT / constrained devices' },
  { id:'mlkem768',    label:'ML-KEM-768',        type:'KEM',        nist:'approved',   lvl:3, qs:true,  std:'FIPS 203',          ks:'1184B pk',             rec:'Recommended baseline' },
  { id:'mlkem1024',   label:'ML-KEM-1024',       type:'KEM',        nist:'approved',   lvl:5, qs:true,  std:'FIPS 203',          ks:'1568B pk',             rec:'High-security environments' },
  { id:'mldsa44',     label:'ML-DSA-44',         type:'Signature',  nist:'approved',   lvl:2, qs:true,  std:'FIPS 204',          ks:'1312B pk',             rec:'General use, Level 2' },
  { id:'mldsa65',     label:'ML-DSA-65',         type:'Signature',  nist:'approved',   lvl:3, qs:true,  std:'FIPS 204',          ks:'1952B pk',             rec:'Recommended standard' },
  { id:'mldsa87',     label:'ML-DSA-87',         type:'Signature',  nist:'approved',   lvl:5, qs:true,  std:'FIPS 204',          ks:'2592B pk',             rec:'High-assurance systems' },
  { id:'slhdsa128s',  label:'SLH-DSA-128s',      type:'Signature',  nist:'approved',   lvl:1, qs:true,  std:'FIPS 205',          ks:'32B pk',               rec:'Hash-based, conservative' },
  { id:'slhdsa256f',  label:'SLH-DSA-256f',      type:'Signature',  nist:'approved',   lvl:5, qs:true,  std:'FIPS 205',          ks:'64B pk',               rec:'Fast variant, high security' },
  { id:'falcon512',   label:'FALCON-512',         type:'Signature',  nist:'pending',    lvl:1, qs:true,  std:'Draft FIPS 206',    ks:'897B pk',              rec:'Compact — await FIPS 206' },
  { id:'x25519mlkem', label:'X25519+ML-KEM-768', type:'Hybrid KEM', nist:'approved',   lvl:3, qs:true,  std:'RFC 9180+FIPS 203', ks:'32B+1184B',            rec:'Recommended during migration' },
  { id:'ecdh256',     label:'ECDH P-256',         type:'KEM',        nist:'deprecated', lvl:0, qs:false, std:'ANSI X9.63',        ks:'32B (vulnerable)',     rec:'REPLACE with ML-KEM now' },
  { id:'rsa2048',     label:'RSA-2048',           type:'KEM',        nist:'deprecated', lvl:0, qs:false, std:'PKCS#1',            ks:'256B (vulnerable)',    rec:'REPLACE with ML-KEM now' },
  { id:'ecdsa256',    label:'ECDSA P-256',        type:'Signature',  nist:'deprecated', lvl:0, qs:false, std:'ANSI X9.62',        ks:'32B (vulnerable)',     rec:'REPLACE with ML-DSA now' },
  { id:'aes256',      label:'AES-256-GCM',        type:'Symmetric',  nist:'approved',   lvl:5, qs:true,  std:'FIPS 197',          ks:'256-bit key',          rec:'Recommended symmetric' },
  { id:'chacha',      label:'ChaCha20-Poly1305',  type:'Symmetric',  nist:'approved',   lvl:4, qs:true,  std:'RFC 8439',          ks:'256-bit key',          rec:'Recommended symmetric' },
];

const SEL = new Set(['mlkem768','mldsa65','x25519mlkem','ecdh256','rsa2048','ecdsa256','aes256','chacha']);

// ─────────────────────────────────────────────
// CHIPS BAR
// ─────────────────────────────────────────────
(function(){
  const groups = [
    { lbl:'ML-KEM:',    ids:['mlkem512','mlkem768','mlkem1024'] },
    { lbl:'ML-DSA:',    ids:['mldsa44','mldsa65','mldsa87'] },
    { lbl:'SLH-DSA:',   ids:['slhdsa128s','slhdsa256f','falcon512'] },
    { lbl:'Hybrid:',    ids:['x25519mlkem'] },
    { lbl:'Classical:', ids:['ecdh256','rsa2048','ecdsa256','aes256','chacha'] },
  ];
  const c = document.getElementById('chips');
  groups.forEach(g => {
    const sep = document.createElement('span');
    sep.className = 'chip-sep'; sep.textContent = g.lbl; c.appendChild(sep);
    g.ids.forEach(id => {
      const a = ALGOS.find(x => x.id === id);
      if (!a) return;
      const ch = document.createElement('span');
      ch.className = 'chip' + (SEL.has(id) ? ' active' : '');
      ch.textContent = a.label;
      ch.onclick = () => { SEL.has(id) ? SEL.delete(id) : SEL.add(id); ch.classList.toggle('active'); };
      c.appendChild(ch);
    });
  });
})();

// ─────────────────────────────────────────────
// CHARTS
// ─────────────────────────────────────────────
Chart.defaults.color = '#8d8d8d';
Chart.defaults.font.family = "'IBM Plex Mono', monospace";
let c1, c2, c3, cBar;

const SCAN_HISTORY_KEY = 'aegis_scan_history_v1';
const MAX_SCAN_HISTORY = 50;

function clampRiskScore(score) {
  const n = Number(score);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(100, Math.round(n)));
}

function parseScanHistorySafe(raw) {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (e) {
    console.warn('[AegisGuard] Failed to parse local scan history, resetting.', e);
    return [];
  }
}

function loadScanHistory() {
  try {
    const raw = localStorage.getItem(SCAN_HISTORY_KEY);
    const records = parseScanHistorySafe(raw)
      .map((r) => {
        const ts = new Date(r?.timestamp || 0);
        const validTs = Number.isFinite(ts.getTime());
        const domain = typeof r?.domain === 'string' ? r.domain.trim() : '';
        return {
          timestamp: validTs ? ts.toISOString() : new Date(0).toISOString(),
          domain: domain || 'unknown',
          score: clampRiskScore(r?.score),
          pqcSafe: Boolean(r?.pqcSafe),
          _validTs: validTs,
        };
      })
      .filter((r) => r._validTs);

    records.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
    return records.slice(-MAX_SCAN_HISTORY).map(({ _validTs, ...r }) => r);
  } catch (e) {
    console.warn('[AegisGuard] localStorage unavailable, returning empty history.', e);
    return [];
  }
}

function saveScanResult(domain, score, pqcSafe) {
  const safeDomain = (domain || '').trim();
  if (!safeDomain) return loadScanHistory();

  const history = loadScanHistory();
  history.push({
    timestamp: new Date().toISOString(),
    domain: safeDomain,
    score: clampRiskScore(score),
    pqcSafe: Boolean(pqcSafe),
  });

  const bounded = history.slice(-MAX_SCAN_HISTORY);
  try {
    localStorage.setItem(SCAN_HISTORY_KEY, JSON.stringify(bounded));
  } catch (e) {
    console.warn('[AegisGuard] Failed to persist scan history.', e);
  }
  return bounded;
}

function getTrendChartData(granularity = 'scan') {
  const history = loadScanHistory();
  if (!history.length) {
    return { labels: ['No history'], scores: [0], domains: ['—'], latestIndex: -1, hasData: false };
  }

  if (granularity === 'day' || granularity === 'month') {
    const grouped = new Map();
    history.forEach((r) => {
      const d = new Date(r.timestamp);
      const key = granularity === 'month'
        ? `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`
        : `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}-${String(d.getUTCDate()).padStart(2, '0')}`;
      const curr = grouped.get(key) || { total: 0, count: 0, domain: r.domain, ts: r.timestamp };
      curr.total += clampRiskScore(r.score);
      curr.count += 1;
      curr.domain = r.domain;
      curr.ts = r.timestamp;
      grouped.set(key, curr);
    });

    const rows = Array.from(grouped.values()).slice(-MAX_SCAN_HISTORY).map((g) => {
      const d = new Date(g.ts);
      return {
        label: granularity === 'month'
          ? d.toLocaleDateString('en-US', { month: 'short', year: 'numeric' })
          : d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
        score: clampRiskScore(g.count ? g.total / g.count : 0),
        domain: g.domain,
      };
    });

    return {
      labels: rows.map((r) => r.label),
      scores: rows.map((r) => r.score),
      domains: rows.map((r) => r.domain),
      latestIndex: rows.length - 1,
      hasData: rows.length > 0,
    };
  }

  const rows = history.slice(-MAX_SCAN_HISTORY).map((r) => {
    const d = new Date(r.timestamp);
    return {
      label: d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
      score: clampRiskScore(r.score),
      domain: r.domain,
    };
  });

  return {
    labels: rows.map((r) => r.label),
    scores: rows.map((r) => r.score),
    domains: rows.map((r) => r.domain),
    latestIndex: rows.length - 1,
    hasData: rows.length > 0,
  };
}

function normalizeTrendData(trend) {
  if (trend && Array.isArray(trend.labels) && Array.isArray(trend.scores)) {
    return {
      labels: trend.labels,
      scores: trend.scores.map(clampRiskScore),
      domains: Array.isArray(trend.domains) ? trend.domains : trend.labels.map(() => '—'),
      latestIndex: Number.isInteger(trend.latestIndex) ? trend.latestIndex : trend.scores.length - 1,
      hasData: Boolean(trend.hasData),
    };
  }

  const scores = Array.isArray(trend) ? trend.map(clampRiskScore) : [];
  return {
    labels: scores.map((_, i) => `Scan ${i + 1}`),
    scores: scores.length ? scores : [0],
    domains: scores.map(() => '—'),
    latestIndex: scores.length - 1,
    hasData: scores.length > 0,
  };
}

function initCharts(pqcPct, vulnPct, partialPct, tlsVer, kemType, trend) {
  if (c1) c1.destroy(); if (c2) c2.destroy(); if (c3) c3.destroy(); if (cBar) cBar.destroy();
  const trendData = normalizeTrendData(trend);
  const cut = '88%';
  c1 = new Chart(document.getElementById('chart1'), {
    type:'doughnut',
    data:{ datasets:[{ data:[pqcPct,partialPct,vulnPct], backgroundColor:['#24a148','#f1c21b','#da1e28'], borderWidth:0, cutout:cut }] },
    options:{ responsive:true, maintainAspectRatio:false, animation:{duration:1000}, plugins:{tooltip:{enabled:false}} }
  });
  c2 = new Chart(document.getElementById('chart2'), {
    type:'doughnut',
    data:{ datasets:[{ data: tlsVer==='1.3'?[80,20,0]:tlsVer==='1.2'?[0,100,0]:[0,30,70], backgroundColor:['#08bdba','#8a3ffc','#da1e28'], borderWidth:0, cutout:cut }] },
    options:{ responsive:true, maintainAspectRatio:false, plugins:{tooltip:{enabled:false}} }
  });
  c3 = new Chart(document.getElementById('chart3'), {
    type:'doughnut',
    data:{ datasets:[{ data: kemType==='pqc'?[80,20,0]:kemType==='hybrid'?[30,60,10]:[0,10,90], backgroundColor:['#8a3ffc','#1192e8','#da1e28'], borderWidth:0, cutout:cut }] },
    options:{ responsive:true, maintainAspectRatio:false, plugins:{tooltip:{enabled:false}} }
  });
  cBar = new Chart(document.getElementById('barChart'), {
    type:'bar',
    data:{
      labels: trendData.labels,
      datasets:[{
        data: trendData.scores,
        backgroundColor: trendData.scores.map((_, idx) =>
          !trendData.hasData ? '#525252' : (idx === trendData.latestIndex ? '#08bdba' : '#d02670')
        ),
        barThickness: 28,
      }]
    },
    options:{
      responsive:true,
      maintainAspectRatio:false,
      plugins:{
        legend:{display:false},
        title:{
          display: !trendData.hasData,
          text: 'No scan history available',
          color: '#8d8d8d',
          font: { family: "'IBM Plex Mono', monospace", size: 11 },
        },
        tooltip:{
          enabled: trendData.hasData,
          callbacks:{
            label: (ctx) => {
              const domain = trendData.domains?.[ctx.dataIndex] || 'unknown';
              const score = clampRiskScore(ctx.raw);
              return `${domain} — ${score}/100`;
            }
          }
        }
      },
      scales:{
        y:{beginAtZero:true,grid:{color:'#393939'},max:100,ticks:{font:{size:10}}},
        x:{grid:{display:false},ticks:{font:{size:10}}}
      }
    }
  });
}
initCharts(0,100,0,'unknown','classical', getTrendChartData('day'));

// ─────────────────────────────────────────────
// BACKEND CHECK
// ─────────────────────────────────────────────
async function checkBackend() {
  const el = document.getElementById('backendStatus');
  const loginEl = document.getElementById('loginBackendStatus');
  try {
    const r = await fetch(`${BACKEND_URL}/health`, { signal: AbortSignal.timeout(3000) });
    if (r.ok) {
      el.textContent='✓ BACKEND READY';
      el.className='ibm-badge backend-ok';
      if (loginEl) {
        loginEl.textContent = 'Backend status: ONLINE';
        loginEl.style.color = 'var(--green)';
        loginEl.style.borderColor = 'var(--green)';
      }
    }
    else throw new Error();
  } catch {
    el.textContent='✕ BACKEND OFFLINE'; el.className='ibm-badge backend-err';
    if (loginEl) {
      loginEl.textContent = 'Backend status: OFFLINE';
      loginEl.style.color = 'var(--red)';
      loginEl.style.borderColor = 'var(--red)';
    }
  }
}
checkBackend();

// ─────────────────────────────────────────────
// STATE
// ─────────────────────────────────────────────
let scanResults = null;
let lastCBOM = null;
const delay = (a,b) => new Promise(r => setTimeout(r, a + Math.random()*(b-a)));

// ─────────────────────────────────────────────
// TAB SWITCH
// ─────────────────────────────────────────────
function switchTab(name, btn) {
  document.querySelectorAll('.tab-content').forEach(t => t.style.display = 'none');
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  const tc = document.getElementById('tab-' + name);
  if (tc) tc.style.display = 'block';
  btn.classList.add('active');

  if (name === 'reporting') {
    showReportPanel('ondemand');
  }
}

// ─────────────────────────────────────────────
// MAIN SCAN
// ─────────────────────────────────────────────
async function startScan(event) {
  if (event?.preventDefault) event.preventDefault();
  const target = document.getElementById('target').value.trim() || 'example.com';
  const port   = document.getElementById('port').value.trim()   || '443';
  const mode   = document.getElementById('mode').value;

  const statusEl = document.getElementById('backendStatus');
  if (statusEl.className.includes('backend-err')) {
    alert('Backend scanner is offline.\n\nStart it:\n  pip install fastapi uvicorn pyOpenSSL\n  python app.py\n\nThen refresh.'); return;
  }

  document.getElementById('results').style.display = 'none';
  document.getElementById('loader').style.display  = 'flex';
  document.getElementById('mainScanBtn').disabled  = true;
  document.getElementById('scanLog').innerHTML     = '';
  document.getElementById('loaderStatus').textContent = `INITIATE LIVE SCANNING ${target}:${port}`;

  const logEl = document.getElementById('scanLog');
  function addLog(type, txt) {
    const colors = {pqc:'#08bdba', ok:'#24a148', bad:'#da1e28', warn:'#f1c21b'};
    const pfx    = {pqc:'[PQC]', ok:'[ OK]', bad:'[ERR]', warn:'[WRN]'};
    const ln = document.createElement('div');
    ln.className = 'log-line';
    ln.innerHTML = `<span style="color:${colors[type]}">${pfx[type]}</span> ${txt}`;
    logEl.appendChild(ln); logEl.scrollTop = logEl.scrollHeight;
  }

  addLog('pqc', `Initiating TLS probe of ${target}:${port}...`);
  await delay(150,300);
  addLog('ok',  'AegisGuard v1.0.0 backend connected');
  await delay(100,200);
  addLog('pqc', 'Opening TLS handshake & negotiating cipher...');
  await delay(200,400);
  addLog('pqc', 'Running PQC analysis + CVE intelligence + HNDL timeline...');
  await delay(100,200);
  addLog('pqc', 'Auditing security headers + compliance mapping...');
  await delay(100,200);
  addLog('pqc', 'Calculating crypto agility score + generating CBOM...');
  await delay(100,200);

  let data;
  try {
    const resp = await fetch(`${BACKEND_URL}/scan`, {
      method:'POST',
      headers:{'Content-Type':'application/json', ...getAuthHeaders()},
      body: JSON.stringify({ target, port: parseInt(port), mode }),
      signal: AbortSignal.timeout(120000)
    });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ detail: resp.statusText }));
      throw new Error(err.detail || `HTTP ${resp.status}`);
    }
    data = await resp.json();
    console.log('[AegisGuard] /scan response:', data);

    addLog('ok',  `TLS: ${data.tls_version || '?'} | Cipher: ${data.raw_tls?.cipher_suite || 'parsed'}`);
    await delay(80,150);
    addLog('pqc', `KEX: ${data.kem_name || 'analyzed'} | PQC: ${data.quantum_safe ? '✓ SAFE' : '✗ VULNERABLE'}`);
    await delay(80,150);
    if (data.probe?.cert_subject) addLog('ok', `Cert: ${data.probe.cert_subject}`);
    await delay(80,150);
    addLog('pqc', `Score: ${data.score}/100 | Grade: ${data.grade} | Label: ${data.pqc_label || 'N/A'}`);
    await delay(80,150);
    if (data.validation) addLog(data.validation.low_confidence ? 'warn' : 'ok', `Validation: ${(Number(data.validation.confidence) || 0).toFixed(2)} confidence${data.validation.low_confidence ? ' (low confidence)' : ''}`);
    await delay(60,120);
    if (data.ai_insights?.severity) addLog(data.ai_insights.priority <= 2 ? 'warn' : 'ok', `AI Insight: ${data.ai_insights.severity} severity | priority ${data.ai_insights.priority}`);
    await delay(60,120);
    // v1.0.0 intelligence pipeline logs
    if (data.cve_intelligence) addLog(data.cve_intelligence.length > 0 ? 'warn' : 'ok', `CVE Intel: ${data.cve_intelligence.length} vulnerabilities cross-referenced`);
    await delay(60,120);
    if (data.hndl_timeline) addLog('pqc', `HNDL Threat: ${data.hndl_timeline.overall_threat || 'analyzed'}`);
    await delay(60,120);
    if (data.security_headers) addLog(data.security_headers.grade === 'F' || data.security_headers.grade === 'D' ? 'warn' : 'ok', `Security Headers: Grade ${data.security_headers.grade} (${data.security_headers.score}/${data.security_headers.max_score})`);
    await delay(60,120);
    if (data.crypto_agility) addLog('pqc', `Crypto Agility: Grade ${data.crypto_agility.grade} — Migration: ${data.crypto_agility.migration_difficulty}`);
    await delay(60,120);
    if (data.compliance) addLog('ok', `Compliance: ${Object.keys(data.compliance).length} frameworks evaluated (RBI/PCI-DSS/ISO/NIST/SEBI/CERT-In)`);
    await delay(80,150);
    addLog('ok',  'CBOM generated | All intelligence pipelines complete');
    await delay(100,200);

  } catch(e) {
    addLog('bad', `Scan error: ${e.message}`);
    await delay(400,600);
    document.getElementById('loader').style.display  = 'none';
    document.getElementById('mainScanBtn').disabled  = false;
    alert(`Scan failed: ${e.message}\n\nMake sure app.py is running:\n  python app.py`); return;
  }

  document.getElementById('loader').style.display  = 'none';
  document.getElementById('mainScanBtn').disabled  = false;
  saveScanResult(target, data?.score, data?.quantum_safe);
  scanResults = { target, port, mode, data };
  lastCBOM    = data.cbom || null;
  render(target, port, mode, data);
  if (authToken) loadHistory(); // Auto-refresh history after scan
  loadReportScans();

  if (data.cert_eligible) {
    autoDownloadCertificate(target, port, data.grade).catch((e) => {
      console.warn('Auto certificate download failed:', e);
    });
  }
}

// ─────────────────────────────────────────────
// RENDER
// ─────────────────────────────────────────────
function riskSeverityRank(severity) {
  const key = String(severity || 'INFO').toUpperCase();
  if (key === 'CRITICAL') return 0;
  if (key === 'HIGH') return 1;
  if (key === 'MEDIUM') return 2;
  return 3;
}

function riskSeverityClass(severity) {
  const key = String(severity || 'INFO').toUpperCase();
  if (key === 'CRITICAL') return 'critical';
  if (key === 'HIGH') return 'high';
  if (key === 'MEDIUM') return 'medium';
  return 'info';
}

function normalizeRiskPenalties(data) {
  const raw = Array.isArray(data?.risk_penalties)
    ? data.risk_penalties
    : Array.isArray(data?.score_breakdown?.finding_details)
      ? data.score_breakdown.finding_details.map((f, i) => ({
          id: i + 1,
          severity: String(f?.severity || 'Info').toUpperCase(),
          category: String(f?.category || 'tls').toLowerCase(),
          category_label: String(f?.category || 'TLS').toUpperCase(),
          reason: f?.message || 'Risk factor identified',
          deduction: Number(f?.impact || 0),
        }))
      : [];

  return raw
    .map((item, idx) => ({
      id: item?.id || idx + 1,
      severity: String(item?.severity || 'INFO').toUpperCase(),
      category: String(item?.category || 'tls').toLowerCase(),
      category_label: item?.category_label || String(item?.category || 'tls').toUpperCase(),
      reason: item?.reason || 'Risk factor identified',
      deduction: Number(item?.deduction || 0),
    }))
    .sort((a, b) => {
      const severityDelta = riskSeverityRank(a.severity) - riskSeverityRank(b.severity);
      if (severityDelta !== 0) return severityDelta;
      return b.deduction - a.deduction;
    });
}

function getRiskCategoryTotals(data, penalties, deducted) {
  const fromBackend = data?.score_breakdown?.category_totals || {};
  const keys = ['tls', 'cipher', 'certificate', 'hsts', 'pqc'];
  const totals = {};

  keys.forEach((key) => {
    const val = Number(fromBackend[key]);
    totals[key] = Number.isFinite(val) ? val : 0;
  });

  const backendTotal = keys.reduce((acc, k) => acc + totals[k], 0);
  if (backendTotal <= 0 && penalties.length) {
    penalties.forEach((p) => {
      const bucket = keys.includes(p.category) ? p.category : 'tls';
      totals[bucket] += Number(p.deduction || 0);
    });
  }

  const finalTotal = keys.reduce((acc, k) => acc + totals[k], 0);
  if (finalTotal <= 0 && deducted > 0) {
    totals.tls = deducted;
  }

  return totals;
}

function renderRiskBreakdown(data) {
  const panel = document.getElementById('riskBreakdownPanel');
  const equation = document.getElementById('riskScoreEquation');
  const barsRoot = document.getElementById('riskCategoryBars');
  const findingsRoot = document.getElementById('riskFindingsList');
  if (!panel || !equation || !barsRoot || !findingsRoot) return;

  const score = clampRiskScore(data?.score);
  const deducted = Math.max(0, Number((100 - score).toFixed(2)));
  const penalties = normalizeRiskPenalties(data);
  const categoryTotals = getRiskCategoryTotals(data, penalties, deducted);
  const maxForBars = Math.max(deducted, 1);

  const finalColor = score >= 80 ? 'var(--green)' : score >= 60 ? 'var(--yellow)' : 'var(--red)';
  equation.innerHTML = `100 - <span style="color:var(--red)">${deducted.toFixed(1)}</span> = <span style="color:${finalColor}">${score}</span>`;

  const categoryMeta = [
    { key: 'tls', label: 'TLS', color: '#ff832b' },
    { key: 'cipher', label: 'Cipher', color: '#8a3ffc' },
    { key: 'certificate', label: 'Certificate', color: '#da1e28' },
    { key: 'hsts', label: 'HSTS', color: '#1192e8' },
    { key: 'pqc', label: 'PQC', color: '#08bdba' },
  ];

  barsRoot.innerHTML = categoryMeta.map((meta) => {
    const value = Number(categoryTotals[meta.key] || 0);
    const fillPct = Math.max(0, Math.min(100, (value / maxForBars) * 100));
    return `<div class="risk-bar-row">
      <span>${meta.label}</span>
      <div class="risk-bar-track"><div class="risk-bar-fill" style="--fill:${fillPct}%;background:${meta.color}"></div></div>
      <span>-${value.toFixed(1)}</span>
    </div>`;
  }).join('');

  requestAnimationFrame(() => {
    barsRoot.querySelectorAll('.risk-bar-fill').forEach((el) => el.classList.add('animate'));
  });

  if (!penalties.length) {
    findingsRoot.innerHTML = `<div class="risk-findings-item"><div class="risk-reason">No deductions applied for this scan.</div></div>`;
  } else {
    findingsRoot.innerHTML = penalties.map((item) => {
      const sevClass = riskSeverityClass(item.severity);
      return `<div class="risk-findings-item">
        <div class="risk-findings-head">
          <span class="risk-severity risk-severity-${sevClass}">${item.severity}</span>
          <span class="risk-deduction">-${Number(item.deduction || 0).toFixed(1)}</span>
        </div>
        <div class="risk-reason">${escapeHtml(item.reason)}</div>
      </div>`;
    }).join('');
  }

  panel.style.display = 'block';
}

function render(target, port, mode, d) {
  try {
    const probe = d.probe || {};
    const storedTrend = getTrendChartData('day');
    const liveTrend = Array.isArray(d.trend) ? d.trend : [];
    const trendData = (storedTrend && storedTrend.labels && storedTrend.labels.length)
      ? storedTrend
      : { labels: liveTrend.map((_, i) => `T-${(liveTrend.length - 1 - i)}`), data: liveTrend };

    initCharts(d.pqc_pct ?? 0, d.vuln_pct ?? 100, d.partial_pct ?? 0,
               d.tls_version||'unknown', d.kem_type||'classical',
               trendData);

    document.getElementById('scoreVal').textContent    = d.score ?? '—';
    document.getElementById('protocolVal').textContent = d.tls_version || '—';
    document.getElementById('kemVal').textContent      = 'KEM';
    document.getElementById('kemLbl').textContent      = d.kem_name || 'Unknown';

    // PQC Label
    const labelEl = document.getElementById('pqcLabelBadge');
    const labelWrap = document.getElementById('pqcLabelWrap');
    if (labelWrap) labelWrap.style.display = 'block';
    const lbl = String(d.pqc_label || d.cbom?.pqcAssessment?.status || (d.quantum_safe ? 'Fully Quantum Safe' : 'Not Quantum Safe'));
    if (labelEl) {
      labelEl.textContent = lbl;
      labelEl.className = 'pqc-label-badge ' + (
        lbl.includes('Fully') ? 'pqc-label-safe' :
        lbl.includes('Hybrid') ? 'pqc-label-hybrid' : 'pqc-label-vuln'
      );
    }

  // Policy table
  const timeNow = new Date().toLocaleTimeString('en-US',{hour:'numeric',minute:'2-digit'}).toLowerCase();
  const today   = new Date().toLocaleDateString('en-US',{month:'short',day:'numeric',year:'numeric'});
  const pc = d.policy_compliance || {};
  const policies = [
    {name:'Key Exchange',    safe:pc.key_exchange,   type:'kem'},
    {name:'Digital Sig',     safe:pc.digital_sig,    type:'sig'},
    {name:'Cipher Suite',    safe:pc.cipher_suite,   type:'sym'},
    {name:'TLS Protocol',    safe:pc.tls_protocol,   type:'tls'},
    {name:'PQC Compliance',  safe:pc.pqc_compliance, type:'pqc'},
  ];
    document.getElementById('policyTable').innerHTML = policies.map(p => {
    const sev = p.safe
      ? `<span class="sev-l">■</span> Low`
      : p.type==='kem' ? `<span class="sev-c">▲</span> Critical` : `<span class="sev-h">▲</span> High`;
    return `<tr>
      <td><span class="arrow-down">∨</span>${p.name}</td>
      <td style="color:var(--muted);font-size:11px">${today}<br>${timeNow}</td>
      <td style="color:${p.safe?'var(--green)':'var(--orange)'}">${p.safe?'Compliant':'Open'}</td>
      <td>${sev}</td></tr>`;
  }).join('');

    document.getElementById('resultsHost').textContent = `${target}:${port}`;
    document.getElementById('resultsMeta').textContent =
      `LIVE SCAN · ${new Date().toUTCString()} · ${mode.toUpperCase()} · IP: ${probe.ip||'N/A'} · ${d.scan_time_ms||'—'}ms`;

    const grade = d.grade || 'F';
    const gc = document.getElementById('gradeCircle');
    if (gc) gc.className = `grade-circle grade-${grade.replace('+','')}`;
    document.getElementById('gradeVal').textContent = grade;

    const pqcPct = Number.isFinite(d.pqc_pct) ? d.pqc_pct : (d.quantum_safe ? 100 : 0);
    const vulnPct = Number.isFinite(d.vuln_pct) ? d.vuln_pct : (d.quantum_safe ? 0 : 100);
    const validationConfidence = Number.isFinite(Number(d.validation?.confidence)) ? Number(d.validation.confidence) : Number(d.confidence || 0);
    document.getElementById('statsRow').innerHTML = [
    {n:d.score ?? 0,             l:'SECURITY SCORE', c:'var(--teal)'},
    {n:Math.round(pqcPct)+'%',   l:'PQC COVERAGE',   c:'var(--green)'},
    {n:Math.round(vulnPct)+'%',  l:'VULNERABLE',     c:'var(--red)'},
    {n:Math.round(validationConfidence * 100) + '%', l:'CONFIDENCE', c:validationConfidence < 0.7 ? 'var(--orange)' : 'var(--green)'},
    {n:probe.hsts?'YES':'NO',l:'HSTS ENABLED',   c:probe.hsts?'var(--green)':'var(--orange)'},
    {n:d.tls_version||'—',  l:'TLS VERSION',     c:'var(--cyan)'},
    {n:d.quantum_safe?'YES':'NO', l:'PQC READY',  c:d.quantum_safe?'var(--green)':'var(--red)'},
  ].map(s=>`<div class="stat">
    <div class="stat-num" style="color:${s.c}">${s.n}</div>
    <div class="stat-lbl">${s.l}</div></div>`).join('');

    renderRiskBreakdown(d);

    // Action bar
    document.getElementById('actionBar').style.display = 'flex';
    const certBtn = document.getElementById('certBtn');
    if (certBtn) {
      if (!d.cert_eligible) {
        certBtn.style.opacity = '0.4';
        certBtn.title = 'Certificate available only for scan grades A+ or A';
      } else {
        certBtn.style.opacity = '1';
        certBtn.title = 'Download PQC Certificate PDF (A+/A)';
      }
    }

    if (d.scan_summary) {
      document.getElementById('summaryBox').style.display = 'block';
      document.getElementById('summaryText').textContent  = d.scan_summary;
    }

    const scoreBox = document.getElementById('scoreExplainBox');
    const scoreText = document.getElementById('scoreExplainText');
    if (scoreBox && scoreText) {
    const breakdown = d.score_breakdown || {};
    const validation = d.validation || {};
    const ai = d.ai_insights || {};
    const topFindings = (breakdown.finding_details || []).slice(0, 4);
    const lines = [
      `Formula: ${breakdown.score_formula || 'security_score = max(0, 100 - weighted_risk)'}`,
      `Validation confidence: ${Math.round((Number(validation.confidence) || 0) * 100)}% ${validation.low_confidence ? '(low confidence)' : '(validated)'}`,
      `Weighted risk: ${Math.round(Number(breakdown.risk_total) || 0)} | Readiness: ${Math.round(Number(breakdown.readiness_total) || 0)}`,
    ];
    if (ai.severity) lines.push(`AI severity: ${ai.severity} | Priority: ${ai.priority} | Trend: ${ai.trend?.direction || 'unknown'}`);
    if (topFindings.length) {
      lines.push('Top drivers:');
      topFindings.forEach((finding) => {
        lines.push(`- ${finding.message} (${Math.round((Number(finding.confidence) || 0) * 100)}% confidence)`);
      });
    }
      scoreText.textContent = lines.join('\n');
      scoreBox.style.display = 'block';
    }

    if (d.raw_tls) {
      document.getElementById('rawBox').style.display = 'block';
      document.getElementById('rawData').textContent  = JSON.stringify(d.raw_tls, null, 2);
    }

  // CBOM Panel
    if (d.cbom) {
      renderCBOMPanel(d.cbom);
      document.getElementById('cbomPanel').style.display = 'block';
    }

  // Certificate
    if (probe.cert_subject) {
      document.getElementById('certSection').style.display = 'block';
      document.getElementById('certTable').innerHTML = [
      ['Subject',          probe.cert_subject    ||'—'],
      ['Issuer',           probe.cert_issuer     ||'—'],
      ['Public Key Algo',  probe.cert_pubkey_alg ||'—'],
      ['Key Size',         probe.cert_pubkey_bits ? probe.cert_pubkey_bits+' bits' : '—'],
      ['Signature Algo',   probe.cert_sig_alg    ||'—'],
      ['Valid Until',      probe.cert_not_after  ||'—'],
      ['Days to Expiry',   probe.cert_days_left != null ? probe.cert_days_left+' days' : '—'],
      ['Expired',          probe.cert_expired    ?'⚠ YES':'No'],
      ['Self-Signed',      probe.cert_self_signed?'⚠ YES':'No'],
      ['SHA-256 Fingerprint', probe.cert_sha256  ||'—'],
      ].map(([k,v])=>`<tr><td style="color:var(--muted);width:220px">${k}</td><td style="color:var(--text2)">${v}</td></tr>`).join('');
    }

  // Findings
    const F = [];
    (d.critical_findings||[]).forEach(f=>F.push({sev:'CRITICAL',cls:'critical',title:f,desc:'Detected by real-time TLS backend scan.'}));
    (d.high_findings    ||[]).forEach(f=>F.push({sev:'HIGH',    cls:'high',    title:f,desc:'Detected by real-time TLS backend scan.'}));
    (d.medium_findings  ||[]).forEach(f=>F.push({sev:'MEDIUM',  cls:'medium',  title:f,desc:'Detected by real-time TLS backend scan.'}));
    (d.low_findings     ||[]).forEach(f=>F.push({sev:'LOW',     cls:'low',     title:f,desc:'Informational finding from TLS scan.'}));
    (d.info_findings    ||[]).forEach(f=>F.push({sev:'INFO',    cls:'info',    title:f,desc:'Informational finding.'}));
    if (!F.length) F.push({sev:'INFO',cls:'info',title:'Scan complete — no critical issues detected',desc:'No critical PQC vulnerabilities found.'});

    document.getElementById('findingsGrid').innerHTML = F.map((f,i)=>`
    <div class="fcard ${f.cls}" style="animation-delay:${i*.07}s">
      <div class="fcard-sev sev-${f.sev}">● ${f.sev}</div>
      <div class="fcard-title">${f.title}</div>
      <div class="fcard-desc">${f.desc}</div>
      <span class="fcard-algo">Live TLS Scan</span>
      <div class="fcard-source"> Real backend finding</div>
    </div>`).join('');

  // Cipher table
    const nb = s => s==='approved'?'<span class="nb nb-ok">✓ FIPS</span>':s==='pending'?'<span class="nb nb-draft">◎ DRAFT</span>':s==='deprecated'?'<span class="nb nb-dep">✕ DEPRECATED</span>':'<span class="nb nb-none">—</span>';
    const dc = a => a.nist==='deprecated'?'dot-vuln':!a.qs?'dot-warn':'dot-safe';
    const st = a => a.nist==='deprecated'?'<span class="bad">VULNERABLE</span>':a.qs?'<span class="ok">QUANTUM SAFE</span>':'<span class="warn">CLASSICAL</span>';

    const liveRows = (d.detected_ciphers||[]).map(c=>{
    const dcl = c.deprecated?'dot-vuln':c.quantum_safe?'dot-safe':'dot-warn';
    const stl = c.deprecated?'<span class="bad">VULNERABLE</span>':c.quantum_safe?'<span class="ok">QUANTUM SAFE</span>':'<span class="warn">CLASSICAL</span>';
    return `<tr style="background:rgba(8,189,186,0.04)">
      <td><span class="dot ${dcl}"></span>${c.name} <span style="font-size:10px;color:var(--teal)">[LIVE]</span></td>
      <td style="color:var(--muted)">${c.type||'—'}</td>
      <td><span class="nb nb-ok">✓ ACTIVE</span></td>
      <td style="color:${(c.security_level||0)>=3?'var(--green)':'var(--yellow)'}">Level ${c.security_level||'—'}</td>
      <td>${stl}</td></tr>`;
  });
  const chipRows = ALGOS.filter(a=>SEL.has(a.id)).map(a=>`<tr>
    <td><span class="dot ${dc(a)}"></span>${a.label}</td>
    <td style="color:var(--muted)">${a.type}</td>
    <td>${nb(a.nist)}</td>
    <td style="color:${a.lvl>=3?'var(--green)':a.lvl>=1?'var(--yellow)':'var(--red)'}">Level ${a.lvl||'—'}</td>
    <td>${st(a)}</td></tr>`);
    document.getElementById('cipherTable').innerHTML = liveRows.join('')+chipRows.join('');

  // KEM table
    const liveKems = (d.detected_kems||[]).map(k=>`<tr style="background:rgba(8,189,186,0.04)">
    <td>${k.name} <span style="font-size:10px;color:var(--teal)">[LIVE]</span></td>
    <td style="color:var(--muted)">${k.standard||'—'}</td>
    <td>${k.key_size||'—'}</td>
    <td>${k.quantum_safe?'<span class="ok">✓ YES</span>':'<span class="bad">✕ NO</span>'}</td>
    <td style="color:${k.quantum_safe?'var(--text2)':'var(--red)'}">${k.recommendation||'—'}</td></tr>`);
  const chipKems = ALGOS.filter(a=>SEL.has(a.id)&&(a.type==='KEM'||a.type==='Hybrid KEM')).map(a=>`<tr>
    <td>${a.label}</td><td style="color:var(--muted)">${a.std}</td><td>${a.ks}</td>
    <td>${a.qs?'<span class="ok">✓ YES</span>':'<span class="bad">✕ NO</span>'}</td>
    <td style="color:${a.qs?'var(--text2)':'var(--red)'}">${a.rec}</td></tr>`);
    document.getElementById('kemTable').innerHTML = (liveKems.length||chipKems.length)
    ? liveKems.join('')+chipKems.join('')
    : `<tr><td colspan="5" style="color:var(--muted);text-align:center;padding:24px">No KEM algorithms detected</td></tr>`;

  // Remediation
    const cbomData = d.cbom || {};
    const remediation = cbomData.remediationPlan || [];
    if (remediation.length > 0) {
      document.getElementById('remediationPanel').style.display = 'block';
      document.getElementById('remediationGrid').innerHTML = remediation.map((r, i) => `
      <div class="fcard ${r.priority==='CRITICAL'?'critical':r.priority==='HIGH'?'high':'low'}" style="animation-delay:${i*.07}s">
        <div class="fcard-sev sev-${r.priority}">● ${r.priority}</div>
        <div class="fcard-title">${r.action}</div>
        <div class="fcard-desc">${r.description}</div>
        <span class="fcard-algo">Target: ${r.target}</span>
        <div class="fcard-source">AegisGuard Remediation Engine</div>
      </div>`).join('');
    }

  // v1.0.0 Advanced Intelligence
    try {
      renderAdvancedIntel(d);
    } catch (e) {
      console.error('[AegisGuard] renderAdvancedIntel failed:', e);
    }

    const resultsEl = document.getElementById('results');
    if (resultsEl) {
      resultsEl.style.display = 'block';
      resultsEl.scrollIntoView({behavior:'smooth'});
    }
  } catch (err) {
    console.error('[AegisGuard] render failed:', err);
    const resultsEl = document.getElementById('results');
    if (resultsEl) {
      resultsEl.style.display = 'block';
      resultsEl.innerHTML = `
        <div style="padding:16px;border:1px solid var(--red);background:#2a1212;color:var(--red);font-family:'IBM Plex Mono',monospace">
          Dashboard render failed: ${err.message}
        </div>` + resultsEl.innerHTML;
    }
  }
}

// ─────────────────────────────────────────────
// CBOM PANEL
// ─────────────────────────────────────────────
function renderCBOMPanel(cbom) {
  console.log('[AegisGuard] CBOM payload:', cbom);

  // Support both legacy keys and v2 keys emitted by backend cbom_generator.
  const target = cbom.asset || cbom.target || {};
  const tlsProfile = cbom.tlsProfile || {};
  const cert = cbom.certificate || cbom.cryptographicInventory?.certificate || {};
  const pqcR = cbom.pqcAssessment || cbom.pqcReadiness || {};
  const risk = cbom.riskScore || cbom.riskAssessment || {};
  const riskBreakdown = risk.details || risk.scoreBreakdown || {};
  const toolName = cbom.metadata?.tools?.[0]?.name || cbom.metadata?.tool?.name || '—';
  const metadataTs = cbom.metadata?.timestamp || cbom.timestamp || '—';
  const hstsValue = target.hsts;

  const cards = [
    {
      title: '📦 CBOM METADATA',
      rows: [
        ['Format', cbom.bomFormat || '—'],
        ['Spec Version', cbom.specVersion || '—'],
        ['Timestamp', String(metadataTs).replace('T',' ').replace('Z','')],
        ['Tool', toolName],
        ['Standard', cbom.metadata?.standard || '—'],
      ]
    },
    {
      title: '🌐 ASSET DETAILS',
      rows: [
        ['Host', target.host || '—'],
        ['Port', target.port ?? '—'],
        ['IP', target.ip || '—'],
        ['Asset Type', target.type || target.assetType || '—'],
        ['HSTS', hstsValue == null ? '—' : (hstsValue ? '✓ Enabled' : '✕ Not Set')],
      ]
    },
    {
      title: '🔐 CRYPTOGRAPHIC INVENTORY',
      rows: [
        ['TLS Version', tlsProfile.version || '—'],
        ['PQC Ready', pqcR.pqcSafe ? '✓ Yes' : '✕ No'],
        ['Cipher Suite', tlsProfile.cipherSuite || '—'],
        ['Key Exchange', tlsProfile.keyExchange || '—'],
        ['Quantum Safe', pqcR.pqcSafe ? '✓ Yes' : '✕ No'],
      ]
    },
    {
      title: '🏆 PQC READINESS',
      rows: [
        ['Label', pqcR.status || pqcR.label || '—'],
        ['Status', pqcR.pqcSafe ? 'Quantum Safe' : 'Quantum Vulnerable'],
        ['NIST Compliant', (pqcR.nistStandards || []).length > 0 ? '✓ Yes' : '✕ No'],
        ['Cert Eligible', pqcR.certificationEligible ? '✓ Yes' : '✕ No'],
        ['NIST Standards', (pqcR.nistStandards || []).join(', ') || 'None'],
      ]
    },
    {
      title: '⚖️ RISK ASSESSMENT',
      rows: [
        ['Score', `${risk.score ?? 0}/100`],
        ['Grade', risk.grade || '—'],
        ['TLS Penalty', riskBreakdown.tls_penalty || 0],
        ['Cipher Penalty', riskBreakdown.cipher_penalty || 0],
        ['PQC Penalty', riskBreakdown.pqc_penalty || 0],
      ]
    },
    {
      title: '📜 CERTIFICATE',
      rows: [
        ['Subject', cert.subject || '—'],
        ['Issuer', cert.issuer || '—'],
        ['Sig Algorithm', cert.signatureAlgorithm || '—'],
        ['Key Algorithm', cert.publicKeyAlgorithm || '—'],
        ['Days to Expiry', cert.daysToExpiry != null ? cert.daysToExpiry + ' days' : '—'],
      ]
    },
  ];

  document.getElementById('cbomGrid').innerHTML = cards.map(card => `
    <div class="cbom-card">
      <div class="cbom-card-title">${card.title}</div>
      ${card.rows.map(([k,v]) => `
        <div class="cbom-row">
          <span class="cbom-key">${k}</span>
          <span class="cbom-val" style="color:${String(v).includes('✓')?'var(--green)':String(v).includes('✕')?'var(--red)':'var(--text2)'}">${v}</span>
        </div>`).join('')}
    </div>`).join('');
}

// ─────────────────────────────────────────────
// BULK SCAN
// ─────────────────────────────────────────────
async function startBulkScan() {
  const raw = document.getElementById('bulkTargets').value.trim();
  if (!raw) { alert('Enter at least one target domain.'); return; }
  const targets = raw.split('\n').map(t=>t.trim()).filter(Boolean).slice(0, 20);
  const port    = parseInt(document.getElementById('bulkPort').value) || 443;

  document.getElementById('bulkLoader').style.display = 'flex';
  document.getElementById('bulkResults').innerHTML = '';

  try {
    const resp = await fetch(`${BACKEND_URL}/scan/bulk`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json', ...getAuthHeaders()},
      body: JSON.stringify({ targets, port, mode: 'full' }),
      signal: AbortSignal.timeout(120000)
    });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ detail: resp.statusText }));
      throw new Error(err.detail || `HTTP ${resp.status}`);
    }
    const data = await resp.json();
    console.log('[AegisGuard] /scan/bulk response:', data);
    document.getElementById('bulkLoader').style.display = 'none';
    renderBulkResults(data);
  } catch (e) {
    document.getElementById('bulkLoader').style.display = 'none';
    document.getElementById('bulkResults').innerHTML = `<div style="padding:32px;color:var(--red);font-family:'IBM Plex Mono',monospace">Error: ${e.message}</div>`;
  }
}

function renderBulkResults(data) {
  const el = document.getElementById('bulkResults');
  const results = Array.isArray(data?.results) ? data.results : [];
  const normalized = results.map(r => {
    const result = r?.result || r;
    return {
      target: r?.target || result?.raw_tls?.host || 'unknown',
      error: r?.error,
      result,
    };
  });

  const total = Number.isFinite(data?.total) ? data.total : (Number.isFinite(data?.count) ? data.count : normalized.length);
  const pqcSafe = Number.isFinite(data?.pqc_safe)
    ? data.pqc_safe
    : normalized.filter(r => !r.error && !!r.result?.quantum_safe).length;
  const pqcVulnerable = Number.isFinite(data?.pqc_vulnerable)
    ? data.pqc_vulnerable
    : Math.max(0, total - pqcSafe);
  const pqcCoverage = total > 0 ? Math.round((pqcSafe / total) * 100) : 0;

  el.innerHTML = `
    <div class="bulk-results-wrap">
      <div class="bulk-summary">
        <div class="bulk-stat"><div class="bulk-stat-num">${total}</div><div class="bulk-stat-lbl">TOTAL SCANNED</div></div>
        <div class="bulk-stat"><div class="bulk-stat-num" style="color:var(--green)">${pqcSafe}</div><div class="bulk-stat-lbl">PQC SAFE</div></div>
        <div class="bulk-stat"><div class="bulk-stat-num" style="color:var(--red)">${pqcVulnerable}</div><div class="bulk-stat-lbl">PQC VULNERABLE</div></div>
        <div class="bulk-stat"><div class="bulk-stat-num" style="color:var(--teal)">${pqcCoverage}%</div><div class="bulk-stat-lbl">PQC COVERAGE</div></div>
      </div>
      <div class="section-head">SCAN RESULTS</div>
      ${normalized.map(r => {
        if (r.error) return `<div class="bulk-row"><span class="bulk-target">${r.target}</span><span style="color:var(--red);font-size:12px;font-family:'IBM Plex Mono',monospace">ERROR: ${r.error}</span></div>`;
        const res = r.result || {};
        const grade = res.grade || 'F';
        const isQS = res.quantum_safe;
        const score = res.score || 0;
        const lbl = res.pqc_label || (isQS ? 'Quantum Safe' : 'Not Quantum Safe');
        return `<div class="bulk-row">
          <span class="bulk-target">${r.target}</span>
          <span class="bulk-score">${score}/100</span>
          <span class="bulk-pqc-badge ${isQS?'bulk-pqc-safe':'bulk-pqc-vuln'}">${lbl}</span>
          <div class="bulk-grade grade-${grade.replace('+','')}">
            <span>${grade}</span>
          </div>
        </div>`;
      }).join('')}
    </div>`;
}

// ─────────────────────────────────────────────
// CBOM EXPORT TAB
// ─────────────────────────────────────────────
async function exportCBOM() {
  const target = document.getElementById('cbomTarget').value.trim() || 'example.com';
  const port   = parseInt(document.getElementById('cbomPort').value) || 443;

  try {
    const resp = await fetch(`${BACKEND_URL}/cbom`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ target, port }),
      signal: AbortSignal.timeout(120000)
    });
    const data = await resp.json();
    lastCBOM = data;
    document.getElementById('cbomExportBox').style.display = 'block';
    document.getElementById('cbomExportData').textContent = JSON.stringify(data, null, 2);
    document.getElementById('cbomExportBox').scrollIntoView({behavior:'smooth'});
  } catch (e) {
    alert(`CBOM export failed: ${e.message}`);
  }
}

function saveCBOM() {
  const data = lastCBOM || (scanResults && scanResults.data && scanResults.data.cbom);
  if (!data) { alert('No CBOM data. Run a scan first.'); return; }
  const target = data.asset?.host || data.target?.host || data.target || 'unknown';
  const a = document.createElement('a');
  a.href = 'data:application/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(data, null, 2));
  a.download = `cbom_${target}_${Date.now()}.json`;
  a.click();
}

// ─────────────────────────────────────────────
// CERTIFICATE TAB
// ─────────────────────────────────────────────
async function generateCert() {
  const target = document.getElementById('certTarget').value.trim() || 'cloudflare.com';
  const port   = parseInt(document.getElementById('certPort').value) || 443;
  const box    = document.getElementById('certStatusBox');
  const content = document.getElementById('certStatusContent');

  box.style.display = 'block';
  content.innerHTML = `<div style="padding:20px;color:var(--teal);font-family:'IBM Plex Mono',monospace">⟳ Scanning ${target} for PQC compliance...</div>`;
  box.scrollIntoView({behavior:'smooth'});

  try {
    const resp = await fetch(`${BACKEND_URL}/certificate`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ target, port }),
      signal: AbortSignal.timeout(120000)
    });

    if (resp.ok && resp.headers.get('content-type')?.includes('pdf')) {
      const blob = await resp.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href     = url;
      a.download = `pqc_certificate_${target}.pdf`;
      a.click();
      content.innerHTML = `
        <div class="cert-status-safe">
          <div class="cert-status-title" style="color:var(--green)">🏆 Certificate Issued Successfully!</div>
          <div class="cert-status-sub">PQC Compliance Certificate has been generated for <strong>${target}</strong></div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:10px">
            <span class="ibm-badge pqc">✓ NIST FIPS 203 (ML-KEM)</span>
            <span class="ibm-badge nist">✓ NIST FIPS 204 (ML-DSA)</span>
            <span class="ibm-badge live-badge">✓ Fully Quantum Safe</span>
          </div>
        </div>`;
    } else {
      const err = await resp.json().catch(() => ({detail: 'Not quantum safe or server error'}));
      content.innerHTML = `
        <div class="cert-status-vuln">
          <div class="cert-status-title" style="color:var(--red)">✕ Certificate Cannot Be Issued</div>
          <div class="cert-status-sub">${err.detail || 'Certificate requires scan grade A+ or A.'}</div>
          <div style="margin-top:12px;font-family:'IBM Plex Mono',monospace;font-size:12px;color:var(--muted)">
            Certificate policy: issued only when scan findings produce<br>
            grade A+ or A. Resolve high/critical findings, then re-scan.
          </div>
          <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">
            <span class="ibm-badge" style="color:var(--red);border-color:var(--red)">✕ Grade below A</span>
            <span class="ibm-badge cbom-badge">→ Re-run scan after remediation</span>
          </div>
        </div>`;
    }
  } catch (e) {
    content.innerHTML = `<div style="padding:20px;color:var(--red);font-family:'IBM Plex Mono',monospace">Error: ${e.message}</div>`;
  }
}

async function autoDownloadCertificate(target, port, grade) {
  const resp = await fetch(`${BACKEND_URL}/certificate`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ target, port: parseInt(port, 10) }),
    signal: AbortSignal.timeout(120000)
  });

  if (!resp.ok) {
    const err = await resp.json().catch(() => ({ detail: resp.statusText }));
    throw new Error(err.detail || `HTTP ${resp.status}`);
  }

  if (!resp.headers.get('content-type')?.includes('pdf')) {
    throw new Error('Certificate endpoint did not return a PDF file.');
  }

  const blob = await resp.blob();
  const a = document.createElement('a');
  const objectUrl = URL.createObjectURL(blob);
  a.href = objectUrl;
  a.download = `pqc_certificate_${target}_${grade}_${Date.now()}.pdf`;
  a.click();
  URL.revokeObjectURL(objectUrl);
}

// ─────────────────────────────────────────────
// EXPORT
// ─────────────────────────────────────────────
async function downloadReport() {
  if (!scanResults) { alert('Run a scan first.'); return; }
  const {target, port} = scanResults;

  try {
    const response = await fetch(`${BACKEND_URL}/export`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
      body: JSON.stringify({ target, port: parseInt(port, 10) }),
      signal: AbortSignal.timeout(120000)
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({ detail: response.statusText }));
      throw new Error(err.detail || `HTTP ${response.status}`);
    }

    const blob = await response.blob();

    // Trigger file download from API blob response.
    const a = document.createElement('a');
    const objectUrl = URL.createObjectURL(blob);
    a.href = objectUrl;
    a.download = `aegisguard_scan_${target}_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(objectUrl);
  } catch (e) {
    alert(`Export failed: ${e.message}`);
  }
}

function downloadCBOM() {
  const data = lastCBOM || (scanResults && scanResults.data && scanResults.data.cbom);
  if (!data) { alert('Run a scan first to generate CBOM data.'); return; }
  saveCBOM();
}

async function downloadCert() {
  if (!scanResults) { alert('Run a scan first.'); return; }
  document.getElementById('certTarget').value = scanResults.target;
  document.getElementById('certPort').value = scanResults.port;
  // Switch to cert tab
  document.querySelectorAll('.tab-content').forEach(t => t.style.display = 'none');
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById('tab-cert').style.display = 'block';
  document.querySelectorAll('.tab')[3].classList.add('active');
  document.getElementById('tab-cert').scrollIntoView({behavior:'smooth'});
  await generateCert();
}

// ─────────────────────────────────────────────
// ASSET DISCOVERY TAB
// ─────────────────────────────────────────────
let discoveryData = null;
let currentDiscTab = 'domains';
let currentDiscFilter = 'all';

async function startDiscovery() {
  const domain = document.getElementById('discoveryDomain').value.trim();
  if (!domain) { alert('Enter a root domain to discover subdomains.'); return; }

  // Clear any previous discovery state
  discoveryData = null;
  document.getElementById('discoveryResults').style.display = 'none';
  document.getElementById('discoveryLoader').style.display = 'flex';
  document.getElementById('discoveryBtn').disabled = true;
  document.getElementById('discoveryLoaderStatus').textContent =
    `DISCOVERING SUBDOMAINS FOR ${domain.toUpperCase()} & SCANNING TLS...`;

  try {
    // STEP 1: POST /discover to start async job
    console.log('[Discovery] Starting job for domain:', domain);
    
    const controller1 = new AbortController();
    const timer1 = setTimeout(() => controller1.abort(), 120000); // 120-second timeout for job creation
    
    let resp;
    try {
      resp = await fetch(`${BACKEND_URL}/discover`, {
        method: 'POST',
        headers: Object.assign({'Content-Type': 'application/json'}, getAuthHeaders()),
        body: JSON.stringify({ domain, scan_subdomains: true }),
        signal: controller1.signal
      });
      clearTimeout(timer1);
    } catch (fetchError) {
      clearTimeout(timer1);
      throw new Error(`Job creation failed: ${fetchError.message}`);
    }
    
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({detail: resp.statusText}));
      throw new Error(err.detail || `HTTP ${resp.status}`);
    }
    
    const payload = await resp.json();
    console.log('[Discovery] Job created:', payload.job_id);

    // Backward-compatible: some deployments return final payload directly
    if (payload && payload.summary && Array.isArray(payload.domains)) {
      console.log('[Discovery] Got direct response (not async job)');
      discoveryData = payload;
      renderDiscovery(discoveryData);
      return;
    }

    // Async job path: poll for completion
    if (!payload?.job_id) {
      throw new Error('Server did not return job ID');
    }

    const jobId = payload.job_id;
    await pollDiscoveryJob(jobId);
    
  } catch(e) {
    console.warn('[Discovery] Error:', e.message);
    
    // Show warning in UI instead of alert
    const loaderStatus = document.getElementById('discoveryLoaderStatus');
    if (loaderStatus) {
      loaderStatus.textContent = `⚠️ WARNING: ${e.message}`;
      loaderStatus.style.color = 'var(--orange)';
      loaderStatus.style.fontSize = '13px';
    } else {
      alert(`Discovery notice: ${e.message}`);
    }
  } finally {
    document.getElementById('discoveryLoader').style.display = 'none';
    document.getElementById('discoveryBtn').disabled = false;
  }
}

let discoveryPollSessionId = 0;
let discoveryPollAbortController = null;

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function jitterDelay(baseMs, spread = 0.2) {
  const delta = baseMs * spread * (Math.random() * 2 - 1);
  return Math.max(250, Math.round(baseMs + delta));
}

/**
 * Poll discovery job until completion or timeout.
 */
async function pollDiscoveryJob(jobId) {
  const pollSessionId = ++discoveryPollSessionId;
  if (discoveryPollAbortController) {
    discoveryPollAbortController.abort();
  }
  discoveryPollAbortController = new AbortController();

  const pollStart = Date.now();
  const maxPollMs = 300000;
  const statusTimeoutMs = 10000;
  const resultTimeoutMs = 5000;
  const basePollDelayMs = document.visibilityState === 'visible' ? 2000 : 5000;
  const maxPollDelayMs = document.visibilityState === 'visible' ? 5000 : 15000;
  const maxRetries = 15;

  let lastStage = 'queued';
  let consecutiveNetworkErrors = 0;
  let serverErrorCount = 0;
  let pollAttempt = 0;

  console.log(`[Discovery] Polling job ${jobId} with short status timeouts`);

  try {
    while (Date.now() - pollStart < maxPollMs && pollSessionId === discoveryPollSessionId) {
      try {
        const statusData = await fetchWithTimeout(
          `${BACKEND_URL}/status/${jobId}`,
          { method: 'GET', headers: Object.assign({ 'Content-Type': 'application/json' }, getAuthHeaders()) },
          statusTimeoutMs,
          discoveryPollAbortController.signal
        );

        consecutiveNetworkErrors = 0;
        pollAttempt = 0;

        const status = statusData?.status || 'running';
        const stage = statusData?.progress?.stage || status;
        const counts = statusData?.progress?.counts || {};

        if (stage !== lastStage) {
          const loaderStatus = document.getElementById('discoveryLoaderStatus');
          if (loaderStatus) {
            const discovered = Number(counts.discovered || 0);
            const reachable = Number(counts.reachable || 0);
            loaderStatus.textContent = `DISCOVERY STAGE: ${String(stage).toUpperCase()} | ${discovered} discovered | ${reachable} reachable`;
          }
          lastStage = stage;
          console.log(`[Discovery] Stage: ${stage}`);
        }

        if (['completed', 'done', 'completed_partial', 'partial_success'].includes(status)) {
          console.log(`[Discovery] Job ${status}, fetching final result...`);

          const resultData = await fetchWithTimeout(
            `${BACKEND_URL}/discover/result/${jobId}`,
            { method: 'GET', headers: Object.assign({ 'Content-Type': 'application/json' }, getAuthHeaders()) },
            resultTimeoutMs,
            discoveryPollAbortController.signal
          );

          const finalPayload = resultData?.result || resultData;
          if (!finalPayload) {
            throw new Error('Server returned empty result');
          }

          if (!finalPayload.summary && !finalPayload.domains && !finalPayload.discovered_subdomains) {
            throw new Error('Server result has no discovery data');
          }

          if (!finalPayload.summary) {
            const rawScans = Array.isArray(finalPayload.raw_scans) ? finalPayload.raw_scans : [];
            const reachableRows = rawScans.filter(r => r && r.reachable);
            const pqcSafeRows = rawScans.filter(r => r && r.pqc_safe);
            finalPayload.summary = {
              total_discovered: (finalPayload.domains || []).length,
              total_reachable: reachableRows.length,
              total_pqc_safe: pqcSafeRows.length,
              total_pqc_vulnerable: Math.max(0, reachableRows.length - pqcSafeRows.length),
            };
          }

          if (status === 'completed_partial') {
            finalPayload.is_partial = true;
            finalPayload.partial_reason = resultData?.warning || statusData?.error || 'Some discovery sources timed out';
          }

          discoveryData = finalPayload;
          console.log(`[Discovery] ✓ Complete: ${finalPayload.summary?.total_discovered || 0} discovered${status === 'completed_partial' ? ' (PARTIAL)' : ''}`);
          renderDiscovery(discoveryData);
          return;
        }

        if (status === 'failed' || status === 'error') {
          throw new Error(statusData?.error || 'Discovery job failed');
        }

        if (status === 'timed_out' || status === 'timedout' || status === 'timeout') {
          console.warn(`[Discovery] Job timed out on backend (${jobId}).`);
          let finalPayload = statusData?.result || null;
          if (!finalPayload) {
            try {
              const resultData = await fetchWithTimeout(
                `${BACKEND_URL}/discover/result/${jobId}`,
                { method: 'GET', headers: Object.assign({ 'Content-Type': 'application/json' }, getAuthHeaders()) },
                resultTimeoutMs,
                discoveryPollAbortController.signal
              );
              finalPayload = resultData?.result || resultData || null;
            } catch (resultErr) {
              console.warn('[Discovery] Could not fetch timed-out partial result:', resultErr.message);
            }
          }
          if (finalPayload) {
            finalPayload.is_partial = true;
            finalPayload.partial_reason = statusData?.error || 'Backend discovery timed out';
            discoveryData = finalPayload;
            renderDiscovery(discoveryData);
            return;
          }
          const loaderStatus = document.getElementById('discoveryLoaderStatus');
          if (loaderStatus) {
            loaderStatus.textContent = '⚠️ Backend discovery timed out. Try again later.';
            loaderStatus.style.color = 'var(--orange)';
          }
          return;
        }

        if (status === 'cancelled') {
          const loaderStatus = document.getElementById('discoveryLoaderStatus');
          if (loaderStatus) {
            loaderStatus.textContent = 'Discovery cancelled.';
            loaderStatus.style.color = 'var(--muted)';
          }
          return;
        }

        pollAttempt++;
        const backoff = jitterDelay(Math.min(maxPollDelayMs, basePollDelayMs * Math.pow(2, Math.max(0, pollAttempt - 1))));
        console.log(`[Discovery] Status: ${status}, waiting ${backoff}ms before next poll`);
        await sleep(backoff);
      } catch (pollError) {
        const elapsedSec = Math.floor((Date.now() - pollStart) / 1000);
        const errorText = String(pollError?.message || pollError || 'Unknown polling error');
        const isNetworkError = errorText.includes('timed out') || errorText.includes('Failed to fetch') || errorText.includes('NetworkError') || errorText.includes('Request aborted');

        // If we can extract an HTTP status code, handle 4xx/5xx differently
        const httpMatch = errorText.match(/HTTP\s+(\d{3})/);
        const httpCode = httpMatch ? parseInt(httpMatch[1], 10) : null;
        if (httpCode && httpCode >= 400 && httpCode < 500) {
          console.error('[Discovery] Client error while polling. Stopping.');
          if (httpCode === 401 || httpCode === 403) showAuthError('Session expired or unauthorized. Please login.');
          const loaderStatus = document.getElementById('discoveryLoaderStatus');
          if (loaderStatus) {
            loaderStatus.textContent = `Error ${httpCode}: ${errorText}`;
            loaderStatus.style.color = 'var(--red)';
          }
          return;
        }
        if (httpCode && httpCode >= 500) {
          serverErrorCount++;
          console.warn(`[Discovery] Server error HTTP ${httpCode} (attempt ${serverErrorCount}/3)`);
          if (serverErrorCount > 3) {
            throw pollError;
          }
          // allow transient server errors to be retried
        }

        if (errorText.includes('Backend discovery timed out')) {
          console.warn('[Discovery] Backend timed out — stopping polling.');
          if (discoveryData) {
            discoveryData.is_partial = true;
            discoveryData.partial_reason = errorText;
            renderDiscovery(discoveryData);
            return;
          }
          const loaderStatus = document.getElementById('discoveryLoaderStatus');
          if (loaderStatus) {
            loaderStatus.textContent = `⚠️ ${errorText}`;
            loaderStatus.style.color = 'var(--orange)';
          }
          return;
        }

        if (errorText.includes('no discovery data') && discoveryData) {
          discoveryData.is_partial = true;
          discoveryData.partial_reason = 'Backend returned partial results due to timeout';
          renderDiscovery(discoveryData);
          return;
        }

        if (isNetworkError) {
          consecutiveNetworkErrors++;
          const backoffMs = jitterDelay(Math.min(20000, 2000 * Math.pow(2, consecutiveNetworkErrors - 1)));
          console.warn(`[Discovery] Network error (attempt ${consecutiveNetworkErrors}/${maxRetries}) after ${elapsedSec}s:`, errorText);

          // Hard ceiling: if polling already took too long, show an informative message
          if (elapsedSec > 120) {
            const loaderStatus = document.getElementById('discoveryLoaderStatus');
            if (loaderStatus) {
              loaderStatus.textContent = 'Taking longer than expected — check server logs for details.';
              loaderStatus.style.color = 'var(--orange)';
            }
            if (discoveryData) {
              discoveryData.is_partial = true;
              discoveryData.partial_reason = `Polling paused after ${elapsedSec}s due to network issues`;
              renderDiscovery(discoveryData);
              return;
            }
            throw new Error(`Network error: ${errorText}`);
          }

          if (consecutiveNetworkErrors >= maxRetries) {
            console.error(`[Discovery] ✗ Max retries (${maxRetries}) exceeded. Giving up.`);
            if (discoveryData) {
              discoveryData.is_partial = true;
              discoveryData.partial_reason = `Network failed after ${elapsedSec}s and ${maxRetries} retries`;
              renderDiscovery(discoveryData);
              return;
            }
            throw new Error(`Network error: ${errorText}`);
          }

          console.log(`[Discovery] Retrying in ${backoffMs}ms...`);
          await sleep(backoffMs);
          continue;
        }

        console.error('[Discovery] ✗ Fatal error:', errorText);
        throw pollError;
      }
    }
  } finally {
    if (pollSessionId === discoveryPollSessionId) {
      discoveryPollAbortController = null;
    }
  }

  const totalSec = Math.floor((Date.now() - pollStart) / 1000);
  console.error(`[Discovery] ✗ Polling timeout (${totalSec}s exceeded max of ${maxPollMs / 1000}s)`);

  if (discoveryData) {
    discoveryData.is_partial = true;
    discoveryData.partial_reason = `Polling stopped after ${totalSec}s (max: ${maxPollMs / 1000}s)`;
    renderDiscovery(discoveryData);
    return;
  }

  throw new Error(`Discovery polling exceeded ${maxPollMs / 1000}s limit. Try again.`);
}

/**
 * Fetch with explicit timeout management - avoids AbortSignal.timeout() race conditions
 * CRITICAL: Clears timeout immediately when fetch completes
 */
async function fetchWithTimeout(url, options, timeoutMs, externalSignal) {
  const controller = new AbortController();
  const timer = setTimeout(() => {
    console.warn(`[Fetch] Timeout after ${timeoutMs}ms for ${url}`);
    controller.abort();
  }, timeoutMs);

  const abortExternal = () => controller.abort();
  if (externalSignal) {
    if (externalSignal.aborted) {
      controller.abort();
    } else {
      externalSignal.addEventListener('abort', abortExternal, { once: true });
    }
  }

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal
    });
    
    // CRITICAL: Clear timeout immediately on success
    clearTimeout(timer);
    
    if (!response.ok) {
      const errData = await response.json().catch(() => ({detail: response.statusText}));
      const detail = errData.detail || response.statusText || '';
      throw new Error(`HTTP ${response.status}: ${detail}`);
    }
    
    return await response.json();
    
  } catch (error) {
    // CRITICAL: Clear timeout even on error
    clearTimeout(timer);
    if (externalSignal) {
      externalSignal.removeEventListener('abort', abortExternal);
    }
    
    if (error.name === 'AbortError') {
      throw new Error(`Request timed out after ${timeoutMs}ms`);
    }
    throw error;
  } finally {
    if (externalSignal) {
      externalSignal.removeEventListener('abort', abortExternal);
    }
  }
}

function renderDiscovery(data) {
  const s = data.summary || {};
  
  // Show warning if partial result
  const warningEl = document.createElement('div');
  if (data.is_partial) {
    warningEl.style.cssText = 'background:var(--orange);color:#000;padding:12px 16px;border-radius:4px;margin-bottom:16px;font-size:13px;font-weight:600';
    warningEl.innerHTML = `⚠️ <strong>Partial Results:</strong> ${data.partial_reason}. Some subdomains or sources may not have been fully scanned.`;
  }
  
  document.getElementById('discoveryStats').innerHTML = [
    {n: s.total_discovered || 0, l: 'DISCOVERED', c: 'var(--teal)'},
    {n: s.total_reachable || 0, l: 'REACHABLE', c: 'var(--green)'},
    {n: s.total_pqc_safe || 0, l: 'PQC SAFE', c: 'var(--green)'},
    {n: s.total_pqc_vulnerable || 0, l: 'PQC VULNERABLE', c: 'var(--red)'},
    {n: (data.scan_time_ms || 0) + 'ms', l: 'SCAN TIME', c: 'var(--cyan)'},
  ].map(s => `<div class="stat"><div class="stat-num" style="color:${s.c}">${s.n}</div><div class="stat-lbl">${s.l}</div></div>`).join('');

  // Insert warning if present
  const statsEl = document.getElementById('discoveryStats');
  if (data.is_partial && statsEl.parentElement) {
    const existingWarning = statsEl.parentElement.querySelector('[style*="var(--orange)"]');
    if (existingWarning) existingWarning.remove();
    statsEl.parentElement.insertBefore(warningEl, statsEl);
  }

  // Update tab counts
  document.getElementById('discDomainCount').textContent = (data.domains || []).length;
  document.getElementById('discSSLCount').textContent = (data.ssl || []).length;
  document.getElementById('discIPCount').textContent = (data.ip_addresses || []).length;
  document.getElementById('discSWCount').textContent = (data.software || []).length;

  // Render scan detail cards
  const scans = data.raw_scans || [];
  if (scans.length > 0) {
    document.getElementById('discScanDetails').style.display = 'block';
    document.getElementById('discScanGrid').innerHTML = scans
      .filter(s => s.reachable)
      .map((s, i) => `
        <div class="disc-scan-card" style="animation-delay:${i*.05}s">
          <div class="disc-scan-host">${s.hostname}</div>
          <div class="disc-scan-row"><span>IP</span><span class="disc-scan-val">${s.ip || '—'}</span></div>
          <div class="disc-scan-row"><span>TLS</span><span class="disc-scan-val">${s.tls_version || '—'}</span></div>
          <div class="disc-scan-row"><span>Grade</span><span class="disc-scan-val" style="color:${s.risk_grade==='A'||s.risk_grade==='A+'?'var(--green)':'var(--orange)'}">${s.risk_grade || '—'}</span></div>
          <div class="disc-scan-row"><span>Score</span><span class="disc-scan-val">${s.risk_score || '—'}/100</span></div>
          <div class="disc-scan-row"><span>Confidence</span><span class="disc-scan-val" style="color:${(Number(s.validation_confidence)||0) < 0.7 ? 'var(--orange)' : 'var(--green)'}">${Math.round((Number(s.validation_confidence)||0) * 100)}%</span></div>
          <div class="disc-scan-row"><span>PQC</span><span class="disc-scan-val" style="color:${s.pqc_safe?'var(--green)':'var(--red)'}">${s.pqc_safe ? '✓ Safe' : '✕ Vulnerable'}</span></div>
          <div class="disc-scan-row"><span>Cert</span><span class="disc-scan-val">${s.cert_subject || '—'}</span></div>
          <div class="disc-scan-row"><span>Cipher</span><span class="disc-scan-val" style="font-size:10px">${(s.cipher_suite||'—').substring(0,35)}</span></div>
        </div>`).join('');
  }

  currentDiscTab = 'domains';
  currentDiscFilter = 'all';
  renderDiscTable();
  document.getElementById('discoveryResults').style.display = 'block';
  document.getElementById('discoveryResults').scrollIntoView({behavior:'smooth'});
}

function switchDiscTab(tab, btn) {
  currentDiscTab = tab;
  document.querySelectorAll('.disc-tab').forEach(t => t.classList.remove('active'));
  btn.classList.add('active');
  currentDiscFilter = 'all';
  document.querySelectorAll('.disc-filter').forEach(f => f.classList.remove('active'));
  document.querySelectorAll('.disc-filter').forEach(f => { if(f.textContent.startsWith('All')) f.classList.add('active'); });
  renderDiscTable();
}

function filterDiscData(filter, btn) {
  currentDiscFilter = filter;
  document.querySelectorAll('.disc-filter').forEach(f => f.classList.remove('active'));
  btn.classList.add('active');
  renderDiscTable();
}

function renderDiscTable() {
  if (!discoveryData) return;
  const thead = document.getElementById('discoveryTableHead');
  const tbody = document.getElementById('discoveryTableBody');

  let items = [];
  let headers = [];

  if (currentDiscTab === 'domains') {
    headers = ['Detection Date', 'Domain Name', 'IP Address', 'Registrar', 'Company Name', 'Status'];
    items = (discoveryData.domains || []).map(d => ({
      ...d,
      _status: d.reachable ? 'confirmed' : 'new',
      _row: [d.detection_date, d.domain_name, d.ip || '—', d.registrar, d.company_name,
             d.reachable ? '<span style="color:var(--green)">✓ Reachable</span>' : '<span style="color:var(--orange)">DNS Only</span>']
    }));
  } else if (currentDiscTab === 'ssl') {
    headers = ['Detection Date', 'SSL SHA Fingerprint', 'Valid From', 'Common Name', 'Company Name', 'Certificate Authority'];
    items = (discoveryData.ssl || []).map(s => ({
      ...s, _status: s.cert_expired ? 'new' : 'confirmed',
      _row: [s.detection_date, s.ssl_sha_fingerprint, s.valid_from, s.common_name, s.company_name, s.certificate_authority]
    }));
  } else if (currentDiscTab === 'ip') {
    headers = ['Detection Date', 'IP Address', 'Ports', 'Hostname', 'TLS Version', 'PQC Safe', 'Grade', 'Company'];
    items = (discoveryData.ip_addresses || []).map(ip => ({
      ...ip, _status: ip.pqc_safe ? 'confirmed' : 'new',
      _row: [ip.detection_date, ip.ip_address, ip.ports, ip.hostname, ip.tls_version || '—',
             ip.pqc_safe ? '<span style="color:var(--green)">✓ Yes</span>' : '<span style="color:var(--red)">✕ No</span>',
             ip.risk_grade || '—', ip.company]
    }));
  } else if (currentDiscTab === 'software') {
    headers = ['Detection Date', 'Product', 'Version', 'Type', 'Port', 'Host', 'Company Name'];
    items = (discoveryData.software || []).map(sw => ({
      ...sw, _status: sw.pqc_safe ? 'confirmed' : 'new',
      _row: [sw.detection_date, sw.product, (sw.version||'').substring(0,30), sw.type, sw.port, sw.host, sw.company_name]
    }));
  }

  // Apply filter
  let filtered = items;
  if (currentDiscFilter === 'new') filtered = items.filter(i => i._status === 'new');
  else if (currentDiscFilter === 'confirmed') filtered = items.filter(i => i._status === 'confirmed');
  else if (currentDiscFilter === 'false_positive') filtered = [];

  // Update filter counts
  document.getElementById('discFilterNew').textContent = items.filter(i => i._status === 'new').length;
  document.getElementById('discFilterConf').textContent = items.filter(i => i._status === 'confirmed').length;
  document.getElementById('discFilterFP').textContent = '0';
  document.getElementById('discFilterAll').textContent = items.length;

  thead.innerHTML = `<tr>${headers.map(h => `<th>${h}</th>`).join('')}</tr>`;
  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="${headers.length}" style="text-align:center;color:var(--muted);padding:32px">No data in this filter</td></tr>`;
  } else {
    tbody.innerHTML = filtered.map((item, i) =>
      `<tr style="animation:fadeIn .3s ${i*.03}s both">${item._row.map(v => `<td>${v}</td>`).join('')}</tr>`
    ).join('');
  }
}

// ─────────────────────────────────────────────
// REPORTING TAB
// ─────────────────────────────────────────────
let reportChartRisk = null;
let reportChartPqc = null;

function showReportPanel(type) {
  document.querySelectorAll('.report-type-card').forEach((card) => {
    card.classList.toggle('active', card.dataset.reportType === type);
  });

  ['executive','scheduled','ondemand'].forEach(t => {
    const el = document.getElementById('reportPanel-'+t);
    if (el) {
      el.style.display = t === type ? 'block' : 'none';
      el.classList.remove('is-visible');
    }
  });

  const activePanel = document.getElementById('reportPanel-' + type);
  if (activePanel) {
    activePanel.classList.add('is-visible');
    activePanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  if (type === 'executive') loadReportHistory();
  if (type === 'scheduled') loadSchedules();
  if (type === 'ondemand') loadReportScans();
}

function setSchedFrequency(value, chip) {
  const input = document.getElementById('schedFrequency');
  if (input) input.value = value;
  document.querySelectorAll('#schedFrequencyChips .pill-chip').forEach((item) => item.classList.remove('active'));
  chip?.classList.add('active');
}

// SQLite stores datetime as "YYYY-MM-DD HH:MM:SS" (space, not T).
// new Date("2024-01-01 12:00:00Z") parses as Invalid Date in Safari.
// This helper normalises to ISO 8601 before parsing.
function formatDate(raw) {
  if (!raw) return '—';
  const iso = raw.trim().replace(' ', 'T');
  const d = new Date(iso.endsWith('Z') ? iso : iso + 'Z');
  if (!Number.isFinite(d.getTime())) return raw;
  return d.toLocaleString();
}

function _parseErrorPayload(payload, fallback='Request failed') {
  if (!payload) return fallback;
  if (typeof payload === 'string') return payload;
  if (payload.detail) {
    if (typeof payload.detail === 'string') return payload.detail;
    return JSON.stringify(payload.detail);
  }
  return fallback;
}

async function fetchJson(url, opts={}) {
  const response = await fetch(url, opts);
  let data;
  try {
    data = await response.json();
  } catch (parseErr) {
    const raw = await response.text().catch(() => '');
    const preview = raw.slice(0, 300);
    console.error('[fetchJson] JSON parse failed:', parseErr.message, 'Response preview:', preview);
    throw new Error(`Server returned invalid JSON (${response.status}). Check console for details.`);
  }
  if (!response.ok) {
    throw new Error(_parseErrorPayload(data, `HTTP ${response.status}`));
  }
  return data;
}

function _num(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function normalizeReportMetrics(data) {
  const dashboard = data?.dashboard || {};
  const cards = dashboard?.cards || {};
  const asset = data?.asset_summary || {};
  const tls = data?.tls_security_metrics || {};
  const pqc = data?.pqc_readiness || {};
  const metrics = data?.metrics || {};

  const totalAssets = _num(data.total_assets, _num(cards.total_assets, _num(metrics.total_assets, _num(asset.total_assets, 0))));
  const reachableAssets = _num(data.reachable, _num(cards.reachable_assets, _num(metrics.reachable, _num(asset.reachable_assets, 0))));
  const pqcSafe = _num(data.pqc_safe, _num(cards.pqc_safe, _num(metrics.pqc_safe, _num(pqc.ready_count, 0))));
  const pqcVulnerable = _num(data.pqc_vulnerable, _num(cards.pqc_vulnerable, _num(metrics.pqc_vulnerable, _num(pqc.not_ready_count, 0))));
  const avgScore = _num(data.avg_score, _num(cards.avg_score, _num(metrics.avg_score, _num(tls.avg_score, 0))));
  const pqcCoverage = _num(data.pqc_coverage, _num(cards.pqc_coverage_pct, _num(metrics.pqc_coverage, _num(pqc.coverage_pct, 0))));
  const vulnPct = _num(cards.vulnerability_pct, _num(tls.vulnerability_pct, _num(tls.vuln_pct, 0)));

  return {
    total_assets: Math.round(totalAssets),
    reachable_assets: Math.round(reachableAssets),
    pqc_safe: Math.round(pqcSafe),
    pqc_vulnerable: Math.round(pqcVulnerable),
    avg_score: Number(avgScore.toFixed(2)),
    pqc_coverage_pct: Number(pqcCoverage.toFixed(2)),
    vulnerability_pct: Number(vulnPct.toFixed(2)),
  };
}

function computeReportDataConfidence(metrics, scanCount, consistencyChecks) {
  let score = 1.0;
  const required = ['total_assets','reachable_assets','pqc_safe','pqc_vulnerable','avg_score','pqc_coverage_pct'];
  const missing = required.filter(k => !Number.isFinite(Number(metrics?.[k])));
  if (missing.length) score -= 0.15 * missing.length;

  if (Number.isFinite(scanCount) && scanCount > 0 && Number(metrics.total_assets) !== scanCount) {
    score -= 0.25;
  }

  if (consistencyChecks && consistencyChecks.pqc_pct_matches_counts === false) {
    score -= 0.2;
  }

  return Math.max(0, Math.min(1, Number(score.toFixed(2))));
}

async function generateExecReport() {
  const raw = document.getElementById('execReportTargets').value.trim();
  if (!raw) { alert('Enter at least one target.'); return; }
  const targets = raw.split('\n').map(t=>t.trim()).filter(Boolean);

  document.getElementById('execReportLoader').style.display = 'flex';
  document.getElementById('execReportResults').style.display = 'none';

  try {
    const payload = { report_type: 'executive', targets, generated_by: authUser || 'frontend' };
    console.log('[DEBUG] Sending executive report request:', payload);
    const data = await fetchJson(`${BACKEND_URL}/report/generate`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload)
    });
    console.log('[DEBUG] Received report data:', data);
    renderExecReport(data, 'execReportResults');
    loadReportHistory();
    loadReportScans();
  } catch(e) {
    console.error('[ERROR] Report generation failed:', e);
    alert(`Report generation failed: ${e.message}`);
  } finally {
    document.getElementById('execReportLoader').style.display = 'none';
  }
}

function renderExecReport(data, elementId='execReportResults') {
  try {
    const el = document.getElementById(elementId);
    if (!el) {
      console.error('[ERROR] Element not found:', elementId);
      return;
    }

    console.log('[DEBUG] renderExecReport - full data:', data);
    const dashboard = data.dashboard || {};
    const cards = normalizeReportMetrics(data);
    const charts = dashboard.charts || {};
    const ai = data.ai_summary || {};
    const asset = data.asset_summary || {};
    const cert = data.certificate_health || {};
    const scansArray = Array.isArray(data.results) ? data.results : (Array.isArray(data.scans) ? data.scans : []);
    const backendCount = Number(cards.total_assets || 0);
    const frontendCount = scansArray.length;
    const countMismatch = frontendCount > 0 && backendCount !== frontendCount;
    const confidenceScore = computeReportDataConfidence(cards, frontendCount, data.consistency_checks || {});

    console.log('[DEBUG] report normalized metrics:', cards);
    console.log('[DEBUG] report render state:', {
      backendCount,
      frontendCount,
      countMismatch,
      confidenceScore,
      consistency: data.consistency_checks || {},
    });

    if (countMismatch) {
      console.error('[AegisGuard][REPORT] Backend/frontend count mismatch', {
        backendCount,
        frontendCount,
      });
    }

    if (Array.isArray(data.results) && data.results.length !== Number(data.total_assets || 0)) {
      console.error('Data mismatch detected', {
        resultsLength: data.results.length,
        totalAssets: Number(data.total_assets || 0),
      });
    }
    
    console.log('API RESPONSE:', data);
    console.log('[DEBUG] dashboard:', dashboard);
    console.log('[DEBUG] cards:', cards);
    console.log('[DEBUG] charts:', charts);

    const finalGrade = data.final_score?.grade || 'F';
    const gradeColor = finalGrade === 'A+' || finalGrade === 'A' ? 'var(--green)' :
      finalGrade === 'B' ? 'var(--teal)' : finalGrade === 'C' ? 'var(--yellow)' : 'var(--red)';

    el.innerHTML = `
      <div style="background:#1a1a1a;border:2px solid #00ff00;padding:12px;margin-bottom:12px;border-radius:4px;color:#00ff00;font-family:monospace;font-size:11px">
        ✓ REPORT RENDERED | Assets: ${cards.total_assets} | Grade: ${data.final_score?.grade || cards.grade || 'F'} | Score: ${data.final_score?.final_score || cards.final_score || 0}
      </div>
      ${countMismatch ? `<div style="background:#3a1f00;border:1px solid var(--orange);padding:10px;margin-bottom:12px;border-radius:4px;color:var(--yellow);font-family:monospace;font-size:11px">⚠ COUNT MISMATCH: backend=${backendCount} frontend=${frontendCount}</div>` : ''}
    <div class="exec-summary-grid">
      <div class="exec-stat-card"><div class="exec-stat-num" style="color:var(--teal)">${cards.total_assets || 0}</div><div class="exec-stat-lbl">Total Assets</div></div>
      <div class="exec-stat-card"><div class="exec-stat-num" style="color:var(--green)">${cards.reachable_assets || 0}</div><div class="exec-stat-lbl">Reachable Assets</div></div>
      <div class="exec-stat-card"><div class="exec-stat-num" style="color:var(--green)">${cards.pqc_safe || 0}</div><div class="exec-stat-lbl">PQC Safe</div></div>
      <div class="exec-stat-card"><div class="exec-stat-num" style="color:var(--red)">${cards.pqc_vulnerable || 0}</div><div class="exec-stat-lbl">PQC Vulnerable</div></div>
      <div class="exec-stat-card"><div class="exec-stat-num" style="color:var(--cyan)">${cards.avg_score || 0}</div><div class="exec-stat-lbl">Avg TLS Score</div></div>
      <div class="exec-stat-card"><div class="exec-stat-num" style="color:var(--purple)">${cards.pqc_coverage_pct || 0}%</div><div class="exec-stat-lbl">PQC Coverage</div></div>
      <div class="exec-stat-card"><div class="exec-stat-num" style="color:${gradeColor}">${data.final_score?.final_score || cards.final_score || 0}</div><div class="exec-stat-lbl">Final Score / 1000</div></div>
      <div class="exec-stat-card"><div class="exec-stat-num" style="color:${gradeColor}">${data.final_score?.grade || cards.grade || 'F'}</div><div class="exec-stat-lbl">Enterprise Grade</div></div>
    </div>

    <div style="margin-top:10px;font-size:11px;color:var(--muted);font-family:'IBM Plex Mono',monospace">
      Data Confidence: <strong style="color:${confidenceScore >= 0.8 ? 'var(--green)' : confidenceScore >= 0.6 ? 'var(--yellow)' : 'var(--red)'}">${Math.round(confidenceScore * 100)}%</strong>
    </div>

    <div class="cyber-rating-box" style="margin-top:14px">
      <div style="font-size:12px;color:var(--muted);margin-bottom:8px;font-family:'IBM Plex Mono',monospace">AI EXECUTIVE SUMMARY</div>
      <div style="font-size:13px;line-height:1.65;color:var(--text2)">${ai.summary || 'No AI summary available.'}</div>
      <div style="margin-top:10px;font-size:11px;color:var(--muted)">Severity: <strong style="color:${ai.severity==='Critical'?'var(--red)':ai.severity==='High'?'var(--orange)':ai.severity==='Medium'?'var(--yellow)':'var(--green)'}">${ai.severity || 'N/A'}</strong></div>
    </div>

    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px;margin-top:14px">
      <div style="padding:12px;background:var(--bg-panel);border:1px solid #2e2e2e;border-radius:8px"><canvas id="reportRiskChart" height="180"></canvas></div>
      <div style="padding:12px;background:var(--bg-panel);border:1px solid #2e2e2e;border-radius:8px"><canvas id="reportPqcChart" height="180"></canvas></div>
    </div>

    <div class="section-head" style="margin-top:16px">CERTIFICATE HEALTH</div>
    <table class="atbl">
      <thead><tr><th>Healthy</th><th>Expiring <=30d</th><th>Expired</th><th>Self Signed</th></tr></thead>
      <tbody><tr>
        <td>${cert.healthy || 0}</td>
        <td style="color:var(--yellow)">${cert.expiring_30d || 0}</td>
        <td style="color:var(--red)">${cert.expired || 0}</td>
        <td style="color:var(--orange)">${cert.self_signed || 0}</td>
      </tr></tbody>
    </table>

    <div class="section-head" style="margin-top:16px">PORTFOLIO FINDINGS</div>
    <table class="atbl">
      <thead><tr><th>Metric</th><th>Value</th></tr></thead>
      <tbody>
        <tr><td>Total Assets</td><td>${cards.total_assets || asset.total_assets || 0}</td></tr>
        <tr><td>Reachable Assets</td><td>${cards.reachable_assets || asset.reachable_assets || 0}</td></tr>
        <tr><td>Subdomains Discovered</td><td>${asset.subdomains_discovered || 0}</td></tr>
        <tr><td>Portfolio Vulnerability %</td><td>${cards.vulnerability_pct || 0}%</td></tr>
      </tbody>
    </table>

    <div style="margin-top:16px">
      <button class="btn-blue" onclick="downloadReportJSON()">Download Report JSON</button>
      <button class="btn-blue" onclick="downloadReportPDF()">Download Report PDF</button>
    </div>`;

    el.style.display = 'block';
    el.scrollIntoView({behavior:'smooth'});
    window._lastReport = data;

    try {
      if (reportChartRisk) reportChartRisk.destroy();
      if (reportChartPqc) reportChartPqc.destroy();

      reportChartRisk = new Chart(document.getElementById('reportRiskChart'), {
        type: 'bar',
        data: {
          labels: ['Critical', 'High', 'Medium', 'Low'],
          datasets: [{
            data: [
              charts.risk_distribution?.critical || 0,
              charts.risk_distribution?.high || 0,
              charts.risk_distribution?.medium || 0,
              charts.risk_distribution?.low || 0,
            ],
            backgroundColor: ['#da1e28', '#ff832b', '#f1c21b', '#24a148']
          }]
        },
        options: { plugins: { legend: { display: false }, title: { display: true, text: 'Risk Distribution' } } }
      });

      reportChartPqc = new Chart(document.getElementById('reportPqcChart'), {
        type: 'doughnut',
        data: {
          labels: ['PQC Ready', 'Not Ready'],
          datasets: [{
            data: [charts.pqc_ready_split?.ready || 0, charts.pqc_ready_split?.not_ready || 0],
            backgroundColor: ['#24a148', '#da1e28']
          }]
        },
        options: { plugins: { legend: { position: 'bottom' }, title: { display: true, text: 'PQC Readiness Split' } } }
      });
    } catch (chartErr) {
      console.warn('[WARN] Chart rendering failed:', chartErr);
    }
  } catch (err) {
    console.error('[ERROR] renderExecReport failed:', err);
    const el = document.getElementById(elementId);
    if (el) {
      el.innerHTML = `<div style="color:var(--red);padding:12px;border:1px solid var(--red);">ERROR: ${err.message}</div>`;
      el.style.display = 'block';
    }
  }
}

function downloadReportJSON() {
  const data = window._lastReport;
  if (!data) { alert('No report data.'); return; }

  if (data.report_id) {
    window.open(`${BACKEND_URL}/report/${data.report_id}/json`, '_blank');
    return;
  }

  const a = document.createElement('a');
  a.href = 'data:application/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(data, null, 2));
  a.download = `aegisguard_report_${Date.now()}.json`;
  a.click();
}

function downloadReportPDF() {
  const data = window._lastReport;
  if (!data || !data.report_id) { alert('Generate a saved report first to download PDF.'); return; }
  window.open(`${BACKEND_URL}/report/${data.report_id}/pdf`, '_blank');
}

async function scheduleReport() {
  const targets = document.getElementById('schedTargets').value.trim().split('\n').filter(Boolean);
  const email = document.getElementById('schedEmail').value.trim();
  if (!targets.length) { alert('Enter at least one target.'); return; }

  try {
    const data = await fetchJson(`${BACKEND_URL}/report/schedule`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        report_type: document.getElementById('schedReportType').value,
        frequency: document.getElementById('schedFrequency').value,
        targets,
        email,
        timezone: document.getElementById('schedTimezone').value || 'UTC'
      })
    });

    const box = document.getElementById('schedReportStatus');
    box.style.display = 'block';
    box.innerHTML = `
      <div style="padding:20px;background:var(--bg-panel);border:1px solid var(--green);border-radius:8px;margin-top:12px">
        <div style="color:var(--green);font-size:16px;font-weight:600">Schedule created successfully.</div>
        <div style="color:var(--muted);font-size:12px;margin-top:8px;font-family:'IBM Plex Mono',monospace">
          Schedule ID: ${data.id}<br>
          Type: ${data.report_type} | Frequency: ${data.frequency}<br>
          Next Run: ${data.next_run_at || 'N/A'}<br>
          ${data.email ? 'Email: ' + data.email : ''}
        </div>
      </div>`;
    loadSchedules();
  } catch(e) {
    alert(`Scheduling failed: ${e.message}`);
  }
}

async function generateOnDemandReport() {
  const rawTargets = document.getElementById('odTargets').value.trim();
  const rawScanIds = (document.getElementById('odScanIds').value || '').trim();
  const targets = rawTargets ? rawTargets.split('\n').map(t=>t.trim()).filter(Boolean) : [];
  const scanIds = rawScanIds
    ? rawScanIds.split(',').map(s => Number(s.trim())).filter(n => Number.isInteger(n) && n > 0)
    : [];

  if (!targets.length && !scanIds.length) {
    alert('Enter targets and/or scan IDs.');
    return;
  }

  document.getElementById('odReportLoader').style.display = 'flex';
  document.getElementById('odReportResults').style.display = 'none';

  try {
    const payload = {
      domains: targets,
      scan_ids: scanIds,
      generated_by: authUser || 'frontend'
    };
    console.log('[DEBUG] Sending on-demand report request:', payload);
    const data = await fetchJson(`${BACKEND_URL}/report/on-demand`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload)
    });
    console.log('[DEBUG] Received on-demand report data:', data);

    const el = document.getElementById('odReportResults');
    renderExecReport(data, 'odReportResults');
    el.style.marginTop = '12px';
    loadReportHistory();
    loadReportScans();
  } catch(e) {
    console.error('[ERROR] On-demand report generation failed:', e);
    alert(`Report generation failed: ${e.message}`);
  } finally {
    document.getElementById('odReportLoader').style.display = 'none';
  }
}

async function loadReportHistory() {
  const el = document.getElementById('reportHistoryList');
  if (!el) return;
  el.innerHTML = `<div style="padding:12px;color:var(--muted)">Loading report history...</div>`;

  try {
    const data = await fetchJson(`${BACKEND_URL}/report/history?limit=20`);
    const reports = data.reports || [];
    if (!reports.length) {
      el.innerHTML = `<div style="padding:16px;color:var(--muted)">No reports generated yet.</div>`;
      return;
    }

    el.innerHTML = `
      <div style="overflow-x:auto">
        <table class="atbl">
          <thead><tr><th>ID</th><th>Type</th><th>Grade</th><th>Score</th><th>Domains</th><th>Created</th><th>Actions</th></tr></thead>
          <tbody>
            ${reports.map(r => `
              <tr>
                <td>#${r.id}</td>
                <td>${r.report_type}</td>
                <td style="color:${r.grade==='A+'||r.grade==='A'?'var(--green)':r.grade==='B'?'var(--teal)':r.grade==='C'?'var(--yellow)':'var(--red)'}">${r.grade}</td>
                <td>${r.final_score || 0}</td>
                <td>${(r.domains || []).slice(0,3).join(', ')}${(r.domains || []).length > 3 ? ' ...' : ''}</td>
                <td>${formatDate(r.created_at)}</td>
                <td>
                  <button class="btn-blue" style="font-size:11px;padding:4px 8px" onclick="viewReport(${r.id})">View</button>
                  <button class="btn-blue" style="font-size:11px;padding:4px 8px" onclick="window.open('${BACKEND_URL}/report/${r.id}/json','_blank')">JSON</button>
                  <button class="btn-blue" style="font-size:11px;padding:4px 8px" onclick="window.open('${BACKEND_URL}/report/${r.id}/pdf','_blank')">PDF</button>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>`;
  } catch (e) {
    el.innerHTML = `<div style="padding:12px;color:var(--red)">Failed to load history: ${e.message}</div>`;
  }
}

async function viewReport(reportId) {
  try {
    const detail = await fetchJson(`${BACKEND_URL}/report/${reportId}`);
    const report = detail.report || {};
    // Inject report_id so downloadReportPDF/JSON work correctly on viewed reports
    window._lastReport = { ...report, report_id: reportId };
    // Ensure the executive panel is visible before rendering into it
    showReportPanel('executive');
    renderExecReport(window._lastReport, 'execReportResults');
  } catch (e) {
    alert(`Could not load report ${reportId}: ${e.message}`);
  }
}

async function loadSchedules() {
  const el = document.getElementById('schedList');
  if (!el) return;
  el.innerHTML = `<div style="padding:12px;color:var(--muted)">Loading schedules...</div>`;
  try {
    const data = await fetchJson(`${BACKEND_URL}/report/schedules?active_only=false`);
    const schedules = data.schedules || [];
    if (!schedules.length) {
      el.innerHTML = `<div style="padding:12px;color:var(--muted)">No schedules configured.</div>`;
      return;
    }

    el.innerHTML = `
      <div style="overflow-x:auto">
        <table class="atbl">
          <thead><tr><th>ID</th><th>Frequency</th><th>Targets</th><th>Status</th><th>Next Run</th><th>Last Run</th><th>Email</th></tr></thead>
          <tbody>
            ${schedules.map(s => `
              <tr>
                <td>#${s.id}</td>
                <td>${s.frequency}</td>
                <td>${(s.targets || []).slice(0,3).join(', ')}${(s.targets || []).length > 3 ? ' ...' : ''}</td>
                <td>${s.status}</td>
                <td>${s.next_run_at || '-'}</td>
                <td>${s.last_run_at || '-'}</td>
                <td>${s.email || '-'}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>`;
  } catch (e) {
    el.innerHTML = `<div style="padding:12px;color:var(--red)">Failed to load schedules: ${e.message}</div>`;
  }
}

async function loadReportScans() {
  const el = document.getElementById('odScanHistoryList');
  if (!el) return;
  el.innerHTML = `<div style="padding:12px;color:var(--muted)">Loading scan history...</div>`;

  try {
    const data = await fetchJson(`${BACKEND_URL}/report/scans?limit=50`);
    const scans = data.scans || [];
    if (!scans.length) {
      el.innerHTML = `<div style="padding:12px;color:var(--muted)">No saved scans available yet. Generate a report first.</div>`;
      return;
    }

    el.innerHTML = `
      <div style="overflow-x:auto">
        <table class="atbl">
          <thead><tr><th>Pick</th><th>Scan ID</th><th>Target</th><th>Score</th><th>Grade</th><th>PQC</th><th>Created</th></tr></thead>
          <tbody>
            ${scans.map(s => `
              <tr>
                <td><input type="checkbox" onchange="toggleOnDemandScanId(${s.id}, this.checked)"></td>
                <td>${s.id}</td>
                <td>${s.target}</td>
                <td>${s.score}</td>
                <td>${s.grade}</td>
                <td style="color:${s.pqc_safe?'var(--green)':'var(--red)'}">${s.pqc_safe?'Safe':'Vulnerable'}</td>
                <td>${formatDate(s.created_at)}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>`;
  } catch (e) {
    el.innerHTML = `<div style="padding:12px;color:var(--red)">Failed to load scans: ${e.message}</div>`;
  }
}

function toggleOnDemandScanId(scanId, checked) {
  const input = document.getElementById('odScanIds');
  if (!input) return;
  const existing = new Set((input.value || '').split(',').map(s => Number(s.trim())).filter(n => Number.isInteger(n) && n > 0));
  if (checked) existing.add(scanId);
  else existing.delete(scanId);
  input.value = [...existing].sort((a,b) => a-b).join(', ');
}

// ─────────────────────────────────────────────
// v1.0.0 ADVANCED INTELLIGENCE RENDERER
// ─────────────────────────────────────────────
function renderAdvancedIntel(d) {
  const panel = document.getElementById('advancedIntelPanel');
  if (!panel) return;
  
  const hasCVEs = d.cve_intelligence && d.cve_intelligence.length > 0;
  const hasHNDL = d.hndl_timeline && d.hndl_timeline.timeline;
  const hasHeaders = d.security_headers && d.security_headers.headers;
  const hasAgility = d.crypto_agility && d.crypto_agility.factors;
  const hasCompliance = d.compliance && Object.keys(d.compliance).length > 0;
  
  if (!hasCVEs && !hasHNDL && !hasHeaders && !hasAgility && !hasCompliance) return;
  panel.style.display = 'block';

  // CVE Intelligence
  if (d.cve_intelligence) {
    const cves = d.cve_intelligence;
    document.getElementById('cveCount').textContent = `${cves.length} vulnerabilities detected`;
    if (cves.length === 0) {
      document.getElementById('cveGrid').innerHTML = `<div class="intel-empty">✓ No known CVE vulnerabilities detected for current TLS configuration</div>`;
    } else {
      document.getElementById('cveGrid').innerHTML = cves.map((c, i) => {
        const sevCls = c.severity === 'CRITICAL' ? 'critical' : c.severity === 'HIGH' ? 'high' : 'low';
        return `<div class="fcard ${sevCls}" style="animation-delay:${i*.06}s">
          <div class="fcard-sev sev-${c.severity}">● ${c.severity} — CVSS ${c.cvss}</div>
          <div class="fcard-title">${c.cve_id} — ${c.name}</div>
          <div class="fcard-desc">${c.description}</div>
          <div class="fcard-remediation"><strong>Fix:</strong> ${c.remediation}</div>
          <span class="fcard-algo">${c.cwe} · Disclosed ${c.year}</span>
          <div class="fcard-source">AegisGuard CVE Intelligence Engine</div>
        </div>`;
      }).join('');
    }
  }

  // HNDL Timeline
  if (hasHNDL) {
    const h = d.hndl_timeline;
    const threatCls = h.overall_threat === 'SAFE' ? 'var(--green)' : 
                      h.overall_threat === 'LOW' ? 'var(--teal)' :
                      h.overall_threat === 'MEDIUM' ? 'var(--yellow)' : 'var(--red)';
    document.getElementById('hndlVerdict').textContent = h.overall_threat;
    document.getElementById('hndlVerdict').style.color = threatCls;

    document.getElementById('hndlPanel').innerHTML = `
      <div class="hndl-verdict" style="border-left:4px solid ${threatCls}">
        <div class="hndl-verdict-title" style="color:${threatCls}">${h.overall_threat} — HNDL Risk Assessment</div>
        <div class="hndl-verdict-text">${h.verdict}</div>
        <div class="hndl-meta">
          <span>Data Shelf Life: <strong>${h.data_shelf_life}</strong></span>
          <span>Action: <strong>${h.recommended_action}</strong></span>
        </div>
      </div>
      <div class="hndl-timeline-grid">
        ${(h.timeline || []).map(t => {
          const tCls = t.threat_level === 'QUANTUM SAFE' ? 'hndl-safe' :
                       t.threat_level === 'LOW' ? 'hndl-low' :
                       t.threat_level === 'SAFE' ? 'hndl-safe' :
                       t.threat_level === 'MEDIUM' ? 'hndl-med' : 'hndl-high';
          return `<div class="hndl-entry ${tCls}">
            <div class="hndl-component">${t.component}</div>
            <div class="hndl-row"><span>Algorithm</span><span>${t.algorithm}</span></div>
            <div class="hndl-row"><span>Years to Break</span><span class="hndl-years">${t.years_to_break}</span></div>
            <div class="hndl-row"><span>Threat Level</span><span>${t.threat_level}</span></div>
            <div class="hndl-row"><span>NIST Deadline</span><span>${t.nist_deadline}</span></div>
            <div class="hndl-row"><span>Qubits Needed</span><span style="font-size:10px">${t.qubits_needed}</span></div>
          </div>`;
        }).join('')}
      </div>`;
  }

  // Security Headers
  if (hasHeaders) {
    const sh = d.security_headers;
    document.getElementById('headerGrade').textContent = `Grade ${sh.grade} — ${sh.score}/${sh.max_score} headers present (${sh.percentage}%)`;
    
    document.getElementById('headersGrid').innerHTML = `
      <div class="headers-summary">
        <div class="headers-score-circle" style="color:${sh.grade==='A'||sh.grade==='B'?'var(--green)':sh.grade==='C'?'var(--yellow)':'var(--red)'}">
          <div class="headers-score-val">${sh.grade}</div>
          <div class="headers-score-lbl">${sh.percentage}%</div>
        </div>
        <div class="headers-info">
          <div>${sh.score} of ${sh.max_score} security headers detected</div>
          ${sh.server_fingerprint ? `<div style="color:var(--muted);font-size:11px">Server: ${sh.server_fingerprint}</div>` : ''}
          ${sh.powered_by ? `<div style="color:var(--orange);font-size:11px">⚠ X-Powered-By exposed: ${sh.powered_by}</div>` : ''}
        </div>
      </div>
      <table class="atbl">
        <thead><tr><th>Header</th><th>Status</th><th>Priority</th><th>Value / Recommended</th></tr></thead>
        <tbody>
          ${(sh.headers || []).map(h => `<tr>
            <td style="font-family:'IBM Plex Mono',monospace;font-size:11px">${h.header}</td>
            <td>${h.present ? '<span class="ok">✓ SET</span>' : '<span class="bad">✕ MISSING</span>'}</td>
            <td><span class="sev-badge sev-badge-${h.priority.toLowerCase()}">${h.priority}</span></td>
            <td style="font-size:10px;color:var(--muted);max-width:300px;overflow:hidden;text-overflow:ellipsis">${h.present ? h.value : h.recommended}</td>
          </tr>`).join('')}
        </tbody>
      </table>`;
  }

  // Crypto Agility
  if (hasAgility) {
    const ag = d.crypto_agility;
    const agCls = ag.grade === 'A+' || ag.grade === 'A' ? 'var(--green)' : 
                  ag.grade === 'B' ? 'var(--teal)' :
                  ag.grade === 'C' ? 'var(--yellow)' : 'var(--red)';
    document.getElementById('agilityGrade').textContent = `Grade ${ag.grade} — ${ag.agility_score}/${ag.max_score} | Migration: ${ag.migration_difficulty} (~${ag.estimated_migration_time})`;

    document.getElementById('agilityPanel').innerHTML = `
      <div class="agility-header">
        <div class="agility-score" style="color:${agCls}">
          <div class="agility-score-val">${ag.agility_score}</div>
          <div class="agility-score-lbl">/ ${ag.max_score}</div>
        </div>
        <div class="agility-meta">
          <div>Migration Difficulty: <strong style="color:${agCls}">${ag.migration_difficulty}</strong></div>
          <div>Estimated Time: <strong>${ag.estimated_migration_time}</strong></div>
        </div>
      </div>
      <div class="agility-factors">
        ${(ag.factors || []).map(f => {
          const pct = Math.round((f.score / f.max) * 100);
          const fCls = f.status === 'READY' || f.status === 'COMPLETE' ? 'var(--green)' :
                       f.status === 'PARTIAL' || f.status === 'IN PROGRESS' ? 'var(--yellow)' : 'var(--red)';
          return `<div class="agility-factor">
            <div class="agility-factor-head">
              <span>${f.factor}</span>
              <span style="color:${fCls};font-weight:600">${f.status} (${f.score}/${f.max})</span>
            </div>
            <div class="agility-bar-bg"><div class="agility-bar-fill" style="width:${pct}%;background:${fCls}"></div></div>
            <div class="agility-factor-detail">${f.detail}</div>
          </div>`;
        }).join('')}
      </div>`;
  }

  // Compliance Mapping
  if (hasCompliance) {
    const comp = d.compliance;
    document.getElementById('complianceGrid').innerHTML = `
      <div class="compliance-cards">
        ${Object.entries(comp).map(([fwId, fw]) => {
          const statusCls = fw.status === 'COMPLIANT' ? 'compliance-pass' : 
                           fw.status === 'PARTIAL' ? 'compliance-partial' : 'compliance-fail';
          const statusColor = fw.status === 'COMPLIANT' ? 'var(--green)' : 
                             fw.status === 'PARTIAL' ? 'var(--yellow)' : 'var(--red)';
          return `<div class="compliance-card ${statusCls}">
            <div class="compliance-card-head">
              <div class="compliance-fw-id">${fwId}</div>
              <div class="compliance-status" style="color:${statusColor}">${fw.status} (${fw.percentage}%)</div>
            </div>
            <div class="compliance-fw-name">${fw.name}</div>
            <div class="compliance-bar-bg"><div class="compliance-bar-fill" style="width:${fw.percentage}%;background:${statusColor}"></div></div>
            <div class="compliance-controls">
              ${fw.controls.map(c => `<div class="compliance-ctrl">
                <span class="compliance-ctrl-id">${c.id}</span>
                <span class="compliance-ctrl-status" style="color:${c.status==='PASS'?'var(--green)':'var(--red)'}">${c.status==='PASS'?'✓':'✕'}</span>
                <span class="compliance-ctrl-req">${c.requirement}</span>
              </div>`).join('')}
            </div>
          </div>`;
        }).join('')}
      </div>`;
  }
}
