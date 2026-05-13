'use strict';

// ── WebSocket ──────────────────────────────────────────────────────────────────
let ws = null;
let wsReady = false;

function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(`${proto}//${location.host}/ws`);

  ws.onopen = () => {
    setWsStatus('Connected', 'success');
    wsReady = true;
    loadInterfaces();
  };
  ws.onclose = () => {
    wsReady = false;
    setWsStatus('Disconnected', 'danger');
    setCaptureRunning(false);
    setTimeout(connectWS, 3000);
  };
  ws.onerror = () => setWsStatus('Error', 'danger');
  ws.onmessage = (ev) => handleWSMessage(JSON.parse(ev.data));
}

function sendWS(obj) {
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}

function handleWSMessage(msg) {
  switch (msg.type) {
    case 'connected': break;
    case 'capture_started':
      setCaptureRunning(true);
      document.getElementById('live-badge').classList.remove('d-none');
      showToast('Live capture started', 'success');
      break;
    case 'capture_stopped':
      setCaptureRunning(false);
      document.getElementById('live-badge').classList.add('d-none');
      showToast('Capture stopped', 'secondary');
      break;
    case 'live_update':
      applyResult(msg.data);
      break;
    case 'error':
      showToast(msg.message || 'Unknown error', 'danger');
      if (msg.message && msg.message.includes('TShark')) {
        document.getElementById('tshark-warning').classList.remove('d-none');
      }
      break;
  }
}

// ── State ──────────────────────────────────────────────────────────────────────
let captureRunning = false;
let currentPackets = [];

function setCaptureRunning(running) {
  captureRunning = running;
  document.getElementById('start-capture').classList.toggle('d-none', running);
  document.getElementById('stop-capture').classList.toggle('d-none', !running);
}

// ── Interfaces ────────────────────────────────────────────────────────────────
async function loadInterfaces() {
  const sel = document.getElementById('iface-select');
  sel.innerHTML = '<option value="">Loading…</option>';
  try {
    const resp = await fetch('/api/interfaces');
    if (!resp.ok) {
      sel.innerHTML = '<option value="">Unavailable</option>';
      document.getElementById('tshark-warning').classList.remove('d-none');
      return;
    }
    const ifaces = await resp.json();
    if (!Array.isArray(ifaces) || ifaces.length === 0) {
      sel.innerHTML = '<option value="">No interfaces found</option>';
      return;
    }
    sel.innerHTML = ifaces.map(i =>
      `<option value="${esc(i.name)}">${esc(i.label)}</option>`
    ).join('');
  } catch {
    sel.innerHTML = '<option value="">Error loading interfaces</option>';
  }
}

// ── File Upload ────────────────────────────────────────────────────────────────
function setupFileUpload() {
  const dropZone = document.getElementById('drop-zone');
  const fileInput = document.getElementById('pcap-file');

  dropZone.addEventListener('dragover', e => {
    e.preventDefault();
    dropZone.classList.add('drop-active');
  });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drop-active'));
  dropZone.addEventListener('drop', e => {
    e.preventDefault();
    dropZone.classList.remove('drop-active');
    const f = e.dataTransfer.files[0];
    if (f) uploadFile(f);
  });
  fileInput.addEventListener('change', () => {
    if (fileInput.files[0]) uploadFile(fileInput.files[0]);
  });
}

async function uploadFile(file) {
  const prog = document.getElementById('upload-progress');
  prog.classList.remove('d-none');
  clearResults();
  const form = new FormData();
  form.append('pcap', file);
  try {
    const resp = await fetch('/api/upload', { method: 'POST', body: form });
    const body = await resp.json();
    if (!resp.ok) {
      showToast(body.error || 'Upload failed', 'danger');
    } else {
      applyResult(body);
      showToast(`Loaded ${file.name}: ${fmtNum(body.total_packets)} packets`, 'success');
    }
  } catch (e) {
    showToast('Upload error: ' + e.message, 'danger');
  } finally {
    prog.classList.add('d-none');
  }
}

// ── Live Capture Controls ─────────────────────────────────────────────────────
function setupCapture() {
  document.getElementById('start-capture').addEventListener('click', () => {
    if (!wsReady) { showToast('WebSocket not connected', 'warning'); return; }
    const iface = document.getElementById('iface-select').value;
    if (!iface) { showToast('Select a network interface first', 'warning'); return; }
    clearResults();
    sendWS({
      type: 'start_capture',
      iface,
      filter: document.getElementById('bpf-filter').value.trim(),
      max_pkts: 0,
    });
  });
  document.getElementById('stop-capture').addEventListener('click', () => {
    sendWS({ type: 'stop_capture' });
  });
  document.getElementById('refresh-ifaces').addEventListener('click', loadInterfaces);
}

// ── Apply Results ─────────────────────────────────────────────────────────────
function applyResult(data) {
  if (!data) return;
  currentPackets = data.packets || [];
  updateStats(data);
  renderPackets(currentPackets);
  renderAlerts(data.alerts || []);
  updateCharts(data);
}

function clearResults() {
  currentPackets = [];
  updateStats(null);
  renderPackets([]);
  renderAlerts([]);
  updateCharts(null);
}

// ── Stats Cards ───────────────────────────────────────────────────────────────
function updateStats(data) {
  const s = data && data.stats;
  const total = data ? (data.total_packets || 0) : 0;
  const alertCount = data ? (data.alerts || []).length : 0;
  const avgPPS = s && s.duration > 0
    ? Math.round(s.total_packets / s.duration) : 0;
  const avgMBps = s && s.duration > 0
    ? (s.total_bytes / s.duration / 1e6).toFixed(2) : '0.00';

  document.getElementById('stat-total').textContent = fmtNum(total);
  document.getElementById('stat-alerts').textContent = alertCount;
  document.getElementById('stat-pps').textContent = fmtNum(avgPPS);
  document.getElementById('stat-bw').textContent = avgMBps;
  document.getElementById('packet-count-badge').textContent = fmtNum(total);

  const alertBadge = document.getElementById('alert-count-badge');
  alertBadge.textContent = alertCount;
  alertBadge.className = alertCount > 0 ? 'badge bg-danger ms-1' : 'badge bg-secondary ms-1';
}

// ── Packet Table ──────────────────────────────────────────────────────────────
function setupPacketFilter() {
  document.getElementById('pkt-filter').addEventListener('input', function () {
    renderPackets(currentPackets, this.value.toLowerCase());
  });
}

function renderPackets(packets, filterStr) {
  const tbody = document.getElementById('pkt-tbody');
  const scroll = document.getElementById('pkt-table-scroll');
  const atBottom = scroll.scrollTop + scroll.clientHeight >= scroll.scrollHeight - 30;

  let rows = packets;
  if (filterStr) {
    rows = packets.filter(p =>
      p.src_ip.includes(filterStr) ||
      p.dst_ip.includes(filterStr) ||
      p.protocol.toLowerCase().includes(filterStr) ||
      (p.info && p.info.toLowerCase().includes(filterStr))
    );
  }

  const frag = document.createDocumentFragment();
  for (const p of rows) {
    const tr = document.createElement('tr');
    if (p.is_suspicious) tr.classList.add('table-warning');
    const ts = p.timestamp > 0
      ? new Date(p.timestamp * 1000).toISOString().substring(11, 23)
      : '—';
    const srcPort = p.src_port ? ':' + p.src_port : '';
    const dstPort = p.dst_port ? ':' + p.dst_port : '';
    const proto = p.protocol.toLowerCase();
    tr.innerHTML =
      `<td class="text-muted">${p.number}</td>` +
      `<td class="font-monospace small">${ts}</td>` +
      `<td class="font-monospace small">${esc(p.src_ip)}${srcPort}</td>` +
      `<td class="font-monospace small">${esc(p.dst_ip)}${dstPort}</td>` +
      `<td><span class="badge proto-${proto}">${esc(p.protocol)}</span></td>` +
      `<td class="text-muted small">${p.length}</td>` +
      `<td class="small text-secondary">${esc(p.info || '')}</td>`;
    frag.appendChild(tr);
  }
  tbody.textContent = '';
  tbody.appendChild(frag);

  if (captureRunning || atBottom) {
    scroll.scrollTop = scroll.scrollHeight;
  }
}

// ── Alerts ────────────────────────────────────────────────────────────────────
const SEV_ICON = {
  LOW: 'bi-info-circle',
  MEDIUM: 'bi-exclamation-triangle',
  HIGH: 'bi-exclamation-octagon',
  CRITICAL: 'bi-x-octagon-fill',
};
const SEV_CLS = {
  LOW: 'success',
  MEDIUM: 'warning',
  HIGH: 'danger',
  CRITICAL: 'danger',
};

function renderAlerts(alerts) {
  const container = document.getElementById('alerts-container');
  if (!alerts || alerts.length === 0) {
    container.innerHTML =
      `<div class="text-center text-muted py-5">
        <i class="bi bi-shield-check fs-1 d-block mb-3"></i>
        No alerts detected.
      </div>`;
    return;
  }

  container.innerHTML = alerts.map(a => {
    const cls = SEV_CLS[a.severity] || 'secondary';
    const icon = SEV_ICON[a.severity] || 'bi-shield';
    const srcList = (a.source_ips || []).slice(0, 6).map(ip => `<code>${esc(ip)}</code>`).join(' ');
    const moreIPs = (a.source_ips || []).length > 6
      ? `<span class="text-muted">+${a.source_ips.length - 6} more</span>` : '';
    const rec = a.recommendation
      ? `<div class="alert alert-info py-2 mb-0 small mt-2">
           <i class="bi bi-lightbulb me-1"></i><strong>Recommendation:</strong> ${esc(a.recommendation)}
         </div>` : '';

    return `
      <div class="card mb-3 border-${cls}-subtle">
        <div class="card-header d-flex align-items-center gap-2 bg-${cls} bg-opacity-10">
          <i class="bi ${icon} text-${cls}"></i>
          <strong>${esc(a.attack_type)}</strong>
          <span class="badge bg-${cls} ms-auto">${a.severity}</span>
        </div>
        <div class="card-body pb-3">
          <p class="mb-2">${esc(a.description)}</p>
          <div class="d-flex flex-wrap gap-3 small text-muted mb-2">
            <span><i class="bi bi-bullseye me-1"></i>Target: <code>${esc(a.target_ip || '—')}</code></span>
            <span><i class="bi bi-speedometer me-1"></i>${a.rate.toFixed(1)} pkt/s</span>
            <span><i class="bi bi-layers me-1"></i>${fmtNum(a.packet_count)} packets</span>
          </div>
          ${srcList ? `<div class="small mb-1"><strong>Sources:</strong> ${srcList} ${moreIPs}</div>` : ''}
          ${rec}
        </div>
      </div>`;
  }).join('');
}

// ── Charts ────────────────────────────────────────────────────────────────────
let chartPPS, chartProto, chartTopIPs;

const PALETTE = [
  '#0d6efd','#198754','#ffc107','#dc3545',
  '#0dcaf0','#6f42c1','#fd7e14','#20c997',
];

const GRID_COLOR = 'rgba(255,255,255,0.07)';
const TICK_COLOR = '#6c757d';

function initCharts() {
  Chart.defaults.color = TICK_COLOR;

  chartPPS = new Chart(document.getElementById('chart-pps'), {
    type: 'line',
    data: {
      labels: [],
      datasets: [{
        label: 'Packets/s',
        data: [],
        borderColor: '#0d6efd',
        backgroundColor: 'rgba(13,110,253,0.12)',
        fill: true,
        tension: 0.4,
        pointRadius: 0,
        borderWidth: 2,
      }],
    },
    options: {
      animation: false,
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: TICK_COLOR, maxTicksLimit: 10 }, grid: { color: GRID_COLOR } },
        y: { ticks: { color: TICK_COLOR }, grid: { color: GRID_COLOR }, beginAtZero: true },
      },
    },
  });

  chartProto = new Chart(document.getElementById('chart-proto'), {
    type: 'doughnut',
    data: { labels: [], datasets: [{ data: [], backgroundColor: PALETTE, borderWidth: 0 }] },
    options: {
      animation: false,
      responsive: true,
      plugins: { legend: { position: 'right', labels: { color: '#adb5bd', boxWidth: 12, padding: 10 } } },
    },
  });

  chartTopIPs = new Chart(document.getElementById('chart-topips'), {
    type: 'bar',
    data: {
      labels: [],
      datasets: [{
        label: 'Packets',
        data: [],
        backgroundColor: 'rgba(13,110,253,0.75)',
        borderWidth: 0,
      }],
    },
    options: {
      animation: false,
      indexAxis: 'y',
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: TICK_COLOR }, grid: { color: GRID_COLOR }, beginAtZero: true },
        y: { ticks: { color: TICK_COLOR, font: { family: 'monospace' } }, grid: { display: false } },
      },
    },
  });
}

function updateCharts(data) {
  const s = data && data.stats;

  // PPS line
  if (s && s.packets_per_second && s.time_buckets) {
    chartPPS.data.labels = s.time_buckets.map(t =>
      new Date(t * 1000).toISOString().substring(11, 19)
    );
    chartPPS.data.datasets[0].data = s.packets_per_second;
  } else {
    chartPPS.data.labels = [];
    chartPPS.data.datasets[0].data = [];
  }
  chartPPS.update('none');

  // Protocol doughnut
  if (s && s.protocol_counts) {
    const entries = Object.entries(s.protocol_counts).sort((a, b) => b[1] - a[1]);
    chartProto.data.labels = entries.map(e => e[0]);
    chartProto.data.datasets[0].data = entries.map(e => e[1]);
  } else {
    chartProto.data.labels = [];
    chartProto.data.datasets[0].data = [];
  }
  chartProto.update('none');

  // Top source IPs
  if (s && s.src_ip_counts) {
    const entries = Object.entries(s.src_ip_counts)
      .sort((a, b) => b[1] - a[1]).slice(0, 10);
    chartTopIPs.data.labels = entries.map(e => e[0]);
    chartTopIPs.data.datasets[0].data = entries.map(e => e[1]);
  } else {
    chartTopIPs.data.labels = [];
    chartTopIPs.data.datasets[0].data = [];
  }
  chartTopIPs.update('none');
}

// ── Utilities ─────────────────────────────────────────────────────────────────
function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function fmtNum(n) {
  return Number(n).toLocaleString();
}

function setWsStatus(text, cls) {
  const el = document.getElementById('ws-status');
  el.textContent = text;
  el.className = `badge bg-${cls}`;
}

function showToast(msg, type = 'secondary') {
  const wrap = document.getElementById('toast-container');
  const el = document.createElement('div');
  el.className = `toast align-items-center text-bg-${type} border-0 show`;
  el.setAttribute('role', 'alert');
  el.innerHTML =
    `<div class="d-flex">` +
    `<div class="toast-body">${esc(msg)}</div>` +
    `<button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>` +
    `</div>`;
  wrap.appendChild(el);
  setTimeout(() => el.remove(), 5000);
}

// ── Bootstrap ─────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initCharts();
  setupFileUpload();
  setupCapture();
  setupPacketFilter();
  connectWS();
});
