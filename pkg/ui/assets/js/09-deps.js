// ── Dependency graph tab ─────────────────────────────────────────────────────

window.loadDeps = function() { loadDeps(); };

let _depsData   = null;   // { nodes, edges }
let _depsNodes  = [];     // positioned nodes
let _dragNode   = null;   // node being dragged
let _simRunning = false;

const STATUS_COLORS = {
  pending:     '#6b7280',
  in_progress: '#3b82f6',
  done:        '#22c55e',
  failed:      '#ef4444',
  skipped:     '#a855f7',
  timed_out:   '#f97316',
};

function loadDeps() {
  api(pUrl('/api/deps')).then(data => {
    _depsData = data;
    renderDepsGraph(data);
  }).catch(() => {});
}

function renderDepsGraph(data) {
  const nodes  = data.nodes  || [];
  const edges  = data.edges  || [];
  const showAll = document.getElementById('depsShowAll') && document.getElementById('depsShowAll').checked;
  const emptyEl = document.getElementById('depsEmpty');
  const container = document.getElementById('depsContainer');
  const svg = document.getElementById('depsSvg');

  // Filter: when filter bar is active, use applyFilters; otherwise use showAll toggle.
  let visNodes;
  if (_filterActive() && appState && appState.plan && appState.plan.tasks) {
    const filteredIds = new Set(applyFilters(appState.plan.tasks).map(t => t.id));
    visNodes = nodes.filter(n => filteredIds.has(n.id));
    updateFilterBadge(visNodes.length, nodes.length);
  } else {
    visNodes = showAll ? nodes : nodes.filter(n => n.status !== 'done' && n.status !== 'skipped');
    updateFilterBadge(visNodes.length, nodes.length);
  }
  const visIds   = new Set(visNodes.map(n => n.id));
  const visEdges = edges.filter(e => visIds.has(e.from) && visIds.has(e.to));

  if (visNodes.length === 0) {
    if (emptyEl) emptyEl.style.display = '';
    container.style.display = 'none';
    return;
  }
  if (emptyEl) emptyEl.style.display = 'none';
  container.style.display = '';

  const W = svg.clientWidth  || svg.getBoundingClientRect().width  || 700;
  const H = svg.clientHeight || svg.getBoundingClientRect().height || 520;
  const R = 22; // node radius

  // Initialise positions with a grid layout, then run force simulation
  const posMap = {};
  visNodes.forEach((n, i) => {
    const cols = Math.max(1, Math.ceil(Math.sqrt(visNodes.length)));
    const col  = i % cols;
    const row  = Math.floor(i / cols);
    posMap[n.id] = {
      x: 60 + col * ((W - 120) / Math.max(cols - 1, 1)),
      y: 60 + row * ((H - 120) / Math.max(Math.ceil(visNodes.length / cols) - 1, 1)),
      vx: 0, vy: 0,
      node: n,
    };
  });
  _depsNodes = Object.values(posMap);

  // Build SVG
  svg.innerHTML = '';
  svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);

  // Defs: arrowhead marker
  const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
  defs.innerHTML = '<marker id="deps-arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto"><path d="M0,0 L0,6 L8,3 z" fill="#6b7280"/></marker>';
  svg.appendChild(defs);

  // Edge layer
  const edgeLayer = document.createElementNS('http://www.w3.org/2000/svg', 'g');
  edgeLayer.id = 'depsEdgeLayer';
  svg.appendChild(edgeLayer);

  // Node layer
  const nodeLayer = document.createElementNS('http://www.w3.org/2000/svg', 'g');
  nodeLayer.id = 'depsNodeLayer';
  svg.appendChild(nodeLayer);

  // Draw edges
  visEdges.forEach(e => {
    const line = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    line.classList.add('deps-edge');
    line.dataset.from = e.from;
    line.dataset.to   = e.to;
    edgeLayer.appendChild(line);
  });

  // Draw nodes
  _depsNodes.forEach(p => {
    const n = p.node;
    const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    g.classList.add('deps-node', 'deps-node-' + n.status);
    g.dataset.id = n.id;

    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('r', R);
    circle.setAttribute('cx', 0);
    circle.setAttribute('cy', 0);
    g.appendChild(circle);

    // Priority badge
    if (n.priority && n.priority <= 3) {
      const badge = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      badge.setAttribute('x', R - 6);
      badge.setAttribute('y', -(R - 6));
      badge.setAttribute('font-size', '9');
      badge.setAttribute('fill', '#facc15');
      badge.setAttribute('text-anchor', 'middle');
      badge.textContent = 'P' + n.priority;
      g.appendChild(badge);
    }

    // Label
    const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    label.setAttribute('x', 0);
    label.setAttribute('y', R + 14);
    label.setAttribute('text-anchor', 'middle');
    label.setAttribute('font-size', '10');
    label.textContent = truncateLabel(n.title, 18);
    g.appendChild(label);

    // ID label inside circle
    const idTxt = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    idTxt.setAttribute('x', 0);
    idTxt.setAttribute('y', 4);
    idTxt.setAttribute('text-anchor', 'middle');
    idTxt.setAttribute('font-size', '11');
    idTxt.setAttribute('font-weight', '600');
    idTxt.setAttribute('fill', '#fff');
    idTxt.setAttribute('pointer-events', 'none');
    idTxt.textContent = '#' + n.id;
    g.appendChild(idTxt);

    // Drag & click
    g.addEventListener('mousedown', e => startDrag(e, p));
    g.addEventListener('touchstart', e => startDrag(e, p), {passive: false});
    g.addEventListener('click', e => { e.stopPropagation(); openDepsDetail(n); });

    nodeLayer.appendChild(g);
  });

  updateDepsPositions();

  // Run force simulation
  runForce(visEdges, posMap, W, H, R);

  // Click on empty area closes sidebar
  svg.addEventListener('click', () => closeDepsDetail());
}

function truncateLabel(s, max) {
  return s.length > max ? s.slice(0, max - 1) + '…' : s;
}

function updateDepsPositions() {
  const svg = document.getElementById('depsSvg');
  if (!svg) return;
  _depsNodes.forEach(p => {
    const g = svg.querySelector('.deps-node[data-id="' + p.node.id + '"]');
    if (g) g.setAttribute('transform', 'translate(' + p.x.toFixed(1) + ',' + p.y.toFixed(1) + ')');
  });
  // Update edges
  const edgeLayer = document.getElementById('depsEdgeLayer');
  if (!edgeLayer || !_depsData) return;
  const posMap = {};
  _depsNodes.forEach(p => { posMap[p.node.id] = p; });
  edgeLayer.querySelectorAll('.deps-edge').forEach(line => {
    const from = posMap[parseInt(line.dataset.from)];
    const to   = posMap[parseInt(line.dataset.to)];
    if (!from || !to) return;
    const dx = to.x - from.x, dy = to.y - from.y;
    const dist = Math.sqrt(dx * dx + dy * dy) || 1;
    const R = 22;
    // shorten path so arrowhead touches circle edge
    const sx = from.x + dx / dist * R;
    const sy = from.y + dy / dist * R;
    const ex = to.x   - dx / dist * (R + 8);
    const ey = to.y   - dy / dist * (R + 8);
    line.setAttribute('d', 'M' + sx.toFixed(1) + ',' + sy.toFixed(1) + ' L' + ex.toFixed(1) + ',' + ey.toFixed(1));
  });
}

function runForce(edges, posMap, W, H, R) {
  if (_simRunning) return;
  _simRunning = true;
  let iter = 0;
  const maxIter = 200;
  const idealLen = 130;

  function step() {
    if (iter++ > maxIter || !_simRunning) { _simRunning = false; return; }
    const nodes = _depsNodes;
    // Repulsion
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i], b = nodes[j];
        const dx = b.x - a.x, dy = b.y - a.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 0.1;
        const force = Math.min(3000 / (dist * dist), 8);
        const fx = force * dx / dist, fy = force * dy / dist;
        a.vx -= fx; a.vy -= fy;
        b.vx += fx; b.vy += fy;
      }
    }
    // Spring attraction along edges
    edges.forEach(e => {
      const a = posMap[e.from], b = posMap[e.to];
      if (!a || !b) return;
      const dx = b.x - a.x, dy = b.y - a.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 0.1;
      const force = (dist - idealLen) * 0.04;
      const fx = force * dx / dist, fy = force * dy / dist;
      a.vx += fx; a.vy += fy;
      b.vx -= fx; b.vy -= fy;
    });
    // Center gravity
    nodes.forEach(p => {
      p.vx += (W / 2 - p.x) * 0.005;
      p.vy += (H / 2 - p.y) * 0.005;
    });
    // Dampen & integrate
    const dampen = 0.8;
    nodes.forEach(p => {
      if (p === _dragNode) { p.vx = 0; p.vy = 0; return; }
      p.vx *= dampen; p.vy *= dampen;
      p.x  = Math.max(R + 2, Math.min(W - R - 2, p.x + p.vx));
      p.y  = Math.max(R + 2, Math.min(H - R - 2, p.y + p.vy));
    });
    updateDepsPositions();
    requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

// ── Drag support ─────────────────────────────────────────────────────────────

function startDrag(evt, posNode) {
  _dragNode = posNode;
  evt.preventDefault && evt.preventDefault();
  const svg = document.getElementById('depsSvg');
  const rect = svg.getBoundingClientRect();
  const W = rect.width, H = rect.height;
  const vbW = parseFloat(svg.getAttribute('viewBox').split(' ')[2]) || W;
  const vbH = parseFloat(svg.getAttribute('viewBox').split(' ')[3]) || H;
  const scaleX = vbW / W, scaleY = vbH / H;

  function getPos(e) {
    const touch = e.touches ? e.touches[0] : e;
    return {
      x: (touch.clientX - rect.left)  * scaleX,
      y: (touch.clientY - rect.top)   * scaleY,
    };
  }

  function onMove(e) {
    if (!_dragNode) return;
    const pos = getPos(e);
    _dragNode.x = pos.x;
    _dragNode.y = pos.y;
    _dragNode.vx = 0;
    _dragNode.vy = 0;
    updateDepsPositions();
  }
  function onUp() {
    _dragNode = null;
    document.removeEventListener('mousemove', onMove);
    document.removeEventListener('mouseup',   onUp);
    document.removeEventListener('touchmove', onMove);
    document.removeEventListener('touchend',  onUp);
  }
  document.addEventListener('mousemove', onMove);
  document.addEventListener('mouseup',   onUp);
  document.addEventListener('touchmove', onMove, {passive: false});
  document.addEventListener('touchend',  onUp);
}

// ── Detail sidebar ────────────────────────────────────────────────────────────

function openDepsDetail(node) {
  const sidebar = document.getElementById('depsSidebar');
  if (!sidebar) return;
  document.getElementById('depsSidebarTitle').textContent = '#' + node.id + ' ' + node.title;
  const statusLabel = {
    pending: 'Pending', in_progress: 'In Progress', done: 'Done',
    failed: 'Failed', skipped: 'Skipped', timed_out: 'Timed Out',
  }[node.status] || node.status;
  const color = STATUS_COLORS[node.status] || '#6b7280';
  let html = '';
  html += '<div class="deps-detail-row"><span class="deps-detail-label">Status</span>'
        + '<span style="color:' + color + '">' + statusLabel + '</span></div>';
  html += '<div class="deps-detail-row"><span class="deps-detail-label">Priority</span>'
        + 'P' + (node.priority || '?') + '</div>';
  if (node.assignee) {
    html += '<div class="deps-detail-row"><span class="deps-detail-label">Assignee</span>'
          + esc(node.assignee) + '</div>';
  }
  if (node.deadline) {
    html += '<div class="deps-detail-row"><span class="deps-detail-label">Deadline</span>'
          + esc(node.deadline) + '</div>';
  }
  if (node.description) {
    html += '<div class="deps-detail-row"><span class="deps-detail-label">Description</span>'
          + '<div style="margin-top:4px;white-space:pre-wrap;line-height:1.5">' + esc(node.description) + '</div></div>';
  }
  // Show blocking/blocked-by info
  if (_depsData) {
    const blockedBy = (_depsData.edges || []).filter(e => e.to   === node.id).map(e => '#' + e.from);
    const blocks    = (_depsData.edges || []).filter(e => e.from === node.id).map(e => '#' + e.to);
    if (blockedBy.length) {
      html += '<div class="deps-detail-row"><span class="deps-detail-label">Blocked by</span>'
            + blockedBy.join(', ') + '</div>';
    }
    if (blocks.length) {
      html += '<div class="deps-detail-row"><span class="deps-detail-label">Blocks</span>'
            + blocks.join(', ') + '</div>';
    }
  }
  document.getElementById('depsSidebarBody').innerHTML = html;
  sidebar.style.display = 'flex';
}

window.closeDepsDetail = function() {
  const sidebar = document.getElementById('depsSidebar');
  if (sidebar) sidebar.style.display = 'none';
};

