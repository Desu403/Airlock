"use strict";
// airlock UI. Everything shown here comes from the Rust side: PNG pixels,
// numbers, and sanitised text — always inserted with textContent, never HTML.

const { invoke } = window.__TAURI__.core;
const $ = (id) => document.getElementById(id);

const PT_TO_PX = 96 / 72;
const ZOOMS = [0.5, 0.67, 0.75, 0.9, 1, 1.1, 1.25, 1.5, 1.75, 2, 2.5, 3];

const state = {
  pages: [],          // [{w, h, el, img, layer, key, url}]
  zoom: 1,
  fitMode: true,      // keep fitting the width on resize / panel toggle
  hits: [],
  hitIndex: -1,
  queue: [],
  rendering: false,
  docOpen: false,
  observer: null,
  findings: null,
};

// ---------------------------------------------------------------- helpers

function status(text, isError = false) {
  const s = $("status");
  s.textContent = text;
  s.classList.toggle("error", isError);
}

function busy(text) {
  $("busy").hidden = !text;
  $("busy-text").textContent = text || "";
}

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function renderDpi() {
  const dpi = 96 * state.zoom * (window.devicePixelRatio || 1);
  return Math.min(600, Math.max(20, Math.round(dpi / 24) * 24));
}

function currentPage() {
  const viewer = $("viewer");
  const mid = viewer.scrollTop + viewer.clientHeight / 3;
  let best = 0;
  for (let i = 0; i < state.pages.length; i++) {
    if (state.pages[i].el.offsetTop <= mid) best = i;
  }
  return best;
}

// ---------------------------------------------------------------- opening

async function openWith(promise, label) {
  busy(`Booting a disposable microVM for ${label}…`);
  status("Opening…");
  const t0 = performance.now();
  try {
    const info = await promise;
    if (!info) { status(state.docOpen ? "Ready" : "Ready"); return; }
    setupDocument(info);
    const secs = ((performance.now() - t0) / 1000).toFixed(1);
    status(`${info.pages.length} page(s) · VM ready in ${(info.ready_ms / 1000).toFixed(1)}s · opened in ${secs}s`);
  } catch (e) {
    status(`Could not open: ${e}`, true);
  } finally {
    busy(null);
  }
}

function openDialog() {
  openWith(invoke("pick_and_open"), "the document");
}

function openPath(path) {
  const name = path.split(/[\\/]/).pop();
  openWith(invoke("open_path", { path }), name);
}

function setupDocument(info) {
  for (const p of state.pages) if (p.url) URL.revokeObjectURL(p.url);
  state.pages = [];
  state.hits = [];
  state.hitIndex = -1;
  state.queue = [];
  state.findings = null;
  state.docOpen = true;
  $("banner").hidden = true;
  $("qcount").textContent = "";
  closePanel();

  $("docname").textContent = info.name;
  for (const id of ["doc", "searchbox", "zoombox", "textbtn", "analyze"]) $(id).hidden = false;
  $("empty").hidden = true;
  $("analyze").disabled = false;

  const container = $("pages");
  container.replaceChildren();
  if (state.observer) state.observer.disconnect();
  state.observer = new IntersectionObserver(onVisible, { root: $("viewer"), rootMargin: "600px 0px" });

  info.pages.forEach(([w, h], i) => {
    const pageEl = el("div", "page loading");
    const img = el("img");
    img.alt = `Page ${i + 1}`;
    const layer = el("div", "layer");
    pageEl.append(img, layer, el("span", "num", String(i + 1)));
    pageEl.dataset.index = String(i);
    container.append(pageEl);
    state.pages.push({ w, h, el: pageEl, img, layer, key: null, url: null, visible: false });
    state.observer.observe(pageEl);
  });
  fitWidth();
  $("viewer").scrollTop = 0;
}

// ---------------------------------------------------------------- rendering

function layout() {
  const scale = state.zoom * PT_TO_PX;
  for (const p of state.pages) {
    p.el.style.width = `${Math.round(p.w * scale)}px`;
    p.el.style.height = `${Math.round(p.h * scale)}px`;
  }
  $("zlabel").textContent = `${Math.round(state.zoom * 100)}%`;
  drawHighlights();
  for (const p of state.pages) if (p.visible) enqueue(state.pages.indexOf(p));
}

function onVisible(entries) {
  for (const e of entries) {
    const i = Number(e.target.dataset.index);
    state.pages[i].visible = e.isIntersecting;
    if (e.isIntersecting) enqueue(i);
  }
}

function enqueue(i) {
  if (!state.queue.includes(i)) state.queue.push(i);
  pump();
}

async function pump() {
  if (state.rendering) return;
  state.rendering = true;
  try {
    while (state.queue.length) {
      // Nearest-to-view first.
      const cur = currentPage();
      state.queue.sort((a, b) => Math.abs(a - cur) - Math.abs(b - cur));
      const i = state.queue.shift();
      const p = state.pages[i];
      const dpi = renderDpi();
      if (!p || !p.visible || p.key === dpi) continue;
      try {
        const buf = await invoke("render_page", { page: i, dpi });
        const url = URL.createObjectURL(new Blob([buf], { type: "image/png" }));
        if (p.url) URL.revokeObjectURL(p.url);
        p.url = url;
        p.img.src = url;
        p.key = dpi;
        p.el.classList.remove("loading");
      } catch (e) {
        status(`Page ${i + 1}: ${e}`, true);
        break;
      }
    }
  } finally {
    state.rendering = false;
  }
  checkViewingFindings();
}

async function checkViewingFindings() {
  if (!state.docOpen) return;
  const report = await invoke("viewing_findings").catch(() => null);
  if (!report) return;
  state.findings = report;
  const n = report.findings.length;
  $("banner-text").textContent = `While rendering, this document triggered ${n} blocked action(s) inside the VM.`;
  $("banner").hidden = false;
}

// ---------------------------------------------------------------- zoom

function setZoom(z, anchorPage) {
  const keep = anchorPage ?? currentPage();
  state.zoom = Math.min(3, Math.max(0.25, z));
  layout();
  const p = state.pages[keep];
  if (p) $("viewer").scrollTop = p.el.offsetTop - 12;
}

function stepZoom(dir) {
  state.fitMode = false;
  const z = state.zoom;
  const next = dir > 0 ? ZOOMS.find((v) => v > z + 0.001) : [...ZOOMS].reverse().find((v) => v < z - 0.001);
  setZoom(next ?? z);
}

function fitWidth() {
  state.fitMode = true;
  if (!state.pages.length) return;
  const maxW = Math.max(...state.pages.map((p) => p.w));
  const avail = $("viewer").clientWidth - 48;
  setZoom(Math.min(2, avail / (maxW * PT_TO_PX)), currentPage());
}

// ---------------------------------------------------------------- search

async function runSearch() {
  const q = $("q").value.trim();
  if (!state.docOpen) return;
  if (!q) {
    state.hits = [];
    state.hitIndex = -1;
    $("qcount").textContent = "";
    drawHighlights();
    return;
  }
  status(`Searching inside the VM for “${q}”…`);
  try {
    state.hits = await invoke("search", { query: q });
    state.hitIndex = state.hits.length ? 0 : -1;
    status(`${state.hits.length} match(es) for “${q}”`);
    drawHighlights();
    showHit();
  } catch (e) {
    status(`Search failed: ${e}`, true);
  }
}

function drawHighlights() {
  const scale = state.zoom * PT_TO_PX;
  for (const p of state.pages) p.layer.replaceChildren();
  state.hits.forEach((h, idx) => {
    const p = state.pages[h.page];
    if (!p) return;
    const [x0, y0, x1, y1] = h.rect;
    const d = el("div", idx === state.hitIndex ? "hl current" : "hl");
    d.style.left = `${x0 * scale - 1}px`;
    d.style.top = `${y0 * scale - 1}px`;
    d.style.width = `${(x1 - x0) * scale + 2}px`;
    d.style.height = `${(y1 - y0) * scale + 2}px`;
    p.layer.append(d);
  });
  $("qcount").textContent = state.hits.length ? `${state.hitIndex + 1} / ${state.hits.length}` : ($("q").value.trim() ? "0" : "");
}

function showHit() {
  const h = state.hits[state.hitIndex];
  if (!h) return;
  drawHighlights();
  const p = state.pages[h.page];
  const scale = state.zoom * PT_TO_PX;
  const viewer = $("viewer");
  viewer.scrollTop = p.el.offsetTop + h.rect[1] * scale - viewer.clientHeight / 3;
}

function stepHit(dir) {
  if (!state.hits.length) return runSearch();
  state.hitIndex = (state.hitIndex + dir + state.hits.length) % state.hits.length;
  showHit();
}

// ---------------------------------------------------------------- panels

function openPanel(title) {
  $("panel-title").textContent = title;
  $("panel").hidden = false;
  if (state.fitMode) fitWidth();
  return $("panel-body");
}

function closePanel() {
  $("panel").hidden = true;
  $("panel-body").replaceChildren();
  if (state.fitMode && state.docOpen) fitWidth();
}

async function showText() {
  const page = currentPage();
  const body = openPanel(`Text · page ${page + 1}`);
  body.replaceChildren(el("p", "note", "Extracting inside the VM…"));
  try {
    const text = await invoke("page_text", { page });
    const copy = el("button", "", "Copy");
    const row = el("div", "row");
    row.append(copy, el("span", "note", "Extracted inside the VM; control and bidi-override characters removed."));
    const pre = el("pre", "", text || "(no text on this page — it may be a scanned image)");
    copy.onclick = async () => {
      try { await navigator.clipboard.writeText(text); copy.textContent = "Copied"; }
      catch { const r = document.createRange(); r.selectNodeContents(pre); getSelection().removeAllRanges(); getSelection().addRange(r); copy.textContent = "Selected — press Ctrl+C"; }
    };
    body.replaceChildren(row, pre);
  } catch (e) {
    body.replaceChildren(el("p", "note", `Could not extract text: ${e}`));
  }
}

const SOURCE_TITLES = {
  outside: "Seen from outside the VM — cannot be faked by the document",
  monitor: "Seen by the in-VM monitor",
  emulated: "What its JavaScript does in a (fake) Adobe Reader",
  static: "Static structure of the file",
};

function renderReport(body, report, title) {
  const v = report.verdict;
  const cls = v.startsWith("MALICIOUS") || v.startsWith("LIKELY") ? "malicious" : v.startsWith("SUSPICIOUS") ? "suspicious" : "clean";
  const box = el("div", `verdict ${cls}`);
  box.append(el("h3", "", v), el("p", "", report.summary));
  const nodes = [box];
  if (title) nodes.push(el("p", "note", title));
  for (const src of ["outside", "monitor", "emulated", "static"]) {
    const items = report.findings.filter((f) => f.source === src);
    if (!items.length) continue;
    nodes.push(el("div", "source", SOURCE_TITLES[src]));
    for (const f of items) {
      const row = el("div", "finding");
      row.append(el("span", `sev ${f.severity}`, f.severity === "medium" ? "med" : f.severity), el("span", "what", f.what));
      if (f.attack && f.attack !== "-") row.append(el("span", "attack", `ATT&CK ${f.attack}`));
      nodes.push(row);
    }
  }
  if (!report.findings.length) nodes.push(el("p", "note", "No findings."));
  body.replaceChildren(...nodes);
}

async function analyze() {
  const btn = $("analyze");
  btn.disabled = true;
  const body = openPanel("Analysis");
  const wait = el("div", "row");
  wait.append(el("div", "spinner"), el("span", "note", "Detonating in a separate microVM wired to a fake internet, then examining its disk in a second VM. You can keep reading meanwhile."));
  body.replaceChildren(wait);
  status("Analyzing in separate microVMs…");
  try {
    const report = await invoke("analyze");
    renderReport(body, report, `${report.document} · analyzed in ${report.seconds.toFixed(1)}s`);
    status(`Analysis: ${report.verdict}`);
  } catch (e) {
    body.replaceChildren(el("p", "note", `Analysis failed: ${e}`));
    status(`Analysis failed: ${e}`, true);
  } finally {
    btn.disabled = false;
  }
}

// ---------------------------------------------------------------- wiring

$("open").onclick = openDialog;
$("zin").onclick = () => stepZoom(1);
$("zout").onclick = () => stepZoom(-1);
$("zfit").onclick = fitWidth;
$("textbtn").onclick = showText;
$("analyze").onclick = analyze;
$("panel-close").onclick = closePanel;
$("qnext").onclick = () => stepHit(1);
$("qprev").onclick = () => stepHit(-1);
$("banner-more").onclick = () => state.findings && renderReport(openPanel("Blocked while viewing"), state.findings);

let searchTimer = null;
$("q").addEventListener("input", () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(runSearch, 300);
});
$("q").addEventListener("keydown", (e) => {
  if (e.key === "Enter") { e.preventDefault(); stepHit(e.shiftKey ? -1 : 1); }
  if (e.key === "Escape") { $("q").value = ""; runSearch(); $("q").blur(); }
});

document.addEventListener("keydown", (e) => {
  const mod = e.ctrlKey || e.metaKey;
  if (mod && e.key.toLowerCase() === "o") { e.preventDefault(); openDialog(); return; }
  if (!state.docOpen) return;
  if (mod && e.key.toLowerCase() === "f") { e.preventDefault(); $("q").focus(); $("q").select(); return; }
  if (e.target.tagName === "INPUT") return;
  if (e.key === "+" || e.key === "=") stepZoom(1);
  else if (e.key === "-") stepZoom(-1);
  else if (e.key === "Escape") closePanel();
});

let resizeTimer = null;
window.addEventListener("resize", () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => state.docOpen && (state.fitMode ? fitWidth() : layout()), 150);
});

// Drag & drop: Tauri hands us the *path*; the bytes are read by Rust only.
window.__TAURI__.webview.getCurrentWebview().onDragDropEvent((event) => {
  const t = event.payload.type;
  $("viewer").classList.toggle("drop", t === "over" || t === "enter");
  if (t === "drop" && event.payload.paths.length) openPath(event.payload.paths[0]);
});

async function runDemo() {
  const script = await invoke("demo_script");
  if (!script) return;
  for (const step of script.split(";")) {
    const [cmd, arg] = step.split("=");
    if (cmd === "search") { $("q").value = arg; await runSearch(); }
    if (cmd === "text") await showText();
    if (cmd === "analyze") await analyze();
  }
}

invoke("initial_path").then(async (p) => {
  if (!p) return;
  await openWith(invoke("open_path", { path: p }), p.split(/[\\/]/).pop());
  runDemo();
});
