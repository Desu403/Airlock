"use strict";
// airlock UI. Everything shown here comes from the Rust side: PNG pixels,
// numbers, and sanitised text — always inserted with textContent, never HTML.

const { invoke } = window.__TAURI__.core;
const $ = (id) => document.getElementById(id);

const PT_TO_PX = 96 / 72;
const ZOOMS = [0.5, 0.67, 0.75, 0.9, 1, 1.1, 1.25, 1.5, 1.75, 2, 2.5, 3];

const state = {
  pages: [],          // [{w, h, el, img, text, layer, key, url, textState}]
  zoom: 1,
  fitMode: true,      // keep fitting the width on resize / panel toggle
  hits: [],
  hitIndex: -1,
  queue: [],
  rendering: false,
  docOpen: false,
  observer: null,
  findings: null,
  pixelsOnly: false,  // no document text leaves the VM (enforced in Rust too)
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
    const r = await promise;
    // Older call sites return the info itself; open_many returns {info, elsewhere}.
    const info = r && "elsewhere" in r ? r.info : r;
    const more = r && r.elsewhere ? ` · ${r.elsewhere} more in new window${r.elsewhere > 1 ? "s" : ""} (one VM each)` : "";
    if (!info) { status(more ? more.slice(3) : "Ready"); return; }
    setupDocument(info);
    const secs = ((performance.now() - t0) / 1000).toFixed(1);
    status(`${info.pages.length} page(s) · VM ready in ${(info.ready_ms / 1000).toFixed(1)}s · opened in ${secs}s${more}`);
  } catch (e) {
    resetDocument();
    status(`Could not open: ${e}`, true);
    // The file was read but cannot be shown: it can still be analyzed.
    const name = await invoke("chosen_name").catch(() => null);
    if (name) showUndisplayable(name, String(e));
  } finally {
    busy(null);
  }
}

// Back to the empty state (the previous document's VM is already gone).
function resetDocument() {
  for (const p of state.pages) if (p.url) URL.revokeObjectURL(p.url);
  if (state.observer) state.observer.disconnect();
  Object.assign(state, { pages: [], hits: [], hitIndex: -1, queue: [], findings: null, docOpen: false });
  $("pages").replaceChildren();
  for (const id of ["doc", "searchbox", "zoombox", "textbtn", "savewrap", "pixels", "analyze", "banner"]) $(id).hidden = true;
  $("empty").hidden = false;
  closePanel();
}

function showUndisplayable(name, why) {
  const body = openPanel("Cannot display");
  const go = el("button", "primary", "Analyze anyway");
  go.onclick = () => analyze(name);
  body.replaceChildren(
    el("p", "", `${name}: ${why}.`),
    el("p", "note", "Analysis does not need anything visible: it detonates the file in a separate microVM wired to a fake internet and inspects its macros and structure."),
    go,
  );
}

function openDialog() {
  openWith(invoke("pick_and_open"), "the document");
}

function openPaths(paths) {
  const name = state.docOpen ? "the documents" : paths[0].split(/[\\/]/).pop();
  openWith(invoke("open_paths", { paths }), name);
}

// ---------------------------------------------------------------- saving

function toggleSaveMenu(open) {
  const m = $("savemenu");
  m.hidden = open === undefined ? !m.hidden : !open;
  $("savebtn").setAttribute("aria-expanded", String(!m.hidden));
}

async function saveSafeCopy() {
  if (!state.docOpen) return;
  toggleSaveMenu(false);
  const stop = await window.__TAURI__.event.listen("export-progress", (e) => {
    const [i, n] = e.payload;
    status(`Saving safe copy: page ${i} of ${n}…`);
  });
  try {
    const path = await invoke("save_safe_copy");
    status(path ? `Saved a safe copy (pixels only) to ${path}` : "Ready");
  } catch (e) {
    status(`Could not save: ${e}`, true);
  } finally {
    stop();
  }
}

// Prints the pixels: every page is drawn once more at print resolution.
async function printDocument() {
  if (!state.docOpen) return;
  toggleSaveMenu(false);
  const out = $("printout");
  const urls = [];
  try {
    for (let i = 0; i < state.pages.length; i++) {
      status(`Preparing to print: page ${i + 1} of ${state.pages.length}…`);
      const buf = await invoke("render_page", { page: i, dpi: 150 });
      const url = URL.createObjectURL(new Blob([buf], { type: "image/png" }));
      urls.push(url);
      const img = el("img");
      img.src = url;
      out.append(img);
    }
    await Promise.all([...out.querySelectorAll("img")].map((img) => img.decode().catch(() => {})));
    window.print();
    status("Ready");
  } catch (e) {
    status(`Could not print: ${e}`, true);
  } finally {
    // print() returns once the dialog is done with the pages.
    setTimeout(() => { out.replaceChildren(); urls.forEach((u) => URL.revokeObjectURL(u)); }, 1000);
  }
}

async function saveReport() {
  try {
    const path = await invoke("save_report");
    if (path) status(`Saved the report to ${path}`);
  } catch (e) {
    status(`Could not save the report: ${e}`, true);
  }
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
  for (const id of ["doc", "searchbox", "zoombox", "savewrap", "pixels", "analyze"]) $(id).hidden = false;
  $("textbtn").hidden = state.pixelsOnly;
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
    const text = el("div", "text");
    const layer = el("div", "layer");
    pageEl.append(img, text, layer, el("span", "num", String(i + 1)));
    pageEl.dataset.index = String(i);
    container.append(pageEl);
    state.pages.push({ w, h, el: pageEl, img, text, layer, key: null, url: null, visible: false, textState: null });
    state.observer.observe(pageEl);
  });
  fitWidth();
  $("viewer").scrollTop = 0;
}

// ---------------------------------------------------------------- rendering

function layout() {
  const scale = state.zoom * PT_TO_PX;
  $("pages").style.setProperty("--s", String(scale));
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
      if (!p.textState && !state.pixelsOnly) await loadTextLayer(p, i);
    }
  } finally {
    state.rendering = false;
  }
  checkViewingFindings();
}

// ---------------------------------------------------------------- text layer
// Invisible text over the page image so it can be selected and copied like
// in any PDF viewer. Lines and boxes come from the VM; the text is the same
// sanitised text as the Text panel and is inserted with textContent only.

async function loadTextLayer(p, i) {
  p.textState = "loading";
  let lines;
  try {
    lines = await invoke("page_lines", { page: i });
  } catch (e) {
    p.textState = null;
    status(`Page ${i + 1} text: ${e}`, true);
    return;
  }
  const spans = [];
  for (const { rect: [x0, y0, x1, y1], text } of lines) {
    const w = x1 - x0, h = y1 - y0;
    // Vertical / rotated lines would need rotation; leave them out.
    if (!text || (h > w * 1.5 && [...text].length > 1)) continue;
    const span = el("span", "", text);
    span.style.setProperty("--x", String(x0));
    span.style.setProperty("--y", String(y0));
    span.style.setProperty("--h", String(h));
    spans.push([span, w]);
  }
  p.text.replaceChildren(...spans.flatMap(([span]) => [span, document.createElement("br")]));
  // Stretch each line to its real width (the page's fonts are not ours).
  // The ratio does not depend on zoom, so it is measured once.
  const scale = state.zoom * PT_TO_PX;
  const widths = spans.map(([span]) => span.offsetWidth);
  spans.forEach(([span, w], k) => {
    if (widths[k] > 0) span.style.transform = `scaleX(${(w * scale) / widths[k]})`;
  });
  p.textState = "ready";
}

async function setPixelsOnly(on, remember = true) {
  await invoke("set_pixels_only", { on });
  state.pixelsOnly = on;
  if (remember) try { localStorage.setItem("airlock.pixelsOnly", on ? "1" : "0"); } catch {}
  $("pixels").setAttribute("aria-pressed", String(on));
  $("textbtn").hidden = on || !state.docOpen;
  if (on) {
    getSelection()?.removeAllRanges();
    for (const p of state.pages) { p.text.replaceChildren(); p.textState = null; }
    if ($("panel-title").textContent.startsWith("Text")) closePanel();
    status("Pixels only: no document text leaves the VM");
  } else {
    for (const [i, p] of state.pages.entries()) if (p.key && !p.textState) await loadTextLayer(p, i);
    status("Text selection on");
  }
}

// Copy plain text only: the layer is transparent, so its HTML would paste
// as invisible text into rich editors.
document.addEventListener("copy", (e) => {
  const sel = getSelection();
  if (!sel || sel.isCollapsed || !$("pages").contains(sel.anchorNode)) return;
  e.clipboardData.setData("text/plain", sel.toString());
  e.preventDefault();
});

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
  signature: "Matches known malware (YARA rules)",
  static: "Static structure of the file",
};

function renderReport(body, report, title) {
  const v = report.verdict;
  const cls = v.startsWith("MALICIOUS") || v.startsWith("LIKELY") ? "malicious" : v.startsWith("SUSPICIOUS") ? "suspicious" : "clean";
  const box = el("div", `verdict ${cls}`);
  box.append(el("h3", "", v), el("p", "", report.summary));
  const nodes = [box];
  if (title) nodes.push(el("p", "note", title));
  for (const src of ["outside", "monitor", "emulated", "signature", "static"]) {
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

async function analyze(name) {
  const btn = $("analyze");
  btn.disabled = true;
  const body = openPanel(typeof name === "string" ? `Analysis · ${name}` : "Analysis");
  const wait = el("div", "row");
  wait.append(el("div", "spinner"), el("span", "note", "Detonating in a separate microVM wired to a fake internet, then examining its disk in a second VM. You can keep reading meanwhile."));
  body.replaceChildren(wait);
  status("Analyzing in separate microVMs…");
  try {
    const report = await invoke("analyze");
    renderReport(body, report, `${report.document} · analyzed in ${report.seconds.toFixed(1)}s`);
    const save = el("button", "", "Save report…");
    save.title = "Save as text (or .json for tools)";
    save.onclick = saveReport;
    body.append(save);
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
$("savebtn").onclick = (e) => { e.stopPropagation(); toggleSaveMenu(); };
$("safecopy").onclick = saveSafeCopy;
$("print").onclick = printDocument;
document.addEventListener("click", (e) => { if (!$("savewrap").contains(e.target)) toggleSaveMenu(false); });
$("pixels").onclick = () => setPixelsOnly(!state.pixelsOnly);
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
  if (mod && e.key.toLowerCase() === "s") { e.preventDefault(); saveSafeCopy(); return; }
  if (mod && e.key.toLowerCase() === "p") { e.preventDefault(); printDocument(); return; }
  if (e.target.tagName === "INPUT") return;
  if (e.key === "+" || e.key === "=") stepZoom(1);
  else if (e.key === "-") stepZoom(-1);
  else if (e.key === "Escape") { toggleSaveMenu(false); closePanel(); }
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
  if (t === "drop" && event.payload.paths.length) openPaths(event.payload.paths);
});

// ---------------------------------------------------------------- updates
// The VM's renderers, kernel and Firecracker are rebuilt from the source
// checkout by scripts/update.sh (verified downloads, regression suite,
// automatic restore on failure). Checked at most once a day.

const updates = { status: null, running: false, log: [], restart: false };

function pref(key, fallback) {
  try { return localStorage.getItem(key) ?? fallback; } catch { return fallback; }
}
function setPref(key, value) {
  try { localStorage.setItem(key, value); } catch {}
}

function describeChanges(st, max) {
  const list = st.changes.slice(0, max);
  const more = st.changes.length - list.length + Math.max(0, st.packages - st.changes.filter((c) => !/^(Guest kernel|Firecracker|Alpine base) /.test(c)).length);
  return { list, more };
}

function noteStatus(st) {
  updates.status = st;
  $("updates-dot").hidden = !(st && st.available);
}

async function checkUpdates(force) {
  const st = await invoke("update_status", { force });
  noteStatus(st);
  return st;
}

// A small notice in the corner: title, text, [label, action] buttons.
function notify(title, text, actions) {
  $("toast-title").textContent = title;
  $("toast-text").textContent = text;
  $("toast-actions").replaceChildren(...actions.map(([label, fn], i) => {
    const b = el("button", i === 0 && actions.length > 1 ? "primary" : "", label);
    b.onclick = fn;
    return b;
  }));
  $("toast").hidden = false;
}

function changeSummary(st) {
  const { list, more } = describeChanges(st, 2);
  return list.join(", ") + (more > 0 ? ` and ${more} more` : "");
}

function showToast(st) {
  notify("Security updates for airlock", `${changeSummary(st)}. Installing them takes about two minutes; you can keep reading.`, [
    ["Update now", () => runUpdate()],
    ["Details", showUpdates],
    ["Later", () => { hideToast(); setPref("airlock.updateSnooze", String(Date.now() + 86_400_000)); }],
  ]);
}

function hideToast() { $("toast").hidden = true; }

function renderUpdates(body) {
  const st = updates.status;
  const nodes = [];
  if (!st || !st.supported) {
    nodes.push(el("p", "", "This copy of airlock has no update kit."),
      el("p", "note", "Install it with scripts/install.sh (which adds the kit), or set AIRLOCK_SOURCE to an airlock source folder."));
    body.replaceChildren(...nodes);
    return;
  }
  if (st.error) nodes.push(el("p", "note", `Last check failed: ${st.error}`));
  else if (st.available) {
    nodes.push(el("p", "", "Security updates are available:"));
    const ul = el("ul", "changes");
    for (const c of st.changes) ul.append(el("li", "", c));
    if (st.packages > st.changes.length) ul.append(el("li", "", `… ${st.packages} packages in total`));
    nodes.push(ul);
  } else nodes.push(el("p", "", "Everything is up to date."));
  const when = st.checked ? new Date(st.checked * 1000).toLocaleString() : "never";
  nodes.push(el("p", "note", `Last checked: ${when} · VM image built ${st.image_age_days} day(s) ago.`));

  const row = el("div", "row");
  const check = el("button", "", "Check now");
  const go = el("button", "primary", updates.running ? "Updating…" : "Update now");
  go.disabled = updates.running;
  check.disabled = updates.running;
  check.onclick = async () => {
    check.disabled = true; check.textContent = "Checking…";
    try { await checkUpdates(true); } catch (e) { status(`Update check failed: ${e}`, true); }
    renderUpdates(body);
  };
  go.onclick = () => runUpdate(body);
  row.append(go, check);
  nodes.push(row, el("p", "note", "Downloads are verified (kernel.org signatures, published checksums). The full test suite must pass before the new version is used; otherwise the current one stays."));

  const toggle = (key, text, onChange) => {
    const label = el("label", "check");
    const box = el("input");
    box.type = "checkbox";
    box.checked = pref(key, "1") === "1";
    box.onchange = () => { setPref(key, box.checked ? "1" : "0"); onChange?.(box.checked); };
    label.append(box, document.createTextNode(text));
    return [label, box];
  };
  const [checkLabel] = toggle("airlock.autoUpdateCheck", "Check for updates automatically (once a day: kernel.org, GitHub, Alpine)", () => renderUpdates(body));
  const [installLabel, installBox] = toggle("airlock.autoInstall", "Install security updates automatically (in the background; you are told afterwards)");
  installBox.disabled = pref("airlock.autoUpdateCheck", "1") !== "1";
  nodes.push(checkLabel, installLabel);

  if (updates.log.length) {
    const ul = el("ul", "progress");
    for (const l of updates.log) ul.append(el("li", "", l));
    nodes.push(ul);
  }
  if (updates.restart) {
    const r = el("button", "primary", "Restart airlock");
    r.onclick = () => invoke("restart_app");
    nodes.push(el("p", "", "airlock itself was updated too. Documents opened from now on already use the new VM; restart to use the new app."), r);
  }
  body.replaceChildren(...nodes);
}

function showUpdates() {
  hideToast();
  renderUpdates(openPanel("Updates"));
}

// quiet: started automatically — no panel, a notice when done.
async function runUpdate(body, quiet = false) {
  if (updates.running) return;
  hideToast();
  if (!updates.status) await checkUpdates(false).catch(() => {});
  updates.running = true;
  updates.restart = false;
  updates.log = ["Starting…"];
  if (!quiet) {
    if (!body || $("panel-title").textContent !== "Updates") body = openPanel("Updates");
    renderUpdates(body);
  }
  status("Updating airlock's VM in the background…");
  let ok = false;
  try {
    const r = await invoke("run_update");
    // The script's summary minus its command-line hints.
    for (const l of r.lines) {
      const t = l.trim();
      if (t && !t.startsWith("==>") && !t.startsWith("undo:")) updates.log.push(t);
    }
    updates.log.push(r.ok ? "Done — all checks passed." : "The update failed its checks; the previous version is still in place.");
    updates.restart = r.ok && r.restart;
    ok = r.ok;
    status(r.ok ? "airlock updated" : "Update failed — nothing was changed", !r.ok);
    try { await checkUpdates(true); } catch {}
  } catch (e) {
    updates.log.push(`Update failed: ${e}`);
    status(`Update failed: ${e}`, true);
  } finally {
    updates.running = false;
    if ($("panel-title").textContent === "Updates" && !$("panel").hidden) renderUpdates($("panel-body"));
  }
  if (quiet) {
    if (ok) notify("airlock was updated", "Security updates were installed and all checks passed. Documents you open now use the updated VM.", [
      ...(updates.restart ? [["Restart airlock", () => invoke("restart_app")]] : []),
      ["Details", showUpdates], ["OK", hideToast]]);
    else notify("Automatic update failed", "Nothing was changed: airlock keeps using the current version. Details are in the Updates panel.", [["Details", showUpdates], ["OK", hideToast]]);
  }
}

window.__TAURI__.event.listen("update-progress", (e) => {
  const line = String(e.payload);
  // Steps only ("==> Rebuilding…"); the full log is in build/update.log.
  if (!line.startsWith("==>")) return;
  updates.log.push(line.slice(4));
  if ($("panel-title").textContent === "Updates" && !$("panel").hidden) renderUpdates($("panel-body"));
});

$("updates").onclick = showUpdates;

async function autoCheckUpdates() {
  if (pref("airlock.autoUpdateCheck", "1") !== "1") return;
  try {
    const st = await checkUpdates(false);
    if (!st.available) return;
    if (pref("airlock.autoInstall", "1") === "1") {
      notify("Installing security updates", `${changeSummary(st)}. airlock is updating in the background; you can keep reading.`, [["Details", showUpdates], ["Hide", hideToast]]);
      runUpdate(null, true);
    } else if (Date.now() > Number(pref("airlock.updateSnooze", "0"))) showToast(st);
  } catch {}
}
setTimeout(autoCheckUpdates, 3000);

async function runDemo() {
  const script = await invoke("demo_script");
  if (!script) return;
  for (const step of script.split(";")) {
    const [cmd, arg] = step.split("=");
    if (cmd === "search") { $("q").value = arg; await runSearch(); }
    if (cmd === "text") await showText();
    if (cmd === "reveal") {
      // Paint the invisible text layer red to check its alignment.
      await new Promise((r) => setTimeout(r, 1500));
      for (const span of document.querySelectorAll(".page .text span")) span.style.color = "rgba(220, 0, 0, 0.75)";
    }
    if (cmd === "select") {
      // Select page 1's text layer and show what a copy would contain.
      await new Promise((r) => setTimeout(r, 1500));
      const r = document.createRange();
      r.selectNodeContents(state.pages[0].text);
      getSelection().removeAllRanges();
      getSelection().addRange(r);
      const body = openPanel("Selection (demo)");
      body.replaceChildren(el("pre", "", JSON.stringify(getSelection().toString()).slice(0, 2000)));
    }
    if (cmd === "analyze") await analyze();
    if (cmd === "savemenu") toggleSaveMenu(true);
    if (cmd === "print") await printDocument();
    if (cmd === "safecopy") await saveSafeCopy();
    if (cmd === "savereport") await saveReport();
    if (cmd === "update") await runUpdate();
    if (cmd === "restart") { await new Promise((r) => setTimeout(r, Number(arg) || 0)); await invoke("restart_app"); }
    if (cmd === "updates") { await checkUpdates(arg === "force"); showUpdates(); }
    if (cmd === "autotoast") notify("airlock was updated", "Security updates were installed and all checks passed. Documents you open now use the updated VM.", [["Restart airlock", () => {}], ["Details", showUpdates], ["OK", hideToast]]);
    if (cmd === "toast") showToast({ changes: ["mupdf-tools 1.27.2-r0 → 1.27.3-r0", "Guest kernel 6.1.190 → 6.1.191"], packages: 14 });
  }
}

// Pixels-only preference: the environment (AIRLOCK_PIXELS_ONLY) or the last choice.
const pixelsReady = invoke("pixels_only").then(async (on) => {
  let saved = null;
  try { saved = localStorage.getItem("airlock.pixelsOnly"); } catch {}
  // Only the user's own toggling is remembered, not the environment's default.
  await setPixelsOnly(on || saved === "1", false);
  status("Ready");
});

invoke("initial_path").then(async (p) => {
  await pixelsReady;
  if (!p) return;
  await openWith(invoke("open_path", { path: p }), p.split(/[\\/]/).pop());
  runDemo();
});
