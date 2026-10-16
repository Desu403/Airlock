// airlock: fake Adobe Reader JavaScript environment.
// Runs inside the disposable VM under QuickJS as `nobody`, with the seccomp
// monitor watching and no network. It pretends to be an old, exploitable
// Reader so that malware takes its "attack" branch, and records everything.
// Output lines: "@@AIRLOCK <KIND> <category> <text>".

(function (G) {
  delete G.std; delete G.os; delete G.scriptArgs;
  var out = 0;
  function clean(t) {
    return String(t).replace(/[\r\n\t]+/g, " ").replace(/[^\x20-\x7e]/g, "?").slice(0, 200);
  }
  function emit(kind, cat, text) {
    if (out++ > 150) return;
    print("@@AIRLOCK " + kind + " " + cat + " " + clean(text));
  }
  function s(a) {
    try {
      if (typeof a === "function") return "<function>";
      if (typeof a === "object" && a !== null) return JSON.stringify(a).slice(0, 160);
      return String(a).slice(0, 160);
    } catch (e) { return "?"; }
  }
  function args(a) { return Array.prototype.map.call(a, s).join(", "); }
  function len(a) { var m = 0; for (var i = 0; i < a.length; i++) if (typeof a[i] === "string") m = Math.max(m, a[i].length); return m; }

  // ---- deobfuscation hooks -------------------------------------------------
  var realEval = G.eval, realFunction = G.Function, realUnescape = G.unescape;
  var layers = 0;
  function runCode(code, self, label) {
    try { return realFunction(String(code)).call(self); }
    catch (e) { emit("ERROR", "runtime", label + ": " + e); }
  }
  G.eval = function (code) {
    if (typeof code === "string" && layers++ < 20) emit("EVAL", "layer", code);
    return realEval(code);
  };
  G.Function = function () {
    var body = arguments[arguments.length - 1];
    if (typeof body === "string" && layers++ < 20) emit("EVAL", "layer", body);
    return realFunction.apply(null, arguments);
  };
  G.unescape = function (x) {
    var r = realUnescape(x);
    var units = typeof x === "string" ? (x.match(/%u[0-9a-f]{4}/gi) || []).length : 0;
    if (units >= 8)
      emit("EXPLOIT", "shellcode", "unescape() decodes " + units + " %u units into raw machine-code bytes (shellcode pattern)");
    return r;
  };
  var bigWarned = false;
  var realRepeat = String.prototype.repeat;
  function watchSize(str) {
    if (!bigWarned && str.length > 1000000) { bigWarned = true; emit("EXPLOIT", "heapspray", "builds strings over 1 MB (heap spray pattern)"); }
    return str;
  }
  String.prototype.repeat = function (n) { return watchSize(realRepeat.call(this, n)); };
  var realSubstr = String.prototype.substring;
  String.prototype.substring = function (a, b) { return watchSize(realSubstr.call(this, a, b)); };

  // ---- fake reader objects ---------------------------------------------------
  function stub(path, cat, check) {
    return function () {
      emit("CALL", cat, path + "(" + args(arguments) + ")");
      if (check) check(arguments);
      return undefined;
    };
  }
  function cve(id, why) { emit("EXPLOIT", "cve", id + " - " + why); }

  var doc = {
    numPages: 1, external: false, title: "invoice", documentFileName: "invoice.pdf",
    path: "/C/Users/user/Documents/invoice.pdf", URL: "file:///C:/Users/user/Documents/invoice.pdf",
    info: { Title: "", Author: "", Subject: "", Keywords: "", Creator: "", Producer: "" },
    dataObjects: [],
    submitForm: stub("doc.submitForm", "net", function (a) {}),
    getURL: stub("doc.getURL", "net"),
    launchURL: stub("doc.launchURL", "net"),
    mailDoc: stub("doc.mailDoc", "net"),
    mailForm: stub("doc.mailForm", "net"),
    exportDataObject: function (o) {
      emit("CALL", "drop", "doc.exportDataObject(" + s(o) + ")");
      if (o && (o.nLaunch === 1 || o.nLaunch === 2)) emit("CALL", "launch", "exportDataObject with nLaunch=" + o.nLaunch + ": saves AND opens the embedded file");
    },
    importDataObject: stub("doc.importDataObject", "drop"),
    createDataObject: stub("doc.createDataObject", "drop"),
    saveAs: stub("doc.saveAs", "drop"),
    print: stub("doc.print", "ui"),
    closeDoc: stub("doc.closeDoc", "ui"),
    addScript: stub("doc.addScript", "persist"),
    setAction: stub("doc.setAction", "persist"),
    setPageAction: stub("doc.setPageAction", "persist"),
    getField: function (n) {
      emit("CALL", "info", "doc.getField(" + s(n) + ")");
      return { name: n, value: "", display: 0, setAction: stub("field.setAction", "persist"), buttonImportIcon: stub("field.buttonImportIcon", "drop") };
    },
    getAnnots: function () {
      emit("CALL", "info", "doc.getAnnots(" + args(arguments) + ")");
      for (var i = 0; i < arguments.length; i++) if (typeof arguments[i] === "number" && arguments[i] < 0) cve("CVE-2009-1492", "getAnnots() with negative arguments");
      return doc.__annots.length ? doc.__annots : null;
    },
    getAnnot: function () { return doc.__annots[0] || null; },
    syncAnnotScan: stub("doc.syncAnnotScan", "info"),
    getPageNthWord: function () { return ""; },
    getPageNumWords: function () { return 0; },
    getOCGs: function () { return []; },
    __annots: []
  };
  var app = {
    viewerVersion: 9.0, viewerType: "Reader", viewerVariation: "Reader", platform: "WIN", language: "ENU",
    formsVersion: 9.0, plugIns: [], doc: doc,
    alert: stub("app.alert", "ui"),
    beep: stub("app.beep", "ui"),
    response: function () { emit("CALL", "ui", "app.response(" + args(arguments) + ")"); return ""; },
    launchURL: stub("app.launchURL", "net"),
    openDoc: stub("app.openDoc", "launch"),
    newDoc: stub("app.newDoc", "drop"),
    mailMsg: stub("app.mailMsg", "net"),
    execMenuItem: stub("app.execMenuItem", "ui"),
    addMenuItem: stub("app.addMenuItem", "persist"),
    addToolButton: stub("app.addToolButton", "persist"),
    trustedFunction: function (f) { emit("CALL", "priv", "app.trustedFunction(...)"); return f; },
    beginPriv: stub("app.beginPriv", "priv"),
    endPriv: stub("app.endPriv", "priv"),
    setTimeOut: function (code, ms) { emit("CALL", "timer", "app.setTimeOut(" + s(code) + ", " + ms + ")"); runCode(code, doc, "setTimeOut"); return {}; },
    setInterval: function (code, ms) { emit("CALL", "timer", "app.setInterval(" + s(code) + ", " + ms + ")"); runCode(code, doc, "setInterval"); return {}; },
    clearTimeOut: function () {}, clearInterval: function () {}
  };
  var util = {
    printf: function (fmt) {
      emit("CALL", "info", "util.printf(" + args(arguments) + ")");
      if (/%\d{3,}/.test(String(fmt))) cve("CVE-2008-2992", "util.printf() with a huge format width (stack overflow exploit)");
      return "";
    },
    printd: function () { return ""; }, printx: function () { return ""; }, scand: function () { return null; },
    byteToChar: function (n) { return String.fromCharCode(n); },
    stringFromStream: function () { return ""; },
    streamFromString: function () { return {}; }
  };
  var Collab = {
    collectEmailInfo: function (o) {
      emit("CALL", "info", "Collab.collectEmailInfo(" + s(o) + ")");
      if (len([o && o.msg]) > 1000 || s(o).length >= 160) cve("CVE-2007-5659", "Collab.collectEmailInfo() with an oversized message");
    },
    getIcon: function (n) {
      emit("CALL", "info", "Collab.getIcon(" + s(n) + ")");
      if (String(n).length > 1000) cve("CVE-2009-0927", "Collab.getIcon() with an oversized name");
      return null;
    }
  };
  var media = { newPlayer: function (a) { emit("CALL", "info", "media.newPlayer(" + s(a) + ")"); if (a === null || a === undefined) cve("CVE-2009-4324", "media.newPlayer(null) use-after-free"); return null; } };
  var spell = { customDictionaryOpen: function () { emit("CALL", "info", "spell.customDictionaryOpen(" + args(arguments) + ")"); if (len(arguments) > 1000) cve("CVE-2009-1493", "spell.customDictionaryOpen() overflow"); } };
  var SOAP = { connect: stub("SOAP.connect", "net"), request: stub("SOAP.request", "net"), stream: function () { return {}; } };
  var Net = { HTTP: { request: stub("Net.HTTP.request", "net") }, SOAP: SOAP };
  var console_ = { println: stub("console.println", "ui"), show: function () {}, clear: function () {} };

  G.app = app; G.util = util; G.Collab = Collab; G.media = media; G.spell = spell; G.SOAP = SOAP; G.Net = Net;
  G.console = console_; G.event = { target: doc, name: "Open", type: "Doc", value: "", rc: true };
  G.global = {}; G.identity = { name: "", loginName: "user", email: "" }; G.security = {}; G.color = {};
  G.display = { visible: 0, hidden: 1, noPrint: 2, noView: 3 };
  // Acrobat resolves bare doc methods at top level (getAnnots(), getURL()...).
  for (var k in doc) if (typeof doc[k] === "function" && !(k in G)) G[k] = doc[k].bind(doc);
  for (var k2 in { info: 1, numPages: 1, URL: 1, documentFileName: 1, path: 1, dataObjects: 1 }) G[k2] = doc[k2];

  G.__airlockSetup = function (info, annots) {
    for (var k in info) doc.info[k] = info[k];
    G.info = doc.info;
    doc.__annots = annots.map(function (a) { return { subject: a.subject, contents: a.contents, type: "Text", name: "", author: "", page: 0 }; });
  };
  G.__airlockRun = function (label, code) {
    emit("RUN", "script", label);
    runCode(code, doc, label);
  };
})(globalThis);
