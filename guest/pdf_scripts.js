// Lists every JavaScript action in a PDF and what triggers it, so the
// emulator can tell "runs when the document opens" from "runs if the reader
// clicks a button". Runs inside the VM: mutool run pdf_scripts.js <pdf>.
// Output, one line per script: "@@JS\t<trigger>\t<1=automatic|0=on user action>\t<hex code>"
var MAX_SCRIPTS = 64, MAX_PAGES = 500, MAX_ANNOTS = 4000, MAX_FIELDS = 4000;
var doc = Document.openDocument(scriptArgs[0]);
var seen = {}, emitted = 0, annots = 0, fields = 0;

function has(o) { return o !== null && o !== undefined && !o.isNull(); }

// Raw bytes of a string or stream, as hex. Streams must be tested on the
// unresolved reference (resolving yields only the stream's dictionary).
function hex(o) {
    var s = "", i, b, n, r;
    if (o.isStream()) {
        b = o.readStream();
        n = Math.min(b.length, 1 << 20);
        for (i = 0; i < n; i++) s += (b.readByte(i) + 0x100).toString(16).slice(1);
        return s;
    }
    r = o.resolve();
    if (r.isString()) {
        b = r.asByteString();
        n = Math.min(b.length, 1 << 20);
        for (i = 0; i < n; i++) s += ((b[i] & 0xff) + 0x100).toString(16).slice(1);
    }
    return s;
}

// An action dictionary (or array of them), following /Next chains.
function action(o, trigger, auto, depth) {
    if (!has(o) || depth > 32 || emitted >= MAX_SCRIPTS) return;
    if (o.isIndirect()) {
        var num = o.asIndirect();
        if (seen[num]) return;
        seen[num] = true;
    }
    var a = o.resolve();
    if (a.isArray()) {
        for (var i = 0; i < a.length && i < 64; i++) action(a.get(i), trigger, auto, depth + 1);
        return;
    }
    if (!a.isDictionary()) return;
    var s = a.get("S");
    if (has(s) && s.isName() && s.asName() === "JavaScript" && has(a.get("JS"))) {
        var code = hex(a.get("JS"));
        if (code.length) {
            print("@@JS\t" + trigger + "\t" + (auto ? 1 : 0) + "\t" + code);
            emitted++;
        }
    }
    action(a.get("Next"), trigger, auto, depth + 1);
}

// Additional-actions dictionary: event key -> [label, runs automatically?]
function aa(dict, events, where) {
    if (!has(dict)) return;
    var d = dict.resolve();
    if (!d.isDictionary()) return;
    d.forEach(function (v, k) {
        var e = events[k];
        action(v, where + ": " + (e ? e[0] : "event " + k), e ? e[1] : false, 0);
    });
}

var DOC_EVENTS = { WC: ["before closing", true], WS: ["before saving", true], DS: ["after saving", true], WP: ["before printing", true], DP: ["after printing", true] };
var PAGE_EVENTS = { O: ["page opened", true], C: ["page closed", true] };
var ANNOT_EVENTS = {
    PO: ["page opened", true], PC: ["page closed", true], PV: ["page shown", true], PI: ["page hidden", true],
    E: ["mouse enters", false], X: ["mouse leaves", false], D: ["mouse pressed", false], U: ["mouse released (click)", false],
    Fo: ["focused", false], Bl: ["focus lost", false],
    // Form-field events (field dictionaries and widgets share /AA).
    K: ["typing in a field", false], F: ["field formatted for display", true], V: ["field value changed", false], C: ["form recalculated", false],
};

function nameTree(node, depth) {
    if (!has(node) || depth > 16) return;
    var n = node.resolve();
    if (!n.isDictionary()) return;
    var names = n.get("Names");
    if (has(names) && names.resolve().isArray()) {
        names = names.resolve();
        for (var i = 1; i < names.length && emitted < MAX_SCRIPTS; i += 2) action(names.get(i), "document-level script (runs on open)", true, 0);
    }
    var kids = n.get("Kids");
    if (has(kids) && kids.resolve().isArray()) {
        kids = kids.resolve();
        for (var j = 0; j < kids.length && j < 256; j++) nameTree(kids.get(j), depth + 1);
    }
}

function field(f, depth) {
    if (!has(f) || depth > 16 || fields++ >= MAX_FIELDS) return;
    var d = f.resolve();
    if (!d.isDictionary()) return;
    aa(d.get("AA"), ANNOT_EVENTS, "form field");
    action(d.get("A"), "form field: clicked", false, 0);
    var kids = d.get("Kids");
    if (has(kids) && kids.resolve().isArray()) {
        kids = kids.resolve();
        for (var i = 0; i < kids.length; i++) field(kids.get(i), depth + 1);
    }
}

var root = doc.getTrailer().get("Root");
if (has(root)) {
    root = root.resolve();
    action(root.get("OpenAction"), "document opened (/OpenAction)", true, 0);
    var names = root.get("Names");
    if (has(names)) nameTree(names.resolve().get("JavaScript"), 0);
    aa(root.get("AA"), DOC_EVENTS, "document");
    var pages = Math.min(doc.countPages(), MAX_PAGES);
    for (var p = 0; p < pages && emitted < MAX_SCRIPTS; p++) {
        var page = doc.findPage(p);
        aa(page.get("AA"), PAGE_EVENTS, "page " + (p + 1));
        var list = page.get("Annots");
        if (!has(list) || !list.resolve().isArray()) continue;
        list = list.resolve();
        for (var i = 0; i < list.length && annots < MAX_ANNOTS; i++, annots++) {
            var an = list.get(i);
            if (!has(an)) continue;
            var ad = an.resolve();
            if (!ad.isDictionary()) continue;
            action(ad.get("A"), "link or button clicked (page " + (p + 1) + ")", false, 0);
            aa(ad.get("AA"), ANNOT_EVENTS, "page " + (p + 1) + " annotation");
        }
    }
    var form = root.get("AcroForm");
    if (has(form)) {
        var fl = form.resolve().get("Fields");
        if (has(fl) && fl.resolve().isArray()) {
            fl = fl.resolve();
            for (var k = 0; k < fl.length; k++) field(fl.get(k), 0);
        }
    }
}
