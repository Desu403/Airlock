// Reads a PDF's real structure (MuPDF's object graph, not a byte search):
// every action, what triggers it and whether it runs by itself, embedded
// files, and the risky container features. Runs inside the VM, as nobody,
// under the monitor: mutool run pdf_walk.js <pdf>.
//
// Output, one line each (strings as hex of their raw bytes):
//   @@JS   <trigger> <1=automatic|0=on user action> <hex code>
//   @@ACT  <trigger> <1|0> <action type> <hex detail>   (every other action)
//   @@EMB  <hex name> <size> <hex first 64 bytes>        (embedded file)
//   @@FEAT <XFA|RichMedia|Media|Encrypt|Password>
//   @@DONE                                              (walk completed)
var MAX_ACTIONS = 256, MAX_PAGES = 500, MAX_ANNOTS = 4000, MAX_FIELDS = 4000, MAX_EMB = 64;
var doc = Document.openDocument(scriptArgs[0]);
var seen = {}, emitted = 0, annots = 0, fields = 0, embs = 0, embSeen = {};

function has(o) { return o !== null && o !== undefined && !o.isNull(); }

function hexBytes(b, n) {
    var s = "", i;
    n = Math.min(b.length, n);
    for (i = 0; i < n; i++) s += ((b.readByte ? b.readByte(i) : b[i]) & 0xff | 0x100).toString(16).slice(1);
    return s;
}

// Raw bytes of a string or stream, as hex. Streams must be tested on the
// unresolved reference (resolving yields only the stream's dictionary).
function hex(o) {
    if (!has(o)) return "";
    if (o.isStream()) return hexBytes(o.readStream(), 1 << 20);
    var r = o.resolve();
    if (r.isString()) return hexBytes(r.asByteString(), 1 << 20);
    if (r.isName()) return hexBytes(Array.prototype.map.call(r.asName(), function (c) { return c.charCodeAt(0) & 0xff; }), 256);
    return "";
}

// A file specification: a string, or a dictionary with /UF, /F (or /Win /F).
function fileName(o) {
    if (!has(o)) return "";
    var r = o.resolve();
    if (r.isString()) return hex(r);
    if (!r.isDictionary()) return "";
    var keys = ["UF", "F", "DOS", "Unix"];
    for (var i = 0; i < keys.length; i++) if (has(r.get(keys[i]))) return hex(r.get(keys[i]));
    return "";
}

function detail(a, type) {
    switch (type) {
        case "URI": return hex(a.get("URI"));
        case "Named": return hex(a.get("N"));
        case "Launch":
            if (has(a.get("F"))) return fileName(a.get("F"));
            var w = a.get("Win");
            if (has(w) && w.resolve().isDictionary()) {
                var f = hex(w.resolve().get("F")), p = hex(w.resolve().get("P"));
                return p ? f + "20" + p : f;
            }
            return "";
        case "GoToR": case "GoToE": case "SubmitForm": case "ImportData":
            return fileName(a.get("F"));
        default: return "";
    }
}

// An action dictionary (or array of them), following /Next chains.
function action(o, trigger, auto, depth) {
    if (!has(o) || depth > 32 || emitted >= MAX_ACTIONS) return;
    if (o.isIndirect()) {
        var num = o.asIndirect();
        if (seen[num]) return;
        seen[num] = true;
    }
    var a = o.resolve();
    if (a.isArray()) {
        // An /OpenAction may be a plain destination: "open at this page".
        if (depth === 0 && a.length > 0 && !a.get(0).resolve().isDictionary()) {
            print("@@ACT\t" + trigger + "\t" + (auto ? 1 : 0) + "\tGoTo\t");
            emitted++;
            return;
        }
        for (var i = 0; i < a.length && i < 64; i++) action(a.get(i), trigger, auto, depth + 1);
        return;
    }
    if (!a.isDictionary()) return;
    var s = a.get("S");
    if (has(s) && s.isName()) {
        var type = s.asName();
        if (type === "JavaScript") {
            var code = hex(a.get("JS"));
            if (code.length) {
                print("@@JS\t" + trigger + "\t" + (auto ? 1 : 0) + "\t" + code);
                emitted++;
            }
        } else {
            print("@@ACT\t" + trigger + "\t" + (auto ? 1 : 0) + "\t" + type.replace(/[^A-Za-z0-9]/g, "").slice(0, 32) + "\t" + detail(a, type));
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

// Embedded file from a file specification: name, size, first bytes.
function embedded(fs) {
    if (!has(fs) || embs >= MAX_EMB) return;
    var f = fs.resolve();
    if (!f.isDictionary()) return;
    var ef = f.get("EF");
    if (!has(ef) || !ef.resolve().isDictionary()) return;
    var st = ef.resolve().get("F");
    if (!has(st)) st = ef.resolve().get("UF");
    if (!has(st) || !st.isStream()) return;
    if (st.isIndirect()) {
        if (embSeen[st.asIndirect()]) return;
        embSeen[st.asIndirect()] = true;
    }
    var data = st.readStream();
    print("@@EMB\t" + fileName(f) + "\t" + data.length + "\t" + hexBytes(data, 64));
    embs++;
}

function nameTree(node, depth, each) {
    if (!has(node) || depth > 16) return;
    var n = node.resolve();
    if (!n.isDictionary()) return;
    var names = n.get("Names");
    if (has(names) && names.resolve().isArray()) {
        names = names.resolve();
        for (var i = 1; i < names.length && i < 2048; i += 2) each(names.get(i));
    }
    var kids = n.get("Kids");
    if (has(kids) && kids.resolve().isArray()) {
        kids = kids.resolve();
        for (var j = 0; j < kids.length && j < 256; j++) nameTree(kids.get(j), depth + 1, each);
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

var trailer = doc.needsPassword() ? null : doc.getTrailer();
if (!trailer) print("@@FEAT\tPassword");
else walk();
print("@@DONE");

function walk() {
    if (has(trailer.get("Encrypt"))) print("@@FEAT\tEncrypt");
    var root = trailer.get("Root");
    if (has(root)) {
        root = root.resolve();
        action(root.get("OpenAction"), "document opened (/OpenAction)", true, 0);
        var names = root.get("Names");
        if (has(names)) {
            nameTree(names.resolve().get("JavaScript"), 0, function (v) { action(v, "document-level script (runs on open)", true, 0); });
            nameTree(names.resolve().get("EmbeddedFiles"), 0, embedded);
        }
        aa(root.get("AA"), DOC_EVENTS, "document");
        var pages = Math.min(doc.countPages(), MAX_PAGES);
        var richMedia = false, media = false;
        for (var p = 0; p < pages && emitted < MAX_ACTIONS; p++) {
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
                var sub = ad.get("Subtype");
                if (has(sub) && sub.isName()) {
                    if (sub.asName() === "FileAttachment") embedded(ad.get("FS"));
                    if (sub.asName() === "RichMedia") richMedia = true;
                    if (sub.asName() === "Screen" || sub.asName() === "Movie" || sub.asName() === "Sound") media = true;
                }
                action(ad.get("A"), "link or button clicked (page " + (p + 1) + ")", false, 0);
                aa(ad.get("AA"), ANNOT_EVENTS, "page " + (p + 1) + " annotation");
            }
        }
        if (richMedia) print("@@FEAT\tRichMedia");
        if (media) print("@@FEAT\tMedia");
        var form = root.get("AcroForm");
        if (has(form)) {
            form = form.resolve();
            if (has(form.get("XFA"))) print("@@FEAT\tXFA");
            var fl = form.get("Fields");
            if (has(fl) && fl.resolve().isArray()) {
                fl = fl.resolve();
                for (var k = 0; k < fl.length; k++) field(fl.get(k), 0);
            }
        }
    }
}
