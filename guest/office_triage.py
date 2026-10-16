"""airlock: static triage of Office documents (runs inside the VM, as nobody,
under the seccomp monitor, without network). Never executes macros.

Prints lines "@@AIRLOCK <KIND> <text>" for the agent to forward.
"""
import re
import sys
import zipfile

emitted = 0


def emit(kind, text):
    global emitted
    if emitted > 120:
        return
    emitted += 1
    text = re.sub(r"[\r\n\t]+", " ", str(text))
    text = re.sub(r"[^\x20-\x7e]", "?", text)[:220]
    print(f"@@AIRLOCK {kind} {text}", flush=True)


# Code-execution primitives oletools does not flag by name (MirrorBlast-style
# loaders run JScript from a cell through ScriptControl, for example).
EXEC_PRIMITIVES = [
    ("ScriptControl", "runs JScript/VBScript code from inside the macro"),
    ("ExecuteStatement", "runs script code built at run time"),
    ("AddCode", "loads script code into a script engine"),
    ("CallByName", "calls a method whose name is chosen at run time"),
    ("ExecuteExcel4Macro", "runs Excel 4.0 (XLM) code from VBA"),
    ("MacScript", "runs AppleScript"),
]


def vba(path):
    try:
        from oletools.olevba import VBA_Parser
    except Exception as e:  # pragma: no cover
        emit("ERROR", f"oletools unavailable: {e}")
        return
    try:
        vp = VBA_Parser(path)
    except Exception as e:
        emit("ERROR", f"could not parse container: {e.__class__.__name__}")
        return
    try:
        if vp.detect_vba_macros():
            sources = []
            for _f, _s, name, code in vp.extract_macros():
                sources.append((code or "").lower())
                lines = [l.strip() for l in (code or "").splitlines() if l.strip() and not l.strip().lower().startswith("attribute ")]
                if not lines:
                    continue
                emit("MACRO", f"module {name}: {len(lines)} lines | " + " ; ".join(lines[:6]))
            flagged = set()
            for kw_type, keyword, desc in vp.analyze_macros():
                t = kw_type.lower()
                if t == "autoexec":
                    emit("AUTOEXEC", f"{keyword}: {desc}")
                elif t == "suspicious":
                    flagged.add(keyword.lower())
                    emit("SUSPICIOUS", f"{keyword}: {desc}")
                elif t == "ioc":
                    emit("IOC", f"{keyword} ({desc})")
                elif t in ("hex string", "base64 string", "dridex string", "vba string"):
                    emit("OBFUSCATION", f"{kw_type}: {keyword[:80]} -> {desc[:80]}")
            for keyword, desc in EXEC_PRIMITIVES:
                if keyword.lower() not in flagged and any(keyword.lower() in src for src in sources):
                    emit("SUSPICIOUS", f"{keyword}: {desc}")
            try:
                if vp.detect_vba_stomping():
                    emit("STOMPING", "VBA source does not match the compiled p-code: the visible macro is a decoy, Office would run hidden code")
            except Exception:
                pass
        xlm = getattr(vp, "detect_xlm_macros", None)
        if xlm and xlm():
            emit("XLM", "Excel 4.0 (XLM) macros present: an old macro engine many scanners miss")
    finally:
        try:
            vp.close()
        except Exception:
            pass


EXTERNAL_KINDS = {
    "attachedTemplate": "remote template injection (Office downloads and loads a template at open)",
    "oleObject": "externally linked OLE object",
    "frame": "external frame",
    "subDocument": "external sub-document",
    "image": "external image (tracking pixel / can leak Windows credentials via SMB)",
    "hyperlink": "hyperlink",
}


def ooxml(path):
    try:
        z = zipfile.ZipFile(path)
    except Exception:
        return
    names = z.namelist()[:5000]
    ct = ""
    if "[Content_Types].xml" in names:
        ct = z.read("[Content_Types].xml")[:200000].decode("utf-8", "replace")
    if "macroEnabled" in ct or "vbaProject" in ct:
        emit("CONTAINER", "macro-enabled document format")
    for n in names:
        low = n.lower()
        if "/embeddings/" in low:
            emit("EMBEDDED", f"embedded object {n}")
        if "/activex/" in low and low.endswith(".xml"):
            emit("EMBEDDED", f"ActiveX control {n}")
    for n in names:
        if not n.endswith(".rels"):
            continue
        try:
            x = z.read(n)[:1000000].decode("utf-8", "replace")
        except Exception:
            continue
        for tag in re.findall(r"<Relationship\b[^>]*>", x):
            if 'TargetMode="External"' not in tag:
                continue
            target = (re.search(r'Target="([^"]*)"', tag) or [None, "?"])[1]
            rtype = (re.search(r'Type="([^"]*)"', tag) or [None, "?"])[1].rsplit("/", 1)[-1]
            what = EXTERNAL_KINDS.get(rtype, f"external {rtype}")
            t = target.lower()
            if "ms-msdt" in t or (rtype == "oleObject" and t.startswith("mhtml:")) or t.rstrip("/").endswith(".html!"):
                emit("EXPLOIT", f"Follina-style trigger (CVE-2022-30190): {rtype} -> {target}")
            elif rtype == "hyperlink":
                emit("LINK", target)
            else:
                emit("EXTERNAL", f"{what}: {target}")
    # DDE fields in the main document parts.
    for n in names:
        if re.match(r"(word/document|xl/externalLinks/|word/(header|footer)\d*)", n) and n.endswith(".xml"):
            x = z.read(n)[:5000000].decode("utf-8", "replace")
            for instr in re.findall(r"<w:instrText[^>]*>([^<]*)</w:instrText>", x):
                if re.search(r"\bDDE(AUTO)?\b", instr, re.I):
                    emit("EXPLOIT", f"DDE field runs a command: {instr.strip()[:160]}")


def rtf(data):
    try:
        from oletools.rtfobj import RtfObjParser
    except Exception:
        return
    p = RtfObjParser(data)
    p.parse()
    for obj in p.objects[:50]:
        cls = ""
        if getattr(obj, "is_ole", False):
            cls = (obj.class_name or b"").decode("latin-1", "replace")
        if cls.lower().startswith("equation"):
            emit("EXPLOIT", f"RTF embeds {cls} - Equation Editor exploit (CVE-2017-11882 / CVE-2018-0802)")
        elif cls == "OLE2Link":
            emit("EXPLOIT", "RTF embeds OLE2Link - remote object exploit (CVE-2017-0199)")
        elif getattr(obj, "is_package", False):
            emit("EMBEDDED", f"RTF embeds a file: {obj.filename or '?'}")
        elif cls:
            emit("EMBEDDED", f"RTF embeds OLE object {cls}")
        else:
            emit("EMBEDDED", "RTF embeds raw object data")


def main():
    path = sys.argv[1]
    with open(path, "rb") as f:
        head = f.read(8)
    if head.startswith(b"{\\rt"):
        with open(path, "rb") as f:
            rtf(f.read())
    else:
        vba(path)
        if head.startswith(b"PK"):
            ooxml(path)


if __name__ == "__main__":
    main()
