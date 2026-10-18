"""airlock: static triage of Office documents (runs inside the VM, as nobody,
under the seccomp monitor, without network). Never executes macros.

Prints lines "@@AIRLOCK <KIND> <text>" for the agent to forward.
"""
import html
import re
import struct
import xml.etree.ElementTree as ET
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


def vba(path, data=None, where=""):
    try:
        from oletools.olevba import VBA_Parser
    except Exception as e:  # pragma: no cover
        emit("ERROR", f"oletools unavailable: {e}")
        return
    try:
        vp = VBA_Parser(path, data=data)
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
                emit("MACRO", f"module {name}{where}: {len(lines)} lines | " + " ; ".join(lines[:6]))
            flagged = set()
            for kw_type, keyword, desc in vp.analyze_macros():
                t = kw_type.lower()
                if t == "autoexec":
                    # Control events that need you to click or type are not
                    # automatic (CommandButton1_Click); _Painted, _Layout,
                    # _GotFocus and the like do fire by themselves.
                    if re.search(r"_(Click|DblClick|Change|KeyDown|KeyPress|KeyUp|MouseDown|MouseUp|MouseMove|BeforeUpdate|AfterUpdate|SpinUp|SpinDown|Scroll|DropButtonClick|BeforeDropOrPaste|BeforeDragOver)$", keyword, re.I):
                        emit("SUSPICIOUS", f"runs when you click or use a control: {keyword}")
                    else:
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


def local(name):
    """'{namespace}Relationship' or 'ns0:Relationship' -> 'Relationship'."""
    return name.rsplit("}", 1)[-1].rsplit(":", 1)[-1]


def remote_target(t):
    t = t.strip().lower()
    if t.startswith(("http:", "https:", "ftp:", "\\\\", "//")):
        return True
    if t.startswith("file:"):
        host = t[5:].lstrip("/") if t.startswith("file://") and not t.startswith("file:///") else ""
        return bool(host) and not host.startswith("localhost")
    return False


def external_rels(xml):
    """(type, target) of every external relationship, read with an XML parser:
    any namespace prefix (<ns0:Relationship>), attribute order, quoting or
    character references, as Office itself reads them."""
    out = []
    try:
        root = ET.fromstring(xml)
        for el in root.iter():
            if local(el.tag) != "Relationship":
                continue
            a = {local(k): v for k, v in el.attrib.items()}
            if a.get("TargetMode", "").strip().lower() == "external":
                out.append((a.get("Type", "?").rsplit("/", 1)[-1], a.get("Target", "?")))
        return out
    except ET.ParseError:
        pass
    # Not well-formed: a tolerant scan, so a broken file is still examined.
    for tag in re.findall(r"<(?:[\w.-]+:)?Relationship\b[^>]*>", xml):
        if not re.search(r"""TargetMode\s*=\s*["']\s*External""", tag, re.I):
            continue
        target = (re.search(r"""Target\s*=\s*["']([^"']*)""", tag) or [None, "?"])[1]
        rtype = (re.search(r"""Type\s*=\s*["']([^"']*)""", tag) or [None, "?"])[1].rsplit("/", 1)[-1]
        out.append((rtype, target))
    return out


def field_codes(xml):
    """Word field instructions as Word assembles them: a complex field's code
    is the instrText of all runs between its begin and separate/end marks
    (attackers split "DDE" over several runs), plus simple fields' w:instr.
    Any namespace prefix."""
    codes, depth, cur = [], 0, []
    tok = re.compile(r"<(?:[\w.-]+:)?(fldChar|instrText|fldSimple)\b([^>]*?)(/?)>(?:([^<]*)</(?:[\w.-]+:)?instrText>)?")
    for m in tok.finditer(xml):
        kind, attrs, text = m.group(1), m.group(2), m.group(4) or ""
        if kind == "fldChar":
            t = (re.search(r"""fldCharType\s*=\s*["'](\w+)""", attrs) or [None, ""])[1]
            if t == "begin":
                if depth == 0:
                    cur = []
                depth += 1
            elif t in ("separate", "end") and depth:
                if depth == 1 and cur:
                    codes.append("".join(cur))
                    cur = []
                if t == "end":
                    depth -= 1
        elif kind == "instrText":
            if depth == 1:
                cur.append(html.unescape(text))
            elif depth == 0:
                codes.append(html.unescape(text))
        else:
            v = re.search(r"""instr\s*=\s*(["'])(.*?)\1""", attrs, re.S)
            if v:
                codes.append(html.unescape(v.group(2)))
    if cur:
        codes.append("".join(cur))
    return codes


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
        if "/embeddings/" in low or ("/activex/" in low and low.endswith(".bin")):
            try:
                with z.open(n) as f:
                    head = f.read(8)
                if head == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" and z.getinfo(n).file_size <= 64 << 20:
                    ole_objects(z.read(n), f" in {n}")
            except Exception:
                pass
        if "/embeddings/" in low:
            emit("EMBEDDED", f"embedded object {n}")
        # Parts Word renders as part of the document (altChunk), by content.
        try:
            if z.getinfo(n).file_size <= 64 << 20:
                with z.open(n) as f:
                    if f.read(4) == b"{\\rt":
                        rtf(z.read(n), f" (inside the document as {n})")
        except Exception:
            pass
        if "/activex/" in low and low.endswith(".xml"):
            emit("EMBEDDED", f"ActiveX control {n}")
    for n in names:
        if not n.endswith(".rels"):
            continue
        try:
            x = z.read(n)[:1000000].decode("utf-8", "replace")
        except Exception:
            continue
        for rtype, target in external_rels(x):
            # Word records every attached template as "external", including
            # local ones (C:\\...\\x.dotx, Normal.dotm): only network ones load from outside.
            if rtype == "attachedTemplate" and not remote_target(target):
                continue
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
            for instr in field_codes(x):
                if re.match(r"\s*DDE(AUTO)?\b", instr, re.I):
                    emit("EXPLOIT", f"DDE field runs a command: {instr.strip()[:160]}")


# Embedded OLE objects, identified by class id (not by name, which is free text).
EQUATION_CLSIDS = {"0002CE02-0000-0000-C000-000000000046", "0002CE03-0000-0000-C000-000000000046"}
URL_MONIKER = bytes.fromhex("e0c9ea79f9bace118c8200aa004ba90b")
# Web browser controls embedded as objects: Office renders a web page (and
# whatever it launches) inside the document. CVE-2026-21509 (2026) uses one
# to load a ClickOnce ".application" that Windows runs as a program.
BROWSER_CLSIDS = {
    "EAB22AC3-30C1-11CF-A7EB-0000C05BAE0B": "Shell.Explorer.1",
    "8856F961-340A-11D0-A96B-00C04FD705A2": "Shell.Explorer.2 (WebBrowser)",
    "25336920-03F9-11CF-8FD0-00AA00686F13": "HTML document",
    "3050F4D8-98B5-11CF-BB82-00AA00BDCE0B": "HTML application",
}


def moniker_url(stream):
    """The address in a URL moniker: its class id, a 4-byte length, UTF-16 text."""
    i = stream.find(URL_MONIKER)
    if i < 0 or i + 20 > len(stream):
        return None
    n = struct.unpack_from("<I", stream, i + 16)[0]
    raw = stream[i + 20 : i + 20 + min(n, 4096)]
    return raw.decode("utf-16-le", "replace").split("\x00", 1)[0] or None


def equation_problem(st):
    """Why an Equation Native stream is an exploit, or None for a normal
    formula. [MTEF] 28-byte EQNOLEFILEHDR, then MTEF: a 5-byte header and
    records. CVE-2017-11882 / CVE-2018-0802 overflow Equation Editor's font
    name buffer: a FONT record (tag 8) whose name runs far past 32 bytes."""
    if len(st) < 28 + 5:
        return "a truncated formula header"
    cb_hdr, version = struct.unpack_from("<HI", st, 0)
    if cb_hdr != 0x1C or version not in (0x00020000, 0x00010000):
        return f"a malformed formula header (size {cb_hdr}, version {version:#x})"
    return mtef_problem(st[cb_hdr:])


def mtef_problem(mtef):
    """The formula data itself: [MTEF] header (version, platform 0/1,
    product 0/1), then records, checked for the font-name overflow."""
    if len(mtef) < 5:
        return "a truncated formula"
    # MTEF 4 and 5 are MathType's: Equation Editor 3 never parses them.
    if mtef[0] in (4, 5):
        return None
    if mtef[0] not in (2, 3):
        return f"an unknown formula format (MTEF version {mtef[0]})"
    if mtef[1] > 1 or mtef[2] > 1:
        return f"an invalid formula header (platform {mtef[1]}, product {mtef[2]})"
    # FONT records carry the font name, NUL-terminated. Look for every
    # FONT tag that is followed by a name-like run; a real name is short.
    for i in range(5, min(len(mtef), 4096)):
        if mtef[i] & 0x0F != 8 or i + 3 >= len(mtef):
            continue
        name = mtef[i + 3 : i + 3 + 256]
        end = name.find(b"\x00")
        length = end if end >= 0 else len(name)
        printable = sum(32 <= b < 127 for b in name[:length])
        if length >= 64 or (length > 32 and printable < length):
            return f"a {length}-byte font name (the buffer holds 32): the Equation Editor overflow"
        if end < 0 and len(name) == 256:
            return "a font name with no end: the Equation Editor overflow"
    return None


def ole_objects(data, where):
    """Equation Editor objects (CVE-2017-11882 / CVE-2018-0802) and linked
    objects whose source is a web address (CVE-2017-0199), in an OLE file."""
    try:
        import olefile
        ole = olefile.OleFileIO(data)
    except Exception:
        return
    try:
        streams = ole.listdir(streams=True)[:5000]
        # Every formula made before 2018 is an Equation Editor object; only
        # a malformed one is the exploit.
        eq_streams = [p for p in streams if p[-1].lower() == "equation native"]
        bad = [x for x in (equation_problem(ole.openstream(p).read(1 << 20)) for p in eq_streams) if x]
        if bad:
            emit("EXPLOIT", f"Equation Editor object{where} with {bad[0]} - exploit for CVE-2017-11882 / CVE-2018-0802")
        else:
            # Each Equation Editor storage on its own (a workbook can hold a
            # formula and, separately, an attached file): a real formula keeps
            # its data in "Equation Native"; exploit kits ship the payload in
            # an Ole10Native stream of the same object instead.
            seen, todo = 0, [ole.root]
            while todo and seen < 5000:
                e = todo.pop()
                seen += 1
                kids = [k for k in (getattr(e, "kids", None) or []) if k is not None]
                todo.extend(kids)
                browser = BROWSER_CLSIDS.get((e.clsid or "").upper())
                if browser:
                    urls = []
                    for k in kids:
                        if k.entry_type == olefile.STGTY_STREAM and k.size:
                            raw = ole._open(k.isectStart, k.size).read(1 << 20)
                            for enc in ("utf-16-le", "latin-1"):
                                urls += re.findall(r"(?i)(?:https?|file|ftp)://[\x21-\x7e]{4,300}", raw.decode(enc, "replace"))
                    emit("EXPLOIT", f"embedded web browser control ({browser}){where} that loads {urls[0][:200] if urls else 'a web page'} (CVE-2026-21509 style)")
                    continue
                if (e.clsid or "").upper() not in EQUATION_CLSIDS:
                    continue
                names = {k.name.lower(): k for k in kids}
                if "equation native" not in names and "\x01ole10native" in names:
                    # Older (OLE 1) formulas keep the same header + MTEF in an
                    # Ole10Native stream after a 4-byte size: check that instead.
                    k = names["\x01ole10native"]
                    native = ole._open(k.isectStart, k.size).read(1 << 20) if k.size else b""
                    # Ole10Native: a 4-byte size, then the formula (OLE 1
                    # objects: plain MTEF; or the full header + MTEF).
                    declared = struct.unpack_from("<I", native)[0] if len(native) >= 4 else 0
                    data = native[4:]
                    if len(native) < 9:
                        problem = "an empty formula"
                    elif declared > k.size:
                        problem = f"a declared size of {declared} bytes in a {k.size}-byte stream"
                    elif data[:2] == b"\x1c\x00":
                        problem = equation_problem(data)
                    else:
                        problem = mtef_problem(data)
                    if problem:
                        emit("EXPLOIT", f"Equation Editor object{where} with {problem} (in its Ole10Native stream) - exploit for CVE-2017-11882 / CVE-2018-0802")
                        break
        for p in ole.listdir(streams=True)[:5000]:
            if p[-1] != "\x01Ole":
                continue
            st = ole.openstream(p).read(1 << 20)
            # [MS-OLEDS] OLEStream: version, then flags; bit 0 = linked object.
            if len(st) >= 8 and struct.unpack_from("<I", st, 4)[0] & 1:
                url = moniker_url(st)
                if url and re.match(r"(?i)(https?|ftp|file)://|\\\\", url):
                    emit("EXPLOIT", f"object{where} is a link that loads {url} when opened (CVE-2017-0199 style)")
    except Exception:
        pass
    finally:
        ole.close()


def ppt_atoms(stream):
    """[MS-PPT] record tree of a PowerPoint 97-2003 stream: every atom as
    (parent containers as (type, instance), instance, type, body). Containers (version 0xF)
    are descended; lengths are checked against their container."""
    out, stack, steps = [], [(0, len(stream), ())], 0
    while stack and steps < 300000:
        off, end, parents = stack.pop()
        while off + 8 <= end and steps < 300000:
            steps += 1
            verinst, rtype, rlen = struct.unpack_from("<HHI", stream, off)
            body = off + 8
            if rlen > end - body:
                break
            if verinst & 0x0F == 0x0F:
                if len(parents) < 32:
                    stack.append((body, body + rlen, parents + ((rtype, verinst >> 4),)))
            else:
                out.append((parents, verinst >> 4, rtype, stream[body : body + rlen]))
            off = body + rlen
    return out


def ppt_storages(atoms):
    """OLE storages kept in ExOleObjStg atoms (type 0x1011; instance 1 =
    zlib-compressed after a 4-byte size): the VBA project, embedded objects."""
    import zlib
    out = []
    for _, inst, rtype, raw in atoms:
        if rtype != 0x1011 or len(out) >= 64:
            continue
        try:
            data = zlib.decompressobj().decompress(raw[4:], 64 << 20) if inst == 1 else raw
        except zlib.error:
            data = b""
        if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            out.append(data)
    return out


# Text that makes a slide action or link a command rather than a page.
COMMAND = re.compile(r"(?i)\b(cmd(\.exe)?|powershell|pwsh|rundll32|regsvr32|mshta|wscript|cscript|certutil|bitsadmin|msiexec|schtasks)\b|\.(exe|bat|cmd|ps1|vbs|vbe|js|jse|hta|scr|lnk|dll)\b|%20/[ck]\b")


def ppt_actions(atoms):
    """Slide action settings (InteractiveInfo, 0x0FF2/0x0FF3: instance 0 =
    on click, 1 = on mouse-over) and hyperlink targets (ExHyperlink 0x0FD7,
    CString 0x0FBA: instance 1 = target, 3 = location). Running a program or a command from a slide
    is the "mouse-over" technique (APT28)."""
    strings = lambda pred: [raw.decode("utf-16-le", "replace") for parents, inst, t, raw in atoms if t == 0x0FBA and pred(parents, inst)]
    targets = strings(lambda p, i: any(t == 0x0FD7 for t, _ in p) and i in (1, 3))
    for parents, inst, rtype, raw in atoms:
        if rtype != 0x0FF3 or len(raw) < 16 or not parents or parents[-1][0] != 0x0FF2:
            continue
        action, when = raw[8], "when you point at it" if parents[-1][1] == 1 else "when you click it"
        if action == 2:
            # The program is kept as a hyperlink target. Old decks used this
            # to start a video player: only a command is an attack.
            programs = strings(lambda p, i: bool(p) and p[-1][0] == 0x0FF2 and i == 2)
            prog = " | ".join(t.strip() for t in programs + targets if t.strip())[:200]
            if COMMAND.search(prog):
                emit("EXPLOIT", f"a slide runs a command {when}: {prog}")
            else:
                emit("SUSPICIOUS", f"runs when you click or use a control: a slide starts a program or file {when} ({prog or 'unnamed'})")
        elif action == 1:
            emit("SUSPICIOUS", f"runs when you click or use a control: slide action runs a macro {when}")
    for target in targets[:200]:
        if COMMAND.search(target):
            emit("EXPLOIT", f"a slide link runs a command: {target[:200]}")
        elif target.strip():
            emit("LINK", target.strip())


def ppt(path):
    try:
        import olefile
        ole = olefile.OleFileIO(path)
    except Exception:
        return
    try:
        if not ole.exists("PowerPoint Document"):
            return
        stream = ole.openstream("PowerPoint Document").read(256 << 20)
    finally:
        ole.close()
    atoms = ppt_atoms(stream)
    ppt_actions(atoms)
    for n, data in enumerate(ppt_storages(atoms)):
        try:
            import olefile
            sub = olefile.OleFileIO(data)
            has_vba = any(p[-1].lower() == "dir" and any(x.lower() == "vba" for x in p[:-1]) for p in sub.listdir(streams=True)[:5000])
            sub.close()
        except Exception:
            continue
        if has_vba:
            vba(f"ppt-vba-{n}", data, " (PowerPoint macro project)")
        else:
            # Charts and tables embedded in slides are normal: only check
            # them for exploits.
            ole_objects(data, f" #{n + 1} in the slides")


def rtf_end(data):
    """Offset just after the document's outer group closes (escapes and \\binN skipped)."""
    depth, i, n = 0, 0, len(data)
    while i < n:
        c = data[i]
        if c == 0x5C:  # backslash
            m = re.match(rb"\\bin(-?\d{1,10}) ?", data[i : i + 16])
            if m:
                i += m.end() + max(0, int(m.group(1)))
                continue
            i += 2
            continue
        if c == 0x7B:
            depth += 1
        elif c == 0x7D:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def rtf_structure(data, objects, where=""):
    # Every RTF writer starts "{\\rtf1"; anything else ("{\\rt", a NUL in
    # place of the version) is made to trip up other parsers. Word accepts it.
    if not re.match(rb"\{\\rtf1", data):
        emit("MALFORMED", f"the RTF header is deliberately malformed{where} ({data[:8]!r}): no editor writes this; it is made to confuse scanners")
    # Word only reads the outer group; anything after it is a hiding place.
    tail = data[rtf_end(data):].strip(b" \t\r\n\x00")
    if len(tail) > 256:
        emit("EMBEDDED", f"hidden data after the end of the document{where} ({len(tail)} bytes Word never shows)")
    auto = len(re.findall(rb"\\objupdate", data))
    has_obj = objects or re.search(rb"\\object\b|\\objdata", data)
    if auto and has_obj:
        # Exploit kits pair a self-loading object with a header no editor
        # writes ("{\\rt" instead of "{\\rtf1") to break other parsers.
        if not data.startswith(b"{\\rtf1"):
            emit("EXPLOIT", f"object set to load by itself (\\objupdate) in a deliberately malformed RTF{where} - exploit pattern (CVE-2017-11882 / CVE-2017-0199)")
        else:
            emit("EMBEDDED", f"object set to load by itself when the file opens (\\objupdate){where}")


def rtf(data, where=""):
    rtf_data = data
    rtf_structure(data, 0, where)
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
            data = getattr(obj, "oledata", None) or b""
            if re.search(rb"\\objupdate", rtf_data):
                # Real formulas wait to be shown; this one forces Equation
                # Editor to start as the file opens.
                emit("EXPLOIT", f"RTF{where} embeds {cls} set to load by itself (\\objupdate) - Equation Editor exploit (CVE-2017-11882 / CVE-2018-0802)")
            elif data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
                ole_objects(data, f" in RTF{where}")
            else:
                emit("EXPLOIT", f"RTF{where} embeds {cls} whose data is not a valid OLE object - Equation Editor exploit (CVE-2017-11882 / CVE-2018-0802)")
        elif cls == "OLE2Link":
            emit("EXPLOIT", f"RTF{where} embeds OLE2Link - remote object exploit (CVE-2017-0199)")
        elif getattr(obj, "is_package", False):
            emit("EMBEDDED", f"RTF{where} embeds a file: {obj.filename or '?'}")
        elif cls:
            emit("EMBEDDED", f"RTF{where} embeds OLE object {cls}")
        else:
            emit("EMBEDDED", f"RTF{where} embeds raw object data")


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
        elif head.startswith(b"\xd0\xcf\x11\xe0"):
            ole_objects(path, "")
            ppt(path)


if __name__ == "__main__":
    main()
