"""airlock: unpacks an Office document's insides for the YARA scan (runs
inside the VM, as nobody, under the seccomp monitor, without network).
Signatures are written against what malware *contains*: macro source, the
XML of a part, an embedded OLE object. In the file itself those are
compressed (ZIP) or chunked (OLE streams, compressed VBA), so the raw bytes
alone would match little.

Usage: unpack.py <document> <out-dir>. Writes numbered files plus index.tsv
("<file><TAB><what it is>"). Bounded in count, size and nesting.
"""
import os
import re
import sys
import zipfile

MAX_FILES = 1500
MAX_PART = 32 << 20
MAX_TOTAL = 96 << 20
MAX_DEPTH = 3

out_dir = ""
index = []
total = 0


def label(s):
    return re.sub(r"[^\x20-\x7e]", "?", str(s)).replace("\t", " ")[:160]


def save(data, what):
    global total
    if not data or len(index) >= MAX_FILES or total >= MAX_TOTAL:
        return
    data = data[: min(MAX_PART, MAX_TOTAL - total)]
    name = f"{len(index):04d}"
    with open(os.path.join(out_dir, name), "wb") as f:
        f.write(data)
    total += len(data)
    index.append((name, label(what)))


def macros(path, data, where):
    try:
        from oletools.olevba import VBA_Parser
        vp = VBA_Parser(path if data is None else "part", data=data)
    except Exception:
        return
    try:
        if vp.detect_vba_macros():
            for _f, _s, name, code in vp.extract_macros():
                save((code or "").encode("utf-8", "replace"), f"macro source {name}{where}")
    except Exception:
        pass
    finally:
        try:
            vp.close()
        except Exception:
            pass


def ole(data, where, depth):
    try:
        import olefile
        o = olefile.OleFileIO(data)
    except Exception:
        return
    try:
        for entry in o.listdir(streams=True, storages=False)[:500]:
            try:
                blob = o.openstream(entry).read(MAX_PART)
            except Exception:
                continue
            what = f"OLE stream {'/'.join(entry)}{where}"
            save(blob, what)
            # \x01Ole10Native wraps an embedded file (an "OLE package").
            if entry[-1] == "\x01Ole10Native" and len(blob) > 4:
                save(blob[4:], f"packaged file{where}")
            nested(blob, what, depth)
    finally:
        o.close()


def ooxml(data, where, depth):
    try:
        import io
        z = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        return
    for info in z.infolist()[:2000]:
        if info.is_dir() or info.file_size > MAX_PART * 4:
            continue
        try:
            with z.open(info) as f:
                blob = f.read(MAX_PART)
        except Exception:
            continue
        what = f"part {info.filename}{where}"
        save(blob, what)
        nested(blob, what, depth)


def nested(blob, what, depth):
    if depth >= MAX_DEPTH:
        return
    where = f" (inside {what})"
    if blob.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        ole(blob, where, depth + 1)
        macros(None, blob, where)
    elif blob.startswith(b"PK\x03\x04"):
        ooxml(blob, where, depth + 1)


def rtf(data):
    try:
        from oletools.rtfobj import RtfObjParser
    except Exception:
        return
    p = RtfObjParser(data)
    p.parse()
    for i, obj in enumerate(p.objects[:50]):
        raw = getattr(obj, "rawdata", None)
        save(raw, f"RTF object {i}")
        if getattr(obj, "is_ole", False) and getattr(obj, "oledata", None):
            save(obj.oledata, f"RTF object {i} OLE data")
            nested(obj.oledata, f"RTF object {i}", 0)
        if getattr(obj, "is_package", False) and getattr(obj, "olepkgdata", None):
            save(obj.olepkgdata, f"RTF object {i} packaged file {obj.filename or '?'}")


def main():
    global out_dir
    path, out_dir = sys.argv[1], sys.argv[2]
    os.makedirs(out_dir, exist_ok=True)
    with open(path, "rb") as f:
        data = f.read()
    try:
        if data.startswith(b"{\\rt"):
            rtf(data)
        elif data.startswith(b"PK\x03\x04"):
            ooxml(data, "", 0)
            macros(path, None, "")
        else:
            ole(data, "", 0)
            macros(path, None, "")
    finally:
        with open(os.path.join(out_dir, "index.tsv"), "w") as f:
            for name, what in index:
                f.write(f"{name}\t{what}\n")


if __name__ == "__main__":
    main()
