#!/usr/bin/env python3
"""airlock test bench: thousands of real documents, measured the same way
every time, without keeping hundreds of GB around.

Manifests (committed, tests/bench/*.tsv) list each file by SHA-256 with its
label and where it comes from:

    sha256  label  source  type  name  note

  label   malicious | harmless | decoy (malware-related but harmless on
          its own, e.g. a lure PDF a dropper shows its victim: any verdict
          is accepted, it only must not crash)
  source  bazaar (MalwareBazaar, by hash) | govdocs1:<zip> | poi:<path>

Files live in a cache (build/bench-cache, or $AIRLOCK_BENCH_CACHE) and are
fetched again by hash when missing. Malware stays in its password-protected
zip on disk; each sample is unpacked into RAM ($XDG_RUNTIME_DIR, tmpfs) just
for its analysis and deleted. Nothing on the host opens a sample except 7z
and airlock.

    tests/bench.py add-bazaar --types pdf,doc,docx --limit 100
    tests/bench.py add-govdocs 000 001 [--per-type 150]
    tests/bench.py add-poi
    tests/bench.py run [--jobs 6] [--label malicious] [--limit N]
    tests/bench.py report [RUN]

`run` writes build/bench-runs/<time>/results.tsv and prints a scorecard,
compared with the previous run: anything caught before and missed now, or
clean before and flagged now, is a regression.
"""
import argparse
import concurrent.futures as cf
import csv
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFESTS = os.path.join(ROOT, "tests", "bench")
CACHE = os.environ.get("AIRLOCK_BENCH_CACHE") or os.path.join(ROOT, "build", "bench-cache")
RUNS = os.path.join(ROOT, "build", "bench-runs")
AIRLOCK = os.environ.get("AIRLOCK") or os.path.join(ROOT, "host", "target", "release", "airlock")
KEY_FILE = os.path.expanduser("~/.config/airlock/malwarebazaar.key")
BAZAAR = "https://mb-api.abuse.ch/api/v1/"
GOVDOCS = "https://digitalcorpora.s3.amazonaws.com/corpora/files/govdocs1/zipfiles/{}.zip"
POI = "https://github.com/apache/poi"
FIELDS = ["sha256", "label", "source", "type", "name", "note"]
# What airlock opens (by extension for harmless sets; content decides inside).
DOC_TYPES = {"pdf", "doc", "docx", "docm", "dot", "dotx", "dotm", "xls", "xlsx", "xlsm", "xlsb", "xlam", "ppt", "pptx", "pptm", "rtf", "odt", "ods", "odp"}
VERDICTS = ["NO ACTIVE BEHAVIOUR OBSERVED", "SUSPICIOUS", "LIKELY MALICIOUS", "MALICIOUS BEHAVIOUR"]
SHORT = {"NO ACTIVE BEHAVIOUR OBSERVED": "clean", "SUSPICIOUS": "suspicious", "LIKELY MALICIOUS": "likely", "MALICIOUS BEHAVIOUR": "malicious"}


def manifest_path(label_set):
    return os.path.join(MANIFESTS, f"{label_set}.tsv")


def read_manifest(path):
    if not os.path.exists(path):
        return []
    with open(path, newline="") as f:
        return [r for r in csv.DictReader(f, delimiter="\t") if r.get("sha256")]


def write_manifest(path, rows):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    rows = sorted({r["sha256"]: r for r in rows}.values(), key=lambda r: (r["source"], r["type"], r["sha256"]))
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, FIELDS, delimiter="\t", lineterminator="\n")
        w.writeheader()
        for r in rows:
            w.writerow({k: (r.get(k) or "").replace("\t", " ").replace("\n", " ") for k in FIELDS})


def all_rows():
    rows = []
    for name in sorted(os.listdir(MANIFESTS)) if os.path.isdir(MANIFESTS) else []:
        if name.endswith(".tsv"):
            rows += read_manifest(os.path.join(MANIFESTS, name))
    return rows


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


# ---------------------------------------------------------------- MalwareBazaar

def bazaar(data, raw=False):
    with open(KEY_FILE) as f:
        key = f.read().strip()
    req = urllib.request.Request(BAZAAR, data=urllib.parse.urlencode(data).encode(), headers={"Auth-Key": key})
    with urllib.request.urlopen(req, timeout=120) as r:
        body = r.read()
    return body if raw else json.loads(body)


def bazaar_zip(sha):
    path = os.path.join(CACHE, "malicious", f"{sha}.zip")
    if not os.path.exists(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        body = bazaar({"query": "get_file", "sha256_hash": sha}, raw=True)
        if not body.startswith(b"PK"):
            raise RuntimeError(f"MalwareBazaar did not return a zip for {sha[:12]}")
        with open(path + ".part", "wb") as f:
            f.write(body)
        os.replace(path + ".part", path)
    return path


def cmd_add_bazaar(a):
    path = manifest_path("malicious")
    rows = read_manifest(path)
    have = {r["sha256"] for r in rows}
    added = 0
    for t in a.types.split(","):
        j = bazaar({"query": "get_file_type", "file_type": t, "limit": a.limit})
        for d in j.get("data") or []:
            sha = d["sha256_hash"]
            if sha in have:
                continue
            note = " ".join(x for x in [d.get("signature") or "", ",".join(d.get("tags") or [])] if x)
            rows.append({"sha256": sha, "label": "malicious", "source": "bazaar", "type": t, "name": (d.get("file_name") or "")[:80], "note": note[:120]})
            have.add(sha)
            added += 1
    write_manifest(path, rows)
    print(f"added {added} MalwareBazaar samples ({len(rows)} in {os.path.relpath(path, ROOT)})")


# ---------------------------------------------------------------- harmless sets

def harmless_path(sha):
    return os.path.join(CACHE, "harmless", sha)


def keep_harmless(data):
    sha = hashlib.sha256(data).hexdigest()
    p = harmless_path(sha)
    if not os.path.exists(p):
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p + ".part", "wb") as f:
            f.write(data)
        os.replace(p + ".part", p)
    return sha


def govdocs_zip(z):
    """Download one Govdocs1 slice to a temporary file (deleted by the caller)."""
    tmp = os.path.join(CACHE, f"govdocs1-{z}.zip.part")
    os.makedirs(CACHE, exist_ok=True)
    print(f"downloading Govdocs1 slice {z} (~0.5 GB)...", flush=True)
    urllib.request.urlretrieve(GOVDOCS.format(z), tmp)
    return tmp


def cmd_add_govdocs(a):
    path = manifest_path("harmless-govdocs1")
    rows = read_manifest(path)
    have = {r["sha256"] for r in rows}
    for z in a.zips:
        tmp = govdocs_zip(z)
        try:
            per_type = {}
            with zipfile.ZipFile(tmp) as zf:
                for info in zf.infolist():
                    ext = info.filename.rsplit(".", 1)[-1].lower()
                    if ext not in DOC_TYPES or info.file_size > 50 << 20 or per_type.get(ext, 0) >= a.per_type:
                        continue
                    sha = keep_harmless(zf.read(info))
                    per_type[ext] = per_type.get(ext, 0) + 1
                    if sha not in have:
                        rows.append({"sha256": sha, "label": "harmless", "source": f"govdocs1:{z}", "type": ext, "name": os.path.basename(info.filename), "note": ""})
                        have.add(sha)
            print(f"  slice {z}: " + ", ".join(f"{k} {v}" for k, v in sorted(per_type.items())))
        finally:
            os.remove(tmp)
    write_manifest(path, rows)
    print(f"{len(rows)} files in {os.path.relpath(path, ROOT)}")


def poi_checkout():
    d = os.path.join(CACHE, "poi")
    if not os.path.isdir(os.path.join(d, ".git")):
        subprocess.run(["git", "clone", "-q", "--depth", "1", "--filter=blob:none", "--sparse", POI, d], check=True)
        subprocess.run(["git", "-C", d, "sparse-checkout", "set", "test-data/document", "test-data/spreadsheet", "test-data/slideshow"], check=True)
    return d


def cmd_add_poi(a):
    path = manifest_path("harmless-poi")
    rows = read_manifest(path)
    have = {r["sha256"] for r in rows}
    d = poi_checkout()
    for sub in ["document", "spreadsheet", "slideshow"]:
        base = os.path.join(d, "test-data", sub)
        for name in sorted(os.listdir(base)):
            p = os.path.join(base, name)
            ext = name.rsplit(".", 1)[-1].lower()
            if not os.path.isfile(p) or ext not in DOC_TYPES or os.path.getsize(p) > 50 << 20:
                continue
            with open(p, "rb") as f:
                sha = keep_harmless(f.read())
            if sha not in have:
                rows.append({"sha256": sha, "label": "harmless", "source": f"poi:{sub}/{name}", "type": ext, "name": name, "note": ""})
                have.add(sha)
    write_manifest(path, rows)
    print(f"{len(rows)} files in {os.path.relpath(path, ROOT)}")


def harmless_file(r):
    p = harmless_path(r["sha256"])
    if os.path.exists(p):
        return p
    src = r["source"]
    if src.startswith("poi:"):
        q = os.path.join(poi_checkout(), "test-data", src[4:])
        with open(q, "rb") as f:
            keep_harmless(f.read())
    elif src.startswith("govdocs1:"):
        raise RuntimeError(f"not cached; run add-govdocs {src.split(':')[1]} again")
    if not os.path.exists(p):
        raise RuntimeError("cached copy does not match its hash")
    return p


# ---------------------------------------------------------------- running

def analyze(path, out):
    t = time.time()
    p = subprocess.run([AIRLOCK, "analyze", path, "--out", out, "--report-only"], capture_output=True, text=True, timeout=600)
    rep = None
    try:
        with open(os.path.join(out, "report.json")) as f:
            rep = json.load(f)
    except Exception:
        pass
    verdict = rep.get("verdict") if isinstance(rep, dict) and rep.get("verdict") in VERDICTS else None
    return verdict, round(time.time() - t, 1), rep, (p.stderr or "")[-400:]


def run_one(r, ram, out_root):
    sha = r["sha256"]
    out = os.path.join(out_root, "reports", sha)
    try:
        if r["label"] in ("malicious", "decoy") and r["source"] == "bazaar":
            z = bazaar_zip(sha)
            work = tempfile.mkdtemp(dir=ram)
            try:
                if subprocess.run(["7z", "x", "-pinfected", f"-o{work}", "-y", z], capture_output=True).returncode != 0:
                    return r, "ERROR", 0, "could not extract"
                files = [os.path.join(dp, f) for dp, _, fs in os.walk(work) for f in fs]
                if len(files) != 1:
                    return r, "ERROR", 0, f"expected 1 file, found {len(files)}"
                sample = os.path.join(work, "sample.bin")
                os.rename(files[0], sample)
                verdict, secs, rep, err = analyze(sample, out)
            finally:
                shutil.rmtree(work, ignore_errors=True)
        else:
            verdict, secs, rep, err = analyze(harmless_file(r), out)
        if rep is not None:
            with open(os.path.join(out, "summary.txt"), "w") as f:
                f.write("\n".join(f"{x.get('severity')}\t{x.get('title')}\t{x.get('what')}" for x in rep.get("findings", [])))
        return r, verdict or "ERROR", secs, "" if verdict else (err.strip().splitlines() or [""])[-1]
    except Exception as e:
        return r, "ERROR", 0, str(e)[:200]


def outcome(label, verdict):
    """caught / missed / flagged / false-alarm / clean / ok (decoy) / error"""
    if verdict == "ERROR":
        return "error"
    s = SHORT.get(verdict, "?")
    if label == "malicious":
        return {"likely": "caught", "malicious": "caught", "suspicious": "suspicious", "clean": "missed"}[s]
    if label == "harmless":
        return {"clean": "clean", "suspicious": "flagged", "likely": "false-alarm", "malicious": "false-alarm"}[s]
    return "ok"


def runs():
    return sorted(d for d in os.listdir(RUNS) if os.path.isfile(os.path.join(RUNS, d, "results.tsv"))) if os.path.isdir(RUNS) else []


def load_results(run):
    with open(os.path.join(RUNS, run, "results.tsv"), newline="") as f:
        return {r["sha256"]: r for r in csv.DictReader(f, delimiter="\t")}


def cmd_run(a):
    rows = all_rows() if not a.manifest else read_manifest(manifest_path(a.manifest))
    rows = [r for r in rows if not a.label or r["label"] == a.label]
    if a.type:
        rows = [r for r in rows if r["type"] in a.type.split(",")]
    if a.outcome:
        # Rerun only what had this outcome in the last run (e.g. missed).
        last = load_results(a.in_run or runs()[-1]) if runs() else {}
        rows = [r for r in rows if last.get(r["sha256"], {}).get("outcome") in a.outcome.split(",")]
    if a.limit:
        rows = rows[: a.limit]
    if not rows:
        sys.exit("no files in the manifests (tests/bench/*.tsv); add some first")
    run = time.strftime("%Y%m%d-%H%M%S")
    out_root = os.path.join(RUNS, run)
    os.makedirs(out_root)
    rt = os.environ.get("XDG_RUNTIME_DIR")
    if not rt or subprocess.run(["findmnt", "-no", "FSTYPE", "--target", rt], capture_output=True, text=True).stdout.strip() != "tmpfs":
        sys.exit("needs $XDG_RUNTIME_DIR on tmpfs (samples are unpacked in RAM only)")
    ram = os.path.join(rt, "airlock-bench")
    shutil.rmtree(ram, ignore_errors=True)
    os.makedirs(ram, mode=0o700)
    results = []
    try:
        with cf.ThreadPoolExecutor(a.jobs) as ex:
            futs = [ex.submit(run_one, r, ram, out_root) for r in rows]
            for i, f in enumerate(cf.as_completed(futs), 1):
                r, verdict, secs, err = f.result()
                results.append({**r, "verdict": verdict, "outcome": outcome(r["label"], verdict), "seconds": secs, "error": err or ""})
                if i % 25 == 0 or i == len(rows):
                    print(f"  {i}/{len(rows)}", file=sys.stderr, flush=True)
    finally:
        shutil.rmtree(ram, ignore_errors=True)
    with open(os.path.join(out_root, "results.tsv"), "w", newline="") as f:
        w = csv.DictWriter(f, FIELDS + ["verdict", "outcome", "seconds", "error"], delimiter="\t", lineterminator="\n")
        w.writeheader()
        for r in sorted(results, key=lambda r: (r["label"], r["outcome"], r["sha256"])):
            w.writerow(r)
    report(run)


def rescore(run):
    path = os.path.join(RUNS, run, "results.tsv")
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f, delimiter="\t"))
    for r in rows:
        try:
            with open(os.path.join(RUNS, run, "reports", r["sha256"], "report.json")) as f:
                v = json.load(f).get("verdict")
            if v in VERDICTS:
                r["verdict"], r["outcome"], r["error"] = v, outcome(r["label"], v), ""
        except Exception:
            pass
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, FIELDS + ["verdict", "outcome", "seconds", "error"], delimiter="\t", lineterminator="\n")
        w.writeheader()
        w.writerows(sorted(rows, key=lambda r: (r["label"], r["outcome"], r["sha256"])))
    report(run)


def report(run):
    res = load_results(run)
    # Each file is compared with the last earlier run that included it
    # (runs can be subsets: --type, --outcome).
    prev = [r for r in runs() if r < run]
    old = {}
    for p in prev:
        old.update(load_results(p))
    count = lambda label, o: sum(1 for r in res.values() if r["label"] == label and r["outcome"] == o)
    total = lambda label: sum(1 for r in res.values() if r["label"] == label)
    print(f"\nairlock bench {run}  ({len(res)} files)")
    m = total("malicious")
    if m:
        print(f"  malicious {m:5}: {count('malicious','caught')} caught ({100*count('malicious','caught')//m}%) · {count('malicious','suspicious')} suspicious · {count('malicious','missed')} missed · {count('malicious','error')} errors")
    h = total("harmless")
    if h:
        print(f"  harmless  {h:5}: {count('harmless','clean')} clean ({100*count('harmless','clean')//h}%) · {count('harmless','flagged')} flagged suspicious · {count('harmless','false-alarm')} FALSE ALARMS · {count('harmless','error')} errors")
    d = total("decoy")
    if d:
        print(f"  decoys    {d:5}: {count('decoy','ok')} ok · {count('decoy','error')} errors")
    rank = {"missed": 0, "suspicious": 1, "caught": 2, "false-alarm": 0, "flagged": 1, "clean": 2}
    worse = [r for s, r in res.items() if s in old and r["outcome"] in rank and old[s]["outcome"] in rank and rank[r["outcome"]] < rank[old[s]["outcome"]]]
    better = [r for s, r in res.items() if s in old and r["outcome"] in rank and old[s]["outcome"] in rank and rank[r["outcome"]] > rank[old[s]["outcome"]]]
    if old:
        print(f"  vs earlier runs: {len(better)} better · {len(worse)} REGRESSIONS")
        for r in worse:
            print(f"     regression: {r['sha256'][:12]} {r['label']} {old[r['sha256']]['outcome']} -> {r['outcome']} ({r['source']} {r['name']})")
    for o in ["false-alarm", "missed", "error"]:
        bad = [r for r in res.values() if r["outcome"] == o]
        if bad:
            print(f"  {o} ({len(bad)}):")
            for r in bad[:40]:
                print(f"     {r['sha256'][:12]} {r['type']:5} {r['source'][:28]:28} {r['name'][:40]:40} {r['note'][:40]} {r['error'][:60]}")
    print(f"  details: {os.path.relpath(os.path.join(RUNS, run), ROOT)}/results.tsv, reports/<sha256>/summary.txt")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("add-bazaar")
    p.add_argument("--types", default="pdf,doc,docx,docm,xls,xlsx,xlsm,rtf,ppt")
    p.add_argument("--limit", type=int, default=100)
    p = sub.add_parser("add-govdocs")
    p.add_argument("zips", nargs="+", help="slice numbers, e.g. 000 001")
    p.add_argument("--per-type", type=int, default=150)
    sub.add_parser("add-poi")
    p = sub.add_parser("run")
    p.add_argument("--jobs", type=int, default=6)
    p.add_argument("--label", choices=["malicious", "harmless", "decoy"])
    p.add_argument("--limit", type=int)
    p.add_argument("--type", help="comma-separated file types, e.g. ppt,pdf")
    p.add_argument("--manifest", help="only this manifest, e.g. cve (tests/bench/cve.tsv)")
    p.add_argument("--outcome", help="only files with this outcome in the last run, e.g. missed,false-alarm")
    p.add_argument("--in-run", help="with --outcome: look the outcome up in this run instead of the last one")
    p = sub.add_parser("rescore", help="rebuild a run's results from its saved reports")
    p.add_argument("run")
    p = sub.add_parser("report")
    p.add_argument("run", nargs="?")
    a = ap.parse_args()
    if a.cmd == "add-bazaar":
        cmd_add_bazaar(a)
    elif a.cmd == "add-govdocs":
        cmd_add_govdocs(a)
    elif a.cmd == "add-poi":
        cmd_add_poi(a)
    elif a.cmd == "run":
        cmd_run(a)
    elif a.cmd == "rescore":
        rescore(a.run)
    else:
        r = a.run or (runs() or [None])[-1]
        if not r:
            sys.exit("no runs yet")
        report(r)


if __name__ == "__main__":
    main()
