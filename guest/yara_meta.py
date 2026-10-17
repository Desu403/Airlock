"""airlock: build-time helper. Reads YARA rule files and prints one line per
rule, "name<TAB>score<TAB>description<TAB>author", for the agent to describe
a match (yara itself only prints the rule name). Runs in the image build.
"""
import re
import sys

RULE = re.compile(r"^\s*(?:private\s+|global\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)")
META = re.compile(r'^\s*(score|description|author)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|(\d+))')


def clean(s):
    s = re.sub(r"\\(.)", r"\1", s)
    return re.sub(r"[^\x20-\x7e]", "?", s).replace("\t", " ")[:200]


def main():
    for path in sys.argv[1:]:
        name, meta = None, {}
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                m = RULE.match(line)
                if m:
                    if name:
                        emit(name, meta)
                    name, meta = m.group(1), {}
                    continue
                m = META.match(line)
                if name and m and m.group(1) not in meta:
                    meta[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)
        if name:
            emit(name, meta)


def emit(name, meta):
    try:
        score = int(meta.get("score", "50"))
    except ValueError:
        score = 50
    print(f"{name}\t{score}\t{clean(meta.get('description', ''))}\t{clean(meta.get('author', ''))}")


if __name__ == "__main__":
    main()
