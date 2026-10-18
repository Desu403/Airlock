# Smoke test: ordinary documents

31 small, harmless real-world documents (13 from Govdocs1, US government
web sites, public domain; 18 from the Apache POI test files, Apache-2.0),
picked from the test bench where they came out clean. `tests/run.sh`
analyzes each and fails if any comes out worse than `expected.tsv`: an
update (new renderers, new rules) must not start flagging ordinary files.
The full bench (`tests/bench.py`) is the thorough version of this check.
