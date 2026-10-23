# Compiler-Based Static Analyzer for Security Vulnerability Detection Using Taint and Data-Flow Analysis

BCSE307P Compiler Design Lab, VIT. Mohammed Asif A, 24BCE2076.

An educational prototype. Paste C code into a small web page, press **Analyze**, and the code is compiled to LLVM IR with Clang, cleaned up with `mem2reg`, and checked by a custom C++ taint analyzer that reads the IR through the LLVM APIs. It reports when the return value of `getenv()` can reach argument 0 of `system()`: a potential command injection (CWE-78).

The submitted code is compiled and analyzed. It is never executed.

## Supported check

- **Source:** return value of `getenv()`, treated as untrusted.
- **Sink:** argument 0 of `system()`.
- **Propagation:** direct use, SSA copies, casts, pointer offsets (GEP), `select`, arithmetic, and `if/else` merges (PHI nodes). A PHI is tainted if any incoming value is tainted.
- **Clean result** reads "No tainted flow detected under this prototype's rules", never "safe".

This prototype checks a limited `getenv()` to `system()` data-flow pattern. A clean result does not prove code is secure.

## Run it (WSL2 Ubuntu)

Needs Clang/LLVM 21 (`clang`, `opt`, LLVM CMake package), CMake and Ninja.

```bash
cmake -S . -B build -G Ninja      # add -DLLVM_DIR=/usr/lib/llvm-21/lib/cmake/llvm if CMake cannot find LLVM
cmake --build build
bash test/run_tests.sh            # T01 to T06
python3 test/integration_check.py # server + /api/analyze end to end
python3 server.py                 # then open http://127.0.0.1:8000
```

If the tools are named `clang-21` and `opt-21`, set them first: `export CLANG=clang-21 OPT=opt-21`.

**Hosted page:** https://compiler-security-analyzer.netlify.app serves the same UI. It sends code to the analyzer running on your own machine at `http://127.0.0.1:8000`, so start `python3 server.py` first. Chrome may ask once to allow the page to reach local network devices; allow it. The backend address is editable on the page.

## Architecture

```text
browser (web/)  --POST /api/analyze-->  server.py (127.0.0.1 only)
                                          |  clang -M          check included files
                                          |  clang -S -emit-llvm -O0 -g -Xclang -disable-O0-optnone
                                          |  opt -passes=mem2reg
                                          v
                                        build/taint_analyzer input.opt.ll  -> JSON
```

- `src/taint_analyzer.cpp`: parses the `.ll` with `parseIRFile`, seeds taint on `getenv()` call results, propagates to a fixpoint over value-producing instructions and PHI nodes, keeps a provenance link per tainted value, and reconstructs the source-to-sink path with a cycle guard. Variable names come from the `#dbg_value` records; missing line info prints `line unknown`, never 0.
- `server.py`: Python standard library only. Validates the request, runs the three tool steps with argument lists (`shell=False`) and a 15 s timeout each, returns the analyzer JSON. 20 KB source limit. Binds to `127.0.0.1`, checks the `Host` header, and only allows system headers to be included (checked by text and again with `clang -M`), so the endpoint cannot be used to read local files.
- `web/`: plain HTML, CSS and JavaScript. Shows Potential finding, No tainted flow detected, or Analysis error. An error is never shown as a clean result.

## Test results

From the GitHub Actions run on Ubuntu 24.04 with Clang/LLVM 21.1.8 (`.github/workflows/ci.yml`):

```text
PASS T01_direct: finding  [getenv() -> system() arg 0]
PASS T02_constant: clean
PASS T03_copy: finding  [getenv() -> input -> copy -> cmd -> system() arg 0]
PASS T04_overwrite: clean
PASS T05_branch_merge: finding  [getenv() -> cmd -> if/else merge (PHI) -> system() arg 0]
PASS T06_both_clean: clean
6 passed, 0 failed
```

Integration check through `/api/analyze`: vulnerable example gives a CWE-78 finding, safe example gives no finding, invalid C gives an error, quoted and line-spliced file includes are rejected, and the page is served. 6 passed, 0 failed.

Six hand-written tests show the rules work as designed. They do not measure real-world accuracy.

## Limitations

- One source and one sink. No `printf`, `strcpy` or other vulnerability types.
- Intraprocedural only. Taint does not follow values into or out of other functions, and results of unknown calls are not tracked. Unknown calls are not treated as sanitizers.
- No pointer or alias analysis. Values stored to memory that `mem2reg` cannot promote (arrays, structs, globals) are not followed.
- No sanitizer modelling.

## Related work and gap

Research-grade and industrial tools already provide broad taint tracking with custom source and sink models, for example CodeQL data-flow analysis for C/C++ and the Clang Static Analyzer. This project does not compete with them. As set out in the project reviews (`references/`), its contribution is a small, transparent LLVM-IR pipeline whose every step (IR generation, SSA promotion, propagation, path reconstruction) can be inspected and explained within a Compiler Design Lab project.

## Files

```text
PRD.md                  project requirements
src/taint_analyzer.cpp  the analyzer
server.py               local backend
web/                    frontend
test/cases/             T01 to T06
test/run_tests.sh       test runner
test/integration_check.py
references/             Review 1, Review 2, PRD copy
netlify.toml            hosts web/ on Netlify
```
