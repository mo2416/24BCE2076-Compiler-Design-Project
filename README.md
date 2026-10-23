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

Needs Clang/LLVM 21 (Clang, `opt`, LLVM CMake package), CMake and Ninja.

```bash
cmake -S . -B build -G Ninja -DLLVM_DIR=/usr/lib/llvm-21/lib/cmake/llvm
cmake --build build
bash test/run_tests.sh
python3 test/integration_check.py
python3 server.py
```

Then open http://127.0.0.1:8000. If your tools are named `clang-21` and `opt-21`, set `export CLANG=clang-21 OPT=opt-21` first.

**Hosted page:** https://compiler-security-analyzer.netlify.app serves the UI. It sends code to an analyzer running on your own machine at `http://127.0.0.1:8000`, so start `python3 server.py` first. The hosted page does not host the C++ analyzer itself.

## Architecture

```text
browser (web/) -> server.py (/api/analyze) -> Clang -> LLVM IR
                                             -> opt -passes=mem2reg
                                             -> build/taint_analyzer -> JSON finding
```

- `src/taint_analyzer.cpp`: reads LLVM IR, marks `getenv()` return values tainted, propagates taint through supported IR operations and PHI nodes, and reports a source-to-sink path.
- `server.py`: lightweight Python standard-library backend that compiles and analyzes supplied C source. It does not execute submitted programs.
- `web/`: plain HTML, CSS and JavaScript user interface.
- `test/cases/`: six automated input cases used by `test/run_tests.sh`.

## Test results

Local WSL2 test run on LLVM 21.1.8:

```text
PASS T01_direct: finding  [getenv() -> system() arg 0]
PASS T02_constant: clean
PASS T03_copy: finding  [getenv() -> input -> copy -> cmd -> system() arg 0]
PASS T04_overwrite: clean
PASS T05_branch_merge: finding  [getenv() -> cmd -> if/else merge (PHI) -> system() arg 0]
PASS T06_both_clean: clean

6 passed, 0 failed
```

The integration check also passed 8/8 checks in the local run. These are hand-built tests and do not measure real-world detection accuracy.

## Limitations

- One source and one sink only; no `printf`, `strcpy`, or other vulnerability types.
- Intraprocedural analysis only; taint is not followed through helper functions.
- No general pointer/alias analysis and no sanitizer modelling.
- A finding is a potential unsafe flow, not proof of exploitability. A clean result is not proof of security.

## Research gap and project contribution

Industrial and research tools already offer broader taint analysis. This project does not claim to replace them. Its contribution is an intentionally small and transparent LLVM-IR pipeline that demonstrates source-to-sink taint propagation and PHI-based branch merging in a Compiler Design Lab project. See the review documents in `references/` and the implementation report in `docs/Project_Report.md`.

## Dataset and project report

- **Sample dataset:** `dataset/` contains six controlled C examples with expected finding/clean outcomes. They are small hand-written tests, not a real-world vulnerability benchmark.
- **Project report:** `docs/Project_Report.md`.
- **Course references:** `references/Review1.docx` and `references/Review2.pdf`.
