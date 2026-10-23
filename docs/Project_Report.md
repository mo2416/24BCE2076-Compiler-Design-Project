# Project Report

**Project:** Compiler-Based Static Analyzer for Security Vulnerability Detection Using Taint and Data-Flow Analysis  
**Course:** BCSE307P — Compiler Design Lab, VIT  
**Student:** Mohammed Asif A  
**Register number:** 24BCE2076  
**Class number:** VL2026270103261  
**Slot:** L47+L48  
**Semester:** Fall Semester 2026–27

## 1. Abstract

This project implements a small static-analysis prototype that tracks a selected untrusted input through LLVM Intermediate Representation (IR) and reports a potential command-injection flow. Clang compiles C source into LLVM IR; LLVM's `mem2reg` pass promotes eligible local variables to SSA form; a custom C++ analyzer then tracks taint from the return value of `getenv()` to argument 0 of `system()`. The web interface accepts source code and displays the finding and the supported data-flow path. Submitted source is compiled and analyzed, not executed.

## 2. Problem and objective

Untrusted input that reaches a command-execution function may create a command-injection risk. The objective is to demonstrate a transparent, compiler-based source-to-sink analysis using an explicitly limited model, with an understandable report and controlled positive and negative test cases.

## 3. Scope

**Source:** the return value of `getenv()`.  
**Sink:** argument 0 of `system()`.  
**Finding category:** potential command injection (CWE-78).  
**Supported propagation:** direct values, supported SSA copies/casts and value-producing IR operations, and PHI nodes that merge branch values.

The prototype does not claim to detect every vulnerability. Other sinks such as `printf()` and `strcpy()`, general pointer/alias analysis, sanitizer recognition, and interprocedural taint tracking are out of scope. A finding is not proof of exploitability, and a clean result is not proof that the program is secure.

## 4. Methodology and architecture

1. The user enters C source in the web UI.
2. `server.py` validates the request and runs Clang to emit LLVM IR.
3. `opt -passes=mem2reg` transforms eligible local memory variables into SSA values.
4. The C++ analyzer reads the IR through LLVM APIs, identifies `getenv()` results as tainted, propagates taint through supported operations, and checks the first argument to `system()`.
5. The UI displays either a potential finding with source, sink, and path; a no-tainted-flow result under the prototype's rules; or an analysis error.

The backend uses Python's standard library. The interface is built with plain HTML, CSS, and JavaScript.

## 5. Dataset and evaluation

The repository's `dataset/` directory provides six small, manually constructed C examples. The same test inputs are present in `test/cases/` and are consumed by `test/run_tests.sh`.

| Test | Expected | Purpose |
|---|---|---|
| T01 Direct | Finding | Direct `getenv()` → `system()` |
| T02 Constant | Clean | Constant passed to `system()` |
| T03 Copy | Finding | Taint follows local assignments and cast |
| T04 Overwrite | Clean | Constant overwrites tainted local |
| T05 Branch merge | Finding | Tainted input reaches sink through a PHI merge |
| T06 Both clean | Clean | Both branch outcomes supply constants |

**Local test evidence:** the test runner completed with 6 passed and 0 failed on the student's WSL2 setup using LLVM 21.1.8. The integration check completed with 8 passed and 0 failed. A successful public GitHub Actions run is also available from the repository's Actions tab.

These are controlled examples only; they do not measure accuracy on a representative real-world dataset.

## 6. Example result

For a program in which the value returned by `getenv("CMD")` is copied to local variables and passed to `system()`, the prototype reports a potential CWE-78 command-injection flow. Its path can be displayed as:

`getenv() → input → copy → cmd → system() arg 0`

For the selected safe cases, it reports that no tainted flow was detected under its rules.

## 7. Reproducibility

On WSL2 Ubuntu with a compatible LLVM 21 development installation, CMake and Ninja:

```bash
cmake -S . -B build -G Ninja -DLLVM_DIR=/usr/lib/llvm-21/lib/cmake/llvm
cmake --build build
bash test/run_tests.sh
python3 test/integration_check.py
python3 server.py
```

Then open `http://127.0.0.1:8000`. The hosted Netlify page serves the frontend only; the local backend must be running for analysis.

## 8. Research gap and contribution

Existing static-analysis frameworks provide broader source-to-sink and interprocedural capabilities. This project does not attempt to compete with those tools. Its project-specific contribution is a compact and inspectable demonstration of an LLVM-IR pipeline, taint propagation, PHI-based branch merging, and path reporting within the scope of an undergraduate Compiler Design Lab.

## 9. Conclusion

The tested prototype demonstrates the selected `getenv()`-to-`system()` data-flow rule on a small set of vulnerable and clean cases. The implementation and its limits are documented in the repository. Further work would be needed to add more source/sink models, memory and alias analysis, interprocedural flow tracking, and evaluation on larger benchmark suites.
