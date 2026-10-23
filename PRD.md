# PRD — Compiler-Based Static Analyzer for Security Vulnerability Detection Using Taint and Data-Flow Analysis

**Course:** BCSE307P — Compiler Design Lab, VIT  
**Student:** Mohammed Asif A — 24BCE2076  
**Workspace:** `~/compiler-security-analyzer` in WSL2 Ubuntu  
**Execution constraint:** Build the best demonstrable MVP in one Claude Code session.  
**Product:** A simple local web dashboard for source-to-sink vulnerability detection and data-flow visualization.

## 1. What to build

Build a clean, usable website where a user pastes C code, clicks **Analyze**, and sees whether the code contains the supported risky data flow. Show the source, propagation path, sink, and a short explanation.

This is an **educational prototype**, not an industrial analyzer. The official course project title remains:

**Compiler-Based Static Analyzer for Security Vulnerability Detection Using Taint and Data-Flow Analysis**

The project's contribution is a small custom taint/data-flow analyzer over LLVM IR. Clang/LLVM provides compilation and IR generation. Do not claim the project implements a complete compiler or detects all vulnerability types.

## 2. Scope — do not expand it

Implement only this focused check:

- **Source:** return value of `getenv()` is treated as untrusted.
- **Sink:** argument 0 passed to `system()`.
- **Finding:** report a *potential command-injection flow (CWE-78)* if the tainted value reaches that sink through supported data-flow operations.
- **Supported flow:** direct use, simple SSA copies/casts, and one simple `if/else` merge represented by a PHI node.
- **Clean result:** say **“No tainted flow detected under this prototype’s rules”**, not “safe” or “secure.”
- **Not included:** other vulnerability types, `printf`, `strcpy`, general pointer/alias analysis, loops, interprocedural analysis, sanitizers, databases, logins, cloud hosting, AI-generated explanations, or arbitrary code execution.

Pointer values are supported only for the direct `getenv()`-to-`system()` flow and the explicitly listed propagation cases. Do not implement general pointer analysis.

The visible interface must explain the limitation: **“This prototype checks a limited `getenv()` → `system()` data-flow pattern. A clean result does not prove code is secure.”**

## 3. Technical approach

Use the already verified environment: **Clang/LLVM 21.1.8**, CMake 4.2.3, and Ninja 1.13.2. The Clang-to-LLVM-IR and `mem2reg` smoke test has already passed. Do not reinstall or repeat setup unless a real build error requires it.

Use the simplest architecture that preserves real analysis:

1. **Frontend:** plain HTML, CSS, and vanilla JavaScript. No React, no Node/npm, no external assets, and no elaborate animations.
2. **Local backend:** a small Python standard-library HTTP server serving the page and a single `POST /api/analyze` endpoint.
3. **Compiler pipeline:** submitted source is written to a unique temporary file under the project `build/` directory, then Clang emits LLVM IR and `opt -passes=mem2reg` transforms it.
4. **Custom analyzer:** a small C++17 program reads the transformed `.ll` through LLVM IRReader APIs and performs taint tracking. It must inspect LLVM instructions/calls; do not replace analysis with a text search for the words `getenv` and `system`.
5. **Results:** return structured data from the analyzer/backend to the page, including finding status, source, sink, line information when available, propagation path, and any compilation/analysis error.

Keep the backend thin. It should only validate the request, invoke the compiler pipeline and analyzer, and return results. Do not execute submitted C code or its compiled binary. Bind the server to `127.0.0.1`, set a modest source-size limit and subprocess timeouts, use argument arrays with `shell=False`, and do not allow user-supplied paths or commands.

## 4. Frontend design — important

Make the website look like a **simple student-built developer tool using basic CSS**, not a flashy AI-generated landing page.

Use a restrained palette, readable typography, clear spacing, basic borders, and a responsive two-column layout where practical. No gradients, oversized hero banners, floating blobs, fake metrics, unnecessary cards, or decorative animations.

The main screen should contain:

- Compact project title and one-line description.
- A large editable C-code textarea with a vulnerable example preloaded.
- Buttons: **Analyze**, **Load vulnerable example**, **Load safe example**, and **Clear**.
- A results area showing **Potential finding**, **No tainted flow detected**, or **Analysis error**. Errors must never be shown as clean results.
- For a finding: `CWE-78`, source (`getenv()`), sink (`system()`, argument 0), line numbers where available, and a clear flow display such as `getenv() → cmd → system()`.
- A small scope/limitations note always visible.
- A loading state and disabled Analyze button while a request is running.

No fake results on initial page load. A result must appear only after the backend runs the real analysis. Make the **working end-to-end interaction** the priority over visual polish.

## 5. Analysis logic

Implement a limited intraprocedural analysis:

1. Identify direct `getenv()` calls and mark their return values tainted.
2. Identify direct `system()` calls and inspect argument 0 only.
3. Propagate taint through the supported copies/casts/value-producing operations and PHI nodes. A PHI is tainted if any incoming value is tainted.
4. Preserve basic provenance so a finding can explain the source-to-sink path. Guard path reconstruction against cycles/repeated values.
5. Ensure a tainted value overwritten with a constant is not reported when only that constant reaches the sink.
6. If debug line information is unavailable, show `line unknown`, never line zero.
7. Treat unknown calls as neither sanitizers nor proof of safety.

Keep this implementation as small and understandable as possible. Do not build a generic static-analysis framework.

## 6. Minimal tests

Create an automated test runner with six C examples. Compile them to LLVM IR and analyze the IR; **never execute the test programs**.

| ID | Test | Expected |
|---|---|---|
| T01 | `getenv()` result passed directly to `system()` | Finding |
| T02 | Constant string passed to `system()` | No finding |
| T03 | Tainted value copied before reaching `system()` | Finding with flow path |
| T04 | Tainted value overwritten by a constant before the sink | No finding |
| T05 | One `if/else` branch assigns tainted input and the merged value reaches `system()` | Finding |
| T06 | Both branches assign clean values before the sink | No finding |

The runner must fail if the actual result differs from the expected result. Check that compiler failures are not ignored. Do not claim that six hand-written tests demonstrate real-world accuracy.

Also perform a small integration check: run the local server, submit the vulnerable example and safe example through `/api/analyze`, and confirm invalid C returns an error.

## 7. Use the research gap briefly

If `references/Review1.pdf` and `references/Review2.pdf` exist, skim the relevant project framing and related-work sections. Use Artemis/IRIS and other systems mentioned there only to explain, briefly, that research-grade analyzers offer broader capabilities while this project implements a small, transparent educational source-to-sink prototype. Do not spend significant time browsing papers or writing a long literature review. Do not claim novelty, comparative superiority, or accuracy unsupported by experiments.

## 8. One-session execution priorities

Work autonomously and avoid routine questions. Do not ask the user to run diagnostics one by one. Inspect the current project folder and reuse the already verified toolchain.

**Priority order:**
1. Build and run the real C++ analyzer on one vulnerable and one safe example.
2. Build the local backend so it compiles submitted C to IR and returns actual analyzer results.
3. Build the simple frontend and verify the full browser-to-analyzer flow.
4. Add and run the six tests; fix real failures.
5. Write a concise README and capture genuine screenshots if practical.

If the session budget becomes tight, preserve the functioning end-to-end path and core tests. Skip optional features and extended documentation. Do not stop after creating files that have not been built or tested. If a component cannot be completed, state that clearly rather than faking it.

## 9. Files to keep

Use a minimal structure and add only what is needed:

```text
compiler-security-analyzer/
├── PRD.md
├── README.md
├── CMakeLists.txt
├── src/
│   └── taint_analyzer.cpp
├── web/
│   ├── index.html
│   ├── style.css
│   └── app.js
├── server.py
├── test/
│   ├── cases/        # T01–T06
│   └── run_tests.sh
├── screenshots/      # genuine screenshots only, if available
└── build/            # generated files; ignored by Git
```

A `.gitignore` should exclude `build/`, generated LLVM IR, binaries, caches, and temporary request files. Do not create separate milestone logs, extensive research logs, redundant status documents, backup trees, or empty placeholder files. Keep only a concise `README.md` with setup/run instructions, architecture, supported check, actual test results, limitations, and a short related-work/gap paragraph.

## 10. Completion criteria

The MVP is complete only when evidence shows that:

1. The C++ analyzer builds against the installed LLVM 21 toolchain.
2. It analyzes fresh Clang-generated IR and performs actual taint/data-flow reasoning.
3. T01–T06 pass through the runner.
4. The local website sends code to the backend and displays the real analyzer result.
5. Vulnerable input produces a potential CWE-78 finding, safe input gives no finding under the stated rules, and invalid C gives an error.
6. The app never executes submitted C code.

At the end, print a brief summary with the exact run command, tests passed/failed, how to open the website, and any incomplete item. Keep the focus on a real, demonstrable project—not documentation volume or decorative UI.
