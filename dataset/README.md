# Sample Dataset

This folder contains six small, hand-written C programs used to demonstrate and test the prototype's supported `getenv() -> system()` taint-flow rule.

| File | Expected result | What it checks |
|---|---|---|
| T01_direct.c | Finding | Direct source-to-sink flow |
| T02_constant.c | Clean | Constant command passed to the sink |
| T03_copy.c | Finding | Taint propagation through assignments and cast |
| T04_overwrite.c | Clean | Tainted local overwritten with a constant |
| T05_branch_merge.c | Finding | Taint at an `if/else` PHI merge |
| T06_both_clean.c | Clean | Both branch values are constants |

These examples are duplicated in `test/cases/`, where the test runner reads them. The dataset is intentionally small and manually constructed; it is not a benchmark of real-world vulnerability detection. The programs are compiled to LLVM IR and analyzed, never executed by the analyzer.
