// taint_analyzer.cpp
// Small intraprocedural taint analysis over LLVM IR.
//
//   Source: return value of getenv()
//   Sink:   argument 0 of system()
//   Report: potential command-injection flow (CWE-78)
//
// Input:  an LLVM IR file (.ll) produced by clang and cleaned up by
//         `opt -passes=mem2reg`.
// Output: one JSON object on stdout.
//
// Educational prototype. It does not do alias analysis, loops beyond what
// SSA/PHI already expresses, or interprocedural analysis.

#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugProgramInstruction.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <cstdio>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

using namespace llvm;

namespace {

std::string jsonEscape(const std::string &s) {
  std::string out;
  for (char c : s) {
    switch (c) {
    case '"': out += "\\\""; break;
    case '\\': out += "\\\\"; break;
    case '\n': out += "\\n"; break;
    case '\r': out += "\\r"; break;
    case '\t': out += "\\t"; break;
    default:
      if (static_cast<unsigned char>(c) < 0x20) {
        char buf[8];
        snprintf(buf, sizeof(buf), "\\u%04x", c);
        out += buf;
      } else {
        out += c;
      }
    }
  }
  return out;
}

// "null" when debug info has no usable line, never 0.
std::string lineJson(const Instruction *I) {
  if (!I) return "null";
  const DebugLoc &DL = I->getDebugLoc();
  if (!DL || DL.getLine() == 0) return "null";
  return std::to_string(DL.getLine());
}

const Function *directCallee(const CallBase *CB) {
  return dyn_cast_or_null<Function>(CB->getCalledOperand()->stripPointerCasts());
}

bool isCallTo(const Instruction &I, StringRef name) {
  const auto *CB = dyn_cast<CallBase>(&I);
  if (!CB) return false;
  const Function *F = directCallee(CB);
  return F && F->getName() == name;
}

struct FunctionAnalysis {
  // tainted value -> the operand it got taint from (nullptr for a source)
  std::map<const Value *, const Value *> parent;
  // SSA value -> source-level variable names that hold it (from #dbg_value)
  std::map<const Value *, std::vector<std::string>> varNames;
};

void collectVarNames(const Function &F, FunctionAnalysis &A) {
  for (const BasicBlock &BB : F) {
    for (const Instruction &I : BB) {
      for (const DbgVariableRecord &DVR : filterDbgVars(I.getDbgRecordRange())) {
        if (!DVR.isDbgValue() && !DVR.isDbgDeclare()) continue;
        const DILocalVariable *Var = DVR.getVariable();
        if (!Var) continue;
        std::string name = Var->getName().str();
        for (const Value *V : DVR.location_ops()) {
          auto &names = A.varNames[V];
          bool seen = false;
          for (auto &n : names) seen |= (n == name);
          if (!seen) names.push_back(name);
        }
      }
    }
  }
}

// Value-producing instructions that carry taint from an operand to the result.
bool propagates(const Instruction &I) {
  return isa<CastInst>(I) || isa<PHINode>(I) || isa<SelectInst>(I) ||
         isa<GetElementPtrInst>(I) || isa<BinaryOperator>(I) ||
         isa<FreezeInst>(I);
}

void runTaint(const Function &F, FunctionAnalysis &A) {
  // Seeds.
  for (const BasicBlock &BB : F)
    for (const Instruction &I : BB)
      if (isCallTo(I, "getenv")) A.parent[&I] = nullptr;

  // Fixpoint: a PHI may be visited before its incoming value becomes tainted.
  bool changed = true;
  while (changed) {
    changed = false;
    for (const BasicBlock &BB : F) {
      for (const Instruction &I : BB) {
        if (A.parent.count(&I) || !propagates(I)) continue;
        for (const Use &U : I.operands()) {
          const Value *Op = U.get();
          if (A.parent.count(Op)) {
            A.parent[&I] = Op;
            changed = true;
            break;
          }
        }
      }
    }
  }
}

struct PathStep {
  std::string label;
  std::string kind; // source | variable | operation | sink
  std::string line; // JSON number or null
};

// Walk provenance from the sink argument back to the getenv() call.
std::vector<PathStep> buildPath(const Value *arg, const Instruction *sink,
                                const FunctionAnalysis &A,
                                const Instruction *&sourceOut) {
  std::vector<const Value *> chain;
  std::set<const Value *> visited;
  const Value *cur = arg;
  while (cur && !visited.count(cur)) {
    visited.insert(cur);
    chain.push_back(cur);
    auto it = A.parent.find(cur);
    if (it == A.parent.end()) break;
    cur = it->second;
  }
  std::reverse(chain.begin(), chain.end()); // source first

  std::vector<PathStep> steps;
  std::set<std::string> namesShown;
  sourceOut = nullptr;
  for (const Value *V : chain) {
    const auto *I = dyn_cast<Instruction>(V);
    if (I && isCallTo(*I, "getenv")) {
      sourceOut = I;
      steps.push_back({"getenv()", "source", lineJson(I)});
    } else if (const auto *Phi = dyn_cast_or_null<PHINode>(I)) {
      steps.push_back({"if/else merge (PHI)", "operation", lineJson(Phi)});
    } else if (I && isa<CastInst>(I)) {
      steps.push_back({"cast", "operation", lineJson(I)});
    } else if (I && isa<GetElementPtrInst>(I)) {
      steps.push_back({"pointer offset", "operation", lineJson(I)});
    } else if (I && isa<SelectInst>(I)) {
      steps.push_back({"conditional select", "operation", lineJson(I)});
    } else if (I) {
      steps.push_back({I->getOpcodeName(), "operation", lineJson(I)});
    }
    auto nIt = A.varNames.find(V);
    if (nIt != A.varNames.end()) {
      for (const auto &n : nIt->second) {
        if (namesShown.insert(n).second) steps.push_back({n, "variable", "null"});
      }
    }
  }
  steps.push_back({"system() arg 0", "sink", lineJson(sink)});
  return steps;
}

} // namespace

int main(int argc, char **argv) {
  if (argc != 2) {
    std::cout << "{\"status\":\"error\",\"error\":\"usage: taint_analyzer <file.ll>\"}\n";
    return 2;
  }

  LLVMContext Ctx;
  SMDiagnostic Err;
  std::unique_ptr<Module> M = parseIRFile(argv[1], Err, Ctx);
  if (!M) {
    std::string msg;
    raw_string_ostream os(msg);
    Err.print("taint_analyzer", os);
    std::cout << "{\"status\":\"error\",\"error\":\"" << jsonEscape(os.str()) << "\"}\n";
    return 2;
  }

  std::ostringstream findings;
  int count = 0;
  int functions = 0;
  int sinks = 0;
  int sources = 0;

  for (const Function &F : *M) {
    if (F.isDeclaration()) continue;
    ++functions;
    FunctionAnalysis A;
    collectVarNames(F, A);
    runTaint(F, A);
    for (auto &kv : A.parent)
      if (!kv.second) ++sources;

    for (const BasicBlock &BB : F) {
      for (const Instruction &I : BB) {
        if (!isCallTo(I, "system")) continue;
        ++sinks;
        const auto *CB = cast<CallBase>(&I);
        if (CB->arg_size() < 1) continue;
        const Value *arg = CB->getArgOperand(0);
        if (!A.parent.count(arg)) continue;

        const Instruction *src = nullptr;
        std::vector<PathStep> path = buildPath(arg, &I, A, src);

        if (count++) findings << ",";
        findings << "{\"cwe\":\"CWE-78\","
                 << "\"title\":\"Potential command injection\","
                 << "\"function\":\"" << jsonEscape(F.getName().str()) << "\","
                 << "\"source\":{\"call\":\"getenv()\",\"line\":" << lineJson(src) << "},"
                 << "\"sink\":{\"call\":\"system()\",\"arg\":0,\"line\":" << lineJson(&I) << "},"
                 << "\"path\":[";
        for (size_t i = 0; i < path.size(); ++i) {
          if (i) findings << ",";
          findings << "{\"label\":\"" << jsonEscape(path[i].label) << "\",\"kind\":\""
                   << path[i].kind << "\",\"line\":" << path[i].line << "}";
        }
        findings << "]}";
      }
    }
  }

  std::cout << "{\"status\":\"" << (count ? "finding" : "clean") << "\","
            << "\"stats\":{\"functions\":" << functions << ",\"sources\":" << sources
            << ",\"sinks\":" << sinks << "},"
            << "\"findings\":[" << findings.str() << "]}\n";
  return 0;
}
