#!/usr/bin/env python3
"""Local backend for the taint analyzer.

Serves web/ and one endpoint, POST /api/analyze, which compiles the submitted
C source to LLVM IR (clang, then opt -passes=mem2reg) and runs the C++
analyzer on it. Submitted code is never executed.

Run:  python3 server.py            (http://127.0.0.1:8000)
"""

import json
import os
import shutil
import subprocess
import sys
import uuid
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(ROOT, "web")
BUILD_DIR = os.path.join(ROOT, "build")
REQ_DIR = os.path.join(BUILD_DIR, "requests")

HOST = "127.0.0.1"
PORT = int(os.environ.get("PORT", "8000"))
CLANG = os.environ.get("CLANG", "clang")
OPT = os.environ.get("OPT", "opt")
ANALYZER = os.environ.get("ANALYZER", os.path.join(BUILD_DIR, "taint_analyzer"))

MAX_SOURCE_BYTES = 20_000
STEP_TIMEOUT_S = 15

# Pages allowed to call this server from another origin (the hosted UI).
ALLOWED_ORIGINS = {
    "https://compiler-security-analyzer.netlify.app",
    "http://127.0.0.1:8000",
    "http://localhost:8000",
}
ALLOWED_ORIGINS.update(o for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o)


def run_step(args, cwd):
    """Run one pipeline step with an argument list (never a shell)."""
    return subprocess.run(
        args, cwd=cwd, capture_output=True, text=True,
        timeout=STEP_TIMEOUT_S, shell=False,
    )


def trim(text, limit=4000):
    text = (text or "").strip()
    return text if len(text) <= limit else text[:limit] + "\n..."


def analyze_source(source):
    """Compile C source to IR and analyze it. Returns a JSON-able dict."""
    work = os.path.join(REQ_DIR, uuid.uuid4().hex)
    os.makedirs(work)
    try:
        with open(os.path.join(work, "input.c"), "w", encoding="utf-8") as f:
            f.write(source)

        # -disable-O0-optnone lets mem2reg run on -O0 output.
        clang = run_step([
            CLANG, "-S", "-emit-llvm", "-O0", "-g",
            "-Xclang", "-disable-O0-optnone",
            "-fno-discard-value-names",
            "input.c", "-o", "input.ll",
        ], work)
        if clang.returncode != 0:
            return {"status": "error", "stage": "compile",
                    "error": trim(clang.stderr) or "clang failed"}

        opt = run_step([OPT, "-S", "-passes=mem2reg", "input.ll", "-o", "input.opt.ll"], work)
        if opt.returncode != 0:
            return {"status": "error", "stage": "mem2reg",
                    "error": trim(opt.stderr) or "opt failed"}

        res = run_step([ANALYZER, "input.opt.ll"], work)
        try:
            result = json.loads(res.stdout)
        except json.JSONDecodeError:
            return {"status": "error", "stage": "analyze",
                    "error": trim(res.stderr or res.stdout) or "analyzer returned no JSON"}
        if res.returncode != 0 and result.get("status") != "error":
            return {"status": "error", "stage": "analyze", "error": trim(res.stderr)}
        result["warnings"] = trim(clang.stderr)
        return result
    except subprocess.TimeoutExpired:
        return {"status": "error", "stage": "timeout",
                "error": f"a pipeline step took longer than {STEP_TIMEOUT_S}s"}
    except FileNotFoundError as e:
        return {"status": "error", "stage": "toolchain", "error": f"tool not found: {e.filename}"}
    finally:
        shutil.rmtree(work, ignore_errors=True)


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def cors_headers(self):
        origin = self.headers.get("Origin")
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            # Chrome Private/Local Network Access: hosted page -> 127.0.0.1
            self.send_header("Access-Control-Allow-Private-Network", "true")

    def send_json(self, code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.cors_headers()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.cors_headers()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        if self.path == "/api/health":
            return self.send_json(200, {"ok": True})
        return super().do_GET()

    def do_POST(self):
        if self.path != "/api/analyze":
            return self.send_json(404, {"status": "error", "error": "not found"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_SOURCE_BYTES * 2:
            return self.send_json(413, {"status": "error", "error": "request empty or too large"})
        try:
            data = json.loads(self.rfile.read(length))
            source = data["source"]
            if not isinstance(source, str):
                raise TypeError
        except (ValueError, KeyError, TypeError):
            return self.send_json(400, {"status": "error", "error": "expected JSON {\"source\": \"...\"}"})
        if not source.strip():
            return self.send_json(400, {"status": "error", "error": "source is empty"})
        if len(source.encode("utf-8")) > MAX_SOURCE_BYTES:
            return self.send_json(413, {"status": "error",
                                        "error": f"source is over {MAX_SOURCE_BYTES} bytes"})
        self.send_json(200, analyze_source(source))


def main():
    if not os.path.exists(ANALYZER):
        sys.exit(f"analyzer not built: {ANALYZER}\nrun: cmake -S . -B build -G Ninja && cmake --build build")
    os.makedirs(REQ_DIR, exist_ok=True)
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Serving on http://{HOST}:{PORT}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
