#!/usr/bin/env python3
"""Start server.py, send three requests to /api/analyze, check the answers.

  vulnerable example -> finding (CWE-78)
  safe example       -> clean
  invalid C          -> error
"""

import json
import os
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = os.environ.get("PORT", "8765")
BASE = f"http://127.0.0.1:{PORT}"

VULNERABLE = '#include <stdlib.h>\nint main(void){ char *c = getenv("X"); char *r = c; system(r); return 0; }\n'
SAFE = '#include <stdlib.h>\nint main(int n, char **v){ char *c = getenv("X"); if (n > 1) c = "ls"; else c = "date"; system(c); return 0; }\n'
INVALID = 'int main(void) { this is not C; }\n'


def post(source):
    req = urllib.request.Request(
        BASE + "/api/analyze",
        data=json.dumps({"source": source}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def main():
    env = dict(os.environ, PORT=PORT)
    proc = subprocess.Popen([sys.executable, os.path.join(ROOT, "server.py")], env=env)
    try:
        for _ in range(50):
            try:
                urllib.request.urlopen(BASE + "/api/health", timeout=1)
                break
            except OSError:
                time.sleep(0.2)
        else:
            print("FAIL server did not start")
            return 1

        failures = 0
        for name, src, expected in [
            ("vulnerable", VULNERABLE, "finding"),
            ("safe", SAFE, "clean"),
            ("invalid C", INVALID, "error"),
            ("file include blocked", '#include "/etc/passwd"\nint main(void){return 0;}\n', "error"),
            ("spliced include blocked", '#inc\\\nlude "/etc/hostname"\nint main(void){return 0;}\n', "error"),
            ("spliced embed blocked", 'const char d[] = {\n#em\\\nbed "/etc/hostname"\n};\nint main(void){return 0;}\n', "error"),
        ]:
            res = post(src)
            ok = res.get("status") == expected
            if ok and expected == "finding":
                ok = res["findings"][0]["cwe"] == "CWE-78"
            print(("PASS" if ok else "FAIL"), name, "->", json.dumps(res)[:300])
            failures += 0 if ok else 1

        page = urllib.request.urlopen(BASE + "/", timeout=5).read().decode()
        ok = "Analyze" in page
        print(("PASS" if ok else "FAIL"), "index.html served")
        failures += 0 if ok else 1

        print(f"\n{7 - failures} passed, {failures} failed")
        return 1 if failures else 0
    finally:
        proc.terminate()
        proc.wait(timeout=5)


if __name__ == "__main__":
    sys.exit(main())
