#!/usr/bin/env python3
import json, os, sys, time

# Try to use requests; fall back to stdlib if missing
try:
    import requests
    HAVE_REQUESTS = True
except Exception:
    import urllib.request
    HAVE_REQUESTS = False

API_URL = os.environ.get("LEAN_VERIFIER_URL", "http://localhost:8080/verify")

# --- tiny helpers ---
def post_code(code: str):
    payload = {"code": code}
    data = json.dumps(payload).encode("utf-8")
    if HAVE_REQUESTS:
        r = requests.post(API_URL, data=data, headers={"content-type":"application/json"}, timeout=20)
        r.raise_for_status()
        return r.json()
    else:
        req = urllib.request.Request(API_URL, data=data, headers={"content-type":"application/json"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode("utf-8"))

def color(s, c):
    # simple ANSI colors
    codes = {"g":"\033[32m","r":"\033[31m","y":"\033[33m","c":"\033[36m","b":"\033[34m","reset":"\033[0m"}
    return f"{codes.get(c,'')}{s}{codes['reset']}"

def run(name, code, expect_status=None, expect_diag_contains=None):
    print(color(f"\n=== {name} ===", "c"))
    print(code)
    try:
        res = post_code(code)
    except Exception as e:
        print(color(f"[HTTP ERROR] {e}", "r"))
        return False

    print("Response:", json.dumps(res, indent=2, ensure_ascii=False))

    ok = True
    if expect_status is not None:
        if res.get("status") != expect_status:
            print(color(f"Expected status '{expect_status}', got '{res.get('status')}'", "r"))
            ok = False

    if expect_diag_contains is not None:
        # Flatten diagnostic messages
        msgs = []
        for d in res.get("diagnostics", []):
            msg = d.get("message","")
            if msg:
                msgs.append(msg)
        blob = "\n".join(msgs)
        if expect_diag_contains not in blob:
            print(color(f"Expected diagnostics to contain: {expect_diag_contains!r}", "r"))
            ok = False

    print(color("PASS" if ok else "FAIL", "g" if ok else "r"))
    return ok

def main():
    total = 0
    passed = 0

    tests = [
        {
            "name": "Happy path: trivial theorem (core-only)",
            "code": "theorem triv : True := True.intro\n",
            "expect_status": "ok",
        },
        {
            "name": "Intentional error",
            "code": "theorem boom : True := by exact False.elim ?h\n",
            "expect_status": "errors",
        },
        {
            "name": "Disallow sorry/admit",
            "code": "theorem fake : True := by admit\n",
            "expect_status": "errors",
            "expect_diag_contains": "sorry",  # Lean usually says: declaration uses 'sorry'
        },
        {
            "name": "Minimal capsule axiom",
            "code": "axiom capsule : True\ntheorem uses_capsule : True := capsule\n",
            "expect_status": "ok",
        },
        {
            "name": "Namespaced capsule axiom",
            "code": (
                "namespace External\n"
                "axiom thm_hABCD1234 : ∀ n : Nat, n % 2 = 0 → ∃ k, n = 2*k\n"
                "end External\n"
                "open External\n"
                "theorem even_has_half (n : Nat) (h : n % 2 = 0) : ∃ k, n = 2*k :=\n"
                "  thm_hABCD1234 n h\n"
            ),
            "expect_status": "ok",
        },
        {
            "name": "Invalid import without Lake/Mathlib (expected error)",
            "code": "import Mathlib\n#check Nat\n",
            "expect_status": "errors",
            "expect_diag_contains": "unknown module prefix",
        },
    ]

    print(color(f"Using API: {API_URL} (requests={'yes' if HAVE_REQUESTS else 'no'})", "y"))

    for t in tests:
        total += 1
        ok = run(
            t["name"],
            t["code"],
            expect_status=t.get("expect_status"),
            expect_diag_contains=t.get("expect_diag_contains"),
        )
        if ok:
            passed += 1
        # tiny pause so logs are readable
        time.sleep(0.1)

    print(color(f"\nSummary: {passed}/{total} tests passed", "b" if passed==total else "y"))
    sys.exit(0 if passed == total else 1)

if __name__ == "__main__":
    main()
