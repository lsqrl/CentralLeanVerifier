# Lean Verifier (Core-Only) – FastAPI + warm `lean --server`

A tiny HTTP wrapper around a single warm **Lean 4** LSP server (`lean --server`) designed for **core-only** proofs. No Lake/Mathlib required. External facts (validated by your own infra) can be injected as **axioms** (capsules) and composed inside Lean for deterministic checking.

> Status: PoC-ready. One warm worker. Easy to extend into a worker pool.

---

## Why core-only?

- **Simplicity**: no `lakefile.lean`, no `Mathlib` downloads, no dependency pains.
- **Security**: Lean is a pure checker; all networking, signatures, and policy decisions happen *outside* Lean.
- **Determinism**: you pin Lean via `elan`; the server runs one version, forever, with no imports.

If you later need richer math, run the same API inside a Lake project and switch the worker command to `lake env lean --server`.

---

## Project layout

```
lean-verifier/
├─ app.py                 # FastAPI server (warm Lean worker over stdio/LSP)
├─ test_client.py         # Runs smoke tests (happy path, errors, capsule, etc.)
├─ requirements.txt       # fastapi, uvicorn, pydantic (optional: requests)
├─ scripts/
│  └─ run-dev.sh          # local run helper
└─ .lsp/                  # virtual docs (auto-created)
```

---

## Prerequisites

- **Lean 4** installed via `elan` and available on your PATH.
  ```bash
  lean --version
  ```
- **Python 3.10+**

*(No Lake/Mathlib required for core-only mode.)*

---

## Quick start

1) Create and activate a virtualenv, install deps:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
```

2) Run the server:
```bash
mkdir -p .lsp
uvicorn app:app --host 0.0.0.0 --port 8080 --reload
```

3) Smoke test with `curl`:

- Trivial theorem
  ```bash
  curl -s localhost:8080/verify     -H 'content-type: application/json'     --data-binary '{"code":"theorem triv : True := True.intro
"}' | jq
  ```

- Error example
  ```bash
  curl -s localhost:8080/verify     -H 'content-type: application/json'     --data-binary '{"code":"theorem boom : True := by exact False.elim ?h
"}' | jq
  ```

- Disallow `sorry`/`admit`
  ```bash
  curl -s localhost:8080/verify     -H 'content-type: application/json'     --data-binary '{"code":"theorem fake : True := by admit
"}' | jq
  ```

- Minimal capsule (axiom) + usage
  ```bash
  curl -s localhost:8080/verify     -H 'content-type: application/json'     --data-binary '{"code":"axiom capsule : True
theorem uses_capsule : True := capsule
"}' | jq
  ```

- Namespaced capsule
  ```bash
  curl -s localhost:8080/verify     -H 'content-type: application/json'     --data-binary '{"code":"namespace External
axiom thm_hABCD1234 : ∀ n : Nat, n % 2 = 0 → ∃ k, n = 2*k
end External
open External
theorem even_has_half (n : Nat) (h : n % 2 = 0) : ∃ k, n = 2*k :=
  thm_hABCD1234 n h
"}' | jq
  ```

- Invalid import (expected error without Lake/Mathlib)
  ```bash
  curl -s localhost:8080/verify     -H 'content-type: application/json'     --data-binary '{"code":"import Mathlib
#check Nat
"}' | jq
  ```

---

## Run all tests with `test_client.py`

```bash
# server must be running
python test_client.py
# or point to remote
LEAN_VERIFIER_URL="http://host:8080/verify" python test_client.py
```

`test_client.py` covers:
- Happy path (`theorem triv`)
- Intentional error
- `sorry` rejection
- Minimal capsule
- Namespaced capsule
- Import failure (message matched robustly: “invalid import” or “unknown module prefix”)

---

## API

### `POST /verify`

**Request**
```json
{
  "code": "Lean code string",
  "moduleName": "Optional.lean"
}
```

**Response**
```json
{
  "status": "ok" | "errors",
  "diagnostics": [
    {
      "message": "...",
      "range": { "start": {"line":0,"character":0}, "end": {"line":0,"character":0} },
      "severity": 1,
      "source": "Lean 4"
    }
  ]
}
```

- `status = ok` ➜ empty diagnostics array
- `status = errors` ➜ one or more diagnostics from Lean LSP

---

## Capsule (axiom) policy (recommended)

External verified facts should be injected as tiny axioms with names tied to a **hash** of the verified statement and metadata:

```lean
namespace External
/-- auto capsule: hash h<HEX> ; verifiers: ... ; toolchain: 4.24.0 -/
axiom thm_h<HEX> : P
end External

open External
-- use thm_h<HEX> in downstream theorems
```

**Hardening tips** (enforce in your HTTP layer before sending to Lean):

- **Block user-defined axioms** unless their names match your capsule pattern (`External.thm_h[0-9A-F]+`).
- **Reject any `sorry`/`admit`**: treat the corresponding warning diagnostic as a hard error.
- Optionally append `#print axioms yourTheorem` and ensure reported axioms ⊆ your permitted capsule set.

---

## Internals

- A single **warm** `lean --server` process is spawned on startup.
- The server speaks JSON-RPC/LSP over **stdio** (no sockets in Lean).
- Each request opens a virtual doc (`textDocument/didOpen`), collects diagnostics, then closes it.
- Concurrency is serialized with a mutex; extend to a **pool** for throughput.

To switch to a Lake/Mathlib project later:
- Set `cwd` in `LeanWorker` to your project root.
- Run `["lake","env","lean","--server"]` instead of `["lean","--server"]`.

---

## Ops & Security checklist

- Containerize with CPU/memory limits and `--network=none` for untrusted inputs.
- Limit code size (set in `app.py`; default ~2MB).
- Per-request timeout (10–15s is sensible for PoC).
- Log Lean toolchain version in responses if you need provenance.
- Put FastAPI behind HTTPS (nginx/Caddy) if exposed.

---

## License

MIT