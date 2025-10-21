# app.py
# FastAPI + single warm Lean worker (stdio/LSP). Run with: uvicorn app:app --port 8080
import json, os, queue, subprocess, threading, time, uuid, logging, re
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# ------------------ Logging setup ------------------
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
log = logging.getLogger("lean.app")
LOG_LSP = os.getenv("APP_LOG_LSP", "0") == "1"
SAVE_LAST = os.getenv("APP_SAVE_LAST", "0") == "1"

def _shorten(s: str, n: int = 200) -> str:
    return s if len(s) <= n else s[:n] + "…"

# Extract the first theorem signature: "theorem NAME : TYPE :="
_THEOREM_RE = re.compile(
    r"^\s*theorem\s+([^\s:]+)\s*:\s*(.+?)\s*:=",
    re.MULTILINE | re.DOTALL,
)

def extract_first_theorem_signature(code: str) -> str | None:
    m = _THEOREM_RE.search(code)
    if not m:
        return None
    name, ty = m.group(1), m.group(2).strip()
    # collapse whitespace on the type to keep it readable in logs
    ty_one_line = re.sub(r"\s+", " ", ty)
    return f"theorem {name} : {ty_one_line}"

# ------------------ Lean worker (stdio JSON-RPC) ------------------
def _write_msg(proc, obj):
    data = json.dumps(obj).encode("utf-8")
    if LOG_LSP:
        logging.getLogger("lean.lsp").debug("SEND %s", _shorten(json.dumps(obj)))
    proc.stdin.write(f"Content-Length: {len(data)}\r\n\r\n".encode("utf-8"))
    proc.stdin.write(data)
    proc.stdin.flush()

def _reader(proc, out_q):
    # Minimal LSP frame reader
    lsp_log = logging.getLogger("lean.lsp")
    while True:
        # headers
        headers = {}
        line = proc.stdout.readline()
        if not line:
            break
        while line.strip():
            k, v = line.decode().split(":", 1)
            headers[k.lower()] = v.strip()
            line = proc.stdout.readline()
        clen = int(headers.get("content-length", "0"))
        if clen <= 0:
            continue
        body = proc.stdout.read(clen)
        try:
            obj = json.loads(body)
            if LOG_LSP:
                lsp_log.debug("RECV %s", _shorten(json.dumps(obj)))
            out_q.put(obj)
        except Exception:
            pass

class LeanWorker:
    def __init__(self, cwd="."):
        self.cwd = cwd
        # If your project needs lake deps, you can use: ["lake", "env", "lean", "--server"]
        self.proc = subprocess.Popen(
            ["lean", "--server"],
            cwd=self.cwd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        log.info("Started Lean server pid=%s cwd=%s", self.proc.pid, os.path.abspath(self.cwd))
        self.out_q = queue.Queue()
        self.reader = threading.Thread(target=_reader, args=(self.proc, self.out_q), daemon=True)
        self.reader.start()
        self._rpc_id = 0
        self.root_uri = f"file://{os.path.abspath(self.cwd)}"
        self._lock = threading.Lock()  # serialize access (Lean expects coherent sessions)
        self._initialize()

    def _rpc(self, method, params=None, want_reply=True, deadline_s=5.0):
        self._rpc_id += 1
        msg_id = self._rpc_id
        _write_msg(self.proc, {"jsonrpc":"2.0","id":msg_id,"method":method,"params":params or {}})
        if not want_reply:
            return None
        t0 = time.time()
        while time.time() - t0 < deadline_s:
            try:
                msg = self.out_q.get(timeout=0.1)
            except queue.Empty:
                continue
            if "id" in msg and msg["id"] == msg_id:
                return msg
        raise TimeoutError(f"RPC {method} timed out")

    def _notify(self, method, params=None):
        _write_msg(self.proc, {"jsonrpc":"2.0","method":method,"params":params or {}})

    def _initialize(self):
        self._rpc("initialize", {
            "processId": None,
            "rootUri": self.root_uri,
            "capabilities": {},
        })
        self._notify("initialized", {})
        log.info("Lean LSP initialized rootUri=%s", self.root_uri)

    def check_code(self, code: str, module_name: str = None, timeout_s: float = 8.0):
        """
        Open a virtual doc, wait for diagnostics to settle or timeout, close it, return diagnostics list.
        """
        with self._lock:
            # unique virtual URI so parallel opens don't clash (even though we lock)
            name = module_name or f"Scratch_{uuid.uuid4().hex}.lean"
            uri = f"{self.root_uri}/.lsp/{name}"

            # didOpen
            self._notify("textDocument/didOpen", {
                "textDocument": {
                    "uri": uri,
                    "languageId": "lean4",
                    "version": 1,
                    "text": code,
                }
            })

            # collect diagnostics for this uri until quiet or timeout
            diags = None
            t0 = time.time()
            last_update = 0.0
            quiet_ms = 180  # small quiet window to let Lean settle
            while time.time() - t0 < timeout_s:
                try:
                    msg = self.out_q.get(timeout=0.15)
                except queue.Empty:
                    if diags is not None and (time.time() - last_update) >= (quiet_ms/1000.0):
                        break
                    continue
                if msg.get("method") == "textDocument/publishDiagnostics":
                    p = msg.get("params", {})
                    if p.get("uri") == uri:
                        diags = p.get("diagnostics", [])
                        last_update = time.time()
                # ignore other notifications

            # didClose
            self._notify("textDocument/didClose", {"textDocument": {"uri": uri}})
            return diags if diags is not None else []

    def shutdown(self):
        try:
            self._rpc("shutdown", None, want_reply=True, deadline_s=2.0)
        except Exception:
            pass
        try:
            self._notify("exit", None)
        except Exception:
            pass
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.stdout.close()
        except Exception:
            pass
        try:
            self.proc.stderr.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=2)
        except Exception:
            self.proc.kill()
        log.info("Lean server stopped")

# ------------------ FastAPI wiring ------------------
app = FastAPI()
worker: LeanWorker | None = None

class VerifyReq(BaseModel):
    code: str
    moduleName: str | None = None

class VerifyResp(BaseModel):
    status: str
    diagnostics: list

@app.on_event("startup")
def _startup():
    global worker
    os.makedirs(".lsp", exist_ok=True)
    # If your project needs Mathlib/deps, point cwd to the project root
    worker = LeanWorker(cwd=".")  # change to your lean project root if needed
    log.info("App startup complete (SAVE_LAST=%s, LOG_LSP=%s)", SAVE_LAST, LOG_LSP)

@app.on_event("shutdown")
def _shutdown():
    if worker:
        worker.shutdown()

@app.post("/verify", response_model=VerifyResp)
def verify(req: VerifyReq):
    if not req.code or len(req.code) > 2_000_000:
        raise HTTPException(400, "code is missing or too large")

    # Extract a readable statement and context for logging
    theorem_sig = extract_first_theorem_signature(req.code) or "<no theorem found>"
    lines = req.code.count("\n") + 1
    chars = len(req.code)
    mod = req.moduleName or "<auto>"

    if SAVE_LAST:
        try:
            with open(".lsp/_last_verified.lean", "w", encoding="utf-8") as f:
                f.write(req.code)
        except Exception as e:
            log.warning("Failed to save last verified code: %s", e)

    log.info("VERIFY start module=%s lines=%d chars=%d theorem=%s",
             mod, lines, chars, _shorten(theorem_sig, 240))

    t0 = time.time()
    try:
        diags = worker.check_code(req.code, module_name=req.moduleName, timeout_s=10.0)
    except TimeoutError:
        log.error("VERIFY timeout module=%s theorem=%s", mod, _shorten(theorem_sig, 240))
        raise HTTPException(504, "verification timed out")
    except Exception as e:
        log.exception("VERIFY internal error module=%s theorem=%s", mod, _shorten(theorem_sig, 240))
        raise HTTPException(500, f"internal error: {e}")

    dt = (time.time() - t0) * 1000.0
    status = "ok" if not diags else "errors"
    log.info("VERIFY done module=%s status=%s diags=%d time=%.1fms theorem=%s",
             mod, status, len(diags), dt, _shorten(theorem_sig, 240))

    return {
        "status": status,
        "diagnostics": diags
    }
