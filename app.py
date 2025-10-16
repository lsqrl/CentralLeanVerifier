# app.py
# FastAPI + single warm Lean worker (stdio/LSP). Run with: uvicorn app:app --port 8080
import json, os, queue, subprocess, threading, time, uuid
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# ------------------ Lean worker (stdio JSON-RPC) ------------------
def _write_msg(proc, obj):
    data = json.dumps(obj).encode("utf-8")
    proc.stdin.write(f"Content-Length: {len(data)}\r\n\r\n".encode("utf-8"))
    proc.stdin.write(data)
    proc.stdin.flush()

def _reader(proc, out_q):
    # Minimal LSP frame reader
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
            out_q.put(json.loads(body))
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

@app.on_event("shutdown")
def _shutdown():
    if worker:
        worker.shutdown()

@app.post("/verify", response_model=VerifyResp)
def verify(req: VerifyReq):
    if not req.code or len(req.code) > 2_000_000:
        raise HTTPException(400, "code is missing or too large")
    try:
        diags = worker.check_code(req.code, module_name=req.moduleName, timeout_s=10.0)
    except TimeoutError:
        raise HTTPException(504, "verification timed out")
    except Exception as e:
        raise HTTPException(500, f"internal error: {e}")
    return {
        "status": "ok" if not diags else "errors",
        "diagnostics": diags
    }
