# test_e2e_registry_repo.py
import os
import sys
import json
import shutil
from pathlib import Path
from time import perf_counter, strftime

from fastapi.testclient import TestClient
from eth_keys import keys
import server  # uses .env for VERIFIER_PRIVKEY and LEAN_VERIFIER_URL

# ---------- pretty printing helpers ----------
def color(s, c):
    codes = {"g":"\033[32m","r":"\033[31m","y":"\033[33m","c":"\033[36m","b":"\033[34m","m":"\033[35m","reset":"\033[0m"}
    return f"{codes.get(c,'')}{s}{codes['reset']}"

def header(title):
    print(color(f"\n=== {title} ===", "c"))

def kv(k, v):
    print(color(f"{k}: ", "y") + f"{v}")

def jprint(obj, label=None, maxlen=None):
    s = json.dumps(obj, indent=2, ensure_ascii=False)
    if maxlen and len(s) > maxlen:
        s = s[:maxlen] + "… (truncated)"
    if label:
        print(color(label + ":", "b"))
    print(s)

def snippet(text, lines=25):
    arr = text.splitlines()
    if len(arr) > lines:
        arr = arr[:lines] + ["… (truncated)"]
    return "\n".join(arr)

def make_fixed_priv(byte_val: int) -> keys.PrivateKey:
    return keys.PrivateKey(bytes([byte_val]) * 32)

# ---------- chain writers ----------
def chain_as_list():
    return [b.model_dump() for b in server.reg.blocks]  # full chain

def write_chain_pretty(path: Path):
    """Overwrite with the whole chain (pretty JSON array)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(chain_as_list(), indent=2), encoding="utf-8")

def append_chain_snapshot_jsonl(path: Path, tag: str):
    """Append one line: {"tag": ..., "chain": [...]} to snapshots.jsonl."""
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps({"tag": tag, "chain": chain_as_list()}, ensure_ascii=False)
    with path.open("a", encoding="utf-8") as f:
        f.write(line + "\n")

def run_repo_e2e():
    _t0 = perf_counter()

    # --- Resolve repo paths
    repo_root = Path(__file__).parent
    chains_dir = repo_root / ".chains"
    chains_dir.mkdir(exist_ok=True)

    chain_path = chains_dir / "chain.e2e.json"               # canonical chain file in .chains
    artifacts_dir = repo_root / "_e2e_artifacts"
    snapshots_jsonl = artifacts_dir / "chain.snapshots.jsonl" # append-only snapshots log

    # per-step artifacts
    composed1_out = artifacts_dir / "composed.1.lean"
    composed2_out = artifacts_dir / "composed.2.lean"
    req1_out = artifacts_dir / "request.1.json"
    resp1_out = artifacts_dir / "response.1.json"
    req2_out = artifacts_dir / "request.2.json"
    resp2_out = artifacts_dir / "response.2.json"

    artifacts_dir.mkdir(exist_ok=True)

    header("Config")
    kv("Repo root", str(repo_root))
    kv("Chain path", str(chain_path))
    kv("Snapshots", str(snapshots_jsonl))
    kv("VERIFIER_PRIVKEY", os.environ.get("VERIFIER_PRIVKEY", "<not set>"))
    kv("LEAN_VERIFIER_URL", os.environ.get("LEAN_VERIFIER_URL", "http://127.0.0.1:8080/verify"))

    # --- Backup existing chain if present (keep backups in .chains too)
    if chain_path.exists():
        backup = chain_path.with_suffix(".json.bak-" + strftime("%Y%m%d-%H%M%S"))
        shutil.copy2(chain_path, backup)
        kv("Existing chain backed up to", str(backup))

    # Reset snapshots file (start a fresh log for this run)
    if snapshots_jsonl.exists():
        snapshots_jsonl.unlink()

    # --- Initialize registry to point to .chains/chain.e2e.json
    header("Initialize registry in repo (.chains)")
    server.reg = server.Registry(
        path=str(chain_path),
        producer_privkey_hex=server.VERIFIER_PRIVKEY,
    )
    kv("Producer address", server.reg.producer_addr)
    kv("Chain file (.chains)", str(chain_path))
    # First snapshot: genesis only
    write_chain_pretty(chain_path)
    append_chain_snapshot_jsonl(snapshots_jsonl, tag="genesis")

    client = TestClient(server.app)

    # --- Deterministic owner
    header("Create owner address")
    owner_priv = make_fixed_priv(0x22)
    owner_addr = owner_priv.public_key.to_checksum_address()
    kv("Owner address", owner_addr)

    # ============================================================
    # STEP 0: Seed chain with a useful lemma (Block #1)
    # Lemma: ∀ n : Nat, n = n
    # ============================================================
    header("Seed chain with initial lemma (block #1)")
    lemma_stmt_0 = "∀ n : Nat, n = n"
    l0_hash = server.lemma_hash(
        lemma_stmt_0,
        owner_addr,
        server.reg._priv.public_key.to_bytes(),  # type: ignore
    )
    lemma0 = server.Lemma(
        statement=lemma_stmt_0,
        hash=l0_hash,
        owner=owner_addr,
        signer=server.reg.producer_addr,  # type: ignore
    )
    block1 = server.reg.add_block([lemma0])  # block #1 (genesis is #0)
    kv("Block #", block1.number)
    jprint(block1.model_dump(), "Block #1 summary", maxlen=800)
    # Snapshot after seeding
    write_chain_pretty(chain_path)
    append_chain_snapshot_jsonl(snapshots_jsonl, tag="after_block_1")

    # ============================================================
    # STEP 1: Prove 0 = 0 using the lemma
    # Proof: by exact $<l0_hash> 0
    # ============================================================
    header("STEP 1 — POST /verify_and_register (prove 0 = 0 using ∀n, n=n)")
    req1 = {
        "statement": "0 = 0",
        "proof": "by exact $" + l0_hash[2:] + " 0",
        "owner": owner_addr,
    }
    jprint(req1, "Request #1")
    req1_out.write_text(json.dumps(req1, indent=2), encoding="utf-8")

    r1 = client.post("/verify_and_register", json=req1)
    kv("HTTP", f"{r1.status_code}")
    if r1.status_code != 200:
        print(color(r1.text, "r"))
        sys.exit(1)
    data1 = r1.json()
    jprint(data1, "Response #1", maxlen=2000)
    resp1_out.write_text(json.dumps(data1, indent=2), encoding="utf-8")
    composed1_out.write_text(data1["composed_code"], encoding="utf-8")

    assert data1["status"] == "ok", "Expected status=ok for step 1"
    assert "Lemma_h_" in data1["composed_code"], "Missing injected lemma (step 1)"
    s1_hash = data1["lemma"]["hash"]

    header("Composed Lean code (STEP 1, first lines)")
    print(snippet(data1["composed_code"], lines=30))

    # Snapshot after sealing step 1 (Block #2)
    write_chain_pretty(chain_path)
    append_chain_snapshot_jsonl(snapshots_jsonl, tag="after_block_2")

    # ============================================================
    # STEP 2: Prove 0 = 0 ∧ 0 = 0 using theorem #1 twice
    # Proof: by exact And.intro ($<s1_hash>) ($<s1_hash>)
    # ============================================================
    header("STEP 2 — POST /verify_and_register (prove 0=0 ∧ 0=0 using prior lemma)")
    req2 = {
        "statement": "0 = 0 ∧ 0 = 0",
        "proof": "by exact And.intro ($" + s1_hash[2:] + ") ($" + s1_hash[2:] + ")",
        "owner": owner_addr,
    }
    jprint(req2, "Request #2")
    req2_out.write_text(json.dumps(req2, indent=2), encoding="utf-8")

    r2 = client.post("/verify_and_register", json=req2)
    kv("HTTP", f"{r2.status_code}")
    if r2.status_code != 200:
        print(color(r2.text, "r"))
        sys.exit(1)
    data2 = r2.json()
    jprint(data2, "Response #2", maxlen=2000)
    resp2_out.write_text(json.dumps(data2, indent=2), encoding="utf-8")
    composed2_out.write_text(data2["composed_code"], encoding="utf-8")

    assert data2["status"] == "ok", "Expected status=ok for step 2"
    assert "Lemma_h_" in data2["composed_code"], "Missing injected lemma (step 2)"

    header("Composed Lean code (STEP 2, first lines)")
    print(snippet(data2["composed_code"], lines=30))

    # Snapshot after sealing step 2 (Block #3)
    write_chain_pretty(chain_path)
    tip = server.reg.tip()  # type: ignore
    append_chain_snapshot_jsonl(snapshots_jsonl, tag=f"after_block_{tip.number}")

    # --- Read endpoints quick sanity
    header("GET /lemmas?owner=… (final)")
    r_list = client.get(f"/lemmas?owner={owner_addr}")
    kv("HTTP", r_list.status_code)
    lemmas = r_list.json()
    kv("Total lemmas for owner", len(lemmas))

    # --- Finalize (pretty copy of entire chain for easy reading)
    pretty_copy = artifacts_dir / "chain.pretty.json"
    write_chain_pretty(pretty_copy)

    header("Artifacts written")
    kv("Canonical chain (.chains)", str(chain_path))
    kv("Snapshots (JSONL, each line = full chain)", str(snapshots_jsonl))
    kv("Pretty chain copy", str(pretty_copy))
    kv("Composed #1", str(composed1_out))
    kv("Composed #2", str(composed2_out))
    kv("Requests / Responses", f"{req1_out} , {resp1_out} , {req2_out} , {resp2_out}")

    print(color("\nDONE — Open .chains/chain.e2e.json or _e2e_artifacts/chain.pretty.json to inspect the entire chain.", "g"))


if __name__ == "__main__":
    run_repo_e2e()
