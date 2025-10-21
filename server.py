# server.py
# FastAPI server for Lean verifier + minimal registry-chain
# - Composition is SERVER-SIDE ONLY.
# - Loads verifier private key and Lean verifier URL from .env
# - Registry is an append-only JSON file (PoA by the verifier).

import os
import re
import json
import time
from typing import List, Dict, Optional, Tuple

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# HTTP client for calling your real Lean verifier
import requests

# Crypto utils
# (using eth_hash.auto.keccak so it will pick an installed backend; install: eth-hash[pycryptodome])
from eth_hash.auto import keccak
from eth_keys import keys
from eth_utils import to_checksum_address

# =========================
# Env & configuration
# =========================

load_dotenv()  # load .env before anything uses env vars

def _get_chain_path() -> str:
    # Prefer env, else default to .chains/chain.json
    p = os.environ.get("CHAIN_PATH", os.path.join(".chains", "chain.json"))
    d = os.path.dirname(p) or "."
    os.makedirs(d, exist_ok=True)
    return p


def _get_verifier_privkey_from_env() -> str:
    """
    Returns a hex private key string with 0x prefix.
    Validates length and hex.
    """
    pk = os.environ.get("VERIFIER_PRIVKEY", "").strip()
    if not pk:
        raise RuntimeError("VERIFIER_PRIVKEY not set (put it in a .env file)")
    if pk.startswith("0x"):
        body = pk[2:]
    else:
        body = pk
        pk = "0x" + pk
    if len(body) != 64:
        raise RuntimeError(f"VERIFIER_PRIVKEY must be 32 bytes (64 hex chars), got {len(body)}")
    try:
        bytes.fromhex(body)
    except ValueError:
        raise RuntimeError("VERIFIER_PRIVKEY is not valid hex")
    return pk

def _get_lean_verifier_url() -> str:
    url = os.environ.get("LEAN_VERIFIER_URL", "").strip()
    if not url:
        # default to your app.py as documented
        url = "http://127.0.0.1:8080/verify"
    return url

VERIFIER_PRIVKEY = _get_verifier_privkey_from_env()
LEAN_VERIFIER_URL = _get_lean_verifier_url()

# =========================
# Low-level helpers
# =========================

DOMAIN = b"LEMMA_V1"
LEMMA_RE = re.compile(r"\$(?:0x)?([0-9a-fA-F]{64})\b")

def keccak_hex(b: bytes) -> str:
    return "0x" + keccak(b).hex()

def canon_statement(s: str) -> bytes:
    # Minimal canonicalization for v0 (trim); can be improved to a Lean pretty-print later
    return s.strip().encode("utf-8")

def lemma_hash(statement: str, owner_addr: str, verifier_pubkey: bytes) -> str:
    """
    Hash binds (statement, owner, verifier identity) for replay protection and provenance.
    owner_addr must be EIP-55 string (0x + 40 hex).
    verifier_pubkey bytes: uncompressed public key (64 or 65 bytes supported; only data is hashed).
    """
    # Normalize owner to bytes (20B)
    owner_hex = owner_addr[2:] if owner_addr.startswith("0x") else owner_addr
    owner_bytes = bytes.fromhex(owner_hex.lower())
    # Normalize verifier_pubkey to raw 64 bytes if it comes as 65 (drop leading 0x04)
    if len(verifier_pubkey) == 65 and verifier_pubkey[0] == 4:
        verifier_pubkey = verifier_pubkey[1:]
    payload = DOMAIN + canon_statement(statement) + owner_bytes + verifier_pubkey
    return keccak_hex(payload)

# =========================
# Pydantic models (wire / chain)
# =========================

class Lemma(BaseModel):
    statement: str
    hash: str
    owner: str        # EIP-55 address (0x + 40 hex)
    signer: str       # verifier/producer address (EIP-55)

class Block(BaseModel):
    number: int
    timestamp: int
    prev_hash: str
    producer: str     # producer address
    lemmas: List[Lemma]
    producer_sig: str # hex signature over block header hash
    block_hash: str   # keccak(header-json)

# =========================
# Minimal registry-chain
# =========================

class Registry:
    """
    Append-only JSON blockchain with PoA (single trusted producer: the verifier).
    """
    def __init__(self, path: str = "chain.json",
                 trusted_producers: Optional[List[str]] = None,
                 producer_privkey_hex: Optional[str] = None):
        self.path = path
        self.blocks: List[Block] = []
        self.trusted = set([a.lower() for a in (trusted_producers or [])])

        # Initialize chain storage
        self._load_or_genesis()

        # Producer (verifier) key management
        self._priv: Optional[keys.PrivateKey] = None
        self.producer_pub: Optional[keys.PublicKey] = None
        self.producer_addr: Optional[str] = None

        if producer_privkey_hex:
            body = producer_privkey_hex[2:] if producer_privkey_hex.startswith("0x") else producer_privkey_hex
            self._priv = keys.PrivateKey(bytes.fromhex(body))
            self.producer_pub = self._priv.public_key
            # eth_keys PublicKey supports to_checksum_address()
            self.producer_addr = self.producer_pub.to_checksum_address()
            self.trusted.add(self.producer_addr.lower())

    def _persist(self) -> None:
        with open(self.path, "w") as f:
            json.dump([b.model_dump() for b in self.blocks], f, indent=2)

    def _load_or_genesis(self) -> None:
        if os.path.exists(self.path):
            with open(self.path) as f:
                raw = json.load(f)
            self.blocks = [Block(**b) for b in raw]
        else:
            g = Block(
                number=0,
                timestamp=int(time.time()),
                prev_hash="0x" + "00"*32,
                producer="0x" + "00"*20,
                lemmas=[],
                producer_sig="0x",
                block_hash="0x" + "11"*32,
            )
            self.blocks = [g]
            self._persist()

    def tip(self) -> Block:
        return self.blocks[-1]

    def get_lemma(self, h: str) -> Optional[Lemma]:
        h_l = h.lower()
        for b in self.blocks:
            for l in b.lemmas:
                if l.hash.lower() == h_l:
                    return l
        return None

    def verify_block_sig(self, block: Block) -> bool:
        # v0: trust by producer address allowlist
        return block.producer.lower() in self.trusted

    def add_block(self, lemmas: List[Lemma]) -> Block:
        if not self._priv or not self.producer_addr:
            raise RuntimeError("Registry has no producer key configured.")

        prev = self.tip()
        header = {
            "number": prev.number + 1,
            "timestamp": int(time.time()),
            "prev_hash": prev.block_hash,
            "producer": self.producer_addr,
            "lemmas": [l.model_dump() for l in lemmas],
        }
        # Deterministic header encoding
        header_bytes = json.dumps(header, separators=(",", ":"), sort_keys=True).encode()
        block_hash = keccak_hex(header_bytes)
        sig = self._priv.sign_msg_hash(bytes.fromhex(block_hash[2:]))

        block = Block(
            number=header["number"],
            timestamp=header["timestamp"],
            prev_hash=header["prev_hash"],
            producer=header["producer"],
            lemmas=lemmas,
            producer_sig="0x" + sig.to_bytes().hex(),
            block_hash=block_hash,
        )
        self.blocks.append(block)
        self._persist()
        return block

# =========================
# Composition & real Lean verification
# =========================

# Initialize global registry (uses key from .env)
reg = Registry(path=_get_chain_path(), producer_privkey_hex=VERIFIER_PRIVKEY)

def _fetch_and_validate_lemma(hash_hex: str) -> Lemma:
    """
    Looks up a lemma by hash and verifies it was produced by a trusted producer
    and that its hash recomputes from (statement, owner, verifier_pubkey).
    """
    if not hash_hex.startswith("0x"):
        hash_hex = "0x" + hash_hex

    lem = reg.get_lemma(hash_hex)
    if not lem:
        raise HTTPException(400, f"Referenced lemma {hash_hex} not found on-chain")

    # ensure lemma appears in a block by trusted producer
    trusted_ok = False
    for b in reg.blocks:
        if any(l.hash.lower() == hash_hex.lower() for l in b.lemmas):
            if reg.verify_block_sig(b):
                trusted_ok = True
                break
    if not trusted_ok:
        raise HTTPException(400, f"Lemma {hash_hex} not certified by a trusted producer")

    # recompute hash to defend against tampering
    verifier_pub_bytes = reg._priv.public_key.to_bytes() if reg._priv else b""  # type: ignore
    expected = lemma_hash(lem.statement, lem.owner, verifier_pub_bytes)
    if expected.lower() != lem.hash.lower():
        raise HTTPException(400, f"Lemma {hash_hex} failed hash re-computation")

    return lem

def _compose_code_server_side(statement: str, proof_template: str) -> str:
    """
    Server-only composition:
    - Extract $<hash> placeholders
    - Fetch and validate each lemma from the registry
    - Inject axioms and substitute placeholders with axiom names
    - Wrap in a Lean theorem
    """
    hashes = LEMMA_RE.findall(proof_template)
    used: set[str] = set()
    mapping: Dict[str, str] = {}
    axioms: List[str] = []

    for h in hashes:
        if h in used:
            continue
        used.add(h)
        lem = _fetch_and_validate_lemma("0x" + h.lower())
        short = h[:6].lower()
        ax_name = f"Lemma_h_{short}"
        mapping[h] = ax_name
        axioms.append(f"axiom {ax_name} : {lem.statement}")

    # Substitute $<hash> with axiom names
    def sub(m: re.Match) -> str:
        return mapping[m.group(1)]

    proof = LEMMA_RE.sub(sub, proof_template)

    code = "\n".join([
        "set_option autoImplicit true",
        "/- external lemmas from registry -/",
        *axioms,
        "",
        "/- user theorem -/",
        f"theorem user_thm : {statement} :=",
        f"  {proof}",
        ""
    ])
    return code

def compile_lean_via_http(code: str, module_name: Optional[str] = None) -> Tuple[bool, List[Dict]]:
    """
    Calls your real Lean verifier (app.py) over HTTP.
    Expects the /verify endpoint with {code, moduleName} and returns (ok, diagnostics).
    """
    try:
        r = requests.post(
            LEAN_VERIFIER_URL,
            json={"code": code, "moduleName": module_name},
            headers={"content-type": "application/json"},
            timeout=20,
        )
    except requests.RequestException as e:
        raise HTTPException(502, f"Lean verifier unreachable: {e}")

    if r.status_code != 200:
        # Pass through Lean service error text for clarity
        raise HTTPException(r.status_code, f"Lean verifier error: {r.text}")

    data = r.json()
    status = data.get("status")
    diags = data.get("diagnostics", [])
    ok = (status == "ok") and (not diags)
    return ok, diags

# =========================
# FastAPI app & endpoints
# =========================

app = FastAPI(title="Lean Verifier + Registry (server-side composition, real Lean)")

class VerifyAndRegisterRequest(BaseModel):
    statement: str = Field(..., description="Proposition only, e.g. 'True' or '∀ n : Nat, ...'")
    proof: str     = Field(..., description="Lean proof template with $<hash> placeholders")
    owner: str     = Field(..., description="EIP-55 address of the caller (0x + 40 hex)")

class VerifyAndRegisterResponse(BaseModel):
    status: str
    diagnostics: List[Dict] = []
    composed_code: Optional[str] = None
    lemma: Optional[Lemma] = None
    block_number: Optional[int] = None

@app.post("/verify_and_register", response_model=VerifyAndRegisterResponse)
def verify_and_register(req: VerifyAndRegisterRequest):
    # Basic checks
    if not (req.owner.startswith("0x") and len(req.owner) == 42):
        raise HTTPException(400, "Invalid owner address (expected 0x + 40 hex)")

    # 1) Compose (server-side)
    try:
        composed = _compose_code_server_side(req.statement, req.proof)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"Composition failed: {e}")

    # 2) Compile with real Lean verifier (HTTP call)
    try:
        ok, diags = compile_lean_via_http(composed, module_name="UserTheorem")
    except HTTPException:
        # pass through upstream error
        raise
    except Exception as e:
        raise HTTPException(500, f"Internal Lean verification failure: {e}")

    if not ok:
        return VerifyAndRegisterResponse(status="errors", diagnostics=diags, composed_code=composed)

    # 3) On success, compute lemma hash & append a block
    if not reg._priv:
        raise HTTPException(500, "Verifier key not configured in registry")

    verifier_pub = reg._priv.public_key.to_bytes()  # type: ignore
    h = lemma_hash(req.statement, req.owner, verifier_pub)
    lemma = Lemma(statement=req.statement, hash=h, owner=req.owner, signer=reg.producer_addr)  # type: ignore
    block = reg.add_block([lemma])

    return VerifyAndRegisterResponse(
        status="ok",
        diagnostics=[],
        composed_code=composed,
        lemma=lemma,
        block_number=block.number
    )

@app.get("/lemma/{hash_hex}", response_model=Lemma)
def get_lemma(hash_hex: str):
    if not hash_hex.startswith("0x"):
        hash_hex = "0x" + hash_hex
    lem = reg.get_lemma(hash_hex)
    if not lem:
        raise HTTPException(404, "Lemma not found")
    return lem

@app.get("/lemmas", response_model=List[Lemma])
def list_lemmas(owner: Optional[str] = None):
    out: List[Lemma] = []
    for b in reg.blocks:
        for l in b.lemmas:
            if owner and l.owner.lower() != owner.lower():
                continue
            out.append(l)
    return out
