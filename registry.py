# registry.py
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional
import time, json, os, hashlib
from eth_keys import keys  # pip install eth-keys eth-utils
from eth_utils import keccak, to_bytes, to_checksum_address

DOMAIN = b"LEMMA_V1"

def keccak_hex(b: bytes) -> str:
    return "0x" + keccak(b).hex()

def eth_address_from_pubkey(pubkey_bytes: bytes) -> str:
    # pubkey is uncompressed 64 or 65 bytes -> use 64-byte x||y
    if len(pubkey_bytes) == 65 and pubkey_bytes[0] in (4,):
        pubkey_bytes = pubkey_bytes[1:]
    return to_checksum_address(keccak(pubkey_bytes)[12:])  # last 20 bytes

def canon_statement(s: str) -> bytes:
    return s.strip().encode("utf-8")

def lemma_hash(statement: str, owner_addr: str, verifier_pubkey: bytes) -> str:
    b = DOMAIN + canon_statement(statement) + bytes.fromhex(owner_addr[2:].lower()) + verifier_pubkey
    return keccak_hex(b)

@dataclass
class Lemma:
    statement: str
    hash: str
    owner: str       # EIP-55 string
    signer: str      # verifier address

@dataclass
class Block:
    number: int
    timestamp: int
    prev_hash: str
    producer: str
    lemmas: List[Lemma]
    producer_sig: str
    block_hash: str

class Registry:
    def __init__(self, path="chain.json"):
        self.path = path
        self.blocks: List[Block] = []
        if os.path.exists(path):
            self._load()
        else:
            self._genesis()

    def _genesis(self):
        g = Block(0, int(time.time()), "0x"+"00"*32, "0x"+"00"*20, [], "0x", "0x"+"11"*32)
        self.blocks = [g]
        self._persist()

    def _persist(self):
        with open(self.path, "w") as f:
            json.dump([asdict(b) for b in self.blocks], f, indent=2)

    def _load(self):
        with open(self.path) as f:
            raw = json.load(f)
        self.blocks = [Block(**{
            **b, "lemmas": [Lemma(**l) for l in b["lemmas"]]
        }) for b in raw]

    def tip(self) -> Block:
        return self.blocks[-1]

    def get_lemma(self, h: str) -> Optional[Lemma]:
        for b in self.blocks:
            for l in b.lemmas:
                if l.hash.lower() == h.lower():
                    return l
        return None

    def add_block(self, producer_addr: str, producer_sign_fn, lemmas: List[Lemma]) -> Block:
        prev = self.tip()
        header = {
            "number": prev.number + 1,
            "timestamp": int(time.time()),
            "prev_hash": prev.block_hash,
            "producer": producer_addr,
            "lemmas": [asdict(x) for x in lemmas],
        }
        # block_hash over canonical JSON header (no sig/hash fields)
        header_bytes = json.dumps(header, separators=(",", ":"), sort_keys=True).encode()
        block_hash = keccak_hex(header_bytes)
        sig = producer_sign_fn(bytes.fromhex(block_hash[2:]))
        b = Block(header["number"], header["timestamp"], header["prev_hash"],
                  header["producer"], lemmas, sig, block_hash)
        self.blocks.append(b)
        self._persist()
        return b
