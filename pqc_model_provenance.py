#!/usr/bin/env python3
"""
Post-Quantum Model Provenance - a live demonstration.

Securing AI Assets Before Q-Day: signing a model artefact and its AI Bill of
Materials (AIBOM) so the provenance survives the arrival of a cryptographically
relevant quantum computer.

The script shows four things, in order:
  1. A model registry that signs a model artefact + AIBOM and verifies them.
  2. Crypto-agility: the same registry API switching between a classical
     signature (ECDSA), a post-quantum signature (ML-DSA / Dilithium), and a
     hybrid of the two, by changing one configuration string.
  3. Tamper-evidence: altering the weights or the signature is detected.
  4. A comparison of the schemes on key size, signature size, and cost.

The teaching point: classical signatures on model artefacts, AIBOMs and update
channels are forgeable by a quantum computer. Migrating model provenance to
post-quantum signatures, with crypto-agility and a hybrid transition, is an
action available today - not a 2035 problem.

Dependencies (pure-Python, pip-installable):
    pip install dilithium-py cryptography
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.exceptions import InvalidSignature

from dilithium_py.ml_dsa import ML_DSA_65


# --------------------------------------------------------------------------- #
# Signer abstraction - the crypto-agility seam.
# Every scheme implements the same interface, so the registry never needs to
# know which algorithm it is using. Swapping the algorithm is a one-line change.
# --------------------------------------------------------------------------- #
class Signer(Protocol):
    name: str
    category: str

    def keygen(self) -> tuple[bytes, bytes]: ...
    def sign(self, message: bytes, secret_key: bytes) -> bytes: ...
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool: ...


class ClassicalECDSA:
    """Classical signature - quantum-vulnerable. Here for comparison and hybrid."""

    name = "ECDSA-P256"
    category = "classical (quantum-vulnerable)"

    def keygen(self) -> tuple[bytes, bytes]:
        sk = ec.generate_private_key(ec.SECP256R1())
        sk_bytes = sk.private_numbers().private_value.to_bytes(32, "big")
        pub = sk.public_key()
        pk_bytes = pub.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        return pk_bytes, sk_bytes

    def _load_sk(self, secret_key: bytes):
        value = int.from_bytes(secret_key, "big")
        return ec.derive_private_key(value, ec.SECP256R1())

    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        sk = self._load_sk(secret_key)
        der = sk.sign(message, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        try:
            pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key)
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:64], "big")
            der = encode_dss_signature(r, s)
            pub.verify(der, message, ec.ECDSA(hashes.SHA256()))
            return True
        except (InvalidSignature, ValueError):
            return False


class PostQuantumMLDSA:
    """ML-DSA-65 (FIPS 204, lattice-based) - the NIST primary signature standard."""

    name = "ML-DSA-65"
    category = "post-quantum (lattice)"

    def keygen(self) -> tuple[bytes, bytes]:
        return ML_DSA_65.keygen()  # (public_key, secret_key)

    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        return ML_DSA_65.sign(secret_key, message)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        return ML_DSA_65.verify(public_key, message, signature)


class HybridECDSAandMLDSA:
    """
    Hybrid signature - the NCSC-recommended transition posture.
    A forger must break BOTH schemes, so the artefact stays protected if either
    the classical or the post-quantum algorithm later falls.
    """

    name = "Hybrid (ECDSA + ML-DSA-65)"
    category = "hybrid (transition)"

    def __init__(self) -> None:
        self._c = ClassicalECDSA()
        self._p = PostQuantumMLDSA()

    def keygen(self) -> tuple[bytes, bytes]:
        cpk, csk = self._c.keygen()
        ppk, psk = self._p.keygen()
        return _concat(cpk, ppk), _concat(csk, psk)

    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        csk, psk = _split(secret_key)
        return _concat(self._c.sign(message, csk), self._p.sign(message, psk))

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        cpk, ppk = _split(public_key)
        csig, psig = _split(signature)
        return self._c.verify(message, csig, cpk) and self._p.verify(message, psig, ppk)


# length-prefixed concat/split so two byte-strings travel as one
def _concat(a: bytes, b: bytes) -> bytes:
    return len(a).to_bytes(4, "big") + a + b


def _split(blob: bytes) -> tuple[bytes, bytes]:
    n = int.from_bytes(blob[:4], "big")
    return blob[4 : 4 + n], blob[4 + n :]


SIGNERS: dict[str, Signer] = {
    "classical": ClassicalECDSA(),
    "pqc": PostQuantumMLDSA(),
    "hybrid": HybridECDSAandMLDSA(),
}


# --------------------------------------------------------------------------- #
# The model registry - signs a manifest binding the weights to the AIBOM.
# --------------------------------------------------------------------------- #
@dataclass
class RegistryEntry:
    manifest: bytes
    signature: bytes
    algorithm: str
    public_key: bytes


@dataclass
class ModelRegistry:
    """A minimal model registry with crypto-agile, signed provenance."""

    profile: str  # "classical" | "pqc" | "hybrid" - the crypto-agility switch
    _store: dict[str, RegistryEntry] = field(default_factory=dict)
    _keys: dict[str, bytes] = field(default_factory=dict)  # algorithm -> secret key

    def _signer(self) -> Signer:
        return SIGNERS[self.profile]

    def _manifest(self, model_id: str, version: str, weights: bytes, aibom: dict) -> bytes:
        doc = {
            "model_id": model_id,
            "version": version,
            "weights_sha256": hashlib.sha256(weights).hexdigest(),
            "aibom_sha256": hashlib.sha256(_canonical(aibom)).hexdigest(),
            "signed_with": self._signer().name,
        }
        return _canonical(doc)

    def register(self, model_id: str, version: str, weights: bytes, aibom: dict) -> None:
        signer = self._signer()
        if signer.name not in self._keys:
            pk, sk = signer.keygen()
            self._keys[signer.name] = sk
            self._pk = pk  # demo: single signing identity
        manifest = self._manifest(model_id, version, weights, aibom)
        signature = signer.sign(manifest, self._keys[signer.name])
        self._store[model_id] = RegistryEntry(manifest, signature, signer.name, self._pk)

    def verify(self, model_id: str, weights: bytes, aibom: dict, version: str) -> bool:
        entry = self._store[model_id]
        signer = self._signer()
        # 1) integrity: does the artefact still match what was signed?
        expected = self._manifest(model_id, version, weights, aibom)
        if expected != entry.manifest:
            return False
        # 2) authenticity: is the signature valid under the registry's key?
        return signer.verify(entry.manifest, entry.signature, entry.public_key)


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


# --------------------------------------------------------------------------- #
# Demonstration
# --------------------------------------------------------------------------- #
def make_artefact() -> tuple[bytes, dict]:
    """A stand-in model artefact (random 'weights') and a small AIBOM."""
    weights = os.urandom(4 * 1024 * 1024)  # 4 MB of pseudo-weights
    aibom = {
        "model": "deepcyber-triage-llm",
        "version": "1.4.0",
        "base_model": "open-weights-7b",
        "training_data": ["incident-corpus-2025", "synthetic-redteam-set"],
        "components": [
            {"name": "tokenizer", "version": "2.1"},
            {"name": "adapter-lora", "version": "0.9"},
        ],
        "licence": "proprietary",
    }
    return weights, aibom


def banner(title: str) -> None:
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def demo_sign_and_verify(weights: bytes, aibom: dict) -> None:
    banner("1. Sign and verify a model artefact + AIBOM, under each profile")
    for profile in ("classical", "pqc", "hybrid"):
        reg = ModelRegistry(profile=profile)
        reg.register("deepcyber-triage-llm", "1.4.0", weights, aibom)
        ok = reg.verify("deepcyber-triage-llm", weights, aibom, "1.4.0")
        print(f"  [{profile:>8}] signed with {reg._signer().name:<28} verify -> {ok}")


def demo_crypto_agility(weights: bytes, aibom: dict) -> None:
    banner("2. Crypto-agility: one switch moves the whole registry")
    print("  The registry is configured by a single profile string.")
    print("  Migrating from classical to post-quantum is a config change,")
    print("  not a rewrite - this is what 'crypto-agile' means in practice.\n")
    for profile in ("classical", "hybrid", "pqc"):
        reg = ModelRegistry(profile=profile)
        reg.register("m", "1.0", weights, aibom)
        print(f"  profile='{profile}'  ->  provenance now signed with {reg._signer().name}")


def demo_tamper(weights: bytes, aibom: dict) -> None:
    banner("3. Tamper-evidence: altering the model or the signature is caught")
    reg = ModelRegistry(profile="pqc")
    reg.register("m", "1.0", weights, aibom)
    print(f"  clean artefact, untouched          verify -> {reg.verify('m', weights, aibom, '1.0')}")

    tampered = bytearray(weights)
    tampered[123] ^= 0x01  # flip one bit in the 'weights'
    print(f"  one bit flipped in the weights     verify -> {reg.verify('m', bytes(tampered), aibom, '1.0')}")

    aibom_tampered = dict(aibom)
    aibom_tampered["training_data"] = aibom["training_data"] + ["undisclosed-set"]
    print(f"  AIBOM quietly edited               verify -> {reg.verify('m', weights, aibom_tampered, '1.0')}")

    forged = reg._store["m"]
    forged.signature = bytearray(forged.signature)
    forged.signature[5] ^= 0x01  # corrupt the signature
    print(f"  signature corrupted                verify -> {reg.verify('m', weights, aibom, '1.0')}")


def demo_comparison(weights: bytes, aibom: dict, rounds: int = 20) -> None:
    banner("4. Comparison: key size, signature size, and cost")
    manifest = ModelRegistry(profile="pqc")._manifest("m", "1.0", weights, aibom)

    rows = []
    for label in ("classical", "pqc", "hybrid"):
        s = SIGNERS[label]
        pk, sk = s.keygen()
        t0 = time.perf_counter()
        for _ in range(rounds):
            sig = s.sign(manifest, sk)
        sign_ms = (time.perf_counter() - t0) / rounds * 1000
        t0 = time.perf_counter()
        for _ in range(rounds):
            s.verify(manifest, sig, pk)
        verify_ms = (time.perf_counter() - t0) / rounds * 1000
        rows.append((s.name, s.category, len(pk), len(sig), sign_ms, verify_ms, True))

    # SLH-DSA reference figures (FIPS 205, SLH-DSA-SHA2-128f) - published, not measured here.
    rows.append(("SLH-DSA-128f *", "post-quantum (hash) *", 32, 17088, None, None, False))

    print(f"\n  {'scheme':<30}{'type':<26}{'pub key':>9}{'sig':>9}{'sign':>10}{'verify':>10}")
    print("  " + "-" * 94)
    for name, cat, pk, sig, sm, vm, measured in rows:
        sm_s = f"{sm:7.2f}ms" if sm is not None else "    ref"
        vm_s = f"{vm:7.2f}ms" if vm is not None else "    ref"
        print(f"  {name:<30}{cat:<26}{pk:>7}B{sig:>8}B{sm_s:>10}{vm_s:>10}")
    print("\n  * SLH-DSA row shows published reference sizes (not measured in this run):")
    print("    tiny public key, large signature - the hash-based tradeoff, on the most")
    print("    conservative security assumptions. ML-DSA is the balanced default.")
    print("\n  Note on timings: ML-DSA here uses a pure-Python reference implementation,")
    print("  so the millisecond figures are dominated by interpreter overhead. An")
    print("  optimised native library (e.g. liboqs) signs and verifies ML-DSA in well")
    print("  under a millisecond. The durable takeaway is the SIZE tradeoff, not these")
    print("  absolute times - do not present the raw timings as representative.")


def main() -> None:
    print("Post-Quantum Model Provenance - Securing AI Assets Before Q-Day")
    print("Demonstrates crypto-agile signing of a model artefact and its AIBOM.")
    weights, aibom = make_artefact()
    print(f"\nArtefact: {len(weights)//(1024*1024)} MB of weights + AIBOM for "
          f"'{aibom['model']}' v{aibom['version']}")

    demo_sign_and_verify(weights, aibom)
    demo_crypto_agility(weights, aibom)
    demo_tamper(weights, aibom)
    demo_comparison(weights, aibom)

    banner("What this shows")
    print("  - Model provenance can be signed and verified today with NIST")
    print("    post-quantum signatures (ML-DSA), via the same API as classical.")
    print("  - A hybrid signature gives a safe transition: secure unless BOTH")
    print("    the classical and post-quantum schemes are broken.")
    print("  - Tampering with weights, the AIBOM, or the signature is detected.")
    print("  - The migration is a crypto-agility exercise, available now -")
    print("    not a problem to defer to 2035.\n")


if __name__ == "__main__":
    main()
