#!/usr/bin/env python3
"""
Harvest-Now, Decrypt-Later - a live demonstration.

Securing AI Assets Before Q-Day: the confidentiality half of the session.

The threat is timing. An adversary who captures an encrypted model artefact today
can store the ciphertext and decrypt it once a cryptographically relevant quantum
computer (CRQC) exists. Because model weights and regulated training data have
confidentiality lifetimes measured in years, an exfiltration recorded now is a
deferred breach: the loss has happened, even though the plaintext is not yet
exposed. Whether it stays confidential depends on which key-establishment scheme
protected it at the moment of capture.

This script shows:
  1. Encrypting a model artefact under a recipient key, with three profiles:
     classical (ECDH-P256), post-quantum (ML-KEM-768, FIPS 203), and a hybrid.
  2. The harvest-now-decrypt-later picture: all three decrypt for the legitimate
     recipient today, but only post-quantum / hybrid stay confidential after Q-Day.
  3. Tamper-evidence via the authenticated-encryption tag.
  4. A comparison of the schemes on key size, encapsulation size, and cost.

Dependencies (pure-Python, pip-installable):
    pip install kyber-py cryptography
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from kyber_py.ml_kem import ML_KEM_768


def _derive_key(shared: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared)


def _concat(a: bytes, b: bytes) -> bytes:
    return len(a).to_bytes(4, "big") + a + b


def _split(blob: bytes) -> tuple[bytes, bytes]:
    n = int.from_bytes(blob[:4], "big")
    return blob[4 : 4 + n], blob[4 + n :]


# --------------------------------------------------------------------------- #
# Encryptor abstraction - the crypto-agility seam (mirrors the signing demo).
# Each profile establishes a session key, then AES-256-GCM encrypts the artefact.
# --------------------------------------------------------------------------- #
class ClassicalECDH:
    name = "ECDH-P256 + AES-256-GCM"
    category = "classical (quantum-vulnerable)"
    quantum_safe = False

    def keygen(self) -> tuple[bytes, bytes]:
        sk = ec.generate_private_key(ec.SECP256R1())
        pk = sk.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        skb = sk.private_numbers().private_value.to_bytes(32, "big")
        return pk, skb

    def encrypt(self, public_key: bytes, plaintext: bytes) -> bytes:
        recipient_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key)
        eph = ec.generate_private_key(ec.SECP256R1())
        shared = eph.exchange(ec.ECDH(), recipient_pub)
        key = _derive_key(shared, b"classical")
        nonce = os.urandom(12)
        eph_pub = eph.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        ct = AESGCM(key).encrypt(nonce, plaintext, None)
        return _concat(eph_pub, nonce + ct)

    def decrypt(self, secret_key: bytes, envelope: bytes) -> bytes:
        eph_pub, rest = _split(envelope)
        nonce, ct = rest[:12], rest[12:]
        sk = ec.derive_private_key(int.from_bytes(secret_key, "big"), ec.SECP256R1())
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), eph_pub)
        shared = sk.exchange(ec.ECDH(), peer)
        key = _derive_key(shared, b"classical")
        return AESGCM(key).decrypt(nonce, ct, None)


class PostQuantumMLKEM:
    name = "ML-KEM-768 + AES-256-GCM"
    category = "post-quantum (lattice)"
    quantum_safe = True

    def keygen(self) -> tuple[bytes, bytes]:
        return ML_KEM_768.keygen()  # (encapsulation key, decapsulation key)

    def encrypt(self, public_key: bytes, plaintext: bytes) -> bytes:
        shared, kem_ct = ML_KEM_768.encaps(public_key)
        key = _derive_key(shared, b"pqc")
        nonce = os.urandom(12)
        ct = AESGCM(key).encrypt(nonce, plaintext, None)
        return _concat(kem_ct, nonce + ct)

    def decrypt(self, secret_key: bytes, envelope: bytes) -> bytes:
        kem_ct, rest = _split(envelope)
        nonce, ct = rest[:12], rest[12:]
        shared = ML_KEM_768.decaps(secret_key, kem_ct)
        key = _derive_key(shared, b"pqc")
        return AESGCM(key).decrypt(nonce, ct, None)


class HybridECDHandMLKEM:
    """
    Hybrid KEM - the NCSC / IETF transition posture. The session key is derived
    from BOTH a classical ECDH secret and an ML-KEM secret, so the artefact stays
    confidential unless an adversary breaks both.
    """

    name = "Hybrid (ECDH + ML-KEM-768) + AES-256-GCM"
    category = "hybrid (transition)"
    quantum_safe = True

    def __init__(self) -> None:
        self._c = ClassicalECDH()
        self._p = PostQuantumMLKEM()

    def keygen(self) -> tuple[bytes, bytes]:
        cpk, csk = self._c.keygen()
        ppk, psk = self._p.keygen()
        return _concat(cpk, ppk), _concat(csk, psk)

    def encrypt(self, public_key: bytes, plaintext: bytes) -> bytes:
        cpk, ppk = _split(public_key)
        recipient_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), cpk)
        eph = ec.generate_private_key(ec.SECP256R1())
        ecdh_shared = eph.exchange(ec.ECDH(), recipient_pub)
        kem_shared, kem_ct = ML_KEM_768.encaps(ppk)
        key = _derive_key(ecdh_shared + kem_shared, b"hybrid")
        nonce = os.urandom(12)
        eph_pub = eph.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        ct = AESGCM(key).encrypt(nonce, plaintext, None)
        return _concat(_concat(eph_pub, kem_ct), nonce + ct)

    def decrypt(self, secret_key: bytes, envelope: bytes) -> bytes:
        csk, psk = _split(secret_key)
        head, rest = _split(envelope)
        eph_pub, kem_ct = _split(head)
        nonce, ct = rest[:12], rest[12:]
        sk = ec.derive_private_key(int.from_bytes(csk, "big"), ec.SECP256R1())
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), eph_pub)
        ecdh_shared = sk.exchange(ec.ECDH(), peer)
        kem_shared = ML_KEM_768.decaps(psk, kem_ct)
        key = _derive_key(ecdh_shared + kem_shared, b"hybrid")
        return AESGCM(key).decrypt(nonce, ct, None)


ENCRYPTORS = {
    "classical": ClassicalECDH(),
    "pqc": PostQuantumMLKEM(),
    "hybrid": HybridECDHandMLKEM(),
}


# --------------------------------------------------------------------------- #
# Demonstration
# --------------------------------------------------------------------------- #
def make_artefact() -> bytes:
    return os.urandom(4 * 1024 * 1024)  # 4 MB stand-in for model weights


def banner(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def demo_roundtrip(weights: bytes) -> None:
    banner("1. Encrypt the model artefact under each profile, then decrypt")
    for profile in ("classical", "pqc", "hybrid"):
        enc = ENCRYPTORS[profile]
        pk, sk = enc.keygen()
        envelope = enc.encrypt(pk, weights)
        recovered = enc.decrypt(sk, envelope)
        print(f"  [{profile:>8}] {enc.name:<42} roundtrip -> {recovered == weights}")


def demo_harvest_now(weights: bytes) -> None:
    banner("2. Harvest-now, decrypt-later: who is still protected after Q-Day?")
    print("  An adversary records the encrypted artefact and the public material")
    print("  TODAY, and waits. Every profile decrypts for the legitimate recipient")
    print("  now; what differs is whether the harvested ciphertext stays secret")
    print("  once a cryptographically relevant quantum computer exists.\n")
    print(f"  {'profile':<10}{'recipient decrypts today':<28}{'confidential after Q-Day?'}")
    print("  " + "-" * 70)
    verdicts = {
        "classical": "NO - public key yields the session key (Shor)",
        "pqc": "yes - no efficient quantum attack known",
        "hybrid": "yes - unless BOTH schemes are broken",
    }
    for profile in ("classical", "pqc", "hybrid"):
        enc = ENCRYPTORS[profile]
        pk, sk = enc.keygen()
        envelope = enc.encrypt(pk, weights)
        ok_today = enc.decrypt(sk, envelope) == weights
        print(f"  {profile:<10}{('yes' if ok_today else 'no'):<28}{verdicts[profile]}")
    print("\n  The classical row is the harvest-now-decrypt-later breach: an artefact")
    print("  protected this way and captured today is readable the moment a CRQC")
    print("  arrives. Long-lived model IP must be PQ- or hybrid-wrapped before capture,")
    print("  because protection cannot be applied retroactively to stolen ciphertext.")


def demo_tamper(weights: bytes) -> None:
    banner("3. Tamper-evidence: altering the ciphertext is caught")
    enc = ENCRYPTORS["hybrid"]
    pk, sk = enc.keygen()
    envelope = bytearray(enc.encrypt(pk, weights))
    try:
        enc.decrypt(sk, bytes(envelope))
        print("  clean ciphertext            decrypt -> ok")
    except Exception as e:
        print(f"  clean ciphertext            decrypt -> unexpected error: {e}")
    envelope[-1] ^= 0x01  # corrupt the final ciphertext/tag byte
    try:
        enc.decrypt(sk, bytes(envelope))
        print("  one byte flipped            decrypt -> NOT caught (unexpected)")
    except Exception:
        print("  one byte flipped            decrypt -> rejected (authentication failed)")


def demo_comparison(weights: bytes, rounds: int = 10) -> None:
    banner("4. Comparison: key size, encapsulation size, and cost")
    print(f"\n  {'scheme':<42}{'pub key':>9}{'encaps':>9}{'encrypt':>10}{'decrypt':>10}")
    print("  " + "-" * 80)
    for label in ("classical", "pqc", "hybrid"):
        enc = ENCRYPTORS[label]
        pk, sk = enc.keygen()
        env = enc.encrypt(pk, weights)
        overhead = len(env) - len(weights)  # bytes added beyond the AES-GCM payload
        t0 = time.perf_counter()
        for _ in range(rounds):
            env = enc.encrypt(pk, weights)
        enc_ms = (time.perf_counter() - t0) / rounds * 1000
        t0 = time.perf_counter()
        for _ in range(rounds):
            enc.decrypt(sk, env)
        dec_ms = (time.perf_counter() - t0) / rounds * 1000
        print(f"  {enc.name:<42}{len(pk):>7}B{overhead:>8}B{enc_ms:>8.2f}ms{dec_ms:>8.2f}ms")
    print("\n  'encaps' is the key-establishment overhead added to the artefact; the AES")
    print("  payload itself is the same size in every profile. Timings include AES-GCM")
    print("  over 4 MB and are dominated by it; ML-KEM key-establishment is sub-millisecond")
    print("  in an optimised native library. The size overhead is the durable comparison.")


def main() -> None:
    print("Harvest-Now, Decrypt-Later - Securing AI Assets Before Q-Day")
    print("Confidentiality of a model artefact across the quantum transition.")
    weights = make_artefact()
    print(f"\nArtefact: {len(weights)//(1024*1024)} MB stand-in for model weights")

    demo_roundtrip(weights)
    demo_harvest_now(weights)
    demo_tamper(weights)
    demo_comparison(weights)

    banner("What this shows")
    print("  - A model artefact can be wrapped today with NIST post-quantum key")
    print("    establishment (ML-KEM), via the same API as classical ECDH.")
    print("  - Hybrid derives the session key from both schemes: safe unless both fall.")
    print("  - Harvest-now-decrypt-later makes this urgent for long-lived assets:")
    print("    confidentiality must be quantum-safe at the moment of capture, because")
    print("    it cannot be applied retroactively to ciphertext already stolen.")
    print("  - Pair with the provenance demo (signing) for the full asset picture.\n")


if __name__ == "__main__":
    main()
