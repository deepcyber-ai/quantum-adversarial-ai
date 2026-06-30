# Securing AI Assets Before Q-Day - demonstrations

Two short, runnable demonstrations, covering both halves of
the asset-protection story: the **integrity / provenance** of AI assets, and their
**confidentiality** across the quantum transition Both show the migration as a
crypto-agility exercise available today, not a 2035 problem. Additionally a glimpse of adversarial atttacks using quantum agaist quantum-based ML

## The three demos

### 1. Provenance - `pqc_model_provenance.py`
Signs a model artefact and its AI Bill of Materials (AIBOM) so the provenance
survives a cryptographically relevant quantum computer (CRQC). Shows a model
registry signing and verifying; crypto-agility across classical (ECDSA-P256),
post-quantum (ML-DSA-65, FIPS 204) and hybrid; tamper-evidence on the weights, the
AIBOM and the signature; and a size/cost comparison including an SLH-DSA reference row.

### 2. Confidentiality - `pqc_harvest_now.py`
Encrypts a model artefact and tells the harvest-now-decrypt-later story: an
adversary who captures the ciphertext today can read it once a CRQC exists, unless
it was wrapped with quantum-safe key establishment at capture time. Shows
encryption/decryption across classical (ECDH-P256), post-quantum (ML-KEM-768,
FIPS 203) and hybrid; a clear "confidential after Q-Day?" table; authenticated-
encryption tamper-evidence; and a size/cost comparison.

### 3. The glimpse - `vqc_glimpse.py`
 Trains a small variational quantum classifier, exports
its weights as the artefact (the same kind of asset the two demos above protect),
then finds the cheapest gradient-aligned input perturbation that flips a correct
prediction, and contrasts it with random perturbations of the same size. The point
is directionality: a step that does nothing in a random direction reliably flips
the prediction along the model's own gradient. Quantum ML inherits the adversarial
attack surface of classical models - the security work follows AI onto its next
substrate, it does not end at the cryptographic migration.

Run: `pip install pennylane` then `python3 vqc_glimpse.py`. Toy-scale, on a
simulator; keep it short and clearly fenced as forward-looking when presenting.

Together they cover the full asset picture: provenance protects integrity, ML-KEM
wrapping protects confidentiality, and hybrid carries both classical and post-
quantum so the asset is safe unless both fall.

## Run

```bash
pip install dilithium-py kyber-py cryptography pennylane
python3 pqc_model_provenance.py
python3 pqc_harvest_now.py
python3 vqc_glimpse.py
```

No network access and no native build are required; all dependencies are
pure-Python and pip-installable.

## Honest caveats 

- **Timings are not representative.** ML-DSA and ML-KEM here use pure-Python
  reference implementations, so the figures are dominated by interpreter overhead
  (and, in the confidentiality demo, by AES-GCM over the 4 MB artefact). An optimised
  native library (for example liboqs) performs these operations in well under a
  millisecond. The durable takeaway is the **size** overhead, not the absolute times.
- **No cryptography is actually broken.** The "confidential after Q-Day?" verdicts
  are a threat-model statement: a CRQC recovers an ECDH session key from the public
  key via Shor's algorithm, whereas ML-KEM has no known efficient quantum attack.
  The demo does not run Shor; it states the consequence and demonstrates the
  quantum-safe mechanics that follow from it.
- **SLH-DSA is shown as published FIPS 205 reference figures**, not measured; there
  is no clean pure-Python package. It illustrates the hash-based tradeoff: tiny key,
  large signature.
- **The artefact is a stand-in.** The "weights" are random bytes; the point is the
  workflow, not the model.
- **Hybrid** is the conservative transition posture (NCSC / NIST / IETF): a forger,
  or an eavesdropper, must defeat both the classical and the post-quantum scheme.

## The teaching point

The near-term quantum threat to AI is to the confidentiality and integrity of its
assets. Model IP, training data and provenance can be protected with NIST post-
quantum cryptography today, with crypto-agility and a hybrid transition, ahead of
the NCSC 2028 / 2031 / 2035 migration milestones - and harvest-now-decrypt-later
means confidentiality, in particular, cannot wait, because it cannot be applied
retroactively to ciphertext already stolen.

## Standards referenced

- ML-KEM - FIPS 203 (key encapsulation)
- ML-DSA - FIPS 204 (lattice-based signature)
- SLH-DSA - FIPS 205 (hash-based signature)
- NCSC post-quantum migration milestones: 2028 / 2031 / 2035
