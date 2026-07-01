# Securing AI Assets Across the Quantum Transition

Runnable demonstrations for the AMLUCS session *Planning for Quantum-Backed
Adversarial AI*. They are sequenced as a single arc - the direction of travel -
from protecting the classical AI assets you hold today, to the frontier where the
models and the threats themselves become quantum.

```
  TODAY (actionable)                    |   FRONTIER (direction of travel)
  1. provenance signing                 |   3. attacking a quantum classifier
  2. harvest-now, decrypt-later         |   4. attacks crossing the Q/C boundary
```

## The four demos

### 1. Provenance - `pqc_model_provenance.py`
Signs a model artefact and its AI Bill of Materials so provenance survives a
cryptographically relevant quantum computer. Crypto-agile across classical
(ECDSA-P256), post-quantum (ML-DSA-65, FIPS 204) and hybrid; tamper-evidence on
weights, AIBOM and signature; size/cost comparison with an SLH-DSA reference row.

### 2. Confidentiality - `pqc_harvest_now.py`
Encrypts a model artefact and tells the harvest-now-decrypt-later story: ciphertext
captured today is readable once a quantum computer exists, unless it was wrapped
with quantum-safe key establishment at capture time. Classical (ECDH), post-quantum
(ML-KEM-768, FIPS 203) and hybrid, with a clear "confidential after Q-Day?" table.

### 3. The frontier opens - `vqc_glimpse.py`
Trains a small variational quantum classifier, exports its weights as the artefact
(the same kind of asset demos 1 and 2 protect), then flips a correct prediction
along the model's own gradient. Directionality is the point: a step that does
little at random reliably flips the prediction along the gradient. Quantum ML
inherits the adversarial attack surface of classical models.

### 4. The boundary is porous - `vqc_transfer.py`
Trains a quantum classifier and a small classical network on the same data, attacks
each along its own gradient, and measures how often each attack also flips the
other. Adversarial examples cross the quantum-classical boundary in both directions;
the exact asymmetry depends on the models and encodings, not the label. This is the
frontier the field is now mapping.

Method for demo 4 follows Wendlinger, Tscharke & Debus, *A Comparative Analysis of
Adversarial Robustness for Quantum and Classical Machine Learning Models*
(arXiv:2404.16154, 2024), and their repo `mwendlinger/robust-analysis-qml-ml`. The
script here is a lean, toy-scale restatement for a live demo, not their full study.

## Run

```bash
pip install dilithium-py kyber-py cryptography pennylane
python3 pqc_model_provenance.py
python3 pqc_harvest_now.py
python3 vqc_glimpse.py
python3 vqc_transfer.py
```

No network access and no native build are required; all dependencies are
pure-Python and pip-installable.

## Honest caveats

- **The frontier is not an operational threat today.** There is no demonstrated
  quantum advantage for attacking classical AI. Demos 3 and 4 show where the
  adversarial threat model is heading as ML becomes quantum, not a present-day
  capability. Keep the "today | frontier" line visible.
- **The frontier cuts both ways.** Quantum ML is a new attack surface, but quantum
  dynamics can also confer novel robustness (random encoders, noise-as-defence,
  recent robustness theorems). The direction of travel is a shifting threat model,
  defensive as well as offensive - not simply "it gets worse".
- **Timings are not representative.** ML-DSA, ML-KEM and the quantum circuits use
  pure-Python reference implementations; figures are dominated by interpreter
  overhead. Optimised native libraries are far faster. The durable comparisons are
  the sizes (demos 1-2) and the transfer/flip rates (demos 3-4), not absolute times.
- **No cryptography is actually broken** in demos 1-2; the Q-Day verdicts are a
  threat-model statement. **Demos 3-4 are toy-scale on a simulator**, with fixed
  seeds for a reproducible talk; results are representative, not cherry-picked, and
  transfer is architecture-dependent (see the Wendlinger et al. study for the fuller
  treatment this was validated against).
- **Hybrid** is the conservative transition posture (NCSC / NIST / IETF): safe
  unless both the classical and post-quantum scheme fall.

## Conclusions

The near-term quantum threat to AI is to the confidentiality and integrity of its
assets, and that is protectable today with NIST post-quantum cryptography, crypto-
agility and a hybrid transition, ahead of the NCSC 2028 / 2031 / 2035 milestones.
Harvest-now-decrypt-later makes confidentiality urgent, because it cannot be applied
retroactively. And as AI itself moves onto quantum areas, the adversarial
threat model transforms - in both directions - which is the frontier these last two
demos begin to map with running code rather than slogans.

## Standards and references

- ML-KEM - FIPS 203; ML-DSA - FIPS 204; SLH-DSA - FIPS 205
- NCSC post-quantum migration milestones: 2028 / 2031 / 2035
- Lu, Duan & Deng (2020); Ren et al. (2022); West et al. (2023); Wendlinger,
  Tscharke & Debus (2024, arXiv:2404.16154); Dowling et al. (2026) - QML adversarial
  robustness and cross-boundary transfer.
