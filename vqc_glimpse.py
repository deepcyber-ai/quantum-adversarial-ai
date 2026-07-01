# vqc_glimpse.py
# Closing segment for the AMLUCS quantum session: the asset we spent the talk
# protecting (a trained quantum classifier) is itself attackable. Train a small
# variational quantum classifier, export its weights as the artefact, then find a
# minimal input perturbation that flips a correct prediction.
#
#   pip install pennylane
#
# Numbers are toy-scale on a simulator. The point is the phenomenon, not the size.

import numpy as _np
import pennylane as qml
from pennylane import numpy as np

SEED = 7
_np.random.seed(SEED)

N_QUBITS = 2
N_LAYERS = 3
dev = qml.device("default.qubit", wires=N_QUBITS)


@qml.qnode(dev)
def circuit(x, weights):
    qml.AngleEmbedding(x, wires=range(N_QUBITS))
    qml.StronglyEntanglingLayers(weights, wires=range(N_QUBITS))
    return qml.expval(qml.PauliZ(0))


def predict(x, weights):
    # expectation in [-1, 1]; sign is the class label in {-1, +1}
    return circuit(x, weights)


def two_blobs(n=40, sep=1.4):
    # two gaussian clusters, scaled into a sensible angle range for the embedding
    half = n // 2
    a = _np.random.randn(half, 2) * 0.35 + _np.array([sep, sep])
    b = _np.random.randn(half, 2) * 0.35 + _np.array([-sep, -sep])
    X = _np.vstack([a, b]) / 2.5
    y = _np.array([1] * half + [-1] * half, dtype=float)
    idx = _np.random.permutation(n)
    return np.array(X[idx], requires_grad=False), np.array(y[idx], requires_grad=False)


def train(X, y, steps=60, lr=0.25):
    w = np.array(_np.random.uniform(0, 2 * _np.pi,
                 qml.StronglyEntanglingLayers.shape(N_LAYERS, N_QUBITS)),
                 requires_grad=True)
    opt = qml.AdamOptimizer(lr)

    def cost(weights):
        preds = np.stack([circuit(x, weights) for x in X])
        return np.mean((preds - y) ** 2)

    for i in range(steps):
        w, c = opt.step_and_cost(cost, w)
        if (i + 1) % 20 == 0:
            print(f"  step {i+1:>3}  loss {float(c):.4f}")
    return w


def accuracy(X, y, w):
    preds = _np.sign([float(predict(x, w)) for x in X])
    return float(_np.mean(preds == _np.array(y)))


def gradient_attack(x0, label, w, eps_max=1.2, step=0.01):
    # step along the (normalised) input gradient until the prediction crosses zero
    x_t = np.array(_np.array(x0, dtype=float), requires_grad=True)
    g = _np.array(qml.grad(lambda xx: (predict(xx, w) - label) ** 2)(x_t), dtype=float)
    norm = _np.linalg.norm(g)
    if norm == 0:
        return None, None, None
    direction = g / norm
    base_x = _np.array(x0, dtype=float)
    eps = 0.0
    while eps <= eps_max:
        eps += step
        x_adv = np.array(base_x + eps * direction, requires_grad=False)
        if _np.sign(float(predict(x_adv, w))) != label:
            return x_adv, eps, direction
    return None, None, direction


def random_baseline(x0, label, w, eps, trials=50):
    # same step length, but in random directions instead of the gradient's
    base_x = _np.array(x0, dtype=float)
    flips = 0
    for _ in range(trials):
        u = _np.random.randn(*base_x.shape)
        u /= _np.linalg.norm(u)
        x_adv = np.array(base_x + eps * u, requires_grad=False)
        flips += int(_np.sign(float(predict(x_adv, w))) != label)
    return flips, trials


def main():
    X, y = two_blobs()
    print("training a 2-qubit variational classifier")
    w = train(X, y)
    print(f"  train accuracy {accuracy(X, y, w):.2f}\n")

    # the trained weights are the asset; this is what the signing / KEM demos protect
    blob = _np.asarray(w, dtype=_np.float64).tobytes()
    with open("vqc_params.bin", "wb") as fh:
        fh.write(blob)
    print(f"exported model weights -> vqc_params.bin ({len(blob)} bytes)")
    print("  (this artefact is what the provenance and harvest-now demos sign and encrypt)\n")

    # find the correctly-classified point that is cheapest to flip (what an attacker does)
    target = label = x_adv = None
    eps = None
    for x, lab in zip(X, y):
        if _np.sign(float(predict(x, w))) != float(lab):
            continue
        xa, e, _ = gradient_attack(x, float(lab), w)
        if xa is not None and (eps is None or e < eps):
            target, label, x_adv, eps = x, float(lab), xa, e

    base = float(predict(target, w))
    adv = float(predict(x_adv, w))
    print("gradient attack on the most easily flipped correct point:")
    print(f"  clean      x = {_np.round(_np.array(target, dtype=float), 3)}  "
          f"output {base:+.3f}  -> class {int(_np.sign(base)):+d} (correct)")
    print(f"  perturbed  x = {_np.round(_np.array(x_adv, dtype=float), 3)}  "
          f"output {adv:+.3f}  -> class {int(_np.sign(adv)):+d}")
    print(f"  step length (L2): {eps:.2f}\n")

    flips, trials = random_baseline(target, label, w, eps)
    print(f"same step, random direction:   {flips}/{trials} flips")
    print(f"same step, gradient direction: 1/1 flips\n")

    print("the magnitude is not the story - the direction is. A step this size")
    print("rarely flips anything in a random direction, but along the model's own")
    print("gradient it reliably does. Quantum ML inherits the adversarial attack")
    print("surface of classical models; the security work follows AI onto its next")
    print("substrate, it does not end at the cryptographic migration.")


if __name__ == "__main__":
    main()
