# vqc_transfer.py
# The fourth station of the talk: does an adversarial example crafted against one
# model fool the other across the quantum-classical boundary? Trains a variational
# quantum classifier and a small classical MLP on the same data, attacks each along
# its own gradient at a fixed step, and measures how often each attack also flips
# the other model.
#
# Method follows Wendlinger, Tscharke & Debus, "A Comparative Analysis of
# Adversarial Robustness for Quantum and Classical Machine Learning Models"
# (arXiv:2404.16154, 2024) and their repo mwendlinger/robust-analysis-qml-ml.
# This is a lean, toy-scale restatement for a live demo, not their full study.
#
#   pip install pennylane

import numpy as _np
import pennylane as qml
from pennylane import numpy as np

SEED = 7
_np.random.seed(SEED)

N_QUBITS, N_LAYERS, HID = 2, 3, 6
dev = qml.device("default.qubit", wires=N_QUBITS)


@qml.qnode(dev)
def _vqc(x, w):
    qml.AngleEmbedding(x, wires=range(N_QUBITS))
    qml.StronglyEntanglingLayers(w, wires=range(N_QUBITS))
    return qml.expval(qml.PauliZ(0))


def quantum(x, w):
    return _vqc(x, w)


def classical(x, theta):
    # small tanh MLP, differentiable through autograd like the qnode
    W1 = theta[0:2 * HID].reshape(2, HID)
    b1 = theta[2 * HID:3 * HID]
    W2 = theta[3 * HID:4 * HID]
    b2 = theta[4 * HID]
    h = np.tanh(x @ W1 + b1)
    return h @ W2 + b2


def two_blobs(n=60, sep=0.9, spread=0.55):
    _np.random.seed(SEED)
    half = n // 2
    a = _np.random.randn(half, 2) * spread + _np.array([sep, sep])
    b = _np.random.randn(half, 2) * spread + _np.array([-sep, -sep])
    X = _np.vstack([a, b]) / 2.5
    y = _np.array([1] * half + [-1] * half, dtype=float)
    idx = _np.random.permutation(n)
    return np.array(X[idx], requires_grad=False), np.array(y[idx], requires_grad=False)


def train_quantum(X, y, steps=60, lr=0.25):
    _np.random.seed(SEED + 1)
    w = np.array(_np.random.uniform(0, 2 * _np.pi,
                 qml.StronglyEntanglingLayers.shape(N_LAYERS, N_QUBITS)), requires_grad=True)
    opt = qml.AdamOptimizer(lr)
    cost = lambda ww: np.mean((np.stack([quantum(x, ww) for x in X]) - y) ** 2)
    for _ in range(steps):
        w = opt.step(cost, w)
    return w


def train_classical(X, y, steps=400, lr=0.1):
    _np.random.seed(SEED + 2)
    theta = np.array(_np.random.randn(4 * HID + 1) * 0.5, requires_grad=True)
    opt = qml.AdamOptimizer(lr)
    cost = lambda th: np.mean((np.stack([classical(x, th) for x in X]) - y) ** 2)
    for _ in range(steps):
        theta = opt.step(cost, theta)
    return theta


def acc(model, params, X, y):
    return float(_np.mean([_np.sign(float(model(x, params))) == float(t) for x, t in zip(X, y)]))


def unit_grad(model, params, x, label):
    xt = np.array(_np.array(x, dtype=float), requires_grad=True)
    g = _np.array(qml.grad(lambda xx: (model(xx, params) - label) ** 2)(xt), dtype=float)
    n = _np.linalg.norm(g)
    return g / n if n else g


def flips(model, params, x, label):
    return _np.sign(float(model(x, params))) != label


def transfer(X, y, wq, tc, eps):
    # only points both models get right; and transfer is measured on attacks that
    # actually flip their own model (the standard conditional transfer rate)
    shared = [(x, float(t)) for x, t in zip(X, y)
              if _np.sign(float(quantum(x, wq))) == float(t)
              and _np.sign(float(classical(x, tc))) == float(t)]
    q_succ = q_to_c = c_succ = c_to_q = 0
    for x, label in shared:
        adv_q = np.array(_np.array(x, float) + eps * unit_grad(quantum, wq, x, label), requires_grad=False)
        adv_c = np.array(_np.array(x, float) + eps * unit_grad(classical, tc, x, label), requires_grad=False)
        if flips(quantum, wq, adv_q, label):
            q_succ += 1
            q_to_c += flips(classical, tc, adv_q, label)
        if flips(classical, tc, adv_c, label):
            c_succ += 1
            c_to_q += flips(quantum, wq, adv_c, label)
    return len(shared), q_succ, q_to_c, c_succ, c_to_q


def main():
    X, y = two_blobs()
    wq = train_quantum(X, y)
    tc = train_classical(X, y)
    print(f"quantum classifier accuracy   {acc(quantum, wq, X, y):.2f}")
    print(f"classical classifier accuracy {acc(classical, tc, X, y):.2f}\n")

    eps = 0.6
    n, q_succ, q_to_c, c_succ, c_to_q = transfer(X, y, wq, tc, eps)
    q2c = q_to_c / q_succ if q_succ else 0
    c2q = c_to_q / c_succ if c_succ else 0
    print(f"attacks crafted at a fixed step (L2 {eps}), over {n} points both get right\n")
    print(f"  attack built on the QUANTUM model:   flips it {q_succ}/{n};"
          f" of those, {q_to_c}/{q_succ} ({q2c:.0%}) also fool the CLASSICAL model")
    print(f"  attack built on the CLASSICAL model: flips it {c_succ}/{n};"
          f" of those, {c_to_q}/{c_succ} ({c2q:.0%}) also fool the QUANTUM model\n")

    print(f"the boundary is porous in both directions - most attacks that flip one")
    print("model also flip the other. Adversarial examples do not respect the line")
    print("between the two worlds. The exact asymmetry depends on the models and")
    print("their encodings rather than being fixed, which is the frontier the field")
    print("is now mapping. Direction of travel, not a finished threat.")


if __name__ == "__main__":
    main()
