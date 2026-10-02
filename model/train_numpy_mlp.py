import json
import os
import sys
import numpy as np

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend.feature_extractor import extract_url_features
from model.preprocess import run_preprocessing, MODEL_DIR

class NumpyMLP:
    """A pure-Numpy Feed-Forward Neural Network with two hidden layers."""
    def __init__(self, input_dim, hidden_dim1=128, hidden_dim2=64):
        # He initialization for ReLU layers
        self.W1 = np.random.randn(input_dim, hidden_dim1) * np.sqrt(2. / input_dim)
        self.b1 = np.zeros(hidden_dim1)
        self.W2 = np.random.randn(hidden_dim1, hidden_dim2) * np.sqrt(2. / hidden_dim1)
        self.b2 = np.zeros(hidden_dim2)
        self.W3 = np.random.randn(hidden_dim2, 1) * np.sqrt(2. / hidden_dim2)
        self.b3 = np.zeros(1)

    def relu(self, Z):
        return np.maximum(0, Z)

    def relu_deriv(self, Z):
        return (Z > 0).astype(float)

    def sigmoid(self, Z):
        Z = np.clip(Z, -500, 500)
        return 1.0 / (1.0 + np.exp(-Z))

    def forward(self, X):
        self.Z1 = np.dot(X, self.W1) + self.b1
        self.A1 = self.relu(self.Z1)
        self.Z2 = np.dot(self.A1, self.W2) + self.b2
        self.A2 = self.relu(self.Z2)
        self.Z3 = np.dot(self.A2, self.W3) + self.b3
        self.A3 = self.sigmoid(self.Z3)
        return self.A3

    def compute_loss(self, Y, A3):
        m = Y.shape[0]
        loss = - (1/m) * np.sum(Y * np.log(A3 + 1e-8) + (1-Y) * np.log(1 - A3 + 1e-8))
        return loss

    def backward(self, X, Y, A3):
        m = X.shape[0]

        dZ3 = A3 - Y
        dW3 = (1/m) * np.dot(self.A2.T, dZ3)
        db3 = (1/m) * np.sum(dZ3, axis=0)

        dA2 = np.dot(dZ3, self.W3.T)
        dZ2 = dA2 * self.relu_deriv(self.Z2)
        dW2 = (1/m) * np.dot(self.A1.T, dZ2)
        db2 = (1/m) * np.sum(dZ2, axis=0)

        dA1 = np.dot(dZ2, self.W2.T)
        dZ1 = dA1 * self.relu_deriv(self.Z1)
        dW1 = (1/m) * np.dot(X.T, dZ1)
        db1 = (1/m) * np.sum(dZ1, axis=0)

        return dW1, db1, dW2, db2, dW3, db3

    def update_params(self, dW1, db1, dW2, db2, dW3, db3, lr):
        self.W1 -= lr * dW1
        self.b1 -= lr * db1
        self.W2 -= lr * dW2
        self.b2 -= lr * db2
        self.W3 -= lr * dW3
        self.b3 -= lr * db3

    def train(self, X, Y, epochs=3000, lr=0.05):
        Y = Y.reshape(-1, 1)
        for i in range(epochs):
            A3 = self.forward(X)
            loss = self.compute_loss(Y, A3)
            dW1, db1, dW2, db2, dW3, db3 = self.backward(X, Y, A3)
            self.update_params(dW1, db1, dW2, db2, dW3, db3, lr)
            if i % 300 == 0:
                print(f"Epoch {i}, Loss: {loss:.4f}")

    def predict(self, X):
        return self.forward(X)

    def save(self, filepath):
        params = {
            "W1": self.W1.tolist(),
            "b1": self.b1.tolist(),
            "W2": self.W2.tolist(),
            "b2": self.b2.tolist(),
            "W3": self.W3.tolist(),
            "b3": self.b3.tolist(),
        }
        with open(filepath, 'w') as f:
            json.dump(params, f)

    def load(self, filepath):
        with open(filepath, 'r') as f:
            params = json.load(f)
        self.W1 = np.array(params["W1"])
        self.b1 = np.array(params["b1"])
        self.W2 = np.array(params["W2"])
        self.b2 = np.array(params["b2"])
        self.W3 = np.array(params["W3"])
        self.b3 = np.array(params["b3"])

if __name__ == "__main__":
    print("Loading data...")
    data = run_preprocessing()
    X_train = data["X_train"]
    y_train = data["y_train"]
    X_test = data["X_test"]
    y_test = data["y_test"]

    print(f"Input features: {X_train.shape[1]}")
    print(f"Training Custom Numpy MLP (2 hidden layers: 128->64) on {X_train.shape[0]} samples...")
    model = NumpyMLP(input_dim=X_train.shape[1], hidden_dim1=128, hidden_dim2=64)
    model.train(X_train, y_train, epochs=3000, lr=0.05)

    preds_proba = model.predict(X_test)
    preds = (preds_proba >= 0.5).astype(int).flatten()

    acc = np.mean(preds == y_test)
    print(f"\nTest Accuracy: {acc:.4f}")

    # Per-class accuracy
    phish_mask = y_test == 1
    legit_mask = y_test == 0
    if phish_mask.sum() > 0:
        print(f"Phishing recall:    {np.mean(preds[phish_mask] == y_test[phish_mask]):.4f}")
    if legit_mask.sum() > 0:
        print(f"Legitimate recall:  {np.mean(preds[legit_mask] == y_test[legit_mask]):.4f}")

    out_path = os.path.join(MODEL_DIR, "numpy_mlp_weights.json")
    model.save(out_path)
    print(f"\nModel weights saved to {out_path}")
