"""
Browser Screenshot Classifier — MobileNetV2 Transfer Learning (TensorFlow/Keras)

Architecture:
  1. MobileNetV2 (pre-trained on ImageNet, frozen base) — Extracts visual features from webpage screenshots
  2. GlobalAveragePooling2D          — Reduces spatial dimensions to a fixed-length vector
  3. Dense (128, ReLU) + Dropout(0.3) — Learns threat-specific patterns from visual features
  4. Dense (4, Softmax)               — 4-class output:
       0 = Legitimate
       1 = Fake Login Page
       2 = Browser Scam
       3 = Fake Update Page
"""

import os
import base64
import io
import numpy as np

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"

import tensorflow as tf
from tensorflow.keras.applications.mobilenet_v2 import MobileNetV2, preprocess_input
from tensorflow.keras.models import Model, load_model
from tensorflow.keras.layers import GlobalAveragePooling2D, Dense, Dropout
from PIL import Image

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "model")
MODEL_PATH = os.path.join(MODEL_DIR, "browser_mobilenet.h5")
IMG_SIZE = 224

CLASS_LABELS = ["Legitimate", "Fake Login Page", "Browser Scam", "Fake Update Page"]

_model = None


def _generate_synthetic_images(n_per_class=8):
    """Generate patterned images for demo training when no dataset exists."""
    images, labels = [], []
    colors = {
        0: [(240, 240, 245), (200, 210, 230)],      # Legitimate — neutral
        1: [(255, 255, 255), (0, 100, 200)],         # Fake login — white + blue
        2: [(255, 0, 0), (50, 0, 0)],                # Browser scam — red alert
        3: [(255, 200, 0), (100, 80, 0)],            # Fake update — yellow/orange
    }
    rng = np.random.default_rng(42)
    for cls, palette in colors.items():
        for _ in range(n_per_class):
            img = np.zeros((IMG_SIZE, IMG_SIZE, 3), dtype=np.float32)
            c1, c2 = palette
            split = rng.integers(80, 160)
            img[:split, :, 0] = c1[0] / 255.0
            img[:split, :, 1] = c1[1] / 255.0
            img[:split, :, 2] = c1[2] / 255.0
            img[split:, :, 0] = c2[0] / 255.0
            img[split:, :, 1] = c2[1] / 255.0
            img[split:, :, 2] = c2[2] / 255.0
            noise = rng.normal(0, 0.02, img.shape)
            img = np.clip(img + noise, 0, 1)
            images.append(img)
            labels.append(cls)
    return np.array(images), np.array(labels)


def _build_model():
    base = MobileNetV2(weights="imagenet", include_top=False, input_shape=(IMG_SIZE, IMG_SIZE, 3))
    base.trainable = False
    x = GlobalAveragePooling2D()(base.output)
    x = Dense(128, activation="relu")(x)
    x = Dropout(0.3)(x)
    out = Dense(4, activation="softmax")(x)
    model = Model(inputs=base.input, outputs=out)
    model.compile(optimizer="adam", loss="sparse_categorical_crossentropy", metrics=["accuracy"])
    return model


def _train_and_save():
    global _model
    _model = _build_model()
    X, y = _generate_synthetic_images()
    X = preprocess_input(X * 255.0)
    _model.fit(X, y, epochs=8, batch_size=4, verbose=0)
    os.makedirs(MODEL_DIR, exist_ok=True)
    _model.save(MODEL_PATH)
    print("Browser MobileNetV2 model trained and saved.")


def get_browser_cnn():
    global _model
    if _model is None:
        if os.path.exists(MODEL_PATH):
            _model = load_model(MODEL_PATH)
        else:
            _train_and_save()
    return _model


def _decode_image(image_b64):
    if "," in image_b64:
        image_b64 = image_b64.split(",", 1)[1]
    raw = base64.b64decode(image_b64)
    img = Image.open(io.BytesIO(raw)).convert("RGB")
    img = img.resize((IMG_SIZE, IMG_SIZE))
    arr = np.array(img, dtype=np.float32)
    return preprocess_input(arr)


def predict_screenshot(image_b64):
    """Classify a base64-encoded webpage screenshot."""
    if not image_b64:
        return {"class_index": 0, "class_label": "Legitimate", "confidence": 50.0, "probabilities": {}}

    model = get_browser_cnn()
    arr = _decode_image(image_b64)
    batch = np.expand_dims(arr, axis=0)
    probs = model.predict(batch, verbose=0)[0]
    idx = int(np.argmax(probs))
    return {
        "class_index": idx,
        "class_label": CLASS_LABELS[idx],
        "confidence": round(float(probs[idx]) * 100, 2),
        "probabilities": {CLASS_LABELS[i]: round(float(probs[i]) * 100, 2) for i in range(4)},
    }
