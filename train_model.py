import os
import joblib
import pandas as pd

from sklearn.ensemble import (
    RandomForestClassifier,
    ExtraTreesClassifier,
    VotingClassifier
)

from xgboost import XGBClassifier

from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# ==========================
# LOAD DATASET
# ==========================
df = pd.read_csv("dataset.csv")

if "index" in df.columns:
    df.drop("index", axis=1, inplace=True)

X = df.drop("Result", axis=1)

y = df["Result"].replace({
    -1: 1,
     1: 0
})

# ==========================
# SPLIT
# ==========================
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

# ==========================
# MODELS
# ==========================
rf = RandomForestClassifier(
    n_estimators=500,
    max_depth=30,
    random_state=42,
    n_jobs=-1
)

et = ExtraTreesClassifier(
    n_estimators=500,
    random_state=42,
    n_jobs=-1
)

xgb = XGBClassifier(
    n_estimators=300,
    learning_rate=0.1,
    max_depth=6,
    subsample=0.8,
    colsample_bytree=0.8,
    eval_metric="logloss",
    random_state=42
)

# ==========================
# ENSEMBLE
# ==========================
model = VotingClassifier(
    estimators=[
        ("rf", rf),
        ("et", et),
        ("xgb", xgb)
    ],
    voting="soft"
)

print("Training Ensemble...")

model.fit(X_train, y_train)

pred = model.predict(X_test)

acc = accuracy_score(y_test, pred)

print("\nAccuracy :", round(acc*100,4),"%")

print("\nClassification Report")
print(classification_report(y_test,pred))

print("\nConfusion Matrix")
print(confusion_matrix(y_test,pred))

os.makedirs("model",exist_ok=True)

joblib.dump(model,"model/phishing_model.pkl")

print("\nModel Saved")