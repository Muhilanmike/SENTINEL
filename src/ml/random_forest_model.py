import numpy as np
import joblib
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from src.utils.logger import setup_logger
from src.utils.config import config

logger = setup_logger("random_forest")

class RandomForestModel:

    def __init__(self):
        self.model_path = config.get("ml", "random_forest", "model_path",
                                     default="models/saved/random_forest.pkl")
        self.n_estimators = config.get("ml", "random_forest", "n_estimators", default=100)
        self.max_depth = config.get("ml", "random_forest", "max_depth", default=20)
        self.min_samples_split = config.get("ml", "random_forest", "min_samples_split", default=5)
        self.threshold = config.get("ml", "threshold", "rf_confidence", default=0.7)
        self.model = None
        self.label_encoder = LabelEncoder()
        self.is_trained = False
        self.classes = ["NORMAL", "ATTACK"]

    def build(self):
        self.model = RandomForestClassifier(
            n_estimators=self.n_estimators,
            max_depth=self.max_depth,
            min_samples_split=self.min_samples_split,
            random_state=42,
            n_jobs=-1,
            class_weight="balanced"
        )
        logger.info("Random Forest model built")

    def train(self, X: np.ndarray, y: np.ndarray):
        if self.model is None:
            self.build()
        logger.info(f"Training Random Forest with {len(X)} samples")
        self.model.fit(X, y)
        self.is_trained = True
        logger.info("Random Forest training complete")

    def predict(self, features: np.ndarray) -> dict:
        if not self.is_trained:
            logger.warning("Model not trained yet")
            return {"label": "UNKNOWN", "confidence": 0.0, "is_attack": False}

        if features.ndim == 1:
            features = features.reshape(1, -1)

        try:
            prediction = self.model.predict(features)[0]
            probabilities = self.model.predict_proba(features)[0]
            confidence = float(np.max(probabilities))

            is_attack = prediction == "ATTACK" and confidence >= self.threshold

            return {
                "label": prediction,
                "confidence": confidence,
                "is_attack": is_attack,
                "probabilities": probabilities.tolist()
            }

        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return {"label": "ERROR", "confidence": 0.0, "is_attack": False}

    def predict_batch(self, features: np.ndarray) -> list:
        return [self.predict(f) for f in features]

    def get_feature_importance(self) -> dict:
        if not self.is_trained:
            return {}
        importance = self.model.feature_importances_
        return {f"feature_{i}": float(v) for i, v in enumerate(importance)}

    def save(self):
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump(self.model, self.model_path)
        logger.info(f"Random Forest model saved to {self.model_path}")

    def load(self):
        if not os.path.exists(self.model_path):
            logger.warning(f"No saved model found at {self.model_path}")
            return False
        self.model = joblib.load(self.model_path)
        self.is_trained = True
        logger.info(f"Random Forest model loaded from {self.model_path}")
        return True
