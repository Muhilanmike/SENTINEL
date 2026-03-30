import numpy as np
import joblib
import os
from sklearn.ensemble import IsolationForest
from src.utils.logger import setup_logger
from src.utils.config import config

logger = setup_logger("isolation_forest")

class IsolationForestModel:

    def __init__(self):
        self.model_path = config.get("ml", "isolation_forest", "model_path",
                                     default="models/saved/isolation_forest.pkl")
        self.n_estimators = config.get("ml", "isolation_forest", "n_estimators", default=100)
        self.contamination = config.get("ml", "isolation_forest", "contamination", default=0.1)
        self.max_samples = config.get("ml", "isolation_forest", "max_samples", default="auto")
        self.threshold = config.get("ml", "threshold", "if_anomaly_score", default=-0.1)
        self.model = None
        self.is_trained = False

    def build(self):
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            max_samples=self.max_samples,
            random_state=42,
            n_jobs=-1
        )
        logger.info("Isolation Forest model built")

    def train(self, X: np.ndarray):
        if self.model is None:
            self.build()
        logger.info(f"Training Isolation Forest with {len(X)} samples")
        self.model.fit(X)
        self.is_trained = True
        logger.info("Isolation Forest training complete")

    def predict(self, features: np.ndarray) -> dict:
        if not self.is_trained:
            logger.warning("Isolation Forest not trained yet")
            return {"label": "UNKNOWN", "anomaly_score": 0.0, "is_anomaly": False}

        if features.ndim == 1:
            features = features.reshape(1, -1)

        try:
            prediction = self.model.predict(features)[0]
            anomaly_score = float(self.model.score_samples(features)[0])

            is_anomaly = prediction == -1 and anomaly_score <= self.threshold

            return {
                "label": "ANOMALY" if is_anomaly else "NORMAL",
                "anomaly_score": anomaly_score,
                "is_anomaly": is_anomaly,
                "raw_prediction": int(prediction)
            }

        except Exception as e:
            logger.error(f"Isolation Forest prediction error: {e}")
            return {"label": "ERROR", "anomaly_score": 0.0, "is_anomaly": False}

    def predict_batch(self, features: np.ndarray) -> list:
        return [self.predict(f) for f in features]

    def get_anomaly_scores(self, features: np.ndarray) -> np.ndarray:
        if not self.is_trained:
            return np.zeros(len(features))
        return self.model.score_samples(features)

    def save(self):
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump(self.model, self.model_path)
        logger.info(f"Isolation Forest model saved to {self.model_path}")

    def load(self):
        if not os.path.exists(self.model_path):
            logger.warning(f"No saved model found at {self.model_path}")
            return False
        self.model = joblib.load(self.model_path)
        self.is_trained = True
        logger.info(f"Isolation Forest model loaded from {self.model_path}")
        return True
