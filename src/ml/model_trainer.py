import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from src.ml.random_forest_model import RandomForestModel
from src.ml.isolation_forest_model import IsolationForestModel
from src.features.feature_extractor import FeatureExtractor
from src.utils.logger import setup_logger

logger = setup_logger("model_trainer")

class ModelTrainer:

    def __init__(self):
        self.rf_model = RandomForestModel()
        self.if_model = IsolationForestModel()
        self.feature_extractor = FeatureExtractor()

    def prepare_data(self, packets: list, labels: list = None):
        logger.info(f"Preparing data from {len(packets)} packets")
        X = self.feature_extractor.extract_batch(packets)

        if labels:
            y = np.array(labels)
            return X, y
        return X, None

    def train_random_forest(self, X: np.ndarray, y: np.ndarray):
        logger.info("Starting Random Forest training")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
        self.rf_model.train(X_train, y_train)

        # Evaluate
        predictions = [self.rf_model.predict(x)["label"] for x in X_test]
        logger.info("\n" + classification_report(y_test, predictions))
        self.rf_model.save()
        return self.rf_model

    def train_isolation_forest(self, X: np.ndarray):
        logger.info("Starting Isolation Forest training")
        self.if_model.train(X)
        self.if_model.save()
        return self.if_model

    def train_all(self, packets: list, labels: list = None):
        logger.info("Training all models")
        X, y = self.prepare_data(packets, labels)

        if y is not None:
            self.train_random_forest(X, y)

        self.train_isolation_forest(X)
        logger.info("All models trained and saved successfully")

    def load_all(self):
        rf_loaded = self.rf_model.load()
        if_loaded = self.if_model.load()
        logger.info(f"Models loaded - RF: {rf_loaded}, IF: {if_loaded}")
        return rf_loaded, if_loaded

    def train_from_csv(self, csv_path: str, label_column: str = "label"):
        logger.info(f"Training from CSV: {csv_path}")
        df = pd.read_csv(csv_path)

        if label_column in df.columns:
            y = df[label_column].values
            X = df.drop(columns=[label_column]).values
        else:
            y = None
            X = df.values

        if y is not None:
            self.train_random_forest(X, y)
        self.train_isolation_forest(X)
        logger.info("Training from CSV complete")
