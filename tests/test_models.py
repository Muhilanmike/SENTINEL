import numpy as np
import os
import tempfile
from unittest.mock import patch
from src.ml.random_forest_model import RandomForestModel
from src.ml.isolation_forest_model import IsolationForestModel


class TestRandomForestModel:

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.model = RandomForestModel()
        self.model.model_path = os.path.join(self.tmpdir, "rf.pkl")

    def test_untrained_returns_unknown(self, sample_features):
        result = self.model.predict(sample_features)
        assert result["label"] == "UNKNOWN"
        assert result["is_attack"] is False

    def test_train_and_predict(self):
        X = np.random.rand(100, 17)
        y = np.array(["NORMAL"] * 70 + ["ATTACK"] * 30)
        self.model.train(X, y)
        result = self.model.predict(X[0])
        assert result["label"] in ["NORMAL", "ATTACK"]
        assert 0.0 <= result["confidence"] <= 1.0

    def test_save_and_load(self):
        X = np.random.rand(50, 17)
        y = np.array(["NORMAL"] * 35 + ["ATTACK"] * 15)
        self.model.train(X, y)
        self.model.save()
        assert os.path.exists(self.model.model_path)

        new_model = RandomForestModel()
        new_model.model_path = self.model.model_path
        assert new_model.load() is True
        result = new_model.predict(X[0])
        assert result["label"] in ["NORMAL", "ATTACK"]

    def test_load_nonexistent_returns_false(self):
        self.model.model_path = "/nonexistent/path/model.pkl"
        assert self.model.load() is False

    def test_feature_importance_untrained(self):
        assert self.model.get_feature_importance() == {}

    def test_feature_importance_trained(self):
        X = np.random.rand(50, 17)
        y = np.array(["NORMAL"] * 35 + ["ATTACK"] * 15)
        self.model.train(X, y)
        importance = self.model.get_feature_importance()
        assert len(importance) == 17

    def test_threshold_respected(self):
        X = np.random.rand(100, 17)
        y = np.array(["NORMAL"] * 70 + ["ATTACK"] * 30)
        self.model.train(X, y)
        self.model.threshold = 0.99  # very high threshold
        result = self.model.predict(X[0])
        # With threshold 0.99, is_attack should be False unless confidence >= 0.99
        if result["confidence"] < 0.99:
            assert result["is_attack"] is False


class TestIsolationForestModel:

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.model = IsolationForestModel()
        self.model.model_path = os.path.join(self.tmpdir, "if.pkl")

    def test_untrained_returns_unknown(self, sample_features):
        result = self.model.predict(sample_features)
        assert result["label"] == "UNKNOWN"
        assert result["is_anomaly"] is False

    def test_train_and_predict(self):
        X = np.random.rand(100, 17)
        self.model.train(X)
        result = self.model.predict(X[0])
        assert result["label"] in ["NORMAL", "ANOMALY"]
        assert isinstance(result["anomaly_score"], float)

    def test_save_and_load(self):
        X = np.random.rand(50, 17)
        self.model.train(X)
        self.model.save()
        assert os.path.exists(self.model.model_path)

        new_model = IsolationForestModel()
        new_model.model_path = self.model.model_path
        assert new_model.load() is True

    def test_load_nonexistent_returns_false(self):
        self.model.model_path = "/nonexistent/path/model.pkl"
        assert self.model.load() is False

    def test_anomaly_scores(self):
        X = np.random.rand(50, 17)
        self.model.train(X)
        scores = self.model.get_anomaly_scores(X)
        assert len(scores) == 50

    def test_untrained_anomaly_scores(self):
        X = np.random.rand(10, 17)
        scores = self.model.get_anomaly_scores(X)
        assert all(s == 0.0 for s in scores)
