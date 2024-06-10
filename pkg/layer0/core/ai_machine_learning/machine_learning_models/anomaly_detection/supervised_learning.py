# Supervised Learning Module for Anomaly Detection

from sklearn.ensemble import RandomForestClassifier

class SupervisedLearning:
    """
    Supervised learning module for anomaly detection within the Synnergy Network.
    """

    def __init__(self):
        """
        Initializes the SupervisedLearning class.
        """
        self.rf_classifier = RandomForestClassifier(n_estimators=100)

    def train_model(self, X_train, y_train):
        """
        Trains the random forest classifier model.

        Args:
        - X_train (DataFrame): Input data containing transaction features for training.
        - y_train (array): Target labels indicating normal or anomalous transactions.

        Returns:
        - None
        """
        self.rf_classifier.fit(X_train, y_train)

    def predict_anomalies(self, X):
        """
        Predicts anomalies using the trained random forest classifier model.

        Args:
        - X (DataFrame): Input data containing transaction features.

        Returns:
        - anomaly_scores (array): Scores indicating the likelihood of anomalies.
        """
        anomaly_scores = self.rf_classifier.predict_proba(X)[:, 1]
        return anomaly_scores
