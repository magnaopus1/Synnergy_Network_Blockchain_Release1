# Unsupervised Learning Module for Anomaly Detection

from sklearn.cluster import KMeans

class UnsupervisedLearning:
    """
    Unsupervised learning module for anomaly detection within the Synnergy Network.
    """

    def __init__(self, n_clusters=2):
        """
        Initializes the UnsupervisedLearning class.

        Args:
        - n_clusters (int): Number of clusters for KMeans algorithm.
        """
        self.kmeans = KMeans(n_clusters=n_clusters)

    def train_model(self, X):
        """
        Trains the KMeans clustering model.

        Args:
        - X (DataFrame): Input data containing transaction features for training.

        Returns:
        - None
        """
        self.kmeans.fit(X)

    def predict_anomalies(self, X):
        """
        Predicts anomalies using the trained KMeans clustering model.

        Args:
        - X (DataFrame): Input data containing transaction features.

        Returns:
        - anomaly_labels (array): Cluster labels indicating potential anomalies.
        """
        anomaly_labels = self.kmeans.predict(X)
        return anomaly_labels
    
    def detect_anomalies(self, X):
        """
        Detects anomalies using the trained KMeans clustering model.

        Args:
        - X (DataFrame): Input data containing transaction features.

        Returns:
        - anomaly_indices (array): Indices of potentially anomalous transactions.
        """
        anomaly_labels = self.predict_anomalies(X)
        anomaly_indices = [i for i, label in enumerate(anomaly_labels) if label != 0]
        return anomaly_indices
