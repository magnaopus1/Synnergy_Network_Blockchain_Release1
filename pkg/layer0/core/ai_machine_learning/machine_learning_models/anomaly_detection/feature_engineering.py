# Feature Engineering Module for Anomaly Detection

import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer

class FeatureEngineering:
    """
    Feature engineering module for anomaly detection within the Synnergy Network.
    """

    def __init__(self):
        self.scaler = StandardScaler()
        self.imputer = SimpleImputer(strategy='mean')

    def preprocess_data(self, X):
        """
        Preprocesses the input data by handling missing values and normalizing features.

        Args:
        - X (DataFrame): Input data containing transaction features.

        Returns:
        - X_processed (DataFrame): Preprocessed data ready for anomaly detection.
        """
        X_imputed = self.imputer.fit_transform(X)
        X_processed = pd.DataFrame(self.scaler.fit_transform(X_imputed), columns=X.columns)
        return X_processed
