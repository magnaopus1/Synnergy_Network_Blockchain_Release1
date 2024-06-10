from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.ensemble import RandomForestClassifier  # Example model, can be replaced with any other model

class CreditScoring:
    def __init__(self, model=None):
        """
        Initialize the CreditScoring instance with a supervised learning model.

        Args:
            model: The supervised learning model used for credit scoring.
        """
        if model is None:
            # Initialize with a default model if not provided
            self.model = RandomForestClassifier()
        else:
            self.model = model

    def train(self, X_train, y_train):
        """
        Train the supervised learning model using the provided training data.

        Args:
            X_train (array-like): The feature matrix of training samples.
            y_train (array-like): The target labels corresponding to the training samples.
        """
        self.model.fit(X_train, y_train)

    def predict(self, X_test):
        """
        Predict the credit scores for the given test data using the trained model.

        Args:
            X_test (array-like): The feature matrix of test samples.

        Returns:
            array-like: The predicted credit scores for the test samples.
        """
        return self.model.predict(X_test)

    def evaluate(self, X_test, y_test):
        """
        Evaluate the performance of the trained model on the test data.

        Args:
            X_test (array-like): The feature matrix of test samples.
            y_test (array-like): The true labels corresponding to the test samples.

        Returns:
            float: The accuracy of the model on the test data.
        """
        y_pred = self.predict(X_test)
        return accuracy_score(y_test, y_pred)

# Example usage:
# Initialize a CreditScoring instance
credit_scorer = CreditScoring()

# Example training data and labels
X_train = [[1, 2, 3], [4, 5, 6], [7, 8, 9]]
y_train = [0, 1, 0]

# Train the model
credit_scorer.train(X_train, y_train)

# Example test data and labels
X_test = [[2, 3, 4], [5, 6, 7]]
y_test = [0, 1]

# Evaluate the model
accuracy = credit_scorer.evaluate(X_test, y_test)
print("Model accuracy:", accuracy)
