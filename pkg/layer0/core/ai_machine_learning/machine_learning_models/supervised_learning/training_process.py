class TrainingProcess:
    def __init__(self, model):
        """
        Initialize the TrainingProcess instance with a supervised learning model.

        Args:
            model: The supervised learning model to be trained.
        """
        self.model = model

    def train_model(self, X_train, y_train):
        """
        Train the supervised learning model on the labeled dataset.

        Args:
            X_train (array-like): The feature matrix of the training data.
            y_train (array-like): The labels of the training data.
        """
        self.model.fit(X_train, y_train)

    def validate_model(self, X_val, y_val):
        """
        Validate the performance of the trained model on a validation dataset.

        Args:
            X_val (array-like): The feature matrix of the validation data.
            y_val (array-like): The labels of the validation data.

        Returns:
            float: The evaluation metric score (e.g., accuracy, F1-score).
        """
        score = self.model.score(X_val, y_val)
        return score

# Example usage:
# Load or create your supervised learning model
# model = create_model()

# Initialize a TrainingProcess instance with the model
# training_process = TrainingProcess(model)

# Load labeled datasets for training and validation
# X_train, y_train = load_training_data()
# X_val, y_val = load_validation_data()

# Train the model on the training data
# training_process.train_model(X_train, y_train)

# Validate the model performance on the validation data
# validation_score = training_process.validate_model(X_val, y_val)

# Optionally, use the validation score to assess model performance
# print("Validation score:", validation_score)
