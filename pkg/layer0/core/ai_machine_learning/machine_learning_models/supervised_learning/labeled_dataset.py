from sklearn.model_selection import train_test_split

class LabeledDataset:
    def __init__(self, data, labels):
        """
        Initialize the LabeledDataset instance with data and corresponding labels.

        Args:
            data (array-like): The feature matrix of the dataset.
            labels (array-like): The target labels corresponding to the data.
        """
        self.data = data
        self.labels = labels

    def preprocess_data(self):
        """
        Preprocess the data if needed (e.g., scaling, normalization).
        """
        # Add preprocessing steps here if necessary
        pass

    def split_data(self, test_size=0.2, random_state=None):
        """
        Split the dataset into training and testing sets.

        Args:
            test_size (float or int): The proportion of the dataset to include in the test split.
            random_state (int): Controls the randomness of the data splitting.

        Returns:
            tuple: A tuple containing the training data, testing data, training labels, and testing labels.
        """
        X_train, X_test, y_train, y_test = train_test_split(self.data, self.labels, test_size=test_size, random_state=random_state)
        return X_train, X_test, y_train, y_test

    def load_data(self):
        """
        Load the dataset (e.g., from a file or database).
        """
        # Add loading logic here
        pass

    def save_data(self):
        """
        Save the dataset (e.g., to a file or database).
        """
        # Add saving logic here
        pass

# Example usage:
# Load or create your dataset
data = [[1, 2, 3], [4, 5, 6], [7, 8, 9]]
labels = [0, 1, 0]

# Initialize a LabeledDataset instance
labeled_data = LabeledDataset(data, labels)

# Preprocess the data if needed
labeled_data.preprocess_data()

# Split the dataset into training and testing sets
X_train, X_test, y_train, y_test = labeled_data.split_data(test_size=0.2, random_state=42)

# Optionally, load or save the dataset
# labeled_data.load_data()
# labeled_data.save_data()
