from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score
import pandas as pd
import numpy as np
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from nltk.stem import WordNetLemmatizer
import string

class SentimentAnalysisAlgorithms:
    def __init__(self, data):
        self.data = data
        
    def preprocess_text(self, text):
        """
        Preprocesses the text data by tokenization, removing stopwords, and lemmatization.
        
        Args:
        - text: Input text
        
        Returns:
        - preprocessed_text: Preprocessed text
        """
        # Tokenization
        tokens = word_tokenize(text)
        
        # Remove stopwords and punctuation
        stop_words = set(stopwords.words("english"))
        punctuation = set(string.punctuation)
        filtered_tokens = [word for word in tokens if word.lower() not in stop_words and word not in punctuation]
        
        # Lemmatization
        lemmatizer = WordNetLemmatizer()
        lemmatized_tokens = [lemmatizer.lemmatize(token) for token in filtered_tokens]
        
        preprocessed_text = " ".join(lemmatized_tokens)
        return preprocessed_text
    
    def train_model(self):
        """
        Trains a sentiment analysis model using Naive Bayes classifier.
        
        Returns:
        - model: Trained sentiment analysis model
        """
        # Preprocess text data
        self.data["clean_text"] = self.data["text"].apply(self.preprocess_text)
        
        # TF-IDF vectorization
        vectorizer = TfidfVectorizer()
        X = vectorizer.fit_transform(self.data["clean_text"])
        
        # Train-test split
        X_train, X_test, y_train, y_test = train_test_split(X, self.data["sentiment"], test_size=0.2, random_state=42)
        
        # Train Naive Bayes classifier
        model = MultinomialNB()
        model.fit(X_train, y_train)
        
        return model
    
    def evaluate_model(self, model):
        """
        Evaluates the sentiment analysis model using test data.
        
        Args:
        - model: Trained sentiment analysis model
        
        Returns:
        - accuracy: Model accuracy
        """
        # Preprocess test data
        self.data["clean_text"] = self.data["text"].apply(self.preprocess_text)
        X_test = vectorizer.transform(self.data["clean_text"])
        
        # Predict sentiments
        y_pred = model.predict(X_test)
        
        # Evaluate model accuracy
        accuracy = accuracy_score(self.data["sentiment"], y_pred)
        return accuracy

# Example usage:
if __name__ == "__main__":
    # Load data
    data = pd.read_csv("data.csv")  # Replace with actual data file
    
    # Initialize SentimentAnalysisAlgorithms
    sentiment_analysis = SentimentAnalysisAlgorithms(data)
    
    # Train sentiment analysis model
    model = sentiment_analysis.train_model()
    
    # Evaluate model
    accuracy = sentiment_analysis.evaluate_model(model)
    print("Model Accuracy:", accuracy)
