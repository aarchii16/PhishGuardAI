import pandas as pd
import numpy as np
import re
import os
from typing import Dict, List, Tuple, Optional
import logging
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
try:
    import tensorflow as tf
    from tensorflow.keras.models import Sequential, Model
    from tensorflow.keras.layers import (
        Embedding, Conv1D, GlobalMaxPooling1D, Dense, Dropout, LSTM, 
        Bidirectional, Input, Concatenate, BatchNormalization
    )
    from tensorflow.keras.preprocessing.text import Tokenizer
    from tensorflow.keras.preprocessing.sequence import pad_sequences
    from tensorflow.keras.optimizers import Adam
    from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    tf = None
import pickle
import joblib
from real_world_data import real_data_loader

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AdvancedNLPPreprocessor:
    """Advanced NLP preprocessing with deep learning techniques"""
    
    def __init__(self, max_features=20000, max_length=512):
        if not TENSORFLOW_AVAILABLE:
            raise ImportError("TensorFlow not available for deep learning models")
        self.max_features = max_features
        self.max_length = max_length
        self.tokenizer = None
        self.phishing_keywords = []
        
    def preprocess_text(self, text: str) -> str:
        """Enhanced text preprocessing for deep learning"""
        if not text:
            return ""
        
        # Convert to lowercase
        text = text.lower()
        
        # Remove HTML tags but preserve structure
        text = re.sub(r'<[^>]+>', ' [HTML] ', text)
        
        # Normalize URLs and emails with special tokens
        text = re.sub(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', ' [URL] ', text)
        text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', ' [EMAIL] ', text)
        
        # Normalize phone numbers
        text = re.sub(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', ' [PHONE] ', text)
        
        # Normalize currency amounts
        text = re.sub(r'\$\d+(?:,\d{3})*(?:\.\d{2})?', ' [MONEY] ', text)
        
        # Preserve important punctuation patterns
        text = re.sub(r'!{2,}', ' [EXCLAIM] ', text)
        text = re.sub(r'\?{2,}', ' [QUESTION] ', text)
        
        # Remove extra whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        
        return text
    
    def fit_tokenizer(self, texts: List[str]):
        """Fit tokenizer on training texts"""
        processed_texts = [self.preprocess_text(text) for text in texts]
        
        self.tokenizer = Tokenizer(
            num_words=self.max_features,
            oov_token="[UNK]",
            filters='!"#$%&()*+,-./:;<=>?@[\\]^_`{|}~\t\n'
        )
        self.tokenizer.fit_on_texts(processed_texts)
        
    def texts_to_sequences(self, texts: List[str]) -> np.ndarray:
        """Convert texts to padded sequences"""
        processed_texts = [self.preprocess_text(text) for text in texts]
        sequences = self.tokenizer.texts_to_sequences(processed_texts)
        return pad_sequences(sequences, maxlen=self.max_length, padding='post', truncating='post')

class CNNPhishingDetector:
    """CNN-based phishing detector with advanced architecture"""
    
    def __init__(self, max_features=20000, max_length=512, embedding_dim=128):
        self.max_features = max_features
        self.max_length = max_length
        self.embedding_dim = embedding_dim
        self.model = None
        self.preprocessor = AdvancedNLPPreprocessor(max_features, max_length)
        self.is_trained = False
        
    def build_model(self):
        """Build advanced CNN architecture"""
        model = Sequential([
            # Embedding layer
            Embedding(
                input_dim=self.max_features,
                output_dim=self.embedding_dim,
                input_length=self.max_length,
                trainable=True
            ),
            
            # Multiple CNN layers with different filter sizes
            Conv1D(filters=128, kernel_size=3, activation='relu', padding='same'),
            BatchNormalization(),
            Dropout(0.3),
            
            Conv1D(filters=128, kernel_size=4, activation='relu', padding='same'),
            BatchNormalization(),
            Dropout(0.3),
            
            Conv1D(filters=128, kernel_size=5, activation='relu', padding='same'),
            BatchNormalization(),
            
            # Global max pooling
            GlobalMaxPooling1D(),
            
            # Dense layers
            Dense(256, activation='relu'),
            BatchNormalization(),
            Dropout(0.5),
            
            Dense(128, activation='relu'),
            BatchNormalization(),
            Dropout(0.3),
            
            Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer=Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy', 'precision', 'recall']
        )
        
        self.model = model
        return model
    
    def train_on_csv_data(self):
        """Train CNN model on CSV dataset"""
        logger.info("Training CNN model on CSV data...")
        
        try:
            # Load data
            emails, labels = real_data_loader.load_real_phishing_emails()
            
            if len(emails) == 0:
                raise ValueError("No email data available in CSV files")
            
            # Fit preprocessor
            self.preprocessor.fit_tokenizer(emails)
            
            # Convert to sequences
            X = self.preprocessor.texts_to_sequences(emails)
            y = np.array(labels)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # Build model
            if self.model is None:
                self.build_model()
            
            # Callbacks
            callbacks = [
                EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True),
                ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=3, min_lr=1e-6)
            ]
            
            # Train model
            history = self.model.fit(
                X_train, y_train,
                batch_size=32,
                epochs=50,
                validation_data=(X_test, y_test),
                callbacks=callbacks,
                verbose=1
            )
            
            # Evaluate
            test_loss, test_acc, test_prec, test_rec = self.model.evaluate(X_test, y_test, verbose=0)
            logger.info(f"CNN Test Accuracy: {test_acc:.4f}, Precision: {test_prec:.4f}, Recall: {test_rec:.4f}")
            
            self.is_trained = True
            return True
            
        except Exception as e:
            logger.error(f"CNN training failed: {e}")
            return False
    
    def predict(self, email_text: str) -> Dict:
        """Predict using CNN model"""
        if not self.is_trained or self.model is None:
            return {
                'error': 'Model not trained',
                'classification': 'Unknown',
                'confidence': 0.0,
                'risk_score': 0.0
            }
        
        try:
            # Preprocess and predict
            X = self.preprocessor.texts_to_sequences([email_text])
            prediction = self.model.predict(X, verbose=0)[0][0]
            
            classification = 'Phishing' if prediction >= 0.5 else 'Legitimate'
            confidence = float(prediction if prediction >= 0.5 else 1 - prediction)
            
            return {
                'classification': classification,
                'confidence': confidence,
                'risk_score': float(prediction),
                'model_type': 'CNN Deep Learning',
                'training_data': 'CSV dataset only'
            }
            
        except Exception as e:
            logger.error(f"CNN prediction failed: {e}")
            return {
                'error': str(e),
                'classification': 'Unknown',
                'confidence': 0.0,
                'risk_score': 0.0
            }

class LSTMPhishingDetector:
    """LSTM-based phishing detector for sequential analysis"""
    
    def __init__(self, max_features=20000, max_length=512, embedding_dim=128):
        self.max_features = max_features
        self.max_length = max_length
        self.embedding_dim = embedding_dim
        self.model = None
        self.preprocessor = AdvancedNLPPreprocessor(max_features, max_length)
        self.is_trained = False
        
    def build_model(self):
        """Build bidirectional LSTM architecture"""
        model = Sequential([
            # Embedding layer
            Embedding(
                input_dim=self.max_features,
                output_dim=self.embedding_dim,
                input_length=self.max_length,
                trainable=True
            ),
            
            # Bidirectional LSTM layers
            Bidirectional(LSTM(128, return_sequences=True, dropout=0.3, recurrent_dropout=0.3)),
            BatchNormalization(),
            
            Bidirectional(LSTM(64, dropout=0.3, recurrent_dropout=0.3)),
            BatchNormalization(),
            
            # Dense layers
            Dense(128, activation='relu'),
            BatchNormalization(),
            Dropout(0.5),
            
            Dense(64, activation='relu'),
            BatchNormalization(),
            Dropout(0.3),
            
            Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer=Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy', 'precision', 'recall']
        )
        
        self.model = model
        return model
    
    def train_on_csv_data(self):
        """Train LSTM model on CSV dataset"""
        logger.info("Training LSTM model on CSV data...")
        
        try:
            # Load data
            emails, labels = real_data_loader.load_real_phishing_emails()
            
            if len(emails) == 0:
                raise ValueError("No email data available in CSV files")
            
            # Fit preprocessor
            self.preprocessor.fit_tokenizer(emails)
            
            # Convert to sequences
            X = self.preprocessor.texts_to_sequences(emails)
            y = np.array(labels)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # Build model
            if self.model is None:
                self.build_model()
            
            # Callbacks
            callbacks = [
                EarlyStopping(monitor='val_loss', patience=7, restore_best_weights=True),
                ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=4, min_lr=1e-6)
            ]
            
            # Train model
            history = self.model.fit(
                X_train, y_train,
                batch_size=16,  # Smaller batch size for LSTM
                epochs=30,
                validation_data=(X_test, y_test),
                callbacks=callbacks,
                verbose=1
            )
            
            # Evaluate
            test_loss, test_acc, test_prec, test_rec = self.model.evaluate(X_test, y_test, verbose=0)
            logger.info(f"LSTM Test Accuracy: {test_acc:.4f}, Precision: {test_prec:.4f}, Recall: {test_rec:.4f}")
            
            self.is_trained = True
            return True
            
        except Exception as e:
            logger.error(f"LSTM training failed: {e}")
            return False
    
    def predict(self, email_text: str) -> Dict:
        """Predict using LSTM model"""
        if not self.is_trained or self.model is None:
            return {
                'error': 'Model not trained',
                'classification': 'Unknown',
                'confidence': 0.0,
                'risk_score': 0.0
            }
        
        try:
            # Preprocess and predict
            X = self.preprocessor.texts_to_sequences([email_text])
            prediction = self.model.predict(X, verbose=0)[0][0]
            
            classification = 'Phishing' if prediction >= 0.5 else 'Legitimate'
            confidence = float(prediction if prediction >= 0.5 else 1 - prediction)
            
            return {
                'classification': classification,
                'confidence': confidence,
                'risk_score': float(prediction),
                'model_type': 'LSTM Deep Learning',
                'training_data': 'CSV dataset only'
            }
            
        except Exception as e:
            logger.error(f"LSTM prediction failed: {e}")
            return {
                'error': str(e),
                'classification': 'Unknown',
                'confidence': 0.0,
                'risk_score': 0.0
            }

class EnsemblePhishingDetector:
    """Ensemble model combining traditional ML + deep learning"""
    
    def __init__(self):
        self.cnn_model = CNNPhishingDetector()
        self.lstm_model = LSTMPhishingDetector()
        self.is_trained = False
        
    def train_on_csv_data(self):
        """Train all models in ensemble"""
        logger.info("Training ensemble models...")
        
        cnn_success = self.cnn_model.train_on_csv_data()
        lstm_success = self.lstm_model.train_on_csv_data()
        
        self.is_trained = cnn_success and lstm_success
        return self.is_trained
    
    def predict(self, email_text: str) -> Dict:
        """Ensemble prediction with voting"""
        if not self.is_trained:
            return {
                'error': 'Ensemble not trained',
                'classification': 'Unknown',
                'confidence': 0.0,
                'risk_score': 0.0
            }
        
        try:
            # Get predictions from all models
            cnn_result = self.cnn_model.predict(email_text)
            lstm_result = self.lstm_model.predict(email_text)
            
            # Ensemble voting (weighted average)
            cnn_score = cnn_result.get('risk_score', 0.0)
            lstm_score = lstm_result.get('risk_score', 0.0)
            
            # Weighted ensemble (CNN: 0.4, LSTM: 0.6)
            ensemble_score = 0.4 * cnn_score + 0.6 * lstm_score
            
            classification = 'Phishing' if ensemble_score >= 0.5 else 'Legitimate'
            confidence = float(ensemble_score if ensemble_score >= 0.5 else 1 - ensemble_score)
            
            return {
                'classification': classification,
                'confidence': confidence,
                'risk_score': float(ensemble_score),
                'model_type': 'Deep Learning Ensemble (CNN + LSTM)',
                'training_data': 'CSV dataset only',
                'individual_scores': {
                    'cnn': cnn_score,
                    'lstm': lstm_score
                }
            }
            
        except Exception as e:
            logger.error(f"Ensemble prediction failed: {e}")
            return {
                'error': str(e),
                'classification': 'Unknown',
                'confidence': 0.0,
                'risk_score': 0.0
            }

# Initialize global deep learning models
cnn_detector = CNNPhishingDetector()
lstm_detector = LSTMPhishingDetector()
ensemble_detector = EnsemblePhishingDetector()
