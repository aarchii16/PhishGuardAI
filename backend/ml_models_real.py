import pandas as pd
import numpy as np
import re
import pickle
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
import joblib
from urllib.parse import urlparse
import tld
from typing import Dict, List, Tuple
import logging
from real_world_data import real_data_loader

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RealWorldEmailPhishingDetector:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(
            max_features=10000, 
            stop_words='english', 
            ngram_range=(1, 3),  # Increased n-gram range for better pattern detection
            min_df=2,  # Ignore terms that appear in less than 2 documents
            max_df=0.95  # Ignore terms that appear in more than 95% of documents
        )
        self.model = LogisticRegression(
            random_state=42, 
            max_iter=1000,
            class_weight='balanced'  # Handle class imbalance
        )
        self.is_trained = False
        
        # Phishing keywords will be loaded from CSV
        self.phishing_keywords = []
        self.keywords_by_category = {}
    
    def preprocess_email(self, text: str) -> str:
        """Enhanced email text preprocessing"""
        if not text:
            return ""
        
        # Convert to lowercase
        text = text.lower()
        
        # Remove HTML tags
        text = re.sub(r'<[^>]+>', '', text)
        
        # Remove email addresses (but keep domain patterns for analysis)
        text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL]', text)
        
        # Replace URLs with placeholder (but keep for separate analysis)
        text = re.sub(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', '[URL]', text)
        
        # Remove extra whitespace and normalize
        text = re.sub(r'\s+', ' ', text).strip()
        
        # Remove special characters but keep important punctuation
        text = re.sub(r'[^\w\s\!\?\.\,\:\;\-]', '', text)
        
        return text
    
    def extract_advanced_features(self, text: str) -> Dict:
        """Extract advanced features from email text"""
        features = {}
        
        # Keyword matching with weighted scoring
        keyword_count = 0
        urgent_keywords = 0
        financial_keywords = 0
        security_keywords = 0
        
        text_lower = text.lower()
        
        for keyword in self.phishing_keywords:
            if keyword in text_lower:
                keyword_count += 1
                # Weight different types of keywords
                if keyword in ['urgent', 'immediate', 'expires', 'deadline', 'act now']:
                    urgent_keywords += 1
                elif keyword in ['payment', 'billing', 'refund', 'invoice', 'bank']:
                    financial_keywords += 1
                elif keyword in ['security', 'suspicious', 'verify', 'confirm']:
                    security_keywords += 1
        
        features['total_keywords'] = keyword_count
        features['urgent_keywords'] = urgent_keywords
        features['financial_keywords'] = financial_keywords
        features['security_keywords'] = security_keywords
        
        # Text statistics
        features['text_length'] = len(text)
        features['word_count'] = len(text.split()) if text else 0
        features['sentence_count'] = len(re.split(r'[.!?]+', text)) if text else 0
        features['avg_word_length'] = np.mean([len(word) for word in text.split()]) if text.split() else 0
        
        # Punctuation analysis
        features['exclamation_count'] = text.count('!')
        features['question_count'] = text.count('?')
        features['caps_ratio'] = sum(1 for c in text if c.isupper()) / len(text) if text else 0
        
        # URL and email patterns
        features['url_count'] = len(re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text))
        features['email_count'] = len(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text))
        
        # Suspicious patterns
        features['has_click_here'] = 1 if 'click here' in text_lower else 0
        features['has_verify_now'] = 1 if any(phrase in text_lower for phrase in ['verify now', 'verify account', 'verify immediately']) else 0
        features['has_urgent'] = 1 if any(word in text_lower for word in ['urgent', 'immediate', 'asap']) else 0
        
        return features
    
    def train_on_real_data(self):
        """Train model on real-world phishing data from CSV files only"""
        logger.info("Training email model on real-world CSV data...")
        
        try:
            self._validate_csv_data_availability()
            
            # Load real-world data from CSV
            emails, labels = real_data_loader.load_real_phishing_emails()
            
            if len(emails) == 0:
                raise ValueError("No email data available in CSV files")
            
            # Preprocess emails
            processed_emails = [self.preprocess_email(email) for email in emails]
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                processed_emails, labels, test_size=0.2, random_state=42, stratify=labels
            )
            
            # Vectorize text
            X_train_vec = self.vectorizer.fit_transform(X_train)
            X_test_vec = self.vectorizer.transform(X_test)
            
            # Train model
            self.model.fit(X_train_vec, y_train)
            
            # Evaluate
            train_score = self.model.score(X_train_vec, y_train)
            test_score = self.model.score(X_test_vec, y_test)
            
            logger.info(f"Email model training completed!")
            logger.info(f"Training accuracy: {train_score:.3f}")
            logger.info(f"Test accuracy: {test_score:.3f}")
            
            # Generate detailed report with 3 decimal points
            y_pred = self.model.predict(X_test_vec)
            report = classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing'], digits=3)
            logger.info(f"Classification Report:\n{report}")
            
            self.is_trained = True
            return True
            
        except Exception as e:
            logger.error(f"Error training on CSV data: {e}")
            raise
    
    def _validate_csv_data_availability(self):
        """Validate that CSV data files are available and contain data"""
        if not real_data_loader.check_csv_files_exist():
            raise FileNotFoundError(
                "CSV dataset files are missing. Please ensure 'real_phishing_emails.csv' and 'real_malicious_urls.csv' "
                "are present in the datasets directory."
            )
        
        # Try to load a small sample to validate file format
        try:
            emails, labels = real_data_loader.load_real_phishing_emails()
            if len(emails) == 0:
                raise ValueError("Email CSV file is empty or contains no valid data")
        except Exception as e:
            raise ValueError(f"Error validating email CSV data: {e}")
    
    def predict(self, email_text: str) -> Dict:
        """Predict if email is phishing using real-world trained model"""
        if not self.is_trained:
            logger.info("Model not trained, training now...")
            self._validate_csv_data_availability()
            self.train_on_real_data()
        
        processed_text = self.preprocess_email(email_text)
        features = self.extract_advanced_features(email_text)
        
        # Vectorize text
        X = self.vectorizer.transform([processed_text])
        
        # Predict
        prediction = self.model.predict(X)[0]
        probability = self.model.predict_proba(X)[0]
        
        # Calculate confidence score
        confidence = float(max(probability))
        risk_score = float(probability[1])  # Probability of being phishing
        
        # Determine risk level
        if risk_score >= 0.8:
            risk_level = "Critical"
        elif risk_score >= 0.6:
            risk_level = "High"
        elif risk_score >= 0.4:
            risk_level = "Medium"
        elif risk_score >= 0.2:
            risk_level = "Low"
        else:
            risk_level = "Minimal"
        
        return {
            'is_phishing': bool(prediction),
            'confidence': confidence,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'features': features,
            'classification': 'Phishing' if prediction else 'Legitimate',
            'model_version': 'CSV-RealWorld-v2.0',
            'model_type': 'Real-World Trained',
            'training_data': 'CSV dataset only'
        }

class RealWorldURLPhishingDetector:
    def __init__(self):
        self.model = LogisticRegression(
            random_state=42, 
            max_iter=1000,
            class_weight='balanced'
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        
        # Data will be loaded from CSV files
        self.suspicious_tlds = []
        self.phishing_keywords = []
        self.url_shorteners = []
    
    def extract_advanced_url_features(self, url: str) -> np.array:
        """Extract comprehensive features from URL - simplified version without external CSV dependencies"""
        features = []
        
        # Use fixed default values instead of loading from CSV
        suspicious_tlds = [
            'tk', 'ml', 'ga', 'cf', 'ru', 'cn', 'xyz', 'top', 'club', 'info',
            'site', 'online', 'space', 'tech', 'host', 'store', 'loan', 'bid',
            'dating', 'review', 'science', 'party', 'work', 'click', 'link',
            'download', 'help', 'racing', 'win', 'trade', 'accountant'
        ]
        
        phishing_keywords = [
            'urgent', 'immediate', 'act now', 'click here', 'verify', 'confirm', 'account',
            'suspended', 'limited', 'expires', 'deadline', 'asap', 'alert', 'warning',
            'payment', 'billing', 'refund', 'invoice', 'bank', 'financial', 'security',
            'password', 'login', 'signin', 'update', 'upgrade', 'renew', 'reactivate',
            'win', 'winner', 'prize', 'congratulations', 'lottery', 'cash', 'money',
            'free', 'offer', 'deal', 'discount', 'sale', 'paypal', 'amazon', 'google',
            'microsoft', 'apple', 'facebook', 'instagram', 'twitter', 'linkedin'
        ]
        
        url_shorteners = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'buff.ly',
            'is.gd', 'soo.gd', 'adf.ly', 'j.mp', 'cutt.ly', 'shorturl.at',
            'tiny.cc', 'bl.ink', 'rebrand.ly', 'lnkd.in', 'fb.me', 'youtu.be'
        ]
        
        try:
            # Handle potential parsing errors
            if not url or not isinstance(url, str):
                url = ""
            
            parsed = urlparse(url) if url else urlparse("")
            domain = parsed.netloc.lower() if parsed and parsed.netloc else ""
            path = parsed.path.lower() if parsed and parsed.path else ""
            query = parsed.query.lower() if parsed and parsed.query else ""
            full_url = url.lower() if url else ""
            
            # Basic URL features
            features.append(len(url))  # URL length
            features.append(len(domain))  # Domain length
            features.append(len(path))  # Path length
            features.append(len(query))  # Query length
            
            # Character count features
            features.append(url.count('.'))  # Number of dots
            features.append(url.count('/'))  # Number of slashes
            features.append(url.count('-'))  # Number of hyphens
            features.append(url.count('_'))  # Number of underscores
            features.append(url.count('?'))  # Number of question marks
            features.append(url.count('='))  # Number of equals
            features.append(url.count('@'))  # Number of @ symbols
            features.append(url.count('%'))  # Number of percent signs (URL encoding)
            
            # Suspicious character patterns
            features.append(1 if '//' in path else 0)  # Double slash in path
            features.append(1 if '@' in url else 0)  # @ symbol present
            features.append(1 if any(tld in domain for tld in suspicious_tlds) else 0)  # Suspicious TLD
            
            # Keyword matching in URL
            keyword_count = sum(1 for keyword in phishing_keywords if keyword in full_url)
            features.append(keyword_count)
            
            # Domain analysis
            features.append(1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else 0)  # IP address
            features.append(1 if parsed.scheme == 'https' else 0)  # HTTPS check
            features.append(len(domain.split('.')) - 2 if len(domain.split('.')) > 2 else 0)  # Subdomain count
            
            # URL shortening services
            features.append(1 if any(short in domain for short in url_shorteners) else 0)
            
            # Advanced suspicious patterns
            features.append(1 if len(url) > 100 else 0)  # Very long URL
            features.append(1 if url.count('-') > 3 else 0)  # Many hyphens
            features.append(1 if url.count('.') > 5 else 0)  # Many dots
            features.append(1 if any(char.isdigit() for char in domain.replace('.', '')) else 0)  # Numbers in domain
            
            # Typosquatting detection (basic)
            typo_score = 0
            brand_keywords = [kw for kw in phishing_keywords if any(brand in kw.lower() for brand in ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook'])]
            for keyword in brand_keywords:
                if keyword in domain and not domain.endswith(f"{keyword}.com") and not domain.endswith(f"www.{keyword}.com"):
                    typo_score += 1
            features.append(typo_score)
            
            # Port number present
            features.append(1 if ':' in domain and not domain.startswith('http') else 0)
            
            # Query parameters count
            features.append(len(query.split('&')) if query else 0)
            
        except Exception as e:
            logger.error(f"Error extracting URL features: {e}")
            # Return a default feature vector of the correct size (25 features)
            features = [0] * 25
        
        # Ensure we always return exactly 25 features
        if len(features) < 25:
            features.extend([0] * (25 - len(features)))
        elif len(features) > 25:
            features = features[:25]
            
        return np.array(features).reshape(1, -1)
    
    def train_on_real_data(self):
        """Train model on real-world malicious URL data from CSV files only"""
        logger.info("Training URL model on real-world CSV data...")
        
        try:
            # Check if CSV files exist
            if not real_data_loader.check_csv_files_exist():
                raise FileNotFoundError("Required CSV dataset files are missing")
            
            # Load real-world data from CSV
            urls, labels = real_data_loader.load_real_malicious_urls()
            
            if len(urls) == 0:
                raise ValueError("No URL data available in CSV files")
            
            # Extract features
            X_features = []
            y_filtered = []
            
            for url, label in zip(urls, labels):
                try:
                    features = self.extract_advanced_url_features(url)
                    X_features.append(features.flatten())  # Flatten to 1D array
                    y_filtered.append(label)
                except Exception as e:
                    logger.warning(f"Skipping URL {url} due to feature extraction error: {e}")
                    continue
            
            if len(X_features) == 0:
                raise ValueError("No valid URL features extracted")
            
            # Convert to numpy array
            X = np.vstack(X_features)
            y = np.array(y_filtered)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # Scale features
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Train model
            self.model.fit(X_train_scaled, y_train)
            
            # Evaluate model
            train_score = self.model.score(X_train_scaled, y_train)
            test_score = self.model.score(X_test_scaled, y_test)
            
            y_pred = self.model.predict(X_test_scaled)
            
            logger.info(f"URL Model Performance:")
            logger.info(f"Training Accuracy: {train_score:.3f}")
            logger.info(f"Testing Accuracy: {test_score:.3f}")
            # Generate detailed report with 3 decimal points
            report = classification_report(y_test, y_pred, digits=3)
            logger.info(f"Classification Report:\n{report}")
            
            self.is_trained = True
            
            logger.info("URL model training on CSV data completed!")
            return True
            
        except Exception as e:
            logger.error(f"Error training URL model on CSV data: {e}")
            raise
    
    def predict(self, url: str) -> Dict:
        """Predict if URL is malicious using CSV-trained model"""
        if not self.is_trained:
            logger.info("URL model not trained, training now...")
            self.train_on_real_data()
        
        # Extract features
        features = self.extract_advanced_url_features(url)
        features_scaled = self.scaler.transform(features)
        
        # Predict
        prediction = self.model.predict(features_scaled)[0]
        probability = self.model.predict_proba(features_scaled)[0]
        
        confidence = float(max(probability))
        risk_score = float(probability[1])  # Probability of being malicious
        
        # Risk level classification
        if risk_score >= 0.8:
            risk_level = "Critical"
        elif risk_score >= 0.6:
            risk_level = "High"
        elif risk_score >= 0.4:
            risk_level = "Medium"
        elif risk_score >= 0.2:
            risk_level = "Low"
        else:
            risk_level = "Minimal"
        
        return {
            'is_phishing': bool(prediction),
            'confidence': confidence,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'classification': 'Malicious' if prediction else 'Safe',
            'url_length': len(url),
            'suspicious_patterns': self._analyze_advanced_patterns(url),
            'model_type': 'Real-World CSV Trained',
            'training_data': 'CSV dataset only'
        }
    
    def _analyze_advanced_patterns(self, url: str) -> List[str]:
        """Analyze URL for advanced suspicious patterns"""
        patterns = []
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            if len(url) > 100:
                patterns.append("Unusually long URL (>100 chars)")
            
            if '@' in url:
                patterns.append("Contains @ symbol (potential redirect)")
            
            if '//' in url.split('://', 1)[-1]:
                patterns.append("Contains double slashes in path")
            
            if any(tld in domain for tld in self.suspicious_tlds):
                patterns.append("Uses suspicious top-level domain (.tk/.ml/.ga)")
            
            if re.match(r'.*\d+\.\d+\.\d+\.\d+.*', url):
                patterns.append("Uses IP address instead of domain name")
            
            if url.count('-') > 3:
                patterns.append("Excessive hyphens in URL")
            
            if any(shortener in domain for shortener in self.url_shorteners):
                patterns.append("Uses URL shortening service")
            
            # Check for typosquatting using keywords from CSV
            if self.phishing_keywords:
                brand_keywords = [kw for kw in self.phishing_keywords if any(brand in kw.lower() for brand in ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook'])]
                for keyword in brand_keywords:
                    if keyword in domain and not domain.endswith(f"{keyword}.com") and not domain.endswith(f"www.{keyword}.com"):
                        patterns.append(f"Potential {keyword} typosquatting")
            
            # Check for non-HTTPS URLs with sensitive keywords from CSV
            if not parsed.scheme.startswith('https') and self.phishing_keywords:
                sensitive_keywords = [kw for kw in self.phishing_keywords if any(sens in kw.lower() for sens in ['login', 'signin', 'account', 'payment', 'verify', 'confirm'])]
                if any(keyword in url.lower() for keyword in sensitive_keywords):
                    patterns.append("Non-HTTPS URL requesting sensitive information")
                
        except Exception as e:
            patterns.append("URL parsing error - potentially malformed")
        
        return patterns

# Initialize global models with real-world data
email_detector_real = RealWorldEmailPhishingDetector()
url_detector_real = RealWorldURLPhishingDetector()