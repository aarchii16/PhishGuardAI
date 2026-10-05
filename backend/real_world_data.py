import pandas as pd
import numpy as np
import os
import logging
from typing import Dict, List, Tuple

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RealWorldDataLoader:
    def __init__(self):
        # Use relative path for local development
        self.datasets_dir = os.path.join(os.path.dirname(__file__), "datasets")
        os.makedirs(self.datasets_dir, exist_ok=True)
        self.email_csv_path = os.path.join(self.datasets_dir, 'real_phishing_emails.csv')
        self.url_csv_path = os.path.join(self.datasets_dir, 'real_malicious_urls.csv')
        self.keywords_csv_path = os.path.join(self.datasets_dir, 'phishing_keywords.csv')
        self.tlds_csv_path = os.path.join(self.datasets_dir, 'suspicious_tlds.csv')
        self.shorteners_csv_path = os.path.join(self.datasets_dir, 'url_shorteners.csv')
    
    def load_real_phishing_emails(self) -> Tuple[List[str], List[int]]:
        """Load real-world phishing email dataset from CSV file"""
        logger.info("Loading real-world phishing email data from CSV...")
        
        if not os.path.exists(self.email_csv_path):
            raise FileNotFoundError(f"Email dataset CSV file not found: {self.email_csv_path}")
        
        try:
            df = pd.read_csv(self.email_csv_path)
            
            # Clean and validate data
            emails = df['email_content'].astype(str).tolist()
            
            # Convert labels to integers, handling mixed types
            labels = []
            for label in df['is_phishing']:
                try:
                    # Convert to int, handling both string and numeric values
                    if isinstance(label, str):
                        labels.append(1 if label.lower() in ['1', 'true', 'phishing'] else 0)
                    else:
                        labels.append(int(label))
                except (ValueError, TypeError):
                    # Default to 0 for invalid values
                    labels.append(0)
            
            # Filter out empty emails
            valid_data = [(email, label) for email, label in zip(emails, labels) if email.strip()]
            emails, labels = zip(*valid_data) if valid_data else ([], [])
            emails, labels = list(emails), list(labels)
            
            logger.info(f"Loaded {len(emails)} emails from CSV ({sum(labels)} phishing, {len(emails) - sum(labels)} legitimate)")
            return emails, labels
            
        except Exception as e:
            logger.error(f"Error loading email dataset from CSV: {e}")
            raise
    
    def load_real_malicious_urls(self) -> Tuple[List[str], List[int]]:
        """Load real-world malicious URL dataset from CSV file"""
        logger.info("Loading real-world malicious URL data from CSV...")
        
        if not os.path.exists(self.url_csv_path):
            raise FileNotFoundError(f"URL dataset CSV file not found: {self.url_csv_path}")
        
        try:
            df = pd.read_csv(self.url_csv_path)
            
            # Clean and validate data
            urls = df['url'].astype(str).tolist()
            
            # Convert labels to integers, handling mixed types
            labels = []
            for label in df['is_malicious']:
                try:
                    # Convert to int, handling both string and numeric values
                    if isinstance(label, str):
                        labels.append(1 if label.lower() in ['1', 'true', 'malicious'] else 0)
                    else:
                        labels.append(int(label))
                except (ValueError, TypeError):
                    # Default to 0 for invalid values
                    labels.append(0)
            
            # Filter out empty URLs
            valid_data = [(url, label) for url, label in zip(urls, labels) if url.strip()]
            urls, labels = zip(*valid_data) if valid_data else ([], [])
            urls, labels = list(urls), list(labels)
            
            logger.info(f"Loaded {len(urls)} URLs from CSV ({sum(labels)} malicious, {len(urls) - sum(labels)} legitimate)")
            return urls, labels
            
        except Exception as e:
            logger.error(f"Error loading URL dataset from CSV: {e}")
            raise
    
    def check_csv_files_exist(self) -> bool:
        """Check if the main CSV dataset files exist (only require the two main files)"""
        # Only check for the two main files
        main_files_exist = (
            os.path.exists(self.email_csv_path) and 
            os.path.exists(self.url_csv_path)
        )
        
        return main_files_exist
    
    def get_dataset_stats(self):
        """Get statistics about the loaded datasets"""
        try:
            emails, email_labels = self.load_real_phishing_emails()
            urls, url_labels = self.load_real_malicious_urls()
            
            stats = {
                'email_dataset': {
                    'total_samples': len(emails),
                    'phishing_samples': sum(email_labels),
                    'legitimate_samples': len(emails) - sum(email_labels),
                    'phishing_ratio': sum(email_labels) / len(emails) if emails else 0
                },
                'url_dataset': {
                    'total_samples': len(urls),
                    'malicious_samples': sum(url_labels),
                    'legitimate_samples': len(urls) - sum(url_labels),
                    'malicious_ratio': sum(url_labels) / len(urls) if urls else 0
                }
            }
            
            return stats
        except Exception as e:
            logger.error(f"Error getting dataset stats: {e}")
            return {
                'email_dataset': {'total_samples': 0, 'phishing_samples': 0, 'legitimate_samples': 0, 'phishing_ratio': 0},
                'url_dataset': {'total_samples': 0, 'malicious_samples': 0, 'legitimate_samples': 0, 'malicious_ratio': 0}
            }
    
    def load_phishing_keywords(self) -> Dict:
        """Load phishing keywords from CSV file or return defaults"""
        logger.info("Loading phishing keywords...")
        
        if not os.path.exists(self.keywords_csv_path):
            logger.info("Keywords CSV file not found, using default keywords")
            # Return default keywords
            default_keywords = [
                'urgent', 'immediate', 'act now', 'click here', 'verify', 'confirm', 'account',
                'suspended', 'limited', 'expires', 'deadline', 'asap', 'alert', 'warning',
                'payment', 'billing', 'refund', 'invoice', 'bank', 'financial', 'security',
                'password', 'login', 'signin', 'update', 'upgrade', 'renew', 'reactivate',
                'win', 'winner', 'prize', 'congratulations', 'lottery', 'cash', 'money',
                'free', 'offer', 'deal', 'discount', 'sale', 'paypal', 'amazon', 'google',
                'microsoft', 'apple', 'facebook', 'instagram', 'twitter', 'linkedin'
            ]
            return {
                'all_keywords': default_keywords,
                'by_category': {
                    'urgent': [{'keyword': kw, 'weight': 1} for kw in default_keywords if kw in ['urgent', 'immediate', 'act now', 'expires', 'deadline', 'asap']],
                    'financial': [{'keyword': kw, 'weight': 1} for kw in default_keywords if kw in ['payment', 'billing', 'refund', 'invoice', 'bank', 'financial']],
                    'security': [{'keyword': kw, 'weight': 1} for kw in default_keywords if kw in ['security', 'password', 'login', 'signin', 'verify', 'confirm']],
                    'general': [{'keyword': kw, 'weight': 1} for kw in default_keywords if kw not in ['urgent', 'immediate', 'act now', 'expires', 'deadline', 'asap', 'payment', 'billing', 'refund', 'invoice', 'bank', 'financial', 'security', 'password', 'login', 'signin', 'verify', 'confirm']]
                }
            }
        
        try:
            df = pd.read_csv(self.keywords_csv_path)
            keywords_by_category = {}
            all_keywords = []
            
            for _, row in df.iterrows():
                keyword = str(row['keyword']).strip()
                category = str(row['category']).strip()
                weight = int(row.get('weight', 1))
                
                if category not in keywords_by_category:
                    keywords_by_category[category] = []
                
                keywords_by_category[category].append({
                    'keyword': keyword,
                    'weight': weight
                })
                all_keywords.append(keyword)
            
            logger.info(f"Loaded {len(all_keywords)} phishing keywords from CSV")
            return {
                'all_keywords': all_keywords,
                'by_category': keywords_by_category
            }
            
        except Exception as e:
            logger.error(f"Error loading keywords from CSV: {e}")
            # Return defaults as fallback
            return self.load_phishing_keywords()
    
    def load_suspicious_tlds(self) -> List[str]:
        """Load suspicious TLDs from CSV file or return defaults"""
        logger.info("Loading suspicious TLDs...")
        
        if not os.path.exists(self.tlds_csv_path):
            logger.info("TLDs CSV file not found, using default TLDs")
            # Return default suspicious TLDs
            default_tlds = [
                'tk', 'ml', 'ga', 'cf', 'ru', 'cn', 'xyz', 'top', 'club', 'info',
                'site', 'online', 'space', 'tech', 'host', 'store', 'loan', 'bid',
                'dating', 'review', 'science', 'party', 'work', 'click', 'link',
                'download', 'help', 'racing', 'win', 'trade', 'accountant'
            ]
            return default_tlds
        
        try:
            df = pd.read_csv(self.tlds_csv_path)
            tlds = [str(row['tld']).strip() for _, row in df.iterrows()]
            
            logger.info(f"Loaded {len(tlds)} suspicious TLDs from CSV")
            return tlds
            
        except Exception as e:
            logger.error(f"Error loading TLDs from CSV: {e}")
            # Return defaults as fallback
            return self.load_suspicious_tlds()
    
    def load_url_shorteners(self) -> List[str]:
        """Load URL shorteners from CSV file or return defaults"""
        logger.info("Loading URL shorteners...")
        
        if not os.path.exists(self.shorteners_csv_path):
            logger.info("URL shorteners CSV file not found, using default shorteners")
            # Return default URL shorteners
            default_shorteners = [
                'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'buff.ly',
                'is.gd', 'soo.gd', 'adf.ly', 'j.mp', 'cutt.ly', 'shorturl.at',
                'tiny.cc', 'bl.ink', 'rebrand.ly', 'lnkd.in', 'fb.me', 'youtu.be'
            ]
            return default_shorteners
        
        try:
            df = pd.read_csv(self.shorteners_csv_path)
            shorteners = [str(row['domain']).strip() for _, row in df.iterrows()]
            
            logger.info(f"Loaded {len(shorteners)} URL shorteners from CSV")
            return shorteners
            
        except Exception as e:
            logger.error(f"Error loading URL shorteners from CSV: {e}")
            # Return defaults as fallback
            return self.load_url_shorteners()

# Create global instance
real_data_loader = RealWorldDataLoader()