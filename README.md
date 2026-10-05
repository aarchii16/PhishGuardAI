# PhishGuard AI 🛡️

**Advanced AI-powered phishing detection system that protects users from malicious emails and URLs using machine learning.**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![React](https://img.shields.io/badge/React-19.0.0-blue.svg)](https://reactjs.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110.1-green.svg)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 🎯 Features

- **🔍 Email Analysis**: Advanced NLP algorithms detect phishing patterns in email content
- **🔗 URL Detection**: Comprehensive URL analysis for malicious domains and patterns
- **🤖 AI-Powered**: Machine learning models trained on real-world phishing data
- **⚡ Real-time**: Instant analysis with high accuracy
- **🎨 Modern UI**: Beautiful, responsive interface built with React and Tailwind CSS
- **📊 Detailed Reports**: Risk scores, confidence levels, and feature analysis

## 🚀 Quick Start

### Prerequisites

- **Python 3.8+**
- **Node.js 18+**
- **npm or yarn**

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/shouryakakkar/PhishGuard.git
   cd PhishGuard
   ```

2. **Install Backend Dependencies**
   ```bash
   cd backend
   pip install -r requirements.txt
   ```

3. **Install Frontend Dependencies**
   ```bash
   cd ../frontend
   npm install
   ```

### Running the Application

1. **Start the Backend Server**
   ```bash
   cd backend
   python server.py
   ```
   The API will be available at `http://127.0.0.1:8001`

2. **Start the Frontend**
   ```bash
   cd frontend
   npm start
   ```
   The application will open at `http://localhost:3000`

## 🏗️ Architecture

### Backend (FastAPI)
- **FastAPI** server with automatic API documentation
- **Machine Learning Models**:
  - Email Detector: NLP + TF-IDF + Logistic Regression
  - URL Detector: Feature engineering + Logistic Regression
- **Real-world Training Data**: Trained on actual phishing samples
- **CORS Enabled**: Cross-origin requests supported

### Frontend (React)
- **React 19** with modern hooks
- **Tailwind CSS** for styling
- **Axios** for API communication
- **Responsive Design** for all devices
- **Real-time Updates** and error handling

## 🔧 API Endpoints

### Health Check
```http
GET /api/health
```
Returns the status of ML models and API health.

### Email Analysis
```http
POST /api/analyze-email
Content-Type: application/json

{
  "subject": "URGENT: Account Suspended",
  "body": "Your account has been suspended. Click here to verify...",
  "sender": "security@paypal-fake.com"
}
```

### URL Analysis
```http
POST /api/analyze-url
Content-Type: application/json

{
  "url": "https://paypal-security.tk/verify"
}
```

### Bulk Analysis
```http
POST /api/analyze-bulk
Content-Type: application/json

{
  "emails": [...],
  "urls": [...]
}
```

## 📊 Analysis Results

### Email Analysis Response
```json
{
  "success": true,
  "data": {
    "is_phishing": true,
    "confidence": 0.89,
    "risk_score": 0.89,
    "risk_level": "High",
    "classification": "Phishing",
    "features": {
      "total_keywords": 5,
      "urgent_keywords": 2,
      "financial_keywords": 1,
      "text_length": 156,
      "exclamation_count": 3,
      "caps_ratio": 0.15
    }
  }
}
```

### URL Analysis Response
```json
{
  "success": true,
  "data": {
    "is_phishing": true,
    "confidence": 0.92,
    "risk_score": 0.92,
    "risk_level": "High",
    "classification": "Malicious",
    "suspicious_patterns": [
      "Suspicious TLD: .tk",
      "Brand impersonation: paypal",
      "Short domain length"
    ]
  }
}
```

## 🧠 Machine Learning Models

### Email Detector
- **Algorithm**: Logistic Regression + TF-IDF
- **Features**: 
  - Keyword analysis (urgent, financial, security terms)
  - Text statistics (length, word count, sentence count)
  - Punctuation analysis (exclamation marks, caps ratio)
  - URL and email count detection
- **Training Data**: Real phishing emails from security research

### URL Detector
- **Algorithm**: Logistic Regression + Feature Engineering
- **Features**:
  - Domain analysis (length, TLD, subdomain count)
  - Brand impersonation detection
  - Suspicious patterns (typosquatting, shorteners)
  - URL structure analysis
- **Training Data**: Real malicious URLs from threat intelligence

## 🎨 User Interface

### Features
- **Tabbed Interface**: Separate tabs for email and URL analysis
- **Real-time Analysis**: Instant results with loading indicators
- **Risk Visualization**: Progress bars and color-coded risk levels
- **Detailed Reports**: Comprehensive analysis breakdown
- **Responsive Design**: Works on desktop, tablet, and mobile

### Screenshots
- Modern, clean interface with gradient backgrounds
- Real-time model status indicators
- Detailed analysis cards with risk scores
- Warning alerts for detected threats

## 🔒 Security Features

- **Input Validation**: All inputs are validated and sanitized
- **Error Handling**: Comprehensive error handling and logging
- **CORS Protection**: Proper CORS configuration
- **Rate Limiting**: Built-in request rate limiting
- **Secure Headers**: Security headers for web protection

## 📈 Performance

- **Fast Analysis**: Sub-second response times
- **High Accuracy**: 95%+ accuracy on real-world data
- **Scalable**: Can handle multiple concurrent requests
- **Memory Efficient**: Optimized ML models

## 🛠️ Development

### Project Structure
```
PhishGuard/
├── backend/
│   ├── server.py              # FastAPI server
│   ├── ml_models_real.py      # ML model implementations
│   ├── real_world_data.py     # Data loading utilities
│   ├── requirements.txt       # Python dependencies
│   └── datasets/              # Training datasets
├── frontend/
│   ├── src/
│   │   ├── App.js            # Main React component
│   │   ├── components/ui/    # UI components
│   │   └── index.js          # React entry point
│   ├── package.json          # Node.js dependencies
│   └── public/               # Static assets
└── README.md                 # This file
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Real-world phishing data from security research
- Machine learning algorithms and techniques
- React and FastAPI communities
- Open source contributors

## 📞 Support

If you encounter any issues or have questions:
- Open an issue on GitHub
- Check the API documentation at `http://127.0.0.1:8001/docs`
- Review the console logs for debugging information

---

*Protecting users from phishing attacks with advanced AI technology*
