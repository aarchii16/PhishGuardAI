from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any
import os
from dotenv import load_dotenv
import logging
from ml_models_real import email_detector_real as email_detector_traditional, url_detector_real as url_detector
try:
    from ml_models_deep import cnn_detector, lstm_detector, ensemble_detector
    DEEP_LEARNING_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Deep learning models not available: {e}")
    DEEP_LEARNING_AVAILABLE = False
    cnn_detector = lstm_detector = ensemble_detector = None
from real_world_data import real_data_loader

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Phishing Detection API", description="AI-powered phishing detection for emails and URLs")

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request models
class EmailAnalysisRequest(BaseModel):
    email_content: str
    model_type: str = "traditional"  # traditional, cnn, lstm, ensemble, bert, sentence, hybrid

class URLAnalysisRequest(BaseModel):
    url: str

class BulkAnalysisRequest(BaseModel):
    emails: Optional[list] = None
    urls: Optional[list] = None

# Response models
class AnalysisResponse(BaseModel):
    classification: str
    confidence: float
    risk_score: float
    details: Optional[Dict[str, Any]] = None
    model_type: str

@app.on_event("startup")
async def startup_event():
    """Initialize models on server startup with CSV data validation"""
    logger.info("🚀 Starting PhishGuard API server...")
    
    try:
        # Check if CSV dataset files exist first
        logger.info("📊 Checking CSV dataset files...")
        if not real_data_loader.check_csv_files_exist():
            logger.warning("⚠️ CSV dataset files not found. Models will be trained when first prediction is made.")
            logger.info("📝 Please ensure 'real_phishing_emails.csv' and 'real_malicious_urls.csv' are in the datasets directory.")
        else:
            logger.info("✅ CSV dataset files found")
            
            # Initialize and train email detector
            logger.info("📧 Initializing email detector...")
            if not email_detector_traditional.is_trained:
                logger.info("🔄 Training email detector on CSV data...")
                email_detector_traditional.train_on_real_data()
                logger.info("✅ Email detector trained successfully")
            else:
                logger.info("✅ Email detector already trained")
            
            # Initialize and train URL detector
            logger.info("🔗 Initializing URL detector...")
            if not url_detector.is_trained:
                logger.info("🔄 Training URL detector on CSV data...")
                url_detector.train_on_real_data()
                logger.info("✅ URL detector trained successfully")
            else:
                logger.info("✅ URL detector already trained")
        
        logger.info("🎉 Server initialization completed!")
        
    except Exception as e:
        logger.error(f"❌ Error during server initialization: {e}")
        logger.info("⚠️ Server will continue running, models will train on first prediction request.")

@app.get("/")
async def root():
    return {"message": "Phishing Detection API is running", "status": "healthy"}

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "models": {
            "email_detector": email_detector_traditional.is_trained,
            "url_detector": url_detector.is_trained
        }
    }

@app.post("/api/analyze-email")
async def analyze_email(request: EmailAnalysisRequest):
    """Analyze email for phishing patterns"""
    try:
        # Log the incoming request for debugging
        logger.info(f"Received email analysis request: {request}")
        
        # Validate request
        if not request.email_content or not request.email_content.strip():
            raise HTTPException(status_code=400, detail="Email content cannot be empty")
        
        # Check if CSV files exist before training
        if not real_data_loader.check_csv_files_exist():
            raise HTTPException(
                status_code=503,
                detail="CSV dataset files not found. Please ensure 'real_phishing_emails.csv' and 'real_malicious_urls.csv' are in the datasets directory."
            )
        
        # Select model based on request
        model_type = request.model_type.lower() if request.model_type else "traditional"
        
        if model_type == "traditional":
            detector = email_detector_traditional
            if not detector.is_trained:
                logger.info("Training traditional email detector...")
                success = detector.train_on_real_data()
                if not success:
                    raise HTTPException(status_code=500, detail="Failed to train traditional model")
        
        elif model_type in ["cnn", "lstm", "ensemble"]:
            if not DEEP_LEARNING_AVAILABLE:
                raise HTTPException(status_code=503, detail="Deep learning models not available due to dependency issues")
            
            if model_type == "cnn":
                detector = cnn_detector
            elif model_type == "lstm":
                detector = lstm_detector
            else:  # ensemble
                detector = ensemble_detector
            
            if not detector.is_trained:
                logger.info(f"Training {model_type.upper()} email detector...")
                success = detector.train_on_csv_data()
                if not success:
                    raise HTTPException(status_code=500, detail=f"Failed to train {model_type.upper()} model")
        
        elif model_type in ["bert", "sentence", "hybrid"]:
            raise HTTPException(status_code=503, detail="Transformer models temporarily disabled due to compatibility issues")
        
        else:
            raise HTTPException(status_code=400, detail=f"Unknown model type: {model_type}")
        
        # Analyze email
        result = detector.predict(request.email_content)
        
        if 'error' in result:
            raise HTTPException(status_code=500, detail=result['error'])
        
        return AnalysisResponse(
            classification=result.get('classification', 'Unknown'),
            confidence=result.get('confidence', 0.0),
            risk_score=result.get('risk_score', 0.0),
            details=result,
            model_type=result.get('model_type', model_type)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Email analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/analyze-url", response_model=AnalysisResponse)
async def analyze_url(request: URLAnalysisRequest):
    """Analyze URL for malicious patterns"""
    try:
        if not request.url.strip():
            raise HTTPException(status_code=400, detail="URL cannot be empty")
        
        # Ensure model is trained with CSV data validation
        if not url_detector.is_trained:
            logger.info("🔄 URL detector not trained, training on CSV data...")
            if not real_data_loader.check_csv_files_exist():
                raise HTTPException(
                    status_code=503, 
                    detail="CSV dataset files are missing. Please ensure 'real_phishing_emails.csv' and 'real_malicious_urls.csv' are in the datasets directory."
                )
            url_detector.train_on_real_data()
        
        # Basic URL validation
        if not (request.url.startswith('http://') or request.url.startswith('https://')):
            # Add protocol if missing
            url_to_analyze = f"http://{request.url}"
        else:
            url_to_analyze = request.url
        
        # Analyze URL
        logger.info(f"🔍 Analyzing URL: {url_to_analyze}")
        result = url_detector.predict(url_to_analyze)
        result['original_url'] = request.url
        result['analyzed_url'] = url_to_analyze
        
        logger.info(f"✅ URL analysis completed: {result['classification']} (confidence: {result['confidence']:.2f})")
        
        return AnalysisResponse(
            classification=result.get('classification', 'Unknown'),
            confidence=result.get('confidence', 0.0),
            risk_score=result.get('risk_score', 0.0),
            details=result,
            model_type="traditional"
        )
        
    except Exception as e:
        logger.error(f"❌ Error analyzing URL: {e}")
        logger.error(f"Error details: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/api/analyze-bulk", response_model=AnalysisResponse)
async def analyze_bulk(request: BulkAnalysisRequest):
    """Analyze multiple emails and URLs in bulk"""
    try:
        results = {
            'email_results': [],
            'url_results': [],
            'summary': {
                'total_emails': 0,
                'total_urls': 0,
                'phishing_emails': 0,
                'malicious_urls': 0
            }
        }
        
        # Analyze emails
        if request.emails:
            for i, email_data in enumerate(request.emails):
                try:
                    email_content = f"{email_data.get('subject', '')} {email_data.get('body', '')}".strip()
                    if email_content:
                        result = email_detector.predict(email_content)
                        result['index'] = i
                        result['email_data'] = email_data
                        results['email_results'].append(result)
                        
                        if result['is_phishing']:
                            results['summary']['phishing_emails'] += 1
                except Exception as e:
                    logger.error(f"Error analyzing email {i}: {e}")
            
            results['summary']['total_emails'] = len(request.emails)
        
        # Analyze URLs
        if request.urls:
            for i, url in enumerate(request.urls):
                try:
                    if url.strip():
                        # Add protocol if missing
                        url_to_analyze = url if url.startswith(('http://', 'https://')) else f"http://{url}"
                        result = url_detector.predict(url_to_analyze)
                        result['index'] = i
                        result['original_url'] = url
                        results['url_results'].append(result)
                        
                        if result['is_phishing']:
                            results['summary']['malicious_urls'] += 1
                except Exception as e:
                    logger.error(f"Error analyzing URL {i}: {e}")
            
            results['summary']['total_urls'] = len(request.urls)
        
        return AnalysisResponse(
            success=True,
            data=results,
            message="Bulk analysis completed successfully"
        )
        
    except Exception as e:
        logger.error(f"Error in bulk analysis: {e}")
        raise HTTPException(status_code=500, detail=f"Bulk analysis failed: {str(e)}")

@app.get("/api/dataset-info")
async def get_dataset_info():
    """Get information about the real-world datasets being used"""
    try:
        stats = real_data_loader.get_dataset_stats()
        
        dataset_info = {
            'data_source': 'CSV dataset files only - no hardcoded data',
            'training_type': 'Supervised learning on CSV dataset samples only',
            'email_dataset': {
                'description': 'Email data loaded exclusively from real_phishing_emails.csv',
                'total_samples': stats['email_dataset']['total_samples'],
                'phishing_samples': stats['email_dataset']['phishing_samples'],
                'legitimate_samples': stats['email_dataset']['legitimate_samples'],
                'balance_ratio': f"{stats['email_dataset']['phishing_ratio']:.1%} phishing"
            },
            'url_dataset': {
                'description': 'URL data loaded exclusively from real_malicious_urls.csv',
                'total_samples': stats['url_dataset']['total_samples'],
                'malicious_samples': stats['url_dataset']['malicious_samples'],
                'legitimate_samples': stats['url_dataset']['legitimate_samples'],
                'balance_ratio': f"{stats['url_dataset']['malicious_ratio']:.1%} malicious"
            },
            'model_improvements': [
                'Advanced feature engineering with 25+ URL features',
                'Enhanced NLP preprocessing with n-gram analysis',
                'Real-world phishing keyword patterns',
                'Typosquatting and brand impersonation detection',
                'Suspicious TLD and domain pattern recognition'
            ]
        }
        
        return AnalysisResponse(
            success=True,
            data=dataset_info,
            message="Real-world dataset information retrieved successfully"
        )
        
    except Exception as e:
        logger.error(f"Error getting dataset info: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get dataset info: {str(e)}")

@app.get("/api/stats")
async def get_statistics():
    """Get detection statistics and model info"""
    try:
        stats = {
            'models': {
                'email_detector': {
                    'trained': email_detector.is_trained,
                    'type': 'Logistic Regression + TF-IDF',
                    'features': 'Keywords, Text patterns, Statistical features'
                },
                'url_detector': {
                    'trained': url_detector.is_trained,
                    'type': 'Logistic Regression + Feature Engineering',
                    'features': 'URL patterns, Length, Suspicious domains'
                }
            },
            'detection_capabilities': {
                'email_analysis': True,
                'url_analysis': True,
                'bulk_analysis': True,
                'real_time': True
            },
            'supported_formats': {
                'emails': ['subject + body text', 'plain text'],
                'urls': ['http/https URLs', 'domain names']
            }
        }
        
        return AnalysisResponse(
            success=True,
            data=stats,
            message="Statistics retrieved successfully"
        )
        
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get statistics: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)