import requests
import json

def test_server():
    """Test the PhishGuard server endpoints"""
    base_url = "http://localhost:8000"
    
    # Test health check
    try:
        response = requests.get(f"{base_url}/health")
        print(f"Health check: {response.status_code}")
        if response.status_code == 200:
            print(f"Response: {response.json()}")
    except Exception as e:
        print(f"Health check failed: {e}")
        return
    
    # Test email analysis with traditional model
    test_email = "URGENT: Your account will be suspended! Click here to verify immediately."
    
    try:
        response = requests.post(
            f"{base_url}/api/analyze-email",
            json={
                "email_content": test_email,
                "model_type": "traditional"
            }
        )
        print(f"\nEmail analysis (traditional): {response.status_code}")
        if response.status_code == 200:
            result = response.json()
            print(f"Classification: {result['classification']}")
            print(f"Risk Score: {result['risk_score']:.3f}")
            print(f"Model Type: {result['model_type']}")
        else:
            print(f"Error: {response.text}")
    except Exception as e:
        print(f"Email analysis failed: {e}")
    
    # Test URL analysis
    test_url = "http://paypal-verify.tk/login"
    
    try:
        response = requests.post(
            f"{base_url}/api/analyze-url",
            json={"url": test_url}
        )
        print(f"\nURL analysis: {response.status_code}")
        if response.status_code == 200:
            result = response.json()
            print(f"Classification: {result['classification']}")
            print(f"Risk Score: {result['risk_score']:.3f}")
        else:
            print(f"Error: {response.text}")
    except Exception as e:
        print(f"URL analysis failed: {e}")

if __name__ == "__main__":
    print("Testing PhishGuard Server...")
    test_server()
