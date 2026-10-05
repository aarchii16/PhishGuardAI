import requests
import json

def test_email_endpoint():
    """Debug the email endpoint to see exact validation error"""
    url = "http://localhost:8001/api/analyze-email"
    
    # Test different request formats
    test_cases = [
        {"email_content": "URGENT: Your account will be suspended!", "model_type": "traditional"},
        {"email_content": "URGENT: Your account will be suspended!"},  # Without model_type
        {"content": "URGENT: Your account will be suspended!", "model_type": "traditional"},  # Wrong field name
    ]
    
    for i, payload in enumerate(test_cases):
        print(f"\n--- Test Case {i+1} ---")
        print(f"Payload: {json.dumps(payload, indent=2)}")
        
        try:
            response = requests.post(url, json=payload)
            print(f"Status Code: {response.status_code}")
            print(f"Response: {response.text}")
            
            if response.status_code == 422:
                try:
                    error_detail = response.json()
                    print(f"Validation Error Details: {json.dumps(error_detail, indent=2)}")
                except:
                    pass
                    
        except Exception as e:
            print(f"Request failed: {e}")

if __name__ == "__main__":
    test_email_endpoint()
