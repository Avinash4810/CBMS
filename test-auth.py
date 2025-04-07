import os
import json
import logging
import requests
from pathlib import Path
import google_auth_oauthlib.flow
import google.oauth2.credentials
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('test-auth')

def test_credentials_files():
    """Test if credential files exist and are valid"""
    try:
        # Test client_secrets.json
        secrets_path = os.path.join(Path(__file__).parent, "client_secrets.json")
        if not os.path.exists(secrets_path):
            logger.error("client_secrets.json not found")
            return False
            
        with open(secrets_path, 'r') as f:
            client_config = json.load(f)
            if 'web' not in client_config:
                logger.error("Invalid client_secrets.json format")
                return False
            logger.info("client_secrets.json is valid")
            
        # Test service-account.json
        service_account_path = os.path.join(Path(__file__).parent, "service-account.json")
        if not os.path.exists(service_account_path):
            logger.error("service-account.json not found")
            return False
            
        with open(service_account_path, 'r') as f:
            service_config = json.load(f)
            required_keys = ['type', 'project_id', 'private_key_id', 'private_key', 'client_email']
            if not all(key in service_config for key in required_keys):
                logger.error("Invalid service-account.json format")
                return False
            logger.info("service-account.json is valid")
            
        return True
    except Exception as e:
        logger.error(f"Credential file test failed: {str(e)}")
        return False

def test_oauth_flow():
    """Test OAuth flow configuration"""
    try:
        with open("client_secrets.json", 'r') as f:
            client_config = json.load(f)
            
        flow = google_auth_oauthlib.flow.Flow.from_client_config(
            client_config,
            scopes=["https://www.googleapis.com/auth/userinfo.profile",
                   "https://www.googleapis.com/auth/userinfo.email",
                   "openid"]
        )
        
        flow.redirect_uri = "http://localhost:5000/callback"
        
        # Test authorization URL generation
        auth_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'
        )
        
        logger.info(f"Authorization URL generated successfully: {auth_url[:100]}...")
        return True
    except Exception as e:
        logger.error(f"OAuth flow test failed: {str(e)}")
        return False

def test_google_api_access():
    """Test Google API access"""
    try:
        # Load OAuth credentials instead of service account
        with open("client_secrets.json", 'r') as f:
            client_config = json.load(f)
            client_id = client_config['web']['client_id']
            
        # Test token info endpoint instead
        response = requests.get(
            "https://oauth2.googleapis.com/tokeninfo",
            params={'client_id': client_id}
        )
        
        if response.status_code != 400:  # 400 is expected for invalid token
            logger.error(f"Unexpected response from token endpoint: {response.status_code}")
            return False
            
        logger.info("Google API endpoints are accessible")
        return True
    except Exception as e:
        logger.error(f"Google API test failed: {str(e)}")
        return False

def verify_oauth_config():
    """Verify OAuth configuration"""
    try:
        required_env_vars = [
            "GOOGLE_CLIENT_ID",
            "GOOGLE_CLIENT_SECRET",
            "OAUTHLIB_INSECURE_TRANSPORT"
        ]
        
        # Check if variables exist in environment
        missing_vars = []
        for var in required_env_vars:
            value = os.getenv(var)
            if not value:
                missing_vars.append(var)
            else:
                logger.info(f"Found {var}")
                
        if missing_vars:
            logger.error(f"Missing environment variables: {missing_vars}")
            return False
            
        logger.info("All required OAuth environment variables are set")
        return True
    except Exception as e:
        logger.error(f"OAuth config verification failed: {str(e)}")
        return False

def run_all_tests():
    """Run all authentication tests"""
    logger.info("Starting authentication tests...")
    
    results = {
        "Credentials Files": test_credentials_files(),
        "OAuth Flow": test_oauth_flow(),
        "Google API Access": test_google_api_access(),
        "OAuth Config": verify_oauth_config()
    }
    
    logger.info("\nTest Results:")
    for test, passed in results.items():
        logger.info(f"{test}: {'✓ Passed' if passed else '✗ Failed'}")
    
    return all(results.values())

if __name__ == "__main__":
    success = run_all_tests()
    if not success:
        logger.error("\nOne or more tests failed. Authentication may not work properly.")
        exit(1)
    else:
        logger.info("\nAll tests passed! Authentication should work correctly.")