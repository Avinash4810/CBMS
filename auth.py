import os

GOOGLE_CLIENT_ID = "1050027066533-7qusd2s1kha1vbgnv58g33lkbc46l8gd.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

# OAuth 2.0 configuration
OAUTH2_CONFIG = {
    'web': {
        'client_id': GOOGLE_CLIENT_ID,
        'project_id': 'cloud-based-media-storage',
        'auth_uri': 'https://accounts.google.com/o/oauth2/auth',
        'token_uri': 'https://oauth2.googleapis.com/token',
        'auth_provider_x509_cert_url': 'https://www.googleapis.com/oauth2/v1/certs',
        'client_secret': GOOGLE_CLIENT_SECRET,
        'redirect_uris': [
            # Production URIs
            "https://cbms.onrender.com/callback",
            "https://cbms.onrender.com/oauth2callback"
        ],
        'javascript_origins': [
            "https://cbms.onrender.com"
        ]
    }
}