import os
import json
import sys
import logging
import time
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

from flask import Flask, request, send_file, render_template, g, redirect, url_for, session, abort, jsonify

app = Flask(__name__,
    template_folder=os.path.abspath(os.path.join(os.path.dirname(__file__), 'templates')),
    static_folder=os.path.abspath(os.path.join(os.path.dirname(__file__), 'static'))
)
app.secret_key = os.urandom(24)
app.logger.setLevel(logging.DEBUG)
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import google.oauth2.credentials
import google_auth_oauthlib.flow
import google.auth.transport.requests
import google.oauth2.credentials
from google.auth.transport.requests import Request
from google.oauth2 import id_token
from pip._vendor import cachecontrol
from models import User, init_user_db, get_user
import pathlib
import requests
import sqlite3
import io
from gcloud import CloudStorage
from flask_cors import CORS
import traceback
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
import threading
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from logger_config import setup_logger
from googleapiclient.http import MediaIoBaseUpload, MediaIoBaseDownload
import zstandard as zstd
import io
from googleapiclient.discovery import build
from flask_wtf.csrf import CSRFProtect
from flask_wtf.csrf import generate_csrf
import pytz

# Create a timezone object for IST
ist = pytz.timezone('Asia/Kolkata')

# Keep these environment variable settings
if not os.path.exists("service-account.json"):
    raise FileNotFoundError(
        "service-account.json not found. Please add your Google Cloud credentials file."
    )

# Verify environment variable is set
if 'GOOGLE_APPLICATION_CREDENTIALS' not in os.environ:
    os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "service-account.json")
    )

try:
    from dotenv import load_dotenv
    load_dotenv()  # Load environment variables from .env file
except ImportError:
    # In production, environment variables should be set in the hosting platform
    pass

# At the top of the file, after creating Flask app
csrf = CSRFProtect()
csrf.init_app(app)
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_SECRET_KEY'] = os.urandom(24)  # Add this line

# Add this context processor to make csrf_token available in all templates
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf())

# Update the get_google_drive_service function
def get_google_drive_service():
    """Create and return an authorized Google Drive service instance."""
    try:
        if 'credentials' not in session:
            app.logger.error("No credentials in session")
            return None

        # Load credentials from session
        creds_dict = session.get('credentials')
        if not creds_dict:
            app.logger.error("Empty credentials in session")
            return None

        credentials = google.oauth2.credentials.Credentials(
            token=creds_dict.get('token'),
            refresh_token=creds_dict.get('refresh_token'),
            token_uri=creds_dict.get('token_uri'),
            client_id=creds_dict.get('client_id'),
            client_secret=creds_dict.get('client_secret'),
            scopes=creds_dict.get('scopes')
        )

        # Refresh token if expired
        if credentials.expired:
            app.logger.info("Refreshing expired credentials")
            credentials.refresh(Request())
            session['credentials'] = credentials_to_dict(credentials)

        return build('drive', 'v3', credentials=credentials)
    except Exception as e:
        app.logger.error(f"Drive service error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return None

# Add this helper function
def credentials_to_dict(credentials):
    """Convert credentials to dictionary for session storage."""
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

# Load Google OAuth configuration
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
if not GOOGLE_CLIENT_ID:
    raise ValueError("GOOGLE_CLIENT_ID environment variable is not set")

# Set Google Cloud credentials path with absolute path
os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "service-account.json")
)

CORS(app, resources={
    r"/*": {
        "origins": [
            "http://localhost:5000",
            "http://127.0.0.1:5000",
            "https://storage.googleapis.com"
        ],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": [
            "Content-Type", 
            "Authorization",
            "x-requested-with",
            "Access-Control-Allow-Origin",
            "Access-Control-Allow-Methods",
            "Access-Control-Allow-Headers"
        ],
        "supports_credentials": True,
        "max_age": 3600
    }
})

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return get_user(user_id)

# Initialize Cloud Storage with retry
def init_storage():
    max_retries = 3
    for attempt in range(max_retries):
        try:
            storage = CloudStorage()
            app.logger.info("Cloud Storage initialized successfully")
            return storage
        except Exception as e:
            app.logger.error(f"Storage initialization attempt {attempt + 1} failed: {e}")
            if attempt == max_retries - 1:
                app.logger.error("All storage initialization attempts failed")
                return None

# Initialize storage
storage = init_storage()

DATABASE = "files.db"


# Configure Google OAuth
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # Only for development
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secrets.json")

# Update the OAuth flow initialization with Drive scopes
flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=[
        "https://www.googleapis.com/auth/userinfo.profile", 
        "https://www.googleapis.com/auth/userinfo.email", 
        "https://www.googleapis.com/auth/drive.file",  # Add this scope for Drive access
        "openid"
    ],
    redirect_uri=["https://cbms.onrender.com/callback", "http://localhost:5000/callback"]
)

# Add these at the top of your file
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Only for development
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

# Create table if not exists
def init_db():
    with get_db() as conn:
        cur = conn.cursor()
        # Get current schema
        cur.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='files'")
        current_schema = cur.fetchone()
        
        if current_schema:
            app.logger.info("Files table exists with schema:")
            app.logger.info(current_schema[0])
        else:
            app.logger.info("Creating files table...")
            cur.execute("""
                CREATE TABLE files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_file_id INTEGER,
                    user_id TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    storage_path TEXT NOT NULL,
                    mimetype TEXT NOT NULL,
                    filesize INTEGER NOT NULL,
                    upload_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    upload_status TEXT DEFAULT 'pending',
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    UNIQUE(user_id, user_file_id)
                )
            """)
            conn.commit()
            app.logger.info("Files table created successfully")

# Define allowed file extensions
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mp3', 'wav'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Add this function to initialize database on first run
def initialize_app():
    # Create databases if they don't exist
    if not os.path.exists(DATABASE):
        with app.app_context():
            init_db()
            print("Initialized files database")
    
    if not os.path.exists('users.db'):
        init_user_db()
        print("Initialized users database")

@app.before_request
def before_request():
    init_db()

# Add login routes
@app.route("/start-auth", methods=['POST'])
def start_auth():
    try:
        # Verify reCAPTCHA first
        recaptcha_response = request.json.get('g-recaptcha-response')
        if not recaptcha_response:
            return jsonify({'error': 'Please complete the reCAPTCHA verification'}), 400

        # Add remote IP to verification
        verify_url = 'https://www.google.com/recaptcha/api/siteverify'
        response = requests.post(verify_url, data={
            'secret': '6LdcIgUrAAAAACRDr3O0mfpvr1R3qgNo1n7Rqub_',
            'response': recaptcha_response,
            'remoteip': request.remote_addr
        })
        
        verification_response = response.json()
        
        if not verification_response.get('success'):
            app.logger.error(f"reCAPTCHA verification failed: {verification_response}")
            return jsonify({'error': 'reCAPTCHA verification failed'}), 400

        # Continue with OAuth flow
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'
        )
        
        session['state'] = state
        return jsonify({'auth_url': authorization_url})
        
    except Exception as e:
        app.logger.error(f"Auth error: {str(e)}")
        return jsonify({'error': 'Authentication failed'}), 500

@app.route("/login")
def login():
    if request.args.get('code'):
        # Handle OAuth callback
        try:
            flow.fetch_token(authorization_response=request.url)
            credentials = flow.credentials
            
            request_session = requests.session()
            cached_session = cachecontrol.CacheControl(request_session)
            token_request = google.auth.transport.requests.Request(session=cached_session)

            # Add clock_skew_in_seconds parameter to handle minor time differences
            id_info = id_token.verify_oauth2_token(
                id_token=credentials._id_token,
                request=token_request,
                audience=GOOGLE_CLIENT_ID,
                clock_skew_in_seconds=10
            )

            user = User(
                id_=id_info.get("sub"),
                name=id_info.get("name"),
                email=id_info.get("email"),
                profile_pic=id_info.get("picture")
            )

            # Store user in database
            with sqlite3.connect('users.db') as conn:
                c = conn.cursor()
                c.execute('''INSERT OR REPLACE INTO users (id, name, email, profile_pic) 
                            VALUES (?, ?, ?, ?)''', 
                        (user.id, user.name, user.email, user.profile_pic))
                conn.commit()

            login_user(user)
            return redirect(url_for('index'))

        except Exception as e:
            app.logger.error(f"Auth error: {str(e)}")
            return render_template('login.html', error="Authentication failed")
    
    return render_template('login.html')

# Update the callback route to store credentials
@app.route("/callback")
def callback():
    try:
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials
        
        # Store credentials in session
        session['credentials'] = credentials_to_dict(credentials)
        
        # Get user info from Google
        userinfo_endpoint = "https://www.googleapis.com/oauth2/v3/userinfo"
        response = requests.get(
            userinfo_endpoint,
            headers={'Authorization': f'Bearer {credentials.token}'}
        )
        if not response.ok:
            raise Exception("Failed to get user info")
            
        userinfo = response.json()
        
        # Create user
        user = User(
            id_=userinfo.get("sub"),
            name=userinfo.get("name"),
            email=userinfo.get("email"),
            profile_pic=userinfo.get("picture")
        )

        # Store user in database
        with sqlite3.connect('users.db') as conn:
            c = conn.cursor()
            c.execute('''INSERT OR REPLACE INTO users (id, name, email, profile_pic) 
                        VALUES (?, ?, ?, ?)''', 
                    (user.id, user.name, user.email, user.profile_pic))
            conn.commit()

        login_user(user)
        return redirect(url_for('index'))

    except Exception as e:
        app.logger.error(f"Authentication error: {str(e)}")
        return render_template("login.html", error="Authentication failed. Please try again."), 401

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


# Upload file route
@app.route("/upload", methods=["POST"])
@login_required
def upload_file():
    if "file[]" not in request.files:
        return jsonify({"error": "No files selected"}), 400

    files = request.files.getlist("file[]")
    if not files or all(f.filename == "" for f in files):
        return jsonify({"error": "No files selected"}), 400

    uploaded_files = []
    
    try:
        storage = CloudStorage()  # Initialize only when needed
        
        with get_db() as conn:
            cur = conn.cursor()
            
            # Get next file ID
            cur.execute("""
                SELECT COALESCE(MAX(user_file_id), 0)
                FROM files 
                WHERE user_id = ?
            """, (current_user.id,))
            next_file_id = cur.fetchone()[0] + 1
            
            for file in files:
                filename = secure_filename(file.filename)
                file_data = file.read()
                content_type = file.content_type or 'application/octet-stream'
                filesize = len(file_data)
                storage_path = f"{current_user.id}/{next_file_id}/{filename}"
                
                # Upload to storage
                public_url = storage.upload_file(file_data, storage_path, content_type)
                
                # Save to database
                cur.execute("""
                    INSERT INTO files 
                    (user_file_id, user_id, filename, storage_path, mimetype, filesize, upload_timestamp) 
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (next_file_id, current_user.id, filename, storage_path, 
                     content_type, filesize, get_ist_time()))
                
                uploaded_files.append({
                    'filename': filename,
                    'url': public_url
                })
                
                next_file_id += 1
            
            conn.commit()

        return jsonify({
            "message": f"Successfully uploaded {len(uploaded_files)} file(s)",
            "files": uploaded_files
        })
        
    except Exception as e:
        app.logger.error(f"Upload error: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Retrieve file route
@app.route("/file/<int:file_id>")
@login_required
def get_file(file_id):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT filename, storage_path, mimetype 
            FROM files 
            WHERE user_file_id = ? AND user_id = ?
        """, (file_id, current_user.id))
        file = cur.fetchone()
        
    if file is None:
        abort(404)
    
    try:
        # Download from Cloud Storage
        file_data = storage.download_file(file[1])
        
        return send_file(
            io.BytesIO(file_data),
            mimetype=file[2],
            as_attachment=True,
            download_name=file[0]
        )
    except Exception as e:
        app.logger.error(f"Download error: {str(e)}")
        abort(500)

# List files route
@app.route("/files")
@login_required
def list_files():  # This function name should match what's used in templates
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT user_file_id, filename, mimetype, filesize, 
                       datetime(upload_timestamp) as upload_date, storage_path 
                FROM files 
                WHERE user_id = ?
                ORDER BY upload_timestamp DESC
            """, (current_user.id,))
            
            files = [{
                'user_file_id': row[0],
                'filename': row[1],
                'mimetype': row[2],
                'size': round(row[3] / (1024 * 1024), 2),  # Convert to MB
                'upload_date': row[4],
                'storage_path': row[5]
            } for row in cur.fetchall()]
            
            return render_template('files.html', 
                                files=files,
                                username=current_user.name,
                                profile_pic=current_user.profile_pic)
            
    except Exception as e:
        app.logger.error(f"Error listing files: {str(e)}")
        return render_template('error.html', error=str(e)), 500

# Delete files route
@app.route('/delete-files', methods=['POST'])
@login_required
def delete_files():
    try:
        data = request.get_json()
        file_ids = data.get('file_ids', [])

        if not file_ids:
            return jsonify({'error': 'No files selected'}), 400

        # Get storage paths in a single query
        with get_db() as conn:
            cur = conn.cursor()
            placeholders = ','.join('?' * len(file_ids))
            
            # Get paths and delete from DB in a single transaction
            cur.execute(f"""
                SELECT storage_path FROM files 
                WHERE user_id = ? AND user_file_id IN ({placeholders})
            """, (current_user.id, *file_ids))
            storage_paths = [row[0] for row in cur.fetchall()]
            
            # Delete from database immediately
            cur.execute(f"""
                DELETE FROM files 
                WHERE user_id = ? AND user_file_id IN ({placeholders})
            """, (current_user.id, *file_ids))
            conn.commit()

        # Delete from cloud storage
        storage = CloudStorage()
        for path in storage_paths:
            try:
                storage.delete_file(path)
            except Exception as e:
                app.logger.error(f"Cloud storage deletion error for {path}: {e}")
                # Continue with other deletions even if one fails

        return jsonify({'success': True}), 200

    except Exception as e:
        app.logger.error(f"Delete files error: {e}")
        return jsonify({'error': str(e)}), 500

# Debug route
@app.route("/debug")
@login_required
def debug_info():
    try:
        db_status = "Connected"
        storage_status = "Connected"
        error_details = None
        
        # Test database connection
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM files")
            file_count = cur.fetchone()[0]
            
        # Test storage connection
        storage = CloudStorage()
        storage.bucket.exists()
        
        return jsonify({
            'database': db_status,
            'storage': storage_status,
            'file_count': file_count
        })
    except Exception as e:
        return jsonify({
            'error': str(e),
            'trace': traceback.format_exc()
        }), 500

# Test upload route
@app.route("/test-upload", methods=["GET"])
@login_required
def test_upload():
    try:
        # Create test file
        test_data = b"Hello, World!"
        test_filename = "test.txt"
        storage_path = f"{current_user.id}/test/{test_filename}"
        
        # Upload to storage
        storage = CloudStorage()
        public_url = storage.upload_file(
            test_data,
            storage_path,
            "text/plain"
        )
        
        # Save to database
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO files 
                (user_file_id, user_id, filename, storage_path, mimetype, filesize) 
                VALUES (?, ?, ?, ?, ?, ?)
            """, (1, current_user.id, test_filename, storage_path, "text/plain", len(test_data)))
            conn.commit()
            
        return jsonify({
            "message": "Test file uploaded successfully",
            "url": public_url
        })
    except Exception as e:
        app.logger.error(f"Test upload error: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Basic HTML form for testing
@app.route("/")
def index():
    # Get current time in IST
    now = datetime.now(ist)
    return render_template('index.html', 
        user=current_user,
        now=now  # This will be IST
    )

# Route for rendering the upload page
@app.route("/upload")
@login_required
def upload():
    try:
        return render_template(
            'upload.html',
            username=current_user.name,
            profile_pic=current_user.profile_pic
        )
    except Exception as e:
        app.logger.error(f"Upload page error: {str(e)}")
        return redirect(url_for('login', error="Session expired. Please login again."))

# Route for handling file uploads
@app.route("/upload-files", methods=["POST"])
@login_required
def upload_files():
    if "file[]" not in request.files:
        return jsonify({"error": "No files selected"}), 400

    files = request.files.getlist("file[]")
    if not files or all(f.filename == "" for f in files):
        return jsonify({"error": "No files selected"}), 400

    uploaded_files = []
    
    try:
        storage = CloudStorage()
        
        with get_db() as conn:
            cur = conn.cursor()
            
            # Get next file ID for user
            cur.execute("""
                SELECT COALESCE(MAX(user_file_id), 0)
                FROM files 
                WHERE user_id = ?
            """, (current_user.id,))
            next_file_id = cur.fetchone()[0] + 1
            
            for file in files:
                filename = secure_filename(file.filename)
                if not allowed_file(filename):
                    continue
                    
                file_data = file.read()
                content_type = file.content_type or 'application/octet-stream'
                filesize = len(file_data)
                storage_path = f"{current_user.id}/{next_file_id}/{filename}"
                
                # Upload to Cloud Storage
                public_url = storage.upload_file(file_data, storage_path, content_type)
                
                # Save to database
                cur.execute("""
                    INSERT INTO files 
                    (user_file_id, user_id, filename, storage_path, mimetype, filesize, upload_timestamp) 
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (next_file_id, current_user.id, filename, storage_path, 
                     content_type, filesize, get_ist_time()))
                
                uploaded_files.append({
                    'filename': filename,
                    'url': public_url,
                    'size': round(filesize / (1024 * 1024), 2),  # Convert to MB
                    'type': content_type
                })
                
                next_file_id += 1
            
            conn.commit()

        return jsonify({
            "message": f"Successfully uploaded {len(uploaded_files)} file(s)",
            "files": uploaded_files
        })
        
    except Exception as e:
        app.logger.error(f"Upload error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/get-download-url/<int:file_id>")
@login_required
def get_download_url(file_id):
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT storage_path, filename, mimetype 
                FROM files 
                WHERE user_id = ? AND user_file_id = ?
            """, (current_user.id, file_id))
            
            result = cur.fetchone()
            if not result:
                return jsonify({"error": "File not found"}), 404
                
            storage_path, filename, mimetype = result
            storage = CloudStorage()
            
            # Set custom content types for better browser handling
            content_type = mimetype
            if mimetype.startswith('video/'):
                content_type = 'video/mp4'
            elif mimetype.startswith('audio/'):
                content_type = 'audio/mpeg'
                
            view_url = storage.generate_signed_url(
                storage_path,
                expiration=3600,
                content_type=content_type,  # Pass content type
                response_disposition=None  # No download header
            )
            
            return jsonify({"url": view_url})
            
    except Exception as e:
        app.logger.error(f"Error generating view URL: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.after_request
def add_header(response):
    if request.endpoint == 'upload':  # Changed from index
        response.cache_control.max_age = 300  # Cache for 5 minutes
    return response

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

def validate_service_account():
    service_account_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "service-account.json"))
    
    try:
        with open(service_account_path, 'r') as f:
            import json
            credentials_info = json.load(f)
            
        required_keys = ['type', 'project_id', 'private_key_id', 'private_key', 'client_email']
        if not all(key in credentials_info for key in required_keys):
            app.logger.error("Invalid service account JSON structure")
            return False
            
        return True
    except Exception as e:
        app.logger.error(f"Service account validation failed: {str(e)}")
        return False

# Add these new route handlers
@app.route('/g-upload')
@login_required
def g_upload():
    try:
        return render_template(
            'g-upload.html',
            username=current_user.name,
            profile_pic=current_user.profile_pic
        )
    except Exception as e:
        app.logger.error(f"Google Drive upload page error: {str(e)}")
        return redirect(url_for('login', error="Session expired. Please login again."))

@app.route('/g-files')
@login_required
def g_files():
    try:
        service = get_google_drive_service()
        folder_name = f"CBMS_{current_user.id}"
        
        results = service.files().list(
            q=f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder'",
            spaces='drive'
        ).execute()
        
        files = []
        if results.get('files'):
            folder_id = results['files'][0]['id']
            
            results = service.files().list(
                q=f"'{folder_id}' in parents",
                spaces='drive',
                fields='files(id, name, mimeType, size, createdTime, properties)',
                orderBy='createdTime desc'
            ).execute()
            
            files = [{
                'id': f['id'],
                'filename': f['name'].replace('.zst', ''),
                'mimetype': f['mimeType'],
                'size': round(float(f.get('size', 0)) / (1024 * 1024), 2),  # Compressed size in MB
                'original_size': round(float(f.get('properties', {}).get('originalSize', 0)) / (1024 * 1024), 2),  # Original size in MB
                'compression_ratio': f.get('properties', {}).get('compressionRatio', 'N/A'),
                'upload_date': datetime.fromisoformat(f['createdTime'].replace('Z', '+00:00'))
                                    .strftime('%Y-%m-%d %H:%M:%S')
            } for f in results.get('files', [])]
        
        return render_template(
            'g-files.html',
            files=files,
            username=current_user.name,
            profile_pic=current_user.profile_pic
        )
    except Exception as e:
        app.logger.error(f"Error loading Google Drive files: {str(e)}")
        return render_template('error.html', error=str(e))
            
    except Exception as e:
        app.logger.error(f"Error loading Google Drive files: {str(e)}")
        return render_template('error.html', error=str(e))



def get_or_create_folder(service, folder_name):
    """Get or create a folder in Google Drive."""
    # Check if folder exists
    results = service.files().list(
        q=f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder' and trashed=false",
        spaces='drive',
        fields='files(id)'
    ).execute()
    
    if results.get('files'):
        # Folder exists, return its ID
        return results['files'][0]['id']
    
    # Folder doesn't exist, create it
    folder_metadata = {
        'name': folder_name,
        'mimeType': 'application/vnd.google-apps.folder'
    }
    
    folder = service.files().create(
        body=folder_metadata,
        fields='id',
        supportsAllDrives=True
    ).execute()
    
    return folder.get('id')

@app.route('/g-upload-files', methods=['POST'])
@login_required
def g_upload_files():
    if "file[]" not in request.files:
        return jsonify({"error": "No files selected"}), 400

    files = request.files.getlist("file[]")
    if not files or all(f.filename == "" for f in files):
        return jsonify({"error": "No files selected"}), 400

    try:
        service = get_google_drive_service()
        if not service:
            raise Exception("Could not connect to Google Drive")

        folder_name = f"CBMS_{current_user.id}"
        folder_id = get_or_create_folder(service, folder_name)
        
        if not folder_id:
            raise Exception("Failed to create or get Google Drive folder")

        uploaded_files = []
        errors = []

        # Process files sequentially for better error handling
        for file in files:
            if file.filename:
                try:
                    result = process_and_upload_file(file, folder_id, service)
                    if result:
                        uploaded_files.append(result)
                    else:
                        errors.append(f"Failed to upload {file.filename}")
                except Exception as e:
                    app.logger.error(f"Error uploading {file.filename}: {str(e)}")
                    errors.append(f"Error uploading {file.filename}: {str(e)}")

        if not uploaded_files:
            error_message = "; ".join(errors) if errors else "No files were uploaded successfully"
            return jsonify({"error": error_message}), 500

        return jsonify({
            "message": f"Successfully uploaded {len(uploaded_files)} file(s)",
            "files": uploaded_files,
            "errors": errors if errors else None,
            "redirect": url_for('g_files')
        })

    except Exception as e:
        app.logger.error(f"Upload error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

def process_and_upload_file(file, folder_id, service):
    """Process and upload a single file with optimized compression"""
    try:
        filename = secure_filename(file.filename)
        app.logger.info(f"Processing file: {filename}")
        
        file_data = file.read()
        original_size = len(file_data)
        app.logger.info(f"Original file size: {original_size} bytes")

        # Simplified compression parameters for zstandard
        compression_params = {
            'level': 22,  # Maximum compression level
            'write_checksum': True,  # Include checksum for integrity
            'write_content_size': True,  # Include original size in compressed data
            'threads': -1  # Use all available threads
        }
        
        try:
            compressor = zstd.ZstdCompressor(**compression_params)
            compressed_data = compressor.compress(file_data)
            compressed_size = len(compressed_data)
            compression_ratio = (1 - (compressed_size / original_size)) * 100
            
            app.logger.info(f"Compressed size: {compressed_size} bytes, Ratio: {compression_ratio:.2f}%")
        except Exception as e:
            app.logger.error(f"Compression error: {str(e)}")
            raise

        # Create file metadata with compression info
        file_metadata = {
            'name': f"{filename}.zst",
            'parents': [folder_id],
            'properties': {
                'originalName': filename,
                'originalMimeType': file.content_type or 'application/octet-stream',
                'originalSize': str(original_size),
                'compressionRatio': f"{compression_ratio:.2f}%",
                'compressionLevel': '22',
                'compressionType': 'zstd'
            }
        }

        # Upload file in chunks with optimized buffer
        fh = io.BytesIO(compressed_data)
        fh.seek(0)  # Reset buffer position
        
        media = MediaIoBaseUpload(
            fh,
            mimetype='application/octet-stream',  # Changed from application/zstd
            resumable=True,
            chunksize=1024 * 1024  # 1MB chunks
        )

        app.logger.info(f"Starting upload to Google Drive for {filename}")
            
        # Upload with retry mechanism
        max_retries = 3
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                uploaded_file = service.files().create(
                    body=file_metadata,
                    media_body=media,
                    fields='id,name,size,modifiedTime',
                    supportsAllDrives=True
                ).execute()
                break
            except Exception as e:
                retry_count += 1
                if retry_count == max_retries:
                    raise
                time.sleep(1)  # Wait before retry
            
        app.logger.info(f"Successfully uploaded {filename} to Google Drive")

        return {
            'id': uploaded_file.get('id'),
            'filename': filename,
            'originalSize': round(original_size / (1024 * 1024), 2),
            'compressedSize': round(compressed_size / (1024 * 1024), 2),
            'compressionRatio': f"{compression_ratio:.2f}%",
            'upload_date': uploaded_file.get('modifiedTime')
        }

    except Exception as e:
        app.logger.error(f"Error processing {filename}: {str(e)}")
        app.logger.error(traceback.format_exc())
        return None

@app.route('/download-file/<file_id>')
@login_required
def download_file(file_id):
    try:
        service = get_google_drive_service()
        if not service:
            raise Exception("Could not connect to Google Drive")

        # Get file metadata
        file = service.files().get(
            fileId=file_id, 
            fields='name, properties'
        ).execute()
        
        if not file:
            raise Exception("File not found")

        # Get original filename and mimetype
        original_filename = file.get('properties', {}).get('originalName', file['name'].replace('.zst', ''))
        original_mimetype = file.get('properties', {}).get('originalMimeType', 'application/octet-stream')
        
        # Download compressed file
        request = service.files().get_media(fileId=file_id)
        compressed_file = io.BytesIO()
        downloader = MediaIoBaseDownload(compressed_file, request)
        
        done = False
        while not done:
            status, done = downloader.next_chunk()
            if status:
                app.logger.debug(f"Download {int(status.progress() * 100)}%")
        
        # Decompress file
        compressed_file.seek(0)
        decompressor = zstd.ZstdDecompressor()
        decompressed_data = decompressor.decompress(compressed_file.read())
        
        return send_file(
            io.BytesIO(decompressed_data),
            mimetype=original_mimetype,
            as_attachment=True,
            download_name=original_filename
        )
        
    except Exception as e:
        app.logger.error(f"Download error: {str(e)}")
        return jsonify({
            "error": "Failed to download file",
            "details": str(e)
        }), 500

@app.route('/delete-gdrive-files', methods=['POST'])
@login_required
def delete_gdrive_files():
    try:
        data = request.get_json()
        if not data:
            app.logger.error("No JSON data received")
            return jsonify({'success': False, 'error': 'No data received'}), 400

        file_ids = data.get('file_ids', [])
        if not file_ids:
            app.logger.error("No file IDs provided")
            return jsonify({'success': False, 'error': 'No files selected'}), 400

        app.logger.info(f"Attempting to delete files: {file_ids}")

        service = get_google_drive_service()
        if not service:
            app.logger.error("Could not connect to Google Drive")
            return jsonify({'success': False, 'error': 'Could not connect to Google Drive'}), 500

        success_count = 0
        errors = []

        folder_name = f"CBMS_{current_user.id}"
        folder_results = service.files().list(
            q=f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder'",
            spaces='drive',
            fields='files(id)'
        ).execute()

        if not folder_results.get('files'):
            app.logger.error("User folder not found")
            return jsonify({'success': False, 'error': 'User folder not found'}), 404

        folder_id = folder_results['files'][0]['id']

        for file_id in file_ids:
            try:
                # Get file metadata
                file = service.files().get(
                    fileId=file_id,
                    fields='id, parents'
                ).execute()

                if folder_id in file.get('parents', []):
                    service.files().delete(fileId=file_id).execute()
                    success_count += 1
                    app.logger.info(f"Successfully deleted file {file_id}")
                else:
                    errors.append(f'File {file_id} does not belong to user')
                    app.logger.warning(f"File {file_id} does not belong to user")

            except Exception as e:
                app.logger.error(f"Error deleting file {file_id}: {str(e)}")
                errors.append(str(e))

        if success_count == 0:
            app.logger.error("No files were deleted successfully")
            return jsonify({
                'success': False,
                'error': 'Failed to delete files: ' + '; '.join(errors)
            }), 500

        return jsonify({
            'success': True,
            'message': f'Successfully deleted {success_count} file(s)',
            'errors': errors if errors else None
        })

    except Exception as e:
        app.logger.error(f"Delete files error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Initialize CSRF protection after creating the Flask app
csrf = CSRFProtect(app)

@app.route("/privacy-policy")
def privacy_policy():
    return render_template('privacy-policy.html')

@app.route("/terms")
def terms():
    return render_template('terms.html')

# Add this helper function
def get_ist_time():
    """Get current time in IST"""
    return datetime.now(ist).strftime('%Y-%m-%d %H:%M:%S')

# Update the initialization code
if __name__ == "__main__":
    if not validate_service_account():
        print("Error: Invalid service account configuration")
        sys.exit(1)
    
    with app.app_context():
        initialize_app()
        init_user_db()
    
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
