import os
import logging
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
from google.oauth2 import id_token
from pip._vendor import cachecontrol
from models import User, init_user_db, get_user
from auth import GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
import pathlib
import requests
import sqlite3
import io
from gcloud import CloudStorage
from flask_cors import CORS
import traceback
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import threading
from werkzeug.utils import secure_filename

CORS(app, resources={
    r"/*": {
        "origins": "http://localhost:5000",
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "allow_headers": ["Content-Type", "Authorization"]
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

flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", 
            "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://localhost:5000/callback"  # Make sure this matches exactly
)

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
            'remoteip': request.remote_addr  # Add client IP
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

@app.route("/callback")
def callback():
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
                    (user_file_id, user_id, filename, storage_path, mimetype, filesize) 
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (next_file_id, current_user.id, filename, storage_path, 
                     content_type, filesize))
                
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
def list_files():
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
            
            return render_template('files.html', files=files)
            
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
@login_required
def index():
    # Remove storage initialization
    return render_template('index.html')

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
    if request.endpoint == 'index':
        response.cache_control.max_age = 300  # Cache for 5 minutes
    return response

if __name__ == "__main__":
    # Set environment variables
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = os.path.join(
        os.path.dirname(__file__), 
        "service-account.json"
    )
    
    initialize_app()
    init_user_db()  # Initialize user database
    
    # Use environment variables for host and port
    port = int(os.environ.get("PORT", 5000))
    app.run(
        host="0.0.0.0",
        port=port,
        debug=os.environ.get("FLASK_ENV") == "development"
    )
