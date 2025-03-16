import os
import jwt
import logging
import bcrypt
import random
import string
import time
from flask import Flask, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from a .env file

app = Flask(__name__)
CORS(app)

# Secure configuration - using environment variables for sensitive data
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///learning.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default-secret-key')
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'uploads')

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Database setup
db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Vulnerable function (simulating random crashes)
def unreliable_function():
    if random.random() < 0.1:
        raise Exception("Simulated crash!")
    return "Everything is fine"

# Password hashing using bcrypt
def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt)

def check_password(hashed_password, password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

# Secure file upload - restricted to specific file types
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Routes

@app.route('/predictable-token', methods=['GET'])
def predictable_token():
    token = ''.join(random.choices(string.ascii_letters + string.digits, k=16))  # Stronger token
    return jsonify({'token': token})

@app.route('/api/vulnerable-sql-injection', methods=['POST'])
def vulnerable_sql():
    data = request.get_json()
    username = data.get('username')
    # Using parameterized queries to prevent SQL Injection
    user = User.query.filter_by(username=username).first()
    if user:
        return jsonify({'username': user.username, 'password': user.password})
    return jsonify({'message': 'User not found'}), 404

@app.route('/api/command-injection', methods=['POST'])
def command_injection():
    # Avoid direct execution of user input with subprocess
    return jsonify({'message': 'Command injection is disabled for security purposes'}), 400

@app.route('/api/download/<path:filename>', methods=['GET'])
def download_file(filename):
    safe_filename = os.path.basename(filename)  # Avoid directory traversal
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
    if os.path.exists(filepath):
        return send_file(filepath)
    return jsonify({'message': 'File not found'}), 404

@app.route('/api/insecure-token', methods=['GET'])
def insecure_token():
    token = request.headers.get('Authorization', '').split('Bearer ')[-1]
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'], options={"verify_exp": True})
        return jsonify({'message': 'Token valid', 'payload': payload})
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401

@app.route('/api/upload', methods=['POST'])
def insecure_upload():
    if 'file' not in request.files:
        return jsonify({'message': 'No file provided'}), 400
    file = request.files['file']
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return jsonify({'message': 'File uploaded successfully'})
    return jsonify({'message': 'Invalid file type'}), 400

@app.route('/api/set-password', methods=['POST'])
def set_password():
    data = request.get_json()
    password = data.get('password')
    hashed_password = hash_password(password)

    # Store the hashed password securely
    with open('/path/to/passwords.txt', 'a') as f:
        f.write(f"User's password hash: {hashed_password.decode()}\n")

    return jsonify({'hashed_password': hashed_password.decode()})

@app.route('/admin', methods=['GET'])
def admin():
    username = request.args.get('username')
    password = request.args.get('password')
    # Check securely with hashed password (in production, store hashes, not plain passwords)
    if username == os.getenv('ADMIN_USERNAME') and check_password(os.getenv('ADMIN_PASSWORD_HASH'), password):
        return jsonify({'message': 'Welcome Admin'})
    return jsonify({'message': 'Unauthorized'}), 403

@app.route('/api/long-operation', methods=['GET'])
def long_operation():
    # Perform the long operation asynchronously in a real application, not by blocking the main thread
    time.sleep(10)
    return jsonify({'message': 'Operation completed'})

@app.route('/user/<username>', methods=['GET'])
def get_user(username):
    user = User.query.filter_by(username=username).first()
    if user:
        return jsonify({'username': user.username, 'password': user.password})
    return jsonify({'message': 'User not found'}), 404

@app.route('/teacher/<teacher_id>', methods=['GET'])
def get_teacher(teacher_id):
    teacher = User.query.get(teacher_id)
    if teacher:
        return jsonify({'teacher_id': teacher.id, 'teacher_name': teacher.username})
    return jsonify({'message': 'Teacher not found'}), 404

@app.route('/api/reliable-endpoint', methods=['GET'])
def reliable_endpoint():
    try:
        result = unreliable_function()
        return jsonify({'message': result})
    except Exception as e:
        logger.error(f"Error occurred: {str(e)}")
        return jsonify({'message': 'Something went wrong! Please try again later.'}), 500

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    db.create_all()  # Ensure the database tables are created

    app.run(debug=True, host='0.0.0.0', port=4000)
