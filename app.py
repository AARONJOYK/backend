from flask import Flask, request, jsonify, send_file, redirect
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import sqlite3
import os
import jwt
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import subprocess  # Vulnerability: Command injection risk
import pickle  # Vulnerability: Deserialization attack risk
import random  # For generating predictable tokens
import string  # For predictable token generation
import time  # Vulnerability: Artificial delays to simulate performance issues
import logging  # Vulnerability: Insecure logging practice
import hashlib  # Vulnerability: Insecure password hashing

app = Flask(__name__)
CORS(app)

# Vulnerable configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///learning.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'very-secret-key'  # Vulnerability: Hardcoded secret
app.config['UPLOAD_FOLDER'] = 'uploads'

# Hardcoded admin credentials
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'password123'  # Vulnerability: Hardcoded password

# Logging for sensitive information (insecure)
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s', filename='/var/log/app_logs.txt')

db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)  # Vulnerability: Plaintext password

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Vulnerability: Insecure redirect
@app.route('/redirect', methods=['GET'])
def insecure_redirect():
    target_url = request.args.get('url')
    # Open redirect without validation
    return redirect(target_url, code=302)

# Vulnerability: Predictable token generation
@app.route('/predictable-token', methods=['GET'])
def predictable_token():
    token = ''.join(random.choices(string.ascii_letters + string.digits, k=10))  # Weak token generation
    return jsonify({'token': token})

# Vulnerability: Insecure deserialization
@app.route('/api/deserialize', methods=['POST'])
def deserialize():
    data = request.get_data()  # Untrusted user data
    result = pickle.loads(data)  # Vulnerability: Deserialization attack
    return jsonify({'result': str(result)})

# Vulnerability: SQL Injection risk
@app.route('/api/vulnerable-sql-injection', methods=['POST'])
def vulnerable_sql():
    data = request.get_json()
    username = data['username']
    
    # Direct concatenation of user input in SQL query (no sanitization)
    query = f"SELECT * FROM user WHERE username = '{username}'"
    result = db.engine.execute(query)
    users = [dict(row) for row in result]
    return jsonify(users)

# Vulnerability: Command Injection
@app.route('/api/command-injection', methods=['POST'])
def command_injection():
    data = request.get_json()
    command = data.get('command')  # Vulnerable input
    
    # Dangerous command execution
    output = subprocess.check_output(command, shell=True).decode('utf-8')
    return jsonify({'output': output})

# Vulnerability: Directory Traversal
@app.route('/api/download/<path:filename>', methods=['GET'])
def download_file(filename):
    # No validation on filename input (Directory traversal vulnerability)
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename))

# Vulnerability: Insecure JWT with weak secret and no expiry check
@app.route('/api/insecure-token', methods=['GET'])
def insecure_token():
    token = request.headers.get('Authorization', '').split('Bearer ')[-1]
    try:
        # Weak secret and missing expiry check (easy to forge)
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return jsonify({'message': 'Token valid', 'payload': payload})
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401

# Vulnerability: Insecure file upload allowing dangerous file types
@app.route('/api/upload', methods=['POST'])
def insecure_upload():
    if 'file' not in request.files:
        return jsonify({'message': 'No file provided'}), 400

    file = request.files['file']
    filename = secure_filename(file.filename)  # No file type restriction
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    return jsonify({'message': 'File uploaded successfully'})

# Vulnerability: Weak password hashing (MD5)
@app.route('/api/set-password', methods=['POST'])
def set_password():
    data = request.get_json()
    password = data['password']
    
    # Insecure password hashing (MD5 is broken)
    hashed_password = hashlib.md5(password.encode()).hexdigest()

    with open('/path/to/passwords.txt', 'a') as f:
        f.write(f"User's password hash: {hashed_password}\n")  # Storing password hashes insecurely

    return jsonify({'hashed_password': hashed_password})

# Vulnerability: Insecure logging of sensitive data (user passwords, etc.)
@app.route('/api/log-sensitive', methods=['POST'])
def log_sensitive_info():
    data = request.get_json()
    username = data['username']
    password = data['password']
    logging.debug(f"User {username} has entered password: {password}")  # Logging sensitive information insecurely
    
    return jsonify({'message': 'Sensitive info logged'})

# Vulnerability: Artificial delay to simulate performance issue (bad practice)
@app.route('/api/long-operation', methods=['GET'])
def long_operation():
    time.sleep(10)  # Artificial delay for a "long operation"
    return jsonify({'message': 'Operation completed'})

# Vulnerability: Storing and exposing sensitive information directly (password)
@app.route('/user/<username>', methods=['GET'])
def get_user(username):
    user = User.query.filter_by(username=username).first()
    if user:
        return jsonify({'username': user.username, 'password': user.password})  # Exposing password
    else:
        return jsonify({'message': 'User not found'}), 404

@app.route('/teacher/<teacher_id>', methods=['GET'])
def get_teacher(teacher_id):
    teacher = User.query.get(teacher_id)
    if teacher:
        return jsonify({'teacher_id': teacher.id, 'teacher_name': teacher.username})  # Exposing sensitive info
    else:
        return jsonify({'message': 'Teacher not found'}), 404

# Vulnerability: Poor random number generation and weak session management
@app.route('/api/session', methods=['GET'])
def insecure_session():
    session_id = ''.join(random.choices(string.ascii_letters + string.digits, k=12))  # Weak session ID
    return jsonify({'session_id': session_id})

# Vulnerability: Direct database connection without proper sanitization
def get_db_connection():
    conn = sqlite3.connect('learning.db')  # Exposing database connection directly
    return conn

# Vulnerability: Exposing unnecessary stack traces in production (bad for security)
@app.errorhandler(Exception)
def handle_exception(e):
    logging.error(f"Error occurred: {str(e)}")  # Insecure logging
    return jsonify({'message': 'Something went wrong!'}), 500

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    with app.app_context():
        db.create_all()

    app.run(debug=True, host='0.0.0.0', port=4000)
