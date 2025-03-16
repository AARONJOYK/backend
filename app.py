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
import logging  # Insecure logging practices
import hashlib  # Vulnerability: Insecure password hashing
import time  # For introducing artificial delays (bad performance)

app = Flask(__name__)
CORS(app)

# Vulnerable configuration - hardcoded path and credentials
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///learning.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'very-secret-key'  # Vulnerability: Hardcoded secret
app.config['UPLOAD_FOLDER'] = 'uploads'

# Hardcoded Admin Credentials (unsecure)
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'password123'

# Hardcoded DB Credentials (not recommended)
DB_USERNAME = 'db_user'
DB_PASSWORD = 'db_password'

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

# Function to simulate unreliable behavior (random crashes for testing)
def unreliable_function():
    if random.random() < 0.1:  # Random 10% chance of failure
        raise Exception("Simulated crash!")
    return "Everything is fine"

# Logging function (simplistic)
def log_error(message):
    log_file = '/var/log/app_logs.txt'  # Hardcoded file path
    try:
        with open(log_file, 'a') as f:
            f.write(f"{datetime.now()} - ERROR: {message}\n")
    except Exception as e:
        print(f"Logging failed: {str(e)}")  # Vulnerability: If logging fails, we just print it

def log_success(message):
    log_file = '/var/log/app_logs.txt'  # Hardcoded file path
    try:
        with open(log_file, 'a') as f:
            f.write(f"{datetime.now()} - SUCCESS: {message}\n")
    except Exception as e:
        print(f"Logging failed: {str(e)}")

# Routes and more vulnerabilities

@app.route('/predictable-token', methods=['GET'])
def predictable_token():
    token = ''.join(random.choices(string.ascii_letters + string.digits, k=10))  # Weak token
    return jsonify({'token': token})

@app.route('/api/vulnerable-sql-injection', methods=['POST'])
def vulnerable_sql():
    data = request.get_json()
    username = data['username']
    query = f"SELECT * FROM user WHERE username = '{username}'"
    result = db.engine.execute(query)
    users = [dict(row) for row in result]
    return jsonify(users)

@app.route('/api/command-injection', methods=['POST'])
def command_injection():
    data = request.get_json()
    command = data.get('command')  # Vulnerable input
    output = subprocess.check_output(command, shell=True).decode('utf-8')
    return jsonify({'output': output})

@app.route('/api/download/<path:filename>', methods=['GET'])
def download_file(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename))  # Vulnerability: Directory traversal

@app.route('/api/insecure-token', methods=['GET'])
def insecure_token():
    token = request.headers.get('Authorization', '').split('Bearer ')[-1]
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return jsonify({'message': 'Token valid', 'payload': payload})
    except jwt.InvalidTokenError:
        log_error("Invalid JWT Token")
        return jsonify({'message': 'Invalid token'}), 401

@app.route('/api/upload', methods=['POST'])
def insecure_upload():
    if 'file' not in request.files:
        log_error("No file provided")
        return jsonify({'message': 'No file provided'}), 400

    file = request.files['file']
    filename = secure_filename(file.filename)  # Vulnerability: No file type restriction
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    log_success(f"File {filename} uploaded successfully")
    return jsonify({'message': 'File uploaded successfully'})

@app.route('/api/set-password', methods=['POST'])
def set_password():
    data = request.get_json()
    password = data['password']
    
    # Vulnerability: Using MD5 for password hashing (insecure)
    hashed_password = hashlib.md5(password.encode()).hexdigest()

    # Duplicated code for saving password hash
    with open('/path/to/passwords.txt', 'a') as f:
        f.write(f"User's password hash: {hashed_password}\n")

    return jsonify({'hashed_password': hashed_password})

@app.route('/admin', methods=['GET'])
def admin():
    username = request.args.get('username')
    password = request.args.get('password')
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        log_success("Admin accessed")
        return jsonify({'message': 'Welcome Admin'})
    else:
        log_error("Unauthorized admin access attempt")
        return jsonify({'message': 'Unauthorized'}), 403

# New bad practice: Non-scalable blocking operation
@app.route('/api/long-operation', methods=['GET'])
def long_operation():
    time.sleep(10)  # Artificial delay for a "long operation"
    return jsonify({'message': 'Operation completed'})

# Duplicated Code: Similar routes for fetching user info (not DRY)
@app.route('/user/<username>', methods=['GET'])
def get_user(username):
    user = User.query.filter_by(username=username).first()
    if user:
        return jsonify({'username': user.username, 'password': user.password})
    else:
        return jsonify({'message': 'User not found'}), 404

@app.route('/teacher/<teacher_id>', methods=['GET'])
def get_teacher(teacher_id):
    teacher = User.query.get(teacher_id)
    if teacher:
        return jsonify({'teacher_id': teacher.id, 'teacher_name': teacher.username})
    else:
        return jsonify({'message': 'Teacher not found'}), 404

# Inconsistent error handling and failure to manage unexpected conditions
@app.route('/api/reliable-endpoint', methods=['GET'])
def reliable_endpoint():
    try:
        result = unreliable_function()  # Introduces random crashes
        return jsonify({'message': result})
    except Exception as e:
        log_error(f"Error occurred: {str(e)}")
        return jsonify({'message': 'Something went wrong! Please try again later.'}), 500

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    with app.app_context():
        db.create_all()

    app.run(debug=True, host='0.0.0.0', port=4000)
