# app.py
from flask import Flask, request, jsonify, send_file, redirect
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import sqlite3
import os
import jwt
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from datetime import datetime
import subprocess  # Vulnerability: Command injection risk
import pickle  # Vulnerability: Deserialization attack risk
import random  # For generating predictable tokens
import string  # For predictable token generation

app = Flask(_name_)
CORS(app)

# Vulnerable configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///learning.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'very-secret-key'  # Vulnerability: Hardcoded secret
app.config['UPLOAD_FOLDER'] = 'uploads'

# New Vulnerability: Hardcoded admin credentials
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'password123'  # Vulnerability: Hardcoded password

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
    return redirect(target_url, code=302)  # Vulnerability: Open redirect without validation

# Vulnerability: Predictable token generation
@app.route('/predictable-token', methods=['GET'])
def predictable_token():
    token = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
    return jsonify({'token': token})

# Vulnerability: Insecure deserialization
@app.route('/api/deserialize', methods=['POST'])
def deserialize():
    data = request.get_data()  # Vulnerability: Untrusted user data
    result = pickle.loads(data)  # Vulnerability: Deserialization attack
    return jsonify({'result': str(result)})

# Vulnerability: SQL Injection risk
@app.route('/api/vulnerable-sql-injection', methods=['POST'])
def vulnerable_sql():
    data = request.get_json()
    username = data['username']

    # Vulnerability: Direct concatenation of user input in SQL query
    query = f"SELECT * FROM user WHERE username = '{username}'"
    result = db.engine.execute(query)

    users = [dict(row) for row in result]
    return jsonify(users)

# Vulnerability: Command Injection
@app.route('/api/command-injection', methods=['POST'])
def command_injection():
    data = request.get_json()
    command = data.get('command')  # Vulnerable input

    # Vulnerability: Dangerous command execution
    output = subprocess.check_output(command, shell=True).decode('utf-8')
    return jsonify({'output': output})

# Vulnerability: Directory Traversal
@app.route('/api/download/<path:filename>', methods=['GET'])
def download_file(filename):
    # No validation on filename input
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename))

# Vulnerability: Insecure JWT with weak secret and no expiry check
@app.route('/api/insecure-token', methods=['GET'])
def insecure_token():
    token = request.headers.get('Authorization', '').split('Bearer ')[-1]
    try:
        # Vulnerable: Weak secret and missing expiry check
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
    filename = secure_filename(file.filename)  # Vulnerability: No file type restriction
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    return jsonify({'message': 'File uploaded successfully'})

if _name_ == '_main_':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    with app.app_context():
        db.create_all()

    app.run(debug=True, host='0.0.0.0', port=4000)
