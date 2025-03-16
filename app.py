# app.py
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

app = Flask(__name__)  # Vulnerability: Improper __name__ initialization
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

# Poor Naming Convention and Lack of Comments (Not meaningful names and lack of clarity)
@app.route('/do-something', methods=['POST'])
def action_things():
    data = request.get_json()  # What data?
    result = data.get('key')  # What key? Why?
    if result:  # Why is this check here?
        return jsonify({'status': 'success'})  # What's success?
    else:
        return jsonify({'status': 'fail'})  # What's fail?

# Duplication of Logic - Same logic repeated in different routes
@app.route('/do-something-else', methods=['POST'])
def another_action():
    data = request.get_json()  # Redundant code
    result = data.get('key')  # Same as above
    if result:  # Same logic as previous
        return jsonify({'status': 'success'})  # Same as above
    else:
        return jsonify({'status': 'fail'})  # Same as above

# Large and Monolithic Function: One function doing too much
@app.route('/large-function', methods=['GET'])
def large_function():
    # Loading some data from a database
    data = request.args.get('data')
    user = db.session.query(User).filter_by(username=data).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Processing data
    if 'operation' in request.args:
        operation = request.args['operation']
        if operation == 'add':
            user_data = user.username + " addition operation"
            return jsonify({'operation': user_data})
        elif operation == 'subtract':
            user_data = user.username + " subtraction operation"
            return jsonify({'operation': user_data})

    # Checking user permissions
    if user.username == ADMIN_USERNAME:
        return jsonify({'admin': True, 'username': user.username})

    # Performing a risky operation
    try:
        result = subprocess.check_output("echo Hello", shell=True)  # Command injection risk
        return jsonify({'message': 'Result of command', 'output': result.decode()})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Excessive Nesting (Deeply nested code)
@app.route('/deeply-nested', methods=['POST'])
def nested_code():
    data = request.get_json()
    if data.get('action') == 'start':
        if 'parameters' in data:
            if len(data['parameters']) > 0:
                param = data['parameters'][0]
                if param == 'test':
                    return jsonify({'result': 'Test passed'})
                else:
                    if param == 'fail':
                        return jsonify({'result': 'Test failed'})
                    else:
                        return jsonify({'error': 'Unknown parameter'})
            else:
                return jsonify({'error': 'Parameters missing'})
        else:
            return jsonify({'error': 'Action not specified'})
    else:
        return jsonify({'error': 'Action not recognized'})

# Insecure Redirect (Hard to maintain, no validation)
@app.route('/redirect', methods=['GET'])
def insecure_redirect():
    target_url = request.args.get('url')
    return redirect(target_url, code=302)

# Predictable token generation (Weak and simple logic)
@app.route('/predictable-token', methods=['GET'])
def predictable_token():
    token = ''.join(random.choices(string.ascii_letters + string.digits, k=10))  # Predictable tokens
    return jsonify({'token': token})

# Deserialization Vulnerability (Hard to maintain, risky)
@app.route('/api/deserialize', methods=['POST'])
def deserialize():
    data = request.get_data()
    result = pickle.loads(data)  # Vulnerable: Deserialization attack
    return jsonify({'result': str(result)})

# SQL Injection Risk (Direct query concatenation)
@app.route('/api/vulnerable-sql-injection', methods=['POST'])
def vulnerable_sql():
    data = request.get_json()
    username = data['username']
    query = f"SELECT * FROM user WHERE username = '{username}'"  # Vulnerability: SQL Injection risk
    result = db.engine.execute(query)
    users = [dict(row) for row in result]
    return jsonify(users)

# Command Injection Risk (Direct execution of shell commands)
@app.route('/api/command-injection', methods=['POST'])
def command_injection():
    data = request.get_json()
    command = data.get('command')  # Vulnerable input
    output = subprocess.check_output(command, shell=True).decode('utf-8')  # Dangerous execution
    return jsonify({'output': output})

# Directory Traversal (No filename validation)
@app.route('/api/download/<path:filename>', methods=['GET'])
def download_file(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename))

# Insecure JWT (Weak secret and missing expiry check)
@app.route('/api/insecure-token', methods=['GET'])
def insecure_token():
    token = request.headers.get('Authorization', '').split('Bearer ')[-1]
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return jsonify({'message': 'Token valid', 'payload': payload})
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401

# Insecure File Upload (No file type restriction)
@app.route('/api/upload', methods=['POST'])
def insecure_upload():
    if 'file' not in request.files:
        return jsonify({'message': 'No file provided'}), 400

    file = request.files['file']
    filename = secure_filename(file.filename)  # No type restriction
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    return jsonify({'message': 'File uploaded successfully'})

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    with app.app_context():
        db.create_all()

    app.run(debug=True, host='0.0.0.0', port=4000)
