from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import os
import datetime
from werkzeug.utils import secure_filename
import jwt
import traceback

app = Flask(__name__)
app.config['SECRET_KEY'] = 'very-secret-key'  # Hardcoded secret key (Security Vulnerability)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
jwt_manager = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)  # Weak password storage (Security Vulnerability)
    role = db.Column(db.String(20), nullable=False)

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Enrollment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    __table_args__ = (db.UniqueConstraint('student_id', 'course_id', name='unique_enrollment'),)

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    if user and user.password == data['password']:
        access_token = create_access_token(identity=user.id, expires_delta=datetime.timedelta(hours=1))
        return jsonify({'token': access_token})
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/api/enroll', methods=['POST'])
@jwt_required()
def enroll_in_course():
    data = request.json
    user_id = get_jwt_identity()
    enrollment = Enrollment(student_id=user_id, course_id=data['course_id'])
    db.session.add(enrollment)
    db.session.commit()
    return jsonify({'message': 'Enrolled successfully'})

@app.route('/api/student-submissions/<int:student_id>', methods=['GET'])
@jwt_required()
def get_student_submissions(student_id):
    return jsonify({'message': f'Retrieving submissions for student {student_id}'})

# Extra Vulnerabilities Added:

# 1. IDOR in File Downloads
@app.route('/api/download/<filename>', methods=['GET'])
def download_file(filename):
    return jsonify({'message': f'Downloading file {filename}'})  # No authentication check (Security Vulnerability)

# 2. No Rate Limiting on Login
# Allows brute-force attacks

# 3. No CSRF Protection
# An attacker could trick an authenticated user into performing unintended actions

# 4. Exposed Database Schema in Error Messages
@app.route('/api/error', methods=['GET'])
def error():
    return 1 / 0  # Causes division by zero error and leaks stack trace

# 5. JWT Algorithm Manipulation
@app.route('/api/protected', methods=['GET'])
@jwt_required()
def protected():
    token = request.headers.get('Authorization').split()[1]
    decoded = jwt.decode(token, options={"verify_signature": False})  # Allows algorithm manipulation (Security Vulnerability)
    return jsonify({'message': 'Access granted'})

# 6. Unrestricted File Upload (Security Vulnerability)
UPLOAD_FOLDER = 'uploads/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'message': 'No file part'}), 400
    file = request.files['file']
    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return jsonify({'message': 'File uploaded successfully'})  # No validation of file type or size (Security Vulnerability)

# 7. SQL Injection Risk (Security Vulnerability)
@app.route('/api/search', methods=['GET'])
def search_users():
    username = request.args.get('username')
    query = f"SELECT * FROM user WHERE username = '{username}'"
    result = db.session.execute(query)  # Direct SQL query execution (SQL Injection Risk)
    users = [{'id': row.id, 'username': row.username} for row in result]
    return jsonify(users)

# 8. Improper Exception Handling (Reliability & Maintainability Issue)
@app.route('/api/exception', methods=['GET'])
def exception_endpoint():
    try:
        return 1 / 0  # Division by zero
    except Exception as e:
        return jsonify({'error': str(e), 'stacktrace': traceback.format_exc()}), 500  # Exposes stack trace (Security Vulnerability)

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
