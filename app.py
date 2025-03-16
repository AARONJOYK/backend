from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import sqlite3
import os
import jwt
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__)
CORS(app)

# Vulnerable configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///learning.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'very-secret-key'  # Vulnerability: Hardcoded secret
# Vulnerability: Unsanitized file uploads
app.config['UPLOAD_FOLDER'] = 'uploads'

db = SQLAlchemy(app)

# Models
# Add new model for course enrollment


class Enrollment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(
        db.Integer, db.ForeignKey('user.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey(
        'course.id'), nullable=False)
    enrolled_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Vulnerability: No unique constraint on student_id and course_id


class Grade(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    submission_id = db.Column(db.Integer, db.ForeignKey(
        'submission.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey(
        'course.id'), nullable=False)  # Add this
    value = db.Column(db.Integer, nullable=False)
    feedback = db.Column(db.Text)
    graded_at = db.Column(db.DateTime, default=datetime.utcnow)

# Update submission model to ensure course relationship


class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(
        db.Integer, db.ForeignKey('user.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey(
        'course.id'), nullable=False)
    grade = db.Column(db.Integer)
    feedback = db.Column(db.Text)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    grades = db.relationship('Grade', backref='submission', lazy=True)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    # Vulnerability: Passwords stored in plaintext
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'student' or 'teacher'


class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)  # Vulnerability: Stored XSS
    teacher_id = db.Column(
        db.Integer, db.ForeignKey('user.id'), nullable=False)


class Assignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)

    course_id = db.Column(db.Integer, db.ForeignKey(
        'course.id'), nullable=False)
    due_date = db.Column(db.DateTime, nullable=False)


def is_course_teacher(course_id: int, teacher_id: int) -> bool:
    """
    Check if the given teacher is the owner of the course.

    Args:
        course_id (int): The ID of the course to check
        teacher_id (int): The ID of the teacher

    Returns:
        bool: True if the teacher owns the course, False otherwise
    """
    course = Course.query.filter_by(
        id=course_id, teacher_id=teacher_id).first()
    return course is not None

# New routes for enhanced functionality


@app.route('/', methods=['GET'])
def first():

    return jsonify({'message': 'Backend flask app running'}), 200


@app.route('/api', methods=['GET'])
def api_route():

    return jsonify({'message': '/API endpoint called !'}), 200


@app.route('/api/grade-submission', methods=['POST'])
def grade_submission():
    data = request.get_json()

    # Vulnerability: No authentication or authorization check
    submission = Submission.query.get(data['submissionId'])

    if submission:
        grade = Grade(
            submission_id=submission.id,
            value=data['grade'],
            feedback=data['feedback']
        )
        db.session.add(grade)
        db.session.commit()

        return jsonify({'message': 'Grade submitted successfully'})

    return jsonify({'message': 'Submission not found'}), 404


@app.route('/api/student-submissions/<int:student_id>', methods=['GET'])
def get_student_submissions(student_id):
    # Vulnerability: IDOR possible - no authentication check
    submissions = Submission.query.filter_by(student_id=student_id).all()

    return jsonify([{
        'id': sub.id,
        'file_path': sub.file_path,
        'submitted_at': sub.submitted_at.isoformat() if hasattr(sub, 'submitted_at') else None,
        'grade': {
            'value': sub.grade.value,
            'feedback': sub.grade.feedback
        } if sub.grade else None
    } for sub in submissions])


@app.route('/api/courses/<int:course_id>/assignments', methods=['GET'])
def get_course_assignments(course_id):
    # Vulnerability: No authentication check
    assignments = Assignment.query.filter_by(course_id=course_id).all()

    return jsonify([{
        'id': a.id,
        'title': a.title,
        'description': a.description,
        'due_date': a.due_date.isoformat()
    } for a in assignments])

# Vulnerability: No input validation or sanitization
# Modified registration endpoint with role-based signup


@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()

    # Vulnerability: No input validation
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'Username already exists'}), 400

    # Vulnerability: Password stored in plaintext
    new_user = User(
        username=data['username'],
        password=data['password'],
        role=data['role']  # Vulnerability: Role can be manipulated
    )

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'Registration successful'})

# New endpoint for course creation (teachers only)


@app.route('/api/courses', methods=['POST'])
def create_course():
    token = request.headers.get('Authorization', '').split('Bearer ')[-1]
    data = request.get_json()

    try:
        payload = jwt.decode(
            token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.filter_by(id=payload['user_id']).first()

        if not user or user.role != 'teacher':
            return jsonify({'message': 'Unauthorized'}), 403

        new_course = Course(
            title=data['title'],
            description=data['description'],
            teacher_id=user.id  # Explicitly set the teacher_id
        )

        db.session.add(new_course)
        db.session.commit()

        return jsonify({
            'message': 'Course created successfully',
            'course': {
                'id': new_course.id,
                'title': new_course.title,
                'description': new_course.description,
                'teacher_id': new_course.teacher_id
            }
        })

    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401


@app.route('/api/enroll', methods=['POST'])
def enroll_in_course():
    data = request.get_json()
    token = request.headers.get('Authorization', '').split('Bearer ')[-1]

    try:
        # Vulnerability: No token expiration check
        payload = jwt.decode(
            token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(payload['user_id'])

        if not user or user.role != 'student':
            return jsonify({'message': 'Unauthorized'}), 403

        # Vulnerability: No duplicate enrollment check
        enrollment = Enrollment(
            student_id=user.id,
            course_id=data['course_id']
        )

        db.session.add(enrollment)
        db.session.commit()

        return jsonify({'message': 'Enrolled successfully'})

    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401

# Modified get_courses endpoint to include enrollment status for students


@app.route('/api/courses', methods=['GET'])
def get_courses():
    token = request.headers.get('Authorization', '').split('Bearer ')[-1]

    try:
        payload = jwt.decode(
            token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.filter_by(id=payload['user_id']).first()

        if not user:
            return jsonify({'message': 'User not found'}), 404

        if user.role == 'teacher':
            # Teachers only see their own courses
            courses = Course.query.filter_by(teacher_id=user.id).all()
            return jsonify([{
                'id': c.id,
                'title': c.title,
                'description': c.description,
                'teacher_id': c.teacher_id,
                'teacher_name': user.username  # Include teacher's own name
            } for c in courses])
        else:
            # Students see all courses
            courses = Course.query.all()
            enrollments = Enrollment.query.filter_by(student_id=user.id).all()
            enrolled_course_ids = [e.course_id for e in enrollments]

            # Get all teachers at once to avoid N+1 query problem
            teachers = {u.id: u.username for u in User.query.filter_by(
                role='teacher').all()}

            return jsonify([{
                'id': c.id,
                'title': c.title,
                'description': c.description,
                'teacher': teachers.get(c.teacher_id)
            } for c in courses if c.id in enrolled_course_ids])

    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401

# Vulnerability: No validation for file types or path sanitization


@app.route('/api/submit-assignment', methods=['POST'])
def submit_assignment():
    token = request.headers.get('Authorization', '').split('Bearer ')[-1]

    try:
        payload = jwt.decode(
            token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(payload['user_id'])

        if not user or user.role != 'student':
            return jsonify({'message': 'Unauthorized'}), 403

        file = request.files.get('file')

        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            submission = Submission(
                student_id=user.id,
                course_id=request.form['course_id'],
                file_path=file_path
            )

            db.session.add(submission)
            db.session.commit()

            return jsonify({'message': 'Assignment submitted successfully'})

    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401

    return jsonify({'message': 'No file provided'}), 400


@app.route('/api/submit-assignment', methods=['GET'])
def get_assignment():
    submission_id = request.args.get('id')
    # Vulnerability: No user verification check before downloading files
    submission = Submission.query.get(submission_id)
    if submission:
        return send_file(submission.file_path)
    return jsonify({'message': 'Submission not found'}), 404

if __name__ == '__main__':
    app.run(debug=True)
