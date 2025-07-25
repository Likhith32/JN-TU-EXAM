from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import json
import csv
from io import StringIO

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///jntu_quiz.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'

db = SQLAlchemy(app)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# -------------------- Database Models --------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    roll_no = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    address = db.Column(db.Text, nullable=False)
    branch = db.Column(db.String(50), nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    profile_pic = db.Column(db.String(120), default='default.jpg')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Exam(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    duration_minutes = db.Column(db.Integer, default=60)
    total_marks = db.Column(db.Integer, default=100)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    exam_id = db.Column(db.Integer, db.ForeignKey('exam.id'), nullable=False)
    question_text = db.Column(db.Text, nullable=False)
    option_a = db.Column(db.String(500), nullable=False)
    option_b = db.Column(db.String(500), nullable=False)
    option_c = db.Column(db.String(500), nullable=False)
    option_d = db.Column(db.String(500), nullable=False)
    correct_answer = db.Column(db.String(1), nullable=False)
    marks = db.Column(db.Integer, default=1)

class ExamResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    exam_id = db.Column(db.Integer, db.ForeignKey('exam.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    total_marks = db.Column(db.Integer, nullable=False)
    time_taken = db.Column(db.Integer)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)
    answers = db.Column(db.Text)

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

# -------------------- Helpers --------------------
def is_logged_in():
    return 'user_id' in session

def is_admin_logged_in():
    return 'admin' in session

def save_profile_pic(file):
    if file and file.filename != '':
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return filename
    return 'default.jpg'

# -------------------- Routes --------------------
@app.route('/')
def index():
    return render_template('index.html')

# ----- Admin Routes -----
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        admin = Admin.query.filter_by(username=username).first()
        if admin and check_password_hash(admin.password_hash, password):
            session['admin'] = admin.username
            flash('Logged in successfully as admin', 'success')
            return redirect(url_for('admin_dashboard'))
        flash('Invalid admin credentials', 'error')
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if not is_admin_logged_in():
        return redirect(url_for('admin_login'))
    results = db.session.query(ExamResult, User, Exam)\
        .join(User, ExamResult.user_id == User.id)\
        .join(Exam, ExamResult.exam_id == Exam.id)\
        .order_by(ExamResult.completed_at.desc()).all()
    return render_template('admin_dashboard.html', results=results)

@app.route('/admin/results/download')
def download_results_csv():
    if not is_admin_logged_in():
        return redirect(url_for('admin_login'))
    results = db.session.query(ExamResult, User, Exam).join(User).join(Exam).all()
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['Name', 'Roll No', 'Exam', 'Score', 'Total', 'Date'])
    for result, user, exam in results:
        cw.writerow([
            user.name, user.roll_no, exam.title, result.score,
            result.total_marks, result.completed_at.strftime('%d-%m-%Y %H:%M')
        ])
    output = si.getvalue()
    return Response(output, mimetype='text/csv',
                    headers={"Content-Disposition": "attachment;filename=results.csv"})

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('admin_login'))

# ----- User Routes -----
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.form
        roll_no = data['roll_no']

        # Validation
        if len(roll_no) != 10 or not roll_no.isalnum():
            flash("Roll number must be exactly 10 alphanumeric characters.", "error")
            return render_template('register.html')

        if User.query.filter_by(email=data['email']).first():
            flash('Email already registered', 'error')
            return render_template('register.html')

        if User.query.filter_by(roll_no=roll_no).first():
            flash('Roll number already registered', 'error')
            return render_template('register.html')

        if len(data['password']) < 8:
            flash('Password must be at least 8 characters long', 'error')
            return render_template('register.html')

        file = request.files.get('profile_pic')
        profile_pic = save_profile_pic(file)

        user = User(
            name=data['name'],
            roll_no=roll_no,
            email=data['email'],
            phone_number=data['phone_number'],
            address=data['address'],
            branch=data['branch'],
            gender=data['gender'],
            password_hash=generate_password_hash(data['password']),
            profile_pic=profile_pic
        )
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        roll_no = request.form['roll_no']
        password = request.form['password']
        user = User.query.filter_by(roll_no=roll_no).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['user_name'] = user.name
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid roll number or password', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if not is_logged_in():
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    exams = Exam.query.filter_by(is_active=True).all()
    results = ExamResult.query.filter_by(user_id=user.id).all()

    total_exams = len(exams)
    completed_exams = len(results)
    avg_score = sum(r.score for r in results) / len(results) if results else 0

    progress_stats = {
        'total_exams': total_exams,
        'completed_exams': completed_exams,
        'avg_score': round(avg_score, 1),
        'completion_rate': round((completed_exams / total_exams * 100) if total_exams > 0 else 0, 1)
    }

    session.pop('exam_submitted', None)
    return render_template('dashboard.html', user=user, exams=exams, results=results, progress_stats=progress_stats)

@app.route('/exam/<int:exam_id>', methods=['GET'])
def take_exam(exam_id):
    if not is_logged_in():
        return redirect(url_for('login'))

    existing_result = ExamResult.query.filter_by(user_id=session['user_id'], exam_id=exam_id).first()
    if existing_result:
        flash("You have already taken this exam.", "info")
        return redirect(url_for('results'))

    exam = Exam.query.get_or_404(exam_id)
    questions = Question.query.filter_by(exam_id=exam_id).all()

    return render_template('exam.html', exam=exam, questions=questions,
                           current_question=1, total_questions=len(questions))

@app.route('/submit_exam', methods=['POST'])
def submit_exam():
    if not is_logged_in():
        return redirect(url_for('login'))

    if session.get('exam_submitted'):
        return jsonify({'success': False, 'message': 'Exam already submitted'})

    data = request.json
    exam_id = data.get('exam_id')
    answers = data.get('answers', {})
    time_taken = data.get('time_taken')

    exam = Exam.query.get_or_404(exam_id)
    questions = Question.query.filter_by(exam_id=exam_id).all()

    score = 0
    for question in questions:
        user_answer = answers.get(str(question.id))
        if user_answer == question.correct_answer:
            score += question.marks

    result = ExamResult(
        user_id=session['user_id'],
        exam_id=exam_id,
        score=score,
        total_marks=exam.total_marks,
        time_taken=time_taken,
        answers=json.dumps(answers)
    )
    db.session.add(result)
    db.session.commit()

    session['exam_submitted'] = True
    return jsonify({'success': True, 'score': score, 'total_marks': exam.total_marks})

@app.route('/results')
def results():
    if not is_logged_in():
        return redirect(url_for('login'))

    user_results = db.session.query(ExamResult, Exam)\
        .join(Exam).filter(ExamResult.user_id == session['user_id']).all()
    return render_template('results.html', user_results=user_results)

@app.route('/profile')
def profile():
    if not is_logged_in():
        flash("Please log in to view profile", "error")
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    results = db.session.query(ExamResult, Exam)\
        .join(Exam).filter(ExamResult.user_id == user.id).all()
    return render_template('profile.html', user=user, results=results)

# -------------------- Initial DB Seeder --------------------
def init_db():
    with app.app_context():
        db.create_all()
        if not Admin.query.first():
            admin = Admin(username='admin', password_hash=generate_password_hash('admin123'))
            db.session.add(admin)
            db.session.commit()

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
