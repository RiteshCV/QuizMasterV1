from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, session
from datetime import datetime
import sqlite3
import hashlib
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)


def get_db():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def is_user_admin(email):
    conn = get_db()
    user = conn.execute('SELECT is_admin FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()
    return user and user['is_admin'] == 1


@app.route('/')
def home():
    return render_template('home.html', is_home=True)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        if user and user['password'] == hash_password(password):
            session['user'] = {'email': email, 'username': user['username']}
            return redirect(url_for('subjects'))
        else:
            flash('Invalid email or password', 'error')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')

        conn = get_db()
        try:
            conn.execute(
                'INSERT INTO users (email, username, password) VALUES (?, ?, ?)',
                (email, username, hash_password(password))
            )
            conn.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already registered', 'error')
        finally:
            conn.close()

    return render_template('register.html')


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))


@app.route('/subjects')
def subjects():
    if 'user' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    subjects = [row['name'] for row in conn.execute('SELECT name FROM subjects').fetchall()]
    conn.close()

    is_admin = is_user_admin(session['user']['email'])
    return render_template('subjects.html', subjects=subjects, is_admin=is_admin)


@app.route('/subjects/<subject_name>')
def subject_chapters(subject_name):
    if 'user' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    chapters = conn.execute('''
        SELECT chapters.name 
        FROM chapters 
        JOIN subjects ON chapters.subject_id = subjects.id 
        WHERE subjects.name = ?
    ''', (subject_name,)).fetchall()

    chapter_names = [row['name'] for row in chapters]
    conn.close()

    is_admin = is_user_admin(session['user']['email'])
    return render_template('chapters.html', subject_name=subject_name, chapters=chapter_names, is_admin=is_admin)


@app.route('/subjects/<subject_name>/<chapter_name>')
def chapter_quizzes(subject_name, chapter_name):
    if 'user' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    quizzes = conn.execute('''
        SELECT quizzes.id, quizzes.opens_on, quizzes.closes_on, quizzes.duration,
               COUNT(questions.id) as num_questions,
               CASE WHEN qa.attempt_date IS NOT NULL THEN 1 ELSE 0 END as attempted
        FROM quizzes
        JOIN chapters ON quizzes.chapter_id = chapters.id
        JOIN subjects ON chapters.subject_id = subjects.id
        LEFT JOIN questions ON questions.quiz_id = quizzes.id
        LEFT JOIN quiz_attempts qa ON qa.quiz_id = quizzes.id AND qa.user_id = (
            SELECT id FROM users WHERE email = ?
        )
        WHERE subjects.name = ? AND chapters.name = ?
        GROUP BY quizzes.id, quizzes.opens_on, quizzes.closes_on, quizzes.duration
    ''', (session['user']['email'], subject_name, chapter_name)).fetchall()

    quiz_list = []
    for quiz in quizzes:
        quiz_list.append({
            'id': f"Q{quiz['id']:03d}",
            'opens_on': datetime.fromisoformat(quiz['opens_on']),
            'closes_on': datetime.fromisoformat(quiz['closes_on']),
            'duration': quiz['duration'],
            'num_questions': quiz['num_questions'],
            'attempted': bool(quiz['attempted'])
        })

    is_admin = is_user_admin(session['user']['email'])
    return render_template('quizzes.html', subject_name=subject_name, chapter_name=chapter_name, quizzes=quiz_list,
                            now=datetime.now(), is_admin=is_admin)


@app.route('/subjects/<subject_name>/<chapter_name>/<quiz_id>')
def take_quiz(subject_name, chapter_name, quiz_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    quiz_number = int(quiz_id[1:])

    conn = get_db()
    quiz = conn.execute('''
        SELECT quizzes.*, COUNT(questions.id) as num_questions
        FROM quizzes
        JOIN chapters ON quizzes.chapter_id = chapters.id
        JOIN subjects ON chapters.subject_id = subjects.id
        LEFT JOIN questions ON questions.quiz_id = quizzes.id
        WHERE subjects.name = ? AND chapters.name = ? AND quizzes.id = ?
        GROUP BY quizzes.id, quizzes.chapter_id, quizzes.opens_on, quizzes.closes_on, 
         quizzes.duration, quizzes.created_at
    ''', (subject_name, chapter_name, quiz_number)).fetchone()

    if not quiz:
        return "Quiz not found", 404

    questions = conn.execute('''
        SELECT q.id, q.question_text AS question, q.correct_answer
        FROM questions q
        WHERE q.quiz_id = ?
        GROUP BY q.id, q.question_text, q.correct_answer
    ''', (quiz_number,)).fetchall()

    quiz_data = {
        'id': f"Q{quiz['id']:03d}",
        'opens_on': datetime.fromisoformat(quiz['opens_on']),
        'closes_on': datetime.fromisoformat(quiz['closes_on']),
        'duration': quiz['duration']
    }

    questions_list = []
    for q in questions:
        options = conn.execute(
            'SELECT option_text FROM options WHERE question_id = ?',
            (q['id'],)
        ).fetchall()
        options_list = [opt['option_text'] for opt in options]
        questions_list.append({
            'id': q['id'],
            'question': q['question'],
            'options': options_list,
            'correct_answer': q['correct_answer']
        })
    quiz_data['num_questions']=len(questions_list)
    conn.close()
    return render_template('quiz.html', subject_name=subject_name, chapter_name=chapter_name, quiz=quiz_data,
                           questions=questions_list)


@app.route('/quiz/<quiz_id>/history')
def quiz_history(quiz_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    quiz_number = int(quiz_id[1:])
    conn = get_db()

    if is_user_admin(session['user']['email']):
        history = conn.execute('''
            SELECT qa.attempt_date, qa.score, qa.time_taken,
                   COUNT(CASE WHEN qa2.score <= qa.score THEN 1 END) * 100.0 / COUNT(*) as percentile,
                   (SELECT COUNT(*) FROM questions WHERE quiz_id = ?) as total_questions
            FROM quiz_attempts qa
            LEFT JOIN quiz_attempts qa2 ON qa.quiz_id = qa2.quiz_id
            WHERE qa.quiz_id = ?
            GROUP BY qa.attempt_date, qa.score, qa.time_taken
            ORDER BY qa.attempt_date DESC
        ''', (quiz_number, quiz_number)).fetchall()
    else:
        history = conn.execute('''
            SELECT qa.attempt_date, qa.score, qa.time_taken,
                   COUNT(CASE WHEN qa2.score <= qa.score THEN 1 END) * 100.0 / COUNT(*) as percentile,
                   (SELECT COUNT(*) FROM questions WHERE quiz_id = ?) as total_questions
            FROM quiz_attempts qa
            JOIN users u ON qa.user_id = u.id
            LEFT JOIN quiz_attempts qa2 ON qa.quiz_id = qa2.quiz_id
            WHERE u.email = ? AND qa.quiz_id = ?
            GROUP BY qa.attempt_date, qa.score, qa.time_taken
            ORDER BY qa.attempt_date DESC
        ''', (quiz_number, session['user']['email'], quiz_number)).fetchall()

    history_list = []
    for attempt in history:
        correct_answers = int(attempt['score'] * attempt['total_questions'] / 100)
        history_list.append({
            'attempt_date': datetime.fromisoformat(attempt['attempt_date']),
            'score': attempt['score'],
            'time_taken': attempt['time_taken'],
            'correct_answers': correct_answers,
            'total_questions': attempt['total_questions']
        })

    conn.close()
    return jsonify(history_list)


@app.route('/api/subjects/update', methods=['POST'])
def update_subject():
    if 'user' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    if not is_user_admin(session['user']['email']):
        return jsonify({"error": "Forbidden, admin access required"}), 403

    old_name = request.json.get('oldName')
    new_name = request.json.get('newName')

    if not old_name or not new_name:
        return jsonify({"error": "Both oldName and newName are required"}), 400

    conn = get_db()

    subject = conn.execute('SELECT * FROM subjects WHERE name = ?', (old_name,)).fetchone()
    if not subject:
        conn.close()
        return jsonify({"error": "Subject not found"}), 404

    conn.execute('UPDATE subjects SET name = ? WHERE name = ?', (new_name, old_name))
    conn.commit()
    conn.close()

    return jsonify({"message": f"Subject name updated from {old_name} to {new_name}"}), 200


@app.route('/api/subjects/remove', methods=['POST'])
def remove_subject():
    if 'user' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    if not is_user_admin(session['user']['email']):
        return jsonify({"error": "Forbidden, admin access required"}), 403

    subject_name = request.json.get('subject')

    if not subject_name:
        return jsonify({"error": "Subject name is required"}), 400

    conn = get_db()

    subject = conn.execute('SELECT * FROM subjects WHERE name = ?', (subject_name,)).fetchone()
    if not subject:
        conn.close()
        return jsonify({"error": "Subject not found"}), 404

    conn.execute('DELETE FROM subjects WHERE name = ?', (subject_name,))
    conn.commit()
    conn.close()

    return jsonify({"message": f"Subject {subject_name} removed successfully"}), 200


@app.route('/api/subjects/add', methods=['POST'])
def add_subject():
    if 'user' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    if not is_user_admin(session['user']['email']):
        return jsonify({"error": "Forbidden, admin access required"}), 403

    new_subject = request.json.get('newSubject')

    if not new_subject:
        return jsonify({"error": "New subject name is required"}), 400

    conn = get_db()

    existing_subject = conn.execute('SELECT * FROM subjects WHERE name = ?', (new_subject,)).fetchone()
    if existing_subject:
        conn.close()
        return jsonify({"error": "Subject already exists"}), 400

    conn.execute('INSERT INTO subjects (name) VALUES (?)', (new_subject,))
    conn.commit()
    conn.close()

    return jsonify({"message": f"New subject {new_subject} added successfully"}), 200


@app.route('/api/chapters/update', methods=['POST'])
def update_chapter():
    if 'user' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    if not is_user_admin(session['user']['email']):
        return jsonify({"error": "Forbidden, admin access required"}), 403

    old_name = request.json.get('oldName')
    new_name = request.json.get('newName')

    if not old_name or not new_name:
        return jsonify({"error": "Both oldName and newName are required"}), 400

    conn = get_db()

    chapter = conn.execute('SELECT * FROM chapters WHERE name = ?', (old_name,)).fetchone()
    if not chapter:
        conn.close()
        return jsonify({"error": "Chapter not found"}), 404

    conn.execute('UPDATE chapters SET name = ? WHERE name = ?', (new_name, old_name))
    conn.commit()
    conn.close()

    return jsonify({"message": f"Chapter name updated from {old_name} to {new_name}"}), 200


@app.route('/api/chapters/remove', methods=['POST'])
def remove_chapter():
    if 'user' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    if not is_user_admin(session['user']['email']):
        return jsonify({"error": "Forbidden, admin access required"}), 403

    chapter_name = request.json.get('chapter')

    if not chapter_name:
        return jsonify({"error": "Chapter name is required"}), 400

    conn = get_db()

    chapter = conn.execute('SELECT * FROM chapters WHERE name = ?', (chapter_name,)).fetchone()
    if not chapter:
        conn.close()
        return jsonify({"error": "Chapter not found"}), 404

    conn.execute('DELETE FROM chapters WHERE name = ?', (chapter_name,))
    conn.commit()
    conn.close()

    return jsonify({"message": f"Chapter {chapter_name} removed successfully"}), 200


@app.route('/api/chapters/add', methods=['POST'])
def add_chapter():
    if 'user' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    if not is_user_admin(session['user']['email']):
        return jsonify({"error": "Forbidden, admin access required"}), 403

    new_chapter = request.json.get('newChapter')
    subject_name = request.json.get('subjectName')

    if not new_chapter or not subject_name:
        return jsonify({"error": "New chapter name and subject name are required"}), 400

    conn = get_db()

    subject = conn.execute('SELECT id FROM subjects WHERE name = ?', (subject_name,)).fetchone()
    if not subject:
        conn.close()
        return jsonify({"error": "Subject not found"}), 404

    existing_chapter = conn.execute('SELECT * FROM chapters WHERE name = ? AND subject_id = ?', (new_chapter, subject['id'])).fetchone()
    if existing_chapter:
        conn.close()
        return jsonify({"error": "Chapter already exists in this subject"}), 400

    conn.execute('INSERT INTO chapters (name, subject_id) VALUES (?, ?)', (new_chapter, subject['id']))
    conn.commit()
    conn.close()

    return jsonify({"message": f"New chapter {new_chapter} added successfully under {subject_name}"}), 200


@app.route('/api/quizzes/update', methods=['POST'])
def update_quiz():
    if 'user' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    if not is_user_admin(session['user']['email']):
        return jsonify({"error": "Forbidden, admin access required"}), 403

    data = request.json
    quiz_id = data.get('quizId')
    opens_on = data.get('opensOn')
    closes_on = data.get('closesOn')
    duration = data.get('duration')
    questions = data.get('questions')

    if not all([quiz_id, opens_on, closes_on, duration, questions]):
        return jsonify({"error": "All fields are required"}), 400

    conn = get_db()
    conn.execute('''UPDATE quizzes SET opens_on = ?, closes_on = ?, duration = ? WHERE id = ?''',
                 (opens_on, closes_on, duration, quiz_id))
    conn.execute('DELETE FROM questions WHERE quiz_id = ?', (quiz_id,))

    for q in questions:
        cur = conn.execute('INSERT INTO questions (quiz_id, question_text, correct_answer) VALUES (?, ?, ?)',
                           (quiz_id, q['question'], q['correct_answer']))
        question_id = cur.lastrowid
        for opt in q['options']:
            conn.execute('INSERT INTO options (question_id, option_text) VALUES (?, ?)', (question_id, opt))

    conn.commit()
    conn.close()
    return jsonify({"message": "Quiz updated successfully"}), 200


@app.route('/api/quizzes/delete', methods=['POST'])
def delete_quiz():
    if 'user' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    if not is_user_admin(session['user']['email']):
        return jsonify({"error": "Forbidden, admin access required"}), 403

    quiz_id = request.json.get('currentQuizId')
    if not quiz_id:
        return jsonify({"error": "Quiz ID is required"}), 400

    conn = get_db()
    conn.execute('DELETE FROM quizzes WHERE id = ?', (quiz_id,))
    conn.execute('DELETE FROM questions WHERE quiz_id = ?', (quiz_id,))
    conn.commit()
    conn.close()

    return jsonify({"message": "Quiz deleted successfully"}), 200


@app.route('/api/quizzes/create', methods=['POST'])
def create_quiz():
    if 'user' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    if not is_user_admin(session['user']['email']):
        return jsonify({"error": "Forbidden, admin access required"}), 403

    data = request.json
    opens_on = data.get('opensOn')
    closes_on = data.get('closesOn')
    duration = data.get('duration')
    questions = data.get('questions')
    chapter_name = data.get('chapterName')

    if not all([opens_on, closes_on, duration, questions, chapter_name]):
        return jsonify({"error": "All fields are required"}), 400

    conn = get_db()
    chapter = conn.execute('''SELECT id FROM chapters WHERE name = ?''', (chapter_name,)).fetchone()
    if not chapter:
        conn.close()
        return jsonify({"error": "Chapter not found"}), 404
    chapter_id = chapter['id']

    cur = conn.execute('INSERT INTO quizzes (opens_on, closes_on, duration, chapter_id) VALUES (?, ?, ?, ?)',
                       (opens_on, closes_on, duration, chapter_id))
    quiz_id = cur.lastrowid

    for q in questions:
        cur = conn.execute('INSERT INTO questions (quiz_id, question_text, correct_answer) VALUES (?, ?, ?)',
                           (quiz_id, q['question'], q['correct_answer']))
        question_id = cur.lastrowid
        for opt in q['options']:
            conn.execute('INSERT INTO options (question_id, option_text) VALUES (?, ?)', (question_id, opt))

    conn.commit()
    conn.close()
    return jsonify({"message": "Quiz created successfully", "quiz_id": quiz_id}), 201


@app.route('/api/quizzes/<quiz_id>', methods=['GET'])
def get_quiz_details(quiz_id):
    if 'user' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    quiz_id = int(quiz_id[1:])

    conn = get_db()
    quiz = conn.execute(
        'SELECT id, opens_on, closes_on, duration FROM quizzes WHERE id = ?',
        (quiz_id,)
    ).fetchone()

    if not quiz:
        conn.close()
        return jsonify({"error": "Quiz not found"}), 404

    questions = conn.execute(
        'SELECT id, question_text, correct_answer FROM questions WHERE quiz_id = ?',
        (quiz_id,)
    ).fetchall()

    questions_list = []
    for question in questions:
        options = conn.execute(
            'SELECT option_text FROM options WHERE question_id = ?',
            (question['id'],)
        ).fetchall()
        options_list = [opt['option_text'] for opt in options]
        print(options_list)
        questions_list.append({
            'id': question['id'],
            'question': question['question_text'],
            'options': options_list,
            'correct_answer': question['correct_answer']
        })

    conn.close()

    return jsonify({
        'quiz': {
            'id': quiz['id'],
            'opensOn': quiz['opens_on'],
            'closesOn': quiz['closes_on'],
            'duration': quiz['duration'],
            'questions': questions_list
        }
    }), 200


@app.route('/api/quizzes/submit', methods=['POST'])
def submit_quiz():
    if 'user' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    quiz_id = data.get('quizId')
    quiz_id = int(quiz_id[1:])
    answers = data.get('answers')

    if not quiz_id or answers is None:
        return jsonify({"error": "quizId and answers are required"}), 400

    conn = get_db()
    questions = conn.execute(
        'SELECT id, correct_answer FROM questions WHERE quiz_id = ?',
        (quiz_id,)
    ).fetchall()

    total_questions = len(questions)
    if total_questions == 0:
        conn.close()
        return jsonify({"error": "No questions found for this quiz"}), 400

    correct_count = 0
    for question in questions:
        user_answer = answers.get(str(question['id']))
        if user_answer is not None and int(user_answer) == int(question['correct_answer']):
            correct_count += 1

    score = (correct_count / total_questions) * 100
    user = conn.execute('SELECT id FROM users WHERE email = ?', (session['user']['email'],)).fetchone()
    user_id = user['id'] if user else None
    if not user_id:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    attempt_date = datetime.now().isoformat()
    time_taken = data.get('timeTaken', 0)
    conn.execute('''
        INSERT INTO quiz_attempts (quiz_id, user_id, attempt_date, score, time_taken)
        VALUES (?, ?, ?, ?, ?)
    ''', (quiz_id, user_id, attempt_date, score, time_taken))
    conn.commit()
    conn.close()

    return jsonify({"message": "Quiz submitted successfully", "score": score}), 200


@app.route('/api/users', methods=['GET'])
def get_users():
    if 'user' not in session or session['user']['role'] != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403

    conn = get_db()
    users = conn.execute('SELECT id, email FROM users').fetchall()
    conn.close()

    user_list = [{'id': user['id'], 'name': user['name'], 'email': user['email'], 'role': user['role']} for user in
                 users]

    return jsonify(user_list)


@app.route('/api/subjects', methods=['GET'])
def get_subjects():
    conn = get_db()
    subjects = conn.execute('SELECT id, name FROM subjects').fetchall()
    conn.close()

    subject_list = [{'id': subject['id'], 'name': subject['name']} for subject in subjects]

    return jsonify(subject_list)


@app.route('/api/subjects/<subject_name>/chapters', methods=['GET'])
def get_chapters(subject_name):
    conn = get_db()
    subject = conn.execute('SELECT id FROM subjects WHERE name = ?', (subject_name,)).fetchone()
    if not subject:
        conn.close()
        return jsonify({'error': 'Subject not found'}), 404
    chapters = conn.execute('SELECT id, name FROM chapters WHERE subject_id = ?', (subject['id'],)).fetchall()
    conn.close()
    chapter_list = [{'id': chapter['id'], 'name': chapter['name']} for chapter in chapters]
    return jsonify(chapter_list)


if __name__ == '__main__':
    app.run(debug=True)