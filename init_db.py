import sqlite3
from datetime import datetime, timedelta
import hashlib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # Create users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_admin BOOLEAN DEFAULT 0
        )
    ''')

    # Create subjects table
    c.execute('''
        CREATE TABLE IF NOT EXISTS subjects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Create chapters table
    c.execute('''
        CREATE TABLE IF NOT EXISTS chapters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (subject_id) REFERENCES subjects (id),
            UNIQUE (subject_id, name)
        )
    ''')

    # Create quizzes table
    c.execute('''
        CREATE TABLE IF NOT EXISTS quizzes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chapter_id INTEGER NOT NULL,
            opens_on TIMESTAMP NOT NULL,
            closes_on TIMESTAMP NOT NULL,
            duration INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (chapter_id) REFERENCES chapters (id)
        )
    ''')

    # Create questions table
    c.execute('''
        CREATE TABLE IF NOT EXISTS questions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            quiz_id INTEGER NOT NULL,
            question_text TEXT NOT NULL,
            correct_answer INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (quiz_id) REFERENCES quizzes (id)
        )
    ''')

    # Create options table
    c.execute('''
        CREATE TABLE IF NOT EXISTS options (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            question_id INTEGER NOT NULL,
            option_text TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (question_id) REFERENCES questions (id)
        )
    ''')

    # Create quiz_attempts table
    c.execute('''
        CREATE TABLE IF NOT EXISTS quiz_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            quiz_id INTEGER NOT NULL,
            score FLOAT NOT NULL,
            time_taken INTEGER NOT NULL,
            attempt_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (quiz_id) REFERENCES quizzes (id)
        )
    ''')

    # Insert default admin user
    admin_email = "admin@example.com"
    admin_username = "admin"
    admin_password = hash_password("qwerty")
    c.execute('''
            INSERT INTO users (email, username, password, is_admin)
            VALUES (?, ?, ?, 1)
        ''', (admin_email, admin_username, admin_password))

    # Sample subjects
    subjects = [
        "Mathematics",
        "Physics",
        "Chemistry",
        "Biology",
        "Computer Science",
        "English"
    ]
    for subject in subjects:
        c.execute('INSERT INTO subjects (name) VALUES (?)', (subject,))
        subject_id = c.execute('SELECT id FROM subjects WHERE name = ?', (subject,)).fetchone()[0]

        # Sample chapters
        chapters = {
            "Mathematics": ["Algebra", "Calculus", "Geometry", "Trigonometry", "Statistics"],
            "Physics": ["Mechanics", "Thermodynamics", "Optics", "Electromagnetism", "Modern Physics"],
            "Chemistry": ["Organic Chemistry", "Inorganic Chemistry", "Physical Chemistry", "Analytical Chemistry", "Biochemistry"],
            "Biology": ["Cell Biology", "Genetics", "Evolution", "Ecology", "Physiology"],
            "Computer Science": ["Programming Fundamentals", "Data Structures", "Algorithms", "Database Systems", "Operating Systems"],
            "English": ["Grammar", "Literature", "Composition", "Vocabulary", "Comprehension"]
        }
        for chapter in chapters[subject]:
            c.execute('INSERT INTO chapters (subject_id, name) VALUES (?, ?)',
                     (subject_id, chapter))
            chapter_id = c.execute('SELECT id FROM chapters WHERE subject_id = ? AND name = ?',
                                 (subject_id, chapter)).fetchone()[0]

            # Create sample quizzes
            now = datetime.now()
            quiz_data = [
                (chapter_id, now - timedelta(days=1), now + timedelta(days=7), 60),
                (chapter_id, now + timedelta(days=1), now + timedelta(days=14), 45),
                (chapter_id, now - timedelta(days=7), now - timedelta(days=1), 30)
            ]
            for quiz in quiz_data:
                c.execute('''
                    INSERT INTO quizzes 
                    (chapter_id, opens_on, closes_on, duration)
                    VALUES (?, ?, ?, ?)
                ''', quiz)
    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
    print("Database initialized successfully!")