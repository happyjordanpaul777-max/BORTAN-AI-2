from flask import Flask, render_template, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os, re
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-only-change-this-before-public-deployment')
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=bool(os.environ.get('RENDER')) , PERMANENT_SESSION_LIFETIME=__import__('datetime').timedelta(days=30))
DB_PATH = os.environ.get('DATABASE_PATH', os.path.join(os.path.dirname(__file__), 'bortan.db'))


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn


def init_db():
    with db() as con:
        con.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )''')
        con.execute('''CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            title TEXT NOT NULL DEFAULT 'New Chat',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )''')
        con.execute('''CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
            role TEXT NOT NULL CHECK(role IN ('user','assistant')),
            content TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )''')


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get('user_id'):
            return jsonify(error='Please sign in first.'), 401
        return fn(*args, **kwargs)
    return wrapper


def owned_conversation(con, cid):
    return con.execute('SELECT * FROM conversations WHERE id=? AND user_id=?', (cid, session['user_id'])).fetchone()

init_db()

@app.route('/')
def home():
    return render_template('index.html')

@app.post('/api/signup')
def signup():
    data = request.get_json(silent=True) or {}
    username = str(data.get('username', '')).strip()
    password = str(data.get('password', ''))
    if not re.fullmatch(r'[A-Za-z0-9_.-]{3,30}', username):
        return jsonify(error='Username must be 3–30 characters using letters, numbers, dots, _ or -.'), 400
    if len(password) < 8:
        return jsonify(error='Password must be at least 8 characters.'), 400
    try:
        with db() as con:
            cur = con.execute('INSERT INTO users(username,password_hash) VALUES(?,?)', (username, generate_password_hash(password)))
            uid = cur.lastrowid
    except sqlite3.IntegrityError:
        return jsonify(error='That username is already taken. Choose another.'), 409
    session.clear()
    session['user_id'] = uid
    session['username'] = username
    session.permanent = True
    app.permanent_session_lifetime = __import__('datetime').timedelta(days=30)
    return jsonify(message='Account created. You are signed in.', user={'username': username})

@app.post('/api/login')
def login():
    data = request.get_json(silent=True) or {}
    username, password = str(data.get('username','')).strip(), str(data.get('password',''))
    with db() as con:
        user = con.execute('SELECT * FROM users WHERE username=? COLLATE NOCASE', (username,)).fetchone()
    if not user or not check_password_hash(user['password_hash'], password):
        return jsonify(error='Incorrect username or password.'), 401
    session.clear()
    session['user_id'] = user['id']
    session['username'] = user['username']
    session.permanent = True
    return jsonify(message='Signed in successfully.', user={'username': user['username']})

@app.post('/api/logout')
def logout():
    session.clear()
    return jsonify(message='Signed out.')

@app.get('/api/me')
def me():
    if not session.get('user_id'):
        return jsonify(logged_in=False)
    return jsonify(logged_in=True, user={'username': session.get('username')})

@app.get('/api/conversations')
@login_required
def list_conversations():
    with db() as con:
        rows = con.execute('SELECT id,title,updated_at FROM conversations WHERE user_id=? ORDER BY updated_at DESC,id DESC', (session['user_id'],)).fetchall()
    return jsonify(conversations=[dict(r) for r in rows])

@app.post('/api/conversations')
@login_required
def create_conversation():
    data = request.get_json(silent=True) or {}
    title = str(data.get('title') or 'New Chat').strip()[:80] or 'New Chat'
    with db() as con:
        cur = con.execute('INSERT INTO conversations(user_id,title) VALUES(?,?)', (session['user_id'], title))
        row = con.execute('SELECT id,title,updated_at FROM conversations WHERE id=?', (cur.lastrowid,)).fetchone()
    return jsonify(conversation=dict(row)), 201

@app.get('/api/conversations/<int:cid>/messages')
@login_required
def get_messages(cid):
    with db() as con:
        if not owned_conversation(con, cid): return jsonify(error='Chat not found.'), 404
        rows = con.execute('SELECT role,content,created_at FROM messages WHERE conversation_id=? ORDER BY id', (cid,)).fetchall()
    return jsonify(messages=[dict(r) for r in rows])

@app.post('/api/conversations/<int:cid>/messages')
@login_required
def add_message(cid):
    data = request.get_json(silent=True) or {}
    role, content = data.get('role'), str(data.get('content','')).strip()
    if role not in ('user','assistant') or not content:
        return jsonify(error='Message role or content is invalid.'), 400
    if len(content) > 20000: return jsonify(error='Message is too long.'), 413
    with db() as con:
        chat = owned_conversation(con, cid)
        if not chat: return jsonify(error='Chat not found.'), 404
        con.execute('INSERT INTO messages(conversation_id,role,content) VALUES(?,?,?)', (cid,role,content))
        if role == 'user' and chat['title'] == 'New Chat':
            con.execute('UPDATE conversations SET title=?,updated_at=CURRENT_TIMESTAMP WHERE id=?', (content[:60],cid))
        else:
            con.execute('UPDATE conversations SET updated_at=CURRENT_TIMESTAMP WHERE id=?', (cid,))
    return jsonify(saved=True)

@app.delete('/api/conversations/<int:cid>')
@login_required
def delete_conversation(cid):
    with db() as con:
        chat = owned_conversation(con,cid)
        if not chat: return jsonify(error='Chat not found.'),404
        con.execute('DELETE FROM conversations WHERE id=?',(cid,))
    return jsonify(deleted=True)

# The AI model endpoint is intentionally a placeholder until the user's model is connected.
@app.post('/ask')
def ask():
    data=request.get_json(silent=True) or {}
    question=str(data.get('question','')).strip()
    if not question: return jsonify(error='Please enter a question.'),400
    return jsonify(answer='This is the BORTAN 2 interface demo. Your question was received, but the actual AI model has not been connected yet.')

if __name__ == '__main__':
    app.run(debug=True)
