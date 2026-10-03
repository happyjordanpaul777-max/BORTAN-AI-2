
import os
import sqlite3
from functools import wraps
from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    session
)
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

app = Flask(__name__)

# IMPORTANT:
# Set SECRET_KEY as an environment variable when deploying.
# This fallback is only for local development.
app.secret_key = os.environ.get(
    "SECRET_KEY",
    "bortan-2-local-development-key-change-before-deploy"
)

DATABASE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "bortan2.db"
)


# ---------------- DATABASE ----------------

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    with get_db() as db:

        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS conversations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL DEFAULT 'New Chat',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id INTEGER NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (conversation_id)
                    REFERENCES conversations(id)
                    ON DELETE CASCADE
            )
        """)


# ---------------- SECURITY ----------------

def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({
                "success": False,
                "error": "Please sign in first."
            }), 401

        return func(*args, **kwargs)

    return wrapper


def get_json():
    return request.get_json(silent=True) or {}


def get_owned_conversation(db, conversation_id):
    return db.execute("""
        SELECT id, title
        FROM conversations
        WHERE id = ? AND user_id = ?
    """, (conversation_id, session["user_id"])).fetchone()


# ---------------- MAIN WEBSITE ----------------

@app.route("/")
def home():
    return render_template("index.html")


# ---------------- CREATE ACCOUNT ----------------

@app.route("/api/signup", methods=["POST"])
def signup():

    data = get_json()

    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not username or not password:
        return jsonify({
            "success": False,
            "error": "Enter a username and password."
        }), 400

    if len(username) < 3 or len(username) > 30:
        return jsonify({
            "success": False,
            "error": "Username must be 3 to 30 characters."
        }), 400

    if not all(c.isalnum() or c in "_-" for c in username):
        return jsonify({
            "success": False,
            "error": "Use only letters, numbers, _ or - in username."
        }), 400

    if len(password) < 8:
        return jsonify({
            "success": False,
            "error": "Password must be at least 8 characters."
        }), 400

    if len(password) > 128:
        return jsonify({
            "success": False,
            "error": "Password is too long."
        }), 400

    password_hash = generate_password_hash(password)

    try:
        with get_db() as db:
            cursor = db.execute("""
                INSERT INTO users (username, password_hash)
                VALUES (?, ?)
            """, (username, password_hash))

            user_id = cursor.lastrowid

        session.clear()
        session["user_id"] = user_id
        session["username"] = username

        return jsonify({
            "success": True,
            "message": "Account created successfully.",
            "user": {
                "id": user_id,
                "username": username
            }
        }), 201

    except sqlite3.IntegrityError:
        return jsonify({
            "success": False,
            "error": "That username is already taken."
        }), 409


# ---------------- SIGN IN ----------------

@app.route("/api/login", methods=["POST"])
def login():

    data = get_json()

    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not username or not password:
        return jsonify({
            "success": False,
            "error": "Enter your username and password."
        }), 400

    with get_db() as db:
        user = db.execute("""
            SELECT id, username, password_hash
            FROM users
            WHERE username = ?
        """, (username,)).fetchone()

    if user is None or not check_password_hash(
        user["password_hash"], password
    ):
        return jsonify({
            "success": False,
            "error": "Incorrect username or password."
        }), 401

    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]

    return jsonify({
        "success": True,
        "message": "Signed in successfully.",
        "user": {
            "id": user["id"],
            "username": user["username"]
        }
    })


# ---------------- SIGN OUT ----------------

@app.route("/api/logout", methods=["POST"])
def logout():

    session.clear()

    return jsonify({
        "success": True,
        "message": "Signed out successfully."
    })


# ---------------- CURRENT ACCOUNT ----------------

@app.route("/api/me", methods=["GET"])
def current_user():

    if "user_id" not in session:
        return jsonify({
            "success": True,
            "logged_in": False
        })

    return jsonify({
        "success": True,
        "logged_in": True,
        "user": {
            "id": session["user_id"],
            "username": session["username"]
        }
    })


# ---------------- CREATE CHAT ----------------

@app.route("/api/conversations", methods=["POST"])
@login_required
def create_conversation():

    data = get_json()

    title = str(data.get("title", "New Chat")).strip()

    if not title:
        title = "New Chat"

    title = title[:100]

    with get_db() as db:
        cursor = db.execute("""
            INSERT INTO conversations (user_id, title)
            VALUES (?, ?)
        """, (session["user_id"], title))

        conversation_id = cursor.lastrowid

    return jsonify({
        "success": True,
        "conversation": {
            "id": conversation_id,
            "title": title
        }
    }), 201


# ---------------- LIST CHAT HISTORY ----------------

@app.route("/api/conversations", methods=["GET"])
@login_required
def list_conversations():

    with get_db() as db:
        rows = db.execute("""
            SELECT id, title, created_at
            FROM conversations
            WHERE user_id = ?
            ORDER BY id DESC
        """, (session["user_id"],)).fetchall()

    conversations = [
        {
            "id": row["id"],
            "title": row["title"],
            "created_at": row["created_at"]
        }
        for row in rows
    ]

    return jsonify({
        "success": True,
        "conversations": conversations
    })


# ---------------- SAVE CHAT MESSAGE ----------------

@app.route(
    "/api/conversations/<int:conversation_id>/messages",
    methods=["POST"]
)
@login_required
def save_message(conversation_id):

    data = get_json()

    role = str(data.get("role", ""))
    content = str(data.get("content", "")).strip()

    if role not in ("user", "assistant"):
        return jsonify({
            "success": False,
            "error": "Invalid message role."
        }), 400

    if not content:
        return jsonify({
            "success": False,
            "error": "Message cannot be empty."
        }), 400

    if len(content) > 50000:
        return jsonify({
            "success": False,
            "error": "Message is too long."
        }), 400

    with get_db() as db:

        conversation = get_owned_conversation(
            db, conversation_id
        )

        if conversation is None:
            return jsonify({
                "success": False,
                "error": "Conversation not found."
            }), 404

        db.execute("""
            INSERT INTO messages (
                conversation_id,
                role,
                content
            )
            VALUES (?, ?, ?)
        """, (conversation_id, role, content))

        # Use the first user message as the chat title.
        if role == "user" and conversation["title"] == "New Chat":
            db.execute("""
                UPDATE conversations
                SET title = ?
                WHERE id = ? AND user_id = ?
            """, (
                content[:60],
                conversation_id,
                session["user_id"]
            ))

    return jsonify({
        "success": True,
        "message": "Message saved."
    }), 201


# ---------------- OPEN CHAT HISTORY ----------------

@app.route(
    "/api/conversations/<int:conversation_id>/messages",
    methods=["GET"]
)
@login_required
def get_messages(conversation_id):

    with get_db() as db:

        conversation = get_owned_conversation(
            db, conversation_id
        )

        if conversation is None:
            return jsonify({
                "success": False,
                "error": "Conversation not found."
            }), 404

        rows = db.execute("""
            SELECT id, role, content, created_at
            FROM messages
            WHERE conversation_id = ?
            ORDER BY id ASC
        """, (conversation_id,)).fetchall()

    messages = [
        {
            "id": row["id"],
            "role": row["role"],
            "content": row["content"],
            "created_at": row["created_at"]
        }
        for row in rows
    ]

    return jsonify({
        "success": True,
        "conversation": {
            "id": conversation["id"],
            "title": conversation["title"]
        },
        "messages": messages
    })


# ---------------- DELETE CHAT ----------------

@app.route(
    "/api/conversations/<int:conversation_id>",
    methods=["DELETE"]
)
@login_required
def delete_conversation(conversation_id):

    with get_db() as db:

        cursor = db.execute("""
            DELETE FROM conversations
            WHERE id = ? AND user_id = ?
        """, (conversation_id, session["user_id"]))

        if cursor.rowcount == 0:
            return jsonify({
                "success": False,
                "error": "Conversation not found."
            }), 404

    return jsonify({
        "success": True,
        "message": "Conversation deleted."
    })


# ---------------- START SERVER ----------------

init_db()

if __name__ == "__main__":
    app.run(debug=True)
