import os
import sqlite3
import json
from flask import Flask, request, jsonify, session, send_from_directory
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_session import Session
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'byd-business-secret-key-12345'
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)
bcrypt = Bcrypt(app)
CORS(app, supports_credentials=True)

DB_PATH = 'database.db'

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    
    # Profiles table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            user_id INTEGER PRIMARY KEY,
            config TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Operations table (Gains/Costs)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS operations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            value REAL,
            type TEXT,
            date TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Recharges table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS recharges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            value REAL,
            km INTEGER,
            date TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()

# Ensure DB is initialized
init_db()

# --- Auth Routes ---

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'error': 'Email e senha são obrigatórios'}), 400
    
    pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    conn = get_db_connection()
    try:
        conn.execute('INSERT INTO users (email, password_hash) VALUES (?, ?)', (email, pw_hash))
        conn.commit()
        return jsonify({'message': 'Usuário registrado com sucesso'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Email já cadastrado'}), 400
    finally:
        conn.close()

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()
    
    if user and bcrypt.check_password_hash(user['password_hash'], password):
        session['user_id'] = user['id']
        session['email'] = user['email']
        return jsonify({
            'user': {
                'id': user['id'],
                'email': user['email']
            }
        }), 200
    
    return jsonify({'error': 'Credenciais inválidas'}), 401

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Sessão encerrada'}), 200

@app.route('/api/auth/me', methods=['GET'])
def me():
    if 'user_id' not in session:
        return jsonify({'user': None}), 200
    return jsonify({
        'user': {
            'id': session['user_id'],
            'email': session['email']
        }
    }), 200

# --- Data Routes ---

@app.route('/api/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return jsonify({'error': 'Não autorizado'}), 401
    
    user_id = session['user_id']
    conn = get_db_connection()
    
    if request.method == 'POST':
        config = json.dumps(request.json.get('config', {}))
        conn.execute('INSERT OR REPLACE INTO profiles (user_id, config) VALUES (?, ?)', (user_id, config))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Perfil salvo'}), 200
    else:
        profile = conn.execute('SELECT config FROM profiles WHERE user_id = ?', (user_id,)).fetchone()
        conn.close()
        config = json.loads(profile['config']) if profile and profile['config'] else {}
        return jsonify({'config': config}), 200

@app.route('/api/operations', methods=['GET', 'POST', 'DELETE'])
def operations():
    if 'user_id' not in session:
        return jsonify({'error': 'Não autorizado'}), 401
    
    user_id = session['user_id']
    conn = get_db_connection()
    
    if request.method == 'POST':
        data = request.json
        conn.execute('INSERT INTO operations (user_id, value, type, date) VALUES (?, ?, ?, ?)',
                     (user_id, data['value'], data['type'], data['date']))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Operação salva'}), 201
    elif request.method == 'DELETE':
        conn.execute('DELETE FROM operations WHERE user_id = ?', (user_id,))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Operações removidas'}), 200
    else:
        rows = conn.execute('SELECT * FROM operations WHERE user_id = ? ORDER BY created_at DESC', (user_id,)).fetchall()
        conn.close()
        return jsonify([dict(row) for row in rows]), 200

@app.route('/api/recharges', methods=['GET', 'POST', 'DELETE'])
def recharges():
    if 'user_id' not in session:
        return jsonify({'error': 'Não autorizado'}), 401
    
    user_id = session['user_id']
    conn = get_db_connection()
    
    if request.method == 'POST':
        data = request.json
        conn.execute('INSERT INTO recharges (user_id, value, km, date) VALUES (?, ?, ?, ?)',
                     (user_id, data['value'], data['km'], data['date']))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Recarga salva'}), 201
    elif request.method == 'DELETE':
        conn.execute('DELETE FROM recharges WHERE user_id = ?', (user_id,))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Recargas removidas'}), 200
    else:
        rows = conn.execute('SELECT * FROM recharges WHERE user_id = ? ORDER BY created_at DESC', (user_id,)).fetchall()
        conn.close()
        return jsonify([dict(row) for row in rows]), 200

# --- Serve Static Files ---

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def static_proxy(path):
    return send_from_directory('.', path)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
