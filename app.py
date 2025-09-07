# app.py
import os
import json
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

# --- Initial Setup & Configuration ---
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')

# Load encryption key and initialize Fernet
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY').encode()
fernet = Fernet(ENCRYPTION_KEY)

# Load and hash the dashboard password
DASHBOARD_PASSWORD = os.getenv('DASHBOARD_PASSWORD')
DASHBOARD_PASSWORD_HASH = generate_password_hash(DASHBOARD_PASSWORD)

DATA_DIR = 'data'
API_KEYS_FILE = 'api_keys.json'

# --- Helper Functions ---
def get_env_path(namespace, environment):
    return os.path.join(DATA_DIR, namespace, f"{environment}.enc")

def load_api_keys():
    if not os.path.exists(API_KEYS_FILE): return {}
    with open(API_KEYS_FILE, 'r') as f: return json.load(f)

def read_vars(namespace, environment):
    path = get_env_path(namespace, environment)
    if not os.path.exists(path): return {}
    with open(path, 'rb') as f: encrypted_data = f.read()
    try:
        decrypted_data = fernet.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode())
    except InvalidToken:
        return {"error": "Decryption failed. Invalid key or corrupted data."}

def write_vars(namespace, environment, data):
    path = get_env_path(namespace, environment)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    json_data = json.dumps(data).encode()
    encrypted_data = fernet.encrypt(json_data)
    with open(path, 'wb') as f: f.write(encrypted_data)

# --- Web Dashboard Routes ---
@app.route('/<namespace>/<environment>', methods=['GET', 'POST'])
def dashboard(namespace, environment):
    session_key = f'{namespace}_{environment}_authed'
    if request.method == 'POST':
        password = request.form.get('password')
        if password and check_password_hash(DASHBOARD_PASSWORD_HASH, password):
            session[session_key] = True
            return redirect(url_for('dashboard', namespace=namespace, environment=environment))
        else:
            flash('Invalid password.')
    if not session.get(session_key):
        return render_template('login.html', namespace=namespace, environment=environment)
    variables = read_vars(namespace, environment)
    return render_template('dashboard.html', namespace=namespace, environment=environment, variables=variables)

@app.route('/add/<namespace>/<environment>', methods=['POST'])
def add_variable(namespace, environment):
    session_key = f'{namespace}_{environment}_authed'
    if not session.get(session_key):
        return redirect(url_for('dashboard', namespace=namespace, environment=environment))
    key = request.form.get('key')
    value = request.form.get('value')
    if not key or not value: flash('Key and Value are required.')
    else:
        variables = read_vars(namespace, environment)
        variables[key] = value
        write_vars(namespace, environment, variables)
        flash(f'Variable "{key}" added successfully.')
    return redirect(url_for('dashboard', namespace=namespace, environment=environment))

@app.route('/delete/<namespace>/<environment>', methods=['POST'])
def delete_variable(namespace, environment):
    session_key = f'{namespace}_{environment}_authed'
    if not session.get(session_key):
        return redirect(url_for('dashboard', namespace=namespace, environment=environment))
    key_to_delete = request.form.get('key_to_delete')
    if key_to_delete:
        variables = read_vars(namespace, environment)
        if key_to_delete in variables:
            del variables[key_to_delete]
            write_vars(namespace, environment, variables)
            flash(f'Variable "{key_to_delete}" deleted.')
    return redirect(url_for('dashboard', namespace=namespace, environment=environment))

@app.route('/logout/<namespace>/<environment>')
def logout(namespace, environment):
    session_key = f'{namespace}_{environment}_authed'
    session.pop(session_key, None)
    return redirect(url_for('dashboard', namespace=namespace, environment=environment))

# --- API Route ---
@app.route('/api/v1/<namespace>/<environment>')
def api_get_env(namespace, environment):
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "Authorization header missing or invalid"}), 401
    token = auth_header.split(' ')[1]
    api_keys = load_api_keys()
    if api_keys.get(namespace) != token:
        return jsonify({"error": "Invalid API Key for this namespace"}), 403
    variables = read_vars(namespace, environment)
    if "error" in variables: return jsonify(variables), 500
    return jsonify(variables)

if __name__ == '__main__':
    app.run(debug=False, port=8070)
