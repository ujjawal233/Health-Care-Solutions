from flask import Flask, render_template, request, redirect, session, flash, url_for, abort
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
from email.mime.text import MIMEText
import os
import datetime
import logging
import re
import secrets
from markupsafe import Markup

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

try:
    from flask_dance.contrib.google import make_google_blueprint, google
except Exception:
    make_google_blueprint = None
    google = None


# ---------------- Configuration ----------------
EMAIL_HOST = os.getenv('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', '587'))
EMAIL_HOST_USER = os.getenv('EMAIL_USER')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_PASSWORD')
DEFAULT_ADMIN_PASSWORD = os.getenv('DEFAULT_ADMIN_PASSWORD', 'ChangeMe123!')
DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'healthcare.db')


# ---------------- App & Logging ----------------
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY') or os.urandom(24)

# Session cookie hardening (can be relaxed in non-HTTPS dev environments via APP_ENV)
if os.getenv('APP_ENV') == 'production':
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_SAMESITE='Lax'
    )

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger('healthcare')


# ===================================================
# Function: get_db_connection
# Purpose: Centralize creation of sqlite3 connections with sane defaults.
# Parameters: None
# Returns: sqlite3.Connection
# ===================================================
def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    try:
        # improve concurrency and durability in multi-request environments
        conn.execute('PRAGMA journal_mode = WAL')
        conn.execute('PRAGMA foreign_keys = ON')
    except Exception:
        # older sqlite builds may not support PRAGMAs; fail silently
        pass
    return conn


# ===================================================
# CSRF helpers
# ===================================================
@app.context_processor
def inject_csrf():
    def csrf_token():
        token = session.get('_csrf_token')
        if not token:
            token = secrets.token_urlsafe(32)
            session['_csrf_token'] = token
        return token

    def csrf_input():
        return Markup(f"<input type=\"hidden\" name=\"_csrf_token\" value=\"{csrf_token()}\">")

    return dict(csrf_token=csrf_token, csrf_input=csrf_input)


@app.before_request
def validate_csrf():
    # skip safe methods
    if request.method in ('GET', 'HEAD', 'OPTIONS'):
        return

    # Skip CSRF for OAuth callbacks
    if request.path.startswith('/login') and 'google' in request.path:
        return

    token = request.form.get('_csrf_token') or request.headers.get('X-CSRFToken')
    if not token or token != session.get('_csrf_token'):
        abort(400, description='Bad or missing CSRF token')


# ===================================================
# Function: query_db
# Purpose: Helper to run a SELECT query and return rows.
# Parameters: sql (str), params (tuple), one (bool)
# Returns: list[sqlite3.Row] or single Row
# ===================================================
def query_db(sql, params=(), one=False):
    conn = get_db_connection()
    try:
        cur = conn.execute(sql, params)
        rows = cur.fetchall()
        return (rows[0] if rows else None) if one else rows
    finally:
        conn.close()


# ===================================================
# Function: execute_db
# Purpose: Helper to run INSERT/UPDATE/DELETE with parameters.
# Parameters: sql (str), params (tuple)
# Returns: lastrowid, rowcount
# ===================================================
def execute_db(sql, params=()):
    conn = get_db_connection()
    try:
        cur = conn.execute(sql, params)
        conn.commit()
        return cur.lastrowid, cur.rowcount
    finally:
        conn.close()


# ===================================================
# Function: validate_email
# Purpose: Basic email format validation.
# Parameters: email (str)
# Returns: bool
# ===================================================
def validate_email(email: str) -> bool:
    if not email or len(email) > 254:
        return False
    pattern = r'^[\w\.-]+@[\w\.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


# ===================================================
# Function: send_email
# Purpose: Send a plain-text email using configured SMTP credentials.
# Parameters: to_address (str), subject (str), body (str)
# Returns: None but raises exceptions on failure
# ===================================================
def send_email(to_address: str, subject: str, body: str):
    if not EMAIL_HOST_USER or not EMAIL_HOST_PASSWORD:
        logger.warning('Email credentials not configured; skipping send_email')
        raise RuntimeError('Email server not configured')

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_HOST_USER
    msg['To'] = to_address

    server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT, timeout=10)
    server.starttls()
    server.login(EMAIL_HOST_USER, EMAIL_HOST_PASSWORD)
    server.send_message(msg)
    server.quit()
    logger.info('Sent email to %s', to_address)


# ===================================================
# Function: init_db
# Purpose: Create tables and migrate schema while preserving data.
# Parameters: None
# Returns: None
# ===================================================
def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('''
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT,
                hospital TEXT,
                role TEXT DEFAULT 'hospital'
            )
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS doctor_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                doctor_id INTEGER,
                doctor_name TEXT,
                doctor_hospital TEXT,
                action TEXT,
                admin_username TEXT,
                timestamp TEXT
            )
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS doctors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                specialization TEXT,
                location TEXT,
                hospital TEXT,
                email TEXT UNIQUE,
                password TEXT,
                is_active INTEGER DEFAULT 1
            )
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS appointments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                email TEXT,
                doctor TEXT,
                doctor_hospital TEXT,
                date TEXT,
                location TEXT
            )
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE,
                password TEXT
            )
        ''')

        # useful indexes for performance
        cur.execute('CREATE INDEX IF NOT EXISTS idx_doctors_name ON doctors(name)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_appointments_doctor ON appointments(doctor)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_appointments_date ON appointments(date)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_appointments_hospital ON appointments(doctor_hospital)')

        # ensure default super admin exists
        cur.execute("SELECT id FROM admins WHERE username=?", ('admin',))
        if not cur.fetchone():
            hashed = generate_password_hash(DEFAULT_ADMIN_PASSWORD)
            cur.execute("INSERT INTO admins (username,password,hospital,role) VALUES (?,?,?,?)",
                        ('admin', hashed, 'Default Hospital', 'super'))

        conn.commit()
    except Exception as e:
        logger.exception('init_db failed: %s', e)
        raise
    finally:
        conn.close()


# Ensure DB schema exists before any request
@app.before_request
def _ensure_db_initialized():
    init_db()


# ===================================================
# Route: /
# Purpose: Home page listing active doctors and specializations.
# Parameters: None
# Returns: Render index.html
# ===================================================
@app.route('/')
def home():
    rows = query_db("SELECT name, specialization, location FROM doctors WHERE is_active=1")
    doctors = [(r['name'], r['specialization'], r['location']) for r in rows]

    # unique specializations in insertion order
    specializations = []
    for _, spec, _ in doctors:
        if spec not in specializations:
            specializations.append(spec)

    return render_template('index.html', doctors=doctors, specializations=specializations)


# ===================================================
# Route: /book
# Purpose: Create a new appointment booking for a patient.
# Parameters: form fields `name`, `email`, `doctor`, `date`, `location`
# Returns: Redirect to home with flash messages indicating success/failure
# ===================================================
@app.route('/book', methods=['POST'])
def book():
    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip()
    doctor = request.form.get('doctor', '').strip()
    date = request.form.get('date', '').strip()
    location = request.form.get('location', '').strip()

    # basic validations
    if not all([name, email, doctor, date, location]):
        flash('Please fill all booking fields and select a doctor.')
        return redirect('/')

    if not validate_email(email):
        flash('Please provide a valid email address.')
        return redirect('/')

    try:
        appointment_date = datetime.date.fromisoformat(date)
    except Exception:
        flash('Please select a valid appointment date.')
        return redirect('/')

    if appointment_date < datetime.date.today():
        flash('Cannot book appointments in the past.')
        return redirect('/')

    # determine doctor hospital
    row = query_db('SELECT hospital FROM doctors WHERE name=? AND is_active=1', (doctor,), one=True)
    if not row:
        flash('Selected doctor is not available. Please choose a valid doctor.')
        return redirect('/')

    doctor_hospital = row['hospital']

    # prevent duplicate booking
    dup = query_db('SELECT id FROM appointments WHERE email=? AND doctor=? AND date=?', (email, doctor, date), one=True)
    if dup:
        flash('Appointment already exists for this doctor and date.')
        return redirect('/')

    try:
        execute_db('INSERT INTO appointments (name,email,doctor,doctor_hospital,date,location) VALUES (?,?,?,?,?,?)',
                   (name, email, doctor, doctor_hospital, date, location))

        # send confirmation email (best-effort)
        subject = 'Appointment Confirmation'
        body = f"Dear {name},\n\nYour appointment with Dr. {doctor} on {date} has been booked successfully.\n\nThank you for choosing HealthCare+.\n"
        try:
            send_email(email, subject, body)
            flash('Appointment Booked Successfully! Confirmation email sent.')
        except Exception as e:
            logger.warning('Email send failed: %s', e)
            flash('Appointment Booked Successfully! Could not send confirmation email.')
    except Exception as e:
        logger.exception('Failed to insert appointment: %s', e)
        flash('Failed to book appointment. Please try again later.')

    return redirect('/')


# ===================================================
# Route: /login
# Purpose: Authenticate an admin user and establish admin session context.
# Parameters: form fields `username`, `password` (POST)
# Returns: Redirect to `/dashboard` on success or render login template
# ===================================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash('Missing credentials')
            return render_template('login.html')

        row = query_db('SELECT password,hospital,role FROM admins WHERE username=?', (username,), one=True)
        if row and row['password'] and check_password_hash(row['password'], password):
            session['admin'] = username
            session['hospital'] = row['hospital']
            session['admin_role'] = row['role'] or 'hospital'
            logger.info('Admin logged in: %s', username)
            return redirect('/dashboard')
        else:
            flash('Invalid Credentials')

    return render_template('login.html')


# ===================================================
# Route: /admin_register
# Purpose: Allow super-admin to create new admin accounts for hospitals.
# Parameters: form fields `username`, `password`, `role`, optional `hospital`
# Returns: Redirect to `/dashboard` after creating admin
# ===================================================
@app.route('/admin_register', methods=['GET', 'POST'])
def admin_register():
    if 'admin' not in session or session.get('admin_role') != 'super':
        return redirect('/login')

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        role = request.form.get('role', 'hospital')
        hospital = request.form.get('hospital', '').strip()

        if role == 'hospital' and not hospital:
            flash('Hospital is required for hospital admins')
            return redirect('/admin_register')

        if not username or not password:
            flash('Username and password are required')
            return redirect('/admin_register')

        hashed = generate_password_hash(password)
        try:
            execute_db('INSERT OR IGNORE INTO admins (username,password,hospital,role) VALUES (?,?,?,?)',
                       (username, hashed, hospital, role))
            flash(f'New {role} admin created for hospital: {hospital or "N/A"}')
            logger.info('Admin created: %s by %s', username, session.get('admin'))
            return redirect('/dashboard')
        except Exception as e:
            logger.exception('Failed to create admin: %s', e)
            flash('Failed to create admin')

    return render_template('admin_register.html')


# ===================================================
# Route: /doctor_login
# Purpose: Authenticate a doctor by email/password and set session info.
# Parameters: form fields `email`, `password` (POST)
# Returns: Redirect to `/doctor_dashboard` on success or render form
# ===================================================
@app.route('/doctor_login', methods=['GET', 'POST'])
def doctor_login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        if not validate_email(email):
            flash('Invalid email')
            return render_template('doctor_login.html')

        row = query_db('SELECT name,password,hospital FROM doctors WHERE email=? AND is_active=1', (email,), one=True)
        if row and row['password'] and check_password_hash(row['password'], password):
            session['doctor'] = email
            session['doctor_name'] = row['name']
            session['doctor_hospital'] = row['hospital']
            logger.info('Doctor logged in: %s', email)
            return redirect('/doctor_dashboard')
        else:
            flash('Invalid doctor credentials')

    return render_template('doctor_login.html')


# ===================================================
# Route: /doctor_reset
# Purpose: Allow doctors to reset their password by email.
# Parameters: form fields `email`, `password` (POST)
# Returns: Redirect to `/doctor_login` with status flash
# ===================================================
@app.route('/doctor_reset', methods=['GET', 'POST'])
def doctor_reset():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        if not validate_email(email):
            flash('Invalid email')
            return redirect('/doctor_reset')

        row = query_db('SELECT id FROM doctors WHERE email=?', (email,), one=True)
        if row:
            hashed = generate_password_hash(password)
            try:
                execute_db('UPDATE doctors SET password=? WHERE email=?', (hashed, email))
                flash('Password reset successfully')
            except Exception as e:
                logger.exception('Failed to reset doctor password: %s', e)
                flash('Failed to reset password')
        else:
            flash('No doctor found with that email')
        return redirect('/doctor_login')

    return render_template('doctor_reset.html')


# ===================================================
# Route: /doctor_dashboard
# Purpose: Show authenticated doctor's appointments and context.
# Parameters: Session `doctor`, `doctor_name`, `doctor_hospital`
# Returns: Render `doctor_dashboard.html` with appointment list
# ===================================================
@app.route('/doctor_dashboard')
def doctor_dashboard():
    if 'doctor' not in session:
        return redirect('/doctor_login')

    doctor_name = session.get('doctor_name')
    doctor_hospital = session.get('doctor_hospital')

    rows = query_db('''
        SELECT id, name, email, doctor, date, location, doctor_hospital
        FROM appointments
        WHERE doctor=? AND doctor_hospital=?
        ORDER BY date DESC
    ''', (doctor_name, doctor_hospital))

    appointments = [tuple(r) for r in rows]
    return render_template('doctor_dashboard.html', doctor_name=doctor_name, doctor_hospital=doctor_hospital, appointments=appointments)


# ===================================================
# Route: /doctor_cancel/<id>
# Purpose: Allow doctor to cancel their own appointment by id.
# Parameters: `id` (int) path parameter
# Returns: Redirect to `/doctor_dashboard`
# ===================================================
@app.route('/doctor_cancel/<int:id>', methods=['GET', 'POST'])
def doctor_cancel(id):
    if 'doctor' not in session:
        return redirect('/doctor_login')

    row = query_db('SELECT doctor, doctor_hospital FROM appointments WHERE id=?', (id,), one=True)
    if row and row['doctor'] == session.get('doctor_name') and row['doctor_hospital'] == session.get('doctor_hospital'):
        try:
            execute_db('DELETE FROM appointments WHERE id=?', (id,))
            logger.info('Appointment %s cancelled by doctor %s', id, session.get('doctor'))
        except Exception as e:
            logger.exception('Failed to cancel appointment: %s', e)

    return redirect('/doctor_dashboard')


# ===================================================
# Route: /doctor_edit/<id>
# Purpose: Allow doctor to edit their appointment's date/location.
# Parameters: `id` (int), form `date`, `location` (POST)
# Returns: Render edit form (GET) or redirect to `/doctor_dashboard` (POST)
# ===================================================
@app.route('/doctor_edit/<int:id>', methods=['GET', 'POST'])
def doctor_edit(id):
    if 'doctor' not in session:
        return redirect('/doctor_login')

    appt = query_db('SELECT id, name, email, doctor, date, location, doctor_hospital FROM appointments WHERE id=?', (id,), one=True)
    if not appt or appt['doctor'] != session.get('doctor_name') or appt['doctor_hospital'] != session.get('doctor_hospital'):
        return redirect('/doctor_dashboard')

    if request.method == 'POST':
        new_date = request.form.get('date', '').strip()
        new_location = request.form.get('location', '').strip()
        try:
            # validate date
            datetime.date.fromisoformat(new_date)
            execute_db('UPDATE appointments SET date=?, location=? WHERE id=?', (new_date, new_location, id))
            logger.info('Appointment %s updated by doctor %s', id, session.get('doctor'))
        except Exception as e:
            logger.exception('Failed to update appointment: %s', e)
            flash('Failed to update appointment')
        return redirect('/doctor_dashboard')

    # convert to tuple to keep compatibility with templates expecting indices
    appointment = tuple(appt)
    return render_template('doctor_edit.html', appointment=appointment)


# ===================================================
# Route: /user_login
# Purpose: Authenticate or register a patient user via email/password.
# Parameters: form fields `email`, `password` (POST)
# Returns: Redirect to home on success or render login page
# ===================================================
@app.route('/user_login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        if not validate_email(email):
            flash('Invalid email')
            return render_template('user_login.html', google_signin_available=(make_google_blueprint is not None))

        row = query_db('SELECT password FROM users WHERE email=?', (email,), one=True)
        if row:
            if row['password'] and check_password_hash(row['password'], password):
                session['user'] = email
                return redirect('/')
            else:
                flash('Invalid username or password')
        else:
            # register new user
            hashed = generate_password_hash(password)
            try:
                execute_db('INSERT INTO users (email,password) VALUES (?,?)', (email, hashed))
                session['user'] = email
                flash('Account created and logged in')
                return redirect('/')
            except Exception as e:
                logger.exception('Failed to register user: %s', e)
                flash('Registration failed')

    return render_template('user_login.html', google_signin_available=(make_google_blueprint is not None))


# ===================================================
# Route: /logout
# Purpose: Clear session context for all user roles.
# Parameters: None
# Returns: Redirect to home `/`
# ===================================================
@app.route('/logout')
def logout():
    keys = ['admin', 'user', 'doctor', 'doctor_name', 'doctor_hospital', 'hospital']
    for k in keys:
        session.pop(k, None)
    return redirect('/')


# ===================================================
# Route: /google_login
# Purpose: Handle OAuth callback for Google sign-in (Flask-Dance).
# Parameters: None (uses Flask-Dance internals)
# Returns: Redirects to home on success or `/user_login` on failure
# ===================================================
@app.route('/google_login')
def google_login():
    if make_google_blueprint is None or google is None:
        flash('Google OAuth not configured on the server (missing Flask-Dance).')
        return redirect('/user_login')

    if not google.authorized:
        return redirect(url_for('google.login'))

    resp = google.get('/oauth2/v2/userinfo')
    if not resp.ok:
        flash('Failed to fetch user info from Google.')
        return redirect('/user_login')

    info = resp.json()
    email = info.get('email')
    if email:
        row = query_db('SELECT id FROM users WHERE email=?', (email,), one=True)
        if not row:
            execute_db('INSERT INTO users (email,password) VALUES (?,?)', (email, 'google-oauth'))
        session['user'] = email
        flash('Logged in with Google: ' + email)
        return redirect('/')

    flash('Google login failed.')
    return redirect('/user_login')


# ===================================================
# Route: /dashboard
# Purpose: Admin dashboard showing counts and appointment lists per role.
# Parameters: Session `admin`, `admin_role`, `hospital`
# Returns: Render `dashboard.html` with aggregated data
# ===================================================
@app.route('/dashboard')
def dashboard():
    if 'admin' not in session:
        return redirect('/login')

    if session.get('admin_role') == 'super':
        total_appointments = query_db('SELECT COUNT(*) as cnt FROM appointments', (), one=True)['cnt']
        total_doctors = query_db('SELECT COUNT(*) as cnt FROM doctors', (), one=True)['cnt']
        appointments = query_db('''
            SELECT a.id, a.name, a.email, a.doctor, a.date, a.location, d.specialization
            FROM appointments a
            LEFT JOIN doctors d ON a.doctor = d.name
        ''')
    else:
        hospital = session.get('hospital')
        total_appointments = query_db('SELECT COUNT(*) as cnt FROM appointments WHERE doctor_hospital=?', (hospital,), one=True)['cnt']
        total_doctors = query_db('SELECT COUNT(*) as cnt FROM doctors WHERE hospital=?', (hospital,), one=True)['cnt']
        appointments = query_db('''
            SELECT a.id, a.name, a.email, a.doctor, a.date, a.location, d.specialization
            FROM appointments a
            LEFT JOIN doctors d ON a.doctor = d.name
            WHERE a.doctor_hospital = ?
        ''', (hospital,))

    hospital_report = query_db('''
        SELECT doctor_hospital, COUNT(*) as cnt
        FROM appointments
        GROUP BY doctor_hospital
    ''') if session.get('admin_role') == 'super' else query_db('''
        SELECT doctor_hospital, COUNT(*) as cnt
        FROM appointments
        WHERE doctor_hospital = ?
        GROUP BY doctor_hospital
    ''', (session.get('hospital'),))

    appointments = [tuple(a) for a in appointments]
    hospital_report = [tuple(h) for h in hospital_report]

    return render_template('dashboard.html', total_appointments=total_appointments, total_doctors=total_doctors, appointments=appointments, hospital_report=hospital_report)


# ===================================================
# Route: /delete/<id>
# Purpose: Allow admin to delete an appointment by id (POST only).
# Parameters: `id` (int)
# Returns: Redirect to `/dashboard`
# ===================================================
@app.route('/delete/<int:id>', methods=['POST'])
def delete(id):
    if 'admin' not in session:
        return redirect('/login')
    try:
        execute_db('DELETE FROM appointments WHERE id=?', (id,))
        logger.info('Appointment %s deleted by admin %s', id, session.get('admin'))
    except Exception as e:
        logger.exception('Failed to delete appointment: %s', e)
    return redirect('/dashboard')


# ===================================================
# Route: /delete_doctor/<id>
# Purpose: Soft-delete a doctor (mark inactive) by id.
# Parameters: `id` (int)
# Returns: Redirect to `/doctors`
# ===================================================
@app.route('/delete_doctor/<int:id>', methods=['GET', 'POST'])
def delete_doctor(id):
    if 'admin' not in session:
        return redirect('/login')
    # ensure admin belongs to same hospital unless super
    doctor = query_db('SELECT hospital FROM doctors WHERE id=?', (id,), one=True)
    if not doctor:
        flash('Doctor not found')
        return redirect('/doctors')

    if session.get('admin_role') != 'super' and doctor['hospital'] != session.get('hospital'):
        flash('Not authorized to delete this doctor')
        return redirect('/doctors')

    try:
        execute_db('UPDATE doctors SET is_active=0 WHERE id=?', (id,))
        logger.info('Doctor %s soft-deleted by admin %s', id, session.get('admin'))
    except Exception as e:
        logger.exception('Failed to soft-delete doctor: %s', e)

    return redirect('/doctors')


# ===================================================
# Route: /doctors_all
# Purpose: Admin-only view to list all doctors across hospitals.
# Parameters: None
# Returns: Render `doctors.html` with full doctor list
# ===================================================
@app.route('/doctors_all')
def doctors_all():
    if 'admin' not in session:
        return redirect('/login')
    data = query_db('SELECT * FROM doctors')
    # convert to tuples for template compatibility
    doctors = [tuple(d) for d in data]
    return render_template('doctors.html', doctors=doctors, audit=[])


# ===================================================
# Route: /restore_doctor/<id>
# Purpose: Restore a soft-deleted doctor (set active) by id.
# Parameters: `id` (int)
# Returns: Redirect to `/doctors`
# ===================================================
@app.route('/restore_doctor/<int:id>', methods=['GET', 'POST'])
def restore_doctor(id):
    if 'admin' not in session:
        return redirect('/login')
    try:
        execute_db('UPDATE doctors SET is_active=1 WHERE id=?', (id,))
        logger.info('Doctor %s restored by admin %s', id, session.get('admin'))
    except Exception as e:
        logger.exception('Failed to restore doctor: %s', e)
    return redirect('/doctors')


# ===================================================
# Route: /purge_doctor/<id>
# Purpose: Permanently delete a doctor and their appointments, with audit.
# Parameters: `id` (int)
# Returns: Redirect to `/doctors`
# ===================================================
@app.route('/purge_doctor/<int:id>', methods=['GET', 'POST'])
def purge_doctor(id):
    if 'admin' not in session:
        return redirect('/login')

    doctor_row = query_db('SELECT name, hospital FROM doctors WHERE id=?', (id,), one=True)
    if not doctor_row:
        flash('Doctor not found')
        return redirect('/doctors')

    if session.get('admin_role') != 'super' and doctor_row['hospital'] != session.get('hospital'):
        flash('Not authorized to purge this doctor')
        return redirect('/doctors')

    try:
        # delete related appointments first for referential clarity
        execute_db('DELETE FROM appointments WHERE doctor=?', (doctor_row['name'],))
        execute_db('DELETE FROM doctors WHERE id=?', (id,))
        execute_db('INSERT INTO doctor_audit (doctor_id, doctor_name, doctor_hospital, action, admin_username, timestamp) VALUES (?,?,?,?,?,?)',
                   (id, doctor_row['name'], doctor_row['hospital'], 'purge', session.get('admin'), datetime.datetime.utcnow().isoformat()))
        logger.info('Doctor %s purged by admin %s', id, session.get('admin'))
    except Exception as e:
        logger.exception('Failed to purge doctor: %s', e)
        flash('Failed to purge doctor')

    return redirect('/doctors')


# ===================================================
# Route: /doctors
# Purpose: Manage doctors for the admin's hospital; supports create and list.
# Parameters: form fields for creating doctor (POST)
# Returns: Render `doctors.html` with hospital-specific doctors and audit
# ===================================================
@app.route('/doctors', methods=['GET', 'POST'])
def doctors():
    if 'admin' not in session:
        return redirect('/login')

    if request.method == 'POST':
        hospital = session.get('hospital', 'Default Hospital')
        if session.get('admin_role') == 'super':
            hospital = request.form.get('hospital', hospital).strip() or hospital

        name = request.form.get('name', '').strip()
        specialization = request.form.get('specialization', '').strip()
        location = request.form.get('location', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        if not all([name, specialization, email, password]):
            flash('Please fill all required doctor fields')
            return redirect('/doctors')

        if not validate_email(email):
            flash('Invalid doctor email')
            return redirect('/doctors')

        hashed = generate_password_hash(password)
        try:
            execute_db('INSERT INTO doctors (name,specialization,location,hospital,email,password) VALUES (?,?,?,?,?,?)',
                       (name, specialization, location, hospital, email, hashed))
            logger.info('Doctor added: %s by admin %s', name, session.get('admin'))
        except sqlite3.IntegrityError as e:
            logger.warning('Doctor insert integrity error: %s', e)
            flash('Failed to add doctor: email may already exist')
        except Exception as e:
            logger.exception('Failed to add doctor: %s', e)
            flash('Failed to add doctor')

        return redirect('/doctors')

    # GET -> list doctors for this admin's hospital
    hospital = session.get('hospital')
    data = query_db('SELECT * FROM doctors WHERE hospital=?', (hospital,))
    audit = query_db('SELECT id, doctor_id, doctor_name, action, admin_username, timestamp FROM doctor_audit WHERE doctor_hospital=? ORDER BY timestamp DESC LIMIT 25', (hospital,))

    doctors = [tuple(d) for d in data]
    audit = [tuple(a) for a in audit]
    return render_template('doctors.html', doctors=doctors, audit=audit)


# ===================================================
# Error Handler: 404 Not Found
# Purpose: Provide a simple response for missing pages and log occurrence.
# Parameters: exception
# Returns: tuple (body, 404)
# ===================================================
@app.errorhandler(404)
def handle_404(err):
    logger.warning('404 Not Found: %s', request.path)
    return '404 Not Found', 404


# ===================================================
# Error Handler: 500 Internal Server Error
# Purpose: Log exception and return a safe generic message to clients.
# Parameters: exception
# Returns: tuple (body, 500)
# ===================================================
@app.errorhandler(500)
def handle_500(err):
    logger.exception('Internal server error: %s', err)
    return 'Internal Server Error', 500


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
