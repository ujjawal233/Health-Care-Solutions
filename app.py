from flask import Flask, render_template, request, redirect, session, flash, url_for, abort, send_file
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
from email.mime.text import MIMEText
import os
import datetime
import logging
import re
import secrets
import csv
import io
from markupsafe import Markup

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    from reportlab.lib.units import inch
except ImportError:
    letter = None
    canvas = None
    inch = None

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


EMAIL_HOST = os.getenv('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', '587'))
EMAIL_USE_TLS = os.getenv('EMAIL_USE_TLS', 'True').lower() in ('1', 'true', 'yes')
EMAIL_HOST_USER = os.getenv('EMAIL_USER')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_PASSWORD')
DEFAULT_ADMIN_PASSWORD = os.getenv('DEFAULT_ADMIN_PASSWORD', 'ChangeMe123!')
DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'healthcare.db')
GOOGLE_OAUTH_CLIENT_ID = os.getenv('GOOGLE_OAUTH_CLIENT_ID')
GOOGLE_OAUTH_CLIENT_SECRET = os.getenv('GOOGLE_OAUTH_CLIENT_SECRET')
APP_ENV = os.getenv('APP_ENV', 'development')

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY') or os.urandom(24)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(days=7),
    TEMPLATES_AUTO_RELOAD=(APP_ENV != 'production')
)
if APP_ENV == 'production':
    app.config['SESSION_COOKIE_SECURE'] = True

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger('healthcare')

GOOGLE_OAUTH_ENABLED = False
if make_google_blueprint and GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET:
    google_bp = make_google_blueprint(
        client_id=GOOGLE_OAUTH_CLIENT_ID,
        client_secret=GOOGLE_OAUTH_CLIENT_SECRET,
        scope=['openid', 'profile', 'email'],
        redirect_url='/google_login'
    )
    app.register_blueprint(google_bp, url_prefix='/login')
    GOOGLE_OAUTH_ENABLED = True


def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute('PRAGMA foreign_keys = ON')
        conn.execute('PRAGMA journal_mode = WAL')
        conn.execute('PRAGMA busy_timeout = 3000')
    except sqlite3.DatabaseError:
        pass
    return conn


def utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def to_iso(timestamp: datetime.datetime) -> str:
    return timestamp.astimezone(datetime.timezone.utc).isoformat()


def parse_iso_datetime(value: str) -> datetime.datetime:
    dt = datetime.datetime.fromisoformat(value)
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=datetime.timezone.utc)


def query_db(sql, params=(), one=False):
    with get_db_connection() as conn:
        cur = conn.execute(sql, params)
        rows = cur.fetchall()
        return (rows[0] if rows else None) if one else rows


def execute_db(sql, params=()):
    with get_db_connection() as conn:
        cur = conn.execute(sql, params)
        conn.commit()
        return cur.lastrowid, cur.rowcount


def record_audit(actor: str, role: str, action: str, target: str, ip_address: str = '', user_agent: str = ''):
    execute_db(
        'INSERT INTO audit_logs (actor, role, action, target, ip_address, user_agent, timestamp) VALUES (?,?,?,?,?,?,?)',
        (actor, role, action, target, ip_address, user_agent, to_iso(utcnow()))
    )


def get_notifications(recipient: str, recipient_role: str):
    rows = query_db(
        'SELECT id, recipient, recipient_role, message, is_read, created_at FROM notifications WHERE recipient=? AND recipient_role=? ORDER BY created_at DESC LIMIT 50',
        (recipient, recipient_role)
    )
    return [
        dict(id=r['id'], recipient=r['recipient'], recipient_role=r['recipient_role'], message=r['message'], is_read=r['is_read'], created_at=r['created_at'])
        for r in rows
    ]


def send_otp_for_verification(identity: str, role: str):
    otp = ''.join(str(secrets.randbelow(10)) for _ in range(6))
    expires_at = to_iso(utcnow() + datetime.timedelta(minutes=15))

    if role == 'patient':
        row = query_db('SELECT email FROM patients WHERE email=?', (identity,), one=True)
        table = 'patients'
        field = 'email'
    elif role == 'doctor':
        row = query_db('SELECT email FROM doctors WHERE email=?', (identity,), one=True)
        table = 'doctors'
        field = 'email'
    elif role == 'admin':
        row = query_db('SELECT email FROM admins WHERE username=?', (identity,), one=True)
        table = 'admins'
        field = 'username'
    else:
        raise RuntimeError('Unsupported verification role')

    if not row or not row['email']:
        raise RuntimeError('No valid email address found for OTP delivery')

    execute_db(f'UPDATE {table} SET otp_code=?, otp_expires=? WHERE {field}=?', (otp, expires_at, identity))
    send_email(row['email'], 'Your verification OTP', f'Your verification code is: {otp}\nThis code expires in 15 minutes.')


def validate_email(email: str) -> bool:
    if not email or len(email) > 254:
        return False
    pattern = r'^[\w\.-]+@[\w\.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def send_email(to_address: str, subject: str, body: str):
    if not EMAIL_HOST_USER or not EMAIL_HOST_PASSWORD:
        logger.warning('Missing SMTP credentials; email not sent to %s', to_address)
        raise RuntimeError('Email server not configured')

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_HOST_USER
    msg['To'] = to_address

    with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT, timeout=10) as server:
        if EMAIL_USE_TLS:
            server.starttls()
        server.login(EMAIL_HOST_USER, EMAIL_HOST_PASSWORD)
        server.send_message(msg)
    logger.info('Email sent to %s', to_address)


def create_pdf_prescription(patient_name: str, doctor_name: str, details: str) -> io.BytesIO:
    if canvas is None:
        raise RuntimeError('ReportLab is not installed')

    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    c.setFont('Helvetica-Bold', 18)
    c.drawString(1 * inch, 10 * inch, 'Prescription')
    c.setFont('Helvetica', 12)
    c.drawString(1 * inch, 9.4 * inch, f'Patient: {patient_name}')
    c.drawString(1 * inch, 9.0 * inch, f'Doctor: {doctor_name}')
    c.drawString(1 * inch, 8.6 * inch, f'Date: {datetime.date.today().isoformat()}')
    text = c.beginText(1 * inch, 8.2 * inch)
    text.setFont('Helvetica', 11)
    for line in details.splitlines():
        text.textLine(line)
    c.drawText(text)
    c.showPage()
    c.save()
    buffer.seek(0)
    return buffer


def get_table_columns(cur, table_name):
    cur.execute(f"PRAGMA table_info('{table_name}')")
    return [row[1] for row in cur.fetchall()]


def ensure_column(cur, table_name, column_name, column_definition):
    if column_name not in get_table_columns(cur, table_name):
        logger.info('Adding missing column %s.%s', table_name, column_name)
        definition = column_definition
        unique_index = None

        if 'UNIQUE' in column_definition.upper():
            definition = ' '.join(part for part in column_definition.split() if part.upper() != 'UNIQUE')
            unique_index = f'idx_{table_name}_{column_name}_unique'

        cur.execute(f'ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}')

        if unique_index:
            cur.execute(f'CREATE UNIQUE INDEX IF NOT EXISTS {unique_index} ON {table_name}({column_name})')
        return True
    return False


def migrate_legacy_appointments(cur):
    old_columns = get_table_columns(cur, 'appointments')
    if 'date' not in old_columns and 'patient_id' in old_columns and 'appointment_date' in old_columns:
        return

    select_columns = ['id']
    for column in ('patient_id', 'name', 'email', 'doctor_id', 'date', 'doctor', 'doctor_hospital', 'location'):
        if column in old_columns:
            select_columns.append(column)

    cur.execute('SELECT ' + ','.join(select_columns) + ' FROM appointments')
    rows = cur.fetchall()
    now = to_iso(utcnow())

    for row in rows:
        row_map = dict(zip(select_columns, row))
        updates = {}

        if 'patient_id' in old_columns and row_map.get('patient_id') is None and row_map.get('email'):
            patient = cur.execute('SELECT id FROM patients WHERE email=?', (row_map['email'],)).fetchone()
            if patient:
                patient_id = patient[0]
            else:
                random_password = secrets.token_urlsafe(16)
                patient_id = cur.execute(
                    'INSERT INTO patients (name, email, password, email_verified, registered_at) VALUES (?,?,?,?,?)',
                    (row_map.get('name') or 'Patient', row_map['email'], generate_password_hash(random_password), 0, now)
                ).lastrowid
            updates['patient_id'] = patient_id

        if 'appointment_date' in old_columns and row_map.get('date'):
            updates['appointment_date'] = row_map['date']

        if 'status' in old_columns and not row_map.get('status'):
            updates['status'] = 'scheduled'

        if 'notes' in old_columns and row_map.get('notes') is None:
            updates['notes'] = ''

        if 'created_at' in old_columns and not row_map.get('created_at'):
            updates['created_at'] = now

        if 'updated_at' in old_columns and not row_map.get('updated_at'):
            updates['updated_at'] = now

        if updates:
            set_clause = ', '.join(f"{key}=?" for key in updates)
            params = list(updates.values()) + [row_map['id']]
            cur.execute(f'UPDATE appointments SET {set_clause} WHERE id=?', params)


def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute('''
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                email TEXT UNIQUE,
                password TEXT,
                hospital TEXT,
                role TEXT DEFAULT 'hospital',
                is_verified INTEGER DEFAULT 0,
                otp_code TEXT,
                otp_expires TEXT,
                profile_photo TEXT,
                registered_at TEXT
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
                is_active INTEGER DEFAULT 1,
                is_available INTEGER DEFAULT 1,
                availability_schedule TEXT,
                profile_photo TEXT,
                email_verified INTEGER DEFAULT 0,
                otp_code TEXT,
                otp_expires TEXT
            )
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS patients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                email TEXT UNIQUE,
                password TEXT,
                email_verified INTEGER DEFAULT 0,
                otp_code TEXT,
                otp_expires TEXT,
                profile_photo TEXT,
                registered_at TEXT
            )
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS hospitals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE,
                location TEXT,
                contact_email TEXT,
                created_at TEXT,
                is_active INTEGER DEFAULT 1
            )
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS appointments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                patient_id INTEGER,
                doctor_id INTEGER,
                status TEXT DEFAULT 'scheduled',
                appointment_date TEXT,
                location TEXT,
                notes TEXT,
                created_at TEXT,
                updated_at TEXT,
                FOREIGN KEY(patient_id) REFERENCES patients(id) ON DELETE CASCADE,
                FOREIGN KEY(doctor_id) REFERENCES doctors(id) ON DELETE CASCADE
            )
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS medical_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                appointment_id INTEGER,
                report_title TEXT,
                findings TEXT,
                created_at TEXT,
                FOREIGN KEY(appointment_id) REFERENCES appointments(id) ON DELETE CASCADE
            )
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS prescriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                appointment_id INTEGER,
                prescription_text TEXT,
                created_at TEXT,
                FOREIGN KEY(appointment_id) REFERENCES appointments(id) ON DELETE CASCADE
            )
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor TEXT,
                role TEXT,
                action TEXT,
                target TEXT,
                ip_address TEXT,
                user_agent TEXT,
                timestamp TEXT
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
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient TEXT,
                recipient_role TEXT,
                message TEXT,
                is_read INTEGER DEFAULT 0,
                created_at TEXT
            )
        ''')

        ensure_column(cur, 'admins', 'email', 'TEXT UNIQUE')
        ensure_column(cur, 'admins', 'is_verified', 'INTEGER DEFAULT 0')
        ensure_column(cur, 'admins', 'otp_code', 'TEXT')
        ensure_column(cur, 'admins', 'otp_expires', 'TEXT')
        ensure_column(cur, 'admins', 'profile_photo', 'TEXT')
        ensure_column(cur, 'admins', 'registered_at', 'TEXT')

        ensure_column(cur, 'doctors', 'is_available', 'INTEGER DEFAULT 1')
        ensure_column(cur, 'doctors', 'availability_schedule', 'TEXT')
        ensure_column(cur, 'doctors', 'profile_photo', 'TEXT')
        ensure_column(cur, 'doctors', 'email_verified', 'INTEGER DEFAULT 0')
        ensure_column(cur, 'doctors', 'otp_code', 'TEXT')
        ensure_column(cur, 'doctors', 'otp_expires', 'TEXT')

        old_appointment_columns = get_table_columns(cur, 'appointments')
        ensure_column(cur, 'appointments', 'patient_id', 'INTEGER')
        ensure_column(cur, 'appointments', 'status', "TEXT DEFAULT 'scheduled'")
        ensure_column(cur, 'appointments', 'appointment_date', 'TEXT')
        ensure_column(cur, 'appointments', 'notes', 'TEXT')
        ensure_column(cur, 'appointments', 'created_at', 'TEXT')
        ensure_column(cur, 'appointments', 'updated_at', 'TEXT')

        migrate_legacy_appointments(cur)

        cur.execute('CREATE INDEX IF NOT EXISTS idx_doctors_name ON doctors(name)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_doctors_hospital ON doctors(hospital)')

        appointment_columns = get_table_columns(cur, 'appointments')
        if 'patient_id' in appointment_columns:
            cur.execute('CREATE INDEX IF NOT EXISTS idx_appointments_patient ON appointments(patient_id)')
        if 'doctor_id' in appointment_columns:
            cur.execute('CREATE INDEX IF NOT EXISTS idx_appointments_doctor ON appointments(doctor_id)')
        if 'appointment_date' in appointment_columns:
            cur.execute('CREATE INDEX IF NOT EXISTS idx_appointments_date ON appointments(appointment_date)')

        cur.execute('CREATE INDEX IF NOT EXISTS idx_notifications_recipient ON notifications(recipient)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_doctor_audit_doctor ON doctor_audit(doctor_id)')

        cur.execute('SELECT id FROM admins WHERE username=?', ('admin',))
        if not cur.fetchone():
            hashed = generate_password_hash(DEFAULT_ADMIN_PASSWORD)
            cur.execute(
                'INSERT INTO admins (username,email,password,hospital,role,is_verified,registered_at) VALUES (?,?,?,?,?,?,?)',
                ('admin', 'admin@example.com', hashed, 'Default Hospital', 'super', 1, to_iso(utcnow()))
            )

        conn.commit()
    except Exception as exc:
        logger.exception('init_db failed: %s', exc)
        raise
    finally:
        conn.close()


_db_initialized = False

@app.before_request
def ensure_db_initialized():
    global _db_initialized
    if not _db_initialized:
        init_db()
        _db_initialized = True


@app.context_processor
def inject_csrf():
    def csrf_token():
        token = session.get('_csrf_token')
        if not token:
            token = secrets.token_urlsafe(32)
            session['_csrf_token'] = token
        return token

    def csrf_input():
        return Markup(f'<input type="hidden" name="_csrf_token" value="{csrf_token()}">')

    return dict(csrf_token=csrf_token, csrf_input=csrf_input, datetime=datetime, google_oauth_enabled=GOOGLE_OAUTH_ENABLED)


@app.before_request
def validate_csrf():
    if request.method in ('GET', 'HEAD', 'OPTIONS'):
        return

    if request.endpoint and request.endpoint.startswith('google.'):
        return
    if request.path.startswith('/google_login'):
        return

    token = request.form.get('_csrf_token') or request.headers.get('X-CSRFToken')
    if not token or token != session.get('_csrf_token'):
        abort(400, description='Bad or missing CSRF token')


@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response


@app.route('/')
def home():
    rows = query_db('SELECT id, name, specialization, location, hospital, is_available FROM doctors WHERE is_active=1')
    doctors = [dict(id=r['id'], name=r['name'], specialization=r['specialization'], location=r['location'], hospital=r['hospital'], is_available=r['is_available']) for r in rows]
    specializations = []
    for doctor in doctors:
        if doctor['specialization'] and doctor['specialization'] not in specializations:
            specializations.append(doctor['specialization'])
    return render_template('index.html', doctors=doctors, specializations=specializations)


@app.route('/book', methods=['POST'])
def book():
    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip()
    doctor_id_value = request.form.get('doctor_id', '').strip()
    appointment_date = request.form.get('date', '').strip()
    location = request.form.get('location', '').strip()
    notes = request.form.get('notes', '').strip()

    if not all([name, email, doctor_id_value, appointment_date, location]):
        flash('Please fill all required booking fields.')
        return redirect('/')

    if not validate_email(email):
        flash('Please provide a valid email address.')
        return redirect('/')

    try:
        doctor_id = int(doctor_id_value)
    except ValueError:
        flash('Invalid doctor selection.')
        return redirect('/')

    try:
        appointment_date_obj = datetime.date.fromisoformat(appointment_date)
    except ValueError:
        flash('Please select a valid appointment date.')
        return redirect('/')

    if appointment_date_obj < datetime.date.today():
        flash('Cannot book appointments in the past.')
        return redirect('/')

    doctor = query_db('SELECT id, name, hospital, is_available FROM doctors WHERE id=? AND is_active=1', (doctor_id,), one=True)
    if not doctor or not doctor['is_available']:
        flash('Selected doctor is not available. Please choose another doctor.')
        return redirect('/')

    patient = query_db('SELECT id FROM patients WHERE email=?', (email,), one=True)
    if patient:
        patient_id = patient['id']
    else:
        patient_id, _ = execute_db('INSERT INTO patients (name, email, password, email_verified, registered_at) VALUES (?,?,?,?,?)',
                                   (name, email, generate_password_hash(secrets.token_urlsafe(16)), 0, to_iso(utcnow())))

    duplicate = query_db('SELECT id FROM appointments WHERE patient_id=? AND doctor_id=? AND appointment_date=?',
                         (patient_id, doctor_id, appointment_date), one=True)
    if duplicate:
        flash('You already have an appointment with this doctor on the selected date.')
        return redirect('/')

    try:
        now = to_iso(utcnow())
        appointment_id, _ = execute_db('INSERT INTO appointments (patient_id, doctor_id, status, appointment_date, location, notes, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)',
                                       (patient_id, doctor_id, 'scheduled', appointment_date, location, notes, now, now))
        record_audit(email, 'patient', 'book_appointment', str(appointment_id), request.remote_addr or '', request.user_agent.string or '')
        execute_db('INSERT INTO notifications (recipient, recipient_role, message, created_at) VALUES (?,?,?,?)',
                   (email, 'patient', f'Appointment booked with Dr. {doctor["name"]} on {appointment_date}.', now))
        try:
            send_email(email, 'Appointment Confirmation',
                       f'Dear {name},\n\nYour appointment with Dr. {doctor["name"]} on {appointment_date} has been scheduled.\n\nThank you,\nHealthCare+ Team')
            flash('Appointment booked successfully. Check your email for confirmation.')
        except RuntimeError:
            flash('Appointment booked successfully, but email could not be sent.')
    except Exception as exc:
        logger.exception('Failed to create appointment: %s', exc)
        flash('Unable to book appointment at this time.')

    return redirect('/')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            flash('Missing credentials')
            return render_template('login.html')

        row = query_db('SELECT password, hospital, role FROM admins WHERE username=?', (username,), one=True)
        if row and row['password'] and check_password_hash(row['password'], password):
            session.permanent = True
            session['admin'] = username
            session['hospital'] = row['hospital']
            session['admin_role'] = row['role'] or 'hospital'
            logger.info('Admin logged in: %s', username)
            return redirect('/dashboard')

        flash('Invalid credentials')
    return render_template('login.html')


@app.route('/admin_register', methods=['GET', 'POST'])
def admin_register():
    if 'admin' not in session or session.get('admin_role') != 'super':
        return redirect('/login')

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        role = request.form.get('role', 'hospital')
        hospital = request.form.get('hospital', '').strip()
        email = request.form.get('email', '').strip()

        if role == 'hospital' and not hospital:
            flash('Hospital is required for hospital admins')
            return redirect('/admin_register')
        if not username or not password:
            flash('Username and password are required')
            return redirect('/admin_register')
        if email and not validate_email(email):
            flash('Invalid admin email address')
            return redirect('/admin_register')

        if query_db('SELECT id FROM admins WHERE username=?', (username,), one=True):
            flash('Admin username already exists')
            return redirect('/admin_register')

        hashed = generate_password_hash(password)
        try:
            execute_db('INSERT INTO admins (username, email, password, hospital, role, registered_at) VALUES (?,?,?,?,?,?)',
                       (username, email or None, hashed, hospital, role, to_iso(utcnow())))
            flash(f'New {role} admin created for hospital: {hospital or "N/A"}')
            logger.info('Admin created: %s by %s', username, session.get('admin'))
            return redirect('/dashboard')
        except Exception as exc:
            logger.exception('Failed to create admin: %s', exc)
            flash('Failed to create admin')
    return render_template('admin_register.html')


@app.route('/doctor_login', methods=['GET', 'POST'])
def doctor_login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        if not validate_email(email):
            flash('Invalid email')
            return render_template('doctor_login.html')

        row = query_db('SELECT id, name, password, hospital, email_verified, is_available FROM doctors WHERE email=? AND is_active=1', (email,), one=True)
        if row and row['password'] and check_password_hash(row['password'], password):
            session.permanent = True
            session['doctor'] = email
            session['doctor_id'] = row['id']
            session['doctor_name'] = row['name']
            session['doctor_hospital'] = row['hospital']
            session['doctor_email_verified'] = row['email_verified']
            session['doctor_available'] = row['is_available']
            logger.info('Doctor logged in: %s', email)
            return redirect('/doctor_dashboard')

        flash('Invalid doctor credentials')
    return render_template('doctor_login.html')


@app.route('/doctor_reset', methods=['GET', 'POST'])
def doctor_reset():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        if not validate_email(email):
            flash('Invalid email')
            return redirect('/doctor_reset')

        doctor = query_db('SELECT id FROM doctors WHERE email=?', (email,), one=True)
        if not doctor:
            flash('No doctor found with that email')
            return redirect('/doctor_login')

        try:
            execute_db('UPDATE doctors SET password=? WHERE email=?', (generate_password_hash(password), email))
            flash('Password reset successfully')
        except Exception as exc:
            logger.exception('Failed to reset doctor password: %s', exc)
            flash('Failed to reset password')
        return redirect('/doctor_login')
    return render_template('doctor_reset.html')


@app.route('/doctor_dashboard')
def doctor_dashboard():
    if 'doctor' not in session:
        return redirect('/doctor_login')

    doctor_id = session.get('doctor_id')
    doctor_name = session.get('doctor_name')
    doctor_hospital = session.get('doctor_hospital')

    doctor = query_db('SELECT is_available FROM doctors WHERE id=?', (doctor_id,), one=True)
    is_available = doctor['is_available'] if doctor else 0

    rows = query_db('''
        SELECT a.id, p.name as patient, p.email as patient_email, a.appointment_date, a.location, a.status, a.notes
        FROM appointments a
        JOIN patients p ON a.patient_id = p.id
        WHERE a.doctor_id = ?
        ORDER BY a.appointment_date DESC
    ''', (doctor_id,))
    appointments = [dict(id=r['id'], patient=r['patient'], email=r['patient_email'], appointment_date=r['appointment_date'], location=r['location'], status=r['status'], notes=r['notes']) for r in rows]

    counts = {
        'scheduled': sum(1 for a in appointments if a['status'] == 'scheduled'),
        'completed': sum(1 for a in appointments if a['status'] == 'completed'),
        'cancelled': sum(1 for a in appointments if a['status'] == 'cancelled')
    }
    return render_template('doctor_dashboard.html', doctor_name=doctor_name, doctor_hospital=doctor_hospital, appointments=appointments, counts=counts, is_available=is_available)


@app.route('/doctor_cancel/<int:id>', methods=['POST'])
def doctor_cancel(id):
    if 'doctor' not in session:
        return redirect('/doctor_login')

    row = query_db('SELECT doctor_id FROM appointments WHERE id=?', (id,), one=True)
    if row and row['doctor_id'] == session.get('doctor_id'):
        try:
            execute_db('UPDATE appointments SET status=?, updated_at=? WHERE id=?', ('cancelled', to_iso(utcnow()), id))
            execute_db('INSERT INTO notifications (recipient, recipient_role, message, created_at) VALUES (?,?,?,?)',
                       (session.get('doctor'), 'doctor', f'Appointment {id} cancelled successfully.', to_iso(utcnow())))
        except Exception as exc:
            logger.exception('Failed to cancel appointment: %s', exc)
    return redirect('/doctor_dashboard')


@app.route('/doctor_edit/<int:id>', methods=['GET', 'POST'])
def doctor_edit(id):
    if 'doctor' not in session:
        return redirect('/doctor_login')

    appt = query_db('SELECT id, patient_id, doctor_id, appointment_date, location, status, notes FROM appointments WHERE id=?', (id,), one=True)
    if not appt or appt['doctor_id'] != session.get('doctor_id'):
        return redirect('/doctor_dashboard')

    patient = query_db('SELECT name, email FROM patients WHERE id=?', (appt['patient_id'],), one=True)
    if not patient:
        return redirect('/doctor_dashboard')

    if request.method == 'POST':
        new_date = request.form.get('date', '').strip()
        new_location = request.form.get('location', '').strip()
        new_status = request.form.get('status', '').strip() or appt['status']
        new_notes = request.form.get('notes', '').strip()

        if new_status not in ('scheduled', 'completed', 'cancelled'):
            new_status = appt['status']

        try:
            datetime.date.fromisoformat(new_date)
            execute_db('UPDATE appointments SET appointment_date=?, location=?, status=?, notes=?, updated_at=? WHERE id=?',
                       (new_date, new_location, new_status, new_notes, to_iso(utcnow()), id))
            flash('Appointment updated successfully')
        except ValueError:
            flash('Please provide a valid date.')
        except Exception as exc:
            logger.exception('Failed to update appointment: %s', exc)
            flash('Failed to update appointment')
        return redirect('/doctor_dashboard')

    appointment = dict(id=appt['id'], patient_name=patient['name'], patient_email=patient['email'], appointment_date=appt['appointment_date'], location=appt['location'], status=appt['status'], notes=appt['notes'])
    return render_template('doctor_edit.html', appointment=appointment)


@app.route('/user_login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        if not validate_email(email):
            flash('Invalid email')
            return render_template('user_login.html')

        row = query_db('SELECT id, password, email_verified FROM patients WHERE email=?', (email,), one=True)
        if row and row['password'] and check_password_hash(row['password'], password):
            session.permanent = True
            session['user'] = email
            session['user_id'] = row['id']
            session['user_email_verified'] = row['email_verified']
            record_audit(email, 'patient', 'login', email, request.remote_addr or '', request.user_agent.string or '')
            return redirect('/patient_dashboard')

        if row:
            flash('Invalid username or password')
        else:
            try:
                hashed = generate_password_hash(password)
                user_id, _ = execute_db('INSERT INTO patients (name, email, password, email_verified, registered_at) VALUES (?,?,?,?,?)',
                                         (email.split('@')[0], email, hashed, 0, to_iso(utcnow())))
                session.permanent = True
                session['user'] = email
                session['user_id'] = user_id
                session['user_email_verified'] = 0
                record_audit(email, 'patient', 'register', email, request.remote_addr or '', request.user_agent.string or '')
                flash('Account created and logged in')
                return redirect('/patient_dashboard')
            except Exception as exc:
                logger.exception('Failed to register user: %s', exc)
                flash('Registration failed')

    return render_template('user_login.html')


@app.route('/patient_dashboard')
def patient_dashboard():
    if 'user' not in session:
        return redirect('/user_login')

    user_email = session['user']
    user_id = session['user_id']
    rows = query_db('''
        SELECT a.id, a.appointment_date, a.location, a.status, d.name as doctor_name, d.specialization
        FROM appointments a
        JOIN doctors d ON a.doctor_id = d.id
        WHERE a.patient_id = ?
        ORDER BY a.appointment_date ASC
    ''', (user_id,))
    appointments = [dict(id=r['id'], appointment_date=r['appointment_date'], location=r['location'], status=r['status'], doctor_name=r['doctor_name'], specialization=r['specialization']) for r in rows]

    report_rows = query_db('''
        SELECT r.id, r.report_title, r.created_at, a.appointment_date
        FROM medical_reports r
        JOIN appointments a ON a.id = r.appointment_id
        WHERE a.patient_id = ?
        ORDER BY r.created_at DESC
    ''', (user_id,))
    reports = [dict(id=r['id'], title=r['report_title'], created_at=r['created_at'], appointment_date=r['appointment_date']) for r in report_rows]

    notifications = get_notifications(user_email, 'patient')
    upcoming = [a for a in appointments if a['status'] == 'scheduled']
    upcoming_count = len(upcoming)
    next_appointment = upcoming[0]['appointment_date'] if upcoming else None
    unread_notifications = sum(1 for n in notifications if not n['is_read'])

    return render_template('patient_dashboard.html', appointments=appointments, report_count=len(reports), notifications=notifications, upcoming_count=upcoming_count, next_appointment=next_appointment, unread_notifications=unread_notifications)


@app.route('/appointments_calendar')
def appointments_calendar():
    if 'user' in session:
        user_id = session['user_id']
        rows = query_db('''
            SELECT a.appointment_date as date, d.name as doctor_name, d.specialization, a.status
            FROM appointments a
            JOIN doctors d ON a.doctor_id = d.id
            WHERE a.patient_id = ?
            ORDER BY a.appointment_date ASC
        ''', (user_id,))
        role = 'patient'
    elif 'doctor' in session:
        doctor_id = session['doctor_id']
        rows = query_db('''
            SELECT a.appointment_date as date, p.name as patient_name, p.email as patient_email, a.status
            FROM appointments a
            JOIN patients p ON a.patient_id = p.id
            WHERE a.doctor_id = ?
            ORDER BY a.appointment_date ASC
        ''', (doctor_id,))
        role = 'doctor'
    else:
        return redirect('/user_login')

    events = []
    for row in rows:
        event = dict(row)
        event['title'] = event.get('doctor_name') or event.get('patient_name')
        event['subtitle'] = event.get('specialization') or event.get('patient_email')
        events.append(event)
    return render_template('appointments_calendar.html', events=events, role=role)


@app.route('/patient_reports')
def patient_reports():
    if 'user' not in session:
        return redirect('/user_login')

    user_id = session['user_id']
    rows = query_db('''
        SELECT r.id, r.report_title, r.findings, r.created_at, d.name as doctor_name
        FROM medical_reports r
        JOIN appointments a ON r.appointment_id = a.id
        JOIN doctors d ON a.doctor_id = d.id
        WHERE a.patient_id = ?
        ORDER BY r.created_at DESC
    ''', (user_id,))
    reports = [dict(id=r['id'], title=r['report_title'], findings=r['findings'], created_at=r['created_at'], doctor_name=r['doctor_name']) for r in rows]
    return render_template('patient_reports.html', reports=reports)


@app.route('/export_patient_report')
def export_patient_report():
    if 'user' not in session:
        return redirect('/user_login')

    user_id = session['user_id']
    rows = query_db('''
        SELECT a.appointment_date, d.name as doctor_name, d.specialization, a.location, a.status
        FROM appointments a
        JOIN doctors d ON a.doctor_id = d.id
        WHERE a.patient_id = ?
        ORDER BY a.appointment_date ASC
    ''', (user_id,))

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Date', 'Doctor', 'Specialization', 'Location', 'Status'])
    for row in rows:
        writer.writerow([row['appointment_date'], row['doctor_name'], row['specialization'], row['location'], row['status']])
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode('utf-8')), mimetype='text/csv', as_attachment=True, download_name='appointments.csv')


@app.route('/hospital_dashboard')
def hospital_dashboard():
    if 'admin' not in session or session.get('admin_role') != 'super':
        return redirect('/login')

    hospitals = query_db('SELECT id, name, location, contact_email, is_active FROM hospitals ORDER BY name')
    hospital_stats = []
    for hospital in hospitals:
        appointment_count = query_db('''
            SELECT COUNT(a.id) as cnt
            FROM appointments a
            JOIN doctors d ON a.doctor_id = d.id
            WHERE d.hospital = ?
        ''', (hospital['name'],), one=True)['cnt']
        doctors_count = query_db('SELECT COUNT(*) as cnt FROM doctors WHERE hospital=?', (hospital['name'],), one=True)['cnt']
        hospital_stats.append(dict(name=hospital['name'], location=hospital['location'], doctor_count=doctors_count, appointment_count=appointment_count, active=hospital['is_active']))
    return render_template('hospital_dashboard.html', hospitals=hospital_stats)


@app.route('/analytics')
def analytics():
    if 'admin' not in session:
        return redirect('/login')

    appointment_counts = query_db('''
        SELECT d.specialization AS label, COUNT(a.id) as total
        FROM appointments a
        JOIN doctors d ON a.doctor_id = d.id
        GROUP BY d.specialization
        ORDER BY total DESC
        LIMIT 10
    ''')
    doctor_counts = query_db('''
        SELECT d.name AS label, COUNT(a.id) as total
        FROM appointments a
        JOIN doctors d ON a.doctor_id = d.id
        GROUP BY d.name
        ORDER BY total DESC
        LIMIT 10
    ''')
    hospital_counts = query_db('''
        SELECT d.hospital AS label, COUNT(a.id) as total
        FROM appointments a
        JOIN doctors d ON a.doctor_id = d.id
        GROUP BY d.hospital
        ORDER BY total DESC
        LIMIT 10
    ''')
    return render_template('analytics.html', appointment_counts=appointment_counts, doctor_counts=doctor_counts, hospital_counts=hospital_counts)


@app.route('/admin_management')
def admin_management():
    if 'admin' not in session or session.get('admin_role') != 'super':
        return redirect('/login')

    rows = query_db('SELECT id, username, email, hospital, role, is_verified FROM admins ORDER BY role, username')
    admins = [dict(id=r['id'], username=r['username'], email=r['email'], hospital=r['hospital'], role=r['role'], is_verified=r['is_verified']) for r in rows]
    return render_template('admin_management.html', admins=admins)


@app.route('/prescription_pdf/<int:appointment_id>')
def prescription_pdf(appointment_id):
    if 'doctor' not in session and 'admin' not in session:
        return redirect('/login')

    prescription = query_db('''
        SELECT p.prescription_text, a.appointment_date, d.name as doctor_name, pt.name as patient_name
        FROM prescriptions p
        JOIN appointments a ON p.appointment_id = a.id
        JOIN doctors d ON a.doctor_id = d.id
        JOIN patients pt ON a.patient_id = pt.id
        WHERE p.appointment_id = ?
    ''', (appointment_id,), one=True)
    if not prescription:
        flash('Prescription not found')
        return redirect('/doctor_dashboard' if 'doctor' in session else '/dashboard')

    buffer = create_pdf_prescription(prescription['patient_name'], prescription['doctor_name'], prescription['prescription_text'])
    return send_file(buffer, mimetype='application/pdf', as_attachment=True, download_name=f'prescription_{appointment_id}.pdf')


@app.route('/audit_logs')
def audit_logs():
    if 'admin' not in session:
        return redirect('/login')

    rows = query_db('SELECT actor, role, action, target, ip_address, user_agent, timestamp FROM audit_logs ORDER BY timestamp DESC LIMIT 100')
    logs = [dict(actor=r['actor'], role=r['role'], action=r['action'], target=r['target'], ip_address=r['ip_address'], user_agent=r['user_agent'], timestamp=r['timestamp']) for r in rows]
    return render_template('audit_logs.html', logs=logs)


@app.route('/verify_email', methods=['GET', 'POST'])
def verify_email():
    if 'user' not in session and 'doctor' not in session and 'admin' not in session:
        return redirect('/login')

    if request.method == 'POST':
        otp = request.form.get('otp', '').strip()
        if 'user' in session:
            table, identity, field = 'patients', session['user'], 'email'
        elif 'doctor' in session:
            table, identity, field = 'doctors', session['doctor'], 'email'
        else:
            table, identity, field = 'admins', session['admin'], 'username'

        row = query_db(f'SELECT otp_code, otp_expires FROM {table} WHERE {field}=?', (identity,), one=True)
        if row and row['otp_code'] == otp:
            try:
                if utcnow() <= parse_iso_datetime(row['otp_expires']):
                    execute_db(f'UPDATE {table} SET email_verified=1, otp_code=NULL, otp_expires=NULL WHERE {field}=?', (identity,))
                    flash('Email verified successfully')
                    return redirect('/dashboard' if 'admin' in session else '/doctor_dashboard' if 'doctor' in session else '/patient_dashboard')
            except Exception:
                pass
        flash('Invalid or expired OTP')

    return render_template('verify_email.html')


@app.route('/send_verification_otp', methods=['POST'])
def send_verification_otp():
    if 'user' in session:
        identity = session['user']
        role = 'patient'
    elif 'doctor' in session:
        identity = session['doctor']
        role = 'doctor'
    elif 'admin' in session:
        identity = session['admin']
        role = 'admin'
    else:
        return redirect('/login')

    try:
        send_otp_for_verification(identity, role)
        flash('OTP sent to your registered email address')
    except Exception as exc:
        logger.exception('Failed to send OTP: %s', exc)
        flash('Could not send OTP at this time')
    return redirect('/verify_email')


@app.route('/doctor_availability', methods=['POST'])
def doctor_availability():
    if 'doctor' not in session:
        return redirect('/doctor_login')

    doctor_id = session['doctor_id']
    status = 1 if request.form.get('available', '0') == '1' else 0
    execute_db('UPDATE doctors SET is_available=? WHERE id=?', (status, doctor_id))
    session['doctor_available'] = status
    flash('Availability updated')
    return redirect('/doctor_dashboard')


@app.route('/logout')
def logout():
    for key in ['admin', 'user', 'doctor', 'doctor_name', 'doctor_hospital', 'hospital', 'user_id', 'doctor_id', 'user_email_verified', 'doctor_email_verified', 'doctor_available', '_csrf_token']:
        session.pop(key, None)
    session.modified = True
    return redirect('/')


@app.route('/google_login')
def google_login():
    if make_google_blueprint is None or google is None:
        flash('Google OAuth is not configured on this server.')
        return redirect('/user_login')

    if not google.authorized:
        return redirect(url_for('google.login'))

    resp = google.get('/oauth2/v2/userinfo')
    if not resp.ok:
        flash('Failed to fetch user info from Google.')
        return redirect('/user_login')

    info = resp.json()
    email = info.get('email')
    if not email:
        flash('Google account did not provide an email address.')
        return redirect('/user_login')

    row = query_db('SELECT id FROM patients WHERE email=?', (email,), one=True)
    if not row:
        execute_db('INSERT INTO patients (name,email,password,email_verified,registered_at) VALUES (?,?,?,?,?)',
                   (info.get('name', email.split('@')[0]), email, generate_password_hash(secrets.token_urlsafe(16)), 1, to_iso(utcnow())))
        row = query_db('SELECT id FROM patients WHERE email=?', (email,), one=True)

    session.permanent = True
    session['user'] = email
    session['user_id'] = row['id']
    session['user_email_verified'] = 1
    flash('Logged in with Google: ' + email)
    return redirect('/patient_dashboard')


@app.route('/dashboard')
def dashboard():
    if 'admin' not in session:
        return redirect('/login')

    hospital = session.get('hospital')
    if session.get('admin_role') == 'super':
        total_appointments = query_db('SELECT COUNT(*) as cnt FROM appointments', (), one=True)['cnt']
        total_doctors = query_db('SELECT COUNT(*) as cnt FROM doctors', (), one=True)['cnt']
        total_hospitals = query_db('SELECT COUNT(*) as cnt FROM hospitals', (), one=True)['cnt']
        appointments = query_db('''
            SELECT a.id, p.name as patient_name, p.email as patient_email, d.name as doctor_name, d.specialization, a.status, a.appointment_date, a.location
            FROM appointments a
            JOIN patients p ON a.patient_id = p.id
            JOIN doctors d ON a.doctor_id = d.id
            ORDER BY a.appointment_date DESC
            LIMIT 50
        ''')
        hospital_report = query_db('''
            SELECT h.name as label, COUNT(a.id) as appointment_count
            FROM hospitals h
            LEFT JOIN doctors d ON d.hospital = h.name
            LEFT JOIN appointments a ON a.doctor_id = d.id
            GROUP BY h.name
        ''')
    else:
        total_appointments = query_db('''SELECT COUNT(*) as cnt FROM appointments a JOIN doctors d ON a.doctor_id = d.id WHERE d.hospital=?''', (hospital,), one=True)['cnt']
        total_doctors = query_db('SELECT COUNT(*) as cnt FROM doctors WHERE hospital=?', (hospital,), one=True)['cnt']
        total_hospitals = 1
        appointments = query_db('''
            SELECT a.id, p.name as patient_name, p.email as patient_email, d.name as doctor_name, d.specialization, a.status, a.appointment_date, a.location
            FROM appointments a
            JOIN patients p ON a.patient_id = p.id
            JOIN doctors d ON a.doctor_id = d.id
            WHERE d.hospital = ?
            ORDER BY a.appointment_date DESC
            LIMIT 50
        ''', (hospital,))
        hospital_report = query_db('''
            SELECT d.hospital as label, COUNT(a.id) as appointment_count
            FROM appointments a
            JOIN doctors d ON a.doctor_id = d.id
            WHERE d.hospital = ?
            GROUP BY d.hospital
        ''', (hospital,))

    appointments = [dict(id=r['id'], patient_name=r['patient_name'], patient_email=r['patient_email'], doctor_name=r['doctor_name'], specialization=r['specialization'], status=r['status'], appointment_date=r['appointment_date'], location=r['location']) for r in appointments]
    hospital_report = [dict(label=r['label'], appointment_count=r['appointment_count']) for r in hospital_report]
    return render_template('dashboard.html', total_appointments=total_appointments, total_doctors=total_doctors, total_hospitals=total_hospitals, appointments=appointments, hospital_report=hospital_report)


@app.route('/delete/<int:id>', methods=['POST'])
def delete(id):
    if 'admin' not in session:
        return redirect('/login')

    appointment = query_db('SELECT a.id, d.hospital FROM appointments a JOIN doctors d ON a.doctor_id = d.id WHERE a.id = ?', (id,), one=True)
    if not appointment:
        flash('Appointment not found')
        return redirect('/dashboard')
    if session.get('admin_role') != 'super' and appointment['hospital'] != session.get('hospital'):
        flash('Not authorized to delete this appointment')
        return redirect('/dashboard')

    try:
        execute_db('UPDATE appointments SET status=?, updated_at=? WHERE id=?', ('cancelled', to_iso(utcnow()), id))
        record_audit(session.get('admin'), session.get('admin_role'), 'cancel_appointment', str(id), request.remote_addr or '', request.user_agent.string or '')
    except Exception as exc:
        logger.exception('Failed to cancel appointment: %s', exc)
    return redirect('/dashboard')


@app.route('/delete_doctor/<int:id>', methods=['POST'])
def delete_doctor(id):
    if 'admin' not in session:
        return redirect('/login')

    doctor = query_db('SELECT hospital FROM doctors WHERE id=?', (id,), one=True)
    if not doctor:
        flash('Doctor not found')
        return redirect('/doctors')
    if session.get('admin_role') != 'super' and doctor['hospital'] != session.get('hospital'):
        flash('Not authorized to delete this doctor')
        return redirect('/doctors')

    try:
        execute_db('UPDATE doctors SET is_active=0 WHERE id=?', (id,))
    except Exception as exc:
        logger.exception('Failed to soft-delete doctor: %s', exc)
    return redirect('/doctors')


@app.route('/doctors_all')
def doctors_all():
    if 'admin' not in session:
        return redirect('/login')
    rows = query_db('SELECT * FROM doctors')
    doctors = [dict(id=r['id'], name=r['name'], specialization=r['specialization'], location=r['location'], hospital=r['hospital'], email=r['email'], is_active=r['is_active'], is_available=r['is_available'], availability_schedule=r['availability_schedule']) for r in rows]
    return render_template('doctors.html', doctors=doctors, audit=[])


@app.route('/restore_doctor/<int:id>', methods=['POST'])
def restore_doctor(id):
    if 'admin' not in session:
        return redirect('/login')

    try:
        execute_db('UPDATE doctors SET is_active=1 WHERE id=?', (id,))
    except Exception as exc:
        logger.exception('Failed to restore doctor: %s', exc)
    return redirect('/doctors')


@app.route('/purge_doctor/<int:id>', methods=['POST'])
def purge_doctor(id):
    if 'admin' not in session:
        return redirect('/login')

    doctor_row = query_db('SELECT id, name, hospital FROM doctors WHERE id=?', (id,), one=True)
    if not doctor_row:
        flash('Doctor not found')
        return redirect('/doctors')
    if session.get('admin_role') != 'super' and doctor_row['hospital'] != session.get('hospital'):
        flash('Not authorized to purge this doctor')
        return redirect('/doctors')

    try:
        execute_db('DELETE FROM appointments WHERE doctor_id=?', (id,))
        execute_db('DELETE FROM doctors WHERE id=?', (id,))
        execute_db('INSERT INTO doctor_audit (doctor_id, doctor_name, doctor_hospital, action, admin_username, timestamp) VALUES (?,?,?,?,?,?)',
                   (id, doctor_row['name'], doctor_row['hospital'], 'purge', session.get('admin'), to_iso(utcnow())))
    except Exception as exc:
        logger.exception('Failed to purge doctor: %s', exc)
        flash('Failed to purge doctor')
    return redirect('/doctors')


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
        availability = request.form.get('availability', '1')

        if not all([name, specialization, email, password]):
            flash('Please fill all required doctor fields')
            return redirect('/doctors')
        if not validate_email(email):
            flash('Invalid doctor email')
            return redirect('/doctors')

        hashed = generate_password_hash(password)
        try:
            execute_db('INSERT INTO doctors (name, specialization, location, hospital, email, password, is_available, availability_schedule) VALUES (?,?,?,?,?,?,?,?)',
                       (name, specialization, location, hospital, email, hashed, int(availability), 'Mon-Fri 09:00-17:00'))
            logger.info('Doctor added: %s by admin %s', name, session.get('admin'))
        except sqlite3.IntegrityError as exc:
            logger.warning('Doctor insert integrity error: %s', exc)
            flash('Failed to add doctor: email may already exist')
        except Exception as exc:
            logger.exception('Failed to add doctor: %s', exc)
            flash('Failed to add doctor')
        return redirect('/doctors')

    hospital = session.get('hospital')
    if session.get('admin_role') == 'super':
        data = query_db('SELECT * FROM doctors')
    else:
        data = query_db('SELECT * FROM doctors WHERE hospital=?', (hospital,))

    audit = query_db('SELECT id, doctor_id, doctor_name, action, admin_username, timestamp FROM doctor_audit WHERE doctor_hospital=? ORDER BY timestamp DESC LIMIT 25', (hospital,))
    doctors = [dict(id=r['id'], name=r['name'], specialization=r['specialization'], location=r['location'], hospital=r['hospital'], email=r['email'], is_active=r['is_active'], is_available=r['is_available'], availability_schedule=r['availability_schedule']) for r in data]
    audit = [dict(id=r['id'], doctor_id=r['doctor_id'], doctor_name=r['doctor_name'], action=r['action'], admin_username=r['admin_username'], timestamp=r['timestamp']) for r in audit]
    return render_template('doctors.html', doctors=doctors, audit=audit)


@app.errorhandler(404)
def handle_404(err):
    logger.warning('404 Not Found: %s', request.path)
    return '404 Not Found', 404


@app.errorhandler(500)
def handle_500(err):
    logger.exception('Internal server error: %s', err)
    return 'Internal Server Error', 500


if __name__ == '__main__':
    init_db()
    app.run(debug=(APP_ENV != 'production'))
