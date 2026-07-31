from flask import Flask, render_template, request, redirect, session, flash, url_for
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
from email.mime.text import MIMEText
import os
import datetime
try:
    from flask_dance.contrib.google import make_google_blueprint, google
except Exception:
    make_google_blueprint = None
    google = None


# configure these for your SMTP server (Gmail example)
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_HOST_USER = 'youremail@gmail.com'     # replace with real sender
EMAIL_HOST_PASSWORD = 'yourpassword'        # app password or real password


def send_email(to_address: str, subject: str, body: str):
    # simple SMTP email sender
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_HOST_USER
    msg['To'] = to_address

    # perform SMTP operations and allow exceptions to propagate so caller can handle them
    server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT, timeout=10)
    server.starttls()
    server.login(EMAIL_HOST_USER, EMAIL_HOST_PASSWORD)
    server.send_message(msg)
    server.quit()
    print(f"Email sent to {to_address}")

app = Flask(__name__)
app.secret_key = "super_secret_key"

# --- Google OAuth (optional) ---
if make_google_blueprint:
    # Use environment variables to store client id/secret in production
    GOOGLE_OAUTH_CLIENT_ID = os.getenv('GOOGLE_OAUTH_CLIENT_ID', 'your-google-client-id')
    GOOGLE_OAUTH_CLIENT_SECRET = os.getenv('GOOGLE_OAUTH_CLIENT_SECRET', 'your-google-client-secret')
    google_bp = make_google_blueprint(
        client_id=GOOGLE_OAUTH_CLIENT_ID,
        client_secret=GOOGLE_OAUTH_CLIENT_SECRET,
        scope=["profile", "email"],
        redirect_url="/google_login"
    )
    app.register_blueprint(google_bp, url_prefix="/login")

# ---------------- DATABASE INIT ----------------
def init_db():
    conn = sqlite3.connect('healthcare.db')
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            hospital TEXT,
            role TEXT DEFAULT 'hospital'
        )
    ''')

    # Make sure existing admins have required columns
    cursor.execute("PRAGMA table_info(admins)")
    admin_columns = [row[1] for row in cursor.fetchall()]
    if 'hospital' not in admin_columns:
        cursor.execute('ALTER TABLE admins ADD COLUMN hospital TEXT')
    if 'role' not in admin_columns:
        cursor.execute("ALTER TABLE admins ADD COLUMN role TEXT DEFAULT 'hospital'")

    cursor.execute('''
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

    cursor.execute('''
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

    # Make sure existing doctors have required columns
    cursor.execute("PRAGMA table_info(doctors)")
    columns = [row[1] for row in cursor.fetchall()]
    if 'hospital' not in columns:
        cursor.execute('ALTER TABLE doctors ADD COLUMN hospital TEXT')
    if 'email' not in columns:
        cursor.execute('ALTER TABLE doctors ADD COLUMN email TEXT')
    if 'password' not in columns:
        cursor.execute('ALTER TABLE doctors ADD COLUMN password TEXT')

    # Make sure existing doctors have a hospital column
    cursor.execute("PRAGMA table_info(doctors)")
    columns = [row[1] for row in cursor.fetchall()]
    if 'hospital' not in columns:
        cursor.execute('ALTER TABLE doctors ADD COLUMN hospital TEXT')

    # Add missing columns if the DB already exists
    cursor.execute("PRAGMA table_info(doctors)")
    columns = [row[1] for row in cursor.fetchall()]
    if 'location' not in columns:
        cursor.execute('ALTER TABLE doctors ADD COLUMN location TEXT')
    if 'is_active' not in columns:
        cursor.execute('ALTER TABLE doctors ADD COLUMN is_active INTEGER DEFAULT 1')

    cursor.execute('''
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

    # Add missing columns for existing databases
    cursor.execute("PRAGMA table_info(appointments)")
    appointment_columns = [row[1] for row in cursor.fetchall()]
    if 'location' not in appointment_columns:
        cursor.execute('ALTER TABLE appointments ADD COLUMN location TEXT')
    if 'doctor_hospital' not in appointment_columns:
        cursor.execute('ALTER TABLE appointments ADD COLUMN doctor_hospital TEXT')

    # Add missing columns for existing databases
    cursor.execute("PRAGMA table_info(appointments)")
    appointment_columns = [row[1] for row in cursor.fetchall()]
    if 'location' not in appointment_columns:
        cursor.execute('ALTER TABLE appointments ADD COLUMN location TEXT')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password TEXT
        )
    ''')

    # Default super-admin
    cursor.execute("SELECT * FROM admins WHERE username='admin'")
    if not cursor.fetchone():
        hashed = generate_password_hash("1234")
        cursor.execute("INSERT INTO admins (username,password,hospital,role) VALUES (?,?,?,?)", ("admin", hashed, "Default Hospital", "super"))
    conn.close()

# ---------------- HOME ----------------
@app.route('/')
def home():
    conn = sqlite3.connect('healthcare.db')
    cursor = conn.cursor()
    # fetch active doctors only (so people don’t book inactive ones)
    cursor.execute("SELECT name, specialization, location FROM doctors WHERE is_active=1")
    doctors = cursor.fetchall()
    conn.close()

    # compute specialization list (unique, in insertion order)
    specializations = []
    for _, spec, _ in doctors:
        if spec not in specializations:
            specializations.append(spec)

    return render_template('index.html', doctors=doctors, specializations=specializations)


# Ensure DB schema exists even if the app is imported elsewhere (and for tests)
# (No-op if already initialized.)
@app.before_request
def _ensure_db_initialized():
    # init_db is idempotent (CREATE TABLE IF NOT EXISTS + column checks)
    init_db()


# ---------------- BOOK ----------------
@app.route('/book', methods=['POST'])
def book():
    # Use .get() to avoid BadRequestKeyError when the browser submits without required fields
    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip()
    doctor = request.form.get('doctor', '').strip()
    date = request.form.get('date', '').strip()
    location = request.form.get('location', '').strip()

    if not name or not email or not doctor or not date or not location:
        flash('Please fill all booking fields and select a doctor.')
        return redirect('/')


    # determine doctor hospital so admin sees only relevant appointments
    conn = sqlite3.connect('healthcare.db')
    cursor = conn.cursor()
    cursor.execute("SELECT hospital FROM doctors WHERE name=?", (doctor,))
    row = cursor.fetchone()
    doctor_hospital = row[0] if row else ''

    if not row:
        conn.close()
        flash('Selected doctor is not available. Please choose a valid doctor.')
        return redirect('/')

    data = (name, email, doctor, doctor_hospital, date, location)

    cursor.execute("INSERT INTO appointments (name,email,doctor,doctor_hospital,date,location) VALUES (?,?,?,?,?,?)", data)
    conn.commit()
    conn.close()

    # send confirmation email to user
    subject = "Appointment Confirmation"
    body = f"Dear {name},\n\nYour appointment with Dr. {doctor} on {date} has been booked successfully.\n\nThank you for choosing HealthCare+.\n"
    try:
        send_email(email, subject, body)
        flash("Appointment Booked Successfully! Confirmation email sent.")
    except Exception as e:
        # send_email already prints error; also show user flash
        flash("Appointment Booked Successfully! Could not send confirmation email.")
        print(f"Email error: {e}")

    return redirect('/')

# ---------------- LOGIN ----------------
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('healthcare.db')
        cursor = conn.cursor()
        cursor.execute("SELECT password, hospital, role FROM admins WHERE username=?", (username,))
        data = cursor.fetchone()
        conn.close()

        if data and check_password_hash(data[0], password):
            # store admin context: username + hospital + role
            session['admin'] = username
            session['hospital'] = data[1] if len(data) > 1 else None
            session['admin_role'] = data[2] if len(data) > 2 else 'hospital'
            return redirect('/dashboard')
        else:
            flash("Invalid Credentials")

    return render_template('login.html')


@app.route('/admin_register', methods=['GET', 'POST'])
def admin_register():
    if 'admin' not in session or session.get('admin_role') != 'super':
        return redirect('/login')

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        hospital = request.form.get('hospital', '').strip()

        if role == 'hospital' and not hospital:
            flash('Hospital is required for hospital admins')
            return redirect('/admin_register')

        conn = sqlite3.connect('healthcare.db')
        cursor = conn.cursor()
        hashed = generate_password_hash(password)
        cursor.execute(
            "INSERT OR IGNORE INTO admins (username,password,hospital,role) VALUES (?,?,?,?)",
            (username, hashed, hospital, role)
        )
        conn.commit()
        conn.close()
        flash(f"New {role} admin created for hospital: {hospital or 'N/A'}")
        return redirect('/dashboard')

    return render_template('admin_register.html')


@app.route('/doctor_login', methods=['GET', 'POST'])
def doctor_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = sqlite3.connect('healthcare.db')
        cursor = conn.cursor()
        cursor.execute("SELECT name, password, hospital FROM doctors WHERE email=?", (email,))
        data = cursor.fetchone()
        conn.close()

        if data and data[1] and check_password_hash(data[1], password):
            session['doctor'] = email
            session['doctor_name'] = data[0]
            session['doctor_hospital'] = data[2]
            return redirect('/doctor_dashboard')
        else:
            flash('Invalid doctor credentials')

    return render_template('doctor_login.html')


@app.route('/doctor_reset', methods=['GET', 'POST'])
def doctor_reset():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = sqlite3.connect('healthcare.db')
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM doctors WHERE email=?", (email,))
        if cursor.fetchone():
            hashed = generate_password_hash(password)
            cursor.execute("UPDATE doctors SET password=? WHERE email=?", (hashed, email))
            conn.commit()
            flash('Password reset successfully')
        else:
            flash('No doctor found with that email')
        conn.close()
        return redirect('/doctor_login')

    return render_template('doctor_reset.html')


@app.route('/doctor_dashboard')
def doctor_dashboard():
    if 'doctor' not in session:
        return redirect('/doctor_login')

    doctor_name = session.get('doctor_name')
    doctor_hospital = session.get('doctor_hospital')

    conn = sqlite3.connect('healthcare.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, name, email, doctor, date, location, doctor_hospital
        FROM appointments
        WHERE doctor=? AND doctor_hospital=?
        ORDER BY date DESC
    ''', (doctor_name, doctor_hospital))
    appointments = cursor.fetchall()
    conn.close()

    return render_template('doctor_dashboard.html',
                           doctor_name=doctor_name,
                           doctor_hospital=doctor_hospital,
                           appointments=appointments)


@app.route('/doctor_cancel/<int:id>')
def doctor_cancel(id):
    if 'doctor' not in session:
        return redirect('/doctor_login')

    conn = sqlite3.connect('healthcare.db')
    cursor = conn.cursor()
    # ensure doctor owns this appointment
    cursor.execute("SELECT doctor, doctor_hospital FROM appointments WHERE id=?", (id,))
    row = cursor.fetchone()
    if row and row[0] == session.get('doctor_name') and row[1] == session.get('doctor_hospital'):
        cursor.execute("DELETE FROM appointments WHERE id=?", (id,))
        conn.commit()
    conn.close()
    return redirect('/doctor_dashboard')


@app.route('/doctor_edit/<int:id>', methods=['GET', 'POST'])
def doctor_edit(id):
    if 'doctor' not in session:
        return redirect('/doctor_login')

    conn = sqlite3.connect('healthcare.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, name, email, doctor, date, location, doctor_hospital FROM appointments WHERE id=?', (id,))
    appointment = cursor.fetchone()

    if not appointment or appointment[3] != session.get('doctor_name') or appointment[6] != session.get('doctor_hospital'):
        conn.close()
        return redirect('/doctor_dashboard')

    if request.method == 'POST':
        new_date = request.form['date']
        new_location = request.form['location']
        cursor.execute('UPDATE appointments SET date=?, location=? WHERE id=?', (new_date, new_location, id))
        conn.commit()
        conn.close()
        return redirect('/doctor_dashboard')

    conn.close()
    return render_template('doctor_edit.html', appointment=appointment)


# ---------------- USER LOGIN/REGISTER ----------------
@app.route('/user_login', methods=['GET','POST'])
def user_login():
    # simple form where email/password authenticates or registers new user
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = sqlite3.connect('healthcare.db')
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE email=?", (email,))
        data = cursor.fetchone()

        if data:
            # existing user, check password
            if check_password_hash(data[0], password):
                session['user'] = email
                conn.close()
                return redirect('/')
            else:
                flash("Invalid username or password")
        else:
            # register new user
            hashed = generate_password_hash(password)
            cursor.execute("INSERT INTO users (email,password) VALUES (?,?)", (email, hashed))
            conn.commit()
            session['user'] = email
            conn.close()
            flash("Account created and logged in")
            return redirect('/')

        conn.close()

    return render_template('user_login.html', google_signin_available=(make_google_blueprint is not None))

@app.route('/logout')
def logout():
    # clear all session roles
    session.pop('admin', None)
    session.pop('user', None)
    session.pop('doctor', None)
    session.pop('doctor_name', None)
    session.pop('doctor_hospital', None)
    session.pop('hospital', None)
    return redirect('/')


# Google OAuth callback handler (works when Flask-Dance is installed)
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
        # create user record if not exists
        conn = sqlite3.connect('healthcare.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE email=?', (email,))
        if not cursor.fetchone():
            # create a disabled/random password entry since auth is via Google
            cursor.execute('INSERT INTO users (email,password) VALUES (?,?)', (email, 'google-oauth'))
            conn.commit()
        conn.close()

        session['user'] = email
        flash('Logged in with Google: ' + email)
        return redirect('/')

    flash('Google login failed.')
    return redirect('/user_login')

# ---------------- DASHBOARD ----------------
@app.route('/dashboard')
def dashboard():
    if 'admin' not in session:
        return redirect('/login')

    conn = sqlite3.connect('healthcare.db')
    cursor = conn.cursor()

    if session.get('admin_role') == 'super':
        cursor.execute("SELECT COUNT(*) FROM appointments")
        total_appointments = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM doctors")
        total_doctors = cursor.fetchone()[0]

        cursor.execute('''
            SELECT a.id, a.name, a.email, a.doctor, a.date, a.location, d.specialization
            FROM appointments a
            LEFT JOIN doctors d ON a.doctor = d.name
        ''')
        appointments = cursor.fetchall()
    else:
        cursor.execute("SELECT COUNT(*) FROM appointments WHERE doctor_hospital=?", (session.get('hospital'),))
        total_appointments = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM doctors WHERE hospital=?", (session.get('hospital'),))
        total_doctors = cursor.fetchone()[0]

        cursor.execute('''
            SELECT a.id, a.name, a.email, a.doctor, a.date, a.location, d.specialization
            FROM appointments a
            LEFT JOIN doctors d ON a.doctor = d.name
            WHERE a.doctor_hospital = ?
        ''', (session.get('hospital'),))
        appointments = cursor.fetchall()

    # hospital report
    if session.get('admin_role') == 'super':
        cursor.execute('''
            SELECT doctor_hospital, COUNT(*)
            FROM appointments
            GROUP BY doctor_hospital
        ''')
        hospital_report = cursor.fetchall()
    else:
        cursor.execute('''
            SELECT doctor_hospital, COUNT(*)
            FROM appointments
            WHERE doctor_hospital = ?
            GROUP BY doctor_hospital
        ''', (session.get('hospital'),))
        hospital_report = cursor.fetchall()

    conn.close()

    return render_template('dashboard.html',
                           total_appointments=total_appointments,
                           total_doctors=total_doctors,
                           appointments=appointments,
                           hospital_report=hospital_report)

# ---------------- DELETE ----------------
@app.route('/delete/<int:id>')
def delete(id):
    conn = sqlite3.connect('healthcare.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM appointments WHERE id=?", (id,))
    conn.commit()
    conn.close()
    return redirect('/dashboard')

@app.route('/delete_doctor/<int:id>')
def delete_doctor(id):
    conn = sqlite3.connect('healthcare.db')
    cursor = conn.cursor()
    # Soft-delete: mark doctor inactive so it can be restored.
    cursor.execute("UPDATE doctors SET is_active=0 WHERE id=?", (id,))
    conn.commit()
    conn.close()
    return redirect('/doctors')

@app.route('/doctors_all')
def doctors_all():
    if 'admin' not in session:
        return redirect('/login')

    conn = sqlite3.connect('healthcare.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM doctors")
    data = cursor.fetchall()
    conn.close()

    return render_template('doctors.html', doctors=data, audit=[])

@app.route('/restore_doctor/<int:id>')
def restore_doctor(id):
    conn = sqlite3.connect('healthcare.db')
    cursor = conn.cursor()
    cursor.execute("UPDATE doctors SET is_active=1 WHERE id=?", (id,))
    conn.commit()
    conn.close()
    return redirect('/doctors')

@app.route('/purge_doctor/<int:id>')
def purge_doctor(id):
    conn = sqlite3.connect('healthcare.db')
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM doctors WHERE id=?", (id,))
    row = cursor.fetchone()
    if row:
        doctor_name = row[0]
        cursor.execute("DELETE FROM appointments WHERE doctor=?", (doctor_name,))
        cursor.execute("DELETE FROM doctors WHERE id=?", (id,))
        # audit log
        cursor.execute(
            "INSERT INTO doctor_audit (doctor_id, doctor_name, doctor_hospital, action, admin_username, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
            (id, doctor_name, session.get('hospital'), 'purge', session.get('admin'), datetime.datetime.utcnow().isoformat())
        )
        conn.commit()
    conn.close()
    return redirect('/doctors')

# ---------------- DOCTORS ----------------
@app.route('/doctors', methods=['GET','POST'])
def doctors():
    if 'admin' not in session:
        return redirect('/login')

    if request.method == 'POST':
        hospital = session.get('hospital', 'Default Hospital')
        if session.get('admin_role') == 'super':
            # super admin can assign any hospital (optional)
            hospital = request.form.get('hospital', hospital).strip() or hospital

        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        hashed = generate_password_hash(password) if password else None
        data = (
            request.form['name'],
            request.form['specialization'],
            request.form.get('location', ''),
            hospital,
            email,
            hashed,
        )
        conn = sqlite3.connect('healthcare.db')
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO doctors (name,specialization,location,hospital,email,password) VALUES (?,?,?,?,?,?)",
                data,
            )
            conn.commit()
        except sqlite3.IntegrityError as e:
            flash('Error adding doctor: ' + str(e))
        finally:
            conn.close()

        return redirect('/doctors')

    conn = sqlite3.connect('healthcare.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM doctors WHERE hospital=?", (session.get('hospital'),))
    data = cursor.fetchall()

    cursor.execute("SELECT id, doctor_id, doctor_name, action, admin_username, timestamp FROM doctor_audit WHERE doctor_hospital=? ORDER BY timestamp DESC LIMIT 25", (session.get('hospital'),))
    audit = cursor.fetchall()

    conn.close()

    return render_template('doctors.html', doctors=data, audit=audit)

    conn.close()

    return render_template('doctors.html', doctors=data, audit=audit)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
