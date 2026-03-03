from flask import Flask, render_template, request, redirect, session, flash, url_for
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
from email.mime.text import MIMEText
import os
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
            password TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS doctors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            specialization TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS appointments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT,
            doctor TEXT,
            date TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password TEXT
        )
    ''')

    # Default admin
    cursor.execute("SELECT * FROM admins WHERE username='admin'")
    if not cursor.fetchone():
        hashed = generate_password_hash("1234")
        cursor.execute("INSERT INTO admins (username,password) VALUES (?,?)", ("admin", hashed))

    conn.commit()
    conn.close()

# ---------------- HOME ----------------
@app.route('/')
def home():
    conn = sqlite3.connect('healthcare.db')
    cursor = conn.cursor()
    # fetch both name and specialization so users see full info
    cursor.execute("SELECT name, specialization FROM doctors")
    doctors = cursor.fetchall()
    conn.close()
    return render_template('index.html', doctors=doctors)

# ---------------- BOOK ----------------
@app.route('/book', methods=['POST'])
def book():
    name = request.form['name']
    email = request.form['email']
    doctor = request.form['doctor']
    date = request.form['date']

    data = (name, email, doctor, date)

    conn = sqlite3.connect('healthcare.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO appointments (name,email,doctor,date) VALUES (?,?,?,?)", data)
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
        cursor.execute("SELECT password FROM admins WHERE username=?", (username,))
        data = cursor.fetchone()
        conn.close()

        if data and check_password_hash(data[0], password):
            session['admin'] = True
            return redirect('/dashboard')
        else:
            flash("Invalid Credentials")

    return render_template('login.html')

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
    # clear both admin and user sessions
    session.pop('admin', None)
    session.pop('user', None)
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

    cursor.execute("SELECT COUNT(*) FROM appointments")
    total_appointments = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM doctors")
    total_doctors = cursor.fetchone()[0]

    # join to doctors table so specialization is available
    cursor.execute('''
        SELECT a.id, a.name, a.email, a.doctor, a.date, d.specialization
        FROM appointments a
        LEFT JOIN doctors d ON a.doctor = d.name
    ''')
    appointments = cursor.fetchall()

    conn.close()

    return render_template('dashboard.html',
                           total_appointments=total_appointments,
                           total_doctors=total_doctors,
                           appointments=appointments)

# ---------------- DELETE ----------------
@app.route('/delete/<int:id>')
def delete(id):
    conn = sqlite3.connect('healthcare.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM appointments WHERE id=?", (id,))
    conn.commit()
    conn.close()
    return redirect('/dashboard')

# ---------------- DOCTORS ----------------
@app.route('/doctors', methods=['GET','POST'])
def doctors():
    if request.method == 'POST':
        data = (request.form['name'], request.form['specialization'])
        conn = sqlite3.connect('healthcare.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO doctors (name,specialization) VALUES (?,?)", data)
        conn.commit()
        conn.close()
        return redirect('/doctors')

    conn = sqlite3.connect('healthcare.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM doctors")
    data = cursor.fetchall()
    conn.close()

    return render_template('doctors.html', doctors=data)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)