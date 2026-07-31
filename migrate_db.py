"""
Migration script for HealthCare Solutions SQLite database (healthcare.db).

This script performs safe, non-destructive schema normalization steps:
- Adds `hospitals` table and populates it from existing hospital text values.
- Adds `hospital_id` to `admins` and `doctors` and populates it (keeps original `hospital` text column).
- Adds `doctor_id` to `appointments` and populates it by matching doctor name+hospital.
- Adds useful indexes and a read-only view `appointments_full` joining appointments -> doctors.

It avoids dropping existing columns to preserve backward compatibility with the running
application. At the end it prints recommended destructive SQL to finalize normalization
once application code is updated to use the new normalized fields.

Usage:
    python migrate_db.py

Make a backup of `healthcare.db` before running.
"""

import sqlite3
import os
import sys
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), 'healthcare.db')


def log(msg):
    print(f"[{datetime.utcnow().isoformat()}] {msg}")


def table_exists(conn, name):
    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,))
    return cur.fetchone() is not None


def column_exists(conn, table, column):
    cur = conn.execute(f"PRAGMA table_info({table})")
    cols = [r[1] for r in cur.fetchall()]
    return column in cols


def run():
    if not os.path.exists(DB_PATH):
        log(f"Database not found at {DB_PATH}")
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    try:
        log('Starting migration (non-destructive)')
        # 1) Create hospitals table
        if not table_exists(conn, 'hospitals'):
            log('Creating table: hospitals')
            cur.execute('''
                CREATE TABLE hospitals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE
                )
            ''')

        # populate hospitals from admins and doctors
        log('Populating hospitals from admins and doctors')
        cur.execute("SELECT DISTINCT hospital FROM admins WHERE hospital IS NOT NULL AND TRIM(hospital)<>''")
        for row in cur.fetchall():
            name = row[0]
            if name:
                try:
                    cur.execute('INSERT OR IGNORE INTO hospitals (name) VALUES (?)', (name,))
                except Exception:
                    pass

        cur.execute("SELECT DISTINCT hospital FROM doctors WHERE hospital IS NOT NULL AND TRIM(hospital)<>''")
        for row in cur.fetchall():
            name = row[0]
            if name:
                try:
                    cur.execute('INSERT OR IGNORE INTO hospitals (name) VALUES (?)', (name,))
                except Exception:
                    pass

        # 2) Add hospital_id to admins and doctors (keep existing text column)
        for tbl in ('admins', 'doctors'):
            if not column_exists(conn, tbl, 'hospital_id'):
                log(f'Adding column {tbl}.hospital_id')
                cur.execute(f'ALTER TABLE {tbl} ADD COLUMN hospital_id INTEGER')

        # set hospital_id values by joining on hospitals.name
        log('Updating admins.hospital_id')
        cur.execute("SELECT id, hospital FROM admins")
        for row in cur.fetchall():
            aid = row[0]
            hname = row[1]
            if hname:
                cur.execute('SELECT id FROM hospitals WHERE name=?', (hname,))
                r = cur.fetchone()
                if r:
                    cur.execute('UPDATE admins SET hospital_id=? WHERE id=?', (r[0], aid))

        log('Updating doctors.hospital_id')
        cur.execute("SELECT id, hospital FROM doctors")
        for row in cur.fetchall():
            did = row[0]
            hname = row[1]
            if hname:
                cur.execute('SELECT id FROM hospitals WHERE name=?', (hname,))
                r = cur.fetchone()
                if r:
                    cur.execute('UPDATE doctors SET hospital_id=? WHERE id=?', (r[0], did))

        # 3) Add doctor_id to appointments and populate by matching name+hospital
        if not column_exists(conn, 'appointments', 'doctor_id'):
            log('Adding column appointments.doctor_id')
            cur.execute('ALTER TABLE appointments ADD COLUMN doctor_id INTEGER')

        log('Populating appointments.doctor_id by matching doctors')
        cur.execute('SELECT id, name, hospital FROM doctors')
        doctors = cur.fetchall()
        # build quick lookup map (name, hospital) -> id
        doc_map = {}
        for d in doctors:
            key = (d['name'], d['hospital'])
            doc_map[key] = d['id']

        cur.execute('SELECT id, doctor, doctor_hospital FROM appointments')
        for row in cur.fetchall():
            appt_id = row['id']
            dname = row['doctor']
            dhosp = row['doctor_hospital']
            key = (dname, dhosp)
            did = doc_map.get(key)
            if did:
                cur.execute('UPDATE appointments SET doctor_id=? WHERE id=?', (did, appt_id))

        # 4) Create useful indexes
        log('Creating indexes')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_hospitals_name ON hospitals(name)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_doctors_hospital_id ON doctors(hospital_id)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_doctors_email ON doctors(email)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_appointments_doctor_id ON appointments(doctor_id)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_appointments_date ON appointments(date)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_appointments_email ON appointments(email)')

        # 5) Create a view that joins appointments with doctors for compatibility
        log('Creating view appointments_full (read-only join)')
        cur.execute('DROP VIEW IF EXISTS appointments_full')
        cur.execute('''
            CREATE VIEW appointments_full AS
            SELECT a.id AS id,
                   a.name AS patient_name,
                   a.email AS patient_email,
                   a.doctor AS doctor_name_text,
                   a.doctor_hospital AS doctor_hospital_text,
                   a.doctor_id AS doctor_id,
                   d.name AS doctor_name,
                   d.specialization AS doctor_specialization,
                   d.hospital AS doctor_hospital,
                   a.date AS date,
                   a.location AS location
            FROM appointments a
            LEFT JOIN doctors d ON a.doctor_id = d.id
        ''')

        conn.commit()

        log('Migration completed (non-destructive).')
        print('\nRecommended finalization SQL (run after code updates to use normalized fields):\n')
        print('''-- Remove textual redundancies and enforce foreign keys (destructive, run after code update and backup):
BEGIN TRANSACTION;
-- Example: create new appointments table without doctor text/hospital and with FK to doctors
CREATE TABLE appointments_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT,
    doctor_id INTEGER,
    date TEXT,
    location TEXT,
    FOREIGN KEY (doctor_id) REFERENCES doctors(id)
);
INSERT INTO appointments_new (id,name,email,doctor_id,date,location)
    SELECT id, name, email, doctor_id, date, location FROM appointments;
DROP TABLE appointments;
ALTER TABLE appointments_new RENAME TO appointments;
COMMIT;
''')

    except Exception as e:
        conn.rollback()
        log(f'Migration failed: {e}')
        raise
    finally:
        conn.close()


if __name__ == '__main__':
    run()
