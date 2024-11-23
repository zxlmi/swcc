from flask import Flask, render_template, request, redirect, url_for, session, g
from io import BytesIO
from flask import send_file
from flask_mail import Mail, Message
from datetime import timedelta
import sqlite3
import bcrypt
import pyotp
import qrcode
import hashlib
import random

# Flask application setup
app = Flask(__name__)
app.secret_key = "supersecretkey"  # To manage sessions (required by Flask)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USE_SSL=False,
       SESSION_COOKIE_SECURE=True,  # Only sent over HTTPS
    SESSION_COOKIE_HTTPONLY=True,  # Cannot be accessed by JavaScript
    MAIL_USERNAME='kl2311015266@student.uptm.edu.my',
    MAIL_PASSWORD='feqg fodq tftn bsgi',  # App Password
)

mail = Mail(app)

# Database
DATABASE = 'members.db'

# Generate a secret for MFA (to be stored in your database per user)
def generate_totp_secret():
    return pyotp.random_base32()

# Password hashing Disini
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode('utf-8')

#Function check hashed passworc match or not
def check_password(stored_password, provided_password):
    return bcrypt.checkpw(provided_password.encode(), stored_password.encode())

# Simple user store for staff and members (no security library)
USERS = {
    "staff": {"password": hash_password("staffpass"), "role": "staff", "totp_secret": generate_totp_secret()},
    "member": {"password": hash_password("memberpass"), "role": "member", "totp_secret": generate_totp_secret()},
    "pakkarim": {"password": hash_password("karim"), "role": "staff", "totp_secret": generate_totp_secret()},
}

# Helper function to connect ke SQLite database securely
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

#function for safely query the database guna paramterized untuk prevent SQL
def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args) # sini parameter querie 
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

@app.before_request
def create_tables():
    db = get_db()
    db.execute('''CREATE TABLE IF NOT EXISTS members (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    membership_status TEXT NOT NULL,
                    email TEXT NOT NULL UNIQUE,  
                    password TEXT NOT NULL
                  )''')
    db.execute('''CREATE TABLE IF NOT EXISTS classes (
                    id INTEGER PRIMARY KEY,
                    class_name TEXT NOT NULL,
                    class_time TEXT NOT NULL
                  )''')
    db.execute('''CREATE TABLE IF NOT EXISTS member_classes (
                    member_id INTEGER,
                    class_id INTEGER,
                    FOREIGN KEY (member_id) REFERENCES members (id),
                    FOREIGN KEY (class_id) REFERENCES classes (id)
                  )''')
    db.commit()

# Home Route (Login)
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in USERS:
            stored_password = USERS[username]['password']
            if check_password(stored_password, password):  # Using bcrypt for password verification
                session['user'] = username
                session['role'] = USERS[username]['role']
                return redirect(url_for('mfa'))
        return "SUDAH CAKAP JANGAN CUBA CUBA."
    return render_template('login.html')


# MFA disini
@app.route('/mfa', methods=['GET', 'POST'])
def mfa():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        code = request.form['mfa_code']
        if code == session.get('mfa_code'):
            return redirect(url_for('dashboard'))
        else:
            return "DO`T TRY TO CUBA CUBA HACK YA !!"

    # Generate and send MFA code
    mfa_code = str(random.randint(100000, 999999))
    session['mfa_code'] = mfa_code
    recipient_email = "kl2311015266@student.uptm.edu.my"  # Replace with dynamic user email if needed

    # Create the email message
    msg = Message(
        subject='Ini MFA Code diam diam jangan share',
        sender='kl2311015266@student.uptm.edu.my',
        recipients=[recipient_email]
    )
    msg.body = f"Your MFA code is: {mfa_code}"

    try:
        # Send the email using Flask-Mail
        mail.send(msg)
    except Exception as e:
        return f"Failed to send email: {e}"

    return render_template('mfa.html')

@app.route('/qrcode')
def qrcode():
    if 'user' not in session:
        return redirect(url_for('login'))

    username = session['user']
    totp_secret = USERS[username]['totp_secret']
    totp = pyotp.TOTP(totp_secret)
    uri = totp.provisioning_uri(username, issuer_name="GymApp")
    
    # Generate QR code
    qr = qrcode.make(uri)
    img_io = BytesIO()
    qr.save(img_io, 'PNG')
    img_io.seek(0)
    return send_file(img_io, mimetype='image/png')

# Dashboard (for both staff and members)
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    username = session['user']
    return render_template('dashboard.html', username=username)

# Register New Member
@app.route('/register_member', methods=['GET', 'POST'])
def register_member():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name']
        status = request.form['status']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if not name or not status or not email or not password or not confirm_password:
            return "All fields are required."
        
        if password != confirm_password:
            return "Passwords do not match!"
        
        # Check if email already exists
        existing_member = query_db("SELECT * FROM members WHERE email = ?", [email], one=True)
        if existing_member:
            return "Email already registered!"
        
        hashed_password = hash_password(password)
        
        db = get_db()

        # Use parameterized query to avoid SQL preventation kt sini
        db.execute("INSERT INTO members (name, membership_status, email, password) VALUES (?, ?, ?, ?)", 
                   (name.strip(), status.strip(), email.strip(), hashed_password))
        db.commit()
        return redirect(url_for('view_members'))
    
    return render_template('register_member.html')

# Member Management Routes
@app.route('/add_member', methods=['GET', 'POST'])
def add_member():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name']
        status = request.form['status']
        
        # Validate input
        if not name or not status:
            return "Invalid input! Name and status are required."
        
        db = get_db()
        db.execute("INSERT INTO members (name, membership_status) VALUES (?, ?)", (name.strip(), status.strip()))
        db.commit()
        return redirect(url_for('view_members'))
    
    return render_template('add_member.html')

# View specific member classes
@app.route('/member/<int:member_id>/classes')
def member_classes(member_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Get member classes
    member = query_db("SELECT * FROM members WHERE id = ?", [member_id], one=True)
    classes = query_db("SELECT c.class_name, c.class_time FROM classes c "
                        "JOIN member_classes mc ON c.id = mc.class_id "
                        "WHERE mc.member_id = ?", [member_id])
    
    return render_template('member_classes.html', member=member, classes=classes)

# Register class
@app.route('/register_class/<int:member_id>', methods=['GET', 'POST'])
def register_class(member_id):
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))

    classes = query_db("SELECT * FROM classes")  # Get all available classes
    if request.method == 'POST':
        class_id = request.form['class_id']
        db = get_db()
        db.execute("INSERT INTO member_classes (member_id, class_id) VALUES (?, ?)", (member_id, class_id))
        db.commit()
        return redirect(url_for('member_classes', member_id=member_id))
    
    return render_template('register_class.html', member_id=member_id, classes=classes)

# View users
@app.route('/view_members')
def view_members():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    members = query_db("SELECT * FROM members")
    return render_template('view_members.html', members=members)

# Class Scheduling Routes
@app.route('/add_class', methods=['GET', 'POST'])
def add_class():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        class_name = request.form['class_name']
        class_time = request.form['class_time']
        db = get_db()
        db.execute("INSERT INTO classes (class_name, class_time) VALUES (?, ?)", (class_name, class_time))
        db.commit()
        return redirect(url_for('view_classes'))
    
    return render_template('add_class.html')

@app.route('/view_classes')
def view_classes():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    classes = query_db("SELECT * FROM classes")
    return render_template('view_classes.html', classes=classes)

# Deleting member
@app.route('/delete_member/<int:member_id>', methods=['POST'])
def delete_member(member_id):
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    db = get_db()
    # Use parameterized query here
    db.execute("DELETE FROM members WHERE id = ?", [member_id])
    db.commit()
    return redirect(url_for('view_members'))


# Logout
@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('role', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
