
from flask import Flask, render_template, request, redirect, url_for, session, g, flash, send_file, jsonify
import sqlite3, os, time, datetime, random, json, base64, hashlib
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet, InvalidToken
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, 'app.db')
UPLOAD_DIR = os.path.join(APP_DIR, 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = 'replace_this_with_a_secure_random_key'

# ---------- DB helpers ----------
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.executescript('''
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        points INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS scans(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT,
        size_bytes INTEGER,
        extension TEXT,
        yara_hit INTEGER DEFAULT 0,
        suspicious_name INTEGER DEFAULT 0,
        anomaly_ext INTEGER DEFAULT 0,
        score INTEGER DEFAULT 0,
        label TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS events(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER,
        kind TEXT,
        detail TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(scan_id) REFERENCES scans(id)
    );
    CREATE TABLE IF NOT EXISTS notes(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT,
        title TEXT,
        blob BLOB,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    ''' )
    db.commit()

# ---------- utils ----------
def current_user():
    return session.get('username')

def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            return redirect(url_for('login'))
        return fn(*args, **kwargs)
    return wrapper

def fernet_for_user(user):
    # Not production-grade; for demo we derive a key from app secret + username
    keyseed = (app.secret_key + '::' + user).encode('utf-8')
    d = hashlib.sha256(keyseed).digest()
    key = base64.urlsafe_b64encode(d)
    return Fernet(key)

# ---------- risk engine ----------
SUSPICIOUS = ['malware','ransom','trojan','worm','suspicious','hack','exploit','keylog']
RARE_EXTS = ['exe','scr','js','vbs','ps1','bat','cmd','dll','sys']

def try_yara(filepath):
    try:
        import yara
        RULE = """
rule DummyMalware
{
    strings:
        $a = "malware"
        $b = "ransom"
    condition:
        any of them
}
"""
        rule = yara.compile(source=RULE)
        return 1 if rule.match(filepath) else 0
    except Exception:
        return 0

def compute_score(filename, filepath):
    name = filename.lower()
    size = os.path.getsize(filepath)
    ext = (os.path.splitext(name)[1][1:] or '').lower()

    yara_hit = try_yara(filepath)
    suspicious_name = any(k in name for k in SUSPICIOUS)
    anomaly_ext = 1 if ext in RARE_EXTS else 0

    score = 0
    score += 45 if yara_hit else 0
    score += 25 if suspicious_name else 0
    score += 15 if anomaly_ext else 0
    score += 10 if size > 5*1024*1024 else 0  # >5MB
    score += 5 if size == 0 else 0

    label = 'Low'
    if score >= 70: label = 'High'
    elif score >= 40: label = 'Medium'

    return {'size': size, 'ext': ext, 'yara_hit': int(bool(yara_hit)),
            'suspicious_name': int(bool(suspicious_name)),
            'anomaly_ext': int(bool(anomaly_ext)),
            'score': int(score), 'label': label}

def simulated_behavior(label):
    base = ['Reads user documents','Creates temp files','Checks OS version']
    med = ['Modifies registry','Creates startup entry','Contacts unknown domain']
    high = ['Encrypts files','Exfiltrates data','Stops security service']
    if label=='High': return base+med+high
    if label=='Medium': return base+med
    return base

# ---------- routes ----------
@app.route('/')
def home():
    return render_template('index.html', user=current_user())

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        u = request.form.get('username','').strip()
        p = request.form.get('password','')
        if not u or not p:
            flash('Enter username and password', 'error')
            return render_template('login.html')
        db = get_db()
        row = db.execute('SELECT * FROM users WHERE username=?', (u,)).fetchone()
        if row and check_password_hash(row['password_hash'], p):
            session['username'] = u
            flash('Welcome back, '+u, 'notice')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method=='POST':
        u = request.form.get('username','').strip()
        p = request.form.get('password','')
        if len(u)<3 or len(p)<4:
            flash('Username 3+ chars, password 4+ chars', 'error')
            return render_template('register.html')
        db = get_db()
        try:
            db.execute('INSERT INTO users(username,password_hash) VALUES(?,?)',
                       (u, generate_password_hash(p)))
            db.commit()
            flash('Registration successful. Please login.', 'notice')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists', 'error')
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    counts = {'High':0,'Medium':0,'Low':0}
    for r in db.execute('SELECT label, COUNT(*) c FROM scans GROUP BY label'):
        counts[r['label']] = r['c']
    total = sum(counts.values())
    recent = db.execute('SELECT * FROM scans ORDER BY id DESC LIMIT 6').fetchall()
    # leaderboard
    top = db.execute('SELECT username, points FROM users ORDER BY points DESC, username LIMIT 10').fetchall()
    return render_template('dashboard.html', user=current_user(), counts=counts, total=total, recent=recent, top=top)

@app.route('/timeline')
@login_required
def timeline():
    db = get_db()
    events = db.execute('''SELECT e.*, s.filename FROM events e
                           LEFT JOIN scans s ON s.id=e.scan_id
                           ORDER BY e.id DESC LIMIT 50''').fetchall()
    return render_template('timeline.html', user=current_user(), events=events)

@app.route('/scan', methods=['GET','POST'])
@login_required
def scan():
    result = None; behaviors = []
    if request.method=='POST':
        f = request.files.get('file')
        if not f or f.filename=='':
            flash('No file selected', 'error')
            return render_template('scan.html', user=current_user())
        filename = secure_filename(f.filename)
        path = os.path.join(UPLOAD_DIR, filename)
        f.save(path)

        metrics = compute_score(filename, path)
        db = get_db()
        cur = db.execute('''INSERT INTO scans(filename,size_bytes,extension,yara_hit,
                        suspicious_name,anomaly_ext,score,label)
                        VALUES(?,?,?,?,?,?,?,?)''',
                        (filename, metrics['size'], metrics['ext'],
                         metrics['yara_hit'], metrics['suspicious_name'],
                         metrics['anomaly_ext'], metrics['score'], metrics['label']))
        scan_id = cur.lastrowid
        db.commit()

        # Events
        db.execute('INSERT INTO events(scan_id,kind,detail) VALUES(?,?,?)',
                   (scan_id, 'UPLOAD', f'File {filename} uploaded'))
        db.execute('INSERT INTO events(scan_id,kind,detail) VALUES(?,?,?)',
                   (scan_id, 'ANALYZE', f'Ext:{metrics["ext"]} YARA:{metrics["yara_hit"]} SusName:{metrics["suspicious_name"]} RareExt:{metrics["anomaly_ext"]}'))
        db.execute('INSERT INTO events(scan_id,kind,detail) VALUES(?,?,?)',
                   (scan_id, 'SCORE', f'Risk score {metrics["score"]} => {metrics["label"]}'))
        db.commit()

        # Behavior + simulator points reward
        behaviors = simulated_behavior(metrics['label'])
        db.execute('INSERT INTO events(scan_id,kind,detail) VALUES(?,?,?)',
                   (scan_id, 'SIM', 'Behavior preview: '+', '.join(behaviors[:3])+' ...'))
        # Reward user
        db.execute('UPDATE users SET points = points + ? WHERE username=?',
                   ( 30 if metrics['label']=='High' else (15 if metrics['label']=='Medium' else 8), current_user()))
        db.commit()

        result = {'id': scan_id, 'filename': filename, **metrics}
    return render_template('scan.html', user=current_user(), result=result, behaviors=behaviors)

@app.route('/report/<int:scan_id>')
@login_required
def report(scan_id):
    db = get_db()
    s = db.execute('SELECT * FROM scans WHERE id=?', (scan_id,)).fetchone()
    if not s:
        flash('Scan not found', 'error')
        return redirect(url_for('dashboard'))
    out = os.path.join(APP_DIR, f'report_{scan_id}.pdf')
    c = canvas.Canvas(out, pagesize=A4)
    w,h = A4
    y = h-50
    c.setTitle(f"Cyber Triage Report #{scan_id}")
    c.setFont("Helvetica-Bold",16); c.drawString(40,y,f"Cyber Triage Report #{scan_id}"); y-=28
    c.setFont("Helvetica",11)
    c.drawString(40,y,f"Filename: {s['filename']}"); y-=16
    c.drawString(40,y,f"Score: {s['score']}  |  Label: {s['label']}"); y-=16
    c.drawString(40,y,f"Size: {s['size_bytes']}  |  Ext: {s['extension']}"); y-=16
    c.drawString(40,y,f"YARA:{s['yara_hit']}  SuspName:{s['suspicious_name']}  RareExt:{s['anomaly_ext']}"); y-=20
    ev = db.execute('SELECT * FROM events WHERE scan_id=? ORDER BY id DESC LIMIT 10',(scan_id,)).fetchall()
    c.setFont("Helvetica-Bold",12); c.drawString(40,y,"Timeline:"); y-=16
    c.setFont("Helvetica",10)
    for e in ev:
        txt = f"[{e['created_at']}] {e['kind']}: {e['detail']}"
        for line in [txt[i:i+95] for i in range(0,len(txt),95)]:
            c.drawString(44,y,line); y-=14
            if y<60: c.showPage(); y=h-50; c.setFont("Helvetica",10)
    c.showPage(); c.save()
    return send_file(out, as_attachment=True)

# ---- Gamified Attack Simulator ----
@app.route('/simulator', methods=['GET','POST'])
@login_required
def simulator():
    # simple scenario selection and scoring
    scenarios = [
        {'id':1, 'name':'Phishing Dropper', 'desc':'Suspicious email drops executable in Downloads'},
        {'id':2, 'name':'Lateral Movement', 'desc':'JS file launches PowerShell to connect to admin share'},
        {'id':3, 'name':'Data Exfil', 'desc':'Zip files created and uploaded to unknown host'},
    ]
    result=None
    if request.method=='POST':
        choice = request.form.get('choice')
        if not choice:
            flash('Pick a scenario to defend', 'error')
        else:
            pts = random.randint(10,25)
            get_db().execute('UPDATE users SET points = points + ? WHERE username=?', (pts, current_user()))
            get_db().commit()
            result={'msg': f'Defended scenario #{choice}! +{pts} points', 'pts': pts}
    return render_template('simulator.html', user=current_user(), scenarios=scenarios, result=result)

# ---- Leaderboard ----
@app.route('/leaderboard')
@login_required
def leaderboard():
    rows = get_db().execute('SELECT username, points, created_at FROM users ORDER BY points DESC, username LIMIT 20').fetchall()
    return render_template('leaderboard.html', user=current_user(), rows=rows)

# ---- Secure Notes (AES/Fernet) ----
@app.route('/notes', methods=['GET','POST'])
@login_required
def notes():
    db = get_db()
    if request.method=='POST':
        title = request.form.get('title','').strip() or 'Untitled'
        content = request.form.get('content','')
        f = fernet_for_user(current_user())
        token = f.encrypt(content.encode('utf-8'))
        db.execute('INSERT INTO notes(user,title,blob) VALUES(?,?,?)', (current_user(), title, token))
        db.commit()
        flash('Note saved securely ✓', 'notice')
    items = db.execute('SELECT id,title,created_at FROM notes WHERE user=? ORDER BY id DESC', (current_user(),)).fetchall()
    return render_template('notes.html', user=current_user(), items=items)

@app.route('/notes/<int:note_id>')
@login_required
def note_read(note_id):
    db = get_db()
    row = db.execute('SELECT * FROM notes WHERE id=? AND user=?', (note_id, current_user())).fetchone()
    if not row: 
        flash('Note not found', 'error'); 
        return redirect(url_for('notes'))
    f = fernet_for_user(current_user())
    try:
        text = f.decrypt(row['blob']).decode('utf-8')
    except InvalidToken:
        text = '[decryption error]'
    return render_template('note_read.html', user=current_user(), title=row['title'], text=text, created=row['created_at'])

# ---------- start ----------
if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(debug=True)
