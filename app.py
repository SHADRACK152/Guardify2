import requests
from bs4 import BeautifulSoup
from transformers import pipeline
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit
from datetime import datetime
import os
import PyPDF2

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.secret_key = 'your_secret_key'
db = SQLAlchemy(app)
socketio = SocketIO(app)

# Initialize the Hugging Face pipeline with a question-answering model
qa_pipeline = pipeline("question-answering", model="distilbert-base-uncased-distilled-squad")

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    profile_picture = db.Column(db.String(120), nullable=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(120), nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    severity = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(50), nullable=False, default='Open')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    reported_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    severity = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(50), nullable=False, default='Open')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    reported_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    members = db.relationship('User', secondary='group_members', backref='groups')

group_members = db.Table('group_members',
    db.Column('group_id', db.Integer, db.ForeignKey('group.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password')
    return render_template('login.html')

@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        flash('Email already exists')
        return redirect(url_for('signup'))
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    user = User(username=username, email=email, password=hashed_password)
    db.session.add(user)
    db.session.commit()
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session.get('username'))

@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('home.html', username=session.get('username'))


@app.route('/upload_note', methods=['POST'])
def upload_note():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    file = request.files['file']
    if file:
        filename = secure_filename(file.filename)
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        os.makedirs(os.path.dirname(upload_path), exist_ok=True)
        file.save(upload_path)
        note = Note(filename=filename, uploaded_by=session['user_id'])
        db.session.add(note)
        db.session.commit()
        flash('Note uploaded successfully')
    # Redirect to an existing endpoint
    return redirect(url_for('dashboard'))  # Change 'dashboard' to the desired endpoint
@app.route('/notes')
def notes():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_notes = Note.query.filter_by(uploaded_by=session['user_id']).all()
    return render_template('notes.html', notes=user_notes, username=session.get('username'))
@app.route('/community')
def community():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('community.html', username=session.get('username'))

@app.route('/games')
def games():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('games.html', username=session.get('username'))

@app.route('/game1')
def game1():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('game1.html', username=session.get('username'))

@app.route('/game2')
def game2():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('game2.html', username=session.get('username'))

@app.route('/game3')
def game3():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('game3.html', username=session.get('username'))

@app.route('/game4')
def game4():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('game4.html', username=session.get('username'))

@app.route('/game5')
def game5():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('game5.html', username=session.get('username'))

@app.route('/charts')
def charts():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('charts.html', username=session.get('username'))

@app.route('/search_users', methods=['GET'])
def search_users():
    query = request.args.get('query')
    users = User.query.filter(User.username.contains(query)).all()
    return jsonify([{'id': user.id, 'username': user.username, 'profile_picture': user.profile_picture} for user in users])

@app.route('/send_message', methods=['POST'])
def send_message():
    """Handle user messages and provide responses."""
    data = request.get_json()
    message = data['message']
    
    # Search the internet for relevant information using OpenSearch
    context = search_opensearch(message)
    
    # Use Hugging Face's question-answering model to generate a response
    result = qa_pipeline(question=message, context=context)
    return jsonify({'message': result['answer']})



@app.route('/create_group', methods=['POST'])
def create_group():
    group_name = request.form['group_name']
    member_ids = request.form.getlist('member_ids')
    group = Group(name=group_name)
    for member_id in member_ids:
        user = User.query.get(member_id)
        group.members.append(user)
    db.session.add(group)
    db.session.commit()
    return jsonify({'status': 'Group created'})

@app.route('/chat/<int:user_id>')
def chat(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(user_id)
    if not user:
        flash('User not found')
        return redirect(url_for('dashboard'))
    messages = Message.query.filter(
        ((Message.sender_id == session['user_id']) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == session['user_id']))
    ).order_by(Message.timestamp).all()
    
    # Mark messages as read
    for message in messages:
        if message.receiver_id == session['user_id']:
            message.read = True
    db.session.commit()
    
    return render_template('chat.html', user=user, messages=messages, username=session.get('username'))

@app.route('/group_chat/<int:group_id>')
def group_chat(group_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    group = Group.query.get(group_id)
    if not group:
        flash('Group not found')
        return redirect(url_for('dashboard'))
    return render_template('group_chat.html', group=group, username=session.get('username'))

@app.route('/unread_messages', methods=['GET'])
def unread_messages():
    if 'user_id' not in session:
        return jsonify({'count': 0})
    user_id = session['user_id']
    count = Message.query.filter_by(receiver_id=user_id, read=False).count()
    return jsonify({'count': count})

@app.route('/recover', methods=['GET', 'POST'])
def recover():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            # Here you would send an email with a recovery link
            flash('Password recovery instructions have been sent to your email.')
        else:
            flash('Email not found.')
    return render_template('recover.html')

@app.route('/threat_detection')
def threat_detection():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('threat_detection.html', username=session.get('username'))

@app.route('/incident_response')
def incident_response():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    incidents = Incident.query.all()
    return render_template('incident_response.html', incidents=incidents, username=session.get('username'))

@app.route('/report_incident', methods=['POST'])
def report_incident():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    title = request.form['title']
    description = request.form['description']
    severity = request.form['severity']
    incident = Incident(title=title, description=description, severity=severity, reported_by=session['user_id'])
    db.session.add(incident)
    db.session.commit()
    flash('Incident reported successfully')
    return redirect(url_for('incident_response'))

@app.route('/view_incident/<int:incident_id>')
def view_incident(incident_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    incident = Incident.query.get(incident_id)
    if not incident:
        flash('Incident not found')
        return redirect(url_for('incident_response'))
    return render_template('view_incident.html', incident=incident, username=session.get('username'))

@app.route('/resolve_incident/<int:incident_id>')
def resolve_incident(incident_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    incident = Incident.query.get(incident_id)
    if not incident:
        flash('Incident not found')
        return redirect(url_for('incident_response'))
    incident.status = 'Resolved'
    db.session.commit()
    flash('Incident resolved successfully')
    return redirect(url_for('incident_response'))

@app.route('/vulnerability_management')
def vulnerability_management():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    vulnerabilities = Vulnerability.query.all()
    return render_template('vulnerability_management.html', vulnerabilities=vulnerabilities, username=session.get('username'))

@app.route('/report_vulnerability', methods=['POST'])
def report_vulnerability():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    title = request.form['title']
    description = request.form['description']
    severity = request.form['severity']
    vulnerability = Vulnerability(title=title, description=description, severity=severity, reported_by=session['user_id'])
    db.session.add(vulnerability)
    db.session.commit()
    flash('Vulnerability reported successfully')
    return redirect(url_for('vulnerability_management'))

@app.route('/view_vulnerability/<int:vulnerability_id>')
def view_vulnerability(vulnerability_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    vulnerability = Vulnerability.query.get(vulnerability_id)
    if not vulnerability:
        flash('Vulnerability not found')
        return redirect(url_for('vulnerability_management'))
    return render_template('view_vulnerability.html', vulnerability=vulnerability, username=session.get('username'))

@app.route('/resolve_vulnerability/<int:vulnerability_id>')
def resolve_vulnerability(vulnerability_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    vulnerability = Vulnerability.query.get(vulnerability_id)
    if not vulnerability:
        flash('Vulnerability not found')
        return redirect(url_for('vulnerability_management'))
    vulnerability.status = 'Resolved'
    db.session.commit()
    flash('Vulnerability resolved successfully')
    return redirect(url_for('vulnerability_management'))
@app.route('/guardify_assistant')
def guardify_assistant():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('guardify_assistant.html', username=session.get('username'))

@app.route('/upload_file', methods=['POST'])
def upload_file():
    file = request.files['file']
    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    response_message = analyze_file(file)
    return jsonify({'message': response_message})

def analyze_file(file):
    # Placeholder function for file analysis
    return "File analysis result."

def send_notification(message):
    socketio.emit('notification', {'message': message})

@app.template_global()
def get_icon_class(filename):
    ext = filename.split('.')[-1].lower()
    if ext == 'pdf':
        return 'fas fa-file-pdf'
    elif ext in ['doc', 'docx']:
        return 'fas fa-file-word'
    elif ext in ['ppt', 'pptx']:
        return 'fas fa-file-powerpoint'
    elif ext in ['xls', 'xlsx']:
        return 'fas fa-file-excel'
    elif ext in ['jpg', 'jpeg', 'png', 'gif']:
        return 'fas fa-file-image'
    else:
        return 'fas fa-file'
    
def search_opensearch(query):
    """Search the internet using OpenSearch (e.g., Wikipedia)."""
    url = "https://en.wikipedia.org/w/api.php"
    params = {
        "action": "opensearch",
        "search": query,
        "limit": 5,
        "namespace": 0,
        "format": "json"
    }
    response = requests.get(url, params=params)
    if response.status_code == 200:
        results = response.json()
        # Combine the titles and descriptions of the search results
        snippets = [f"{title}: {desc}" for title, desc in zip(results[1], results[2]) if desc]
        return " ".join(snippets) if snippets else "No relevant information found."
    else:
        return "Failed to fetch information from OpenSearch."


# Load the PDF text into memory
# Load the PDF text into memory
def load_all_pdfs(pdf_directory):
    """Extract and combine text from all PDFs in a directory."""
    combined_text = ""
    try:
        for filename in os.listdir(pdf_directory):
            if filename.endswith('.pdf'):
                pdf_path = os.path.join(pdf_directory, filename)
                with open(pdf_path, 'rb') as pdf_file:
                    reader = PyPDF2.PdfReader(pdf_file)
                    for page in reader.pages:
                        combined_text += page.extract_text()
        return combined_text
    except Exception as e:
        print(f"Error reading PDFs: {e}")
        return ""

# Load cybersecurity-related text from PDFs or provide a default context
cybersecurity_text = load_all_pdfs('static/uploads/pdfs') or "Default cybersecurity context."

@app.route('/ask', methods=['POST'])
def ask_guardify_assistant():
    """Handle user questions and provide answers."""
    user_question = request.json.get('question', '').strip().lower()
    if not user_question:
        return jsonify({'answer': 'Please ask a question.'}), 400

    # Handle greetings
    greetings = ['hi', 'hello', 'hey', 'what\'s up', 'howdy']
    if user_question in greetings:
        return jsonify({'answer': 'Hello, welcome to Guardify! How can I assist you today?'})

    # Handle conversational queries
    conversational_queries = ['how are you', 'how are you today', 'what\'s going on', 'how\'s it going']
    if user_question in conversational_queries:
        return jsonify({'answer': 'I\'m just a program, but I\'m here to help! How can I assist you today?'})

    # Use the combined PDF text as context for answering questions
    if cybersecurity_text:
        result = qa_pipeline(question=user_question, context=cybersecurity_text)
        return jsonify({'answer': result['answer']})

    # Fallback to OpenSearch if no PDF text is available
    context = search_opensearch(user_question)
    if context == "No relevant information found.":
        return jsonify({'answer': 'I\'m sorry, I couldn\'t find any relevant information. Can you please rephrase your question?'})

    result = qa_pipeline(question=user_question, context=context)
    return jsonify({'answer': result['answer']})

@socketio.on('message')
def handle_message(data):
    """Handle incoming messages from the chat interface."""
    user_message = data['message']
    context = search_opensearch(user_message)
    result = qa_pipeline(question=user_message, context=context)
    emit('response', {'message': result['answer']})
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Ensure the 'read' column exists in the 'message' table
        try:
            db.engine.execute('ALTER TABLE message ADD COLUMN read BOOLEAN DEFAULT FALSE')
        except Exception as e:
            print(f"Column 'read' already exists or error occurred: {e}")
    socketio.run(app, debug=True)