from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit
import os
import eventlet

app = Flask(__name__)
app.secret_key = 'ougisecretkeyhahahaha'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Configure PostgreSQL database
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://neondb_owner:npg_Ik5JGUg7QxmA@ep-snowy-night-a29fbl53-pooler.eu-central-1.aws.neon.tech/neondb?sslmode=require'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Define Message model
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user = db.relationship('User', backref=db.backref('messages', lazy=True))

# Helper function to check if a username exists
def is_username_taken(username):
    return User.query.filter_by(username=username).first() is not None

# Routes
@app.route('/')
def index():
    if 'username' in session:
        user = User.query.filter_by(username=session['username']).first()
        if user:  # Ensure the user exists
            messages = Message.query.all()
            messages_with_usernames = [
                {'id': message.id, 'content': message.content, 'user': message.user.username}
                for message in messages
            ]
            return render_template('index.html', username=user.username, messages=messages_with_usernames)
        else:
            session.pop('username', None)
            return redirect(url_for('login'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username and password:
            user = User.query.filter_by(username=username).first()
            if user and check_password_hash(user.password, password):
                session['username'] = username
                return redirect(url_for('index'))
            else:
                return "Invalid username or password", 401
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username and password:
            if is_username_taken(username):
                return "Username already exists. Please choose a different one.", 400
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            user = User(username=username, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/Media/<path:filename>')
def media(filename):
    return send_from_directory('templates/Media', filename)

@socketio.on('send_message')
def handle_send_message(data):
    if 'username' in session:
        user = User.query.filter_by(username=session['username']).first()
        if user:
            content = data.get('content')
            if content:
                # Save the message to the database
                message = Message(user_id=user.id, content=content)
                db.session.add(message)
                db.session.commit()

                # Broadcast the new message to all connected clients
                emit('new_message', {'user': user.username, 'content': content}, broadcast=True)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get('PORT', 5000))  # Use PORT from environment or default to 5000
    socketio.run(app, host='0.0.0.0', port=port, debug=False, allow_unsafe_werkzeug=True)