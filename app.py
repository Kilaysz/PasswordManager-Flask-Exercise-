import re
from flask import Flask, jsonify, render_template, request, redirect, session, url_for
from extensions import db# login_manager
from models import User
from werkzeug.security import generate_password_hash,  check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db.init_app(app)
app.secret_key = 'Theodora'
# login_manager.init_app(app)

with app.app_context():
    users = User.query.all()
    for user in users:
        print(f"{user.id} - {user.username} - {user.password}")

# @login_manager.user_loader
# def load_user(user_id):
#     return User.query.get(int(user_id))

@app.route('/')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'] )
def handle_login():
    username = request.form['username']
    password = request.form['password']
    user = User.query.filter_by(username=username).first()

    if(not user or user.password != password):
        return render_template("login.html", message = "Wrong Password\n Please Try Again")
    session['username'] = username  
    return render_template("dashboard.html", username = username, password = password)

@app.route('/register', methods=['GET', 'POST'] )
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm = request.form['confirm_password']

        if password != confirm:
            return render_template('register.html', message="Passwords do not match")

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template('register.html', message="Username already exists")

       # hashed_pw = generate_password_hash(password)
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login')) 
    
    return render_template('register.html')

@app.route('/check-strength', methods=['POST'])
def check_strength():
    password = request.json.get('password', '')
    if len(password) < 8:
        return jsonify({'strength': 'Weak'})

    strong = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{12,}$')
    medium = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$')

    if strong.match(password):
        return jsonify({'strength': 'Strong'})
    elif medium.match(password):
        return jsonify({'strength': 'Medium'})
    else:
        return jsonify({'strength': 'Weak'})
    
@app.route('/change', methods=['POST','GET'])
def change():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method=='POST':
        user = User.query.filter_by(username=session['username']).first()
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if user.password == new_password:
            return render_template('change_password.html', message="New password cannot be same as old", username = session['username'])
        
        if new_password != confirm_password:
            return render_template('change_password.html', message="Passwords do not match", username = session['username'])

        user.password = new_password
        db.session.commit()
        return render_template('dashboard.html', username = user.username, password = user.password)
    
    return render_template('change_password.html', username=session['username'])