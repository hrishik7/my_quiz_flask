from flask import Flask, render_template, redirect, url_for, request, flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField, FieldList, FormField, SubmitField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from sqlalchemy import create_engine, desc, text
import requests
import json
import sqlite3
import operator
#import sqlite3
li = []
un = ""
#con = sqlite3.connect('mydatabase.db')
app = Flask(__name__) #creating the Flask class object 
bootstrap = Bootstrap(app)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydatabase.db'
app.config['SQLALCHEMY_BINDS'] = {'leaderboard' : 'sqlite:///leaderboard.db' }
app.config['TESTING'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    #__bind_key__ = 'mydatabase'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

class diff_scores(db.Model):
    __bind_key__ = 'leaderboard'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique = False)
    score = db.Column(db.Integer, unique = False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])


class PlayForm(FlaskForm):
    question = StringField('question')
    option = StringField('option')

class PlayForm_Super(FlaskForm):
    p2 = FieldList(FormField(PlayForm),min_entries = 10)
    s = SubmitField('submit')

@app.route('/') #decorator drfines the   
def home():  
    return render_template('index.html');


@app.route('/login', methods = ['GET', 'POST']) #decorator drfines the   
def login():
    form = LoginForm()  
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            global un
            un = form.username.data
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('play'))
        flash("Invalid username or password")
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)

@app.route('/register', methods = ['GET', 'POST']) #decorator drfines the   
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        em = User.query.filter_by(email=form.email.data).first()
        if user or em:
            flash("Username or email is not available")
            return render_template('register.html', form = form);
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password = hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("New user has been created")

    return render_template('register.html', form = form);

@app.route('/play', methods = ['GET', 'POST']) #decorator defines the
@login_required   
def play():
    req = requests.get('https://opentdb.com/api.php?amount=10')
    data = req.content
    json_data = json.loads(data)
    data = json_data['results']
    
    for key in data:
        li.append(key['correct_answer'])
    # temp = request.form.getlist('options')
    # print (temp)
    # if request.method == "POST":
    #     print(dict(request.form))
    #     li1 = request.form.getlist('selected_')
    #     print (li1)
    return render_template('play.html',data = data);

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/score',methods = ['GET', 'POST'])
@login_required
def score():
    #print(li)
    if request.method == "POST":
        #print(dict(request.form))
        li1 = dict(request.form)
    scr = 0;
    cnt = 0;
    #print (li1.values())
    for val in li1.values():
        if cnt == len(li):
            break
        if li[cnt] == val:
            scr += 1
        cnt += 1
    #print(scr)
    #print(un)
    new_entry = diff_scores(username = un, score = scr)
    db.session.add(new_entry)
    db.session.commit()
    engine = create_engine('sqlite:///leaderboard.db')
    connection = engine.raw_connection()
    with engine.connect() as connection:
        data = connection.execute("select * from diff_scores;").fetchall()
        data = sorted(data, key = operator.itemgetter(2),reverse = True)
        #print(data)
        return render_template('score.html', scr = scr,data = data)
    #data = mycursor.fetchall()
    #print(data)
    
  
if __name__ =='__main__':  
    app.run(debug = True)




