import os
from datetime import datetime
from flask import Flask, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_required, login_user, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError

path = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
# Security to app
app.config['SECRET_KEY'] = 'you-will-never-guess'
# Enable communication with a database, location of the application’s database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(path, 'databaseteste.db')
# Disable a feature that signals the application every time a change is about to be made in the database.
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Configurandos novas BINDS (caminhos para multiplas databases)
app.config['SQLALCHEMY_BINDS'] = {
   'user_database': 'sqlite:///' + os.path.join(path, 'user-database.db')
}

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
   return User.query.get(int(user_id))

db = SQLAlchemy(app)

# User model to database
class User(UserMixin, db.Model):
    __bind_key__ = 'user_database'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), unique = True, index = True)
    password_hash = db.Column(db.String(128))
    joined_at = db.Column(db.DateTime(), default = datetime.utcnow, index = True)

    def __repr__(self):
        return f'{self.username}'
    
    def set_passoword(self, password):
        self.password_hash = generate_password_hash(password)

# Registration Form
        
class RegistoFormulario(FlaskForm):
    username = StringField('Username', validators=[DataRequired()], render_kw={"placeholder": "Username"})
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])

    submit = SubmitField('Register')

    def validate_username(self, username):
       existing_user_username = User.query.filter_by(username=username.data).first()
       if existing_user_username:
          raise ValidationError("Thas username already exists! Type another")

class LoginFormulario(FlaskForm):
    username = StringField('Username', validators=[DataRequired()], render_kw={"placeholder": "Username"})
    password_hash = PasswordField('Password', validators=[DataRequired()])

    submit = SubmitField('Login')

@app.route('/')
def index():
  current_users = User.query.all()
  return render_template('home.html', current_users=current_users)

@app.route('/register', methods=['GET', 'POST'])
def register():
  register_form = RegistoFormulario(csrf_enabled=False)

  if register_form.validate_on_submit():
    
    user = User(username=register_form.username.data, email=register_form.email.data)
    user.set_passoword(register_form.password.data)
    db.session.add(user)
    db.session.commit()
    return "Cadastrado com sucesso"
  return render_template('register.html', title='Register', form=register_form)

@app.route('/login', methods=["GET", "POST"])
def login():
  login_form = LoginFormulario()

  if login_form.validate_on_submit():
     user = User.query.filter_by(username=login_form.username.data).first()
     if user:
        if check_password_hash(user.password_hash, login_form.password_hash.data):
           login_user(user)
           return redirect(url_for('dashboard'))
  return render_template("login.html", login_form=login_form)

@app.route("/dashboard")
def dashboard():
   return render_template("dashboard.html")

if __name__ == '__main__':
   app.run(debug=True)
