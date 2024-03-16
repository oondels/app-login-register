import os
from datetime import datetime
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_required, login_user, current_user
from werkzeug.security import generate_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo

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
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])

    submit = SubmitField('Register')

@app.route('/')
def index():
  current_users = User.query.all()
  return render_template('home.html', current_users=current_users)

@app.route('/register', methods=['GET', 'POST'])
def register():
  form = RegistoFormulario(csrf_enabled=False)

  if form.validate_on_submit():
    user = User(username=form.username.data, email=form.email.data)
    user.set_passoword(form.password.data)
    db.session.add(user)
    db.session.commit()
  return render_template('register.html', title='Register', form=form)

@app.route('/login')
def login():
   pass

if __name__ == '__main__':
   app.run(debug=True)
