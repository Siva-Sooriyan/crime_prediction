from flask import Flask,render_template,url_for,redirect,request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin,login_user,LoginManager,login_required,logout_user,current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import pickle
# from keras.models import load_model
from joblib import load
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from io import BytesIO
import base64


# Postgresql Configuration
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:1Suriya!@localhost/mydatabase'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = 'thisisthesecretkey'


# Loaded Model for prediction
loaded_model = load('model.h5')

# pictorial representation
data = pd.read_csv('crime.csv')


# Login Management
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


# Creating database columns
class User(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

# Register form using Flaskform
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError('That username already exists. Please choose a different one.')
        
# Login form using Flaskform
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')



# Routes for Home Page
@app.route('/')
def home():
  return render_template('home.html')

# Routes for Login Page
@app.route('/login',methods=['GET','POST'])
def login():
  form = LoginForm()
  # Validtion
  if form.validate_on_submit():
    user = User.query.filter_by(username=form.username.data).first()
    if user:
      if bcrypt.check_password_hash(user.password, form.password.data):
        login_user(user)
        return redirect(url_for('index'))
  return render_template('login.html',form=form)


# ########################################################
# Routes for Dashboard  (when user is Logged in )
# @app.route('/dashboard',methods=['GET','POST'])
# @login_required
# def dashboard():
#   return render_template('dashboard.html')
# ########################################################


# Index page for Crime Prediction
@app.route('/index')
@login_required
def index():
   return render_template('index.html')


# Result page routes of crime prediciton
@app.route('/predict',methods=['POST','GET'])
def predict():
    if request.method == 'POST':
        print("posted")
        to_predict_list = request.form.to_dict() 
        # print(to_predict_list)
        to_predict_list = list(to_predict_list.values()) 
        # print(to_predict_list)
        to_predict_list = list(map(float, to_predict_list))
        print(to_predict_list)
        result = loaded_model.predict([to_predict_list]) 
        print(result)
    if int(result)==1:
        prediction='LOW' 
        print(prediction) 
    elif int(result)==2:
        prediction ='MEDIUM' 
        print(prediction)
    elif int(result)==3:
        prediction ='HIGH'
        print(prediction)
    elif int(result)==4:
        prediction ='MAX' 
        print(prediction)  
    return render_template("result.html",prediction=prediction) 


# Routes for Logout User
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# Routes for Register new User
@app.route('/register',methods=['GET','POST'])
def register():
  form = RegisterForm()
   # Validation 
  if form.validate_on_submit():
    hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
    new_user = User(username=form.username.data, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('login'))
  
  return render_template('register.html',form=form)
     




if __name__ == '__main__':
  app.run(debug=True)