from flask import Flask, render_template, url_for, redirect, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import IntegerField, StringField, PasswordField, SubmitField, FileField 
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import pdfkit
import os
import json
import base64
from io import BytesIO, FileIO, BufferedReader
# Init app

app = Flask(__name__)

# configuring pdfkit to point to our installation of wkhtmltopdf
config = pdfkit.configuration(wkhtmltopdf = r"C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe")

bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/Users/mustc/Documents/ebook/database.db'
app.config['SECRET_KEY'] = 'secretkey'
db = SQLAlchemy(app)

print('DATABASE', db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(80), nullable=False)
    phoneNumber = db.Column(db.Integer, nullable=False)

class Notes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(20), nullable=False)
    desc = db.Column(db.String(200), nullable=False)
    author = db.Column(db.String(20), nullable=False)

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    email = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    phoneNumber = IntegerField(validators=[InputRequired()], render_kw={"placeholder": "Phone Number"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')

class DashboardForm(FlaskForm):    
    title = StringField(validators=[InputRequired(), Length(min=2, max=20)], render_kw={"placeholder": "Title"})
    desc = StringField(validators=[InputRequired(), Length(min=2, max=1000)], render_kw={"placeholder": "Description"})
    author = StringField(validators=[InputRequired(), Length(min=2, max=20)], render_kw={"placeholder": "Author"})
    publisher = StringField(validators=[InputRequired(), Length(min=2, max=20)], render_kw={"placeholder": "Publisher"})
    category = StringField(validators=[InputRequired(), Length(min=2, max=20)], render_kw={"placeholder": "Category"})
    image = FileField(validators=[InputRequired()], render_kw={"placeholder": "Image File"})
    submit = SubmitField('Submit')

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

class DisplayForm(FlaskForm):
    display = StringField(validators=[InputRequired()])
    submit = SubmitField('Submit')

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)

@app.route('/pdf/<path:path>')
def send_report(path):
    return send_from_directory('pdf', path)

@app.route('/display', methods=['GET','POST'])
@login_required
def display():
    form = DisplayForm()
    print('dISPLAY CALLED')
    if form.validate_on_submit():
        print('LINE 11', form.display.data)
        jsonDecod = json.loads(form.display.data)
        myPdf = f"""
            <div>
                <h1 style="width:100%; text-align:center; color:grey;">{jsonDecod['title']}</h1>
                <img style="width: 100%; height: 300px;" alt="bookimage" src="data:image/png;base64,{jsonDecod['image']}"/>
                <p style="text-align:justify; paddingVertical: 20px;"> Desc: {jsonDecod['desc']}</p>
                <h4 style="width:100%;">Category: {jsonDecod['category']}</h5>
                <p style="width:100%; text-align:right; font-size: 15px;">Publisher - {jsonDecod['publisher']}</p><br>
                <p style="width:100%; text-align:right; font-size: 15px;">Author - {jsonDecod['author']}</p>
            </div>
        """
        fileName = 'pdf/' + jsonDecod['title'].replace(' ','_') + '.pdf'
        pdfkit.from_string(myPdf, fileName, configuration=config)
        return redirect(url_for('dashboard')) 
    return render_template('display.html', form=form, data=jsonDecod)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = DashboardForm()
    allPdf = []    
    for path in os.listdir('pdf'):
        allPdf.append(path)
    print("=======", form.validate_on_submit())
    if form.validate_on_submit():        
        formData = {'title': form.title.data, 'desc': form.desc.data, 'author': form.author.data, 'category': form.category.data, 'publisher': form.publisher.data  }        
        formData['image'] = (base64.b64encode(form.image.data.stream.read())).decode('utf-8')
        allData = json.dumps(formData, separators=(',', ':'))
        return render_template('display.html', form=DisplayForm(), data=formData, jsonData=allData ) 
    return render_template('dashboard.html', form=form, list=allPdf, len=len(allPdf))

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()        
    if form.validate_on_submit():
        print('NEW USER1', form.password.data)
        hashed_password = bcrypt.generate_password_hash(form.password.data)        
        new_user = User(username=form.username.data, password=hashed_password, email= form.email.data, phoneNumber = form.phoneNumber.data)
        print('NEW USER', new_user)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

if __name__ == '__main__':
  app.run(debug=True)