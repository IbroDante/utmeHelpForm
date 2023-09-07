from flask import Flask, render_template, request, redirect, url_for, session
# from flaskext.mysql import MySQL
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
import mysql.connector
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError, Email, EqualTo
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:root123@localhost/edung'
app.config['SECRET_KEY'] = 'root1234'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    roles = db.Column(db.String(255), nullable=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
	name = StringField(validators=[InputRequired(), Length(min=4, max=50)], render_kw={"placeholder": "Full Name"})
	username = StringField(validators=[InputRequired(), Length(min=4, max=50)], render_kw={"placeholder": "Username"})
	email = StringField(validators=[InputRequired(), Length(min=4, max=50)], render_kw={"placeholder": "Email"})
	password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
	confirm_password = PasswordField(validators=[InputRequired(), EqualTo('password')], render_kw={"placeholder": "Confirm Password"})
	submit = SubmitField("Register")

	def validate_username(self, username):
		existing_user_username = User.query.filter_by(username=username.data).first()

		if existing_user_username:
			raise ValidationError("That username already exists, Please choose a different one.")

	def validate_email(self, email):
		existing_user_email = User.query.filter_by(email=email.data).first()

		if existing_user_email:
			raise ValidationError("That email already exists, Please choose a different one.")

class LoginForm(FlaskForm):
	username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
	password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
	submit = SubmitField("Login")

	def validate_username(self, username):
		user = User.query.filter_by(username=username.data).first()
		
		if not user:
			raise ValidationError("Username not found. Please check your username.")
			
	def validate_password(self, password):
		user = User.query.filter_by(username=self.username.data).first()
		
		if user and not bcrypt.check_password_hash(user.password, password.data):
			raise ValidationError("Incorrect password. Please check your password.")

with app.app_context():
#     # Create database tables using db.create_all()
    db.create_all()

@app.route("/")
def main():
	return render_template("index.html")

@app.route("/index.html")
def index():
	return render_template("index.html")

@app.route("/login", methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(username=form.username.data).first()
		if user:
			if bcrypt.check_password_hash(user.password, form.password.data):
				login_user(user)
				return redirect(url_for('dashboard'))
	return render_template("login.html", form=form)


@app.route("/dashboard", methods=['GET', 'POST'])
@login_required
def dashboard():
	user = current_user
	return render_template("dashboard.html", user=user)


@app.route("/logout", methods=['GET', 'POST'])
@login_required
def logout():
	logout_user()
	return redirect(url_for("login"))


@app.route("/register", methods=['GET', 'POST'])
def register():
	form = RegisterForm()

	if form.validate_on_submit():
		hashed_password = bcrypt.generate_password_hash(form.password.data)
		new_user = User(username=form.username.data, email=form.email.data, password=hashed_password, name=form.name.data, roles="user")
		db.session.add(new_user)
		db.session.commit()
		return redirect(url_for('login'))
		flash('Your account has been created! You can now log in.', 'successful')

	return render_template("register.html", form=form)

@app.route("/about.html")
def about():
	return render_template("about.html")

@app.route("/blog.html")
def blog():
	return render_template("blog.html")

@app.route("/business.html")
def business():
	return render_template("business.html")

@app.route("/coming_soon.html")
def coming_soon():
	return render_template("coming_soon.html")

@app.route("/form.html")
def form():
	return render_template("form.html")

@app.route("/communication.html")
def communication():
	return render_template("communication.html")

@app.route("/contact.html")
def contact():
	return render_template("contact.html")

@app.route("/course_details.html")
def course_details():
	return render_template("course_details.html")

@app.route("/faq.html")
def faq():
	return render_template("faq.html")

@app.route("/gallery.html")
def gallery():
	return render_template("gallery.html")

@app.route("/language.html")
def language():
	return render_template("language.html")

@app.route("/photography.html")
def photography():
	return render_template("photography.html")

@app.route("/single.html")
def single():
	return render_template("single.html")

@app.route("/social_media.html")
def social_media():
	return render_template("social_media.html")

@app.route("/software.html")
def software():
	return render_template("software.html")

@app.route("/404.html")
def err404():
	return render_template("404.html")

if __name__ == '__main__':
	app.run()
