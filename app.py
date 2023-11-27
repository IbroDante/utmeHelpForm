from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
import mysql.connector
from flask_wtf import FlaskForm
from wtforms.fields import StringField, DateTimeField, SelectField, IntegerField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError, Email, EqualTo, DataRequired
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from sqlalchemy.orm import relationship
from sqlalchemy import ForeignKey
from flask_wtf.file import FileField
from flask import send_file
import os
from werkzeug.utils import secure_filename
from datetime import timedelta, datetime
from wtforms.widgets import TextArea


app = Flask(__name__)
# app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:root123@localhost/helpform'
app.secret_key = 'root1234'
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
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    roles = db.Column(db.String(255), nullable=True)
    date_created = db.Column(db.DateTime, default=datetime.now, nullable=False)
    date_updated = db.Column(db.DateTime, default=datetime.now, nullable=False)

    # Add a relationship to link User and Form models

    forms_sent = db.relationship('Form', foreign_keys='Form.sender_id', back_populates='sender', lazy=True)
    forms_received = db.relationship('Form', foreign_keys='Form.recipient_id', back_populates='recipient', lazy=True)
    forms_other = db.relationship('Form', foreign_keys='Form.user_id', back_populates='user', lazy=True)

    def __init__(self, name, username, password, roles=None, date_created=None, date_updated=None):
        self.name = name
        self.username = username
        self.password = password
        self.roles = roles

        if date_created is not None:
            self.date_created = date_created
        if date_updated is not None:
            self.date_updated = date_updated


class Form(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    centrename = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(10), nullable=False)
    centreno = db.Column(db.String(10), nullable=False)
    sessionno = db.Column(db.String(10), nullable=False)
    caller = db.Column(db.String(20), nullable=False)
    issuecat = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text)
    descriptionprevious = db.Column(db.Text)
    solution = db.Column(db.Text)
    resolved = db.Column(db.String(10), nullable=False)
    phonenumber = db.Column(db.String(20), nullable=False)
    transfer_to_user = db.Column(db.Integer, nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.now, nullable=False)
    date_updated = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now, nullable=False)
    updated_by = db.Column(db.String(50))


    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    sender = db.relationship('User', foreign_keys=[sender_id], back_populates='forms_sent', lazy=True)
    recipient = db.relationship('User', foreign_keys=[recipient_id], back_populates='forms_received', lazy=True)
    user = db.relationship('User', foreign_keys=[user_id], back_populates='forms_other', lazy=True)

    def __init__(self, name, centrename, state, centreno, sessionno, caller, issuecat, description, descriptionprevious, solution, resolved, phonenumber, transfer_to_user, sender, recipient, user, date_created=None, date_updated=None, **kwargs):
        self.name = name
        self.centrename = centrename
        self.state = state
        self.centreno = centreno
        self.sessionno = sessionno
        self.caller = caller
        self.issuecat = issuecat
        self.description = description
        self.descriptionprevious = descriptionprevious
        self.solution = solution
        self.resolved = resolved
        self.phonenumber = phonenumber
        self.transfer_to_user = transfer_to_user
        self.sender = sender
        self.recipient = recipient
        self.user = user
        super(Form, self).__init__(**kwargs)

        if date_created is not None:
            self.date_created = date_created
        if date_updated is not None:
            self.date_updated = date_updated


class RegisterForm(FlaskForm):
    name = StringField(validators=[InputRequired(), Length(
        min=4, max=50)], render_kw={"placeholder": "Full Name"})
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=50)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    confirm_password = PasswordField(validators=[InputRequired(), EqualTo(
        'password')], render_kw={"placeholder": "Confirm Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()

        if existing_user_username:
            raise ValidationError(
                "That username already exists, Please choose a different one.")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()

        if not user:
            raise ValidationError(
                "Username not found. Please check your username.")

    def validate_password(self, password):
        user = User.query.filter_by(username=self.username.data).first()

        if user and not bcrypt.check_password_hash(user.password, password.data):
            raise ValidationError(
                "Incorrect password. Please check your password.")


class RegForm(FlaskForm):
    name = StringField(validators=[InputRequired(), Length(
        min=4, max=100)], render_kw={"placeholder": "Full Name"})
    centrename = SelectField(validators=[InputRequired()], choices=[('select choice', 'Select Choice'), ('abuja', 'Abuja'), ('ogun', 'Ogun'), ('kano', 'Kano'), ('other', 'Other')], render_kw={"placeholder": "Select Centre Name"})
    state = StringField(validators=[InputRequired(), Length(
        min=3, max=10)], render_kw={"placeholder": "State"})
    centreno = IntegerField(validators=[InputRequired()], render_kw={
                               "placeholder": "CBT Centre No"})
    sessionno = IntegerField(validators=[InputRequired()], render_kw={
                               "placeholder": "Session No"})
    caller = SelectField(validators=[InputRequired()], choices=[('select choice', 'Select Choice'), ('supervisor', 'Supervisor'), ('technical', 'Technical'), ('bvm operator', 'BVM Operator'), ('other', 'Other')], render_kw={"placeholder": "Select Caller"})
    issuecat = SelectField(validators=[InputRequired()], choices=[('select category', 'Select Category'), ('administration', 'Administration'), ('laptop hardware', 'Laptop Hardware'),
                                   ('network', 'Network'), ('test software', 'Test Software'), ('security', 'Security'), ('others', 'Others')], render_kw={"placeholder": "Select Issue Category"})
    description = StringField("Description of Problem by Caller", validators=[
                          DataRequired()], widget=TextArea())
    descriptionprevious = StringField("Description of the previous call", validators=[
                          DataRequired()], widget=TextArea())
    solution = StringField("Summary of the Solution by Help Line Operator", validators=[
                          DataRequired()], widget=TextArea())
    resolved = SelectField(validators=[InputRequired()], choices=[('select choice', 'Select Choice'), ('yes', 'Yes'), ('no', 'No')],  render_kw={"placeholder": "Select"})
    phonenumber = IntegerField(validators=[InputRequired()], render_kw={
                               "placeholder": "Phone Number"})
    transfer_to_user = SelectField(choices=[], default=-1, coerce=int)
    submit = SubmitField("Submit")

    def __init__(self, *args, **kwargs):
        super(RegForm, self).__init__(*args, **kwargs)
        # Initialize choices in __init__
        self.transfer_to_user.choices = [(-1, 'Do not transfer')] + [(user.id, user.username) for user in User.query.all()]
    

def validate_user_info(user_id, name, phonenumber):
    user = User.query.get(user_id)
    if user and (user.name == name or Form.query.filter_by(user_id=user.id, name=name, phonenumber=phonenumber).first()):
        return True
    return False

    # def validate_phonenumber(self, phonenumber):
    #     existing_user_phonenumber = User.query.filter_by(phonenumber=phonenumber.data).first()

    #     if existing_user_phonenumber:
    #         raise ValidationError("That Phone Number already exists. Please choose a different one.")

    # def validate_email(self, email):
    #     existing_user_email = User.query.filter_by(email=email.data).first()

    #     if existing_user_email:
    #         raise ValidationError("That email already exists. Please choose a different one.")

@app.route("/")
def main():
    return render_template("login.html")

@app.route("/index.html")
def index():
    return render_template("index.html")

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

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
    user_forms_received = Form.query.filter_by(recipient_id=current_user.id).all()
    user_forms = Form.query.filter_by(user_id=current_user.id).all()

    return render_template("dashboard.html", user_forms_received=user_forms_received, user_forms=user_forms, user=current_user)

@app.route("/logout", methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(
            name=form.name.data,
            username=form.username.data,
            password=hashed_password,
            roles="user"
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template("register.html", form=form)

@app.route("/form.html", methods=['GET', 'POST'])
@login_required
def form():
    form = RegForm()

    # Populate choices for transfer_to_user field
    form.transfer_to_user.choices = [(user.id, user.username) for user in User.query.all()]

    if form.validate_on_submit():
        # Get the current user who is logged in
        user = current_user

        if not validate_user_info(user.id, form.name.data, form.phonenumber.data):
            flash(
                'Name do not match with your profile creation. Please check your information.')

            return render_template("form.html", form=form)

        # Check if the user is logged in and has a valid user ID
        if user and user.id:
            new_form = Form(
                name=form.name.data,
                centrename=form.centrename.data,
                state=form.state.data,
                centreno=form.centreno.data,
                sessionno=form.sessionno.data,
                caller=form.caller.data,
                issuecat=form.issuecat.data,
                description=form.description.data,
                descriptionprevious=form.descriptionprevious.data,
                solution=form.solution.data,
                resolved=form.resolved.data,
                phonenumber=form.phonenumber.data,
                transfer_to_user=form.transfer_to_user.data,
                sender=current_user,
                recipient=User.query.get(form.transfer_to_user.data) if form.transfer_to_user.data != -1 else None,
                user=current_user,
            )
            # new_form.user = current_user

            db.session.add(new_form)
            db.session.commit()

            return redirect(url_for('dashboard'))

    return render_template("form.html", form=form)

# Edit Form
@app.route("/edit_form/<int:form_id>", methods=['GET', 'POST'])
@login_required
def edit_form(form_id):
    form = RegForm()
    edited_form = Form.query.filter_by(
        id=form_id, user_id=current_user.id).first()

    if edited_form is None or edited_form.user_id != current_user.id:
        return redirect(url_for('dashboard'))

    if form.validate_on_submit():
        # Update the form record with the edited data
        edited_form.name = form.name.data
        edited_form.centrename = form.centrename.data
        edited_form.state = form.state.data
        edited_form.centreno = form.centreno.data
        edited_form.sessionno = form.sessionno.data
        edited_form.caller = form.caller.data
        edited_form.issuecat = form.issuecat.data
        edited_form.description = form.description.data
        edited_form.descriptionprevious = form.descriptionprevious.data
        edited_form.solution = form.solution.data
        edited_form.resolved = form.resolved.data
        edited_form.phonenumber = form.phonenumber.data
        edited_form.transfer_to_user = form.transfer_to_user.data

        db.session.commit()
        return redirect(url_for('dashboard'))

    # Populate the form fields with existing data
    form.name.data = edited_form.name
    form.centrename.data = edited_form.centrename
    form.state.data = edited_form.state
    form.centreno.data = edited_form.centreno
    form.sessionno.data = edited_form.sessionno
    form.caller.data = edited_form.caller
    form.issuecat.data = edited_form.issuecat
    form.description.data = edited_form.description
    form.descriptionprevious.data = edited_form.descriptionprevious
    form.solution.data = edited_form.solution 
    form.resolved.data = edited_form.resolved 
    form.phonenumber.data = edited_form.phonenumber
    form.transfer_to_user.data = edited_form.transfer_to_user

    return render_template("edit_form.html", form=form, user=current_user)

# Delete Form


@app.route("/delete_form/<int:form_id>", methods=['POST'])
@login_required
def delete_form(form_id):
    deleted_form = Form.query.filter_by(
        id=form_id, user_id=current_user.id).first()

    if deleted_form is None:
        flash("Form.")
    else:
        db.session.delete(deleted_form)
        db.session.commit()
        flash("Form deleted successfully.")

    return redirect(url_for('dashboard'))

@app.route("/view_form/<int:form_id>", methods=['GET', 'POST'])
@login_required
def view_form(form_id):
    form = Form.query.get(form_id)

    print(f"Form Recipient ID: {form.recipient.id}")
    print(f"Current User ID: {current_user.id}")    
# Check if the logged-in user is the recipient of the form
    
    if form.recipient != current_user:
        flash('Not Authorized')
        return redirect(url_for('dashboard'))

    # Handle form submission
    if request.method == 'POST':
        form.resolved = request.form.get('resolved')
        form.solution = request.form.get('solution')
        form.updated_by = current_user.username
        db.session.commit()
        flash("Form updated successfully.")

        return redirect(url_for('dashboard'))

    return render_template("view_form.html", form=form, user=current_user)

@app.route('/summary')
def summary():
    # Fetch only the forms with 'resolved' set to 'yes' from the database
    resolved_forms = Form.query.filter_by(resolved='yes').all()
    return render_template('summary.html', resolved_forms=resolved_forms)


if __name__ == '__main__':
    # Add app context here before running the app
    with app.app_context():
        db.create_all()
    app.run()
