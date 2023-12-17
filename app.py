from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
import mysql.connector
from flask_wtf import FlaskForm
from wtforms.fields import StringField, DateTimeField, SelectField, IntegerField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError, Email, EqualTo, DataRequired
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from sqlalchemy.orm import relationship
from sqlalchemy import ForeignKey, desc
from flask_wtf.file import FileField
from flask import send_file
import os
from werkzeug.utils import secure_filename
from datetime import timedelta, datetime
from wtforms.widgets import TextArea
from collections import Counter


app = Flask(__name__)
# app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root123@localhost/helpform'
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
    date_updated = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now, nullable=False)
    updated_by = db.Column(db.String(50))

    def is_admin(self):
        return 'admin' in self.roles.split(',')

    forms_sent = db.relationship('Form', foreign_keys='Form.sender_id', back_populates='sender', lazy=True)
    forms_received = db.relationship('Form', foreign_keys='Form.recipient_id', back_populates='recipient', lazy=True)
    forms_other = db.relationship('Form', foreign_keys='Form.user_id', back_populates='user', lazy=True)

    def __init__(self, name, username, password, roles=None, date_created=None, date_updated=None, updated_by=None):
        self.name = name
        self.username = username
        self.password = password
        self.roles = roles
        self.updated_by = updated_by

        if date_created is not None:
            self.date_created = date_created
        if date_updated is not None:
            self.date_updated = date_updated


class Form(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    centreno = db.Column(db.String(10), nullable=False)
    centrename = db.Column(db.String(255), nullable=False)
    state = db.Column(db.String(255), nullable=True)
    sessionno = db.Column(db.String(255), nullable=False)
    caller = db.Column(db.String(255), nullable=False)
    issuecat = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    descriptionprevious = db.Column(db.Text)
    solution = db.Column(db.Text)
    resolved = db.Column(db.String(255), nullable=False)
    phonenumber = db.Column(db.String(255), nullable=False)
    transfer_to_user = db.Column(db.Integer, nullable=True)
    date_created = db.Column(db.DateTime, default=datetime.now, nullable=False)
    date_updated = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now, nullable=False)
    updated_by = db.Column(db.String(50))

    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    sender = db.relationship('User', foreign_keys=[sender_id], back_populates='forms_sent', lazy=True)
    recipient = db.relationship('User', foreign_keys=[recipient_id], back_populates='forms_received', lazy=True)
    user = db.relationship('User', foreign_keys=[user_id], back_populates='forms_other', lazy=True)

    def __init__(self, name=None, centreno=None, centrename=None, state=None, sessionno=None,
                 caller=None, issuecat=None, description=None, descriptionprevious=None,
                 solution=None, resolved=None, phonenumber=None, transfer_to_user=None,
                 sender=None, recipient=None, user=None, date_created=None, date_updated=None,
                 updated_by=None, **kwargs):
        self.name = name
        self.centreno = centreno
        self.centrename = centrename
        self.state = state
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
        self.updated_by = updated_by
        
        super(Form, self).__init__(**kwargs)

        if date_created is not None:
            self.date_created = date_created
        if date_updated is not None:
            self.date_updated = date_updated

class ManualResetPasswordForm(FlaskForm):
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Reset Password')


class RegisterForm(FlaskForm):
    name = StringField(validators=[InputRequired(), Length(
        min=4, max=50)], render_kw={"placeholder": "Full Name"})
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=50)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=6, max=20)], render_kw={"placeholder": "Password"})
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
    centreno = SelectField('Centreno', choices=[], default='', coerce=str)
    centrename = SelectField('Centrename', choices=[], default='', coerce=str)
    state = SelectField('State', choices=[], default='', coerce=str)
    sessionno = SelectField(validators=[InputRequired()], choices=[('select choice', 'Select Choice'), ('session 1', 'Session 1'), ('session 2', 'Session 2'), ('session 3', 'Session 3'), ('session 4', 'Session 4'), ('session 5', 'Session 5')], render_kw={"placeholder": "Select Session"})
    caller = SelectField(validators=[InputRequired()], choices=[('select choice', 'Select Choice'), ('supervisor', 'Supervisor'), ('technical', 'Technical'), ('bvm operator', 'BVM Operator'), ('centre technical', 'Centre Technical'), ('centre admin', 'Centre Admin'), ('state coordinator', 'State Coordinator'), ('zonal technical', 'Zonal Technical'), ('others', 'Others')], render_kw={"placeholder": "Select Caller"})
    issuecat = SelectField(validators=[InputRequired()], choices=[('select category', 'Select Category'), ('administration', 'Administration'), ('laptop hardware', 'Laptop Hardware'),
                                   ('network', 'Network'), ('test software', 'Test Software'), ('security', 'Security'), ('biometrics', 'Biometrics'), ('registration sim', 'Registration SIM'), ('registration router', 'Registration Router'), ('registration software', 'Registration Software'),
                                   ('ussd', 'USSD'),
                                   ('thump print', 'Thump Print'),
                                   ('payment', 'Payment'),
                                   ('biometrics capturing', 'Biometric Capturing'), ('camera not capturing', 'Camera not Capturing'),
                                   ('access code', 'Access code /Reference Number'),
                                   ('daily password', 'Daily Password'), ('others', 'Others')], render_kw={"placeholder": "Select Issue Category"})
    description = StringField("Description of Problem by Caller", validators=[
                          DataRequired()], widget=TextArea())
    descriptionprevious = StringField("Description of the previous call", validators=[
                          DataRequired()], widget=TextArea())
    solution = StringField("Summary of the Solution by Help Line Operator", validators=[
                          DataRequired()], widget=TextArea())

    
    resolved = SelectField(
        'Status (Resolved)',
        validators=[InputRequired()],
        choices=[('select choice', 'Select Choice'), ('yes', 'Yes'), ('no', 'No')],
        render_kw={"placeholder": "Select Status"}
    )    
    phonenumber = IntegerField(validators=[InputRequired()], render_kw={
                               "placeholder": "Phone Number"})
    transfer_to_user = SelectField(choices=[], default=-1, coerce=int)
    submit = SubmitField("Submit")

    def __init__(self, *args, **kwargs):
        super(RegForm, self).__init__(*args, **kwargs)

        # Initialize choices in __init__
        self.centreno.choices = [('', 'Select Centre Number')] + [(row.centreno, row.centreno) for row in Form.query.distinct(Form.centreno).all()]
        self.centrename.choices = [('', 'Select Centre Name')] + [(row.centrename, row.centrename) for row in Form.query.distinct(Form.centrename).all()]
        self.state.choices = [('', 'Select State')] + [(row.state, row.state) for row in Form.query.distinct(Form.state).all()]

        self.transfer_to_user.choices = [(-1, 'Do not transfer')] + [(user.id, user.username) for user in User.query.all()]
    
    # def validate(self):
    #         # Custom validation logic for the form
    #         if not super().validate():
    #             return False

    #         # Validate user information
    #         user_id = self.transfer_to_user.data
    #         name = self.name.data
    #         phonenumber = self.phonenumber.data

    #         if not validate_user_info(user_id, name, phonenumber):
    #             self.transfer_to_user.errors.append('Invalid user information.')
    #             return False

    #         return True
        
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

@app.route("/reset_password_manually/<username>", methods=['GET', 'POST'])
def reset_password_manually(username):
    user = User.query.filter_by(username=username).first()

    if not user:
        flash('User not found')
        return redirect(url_for('login'))

    if current_user.is_authenticated:
        flash('You are already logged in. Please log out to reset your password.')
        return redirect(url_for('login'))  

    form = ManualResetPasswordForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Password reset successfully. You can now log in with your new password.')
        return redirect(url_for('login'))

    return render_template('reset_password_manually.html', form=form, username=username)


@app.route("/")
def main():
    return render_template("index.html")

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
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Please check your username and password.')

    return render_template("login.html", form=form, user=current_user)


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


@app.route("/admin_dashboard")
@login_required
def admin_dashboard():
    # Ensure that the current user has admin privileges
    if current_user.roles != "admin":
        flash("You do not have permission to access the admin dashboard.")
        return redirect(url_for('dashboard'))

    # Query all transferred forms
    transferred_forms = Form.query.filter(Form.transfer_to_user.isnot(None)).order_by(Form.date_updated.desc()).all()

    return render_template("admin_dashboard.html", transferred_forms=transferred_forms)


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = RegisterForm()

    if form.validate_on_submit():
        roles = "admin" if form.username.data == "admin" else "user"

        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(
            name=form.name.data,
            username=form.username.data,
            password=hashed_password,
            roles=roles
        )
        db.session.add(new_user)
        db.session.commit()
        
        flash('Congratulations, You have registered Successfully!')


        return redirect(url_for('login'))

    return render_template("register.html", form=form)

@app.route("/form.html", methods=['GET', 'POST'])
@login_required
def form():
    form = RegForm()

    # Populate choices for transfer_to_user field
    form.transfer_to_user.choices = [(user.id, user.username) for user in User.query.all()]

    if form.validate_on_submit():
        description_transcript = request.form.get('descriptionTranscript')
        solution_transcript = request.form.get('solutionTranscript')
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
                centreno=form.centreno.data,
                centrename=form.centrename.data,
                state=form.state.data,
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

            db.session.add(new_form)
            db.session.commit()

            flash("Form updated successfully.")

            return redirect(url_for('dashboard'))

    return render_template("form.html", form=form)

# Edit Form
@app.route("/edit_form/<int:form_id>", methods=['GET', 'POST'])
@login_required
def edit_form(form_id):
    edited_form = Form.query.filter_by(
        id=form_id, user_id=current_user.id).first()

    if edited_form is None or edited_form.user_id != current_user.id:
        return redirect(url_for('dashboard'))

    if request.method == 'POST' and request.form.get('submit'):
        edited_form.name = request.form['name']
        edited_form.centreno = request.form['centreno']
        edited_form.centrename = request.form['centrename']
        edited_form.state = request.form['state']
        edited_form.sessionno = request.form['sessionno']
        edited_form.caller = request.form['caller']
        edited_form.issuecat = request.form['issuecat']
        edited_form.description = request.form['description']
        edited_form.descriptionprevious = request.form['descriptionprevious']
        edited_form.solution = request.form['solution']
        edited_form.resolved = request.form['resolved']
        edited_form.phonenumber = request.form['phonenumber']
        edited_form.transfer_to_user = request.form['transfer_to_user']

        db.session.commit()
        flash('Form updated successfully!')
        return redirect(url_for('dashboard'))

    # Pass the existing form data to the template
    return render_template("edit_form.html", form=edited_form, user=current_user)


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

@app.route('/view_form/<int:form_id>', methods=['GET', 'POST'])
@login_required
def view_form(form_id):
    form = Form.query.get(form_id)

    # Check if the logged-in user is an admin
    if current_user.roles == 'admin':

        if request.method == 'POST':
            form.resolved = request.form.get('resolved')
            form.solution = request.form.get('solution')
            form.updated_by = current_user.username
            db.session.commit()
            flash("Form updated successfully.")
            return redirect(url_for('admin_dashboard'))

        return render_template("view_form.html", form=form, user=current_user)

    # If the logged-in user is not an admin, check if the form is related to the user
    elif form.recipient == current_user:
        # Proceed with form viewing/editing only if the logged-in user is the recipient
        if request.method == 'POST':
            form.resolved = request.form.get('resolved')
            form.solution = request.form.get('solution')
            form.updated_by = current_user.username
            db.session.commit()
            flash("Form updated successfully.")
            return redirect(url_for('dashboard'))

        return render_template("view_form.html", form=form, user=current_user)

    # If the logged-in user is neither an admin nor the recipient, deny access
    else:
        flash('Not Authorized')
        return redirect(url_for('dashboard'))


@app.route('/summary')
def summary():
    # Fetch only the forms with 'resolved' set to 'yes' from the database
    resolved_forms = Form.query.filter_by(resolved='yes').all()
    # Reverse the list to achieve descending order
    resolved_forms.reverse()    
    return render_template('summary.html', resolved_forms=resolved_forms)

@app.route('/get_options/<centreno>', methods=['GET'])
def get_options(centreno):
    # Query the database to get related data based on the selected centreno
    options = (
        db.session.query(Form.centrename, Form.state)
        .filter_by(centreno=centreno)
        .group_by(Form.centrename, Form.state)
        .all()
    )

    # Format the data as a list of dictionaries
    data = [{'centrename': option.centrename, 'state': option.state} for option in options]

    return jsonify(data)


@app.route('/get_descriptionprevious/<centreno>', methods=['GET'])
def get_descriptionprevious(centreno):
    # Query the database to get the descriptionprevious data based on the selected centreno
    descriptionprevious_data = (
        Form.query
        .filter_by(centreno=centreno)
        .order_by(Form.date_updated.desc())
        .first()
    )

    data = {'descriptionprevious': descriptionprevious_data.descriptionprevious}

    return jsonify(data)


@app.route('/frequently_selected_values')
def frequently_selected_values():
    all_forms = Form.query.all()

    all_centreno_values = [form.centreno for form in all_forms]
    all_centrename_values = [form.centrename for form in all_forms]

    # Set the threshold for considering a value as frequent
    frequency_threshold = 4 

    # Use Counter to count occurrences
    centreno_counter = Counter(all_centreno_values)
    frequent_centreno_values = [value for value, count in centreno_counter.items() if count >= frequency_threshold]

    centrename_counter = Counter(all_centrename_values)
    frequent_centrename_values = [value for value, count in centrename_counter.items() if count >= frequency_threshold]

    # Pass the frequent values to the template
    return render_template('frequently_selected_values.html',
                           frequent_centreno_values=frequent_centreno_values,
                           frequent_centrename_values=frequent_centrename_values)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000)