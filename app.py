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
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:root123@localhost/edung'
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
    roles = db.Column(db.String(255), nullable=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

    # Add a relationship to link User and Form models
    forms = relationship('Form', backref='user_forms', lazy=True)

    def __init__(self, name, username, email, password, roles=None):
        self.name = name
        self.username = username
        self.email = email
        self.password = password
        self.roles = roles


class Form(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    birthday = db.Column(db.DateTime, nullable=True)
    gender = db.Column(db.String(10), nullable=False)
    phonenumber = db.Column(db.String(20), nullable=False)
    selectcourse = db.Column(db.String(20), nullable=False)
    selectcoursetime = db.Column(db.String(20), nullable=False)
    address = db.Column(db.String(100), nullable=False)
    line = db.Column(db.String(100), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    zipcode = db.Column(db.String(20), nullable=False)

    # Add a foreign key column that references the User model
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    user = db.relationship('User', backref='form_user', lazy=True)

    def __init__(self, name, birthday, gender, phonenumber, selectcourse, selectcoursetime, address, line, city, zipcode):
        self.name = name
        self.birthday = birthday
        self.gender = gender
        self.phonenumber = phonenumber
        self.selectcourse = selectcourse
        self.selectcoursetime = selectcoursetime
        self.address = address
        self.line = line
        self.city = city
        self.zipcode = zipcode


class Material(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    file_path = db.Column(db.String(255), nullable=False)
    form_id = db.Column(db.Integer, ForeignKey('form.id'), nullable=False)

    def __init__(self, name, description, file_path, form_id):
        self.name = name
        self.description = description
        self.file_path = file_path
        self.form_id = form_id


class Blog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    content = db.Column(db.Text)
    author = db.Column(db.String(255))
    slug = db.Column(db.String(255))
    # user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # user = db.relationship('User', backref='blog_user', lazy=True)

    def __init__(self, title, content, author, slug):
        self.title = title
        self.content = content
        self.author = author
        self.slug = slug
        # self.user_id = user_id


class RegisterForm(FlaskForm):
    name = StringField(validators=[InputRequired(), Length(
        min=4, max=50)], render_kw={"placeholder": "Full Name"})
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=50)], render_kw={"placeholder": "Username"})
    email = StringField(validators=[InputRequired(), Length(
        min=4, max=50)], render_kw={"placeholder": "Email"})
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

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()

        if existing_user_email:
            raise ValidationError(
                "That email already exists, Please choose a different one.")


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


class BlogForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    content = StringField("Content", validators=[
                          DataRequired()], widget=TextArea())
    author = StringField("Author", validators=[DataRequired()])
    slug = StringField("Slug", validators=[DataRequired()])

    submit = SubmitField("Submit")


class RegForm(FlaskForm):
    name = StringField(validators=[InputRequired(), Length(
        min=4, max=100)], render_kw={"placeholder": "Full Name"})
    birthday = DateTimeField(validators=[InputRequired(
    )], format='%Y-%m-%d', render_kw={"placeholder": "Birth Day"})
    gender = SelectField(validators=[InputRequired()], choices=[('select', 'Select'), (
        'female', 'Female'), ('male', 'Male'), ('other', 'Other')], render_kw={"placeholder": "Gender"})
    phonenumber = IntegerField(validators=[InputRequired()], render_kw={
                               "placeholder": "Phone Number"})
    selectcourse = SelectField(validators=[InputRequired()], choices=[('select choice', 'Select Choice'), ('language', 'Language'), ('communication', 'Communication'), ('business', 'Business'), ('software', 'Software'), ('social media', 'Social Media'), ('photography', 'Photography'), (
        'web designing', 'Web Designing'), ('web technology', 'Web Technology'), ('pc systems', 'PC Systems'), ('it foundations', 'IT Foundations'), ('hr management', 'HR Management'), ('modeling', 'Modeling'), ('basic marketing', 'Basic Marketing')], render_kw={"placeholder": "Select Course"})
    selectcoursetime = SelectField(validators=[InputRequired()], choices=[('select time', 'Select Time'), ('hours: 8am - 10am', 'Hours: 8am - 10am'), ('hours: 10am - 12pm', 'Hours: 10am - 12pm'),
                                   ('hours: 12pm - 4pm', 'Hours: 12pm - 4pm'), ('hours: 4pm - 7pm', 'Hours: 4pm - 7pm'), ('hours: 7pm - 9pm', 'Hours: 7pm - 9pm')], render_kw={"placeholder": "Select Course Time"})
    address = StringField(validators=[InputRequired(), Length(
        min=7, max=100)], render_kw={"placeholder": "Address"})
    line = StringField(validators=[InputRequired(), Length(
        min=7, max=100)], render_kw={"placeholder": "Line"})
    city = StringField(validators=[InputRequired(), Length(
        min=7, max=100)], render_kw={"placeholder": "City"})
    zipcode = StringField(validators=[InputRequired(), Length(
        min=4, max=100)], render_kw={"placeholder": "Zip Code"})
    material_name = StringField(validators=[Length(max=100)], render_kw={
                                "placeholder": "Material Name"})
    material_description = StringField(validators=[Length(max=255)], render_kw={
                                       "placeholder": "Material Description"})
    material_file = FileField('Upload Material')
    submit = SubmitField("Submit")


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
    user_forms = Form.query.filter_by(user_id=current_user.id).all()
    return render_template("dashboard.html", user_forms=user_forms, user=current_user)


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
            username=form.username.data,
            email=form.email.data,
            password=hashed_password,
            name=form.name.data,
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
                birthday=form.birthday.data,
                gender=form.gender.data,
                phonenumber=form.phonenumber.data,
                selectcourse=form.selectcourse.data,
                selectcoursetime=form.selectcoursetime.data,
                address=form.address.data,
                line=form.line.data,
                city=form.city.data,
                zipcode=form.zipcode.data,
            )

            new_form.user = current_user

            db.session.add(new_form)
            db.session.commit()

            # Handle material upload only if the form submission is valid
            if form.material_file.data:
                # Save the uploaded file to a directory (you can customize this)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(
                    form.material_file.data.filename))
                form.material_file.data.save(file_path)

                # Create a new material associated with the form submission
                new_material = Material(
                    name=form.material_name.data,
                    description=form.material_description.data,
                    file_path=file_path,
                    form_id=new_form.id
                )

                db.session.add(new_material)
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

    if edited_form is None:
        return redirect(url_for('dashboard'))

    if form.validate_on_submit():
        # Update the form record with the edited data
        edited_form.name = form.name.data
        edited_form.birthday = form.birthday.data
        edited_form.gender = form.gender.data
        edited_form.phonenumber = form.phonenumber.data
        edited_form.selectcourse = form.selectcourse.data
        edited_form.selectcoursetime = form.selectcoursetime.data
        edited_form.address = form.address.data
        edited_form.line = form.line.data
        edited_form.city = form.city.data
        edited_form.zipcode = form.zipcode.data

        db.session.commit()
        return redirect(url_for('dashboard'))

    # Populate the form fields with existing data
    form.name.data = edited_form.name
    form.birthday.data = edited_form.birthday
    form.gender.data = edited_form.gender
    form.phonenumber.data = edited_form.phonenumber
    form.selectcourse.data = edited_form.selectcourse
    form.selectcoursetime.data = edited_form.selectcoursetime
    form.address.data = edited_form.address
    form.line.data = edited_form.line
    form.city.data = edited_form.city
    form.zipcode.data = edited_form.zipcode

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


@app.route("/download_material/<int:material_id>")
def download_material(material_id):
    material = Material.query.get(material_id)

    if material:
        return send_file(material.file_path, as_attachment=True)
    else:
        return redirect(url_for('dashboard'))


@app.route("/delete_material/<int:material_id>")
@login_required
def delete_material(material_id):
    material = Material.query.get(material_id)

    if material:
        # Check if the material belongs to the current user's form
        if material.form.user_id == current_user.id:
            # Delete the material file from the filesystem
            os.remove(material.file_path)

            # Delete the material from the database
            db.session.delete(material)
            db.session.commit()
        else:
            flash('Unauthorized to delete this material', 'error')

    return redirect(url_for('dashboard'))


@app.route("/about.html")
def about():
    return render_template("about.html")


@app.route("/add_blog.html", methods=['GET', 'POST'])
@login_required
def addblog():
    form = BlogForm()

    if form.validate_on_submit():
        post = Blog(
            title=form.title.data,
            content=form.content.data,
            author=form.author.data,
            slug=form.slug.data,
            # user_id=current_user.id
        )

        post.date_posted = datetime.utcnow()

        form.title.data = ''
        form.content.data = ''
        form.author.data = ''
        form.slug.data = ''
        # form.user_id.data = ''

        db.session.add(post)
        db.session.commit()

        flash("Blog Post successful")

    return render_template("add_blog.html", form=form)


@app.route("/blog.html")
# @login_required
def blog():
    # posts = Blog.query.order_by(Blog.author)
    # return render_template("blog.html", posts=posts)

    user = current_user
    posts = Blog.query.order_by(Blog.author)

    return render_template("blog.html", posts=posts, user=current_user)


@app.route("/business.html")
def business():
    return render_template("business.html")


@app.route("/coming_soon.html")
def coming_soon():
    return render_template("coming_soon.html")


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
