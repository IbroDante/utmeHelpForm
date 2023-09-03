from flask import Flask, render_template

app = Flask(__name__)

@app.route("/")
def main():
	return render_template("index.html")

@app.route("/index.html")
def index():
	return render_template("index.html")

@app.route("/login.html")
def login():
	return render_template("login.html")

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

@app.route("/register.html")
def register():
	return render_template("register.html")

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
