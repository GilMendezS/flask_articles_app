from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField,validators
from passlib.hash import sha256_crypt
from functools import wraps
from data import Articles

app = Flask(__name__)
# Config Mysql
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'flask'
app.config['MYSQL_PASSWORD'] = 'flask'
app.config['MYSQL_DB'] = 'flask_articles'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
# Initialize Mysql
mysql = MySQL(app)

Articles = Articles()

@app.route('/')
def index():
	return render_template('home.html')

@app.route('/about')
def about():
	return render_template('about.html')
@app.route('/articles')
def articles():
	return render_template('articles.html', articles = Articles)
@app.route('/articles/<string:id>')
def article(id):
	return render_template('article.html', id = id)

class RegisterForm(Form):
	name = StringField('Name', [validators.Length(min=1, max=50)])
	username = StringField('Username', [validators.Length(min=5, max=50)])
	email = StringField('Email', [validators.Length(min=6, max=50)])
	password = PasswordField('Password', [
		validators.DataRequired(),
		validators.EqualTo('confirm', message="Passwords do not match")
	])
	confirm = PasswordField('Confirm Password')
@app.route('/register', methods=['GET','POST'])
def register():
	form = RegisterForm(request.form)
	if request.method == 'POST' and form.validate():
		name = form.name.data
		email = form.email.data
		username = form.username.data
		password = sha256_crypt.encrypt(str(form.password.data))

		#Create cursor
		cursor = mysql.connection.cursor()
		cursor.execute("INSERT INTO users(name, email, username, password) VALUES(%s,%s,%s,%s)", (name,email, username, password))
		# commit to db
		mysql.connection.commit()
		# close connection
		cursor.close()
		flash('You are now registered and can log in','success')
		return redirect(url_for('index'))
	return render_template('auth/register.html', form = form)
@app.route('/login', methods=['GET','POST'])
def login():
	if request.method == 'POST':
		username = request.form['username']
		password_candidate = request.form['password']
		#cursor
		cursor = mysql.connection.cursor()
		result = cursor.execute("SELECT * from users where username=%s", [username])
		if result > 0:
			data = cursor.fetchone()
			password = data['password']
			if sha256_crypt.verify(password_candidate, password):
				session['loggedin'] = True
				session['username'] = username
				return redirect(url_for('dashboard'))
			else :
				flash('Invalid Password', 'danger')
				return render_template('auth/login.html')
			cursor.close();
		else:
			flash('Invalid username', 'danger')
			return render_template('auth/login.html')
	return render_template('auth/login.html')
def is_logged_in(f):
	@wraps(f)
	def wrap(*args, **kwargs):
		if 'loggedin' in session:
			return f(*args, **kwargs)
		else:
			flash('Unauthorized, please login', 'danger')
			return redirect(url_for('login'))
	return wrap

@app.route('/dashboard')
@is_logged_in
def dashboard():
	return render_template('users/dashboard.html')


@app.route('/logout', methods=['POST'])
def logout():
	if request.method == 'POST':
		session.clear();
		return redirect(url_for('login'))
if __name__ == '__main__':
	app.secret_key = 'secret123'
	app.run(debug=True)