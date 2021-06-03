import os
import phishing_detection
from flask import Flask
from flask_mysqldb import MySQL, MySQLdb
import bcrypt
from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from flask import jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__)

app.secret_key = "toughsituation-75"

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'flaskdb'
app.config['MYSQL_PORT'] = 3308
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
mysql = MySQL(app)

UPLOAD_FOLDER = '/files'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'py'])


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/result')
def result():
    url = request.args['url']
    result = phishing_detection.getResult(url)
    return result


@app.route('/', methods=['GET', 'POST'])
def hello():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('no file part')
            return "false"
        file = request.files['file']
        if file.filename == '':
            flash('no select file')
            return 'false'
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            contents = file.read()
            with open("files/URL.txt", "wb") as f:
                f.write(contents)
            file.save = (os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return render_template("index.html")
    return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == 'GET':
        return render_template("register.html")
    else:
        name = request.form['name']
        email = request.form['email']
        password = request.form['password'].encode('utf-8')
        hash_password = bcrypt.hashpw(password, bcrypt.gensalt())

        cur = mysql.connection.cursor()
        cur.execute('''INSERT INTO users (name, email, password) VALUES (%s,%s,%s)''', (name, email, hash_password,))
        mysql.connection.commit()
        session['name'] = request.form['name']
        session['email'] = request.form['email']
        return redirect(url_for('hello'))


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password'].encode('utf-8')

        curl = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        curl.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = curl.fetchone()
        curl.close()

        if len(user) > 0:
            if bcrypt.hashpw(password, user["password"].encode('utf-8')) == user["password"].encode('utf-8'):
                session['name'] = user['name']
                session['email'] = user['email']
                return render_template("index.html")
            else:
                return "Error password and email not match"
        else:
            return "Error user not found"
    else:
        return render_template("login.html")


@app.route('/logout')
def logout():
    session.clear()
    return render_template("index.html")


if __name__ == '__main__':
    app.run(debug=True)
