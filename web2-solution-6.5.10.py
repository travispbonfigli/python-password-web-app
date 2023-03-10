#
##
import pyotp
import sqlite3
import hashlib
import uuid
from flask import Flask, request, render_template, url_for, redirect

app = Flask(__name__)
db_name = 'webtest.db'

@app.route('/')
def index():
    return render_template('index.html')

##
## Creating Plaintext Passwords...
##
@app.route('/signup/v1', methods=['POST'])
def signup_v1():
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS USER_PLAIN(USERNAME TEXT PRIMARY KEY NOT NULL,PASSWORD TEXT NOT NULL);''')
    conn.commit()

    try:
        c.execute("INSERT INTO USER_PLAIN (USERNAME,PASSWORD) " "VALUES ('{0}', '{1}')".format(request.form['username'],request.form['password']))
        conn.commit()
    except sqlite3.IntegrityError:
        return "username has already been registered."

    print('username: ', request.form['username'], ' password: ', request.form['password'])
    return render_template('signup_success.html')

def verify_plain(username, password):
    conn = sqlite3.connect('webtest.db')
    c = conn.cursor()
    query = "SELECT PASSWORD FROM USER_PLAIN WHERE USERNAME = '{0}'".format(username)
    c.execute(query)
    records = c.fetchone()
    conn.close()

    if not records:
        return False
    return records[0] == password

@app.route('/login/v1', methods=['GET', 'POST'])
def login_v1():
    error = None

    if request.method == 'POST':
        if verify_plain(request.form['username'], request.form['password']):
            return redirect(url_for('login_success'))
        else:
            error = 'Invalid username/password'
    else:
        error = 'Invalid Method'
    return error

## Hashed Passwords
##
@app.route('/signup/v2', methods=['GET', 'POST'])
def signup_v2():
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS USER_HASH(USERNAME TEXT PRIMARY KEY NOT NULL, HASH TEXT NOT NULL);''')
    conn.commit()

    try:
        hash_value = hashlib.sha256(request.form['password'].encode()).hexdigest()
        c.execute("INSERT INTO USER_HASH (USERNAME, HASH) " "VALUES ('{0}', '{1}')".format(request.form['username'], hash_value))
        conn.commit()
    except sqlite3.IntegrityError:
        return "username has been registered."

    print('username: ', request.form['username'], ' password: ', request.form['password'], ' hash: ', hash_value)
    return render_template('signup_success.html')

def verify_hash(username, password):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    query = "SELECT HASH FROM USER_HASH WHERE USERNAME = '{0}'".format(username)
    c.execute(query)
    records = c.fetchone()
    conn.close()

    if not records:
        return False
    return records[0] == hashlib.sha256(password.encode()).hexdigest()

@app.route('/login/v2', methods=['GET', 'POST'])
def login_v2():
    error = None

    if request.method == 'POST':
        if verify_hash(request.form['username'], request.form['password']):
            return redirect(url_for('login_success'))
        else:
            error = 'Invalid username/password'
    else:
        error = 'Invalid Method'
    return error

@app.route('/login_success')
def login_success():
    return render_template('login_success.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=7777, ssl_context='adhoc')
