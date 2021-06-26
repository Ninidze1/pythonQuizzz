import ipaddress
import json
import hashlib

import requests
from flask import Flask, render_template, redirect, request, session, flash
from flask_sqlalchemy import SQLAlchemy
import sqlite3


def valid_ip(address):
    try:
        ipaddress.ip_address(address)
        return True
    except:
        return False


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///iphistory.sqlite'
app.config['SECRET_KEY'] = 'qrdbvfoipueadmvfrwertum'
db = SQLAlchemy(app)


class ipaddresses(db.Model):
    ID = db.Column(db.Integer, primary_key=True)
    IP_ADDRESS = db.Column(db.String, nullable=False)

    def __str__(self):
        return f'{self.IP_ADDRESS}'


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/history')
def history():
    return render_template('history.html')


@app.route('/login', methods=['POST', 'GET'])
def login():
    users = dict()
    conn = sqlite3.connect('users.sqlite')
    cursor = conn.cursor()

    cursor.execute('''SELECT * FROM users''')

    for each in cursor.fetchall():
        users[each[0]] = each[1]

    if request.method == "POST":
        username = request.form['loginusername']
        password = request.form['loginpassword']
        encrypted_pass = hashlib.md5(password.encode()).hexdigest()

        if (username in users.keys()) and (encrypted_pass in users.values()):
            session['username'] = username
            return redirect('iplookup')
        else:
            flash("Incorrect input")

    return render_template('login.html')


@app.route('/register', methods=['POST', 'GET'])
def register():
    global user_connection, conn

    conn = sqlite3.connect('users.sqlite')
    cursor = conn.cursor()
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        encrypted_pass = hashlib.md5(password.encode()).hexdigest()

        if username != "" and password != '':
            cursor.execute(f"SELECT count(*) FROM users WHERE USERNAME = '{username}'")
            count = cursor.fetchone()[0]
            if count == 0:
                cursor.execute("INSERT INTO users (USERNAME, PASSWORD) VALUES (?,?)", (username, encrypted_pass))
                conn.commit()
                session['username'] = username
                return render_template('iplookup.html')
            else:
                flash("User already exits")
        else:
            flash("Username or password must not be empty")
    return render_template('register.html')


@app.route('/iplookup', methods=['POST', 'GET'])
def iplookup():
    if request.method == 'POST':
        ip = request.form['ip']
        if ip != "" and valid_ip(ip):
            b1 = ipaddresses(IP_ADDRESS=ip)
            db.session.add(b1)
            db.session.commit()
            flash("Info was sent successfully", 'error')
            return redirect('data')
        else:
            flash("wrong input ", 'error')
    return render_template('iplookup.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    return render_template('index.html')


@app.route('/data', methods=['POST', 'GET'])
def data():
    ip_list = ipaddresses.query.all()
    ip_from_field = str(ip_list[-1])

    token = '2c7863a34f2f06'
    url = f"https://ipinfo.io/{ip_from_field}?token={token}"
    req = requests.get(url)
    res = req.text
    cont = json.loads(res)
    if request.method == 'POST':
        return redirect(f'https://maps.google.com/?q={cont["loc"]}')
    return render_template('data.html', data=cont)


if __name__ == '__main__':
    app.run(debug=True)
