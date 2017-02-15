from flask import Flask, request, redirect, render_template, session, flash
from mysqlconnection import MySQLConnector
import re
from flask.ext.bcrypt import Bcrypt

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
NAME_REGEX = re.compile(r'([a-zA-Z]{2,})', re.MULTILINE)
PWORD_REGEX = re.compile(r'((?=.*?\d)(?=.*?[A-Z])(?=.*?[a-z])[A-Za-z\d]{8,}$)', re.MULTILINE)
app = Flask(__name__)
mysql = MySQLConnector(app, 'mydb')
bcrypt = Bcrypt(app)
app.secret_key = "Thisissecret!"
password = 'password'


# THIS FUNCTION CHECKS TO SEE IF INPUT IS VALID, CALL IT INSIDE OTHER FUNCTIONS WHEN NEEDED WITH THE APPROPIATE PARAMETERS
def invalid(first_name, last_name, email, password, passwordc):
    errors = False
    if len(first_name) < 2 or len(last_name) < 2:
        flash('Name is too short')
        errors = True
    if len(email) < 1:
        flash('Email is too short')
        errors = True
    if len(password) < 8:
        flash('Password must be at least 8 characters ')
        errors = True
    #type validate
    if not EMAIL_REGEX.match(email):
        flash("Invalid Email Address!")
        errors = True
    if not (re.search(r"^[^0-9]*$", first_name) and re.search(r"^[^0-9]*$", last_name)):
        flash('Name cannot contain numbers.')
        errors = True
    if password != passwordc:
        flash('Passwords do not match!')
        errors = True
    return errors

@app.route('/', methods=['GET'])
def index():
    if 'user' in session:
        user_query ='SELECT first_name, last_name FROM users WHERE id = :id'
        user_data ={
            'id': session['user']
        }
        query = mysql.query_db(user_query, user_data)
        flash('You are logged in as ' + query[0]['first_name'] + " " + query[0]['last_name'])
    return render_template('index.html')
@app.route('/success', methods=['POST'])
def register():
    print "^(^(^(^(^(^())))))"
    first_name = request.form['first_name']
    last_name = request.form['last_name']
    email = request.form['email']
    password = request.form['password']
    passwordc = request.form['passwordc']
    pw_hash = bcrypt.generate_password_hash(password)
    pw_hashc = bcrypt.generate_password_hash(passwordc)
    query_data = {
                 'first_name': first_name,
                 'last_name': last_name,
                 'email': email,
                 'pw_hash': pw_hash
    }
    errors = False
    errors = invalid(first_name, last_name, email, password, passwordc)
    if not errors:
         print "********************"
         insert_query = "INSERT INTO users (first_name, last_name, email, pw_hash) VALUES (:first_name, :last_name, :email, :pw_hash)"
         mysql.query_db(insert_query, query_data)
    return redirect('/')
@app.route('/login', methods=['POST'])
def member():
    email = request.form['email']
    password = request.form['password']
    user_query = "SELECT * FROM users WHERE email = :email LIMIT 1"
    query_data = { 'email': email }
    user = mysql.query_db(user_query, query_data)
    if bcrypt.check_password_hash(user[0]['pw_hash'], password):
        session['user'] = user[0]['id']
        return render_template('success.html')
    else:
        flash("Login failed!")
        return redirect('/')
app.run(debug=True)
