import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required

#Import Google data:
import atom.data
import gdata.data
import gdata.contacts.client
import gdata.contacts.data
# ...
  gd_client = gdata.contacts.client.ContactsClient(source='YOUR_APPLICATION_NAME')
  # Authorize the client.
# ...

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///users.db")

# Make sure API key is set
#if not os.environ.get("API_KEY"):
#    raise RuntimeError("API_KEY not set")

@app.route("/")
@login_required
def index():
    #get the user_id
    user_id = session["user_id"]

    #Need to show a table with all the user's contacts
    contacts = db.execute("SELECT * FROM contacts WHERE user_id= :user_id", user_id=user_id)
    return render_template("/index.html", contacts=contacts)

@app.route("/delete", methods=["GET", "POST"])
@login_required
def delete():
    if request.method == "GET":
        return render_template("/")
    else:
        #Get the email address of the selected contact
        current_contact = request.form.get('contact')

        #If this contact doesn't have an email, then we cannot delete it
        if not current_contact:
            return apology("Dont have an email to delete", 403)

        #Need to delete the contact
        db.execute("DELETE FROM contacts WHERE email= :current_contact", current_contact=current_contact)

        #Return to the main viewe
        return redirect("/")

@app.route("/login", methods=["GET", "POST"])
def login():
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET
    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    if request.method == 'GET':
        return render_template('/add.html')
    else:
        #get the user_id
        user_id = session["user_id"]

        #require that a user input a first name:
        first_name = request.form.get("first_name")
        if not first_name:
            return apology("you must provide a name", 403)

        #require that a user input an email:
        email = request.form.get("email")
        if not email:
            return apology("you must provide an email", 403)

        #save the users other inputs
        last_name = request.form.get("last_name")
        phone = request.form.get("phone")
        school = request.form.get("school")
        company = request.form.get("company")
        street_address = request.form.get("street_address")
        category = request.form.get("category")
        notes = request.form.get("notes")
        favorite = request.form.get("favorite")

        #ensure that a user doesnt already exist by querying database for first_name and last_name
        firstnames = db.execute("SELECT first_name FROM contacts WHERE first_name = :first_name", first_name=request.form.get("first_name"))
        for firstname in firstnames:
            if firstname["first_name"] == first_name:
                lastnames = db.execute("SELECT last_name FROM contacts WHERE last_name = :last_name", last_name=request.form.get("last_name"))
                for lastname in lastnames:
                    if lastname["last_name"] == last_name:
                        return apology("You already have this contact in your database!")

        #insert the values
        db.execute("INSERT INTO contacts (user_id, first_name, last_name, email, phone, school, company, street_address, category, notes, favorite) VALUES (:user_id, :first_name, :last_name, :email, :phone, :school, :company, :street_address, :category, :notes, :favorite)", user_id=user_id, first_name=first_name, last_name=last_name, email=email, phone=phone, school=school, company=company, street_address=street_address, category=category, notes=notes, favorite=favorite)
        return redirect("/")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == 'GET':
        return render_template('/register.html')
    else:
        #get the user to provide a username
        username = request.form.get("username")
        if not username:
            return render_template('/apology.html', message="you must provide a username")

        #Ensure that the username doesnt already exist
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))
        if len(rows) != 0:
            return apology("username already exists", 403)

        #Check that the two passwords match
        password = request.form.get("password")
        password2 = request.form.get("password2")
        if password != password2:
            return apology("your passwords dont match", 403)

        #function to hash the password
        hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        if not password:
            return render_template('/apology.html', message='you must provide password')
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)", username=username, hash=hash)
        return redirect("/")

@app.route("/edit", methods=["GET", "POST"])
@login_required
def edit():
    if request.method == 'POST':

        #get the user_id
        user_id = session["user_id"]

        #get the contact email
        email = request.form.get('email')

        #Query the database for contact info
        contact_info = {}
        contact_info = db.execute("SELECT * FROM contacts WHERE user_id= :user_id AND email= :email", user_id=user_id, email=email)

        return render_template('/edit.html', email=email, contact_info=contact_info)

@app.route("/updatenotes", methods=["POST"])
@login_required
def update():
    if request.method == 'POST':

        #get the user_id
        user_id = session["user_id"]

        #get the contact email
        first_name = request.form.get('email')

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
