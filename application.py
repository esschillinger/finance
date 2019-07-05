import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

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

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    
    user_id = session["user_id"]
    
    stocks = db.execute("SELECT * FROM stocks WHERE user_id=:user_id;", user_id=user_id)
    
    cash = db.execute("SELECT * FROM users WHERE id=:user_id", user_id=user_id)[0]["cash"]
    
    stocks_formatted = []
    total = cash
    
    for stock in stocks:
        symbol = stock["symbol"]
        name = lookup(symbol)["name"]
        price = lookup(symbol)["price"]
        shares = stock["shares"]
        
        temp_total = price * shares
        total += temp_total
        
        stocks_formatted.append({
            "symbol" : symbol,
            "name" : name,
            "shares" : shares,
            "price" : usd(price),
            "total" : usd(temp_total)
        })
        
    return render_template("index.html", stocks=stocks_formatted, cash=usd(cash), total=usd(total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    
    if request.method == "GET":
        return render_template("buy.html")
    
    symbol = request.form.get("symbol")
    
    if symbol == "Symbol":
        return apology("Please choose a ticker")
    
    stock = lookup(symbol)
    
    if not stock:
        return apology("Please enter a valid ticker")
    
    shares = request.form.get("shares")
    
    if not shares:
        return apology("Please enter a number of shares")
    
    try:
        num_shares = int(shares)
    except ValueError:
        return apology("Please enter an integer")
    
    current_user = session["user_id"]
    
    cash = db.execute("SELECT * FROM users WHERE id=:current_id", current_id=current_user)[0]["cash"]
    
    cost = num_shares * stock["price"]
    if cost <= 0 or cost > cash:
        return apology("Invalid purrrrrchase")
    
    new_cash = cash - cost
    
    potential_stock = db.execute("SELECT * FROM stocks WHERE user_id=:user_id AND symbol=:symbol", user_id=current_user, symbol=symbol)
            
    if len(potential_stock) == 0:
        db.execute("INSERT INTO stocks (user_id, symbol, shares) VALUES (:user, :sym, :share);", user=current_user, sym=symbol, share=num_shares)
    else:
        prev_shares = potential_stock[0]["shares"]
        new_shares = prev_shares + num_shares
        db.execute("UPDATE stocks SET shares=:new_shares WHERE user_id=:current_id AND symbol=:symbol", new_shares=new_shares, current_id=current_user, symbol=symbol)
    
    db.execute("UPDATE users SET cash=:cash WHERE id=:current_id", cash=new_cash, current_id=current_user)
    
    return redirect("/")


@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    """Change user's password"""
    if request.method == "GET":
        return render_template("change.html")
    
    user_id = session["user_id"]
    
    old = request.form.get("old-password")
    new = request.form.get("new-password")
    retyped = request.form.get("confirmation")
    
    old_hash = db.execute("SELECT * FROM users WHERE id=:user_id", user_id=user_id)[0]["hash"]
    
    if not check_password_hash(old_hash, old):
        return apology("The original password you typed did not match our records")
    
    if not new == retyped:
        return apology("Your new password does not match the confirmation")
    
    db.execute("UPDATE users SET hash=:new_hash WHERE id=:user_id", new_hash=generate_password_hash(new), user_id=user_id)
    
    return redirect("/")
    
@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

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

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "GET":
        return render_template("quote.html")
    
    symbol = request.form.get("symbol")
    
    if not symbol:
        return apology("Please enter a symbol")
    
    stock = lookup(symbol)
    
    if not stock:
        return apology("Please enter a valid ticker")
    
    return render_template("quoted.html", stock=stock)
    

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    elif request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        
        if not username:
            return apology("Please enter a valid username")
    
        match = db.execute("SELECT * FROM users WHERE username = :username", username=username)
    
        if len(match) == 1:
            return apology("This username is already taken")

        if not password or not confirmation or not password == confirmation:
            return apology("Please enter a valid password and retype it")
    
        hashed = generate_password_hash(password)
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :password);", username=username, password=hashed)
    
        return render_template("login.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user_id = session["user_id"]
    user = db.execute("SELECT * FROM users WHERE id=:user_id", user_id=user_id)[0]
    stocks = db.execute("SELECT * FROM stocks WHERE user_id=:user_id", user_id=user_id)
    
    if request.method == "GET":
        return render_template("sell.html", stocks=stocks)
    
    symbol = request.form.get("symbol")
    if symbol == "Symbol":
        return apology("Please select a ticker")
    potential_stock = db.execute("SELECT * FROM stocks WHERE user_id=:user_id AND symbol=:symbol", user_id=user_id, symbol=symbol)
    
    if len(potential_stock) == 0:
        return apology("Please select a stock of which you have a share")
    
    shares = request.form.get("shares")
    if not shares:
        return apology("Please enter a number of shares")
    
    try:
        num_shares = int(shares)
    except ValueError:
        return apology("Please enter an integer")
    
    shares_owned = potential_stock[0]["shares"]
    price = lookup(symbol)["price"]
    
    cash_back = price * num_shares
    
    if num_shares <= 0 or num_shares > shares_owned:
        return apology("Please enter a valid integer")
    elif num_shares == shares_owned:
        db.execute("DELETE FROM stocks WHERE user_id=:user_id AND symbol=:symbol", user_id=user_id, symbol=symbol)
    else:
        db.execute("UPDATE stocks SET shares=:shares WHERE user_id=:user_id", shares=shares_owned - num_shares, user_id=user_id)
    
    prev_cash = user["cash"]
    db.execute("UPDATE users SET cash=:cash WHERE id=:user_id", cash=prev_cash + cash_back, user_id=user_id)
    
    return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
