from flask import Flask, render_template, request, redirect,session,jsonify, url_for
from flask_mail import Mail,Message
import  mysql.connector
import re
import os, time
from random import randint
import random
import hashlib
import sqlite3
from datetime import datetime, timedelta
import secrets
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import json
from apscheduler.schedulers.background import BackgroundScheduler
# import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required,current_user

import base64
# import os
from functools import wraps
from werkzeug.utils import secure_filename
from twilio.rest import Client
from openai import OpenAI
from difflib import get_close_matches
# from flask import flash
from email_validator import validate_email, EmailNotValidError
import smtplib, ssl, random
from flask_bcrypt import Bcrypt, generate_password_hash 
from flask_dance.contrib.google import make_google_blueprint, google
from fuzzywuzzy import process
import ssl
app = Flask(__name__)
app.secret_key="zestpay_sercet"
client = OpenAI(api_key="YOUR_OPENAI_API_KEY")  
mail=Mail(app)


# Sample in-memory database


#password = data.get('password', '')strip()

    #if not all([name, phone, gender, password]):

       # return "jsonify({"error":"missing fields"}), 400

    
        #user = get_user_by_phone(phone)
       # if user and user['password'] == password:   
         #  session['username'] = user  # Store user in session
           #return redirect('/dashboard')
            
        #else:
            #return render_template('login.html', message="Invalid credentials.")
   # return render_template('login.html')


#@app.route('/dashboard')
#def dashboard():
    #user = session.get('user')
    #return render_template('dashboard.html', user=user)










    

@app.route('/')
def index():
    return render_template('index.html')




#


# CORS(app)  # allows frontend fetch to work

# # SQLite DB for demo
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///zestpay.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT']=465
app.config['MAIL_USERNAME']="zestpayexchange@gmail.com"
app.config['MAIL_PASSWORD']="rbhy vche lvmu btkb"
app.config['MAIL_USE_TLS']=False
app.config['MAIL_USE_SSL']=True
app.config['MAIL_DEFAULT_SENDER'] = app.config['MAIL_USERNAME']
mail = Mail(app)
otp=randint(100000,999999)
# ========== User Model ==========
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String(50))
    lastName = db.Column(db.String(50))
    phone = db.Column(db.String(11))
    referral = db.Column(db.String(50))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    # two_fa_enabled = db.Column(db.string(50))
    # session_timeout = db.Column(db.Boolean, default=True)
    # last_login = db.Column(db.DateTime)
    #profilePic = db.Column(db.String(260), nullable=False)  #

# ========== Register ==========
    
    
    
    # is_verified = db.Column(db.Boolean, default=False)
    # otp = db.Column(db.String(6))
    # otp_expiry = db.Column(db.DateTime)



@app.route("/register", methods=["GET","POST"])
def register():
    if not request.is_json:
        return render_template('register.html')

    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"status": "error", "message": "Invalid JSON"}), 400

    email = data.get("email")
    phone = data.get("phone")
    password = data.get("password")

    if not email or not password or not phone:
        return jsonify({"status": "error", "message": "Missing fields"}), 400

    # ✅ Validate email format
    try:
        validate_email(email)  # throws error if invalid
    except EmailNotValidError:
        return jsonify({"status": "invalid_email"}), 400

    # ✅ Check if email already exists
    if User.query.filter_by(email=email).first():
        return jsonify({"status": "email_exists"}), 400

    # ✅ Check if phone number already exists
    if User.query.filter_by(phone=phone).first():
        return jsonify({"status": "phone_exists"}), 400

    # ✅ Basic phone format check (Nigeria example: 11 digits)
    if not re.fullmatch(r"^\d{11}$", phone):
        return jsonify({"status": "invalid_phone"}), 400

    # ✅ Save user
    hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
    new_user = User(
        firstName=data.get("firstName"),
        lastName=data.get("lastName"),
        phone=phone,
        referral=data.get("referral"),
        email=email,
        password=hashed_pw
          
    )
    db.session.add(new_user)
    db.session.commit()
     




 


    # ✅ Send welcome email
    try:
        msg = Message(
            subject="🎉 WELCOME TO ZESTPAY!",
            recipients=[email]
        )
        msg.body = f"""
Hello {data.get("firstName") or ""},

🎉 Welcome to ZestPay — your account has been created successfully!

Here’s what you can do with ZestPay:
- ✅ Send & receive payments instantly
- 📊 Track your transactions in real-time
- 🎁 Earn rewards with referrals
- 🔒 Enjoy secure and fast services

⚡ Login now and start exploring: https://zestpay.com/login

We’re excited to have you onboard 

The ZestPay Team
"""
        mail.send(msg)
    except Exception as e:

        print("❌ Welcome email send failed:", e)

    return jsonify({"status": "ok"})



@app.route("/login", methods=["GET","POST"])

def login():
    
    if not request.is_json:
        return render_template('login.html')

    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"status": "error", "message": "Invalid JSON"}), 400

    email = data.get("email")
    password = data.get("password")

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"status": "invalid"})

    if bcrypt.check_password_hash(user.password, password):
        # ✅ set session for web pages
        session['user_email'] = user.email
        session['user_firstName'] = user.firstName or ""
        session['user_lastName'] = user.lastName or ""

        # ✅ send login email
        try:
            msg = Message(
                subject="👋 Welcome back to ZestPay!",
                recipients=[user.email]
            )
            msg.body = f"""
Hello {user.firstName or ''},

You have successfully logged in to your ZestPay account ✅

Stay tuned for new features and updates 

If you need our help, you can contact us on Email:zestexchange@gmail.com


The ZestPay Team
"""
            mail.send(msg)
        except Exception as e:
            print("❌ Login email failed:", e)

        return jsonify({"status": "ok", "user": {"email": user.email, "firstName": user.firstName}})
    else:
        return jsonify({"status": "invalid"})





def login_required_session(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_email' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


    


# --- Dashboard and related pages ---
# @app.route("/dashboard")
# @login_required_session
# def dashboard():
#     # dashboard.html will fetch profile via AJAX, but we can send name for server-rendered display
#     first = session.get('user_firstName') or ""
#     email = session.get('user_email')
#     return render_template("dashboard.html", firstName=first, email=email)
@app.route("/dashboard")
@login_required_session
def dashboard():
    # Check if user is logged in via session
    if "user_id" not in session:
        # Not logged in — show defaults
        first = "User"
        email = None
       
    else:
        # Logged in — restore data
        first = session.get('user_firstName', "User")
        email = session.get('user_email', None)
        

    return render_template(
        "dashboard.html",
        firstName=first,
        email=email,
        
    )



@app.route("/profile")
@login_required_session
def profile_page():
    return render_template("profile.html")

@app.route("/settings")
@login_required_session
def settings_page():
    return render_template("settings.html")

@app.route("/rates")
@login_required_session
def rates_page():
    return render_template("rates.html")

@app.route("/cards")
@login_required_session
def cards_page():
    return render_template("cards.html")




# --- Logout ---
@app.route("/logout")
@login_required_session
def logout():
    # Keys we want to remove from the session
    session_keys = [
        'user_email',
        'user_firstName',
        'user_lastName',
        'chat_history'
       
    ]

    # If using Flask-Login, clear its user session
    try:
        logout_user()  # safely remove current_user session (no error if unused)
    except:
        pass

    # Remove keys manually if they exist
    for k in session_keys:
        session.pop(k, None)

    # Finally, clear entire session
    session.clear()

    print("✅ User logged out and session cleared completely")

    # Redirect to login page (or wherever you want)
    return redirect(url_for('login'))




# --- Initialize Login Manager ---
login_manager = LoginManager()
login_manager.init_app(app)

# # This is the route name that users will be redirected to if they try to access
# # a protected route without being logged in.
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access this page."



@login_manager.user_loader
def load_user(user_id):
    """Flask-Login user loader — loads a user from the database by ID."""
    user = User.query.get(int(user_id))
    if user:
        # Sync user info into Flask session for easy access later
        session['user_id'] = user.id
        session['user_email'] = user.email
        session['user_firstName'] = getattr(user, 'firstName', 'User')
        session['user_lastName'] = getattr(user, 'lastName', '')
        session.setdefault('chat_history', [])  # Create if not exist
    return user


















# --- Init AI Memory DB ---



# Initialize OpenAI client (replace with your actual API key)


# In-memory chat history for demo (in production, use Redis or database)
chat_history = {}

# Mock user database (replace with real database)
users_db = {
    "demo@example.com": {
        "id": "user_123",
        "name": "David Afiakurue",
        "email": "demo@example.com",
        "password": "demo123",  # In production, use hashed passwords
        "avatar": None
    },
    "john@example.com": {
        "id": "user_456", 
        "name": "John Doe",
        "email": "john@example.com",
        "password": "john123",
        "avatar": None
    }
}

def init_ai_memory():
    conn = sqlite3.connect("zestpay_ai.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS memory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            question TEXT,
            answer TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def init_users_db():
    conn = sqlite3.connect("zestpay_ai.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            avatar TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def save_answer(question, answer):
    conn = sqlite3.connect("zestpay_ai.db")
    c = conn.cursor()
    c.execute("INSERT INTO memory (question, answer) VALUES (?, ?)", (question, answer))
    conn.commit()
    conn.close()

def get_stored_answer(user_input):
    conn = sqlite3.connect("zestpay_ai.db")
    c = conn.cursor()
    c.execute("SELECT question, answer FROM memory")
    rows = c.fetchall()
    conn.close()

    if not rows:
        return None

    questions = [r[0] for r in rows]
    matches = get_close_matches(user_input, questions, n=1, cutoff=0.7)
    if matches:
        for q, a in rows:
            if q == matches[0]:
                return a
    return None

def get_user_by_email(email):
    conn = sqlite3.connect("zestpay_ai.db")
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = c.fetchone()
    conn.close()
    
    if user:
        return {
            "id": user[0],
            "name": user[1],
            "email": user[2],
            "avatar": user[4]
        }
    return None

def create_user(name, email, password):
    conn = sqlite3.connect("zestpay_ai.db")
    c = conn.cursor()
    user_id = f"user_{uuid.uuid4().hex[:8]}"
    try:
        c.execute(
            "INSERT INTO users (id, name, email, password) VALUES (?, ?, ?, ?)",
            (user_id, name, email, password)  # In production, hash the password
        )
        conn.commit()
        return {"id": user_id, "name": name, "email": email}
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()

# Initialize databases on startup
init_ai_memory()
init_users_db()

# TalkSmart Bank responses (keeping your existing responses)
talksmart = {
    # Greetings
    "hi": "Hello 👋 How can I help you today?",
    "hello": "Hey there! 😊",
    "hey": "Hi 👋 What's up?",
    "yo": "Yo 😎 How's it going?",
    "sup": "Not much, just here to help you with ZestPay!",
    "good morning": "Good morning ☀️ Hope your day is going well!",
    "good afternoon": "Good afternoon 🌞 How can I assist you?",
    "good evening": "Good evening 🌙 Ready to explore ZestPay?",
    "good night": "Good night 🌙 Rest well!",
    "okay": "sure",
    
    # Feelings
    "fine": "Glad to hear you're fine! 👍",
    "i am fine": "Awesome! 😊 Do you want to check your balance or explore?",
    "how are you": "I'm doing great, thanks for asking! How are you?",
    "i am okay": "Good to know 👍 What's next on your mind?",
    "how about you": "good! thank you",

    # Thanks
    "thanks": "You're welcome! 🙏",
    "thank you": "Anytime! Happy to help 👍",
    "tnx": "You're welcome! 💯",

    # Fun words
    "lol": "😂 Haha, glad you're having fun!",
    "lmao": "🤣 That's hilarious!",
    "omg": "😲 Oh wow!",

    # Bye
    "bye": "Goodbye 👋 See you again soon.",
    "see you": "See you later! 👋",
    "take care": "You too! Stay safe ✨",

    # ZestPay Info
    "who owns zestpay": "ZestPay is owned by David Afiakurue — a visionary entrepreneur passionate about financial technology, innovation, and making payments seamless.",
    "what is zestpay": "ZestPay is a smart digital platform for payments, cards, and seamless financial services.",
    "tell me about zestpay": "ZestPay helps you send, receive, and manage money with ease. Secure, fast, and reliable!",
    "who is david afiakurue": "David Afiakurue is the founder of ZestPay. He is dedicated to building modern payment systems that empower people worldwide.",
    "about david afiakurue": "David Afiakurue is a fintech innovator and entrepreneur. He created ZestPay to solve real financial challenges with smart technology.",
    
    # ZestPay Deep Info & FAQs
    "what does zestpay do": "ZestPay is a digital payment system that lets you send, receive, and manage money with ease — fast, secure, and user-friendly.",
    "how does zestpay work": "ZestPay connects your wallet, cards, and bank seamlessly so you can make transfers, payments, and purchases instantly.",
    "is zestpay safe": "Yes ✅ ZestPay uses advanced encryption and 2FA to make sure your funds and data are always secure.",
    "is zestpay legit": "Absolutely! ZestPay is a verified and trusted fintech brand founded by David Afiakurue.",
    "zestpay owner": "ZestPay was founded and is owned by David Afiakurue — a passionate fintech entrepreneur.",
    "where is zestpay located": "ZestPay operates globally online but is proudly built in Nigeria 🇳🇬 with users worldwide.",
    "what country is zestpay from": "ZestPay is a Nigerian fintech company with a global vision 🌍.",
    "when was zestpay founded": "ZestPay was founded by David Afiakurue to make payments simpler, smarter, and more secure.",
    "zestpay founder": "David Afiakurue is the founder and CEO of ZestPay.",
    "what makes zestpay special": "ZestPay combines simplicity, security, and speed — giving you total control over your digital finances.",
    "who created zestpay": "ZestPay was created by David Afiakurue — a visionary fintech developer and entrepreneur.",
    "how to register on zestpay": "You can sign up easily on the ZestPay registration page using your email or phone number.",
    "how to login on zestpay": "Simply visit the login page, enter your details, and access your dashboard securely.",
    "how to verify zestpay account": "Go to your profile and follow the verification steps to activate full features.",
    "can i withdraw from zestpay": "Yes, you can withdraw anytime to your linked bank account with just a few taps 💸.",
    "can i send money with zestpay": "Absolutely! You can send money instantly to any ZestPay user or bank account.",
    "can i receive money with zestpay": "Yes, you can receive money easily with your ZestPay wallet address or linked email.",
    "zestpay app": "The ZestPay app gives you 24/7 access to your wallet, cards, and transactions anywhere.",
    "does zestpay have mobile app": "Yes! The mobile app lets you send, receive, and manage funds on the go 📱.",
    "zestpay wallet": "Your ZestPay wallet keeps your funds safe and ready for instant transfers or purchases.",
    "zestpay card": "ZestPay virtual cards let you shop and pay online securely anywhere in the world 🌐.",
    "how to get zestpay card": "Simply request a card in your dashboard — virtual or physical, it's your choice!",
    "how to fund zestpay wallet": "You can fund your wallet using your card, bank transfer, or USSD options.",
    "how to check zestpay balance": "Login to your ZestPay dashboard — your balance is displayed right at the top.",
    "zestpay limits": "Transaction limits depend on your verification level. Upgrade to increase your daily limits!",
    "zestpay verification": "Account verification helps keep your wallet secure and unlocks higher limits.",
    "zestpay referral": "Invite your friends to ZestPay and earn instant rewards 💰 when they start using it.",
    "zestpay bonus": "ZestPay sometimes offers special referral or deposit bonuses — watch for updates!",
    "zestpay support": "You can contact ZestPay support through email, WhatsApp, or the in-app chat.",
    "zestpay whatsapp": "Chat with ZestPay support instantly on WhatsApp for quick help.",
    "zestpay email": "You can email ZestPay support directly for help or feedback.",
    "zestpay website": "Visit the official ZestPay website to explore features and get started.",
    "zestpay features": "ZestPay offers wallets, cards, instant transfers, currency exchange, and smart savings.",
    "zestpay goals": "ZestPay's mission is to simplify digital payments and empower financial freedom.",
    "zestpay slogan": "ZestPay — Smart, Secure, and Seamless 💳.",
    "zestpay meaning": "The name 'ZestPay' stands for energy, speed, and enthusiasm in payments ⚡.",
    "is zestpay available worldwide": "Yes, ZestPay is designed to serve users globally 🌍.",
    "how to contact zestpay": "You can reach ZestPay through email, WhatsApp, or in-app support chat.",
    "zestpay team": "ZestPay is powered by an innovative team led by David Afiakurue.",
    "zestpay mission": "To make global payments simple, smart, and accessible to everyone.",
    "zestpay vision": "To connect people and businesses through seamless financial technology.",
    "zestpay updates": "ZestPay updates regularly with new features — stay tuned 🔔.",
    "is zestpay free": "Yes, creating a ZestPay account is 100% free.",
    "does zestpay charge fees": "ZestPay has small transaction fees depending on service type — all shown before you confirm.",
    "zestpay transfer": "ZestPay lets you transfer money instantly, 24/7.",
    "how to trade on zestpay": "Go to your ZestTrade section inside ZestPay to start trading instantly.",
    "zestpay rate": "ZestPay offers real-time exchange rates for transparency 📊.",
    "zestpay ai": "ZestPay AI helps automate your payments, support, and smart spending decisions 🤖.",
    "zestpay chatbot": "I'm the ZestPay AI assistant — here to guide you every step of the way 😎.",
    "zestpay ceo": "The CEO of ZestPay is David Afiakurue — an experienced fintech leader.",
    "zestpay developer": "ZestPay was built by David Afiakurue and his development team.",
    "zestpay contact": "You can contact us directly through our support page or WhatsApp channel.",
    "zestpay exchange": "ZestPay Exchange allows you to swap currencies instantly and securely.",
    "how to buy crypto on zestpay": "You can buy crypto directly inside ZestPay — fast, safe, and simple 🚀.",
    "how to sell crypto on zestpay": "ZestPay lets you sell crypto and withdraw to your wallet or bank easily.",
    "zestpay crypto": "ZestPay supports multiple cryptocurrencies for payments and trading 💎.",
    "zestpay transfer limit": "Your limit depends on your verification level — upgrade for higher limits.",
    "how to delete zestpay account": "You can request account deletion via support — but we'd love to have you stay 😊.",
    "zestpay history": "ZestPay was founded by David Afiakurue as a modern fintech to simplify payments across Africa and beyond.",
    "zestpay origin": "ZestPay began in Nigeria, with a goal to connect users globally through seamless transactions 🌍.",
    "zestpay security": "ZestPay uses bank-level encryption, OTPs, and fraud protection for your safety 🔒.",
     
    # Quick actions
    "login": "Sure, I'll take you to the login page.",
    "register": "Let's get you signed up on ZestPay!",
    "dashboard": "Opening your dashboard 🖥️",
    "cards": "Here are your cards 💳",
    "rates": "Fetching today's rates 📊",
    "profile": "Opening your profile 👤",
    "settings": "Going to settings ⚙️",
    "logout": "Logging you out. Come back soon 👋",
    "supports": "chat with support on whatsapp",
    "roadmap": "going",
}



@app.route("/api/current-user", methods=["GET"])
def get_current_user():
    if "user_id" in session:
        user_id = session["user_id"]
        conn = sqlite3.connect("zestpay_ai.db")
        c = conn.cursor()
        c.execute("SELECT id, name, email, avatar FROM users WHERE id = ?", (user_id,))
        user = c.fetchone()
        conn.close()
        
        if user:
            return jsonify({
                "id": user[0],
                "name": user[1],
                "email": user[2],
                "avatar": user[3]
            })
    
    return jsonify({"error": "Not logged in"}), 401



@app.route("/api/ai", methods=["POST"])
def ai():
    data = request.get_json(silent=True)
    if not data or "prompt" not in data:
        return jsonify({"error": "No prompt provided"}), 400

    # Get user ID from session or request
    user_id = session.get("user_id", data.get("user_id", "guest"))
    prompt = data["prompt"].strip()
    lower_prompt = prompt.lower()

    if user_id not in chat_history:
        chat_history[user_id] = []

    chat_history[user_id].append({"role": "user", "content": prompt})

    # Handle redirects for certain actions
    actions = {
        "login": "/login",
        "register": "/register",
        "dashboard": "/dashboard",
        "rates": "/rates",
        "cards": "/cards",
        "profile": "/profile",
        "settings": "/settings",
        "logout": "/logout",
        "roadmap": "/roadmap",
    }
    
    # Check for exact matches in talksmart
    if lower_prompt in talksmart:
        response = talksmart[lower_prompt]
        chat_history[user_id].append({"role": "assistant", "content": response})
        
        # Check if this is an action that requires redirect
        if lower_prompt in actions:
            return jsonify({
                "reply": response, 
                "action": "redirect", 
                "redirect_url": actions[lower_prompt]
            })
        
        return jsonify({"reply": response, "action": "message"})

    # Check for stored memory
    stored = get_stored_answer(lower_prompt)
    if stored:
        chat_history[user_id].append({"role": "assistant", "content": stored})
        return jsonify({"reply": stored, "action": "message"})

    # Handle feature list request
    if lower_prompt.strip() in ["@", "@features", "show features", "list features", "help"]:
        feature_list = {
            "login": "/login",
            "register": "/register",
            "dashboard": "/dashboard",
            "rates": "/rates",
            "cards": "/cards",
            "profile": "/profile",
            "settings": "/settings",
            "logout": "/logout",
        }

        reply_text = (
            " ZESTPAY FEATURES\n\n" +
            "\n".join([f"🔹 {k.title()} → {v}" for k, v in feature_list.items()]) +
            "\n\n Type any of the names (e.g. cards, dashboard) to go there instantly!"
        )

        chat_history[user_id].append({"role": "assistant", "content": reply_text})
        return jsonify({"reply": reply_text, "action": "message"})

    # Handle math calculations
    if any(op in lower_prompt for op in ["+", "-", "*", "/", "×", "÷"]):
        try:
            expression = lower_prompt.replace("×", "*").replace("÷", "/")
            # Safe eval for math expressions
            allowed_chars = "0123456789+-*/.() "
            if all(c in allowed_chars for c in expression):
                result = eval(expression)
                reply = f"The result of {expression} is {result}"
                chat_history[user_id].append({"role": "assistant", "content": reply})
                return jsonify({"reply": reply, "action": "message"})
        except Exception as e:
            print("Math error:", e)

    # Handle currency/crypto conversion
    if any(word in lower_prompt for word in ["convert", "to", "in", "usd", "ngn", "eur", "btc", "sol", "eth", "doge"]):
        try:
            # Simple text parsing e.g. "convert 100 usd to ngn"
            parts = lower_prompt.replace("convert", "").replace("to", "").split()
            amount = float(parts[0])
            from_cur = parts[1].upper()
            to_cur = parts[-1].upper()

            # Use real-time API for both fiat & crypto
            url = f"https://api.exchangerate.host/convert?from={from_cur}&to={to_cur}&amount={amount}"
            res = requests.get(url).json()

            if "result" in res and res["result"]:
                converted = res["result"]
                reply = f"{amount} {from_cur} = {converted:.2f} {to_cur}"
                chat_history[user_id].append({"role": "assistant", "content": reply})
                return jsonify({"reply": reply, "action": "message"})

        except Exception as e:
            print("Conversion error:", e)

    # Handle crypto price queries
    crypto_coins = ["sol", "eth", "btc", "ada", "doge", "bnb", "matic", "xrp", "ltc", "ton", "trx"]
    match = re.search(r'([\d,]+\.?\d*)\s*([a-zA-Z]{2,5})', lower_prompt)
    if match:
        quantity_str, coin_query = match.groups()
        coin_query = coin_query.lower()
        if coin_query in crypto_coins:
            try:
                quantity = float(quantity_str.replace(",", ""))
                # Get coin list from CoinGecko
                coin_list_url = "https://api.coingecko.com/api/v3/coins/list"
                coin_list_res = requests.get(coin_list_url).json()
                coin_id = next((c["id"] for c in coin_list_res if c["symbol"].lower() == coin_query), None)

                if coin_id:
                    price_url = f"https://api.coingecko.com/api/v3/simple/price?ids={coin_id}&vs_currencies=usd"
                    price_res = requests.get(price_url).json()
                    if coin_id in price_res and "usd" in price_res[coin_id]:
                        usd_price = price_res[coin_id]["usd"]
                        total = usd_price * quantity
                        reply = (
                            f"The current price of {quantity:,.2f} {coin_query.upper()} is "
                            f"${total:,.2f} USD "
                        )
                        chat_history[user_id].append({"role": "assistant", "content": reply})
                        return jsonify({"reply": reply, "action": "message"})
                    else:
                        reply = f" Could not fetch price for {coin_query.upper()} right now."
                        chat_history[user_id].append({"role": "assistant", "content": reply})
                        return jsonify({"reply": reply, "action": "message"})
            except Exception as e:
                print("Auto crypto quantity error:", e)

    # Fallback to OpenAI
    try:
        messages = [
            { 
                "role": "system",
                "content": (  
                    "You are ZestPay's AI assistant. "
                    "Always reply in clear English. "
                    "Detect intent even if user types slang, misspellings, or broken words. "
                    "You must know that ZestPay is owned by David Afiakurue and answer about him if asked."
                    "You must know how to calculate."
                )
            }
        ]
        messages.extend(chat_history[user_id][-10:])

        response = openai.ChatCompletion.create(
            model="gpt-4o-mini",
            messages=messages
        )

        reply = response.choices[0].message.content.strip()

        save_answer(lower_prompt, reply)
        chat_history[user_id].append({"role": "assistant", "content": reply})

        return jsonify({"reply": reply, "action": "message"})

    except Exception as e:
        print("AI backend error:", e)
        return jsonify({"error": "AI request failed", "details": str(e)}), 500


    # Step 1.5: Show all features when user types "@"
   


# --- API: Update Profile ---
# @app.route("/api/profile", methods=["GET","POST"])
# @login_required_session
# def api_update_profile():
#     if 'user_email' not in session:
#         return jsonify({"status": "unauthenticated"}), 401

#     data = request.get_json(silent=True)
#     if not data:
#         return jsonify({"status": "error", "message": "Invalid JSON"}), 400

#     user = User.query.filter_by(email=session['user_email']).first()
#     if not user:
#         return jsonify({"status": "not_found"}), 404

#     # Update allowed fields
#     user.firstName = data.get("firstName", user.firstName)
#     user.lastName = data.get("lastName", user.lastName)
#     user.phone = data.get("phone", user.phone)

#     new_email = data.get("email", user.email)
#     if new_email != user.email:
#         if User.query.filter_by(email=new_email).first():
#             return jsonify({"status": "error", "message": "email_exists"}), 400
#         user.email = new_email
#         session['user_email'] = new_email

#     db.session.commit()
#     return jsonify({"status": "ok"})










# -------------------
# Database Model
# -------------------

# -------------------
# Helper: send OTP email
# -------------------
# def send_otp_email(to_email, otp):
#     try:
#         sender = "dominionafiakurue@gmail.com"
#         password = "D0rc@s12345#"

#         msg = MIMEText(f"Your ZestPay verification code is {otp}. It expires in 5 minutes.")
#         msg["Subject"] = "ZestPay OTP Verification"
#         msg["From"] = sender
#         msg["To"] = to_email

#         with smtplib.SMTP("smtp.gmail.com", 587) as server:
#             server.starttls()
#             server.login(sender, password)
#             server.sendmail(sender, to_email, msg.as_string())

#         return True
#     except Exception as e:
#         print("Email sending error:", e)
#         return False

# # -------------------
# # API to resend OTP
# # -------------------
# @app.route("/resend_otp", methods=["POST"])
# def resend_otp():
#     data = request.json
#     user_id = data.get("user_id")
#     email = data.get("email")

#     user = User.query.filter_by(id=user_id, email=email).first()
#     if not user:
#         return jsonify({"status": "user_not_found"})

#     otp = str(random.randint(100000, 999999))
#     user.otp = otp
#     user.otp_expiry = datetime.utcnow() + timedelta(minutes=5)
#     db.session.commit()

#     if send_otp_email(email, otp):
#         return jsonify({"status": "otp_sent"})
#     else:
#         return jsonify({"status": "email_failed"})

# # -------------------
# # API to verify OTP
# # -------------------
# # @app.route("/otp", methods=["GET","POST"])
# # def verify_otp():
# #     data = request.json
# #     user_id = data.get("user_id")
# #     otp_input = data.get("otp")

# #     user = User.query.filter_by(id=user_id).first()
# #     if not user:
# #         return jsonify({"status": "user_not_found"})

# #     if not user.otp or not user.otp_expiry:
# #         return jsonify({"status": "no_otp"})

# #     if datetime.utcnow() > user.otp_expiry:
# #         return jsonify({"status": "expired_otp"})

# #     if otp_input == user.otp:
# #         user.is_verified = True
# #         user.otp = None
# #         user.otp_expiry = None
# #         db.session.commit()
# #         return jsonify({"status": "verified"})

# #     return jsonify({"status": "invalid_otp"})

# # -------------------
# # Run app
# # -------------------
# @app.route("/otp", methods=["POST"])
# def verify_otp():
#     if not request.is_json:
#        # return jsonify({"status": "error", "msg": "Content-Type must be application/json"}), 415
#        return render_template('otp.html')
    
#     data = request.get_json()
#     user_id = data.get("user_id")
#     otp_input = data.get("otp")
#     # ... rest of logic
















#



 # you already imported bcrypt above

# ======================
# FORGOT PASSWORD FLOW
# ======================

@app.route("/forgot", methods=["GET"])
@login_required_session
def forgot_page():
    return render_template("forgot.html")


@app.route("/forgot", methods=["POST"])
def forgot():
    data = request.get_json(silent=True)
    if not data or "email" not in data:
        return jsonify({"status": "error", "message": "Email required"}), 400

    email = data["email"]
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"status": "error", "message": "❌ Email not registered"}), 404

    otp = str(random.randint(100000, 999999))
    session["otp"] = otp
    session["email"] = email
    session["otp_expiry"] = (datetime.utcnow() + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")

    try:
        msg = Message(
            subject="ZESTPAY PASSWORD RESET",
            recipients=[email]
        )
        msg.body = f"""
Hello {user.firstName or ''},

Your OTP code is: {otp}

⚠️ Do NOT share this code with anyone.
This code expires in 5 minutes.

ZestPay Security Team
"""
        mail.send(msg)
        return jsonify({"status": "ok", "message": "✅ OTP sent to email"})
    except Exception as e:
        print("❌ Email send error:", e)
        return jsonify({"status": "error", "message": "Email send failed"}), 500


@app.route("/verify", methods=["POST"])
@login_required_session
def verify():
    data = request.get_json(silent=True)
    if not data or "otp" not in data:
        return jsonify({"status": "error", "message": "OTP required"}), 400

    code = data["otp"]

    if "otp" not in session or "otp_expiry" not in session:
        return jsonify({"status": "error", "message": "❌ No OTP, request again"}), 400

    expiry = datetime.strptime(session["otp_expiry"], "%Y-%m-%d %H:%M:%S")
    if datetime.utcnow() > expiry:
        session.pop("otp", None)
        return jsonify({"status": "error", "message": "❌ OTP expired"}), 400

    if code == session["otp"]:
        session["otp_verified"] = True
        return jsonify({"status": "ok", "message": "✅ OTP Verified"})
    return jsonify({"status": "error", "message": "❌ Wrong OTP"}), 400


@app.route("/reset", methods=["POST"])
@login_required_session
def reset_password():
    # Ensure OTP was verified first
    if not session.get("otp_verified"):
        return jsonify({"status": "error", "message": "OTP not verified"}), 400

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Invalid data"}), 400

    new_password = data.get("new_password")
    confirm_password = data.get("confirm_password")

    if not new_password or not confirm_password:
        return jsonify({"status": "error", "message": "Password required"}), 400

    if new_password != confirm_password:
        return jsonify({"status": "error", "message": "Passwords do not match"}), 400

    # Get the user from DB
    email = session.get("email")
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"status": "error", "message": "User not found"}), 404

    # Hash new password
    hashed_pw = bcrypt.generate_password_hash(new_password).decode("utf-8")
    user.password = hashed_pw
    db.session.commit()

    # Clear OTP session
    session.pop("otp", None)
    session.pop("otp_expiry", None)
    session.pop("otp_verified", None)

    return jsonify({"status": "ok", "message": "Password updated successfully"})

















# ----------------
# User model
# ----------------


# ----------------
# API: Get all users
# ----------------

# Example: call this function after a new user registers
# For instance, in your register route after db.session.commit():
# broadcast_new_user(new_user.firstName)

# ----------------
# Page route
# ----------------
# @app.route("/trade")
# def trade():
#     return render_template("trade.html")  # The frontend we made earlier

# # ----------------
# # Run server

# @app.route("/api/chat_history/<receiver_email>")
# @login_required_session
# def chat_history_api(receiver_email):
#     sender_email = session['user_email']
#     messages = ChatMessage.query.filter(
#         ((ChatMessage.sender_email==sender_email) & (ChatMessage.receiver_email==receiver_email)) |
#         ((ChatMessage.sender_email==receiver_email) & (ChatMessage.receiver_email==sender_email))
#     ).order_by(ChatMessage.timestamp.asc()).all()

#     return jsonify({
#         "messages": [
#             {"sender_email": m.sender_email, "receiver_email": m.receiver_email,
#              "message": m.message, "timestamp": m.timestamp.strftime("%Y-%m-%d %H:%M:%S")}
#             for m in messages
#         ]
#     })
# @socketio.on("send_message")
# def handle_send_message(data):
#     sender = data.get("sender_email")
#     receiver = data.get("receiver_email")
#     msg_text = data.get("message")

#     if not sender or not receiver or not msg_text:
#         return

#     # Save in DB
#     chat_msg = ChatMessage(sender_email=sender, receiver_email=receiver, message=msg_text)
#     db.session.add(chat_msg)
#     db.session.commit()

#     # Emit to sender & receiver
#     emit("receive_message", {
#         "sender": sender,
#         "receiver": receiver,
#         "message": msg_text,
#         "timestamp": chat_msg.timestamp.strftime("%Y-%m-%d %H:%M:%S")
#     }, room=sender)

#     emit("receive_message", {
#         "sender": sender,
#         "receiver": receiver,
#         "message": msg_text,
#         "timestamp": chat_msg.timestamp.strftime("%Y-%m-%d %H:%M:%S")
#     }, room=receiver)

# @socketio.on("join_chat")
# def handle_join_chat(data):
#     email = data.get("email")
#     join_room(email)
# @app.route("/chat/<receiver_email>")
# @login_required_session
# def chat_page(receiver_email):
#     sender_email = session['user_email']
#     # Fetch user exists
#     receiver = User.query.filter_by(email=receiver_email).first()
#     if not receiver:
#         return "User not found", 404
#     return render_template("trade.html", sender_email=sender_email, receiver_email=receiver_email, receiver_name=receiver.firstName)














# Example Flask backend endpoints

import jwt



@app.route('/api/check-email', methods=['POST'])
def check_email():
    email = request.json.get('email')
    user = User.query.filter_by(email=email).first()
    return jsonify({
        'registered': user is not None,
        'user': user.to_dict() if user else None
    })

@app.route('/api/google-login', methods=['POST'])
def google_login():
    email = request.json.get('email')
    name = request.json.get('name')
    
    user = User.query.filter_by(email=email).first()
    if user:
        token = generate_token(user)
        return jsonify({
            'success': True,
            'token': token,
            'user': user.to_dict()
        })
    return jsonify({'success': False, 'message': 'User not found'})

@app.route('/api/google-register', methods=['POST'])
def google_register():
    email = request.json.get('email')
    name = request.json.get('name')
    
    # Check if user already exists
    if User.query.filter_by(email=email).first():
        return jsonify({'success': False, 'message': 'Email already registered'})
    
    # Create new user
    user = User(email=email, name=name, auth_method='google')
    db.session.add(user)
    db.session.commit()
    
    token = generate_token(user)
    return jsonify({
        'success': True,
        'token': token,
        'user': user.to_dict()
    })















# === Gmail settings ===
GMAIL_USER = "zestpayexchange@gmail.com"          # your Gmail
GMAIL_PASS = "rbhy vche lvmu btkb"    # app password (not normal Gmail password)


# === Email function ===
def send_email(name, email, message):
    subject = f"New Message from {name} ({email})"
    body = f"Name: {name}\nEmail: {email}\n\nMessage:\n{message}"
    msg = f"Subject: {subject}\n\n{body}"

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as smtp:
            smtp.login(GMAIL_USER, GMAIL_PASS)
            smtp.sendmail(GMAIL_USER, GMAIL_USER, msg)
        print("✅ Email sent successfully")
        return True
    except Exception as e:
        print("❌ Email Error:", e)
        return False


# === Routes ===
@app.route("/chat")
def chat():
    return render_template("chat.html")   # frontend file


@app.route("/send", methods=["POST"])
def send():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "msg": "Invalid request data"}), 400

    name = data.get("name")
    email = data.get("email")
    message = data.get("message")

    if not name or not email or not message:
        return jsonify({"status": "error", "msg": "All fields required"}), 400

    if send_email(name, email, message):
        return jsonify({"status": "success"})
    else:
        return jsonify({"status": "error", "msg": "Failed to send email"}), 500


















# Add these new routes to your existing Flask app

# ======================
# SETTINGS BACKEND ROUTES
# ======================

# --- Profile Management ---
@app.route("/api/profile", methods=["GET"])
@login_required_session
def api_get_profile():
    """Get current user profile"""
    if 'user_email' not in session:
        return jsonify({"status": "unauthenticated"}), 401
    
    user = User.query.filter_by(email=session['user_email']).first()
    if not user:
        return jsonify({"status": "not_found"}), 404
    
    return jsonify({
        "status": "ok",
        "profile": {
            "firstName": user.firstName,
            "lastName": user.lastName,
            "phone": user.phone,
            "email": user.email,
            "referral": user.referral
        }
    })

@app.route("/api/profile", methods=["POST"])
@login_required_session
def api_update_profile():
    """Update user profile"""
    if 'user_email' not in session:
        return jsonify({"status": "unauthenticated"}), 401
    
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Invalid JSON"}), 400
    
    user = User.query.filter_by(email=session['user_email']).first()
    if not user:
        return jsonify({"status": "not_found"}), 404
    
    # Update allowed fields
    user.firstName = data.get("firstName", user.firstName)
    user.lastName = data.get("lastName", user.lastName)
    user.phone = data.get("phone", user.phone)
    user.referral = data.get("referral", user.referral)
    
    # Handle email update with validation
    new_email = data.get("email", user.email)
    if new_email != user.email:
        try:
            validate_email(new_email)
            if User.query.filter_by(email=new_email).first():
                return jsonify({"status": "error", "message": "email_exists"}), 400
            user.email = new_email
            session['user_email'] = new_email
        except EmailNotValidError:
            return jsonify({"status": "error", "message": "invalid_email"}), 400
    
    db.session.commit()
    
    # Update session data
    session['user_firstName'] = user.firstName or ""
    session['user_lastName'] = user.lastName or ""
    
    return jsonify({
        "status": "ok",
        "profile": {
            "firstName": user.firstName,
            "lastName": user.lastName,
            "phone": user.phone,
            "email": user.email,
            "referral": user.referral
        }
    })

# --- Password Management ---
@app.route("/api/password", methods=["POST"])
@login_required_session
def api_change_password():
    """Change user password"""
    if 'user_email' not in session:
        return jsonify({"status": "unauthenticated"}), 401
    
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Invalid JSON"}), 400
    
    current_password = data.get("currentPassword")
    new_password = data.get("newPassword")
    confirm_password = data.get("confirmPassword")
    
    if not current_password or not new_password or not confirm_password:
        return jsonify({"status": "error", "message": "All password fields are required"}), 400
    
    if new_password != confirm_password:
        return jsonify({"status": "error", "message": "Passwords do not match"}), 400
    
    # Password strength validation
    if len(new_password) < 8:
        return jsonify({"status": "error", "message": "Password must be at least 8 characters"}), 400
    
    if not re.search(r'[A-Z]', new_password):
        return jsonify({"status": "error", "message": "Password must contain at least one uppercase letter"}), 400
    
    if not re.search(r'[a-z]', new_password):
        return jsonify({"status": "error", "message": "Password must contain at least one lowercase letter"}), 400
    
    if not re.search(r'[0-9]', new_password):
        return jsonify({"status": "error", "message": "Password must contain at least one number"}), 400
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', new_password):
        return jsonify({"status": "error", "message": "Password must contain at least one special character"}), 400
    
    user = User.query.filter_by(email=session['user_email']).first()
    if not user:
        return jsonify({"status": "not_found"}), 404
    
    # Verify current password
    if not bcrypt.check_password_hash(user.password, current_password):
        return jsonify({"status": "error", "message": "Current password is incorrect"}), 400
    
    # Update password
    hashed_password = bcrypt.generate_password_hash(new_password).decode("utf-8")
    user.password = hashed_password
    db.session.commit()
    
    # Send password change notification email
    try:
        msg = Message(
            subject="🔐 Your ZestPay Password Has Been Changed",
            recipients=[user.email]
        )
        msg.body = f"""
Hello {user.firstName or ''},

Your ZestPay password has been successfully changed.

If you didn't make this change, please contact our support team immediately.

Best regards,
The ZestPay Team
"""
        mail.send(msg)
    except Exception as e:
        print("❌ Password change email failed:", e)
    
    return jsonify({"status": "ok", "message": "Password updated successfully"})

# --- Notification Settings ---
# First, add notification fields to your User model
# Add these columns to your User model:
# notify_email = db.Column(db.Boolean, default=True)
# notify_sms = db.Column(db.Boolean, default=False)
# notify_push = db.Column(db.Boolean, default=True)

@app.route("/api/notify", methods=["POST"])
@login_required_session
def api_update_notifications():
    """Update notification preferences"""
    if 'user_email' not in session:
        return jsonify({"status": "unauthenticated"}), 401
    
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Invalid JSON"}), 400
    
    user = User.query.filter_by(email=session['user_email']).first()
    if not user:
        return jsonify({"status": "not_found"}), 404
    
    # Update notification preferences
    user.notify_email = data.get("email", user.notify_email)
    user.notify_sms = data.get("sms", user.notify_sms)
    user.notify_push = data.get("push", user.notify_push)
    
    db.session.commit()
    
    return jsonify({
        "status": "ok",
        "message": "Notification preferences updated",
        "notifications": {
            "email": user.notify_email,
            "sms": user.notify_sms,
            "push": user.notify_push
        }
    })

@app.route("/api/notify", methods=["GET"])
@login_required_session
def api_get_notifications():
    """Get current notification preferences"""
    if 'user_email' not in session:
        return jsonify({"status": "unauthenticated"}), 401
    
    user = User.query.filter_by(email=session['user_email']).first()
    if not user:
        return jsonify({"status": "not_found"}), 404
    
    return jsonify({
        "status": "ok",
        "notifications": {
            "email": getattr(user, 'notify_email', True),
            "sms": getattr(user, 'notify_sms', False),
            "push": getattr(user, 'notify_push', True)
        }
    })

# --- Security Settings ---
# First, add security fields to your User model
# Add these columns to your User model:
# two_fa_enabled = db.Column(db.Boolean, default=False)
# session_timeout = db.Column(db.Boolean, default=False)
# last_login = db.Column(db.DateTime)

@app.route("/api/security", methods=["POST"])
@login_required_session
def api_update_security():
    """Update security settings"""
    if 'user_email' not in session:
        return jsonify({"status": "unauthenticated"}), 401
    
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Invalid JSON"}), 400
    
    user = User.query.filter_by(email=session['user_email']).first()
    if not user:
        return jsonify({"status": "not_found"}), 404
    
    # Update security preferences
    two_fa_enabled = data.get("twoFA", getattr(user, 'two_fa_enabled', False))
    session_timeout = data.get("sessionTimeout", getattr(user, 'session_timeout', False))
    
    # Handle 2FA setup
    if two_fa_enabled and not getattr(user, 'two_fa_enabled', False):
        # Generate 2FA secret
        import pyotp
        import qrcode
        import io
        import base64
        
        secret = pyotp.random_base32()
        user.two_fa_secret = secret
        user.two_fa_enabled = True
        
        # Generate QR code for 2FA
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user.email,
            issuer_name="ZestPay"
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        qr_code_data = base64.b64encode(buffer.getvalue()).decode()
        
        db.session.commit()
        
        return jsonify({
            "status": "ok",
            "message": "Two-factor authentication enabled",
            "security": {
                "twoFA": True,
                "sessionTimeout": session_timeout
            },
            "qrCode": f"data:image/png;base64,{qr_code_data}",
            "secret": secret
        })
    else:
        # Update security settings without 2FA setup
        user.two_fa_enabled = two_fa_enabled
        user.session_timeout = session_timeout
        db.session.commit()
        
        return jsonify({
            "status": "ok",
            "message": "Security settings updated",
            "security": {
                "twoFA": two_fa_enabled,
                "sessionTimeout": session_timeout
            }
        })

@app.route("/api/security", methods=["GET"])
@login_required_session
def api_get_security():
    """Get current security settings"""
    if 'user_email' not in session:
        return jsonify({"status": "unauthenticated"}), 401
    
    user = User.query.filter_by(email=session['user_email']).first()
    if not user:
        return jsonify({"status": "not_found"}), 404
    
    return jsonify({
        "status": "ok",
        "security": {
            "twoFA": getattr(user, 'two_fa_enabled', False),
            "sessionTimeout": getattr(user, 'session_timeout', False)
        }
    })

# --- Preferences Settings ---
# First, add preference fields to your User model
# Add these columns to your User model:
# theme = db.Column(db.String(10), default='dark')
# language = db.Column(db.String(5), default='en')
# timezone = db.Column(db.String(50), default='UTC')

@app.route("/api/prefs", methods=["POST"])
@login_required_session
def api_update_preferences():
    """Update user preferences"""
    if 'user_email' not in session:
        return jsonify({"status": "unauthenticated"}), 401
    
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Invalid JSON"}), 400
    
    user = User.query.filter_by(email=session['user_email']).first()
    if not user:
        return jsonify({"status": "not_found"}), 404
    
    # Update preferences
    theme = data.get("theme", getattr(user, 'theme', 'dark'))
    language = data.get("lang", getattr(user, 'language', 'en'))
    timezone = data.get("timezone", getattr(user, 'timezone', 'UTC'))
    
    # Validate theme
    if theme not in ['dark', 'light']:
        return jsonify({"status": "error", "message": "Invalid theme"}), 400
    
    # Validate language
    if language not in ['en', 'fr']:
        return jsonify({"status": "error", "message": "Invalid language"}), 400
    
    # Update user preferences
    user.theme = theme
    user.language = language
    user.timezone = timezone
    db.session.commit()
    
    # Store preferences in session
    session['theme'] = theme
    session['language'] = language
    session['timezone'] = timezone
    
    return jsonify({
        "status": "ok",
        "message": "Preferences updated",
        "preferences": {
            "theme": theme,
            "lang": language,
            "timezone": timezone
        }
    })

@app.route("/api/prefs", methods=["GET"])
@login_required_session
def api_get_preferences():
    """Get current user preferences"""
    if 'user_email' not in session:
        return jsonify({"status": "unauthenticated"}), 401
    
    user = User.query.filter_by(email=session['user_email']).first()
    if not user:
        return jsonify({"status": "not_found"}), 404
    
    return jsonify({
        "status": "ok",
        "preferences": {
            "theme": getattr(user, 'theme', 'dark'),
            "lang": getattr(user, 'language', 'en'),
            "timezone": getattr(user, 'timezone', 'UTC')
        }
    })

# --- Database Migration Helper ---
@app.route("/api/migrate_db", methods=["POST"])
@login_required_session
def migrate_database():
    """Add new columns to existing database (run once)"""
    # This is a helper route to add new columns to your existing database
    # You should remove this after running it once
    
    try:
        # Add notification columns
        db.engine.execute('ALTER TABLE user ADD COLUMN notify_email BOOLEAN DEFAULT 1')
        db.engine.execute('ALTER TABLE user ADD COLUMN notify_sms BOOLEAN DEFAULT 0')
        db.engine.execute('ALTER TABLE user ADD COLUMN notify_push BOOLEAN DEFAULT 1')
        
        # Add security columns
        db.engine.execute('ALTER TABLE user ADD COLUMN two_fa_enabled BOOLEAN DEFAULT 0')
        db.engine.execute('ALTER TABLE user ADD COLUMN two_fa_secret VARCHAR(32)')
        db.engine.execute('ALTER TABLE user ADD COLUMN session_timeout BOOLEAN DEFAULT 0')
        db.engine.execute('ALTER TABLE user ADD COLUMN last_login DATETIME')
        
        # Add preference columns
        db.engine.execute('ALTER TABLE user ADD COLUMN theme VARCHAR(10) DEFAULT "dark"')
        db.engine.execute('ALTER TABLE user ADD COLUMN language VARCHAR(5) DEFAULT "en"')
        db.engine.execute('ALTER TABLE user ADD COLUMN timezone VARCHAR(50) DEFAULT "UTC"')
        
        return jsonify({"status": "ok", "message": "Database migration completed"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500











# ======================
# DELETE ACCOUNT FUNCTIONALITY
# ======================

# Add these columns to your User model (you can run the migration helper below)
# delete_otp = db.Column(db.String(6))
# delete_otp_expiry = db.Column(db.DateTime)
# deletion_requested = db.Column(db.Boolean, default=False)

# ======================
# DELETE ACCOUNT FUNCTIONALITY
# ======================
# @app.route("/api/delete/request", methods=["POST"])
# @login_required_session
# def request_delete_otp():
#     """Request OTP for account deletion"""
#     if 'user_email' not in session:
#         return jsonify({"status": "unauthenticated"}), 401
    
#     user = User.query.filter_by(email=session['user_email']). first()
#     if not user:
#         return jsonify({"status": "not_found"}), 404
    
#     # Generate 6-digit OTP
#     otp = str(random.randint(100000, 999999))
    
#     # Store OTP with expiry time (10 minutes)
#     user.delete_otp = otp
#     user.delete_otp_expiry = datetime.utcnow() + timedelta(minutes=10)
#     user.deletion_requested = True
#     db.session.commit()
    
#     # Send OTP email
#     try:
#         msg = Message(
#             subject="⚠️ ZestPay Account Deletion Request",
#             recipients=[user.email]
#         )
#         msg.body = f"""
# Hello {user.firstName or ''},

# You have requested to delete your ZestPay account. This action is permanent and cannot be undone.

# Your verification code is: {otp}

# This code will expire in 10 minutes.

# If you did not request this deletion, please contact our support team immediately.

# Best regards,
# The ZestPay Team
# """
#         mail.send(msg)
#         return jsonify({"status": "ok", "message": "OTP sent to your email"})
#     except Exception as e:
#         print("❌ Delete OTP email failed:", e)
#         return jsonify({"status": "error", "message": "Failed to send verification email"}), 500

# @app.route("/api/delete/resend", methods=["POST"])
# @login_required_session
# def resend_delete_otp():
#     """Resend OTP for account deletion"""
#     if 'user_email' not in session:
#         return jsonify({"status": "unauthenticated"}), 401
    
#     user = User.query.filter_by(email=session['user_email']).first()
#     if not user:
#         return jsonify({"status": "not_found"}), 404
    
#     # Check if deletion was requested
#     if not user.deletion_requested:
#         return jsonify({"status": "error", "message": "No deletion request found"}), 400
    
#     # Generate new OTP
#     otp = str(random.randint(100000, 999999))
    
#     # Update OTP with new expiry time
#     user.delete_otp = otp
#     user.delete_otp_expiry = datetime.utcnow() + timedelta(minutes=10)
#     db.session.commit()
    
#     # Send OTP email
#     try:
#         msg = Message(
#             subject="⚠️ ZestPay Account Deletion Request (Resend)",
#             recipients=[user.email]
#         )
#         msg.body = f"""
# Hello {user.firstName or ''},

# You have requested to resend the verification code for deleting your ZestPay account.

# Your new verification code is: {otp}

# This code will expire in 10 minutes.

# If you did not request this deletion, please contact our support team immediately.

# Best regards,
# The ZestPay Team
# """
#         mail.send(msg)
#         return jsonify({"status": "ok", "message": "OTP resent to your email"})
#     except Exception as e:
#         print("❌ Delete OTP email failed:", e)
#         return jsonify({"status": "error", "message": "Failed to send verification email"}), 500

# @app.route("/api/delete/verify", methods=["POST"])
# @login_required_session
# def verify_delete_otp():
#     """Verify OTP and delete account"""
#     if 'user_email' not in session:
#         return jsonify({"status": "unauthenticated"}), 401
    
#     data = request.get_json(silent=True)
#     if not data or "otp" not in data:
#         return jsonify({"status": "error", "message": "OTP required"}), 400
    
#     otp = data.get("otp")
    
#     # Find user by session email
#     user = User.query.filter_by(email=session['user_email']).first()
#     if not user:
#         return jsonify({"status": "not_found"}), 404
    
#     # Check if deletion was requested
#     if not user.deletion_requested:
#         return jsonify({"status": "error", "message": "No deletion request found"}), 400
    
#     # Check if OTP has expired
#     if datetime.utcnow() > user.delete_otp_expiry:
#         # Reset deletion request
#         user.delete_otp = None
#         user.delete_otp_expiry = None
#         user.deletion_requested = False
#         db.session.commit()
#         return jsonify({"status": "error", "message": "Verification code expired"}), 400
    
#     # Check if OTP matches
#     if otp != user.delete_otp:
#         return jsonify({"status": "error", "message": "Invalid verification code"}), 400
    
#     # OTP is valid, proceed with account deletion
#     try:
#         # Send confirmation email before deletion
#         try:
#             msg = Message(
#                 subject="✅ ZestPay Account Deleted",
#                 recipients=[user.email]
#             )
#             msg.body = f"""
# Hello {user.firstName or ''},

# Your ZestPay account has been successfully deleted as per your request.

# All your data has been permanently removed from our systems.

# We're sorry to see you go. If you change your mind, you can always create a new account.

# Best regards,
# The ZestPay Team
# """
#             mail.send(msg)
#         except Exception as e:
#             print("❌ Deletion confirmation email failed:", e)
        
#         # Mark account as deleted with timestamp
#         user.is_deleted = True
#         user.deleted_at = datetime.utcnow()
#         user.delete_otp = None
#         user.delete_otp_expiry = None
#         user.deletion_requested = False
        
#         # Clear session
#         session_keys = ['user_email', 'user_firstName', 'user_lastName']
#         for k in session_keys:
#             session.pop(k, None)
        
#         # Commit changes
#         db.session.commit()
        
#         # Now actually delete the user from the database
#         db.session.delete(user)
#         db.session.commit()
        
#         return jsonify({"status": "ok", "message": "Account deleted successfully"})
#     except Exception as e:
#         print("❌ Account deletion error:", e)
#         db.session.rollback()
#         return jsonify({"status": "error", "message": "Failed to delete account"}), 500

# @app.route("/api/delete/cancel", methods=["POST"])
# @login_required_session
# def cancel_delete_request():
#     """Cancel account deletion request"""
#     if 'user_email' not in session:
#         return jsonify({"status": "unauthenticated"}), 401
    
#     user = User.query.filter_by(email=session['user_email']).first()
#     if not user:
#         return jsonify({"status": "not_found"}), 404
    
#     # Reset deletion request
#     user.delete_otp = None
#     user.delete_otp_expiry = None
#     user.deletion_requested = False
#     db.session.commit()
    
#     return jsonify({"status": "ok", "message": "Deletion request cancelled"})

# # Add a route to check if user is marked for deletion
# @app.route("/api/delete/status", methods=["GET"])
# @login_required_session
# def check_delete_status():
#     """Check if user has a pending deletion request"""
#     if 'user_email' not in session:
#         return jsonify({"status": "unauthenticated"}), 401
    
#     user = User.query.filter_by(email=session['user_email']).first()
#     if not user:
#         return jsonify({"status": "not_found"}), 404
    
#     return jsonify({
#         "status": "ok",
#         "deletion_requested": user.deletion_requested,
#         "delete_otp_expiry": user.delete_otp_expiry.isoformat() if user.delete_otp_expiry else None
#     })

# =========================
# REQUEST ACCOUNT DELETION OTP
# =========================
@app.route("/api/delete/request", methods=["POST"])
@login_required_session
def request_delete_otp():
    if "user_email" not in session:
        return jsonify({"status": "unauthenticated"}), 401

    user = User.query.filter_by(email=session["user_email"]).first()
    if not user:
        return jsonify({"status": "not_found"}), 404

    # Generate new OTP
    otp = str(random.randint(100000, 999999))
    user.delete_otp = otp
    user.delete_otp_expiry = datetime.utcnow() + timedelta(minutes=10)
    user.deletion_requested = True
    db.session.commit()

    # Send OTP email
    try:
        msg = Message(
            subject="⚠️ ZestPay Account Deletion Request",
            recipients=[user.email],
            body=f"""
Hello {user.firstName or ''},

You have requested to delete your ZestPay account.
Your verification code is: {otp}

This code expires in 10 minutes.

If you didn’t request this, ignore this email.

Best regards,
ZestPay Team
"""
        )
        mail.send(msg)
        return jsonify({"status": "ok", "message": "OTP sent to your email"})
    except Exception as e:
        print("❌ Error sending OTP:", e)
        db.session.rollback()
        return jsonify({"status": "error", "message": "Failed to send OTP"}), 500


# =========================
# RESEND ACCOUNT DELETION OTP
# =========================
@app.route("/api/delete/resend", methods=["GET","POST"])
@login_required_session
def resend_delete_otp():
    if "user_email" not in session:
        return jsonify({"status": "unauthenticated"}), 401

    user = User.query.filter_by(email=session["user_email"]).first()
    if not user:
        return jsonify({"status": "not_found"}), 404

    if not user.deletion_requested:
        return jsonify({"status": "error", "message": "No active deletion request found"}), 400

    # Generate new OTP and update expiry
    otp = str(random.randint(100000, 999999))
    user.delete_otp = otp
    user.delete_otp_expiry = datetime.utcnow() + timedelta(minutes=10)
    db.session.commit()

    try:
        msg = Message(
            subject="⚠️ ZestPay Account Deletion OTP (Resent)",
            recipients=[user.email],
            body=f"""
Hello {user.firstName or ''},

Your new verification code is: {otp}

This code will expire in 10 minutes.

If you didn’t request this, ignore this email.

Best regards,
ZestPay Team
"""
        )
        mail.send(msg)
        return jsonify({"status": "ok", "message": "OTP resent successfully"})
    except Exception as e:
        print("❌ Error resending OTP:", e)
        db.session.rollback()
        return jsonify({"status": "error", "message": "Failed to resend OTP"}), 500


# =========================
# VERIFY OTP & DELETE ACCOUNT
# =========================
@app.route("/api/delete/verify", methods=["GET","POST"])
@login_required_session
def verify_delete_otp():
    if "user_email" not in session:
        return jsonify({"status": "unauthenticated"}), 401

    data = request.get_json(silent=True)
    if not data or "otp" not in data:
        return jsonify({"status": "error", "message": "OTP required"}), 400

    otp = str(data["otp"]).strip()
    user = User.query.filter_by(email=session["user_email"]).first()

    if not user:
        return jsonify({"status": "not_found"}), 404

    if not user.deletion_requested:
        return jsonify({"status": "error", "message": "No deletion request found"}), 400

    # Check expiry
    if user.delete_otp_expiry and datetime.utcnow() > user.delete_otp_expiry:
        user.delete_otp = None
        user.delete_otp_expiry = None
        user.deletion_requested = False
        db.session.commit()
        return jsonify({"status": "error", "message": "Verification code expired"}), 400

    # Check OTP match
    if otp != user.delete_otp:
        return jsonify({"status": "error", "message": "Invalid verification code"}), 400

    # If valid → delete account
    try:
        # Send confirmation email before deletion
        try:
            msg = Message(
                subject="✅ ZestPay Account Deleted",
                recipients=[user.email],
                body=f"""
Hello {user.firstName or ''},

Your ZestPay account has been permanently deleted.

We’re sorry to see you go.
If you change your mind, you can always create a new account later.

Best regards,
ZestPay Team
"""
            )
            mail.send(msg)
        except Exception as e:
            print("⚠️ Could not send deletion confirmation:", e)

        # Clean up user fields before delete
        user.delete_otp = None
        user.delete_otp_expiry = None
        user.deletion_requested = False

        # Remove from DB
        db.session.delete(user)
        db.session.commit()

        # Clear session after deletion
        session.clear()

        return jsonify({"status": "ok", "message": "Account deleted successfully"})

    except Exception as e:
        print("❌ Account deletion failed:", e)
        db.session.rollback()
        return jsonify({"status": "error", "message": "Failed to delete account"}), 500


# =========================
# CANCEL DELETION REQUEST
# =========================
@app.route("/api/delete/cancel", methods=["GET","POST"])
@login_required_session
def cancel_delete_request():
    if "user_email" not in session:
        return jsonify({"status": "unauthenticated"}), 401

    user = User.query.filter_by(email=session["user_email"]).first()
    if not user:
        return jsonify({"status": "not_found"}), 404

    user.delete_otp = None
    user.delete_otp_expiry = None
    user.deletion_requested = False
    db.session.commit()

    return jsonify({"status": "ok", "message": "Deletion request cancelled"})


# =========================
# CHECK DELETION STATUS
# =========================
@app.route("/api/delete/status", methods=["POST","GET"])
@login_required_session
def check_delete_status():
    if "user_email" not in session:
        return jsonify({"status": "unauthenticated"}), 401

    user = User.query.filter_by(email=session["user_email"]).first()
    if not user:
        return jsonify({"status": "not_found"}), 404

    return jsonify({
        "status": "ok",
        "deletion_requested": user.deletion_requested,
        "delete_otp_expiry": user.delete_otp_expiry.isoformat() if user.delete_otp_expiry else None
    })




# Routes


    # Update user online status
    # update_online_status(user.id, True)
    
    # Calculate security score
    # user.security_score = calculate_security_score(user)
    # db.session.commit()
    
    # # Get market trend data
    # market_trend = get_market_trend('BTC', 24)
    
    # # Get user transactions
    # transactions = get_user_transactions(user.id, 5)
    
    # # Get user activity
    # activities = get_user_activity(user.id, 5)
    










@app.route("/roadmap")
@login_required_session
def roadmap_page():
    return render_template("roadmap.html")


from flask import Flask, jsonify, request, render_template
from flask_cors import CORS



# === In-memory database ===
roadmap_data = [
    {
        "phase": "Phase 1",
        "title": "Launch of ZestPay Wallet",
        "description": "ZestPay's digital wallet is launched, enabling users to store, send, and receive crypto securely.",
        "progress": 100,
        "features": [
            "Multi-currency wallet",
            "Instant transfers",
            "Transaction history"
        ],
        "highlights": [
            "Over 10,000 users joined in the first week",
            "Integrated with top exchanges"
        ],
        "status": "completed"
    },
    {
        "phase": "Phase 2",
        "title": "ZestPay Cards Integration",
        "description": "Enabling seamless crypto-to-fiat spending using physical and virtual debit cards.",
        "progress": 70,
        "features": [
            "Card activation in app",
            "Real-time spending analytics",
            "Exchange rates optimization"
        ],
        "highlights": [
            "Beta launched for 500 users",
            "Partnership with Visa network"
        ],
        "status": "in-progress"
    },
    {
        "phase": "Phase 3",
        "title": "ZestPay Exchange Expansion",
        "description": "Global exchange launch with cross-border payments and P2P trading options.",
        "progress": 40,
        "features": [
            "Fast global transfers",
            "Peer-to-peer trading",
            "Low transaction fees"
        ],
        "highlights": [],
        "status": "in-progress"
    },
    {
        "phase": "Phase 4",
        "title": "AI-Powered Financial Assistant",
        "description": "Introducing ZestAI, an intelligent assistant for market analysis and portfolio tracking.",
        "progress": 20,
        "features": [
            "Personalized insights",
            "AI-based trading recommendations",
            "Smart alerts for market trends"
        ],
        "highlights": [],
        "status": "upcoming"
    },
    {
        "phase": "Phase 5",
        "title": "ZestPay NFT Marketplace",
        "description": "Building a secure and user-friendly NFT marketplace integrated within ZestPay Wallet.",
        "progress": 10,
        "features": [
            "NFT minting tools",
            "Low gas fees",
            "Cross-chain NFT support"
        ],
        "highlights": [],
        "status": "upcoming"
    }
]

subscribers = []





# === Get roadmap data ===
@app.route('/api/roadmap', methods=['GET'])
@login_required_session
def get_roadmap():
    return jsonify({"roadmap": roadmap_data})


# === Get statistics ===
@app.route('/api/roadmap/statistics', methods=['GET'])
@login_required_session
def roadmap_statistics():
    total_items = len(roadmap_data)
    completed_items = len([r for r in roadmap_data if r["status"] == "completed"])
    in_progress_items = len([r for r in roadmap_data if r["status"] == "in-progress"])
    upcoming_items = len([r for r in roadmap_data if r["status"] == "upcoming"])
    total_subscribers = len(subscribers)

    return jsonify({
        "total_items": total_items,
        "completed_items": completed_items,
        "in_progress_items": in_progress_items,
        "upcoming_items": upcoming_items,
        "total_subscribers": total_subscribers
    })


# === Newsletter subscription ===
@app.route('/api/roadmap/subscribe', methods=['POST'])
@login_required_session
def subscribe_newsletter():
    data = request.get_json()
    email = data.get("email", "").strip().lower()
    
    if not email:
        return jsonify({"message": "Email is required"}), 400

    # Check if user exists in the database
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"message": "This email is not registered on our website. Please register first."}), 400

    # Check if already subscribed
    if hasattr(user, 'roadmap_subscribed') and user.roadmap_subscribed:
        return jsonify({"message": "You are already subscribed to roadmap updates!"}), 400

    # Mark user as subscribed
    user.roadmap_subscribed = True
    db.session.commit()

    # Send confirmation email
    try:
        msg = Message(
            subject="📋 ZestPay Roadmap Subscription Confirmation",
            recipients=[email]
        )
        msg.body = f"""
Dear {user.firstName or user.email.split('@')[0]},

Thank you for subscribing to ZestPay roadmap updates!

You'll now receive notifications about:
- New roadmap items
- Progress updates
- Feature releases
- Important milestones

You can view our current roadmap at: http://zestpay/roadmap

Stay tuned for exciting updates as we continue to innovate and transform the financial landscape!

Best regards,
The ZestPay Team
"""
        mail.send(msg)
        print(f"✅ Roadmap subscription confirmation sent to {email}")
    except Exception as e:
        print(f"❌ Failed to send subscription email: {str(e)}")
        # Still return success even if email fails

    return jsonify({
        "message": f"Dear {user.firstName or user.email.split('@')[0]}, you have successfully subscribed to ZestPay roadmap updates! Check your email for confirmation."
    })


@app.route('/protilo')
def protilo():
    return render_template('protilo.html')









# Models


# # Helper functions
# def generate_otp(length=6):
#     return ''.join(random.choices(string.digits, k=length))

# def store_otp(email, otp):
#     otp_store[email] = {
#         'otp': otp,
#         'expires': datetime.utcnow() + timedelta(minutes=10),
#         'attempts': 0
#     }

# def verify_stored_otp(email, otp):
#     if email not in otp_store:
#         return False, "No verification code found"
    
#     stored_data = otp_store[email]
    
#     # Check if expired
#     if datetime.utcnow() > stored_data['expires']:
#         del otp_store[email]
#         return False, "Verification code expired"
    
#     # Check attempts (max 3)
#     if stored_data['attempts'] >= 3:
#         del otp_store[email]
#         return False, "Too many attempts. Please request a new code"
    
#     # Verify OTP
#     if stored_data['otp'] != otp:
#         stored_data['attempts'] += 1
#         remaining = 3 - stored_data['attempts']
#         return False, f"Invalid code. {remaining} attempts remaining"
    
#     # OTP is correct - remove it
#     del otp_store[email]
#     return True, "Verified"

# def log_activity(user_id, activity_type, description, ip_address=None, user_agent=None):
#     activity = Activity(
#         user_id=user_id,
#         type=activity_type,
#         description=description,
#         ip_address=ip_address,
#         user_agent=user_agent
#     )
#     db.session.add(activity)
#     db.session.commit()

# def calculate_security_score(user):
#     score = 50  # Base score
    
#     # Email verified (+20)
#     if user.email_verified:
#         score += 20
    
#     # Two-factor enabled (+20)
#     if user.two_factor_enabled:
#         score += 20
    
#     # Strong password (+10)
#     password = user.password
#     if len(password) >= 8 and any(c.isupper() for c in password) and any(c.isdigit() for c in password):
#         score += 10
    
#     # Recent login (-10 if more than 30 days)
#     if user.last_login and (datetime.utcnow() - user.last_login).days > 30:
#         score -= 10
    
#     # Cap at 0-100
#     score = max(0, min(100, score))
    
#     # Update user's security score
#     user.security_score = score
#     db.session.commit()
    
#     return score

# def fetch_market_rates():
#     # This would normally fetch from a real API
#     # For demo purposes, we'll generate random data
#     currencies = ['BTC', 'ETH', 'USDT', 'BNB', 'XRP', 'ADA', 'DOGE', 'DOT', 'LINK', 'LTC']
    
#     for currency in currencies:
#         # Check if we already have this currency
#         rate = MarketRate.query.filter_by(currency=currency).first()
        
#         if not rate:
#             # Create new rate
#             new_rate = MarketRate(
#                 currency=currency,
#                 rate_to_usd=random.uniform(0.1, 50000),
#                 change_24h=random.uniform(-10, 10)
#             )
#             db.session.add(new_rate)
#         else:
#             # Update existing rate with small random change
#             rate.rate_to_usd *= (1 + random.uniform(-0.05, 0.05))
#             rate.change_24h = random.uniform(-10, 10)
#             rate.updated_at = datetime.utcnow()
    
#     db.session.commit()





# @app.route('/api/profile')
# @login_required_session
# def api_profile():
#     if 'user_id' not in session:
#         return jsonify({"status": "error", "message": "Not authenticated"}), 401
    
#     user = User.query.get(session['user_id'])
#     if not user:
#         return jsonify({"status": "error", "message": "User not found"}), 404
    
#     # Calculate security score
#     security_score = calculate_security_score(user)
    
#     # Get transaction count
#     transaction_count = Transaction.query.filter_by(user_id=user.id).count()
    
#     # Get recent activities
#     activities = Activity.query.filter_by(user_id=user.id).order_by(Activity.created_at.desc()).limit(5).all()
    
#     return jsonify({
#         "status": "ok",
#         "profile": {
#             "id": user.id,
#             "firstName": user.firstName,
#             "lastName": user.lastName,
#             "email": user.email,
#             "phone": user.phone,
#             "referral": user.referral,
#             "email_verified": user.email_verified,
#             "created_at": user.created_at.isoformat(),
#             "last_login": user.last_login.isoformat() if user.last_login else None,
#             "security_score": security_score,
#             "transaction_count": transaction_count
#         },
#         "activities": [
#             {
#                 "type": activity.type,
#                 "description": activity.description,
#                 "created_at": activity.created_at.isoformat()
#             } for activity in activities
#         ]
#     })
# def fetch_market_rates():
#     """Update market rates with small random changes and add price check URLs"""
#     # Define currency URLs for price checking
#     currency_urls = {
#         'BTC': 'https://coinmarketcap.com/currencies/bitcoin/',
#         'ETH': 'https://coinmarketcap.com/currencies/ethereum/',
#         'USDT': 'https://coinmarketcap.com/currencies/tether/',
#         'BNB': 'https://coinmarketcap.com/currencies/binance-coin/',
#         'XRP': 'https://coinmarketcap.com/currencies/xrp/',
#         'ADA': 'https://coinmarketcap.com/currencies/cardano/',
#         'DOGE': 'https://coinmarketcap.com/currencies/dogecoin/',
#         'DOT': 'https://coinmarketcap.com/currencies/polkadot-new/',
#         'LINK': 'https://coinmarketcap.com/currencies/chainlink/',
#         'LTC': 'https://coinmarketcap.com/currencies/litecoin/'
#     }
    
#     for currency in currencies:
#         if currency not in market_rates:
#             # Create new rate if it doesn't exist
#             market_rates[currency] = {
#                 "currency": currency,
#                 "rate_to_usd": random.uniform(0.1, 50000),
#                 "change_24h": random.uniform(-10, 10),
#                 "updated_at": datetime.utcnow(),
#                 "price_url": currency_urls.get(currency, f"https://coinmarketcap.com/currencies/{currency.lower()}/"),
#                 "chart_url": f"https://www.tradingview.com/symbols/{currency}USD/",
#                 "coingecko_url": f"https://www.coingecko.com/en/coins/{currency.lower()}"
#             }
#         else:
#             # Update existing rate with small random change
#             rate = market_rates[currency]
#             rate['rate_to_usd'] *= (1 + random.uniform(-0.05, 0.05))
#             rate['change_24h'] = random.uniform(-10, 10)
#             rate['updated_at'] = datetime.utcnow()
#             # Ensure URLs are present
#             if 'price_url' not in rate:
#                 rate['price_url'] = currency_urls.get(currency, f"https://coinmarketcap.com/currencies/{currency.lower()}/")
#             if 'chart_url' not in rate:
#                 rate['chart_url'] = f"https://www.tradingview.com/symbols/{currency}USD/"
#             if 'coingecko_url' not in rate:
#                 rate['coingecko_url'] = f"https://www.coingecko.com/en/coins/{currency.lower()}"

# @app.route('/api/market-rates')
# def api_market_rates():
#     # Check if user is authenticated
#     if 'user_id' not in session:
#         return jsonify({"status": "error", "message": "Not authenticated"}), 401
    
#     # Fetch market rates (updates with random changes)
#     fetch_market_rates()
    
#     # Convert dictionary values to list and sort by updated_at
#     rates_list = list(market_rates.values())
#     rates_list.sort(key=lambda x: x['updated_at'], reverse=True)
    
#     return jsonify({
#         "status": "ok",
#         "rates": [
#             {
#                 "currency": rate['currency'],
#                 "rate_to_usd": rate['rate_to_usd'],
#                 "change_24h": rate['change_24h'],
#                 "updated_at": rate['updated_at'].isoformat(),
#                 "links": {
#                     "coinmarketcap": rate.get('price_url'),
#                     "tradingview": rate.get('chart_url'),
#                     "coingecko": rate.get('coingecko_url')
#                 }
#             } for rate in rates_list
#         ]
#     })

# @app.route('/api/transactions')
# def api_transactions():
#     if 'user_id' not in session:
#         return jsonify({"status": "error", "message": "Not authenticated"}), 401
    
#     page = request.args.get('page', 1, type=int)
#     per_page = request.args.get('per_page', 10, type=int)
    
#     transactions = Transaction.query.filter_by(user_id=session['user_id']).order_by(
#         Transaction.created_at.desc()
#     ).paginate(page=page, per_page=per_page)
    
#     return jsonify({
#         "status": "ok",
#         "transactions": [
#             {
#                 "id": t.id,
#                 "amount": t.amount,
#                 "type": t.type,
#                 "status": t.status,
#                 "description": t.description,
#                 "recipient": t.recipient,
#                 "created_at": t.created_at.isoformat()
#             } for t in transactions.items
#         ],
#         "pagination": {
#             "page": transactions.page,
#             "pages": transactions.pages,
#             "per_page": transactions.per_page,
#             "total": transactions.total
#         }
#     })

# @app.route('/api/ai', methods=['POST'])
# def api_ai():
#     if 'user_id' not in session:
#         return jsonify({"status": "error", "message": "Not authenticated"}), 401
    
#     data = request.get_json()
#     if not data or 'prompt' not in data:
#         return jsonify({"status": "error", "message": "Missing prompt"}), 400
    
#     prompt = data['prompt'].lower()
    
#     # Simple rule-based responses
#     if 'balance' in prompt or 'account' in prompt:
#         user = User.query.get(session['user_id'])
#         return jsonify({
#             "action": "message",
#             "reply": f"Your current account balance is ${random.uniform(100, 5000):.2f}. Would you like to see your transaction history?"
#         })
#     elif 'transaction' in prompt or 'history' in prompt:
#         return jsonify({
#             "action": "redirect",
#             "reply": "I'll take you to your transaction history.",
#             "redirect_url": "/history"
#         })
#     elif 'security' in prompt or 'safe' in prompt:
#         user = User.query.get(session['user_id'])
#         score = calculate_security_score(user)
#         return jsonify({
#             "action": "message",
#             "reply": f"Your current security score is {score}/100. {'This is good, but you can improve it by enabling two-factor authentication.' if score < 80 else 'Your account is well secured!'}"
#         })
#     elif 'market' in prompt or 'rates' in prompt or 'price' in prompt:
#         rates = MarketRate.query.order_by(MarketRate.updated_at.desc()).limit(3).all()
#         rate_text = "Current market rates:\n"
#         for rate in rates:
#             rate_text += f"{rate.currency}: ${rate.rate_to_usd:.2f} ({rate.change_24h:+.2f}%)\n"
#         return jsonify({
#             "action": "message",
#             "reply": rate_text
#         })
#     elif 'help' in prompt or 'support' in prompt:
#         return jsonify({


# class User(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     email = db.Column(db.String(120), unique=True, nullable=False)
#     password_hash = db.Column(db.String(255), nullable=False)
#     first_name = db.Column(db.String(50))
#     last_name = db.Column(db.String(50))
#     phone = db.Column(db.String(20))
#     referral = db.Column(db.String(20))
#     created_at = db.Column(db.DateTime, default=datetime.utcnow)
#     security_score = db.Column(db.Integer, default=50)
#     transaction_count = db.Column(db.Integer, default=0)
#     last_login = db.Column(db.DateTime)
#     verification_status = db.Column(db.String(20), default='unverified')  # unverified, verified, premium

# API Endpoints

# @app.route('/api/market-rates', methods=['GET'])
# def get_market_rates():
#     try:
#         # List of cryptocurrencies to fetch
#         crypto_ids = 'bitcoin,ethereum,litecoin,ripple,bitcoin-cash,tether,binancecoin,cardano,solana,dogecoin'
        
#         # Fetch data from CoinGecko API
#         url = f'https://api.coingecko.com/api/v3/coins/markets?vs_currency=usd&ids={crypto_ids}&order=market_cap_desc&per_page=10&page=1&sparkline=true&price_change_percentage=1h,24h,7d'
        
#         response = requests.get(url, timeout=10)
        
#         if response.status_code != 200:
#             # If API fails, return cached or default data
#             return get_fallback_rates()
        
#         data = response.json()
        
#         # Format rates for response with more trading data
#         rates_data = []
#         for coin in data:
#             # Generate realistic high/low prices based on current price
#             current_price = coin['current_price']
#             price_change_24h = coin['price_change_percentage_24h'] if coin['price_change_percentage_24h'] is not None else 0
            
#             # Calculate high/low based on 24h change
#             if price_change_24h > 0:
#                 high_price = current_price * (1 + abs(price_change_24h) / 100 * 1.5)
#                 low_price = current_price * (1 - abs(price_change_24h) / 100 * 0.5)
#             else:
#                 high_price = current_price * (1 + abs(price_change_24h) / 100 * 0.5)
#                 low_price = current_price * (1 - abs(price_change_24h) / 100 * 1.5)
            
#             # Generate realistic volume
#             volume = coin.get('total_volume', random.uniform(1000000, 100000000))
            
#             rates_data.append({
#                 'currency': coin['symbol'].upper(),
#                 'name': coin['name'],
#                 'rate_to_usd': current_price,
#                 'change_1h': coin.get('price_change_percentage_1h_in_currency', 0),
#                 'change_24h': price_change_24h,
#                 'change_7d': coin.get('price_change_percentage_7d_in_currency', 0),
#                 'high_24h': high_price,
#                 'low_24h': low_price,
#                 'volume_24h': volume,
#                 'market_cap': coin.get('market_cap', 0),
#                 'sparkline': coin.get('sparkline_in_7d', {}).get('price', [])
#             })
        
#         return jsonify({
#             'status': 'ok',
#             'rates': rates_data,
#             'last_updated': datetime.utcnow().isoformat()
#         })
#     except Exception as e:
#         # Return fallback data if anything goes wrong
#         return get_fallback_rates()

# def get_fallback_rates():
#     """Fallback rates when API is unavailable"""
#     fallback_rates = [
#         {'currency': 'BTC', 'name': 'Bitcoin', 'rate_to_usd': 28500.50, 'change_1h': 0.5, 'change_24h': 2.5, 'change_7d': -1.2, 'high_24h': 29000, 'low_24h': 27500, 'volume_24h': 15000000000, 'market_cap': 550000000000},
#         {'currency': 'ETH', 'name': 'Ethereum', 'rate_to_usd': 1850.75, 'change_1h': -0.3, 'change_24h': -1.2, 'change_7d': 3.5, 'high_24h': 1900, 'low_24h': 1800, 'volume_24h': 8000000000, 'market_cap': 220000000000},
#         {'currency': 'LTC', 'name': 'Litecoin', 'rate_to_usd': 95.30, 'change_1h': 0.2, 'change_24h': 0.8, 'change_7d': -2.1, 'high_24h': 98, 'low_24h': 92, 'volume_24h': 400000000, 'market_cap': 7000000000},
#         {'currency': 'XRP', 'name': 'Ripple', 'rate_to_usd': 0.52, 'change_1h': -0.1, 'change_24h': -0.5, 'change_7d': 1.8, 'high_24h': 0.55, 'low_24h': 0.50, 'volume_24h': 1500000000, 'market_cap': 25000000000},
#         {'currency': 'BCH', 'name': 'Bitcoin Cash', 'rate_to_usd': 230.15, 'change_1h': 0.4, 'change_24h': 1.7, 'change_7d': -0.8, 'high_24h': 235, 'low_24h': 225, 'volume_24h': 200000000, 'market_cap': 4500000000},
#         {'currency': 'USDT', 'name': 'Tether', 'rate_to_usd': 1.00, 'change_1h': 0.01, 'change_24h': 0.01, 'change_7d': 0.02, 'high_24h': 1.01, 'low_24h': 0.99, 'volume_24h': 40000000000, 'market_cap': 83000000000},
#         {'currency': 'BNB', 'name': 'Binance Coin', 'rate_to_usd': 310.80, 'change_1h': 0.6, 'change_24h': 3.2, 'change_7d': 5.5, 'high_24h': 320, 'low_24h': 300, 'volume_24h': 1200000000, 'market_cap': 48000000000}
#     ]
    
#     return jsonify({
#         'status': 'ok',
#         'rates': fallback_rates,
#         'note': 'Using cached data - Live rates temporarily unavailable',
#         'last_updated': datetime.utcnow().isoformat()
#     })

# @app.route('/api/activities', methods=['GET'])
# def get_activities():
#     try:
#         # Get user ID from session or token (adjust based on your auth system)
#         user_id = request.args.get('user_id', 1)  # Default to user 1 for demo
        
#         # Get recent activities for the user
#         activities = Activity.query.filter_by(user_id=user_id).order_by(Activity.created_at.desc()).limit(20).all()
        
#         # If no activities, generate realistic sample data
#         if not activities:
#             generate_sample_activities(user_id)
#             activities = Activity.query.filter_by(user_id=user_id).order_by(Activity.created_at.desc()).limit(20).all()
        
#         # Format activities for response
#         activities_data = []
#         for activity in activities:
#             activity_data = {
#                 'id': activity.id,
#                 'type': activity.type,
#                 'description': activity.description,
#                 'created_at': activity.created_at.isoformat()
#             }
            
#             # Add details if available
#             if activity.details:
#                 try:
#                     import json
#                     activity_data['details'] = json.loads(activity.details)
#                 except:
#                     pass
            
#             activities_data.append(activity_data)
        
#         return jsonify({
#             'status': 'ok',
#             'activities': activities_data
#         })
#     except Exception as e:
#         return jsonify({
#             'status': 'error',
#             'message': str(e)
#         }), 500

# def generate_sample_activities(user_id):
#     """Generate realistic sample activities for a user"""
#     import json
    
#     # Get user to determine account age
#     user = User.query.get(user_id)
#     if not user:
#         return
    
#     # Calculate account age in days
#     account_age_days = (datetime.utcnow() - user.created_at).days
    
#     # Generate activities based on account age
#     activities = []
    
#     # Account creation activity
#     activities.append({
#         'type': 'account_created',
#         'description': 'Account created successfully',
#         'details': json.dumps({'ip_address': '192.168.1.1', 'device': 'Chrome on Windows'}),
#         'created_at': user.created_at
#     })
    
#     # Email verification
#     activities.append({
#         'type': 'email_verification',
#         'description': 'Email address verified',
#         'details': json.dumps({'email': user.email}),
#         'created_at': user.created_at + timedelta(hours=1)
#     })
    
#     # Initial login
#     activities.append({
#         'type': 'login',
#         'description': 'First login to account',
#         'details': json.dumps({'ip_address': '192.168.1.1', 'device': 'Chrome on Windows'}),
#         'created_at': user.created_at + timedelta(hours=2)
#     })
    
#     # Security setup
#     activities.append({
#         'type': 'security_update',
#         'description': 'Two-factor authentication enabled',
#         'details': json.dumps({'method': 'SMS', 'phone': user.phone}),
#         'created_at': user.created_at + timedelta(days=1)
#     })
    
#     # Profile updates
#     activities.append({
#         'type': 'profile_update',
#         'description': 'Profile information updated',
#         'details': json.dumps({'fields': ['phone', 'address']}),
#         'created_at': user.created_at + timedelta(days=2)
#     })
    
#     # Generate transactions based on account age
#     num_transactions = min(account_age_days // 7, 20)  # Roughly 1 transaction per week, max 20
    
#     for i in range(num_transactions):
#         # Random date within account history
#         days_ago = random.randint(1, account_age_days)
#         hours_ago = random.randint(0, 23)
#         minutes_ago = random.randint(0, 59)
        
#         created_at = user.created_at + timedelta(
#             days=days_ago, 
#             hours=hours_ago, 
#             minutes=minutes_ago
#         )
        
#         # Random transaction type
#         transaction_type = random.choice(['send', 'receive', 'exchange'])
#         currency = random.choice(['BTC', 'ETH', 'LTC', 'XRP'])
#         amount = round(random.uniform(0.001, 0.5), 6)
        
#         if transaction_type == 'send':
#             description = f"Sent {amount} {currency} to external wallet"
#             details = json.dumps({
#                 'amount': amount,
#                 'currency': currency,
#                 'to_address': f"{'0x' + ''.join([random.choice('0123456789abcdef') for _ in range(40)])}",
#                 'fee': round(amount * 0.001, 6)
#             })
#         elif transaction_type == 'receive':
#             description = f"Received {amount} {currency} from external wallet"
#             details = json.dumps({
#                 'amount': amount,
#                 'currency': currency,
#                 'from_address': f"{'0x' + ''.join([random.choice('0123456789abcdef') for _ in range(40)])}",
#                 'fee': 0
#             })
#         else:  # exchange
#             to_currency = random.choice(['BTC', 'ETH', 'LTC', 'XRP'])
#             if to_currency == currency:
#                 to_currency = 'USD' if currency != 'USD' else 'BTC'
            
#             description = f"Exchanged {amount} {currency} to {to_currency}"
#             details = json.dumps({
#                 'from_amount': amount,
#                 'from_currency': currency,
#                 'to_amount': round(amount * random.uniform(0.8, 1.2), 6),
#                 'to_currency': to_currency,
#                 'fee': round(amount * 0.002, 6)
#             })
        
#         activities.append({
#             'type': 'transaction',
#             'description': description,
#             'details': details,
#             'created_at': created_at
#         })
        
#         # Also create the transaction record
#         new_transaction = Transaction(
#             user_id=user_id,
#             amount=amount,
#             currency=currency,
#             type=transaction_type,
#             status='completed',
#             created_at=created_at,
#             completed_at=created_at + timedelta(minutes=random.randint(5, 30)),
#             description=description
#         )
#         db.session.add(new_transaction)
    
#     # Recent logins
#     for i in range(5):
#         days_ago = random.randint(0, min(30, account_age_days))
#         hours_ago = random.randint(0, 23)
#         minutes_ago = random.randint(0, 59)
        
#         created_at = datetime.utcnow() - timedelta(
#             days=days_ago, 
#             hours=hours_ago, 
#             minutes=minutes_ago
#         )
        
#         device = random.choice(['Chrome on Windows', 'Safari on iPhone', 'Chrome on Android', 'Firefox on Mac'])
#         ip = f"{random.randint(100, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
        
#         activities.append({
#             'type': 'login',
#             'description': f'Logged in from {device}',
#             'details': json.dumps({'ip_address': ip, 'device': device}),
#             'created_at': created_at
#         })
    
#     # Sort activities by date
#     activities.sort(key=lambda x: x['created_at'], reverse=True)
    
#     # Add activities to database
#     for activity in activities:
#         new_activity = Activity(
#             user_id=user_id,
#             type=activity['type'],
#             description=activity['description'],
#             details=activity.get('details'),
#             created_at=activity['created_at']
#         )
#         db.session.add(new_activity)
    
#     db.session.commit()

# @app.route('/api/transactions', methods=['GET'])
# def get_transactions():
#     try:
#         # Get user ID from session or token (adjust based on your auth system)
#         user_id = request.args.get('user_id', 1)  # Default to user 1 for demo
        
#         # Get filter parameters
#         transaction_type = request.args.get('type', '')
#         status = request.args.get('status', '')
#         currency = request.args.get('currency', '')
#         limit = int(request.args.get('limit', 20))
#         offset = int(request.args.get('offset', 0))
        
#         # Build query
#         query = Transaction.query.filter_by(user_id=user_id)
        
#         if transaction_type:
#             query = query.filter_by(type=transaction_type)
        
#         if status:
#             query = query.filter_by(status=status)
            
#         if currency:
#             query = query.filter_by(currency=currency)
        
#         # Get transactions with pagination
#         transactions = query.order_by(Transaction.created_at.desc()).offset(offset).limit(limit).all()
        
#         # If no transactions, generate sample data
#         if not transactions:
#             generate_sample_transactions(user_id)
#             transactions = query.order_by(Transaction.created_at.desc()).offset(offset).limit(limit).all()
        
#         # Format transactions for response
#         transactions_data = []
#         for transaction in transactions:
#             transaction_data = {
#                 'id': transaction.id,
#                 'amount': transaction.amount,
#                 'currency': transaction.currency,
#                 'type': transaction.type,
#                 'status': transaction.status,
#                 'fee': transaction.fee,
#                 'description': transaction.description,
#                 'created_at': transaction.created_at.isoformat()
#             }
            
#             # Add completion time if available
#             if transaction.completed_at:
#                 transaction_data['completed_at'] = transaction.completed_at.isoformat()
            
#             # Add addresses if available
#             if transaction.from_address:
#                 transaction_data['from_address'] = transaction.from_address
                
#             if transaction.to_address:
#                 transaction_data['to_address'] = transaction.to_address
                
#             if transaction.tx_hash:
#                 transaction_data['tx_hash'] = transaction.tx_hash
            
#             transactions_data.append(transaction_data)
        
#         return jsonify({
#             'status': 'ok',
#             'transactions': transactions_data,
#             'total': Transaction.query.filter_by(user_id=user_id).count()
#         })
#     except Exception as e:
#         return jsonify({
#             'status': 'error',
#             'message': str(e)
#         }), 500

# def generate_sample_transactions(user_id):
#     """Generate realistic sample transactions for a user"""
#     # Get user to determine account age
#     user = User.query.get(user_id)
#     if not user:
#         return
    
#     # Calculate account age in days
#     account_age_days = (datetime.utcnow() - user.created_at).days
    
#     # Generate transactions based on account age
#     num_transactions = min(account_age_days // 3, 50)  # Roughly 1 transaction per 3 days, max 50
    
#     currencies = ['BTC', 'ETH', 'LTC', 'XRP', 'BCH', 'USDT', 'BNB']
#     types = ['send', 'receive', 'exchange']
#     statuses = ['completed', 'pending', 'failed']
    
#     for i in range(num_transactions):
#         # Random date within account history
#         days_ago = random.randint(1, account_age_days)
#         hours_ago = random.randint(0, 23)
#         minutes_ago = random.randint(0, 59)
        
#         created_at = user.created_at + timedelta(
#             days=days_ago, 
#             hours=hours_ago, 
#             minutes=minutes_ago
#         )
        
#         # Random transaction data
#         amount = round(random.uniform(0.001, 1.0), 6)
#         currency = random.choice(currencies)
#         transaction_type = random.choice(types)
#         status = random.choice(statuses) if random.random() > 0.8 else 'completed'  # 80% completed
        
#         # Generate description based on type
#         if transaction_type == 'send':
#             description = f"Sent {amount} {currency} to external wallet"
#             from_address = f"{'0x' + ''.join([random.choice('0123456789abcdef') for _ in range(40)])}"
#             to_address = f"{'0x' + ''.join([random.choice('0123456789abcdef') for _ in range(40)])}"
#             fee = round(amount * 0.001, 6)
#             tx_hash = f"{'0x' + ''.join([random.choice('0123456789abcdef') for _ in range(64)])}" if status == 'completed' else None
#         elif transaction_type == 'receive':
#             description = f"Received {amount} {currency} from external wallet"
#             from_address = f"{'0x' + ''.join([random.choice('0123456789abcdef') for _ in range(40)])}"
#             to_address = None
#             fee = 0
#             tx_hash = f"{'0x' + ''.join([random.choice('0123456789abcdef') for _ in range(64)])}" if status == 'completed' else None
#         else:  # exchange
#             to_currency = random.choice(currencies)
#             while to_currency == currency:
#                 to_currency = random.choice(currencies)
            
#             description = f"Exchanged {amount} {currency} to {to_currency}"
#             from_address = None
#             to_address = None
#             fee = round(amount * 0.002, 6)
#             tx_hash = f"{'0x' + ''.join([random.choice('0123456789abcdef') for _ in range(64)])}" if status == 'completed' else None
        
#         # Create completion time if completed
#         completed_at = None
#         if status == 'completed':
#             completed_at = created_at + timedelta(minutes=random.randint(5, 60))
        
#         new_transaction = Transaction(
#             user_id=user_id,
#             amount=amount,
#             currency=currency,
#             type=transaction_type,
#             status=status,
#             fee=fee,
#             from_address=from_address,
#             to_address=to_address,
#             tx_hash=tx_hash,
#             created_at=created_at,
#             completed_at=completed_at,
#             description=description
#         )
#         db.session.add(new_transaction)
    
#     db.session.commit()

# @app.route('/api/profile', methods=['GET'])
# def get_profile():
#     try:
#         # Get user ID from session or token (adjust based on your auth system)
#         user_id = request.args.get('user_id', 1)  # Default to user 1 for demo
        
#         # Get user from database
#         user = User.query.get(user_id)
        
#         if not user:
#             # Create a sample user if not exists
#             user = User(
#                 id=user_id,
#                 email=f"user{user_id}@example.com",
#                 password_hash="hashed_password",
#                 first_name=f"User{user_id}",
#                 last_name="Test",
#                 phone=f"+123456789{user_id}",
#                 referral=f"USER{user_id}",
#                 created_at=datetime.utcnow() - timedelta(days=random.randint(30, 365)),
#                 security_score=random.randint(50, 100),
#                 transaction_count=0,
#                 verification_status=random.choice(['verified', 'unverified', 'premium'])
#             )
#             db.session.add(user)
#             db.session.commit()
        
#         # Update last login
#         user.last_login = datetime.utcnow()
#         db.session.commit()
        
#         # Get recent activities for the user
#         activities = Activity.query.filter_by(user_id=user_id).order_by(Activity.created_at.desc()).limit(5).all()
        
#         # Format activities for response
#         activities_data = []
#         for activity in activities:
#             activity_data = {
#                 'type': activity.type,
#                 'description': activity.description,
#                 'created_at': activity.created_at.isoformat()
#             }
            
#             # Add details if available
#             if activity.details:
#                 try:
#                     import json
#                     activity_data['details'] = json.loads(activity.details)
#                 except:
#                     pass
            
#             activities_data.append(activity_data)
        
#         # Calculate member since with proper formatting
#         member_since = user.created_at.strftime('%B %d, %Y')
        
#         # Calculate account age in days, months, years
#         account_age = datetime.utcnow() - user.created_at
#         years = account_age.days // 365
#         months = (account_age.days % 365) // 30
#         days = account_age.days % 30
        
#         account_age_str = ""
#         if years > 0:
#             account_age_str += f"{years} year{'s' if years > 1 else ''}"
#         if months > 0:
#             if account_age_str:
#                 account_age_str += ", "
#             account_age_str += f"{months} month{'s' if months > 1 else ''}"
#         if days > 0 or not account_age_str:
#             if account_age_str:
#                 account_age_str += ", "
#             account_age_str += f"{days} day{'s' if days != 1 else ''}"
        
#         # Update transaction count
#         transaction_count = Transaction.query.filter_by(user_id=user_id).count()
#         user.transaction_count = transaction_count
#         db.session.commit()
        
#         # Format user profile for response
#         profile_data = {
#             'id': user.id,
#             'email': user.email,
#             'firstName': user.first_name,
#             'lastName': user.last_name,
#             'phone': user.phone,
#             'referral': user.referral,
#             'member_since': member_since,
#             'account_age': account_age_str,
#             'created_at': user.created_at.isoformat(),
#             'security_score': user.security_score,
#             'transaction_count': transaction_count,
#             'verification_status': user.verification_status,
#             'last_login': user.last_login.isoformat() if user.last_login else None
#         }
        
#         return jsonify({
#             'status': 'ok',
#             'profile': profile_data,
#             'activities': activities_data
#         })
#     except Exception as e:
#         return jsonify({
#             'status': 'error',
#             'message': str(e)
#         }), 500

# # Initialize database


from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
from datetime import datetime, timedelta
import random
import requests
import threading
import time
from flask_cors import CORS
import json


# Models (same as before)
class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    details = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(10), nullable=False)
    type = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    fee = db.Column(db.Float, default=0.0)
    from_address = db.Column(db.String(255))
    to_address = db.Column(db.String(255))
    tx_hash = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    description = db.Column(db.String(255))

# class User(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     email = db.Column(db.String(120), unique=True, nullable=False)
#     password_hash = db.Column(db.String(255), nullable=False)
#     first_name = db.Column(db.String(50))
#     last_name = db.Column(db.String(50))
#     phone = db.Column(db.String(20))
#     referral = db.Column(db.String(20))
#     created_at = db.Column(db.DateTime, default=datetime.utcnow)
#     security_score = db.Column(db.Integer, default=50)
#     transaction_count = db.Column(db.Integer, default=0)
#     last_login = db.Column(db.DateTime)
#     verification_status = db.Column(db.String(20), default='unverified')

# Global variable to store the latest market rates
latest_rates = None
last_updated = None

# Real-time price update function
def update_market_rates():
    global latest_rates, last_updated
    
    while True:
        try:
            # List of cryptocurrencies to fetch
            crypto_ids = 'bitcoin,ethereum,litecoin,ripple,bitcoin-cash,tether,binancecoin,cardano,solana,dogecoin'
            
            # Fetch data from CoinGecko API
            url = f'https://api.coingecko.com/api/v3/coins/markets?vs_currency=usd&ids={crypto_ids}&order=market_cap_desc&per_page=10&page=1&sparkline=true&price_change_percentage=1h,24h,7d'
            
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                # Format rates for response with more trading data
                rates_data = []
                for coin in data:
                    # Generate realistic high/low prices based on current price
                    current_price = coin['current_price']
                    price_change_24h = coin['price_change_percentage_24h'] if coin['price_change_percentage_24h'] is not None else 0
                    
                    # Calculate high/low based on 24h change
                    if price_change_24h > 0:
                        high_price = current_price * (1 + abs(price_change_24h) / 100 * 1.5)
                        low_price = current_price * (1 - abs(price_change_24h) / 100 * 0.5)
                    else:
                        high_price = current_price * (1 + abs(price_change_24h) / 100 * 0.5)
                        low_price = current_price * (1 - abs(price_change_24h) / 100 * 1.5)
                    
                    # Generate realistic volume
                    volume = coin.get('total_volume', random.uniform(1000000, 100000000))
                    
                    # Create links to external exchanges
                    exchange_links = {
                        'coingecko': f"https://www.coingecko.com/en/coins/{coin['id']}",
                        'binance': f"https://www.binance.com/en/trade/{coin['symbol'].upper()}_USDT",
                        'coinbase': f"https://www.coinbase.com/price/{coin['id']}"
                    }
                    
                    rates_data.append({
                        'currency': coin['symbol'].upper(),
                        'name': coin['name'],
                        'rate_to_usd': current_price,
                        'change_1h': coin.get('price_change_percentage_1h_in_currency', 0),
                        'change_24h': price_change_24h,
                        'change_7d': coin.get('price_change_percentage_7d_in_currency', 0),
                        'high_24h': high_price,
                        'low_24h': low_price,
                        'volume_24h': volume,
                        'market_cap': coin.get('market_cap', 0),
                        'sparkline': coin.get('sparkline_in_7d', {}).get('price', []),
                        'links': exchange_links
                    })
                
                latest_rates = rates_data
                last_updated = datetime.utcnow()
                
                # Emit real-time update to all connected clients
                socketio.emit('market_update', {
                    'status': 'ok',
                    'rates': rates_data,
                    'last_updated': last_updated.isoformat()
                })
                
                print(f"Market rates updated at {last_updated}")
            else:
                print(f"Failed to fetch market rates: {response.status_code}")
                
        except Exception as e:
            print(f"Error updating market rates: {str(e)}")
        
        # Sleep for 30 seconds before the next update
        time.sleep(30)

# Start the background thread for real-time updates
def start_background_thread():
    thread = threading.Thread(target=update_market_rates)
    thread.daemon = True
    thread.start()

# WebSocket event handlers

# API Endpoints

@app.route('/api/market-rates', methods=['GET'])
def get_market_rates():
    try:
        # If we have cached rates, return them
        if latest_rates:
            return jsonify({
                'status': 'ok',
                'rates': latest_rates,
                'last_updated': last_updated.isoformat() if last_updated else None
            })
        
        # Otherwise, fetch them now
        crypto_ids = 'bitcoin,ethereum,litecoin,ripple,bitcoin-cash,tether,binancecoin,cardano,solana,dogecoin'
        url = f'https://api.coingecko.com/api/v3/coins/markets?vs_currency=usd&ids={crypto_ids}&order=market_cap_desc&per_page=10&page=1&sparkline=true&price_change_percentage=1h,24h,7d'
        
        response = requests.get(url, timeout=10)
        
        if response.status_code != 200:
            return get_fallback_rates()
        
        data = response.json()
        
        # Format rates for response with more trading data
        rates_data = []
        for coin in data:
            # Generate realistic high/low prices based on current price
            current_price = coin['current_price']
            price_change_24h = coin['price_change_percentage_24h'] if coin['price_change_percentage_24h'] is not None else 0
            
            # Calculate high/low based on 24h change
            if price_change_24h > 0:
                high_price = current_price * (1 + abs(price_change_24h) / 100 * 1.5)
                low_price = current_price * (1 - abs(price_change_24h) / 100 * 0.5)
            else:
                high_price = current_price * (1 + abs(price_change_24h) / 100 * 0.5)
                low_price = current_price * (1 - abs(price_change_24h) / 100 * 1.5)
            
            # Generate realistic volume
            volume = coin.get('total_volume', random.uniform(1000000, 100000000))
            
            # Create links to external exchanges
            exchange_links = {
                'coingecko': f"https://www.coingecko.com/en/coins/{coin['id']}",
                'binance': f"https://www.binance.com/en/trade/{coin['symbol'].upper()}_USDT",
                'coinbase': f"https://www.coinbase.com/price/{coin['id']}"
            }
            
            rates_data.append({
                'currency': coin['symbol'].upper(),
                'name': coin['name'],
                'rate_to_usd': current_price,
                'change_1h': coin.get('price_change_percentage_1h_in_currency', 0),
                'change_24h': price_change_24h,
                'change_7d': coin.get('price_change_percentage_7d_in_currency', 0),
                'high_24h': high_price,
                'low_24h': low_price,
                'volume_24h': volume,
                'market_cap': coin.get('market_cap', 0),
                'sparkline': coin.get('sparkline_in_7d', {}).get('price', []),
                'links': exchange_links
            })
        
        return jsonify({
            'status': 'ok',
            'rates': rates_data,
            'last_updated': datetime.utcnow().isoformat()
        })
    except Exception as e:
        return get_fallback_rates()

def get_fallback_rates():
    """Fallback rates when API is unavailable"""
    fallback_rates = [
        {
            'currency': 'BTC', 
            'name': 'Bitcoin', 
            'rate_to_usd': 28500.50, 
            'change_1h': 0.5, 
            'change_24h': 2.5, 
            'change_7d': -1.2, 
            'high_24h': 29000, 
            'low_24h': 27500, 
            'volume_24h': 15000000000, 
            'market_cap': 550000000000,
            'links': {
                'coingecko': "https://www.coingecko.com/en/coins/bitcoin",
                'binance': "https://www.binance.com/en/trade/BTC_USDT",
                'coinbase': "https://www.coinbase.com/price/bitcoin"
            }
        },
        {
            'currency': 'ETH', 
            'name': 'Ethereum', 
            'rate_to_usd': 1850.75, 
            'change_1h': -0.3, 
            'change_24h': -1.2, 
            'change_7d': 3.5, 
            'high_24h': 1900, 
            'low_24h': 1800, 
            'volume_24h': 8000000000, 
            'market_cap': 220000000000,
            'links': {
                'coingecko': "https://www.coingecko.com/en/coins/ethereum",
                'binance': "https://www.binance.com/en/trade/ETH_USDT",
                'coinbase': "https://www.coinbase.com/price/ethereum"
            }
        },
        {
            'currency': 'LTC', 
            'name': 'Litecoin', 
            'rate_to_usd': 95.30, 
            'change_1h': 0.2, 
            'change_24h': 0.8, 
            'change_7d': -2.1, 
            'high_24h': 98, 
            'low_24h': 92, 
            'volume_24h': 400000000, 
            'market_cap': 7000000000,
            'links': {
                'coingecko': "https://www.coingecko.com/en/coins/litecoin",
                'binance': "https://www.binance.com/en/trade/LTC_USDT",
                'coinbase': "https://www.coinbase.com/price/litecoin"
            }
        },
        {
            'currency': 'XRP', 
            'name': 'Ripple', 
            'rate_to_usd': 0.52, 
            'change_1h': -0.1, 
            'change_24h': -0.5, 
            'change_7d': 1.8, 
            'high_24h': 0.55, 
            'low_24h': 0.50, 
            'volume_24h': 1500000000, 
            'market_cap': 25000000000,
            'links': {
                'coingecko': "https://www.coingecko.com/en/coins/ripple",
                'binance': "https://www.binance.com/en/trade/XRP_USDT",
                'coinbase': "https://www.coinbase.com/price/ripple"
            }
        },
        {
            'currency': 'BCH', 
            'name': 'Bitcoin Cash', 
            'rate_to_usd': 230.15, 
            'change_1h': 0.4, 
            'change_24h': 1.7, 
            'change_7d': -0.8, 
            'high_24h': 235, 
            'low_24h': 225, 
            'volume_24h': 200000000, 
            'market_cap': 4500000000,
            'links': {
                'coingecko': "https://www.coingecko.com/en/coins/bitcoin-cash",
                'binance': "https://www.binance.com/en/trade/BCH_USDT",
                'coinbase': "https://www.coinbase.com/price/bitcoin-cash"
            }
        },
        {
            'currency': 'USDT', 
            'name': 'Tether', 
            'rate_to_usd': 1.00, 
            'change_1h': 0.01, 
            'change_24h': 0.01, 
            'change_7d': 0.02, 
            'high_24h': 1.01, 
            'low_24h': 0.99, 
            'volume_24h': 40000000000, 
            'market_cap': 83000000000,
            'links': {
                'coingecko': "https://www.coingecko.com/en/coins/tether",
                'binance': "https://www.binance.com/en/trade/USDT_USD",
                'coinbase': "https://www.coinbase.com/price/tether"
            }
        },
        {
            'currency': 'BNB', 
            'name': 'Binance Coin', 
            'rate_to_usd': 310.80, 
            'change_1h': 0.6, 
            'change_24h': 3.2, 
            'change_7d': 5.5, 
            'high_24h': 320, 
            'low_24h': 300, 
            'volume_24h': 1200000000, 
            'market_cap': 48000000000,
            'links': {
                'coingecko': "https://www.coingecko.com/en/coins/binancecoin",
                'binance': "https://www.binance.com/en/trade/BNB_USDT",
                'coinbase': "https://www.coinbase.com/price/binancecoin"
            }
        }
    ]
    
    return jsonify({
        'status': 'ok',
        'rates': fallback_rates,
        'note': 'Using cached data - Live rates temporarily unavailable',
        'last_updated': datetime.utcnow().isoformat()
    })

@app.route('/api/activities', methods=['GET'])
def get_activities():
    try:
        # Get user ID from session or token (adjust based on your auth system)
        user_id = request.args.get('user_id', 1)  # Default to user 1 for demo
        
        # Get recent activities for the user
        activities = Activity.query.filter_by(user_id=user_id).order_by(Activity.created_at.desc()).limit(20).all()
        
        # If no activities, generate realistic sample data
        if not activities:
            generate_sample_activities(user_id)
            activities = Activity.query.filter_by(user_id=user_id).order_by(Activity.created_at.desc()).limit(20).all()
        
        # Format activities for response
        activities_data = []
        for activity in activities:
            activity_data = {
                'id': activity.id,
                'type': activity.type,
                'description': activity.description,
                'created_at': activity.created_at.isoformat()
            }
            
            # Add details if available
            if activity.details:
                try:
                    activity_data['details'] = json.loads(activity.details)
                except:
                    pass
            
            activities_data.append(activity_data)
        
        return jsonify({
            'status': 'ok',
            'activities': activities_data
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

def generate_sample_activities(user_id):
    """Generate realistic sample activities for a user"""
    # Get user to determine account age
    user = User.query.get(user_id)
    if not user:
        return
    
    # Calculate account age in days
    account_age_days = (datetime.utcnow() - user.created_at).days
    
    # Generate activities based on account age
    activities = []
    
    # Account creation activity
    activities.append({
        'type': 'account_created',
        'description': 'Account created successfully',
        'details': json.dumps({'ip_address': '192.168.1.1', 'device': 'Chrome on Windows'}),
        'created_at': user.created_at
    })
    
    # Email verification
    activities.append({
        'type': 'email_verification',
        'description': 'Email address verified',
        'details': json.dumps({'email': user.email}),
        'created_at': user.created_at + timedelta(hours=1)
    })
    
    # Initial login
    activities.append({
        'type': 'login',
        'description': 'First login to account',
        'details': json.dumps({'ip_address': '192.168.1.1', 'device': 'Chrome on Windows'}),
        'created_at': user.created_at + timedelta(hours=2)
    })
    
    # Security setup
    activities.append({
        'type': 'security_update',
        'description': 'Two-factor authentication enabled',
        'details': json.dumps({'method': 'SMS', 'phone': user.phone}),
        'created_at': user.created_at + timedelta(days=1)
    })
    
    # Profile updates
    activities.append({
        'type': 'profile_update',
        'description': 'Profile information updated',
        'details': json.dumps({'fields': ['phone', 'address']}),
        'created_at': user.created_at + timedelta(days=2)
    })
    
    # Generate transactions based on account age
    num_transactions = min(account_age_days // 7, 20)  # Roughly 1 transaction per week, max 20
    
    for i in range(num_transactions):
        # Random date within account history
        days_ago = random.randint(1, account_age_days)
        hours_ago = random.randint(0, 23)
        minutes_ago = random.randint(0, 59)
        
        created_at = user.created_at + timedelta(
            days=days_ago, 
            hours=hours_ago, 
            minutes=minutes_ago
        )
        
        # Random transaction type
        transaction_type = random.choice(['send', 'receive', 'exchange'])
        currency = random.choice(['BTC', 'ETH', 'LTC', 'XRP'])
        amount = round(random.uniform(0.001, 0.5), 6)
        
        if transaction_type == 'send':
            description = f"Sent {amount} {currency} to external wallet"
            details = json.dumps({
                'amount': amount,
                'currency': currency,
                'to_address': f"{'0x' + ''.join([random.choice('0123456789abcdef') for _ in range(40)])}",
                'fee': round(amount * 0.001, 6)
            })
        elif transaction_type == 'receive':
            description = f"Received {amount} {currency} from external wallet"
            details = json.dumps({
                'amount': amount,
                'currency': currency,
                'from_address': f"{'0x' + ''.join([random.choice('0123456789abcdef') for _ in range(40)])}",
                'fee': 0
            })
        else:  # exchange
            to_currency = random.choice(['BTC', 'ETH', 'LTC', 'XRP'])
            if to_currency == currency:
                to_currency = 'USD' if currency != 'USD' else 'BTC'
            
            description = f"Exchanged {amount} {currency} to {to_currency}"
            details = json.dumps({
                'from_amount': amount,
                'from_currency': currency,
                'to_amount': round(amount * random.uniform(0.8, 1.2), 6),
                'to_currency': to_currency,
                'fee': round(amount * 0.002, 6)
            })
        
        activities.append({
            'type': 'transaction',
            'description': description,
            'details': details,
            'created_at': created_at
        })
        
        # Also create the transaction record
        new_transaction = Transaction(
            user_id=user_id,
            amount=amount,
            currency=currency,
            type=transaction_type,
            status='completed',
            created_at=created_at,
            completed_at=created_at + timedelta(minutes=random.randint(5, 30)),
            description=description
        )
        db.session.add(new_transaction)
    
    # Recent logins
    for i in range(5):
        days_ago = random.randint(0, min(30, account_age_days))
        hours_ago = random.randint(0, 23)
        minutes_ago = random.randint(0, 59)
        
        created_at = datetime.utcnow() - timedelta(
            days=days_ago, 
            hours=hours_ago, 
            minutes=minutes_ago
        )
        
        device = random.choice(['Chrome on Windows', 'Safari on iPhone', 'Chrome on Android', 'Firefox on Mac'])
        ip = f"{random.randint(100, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
        
        activities.append({
            'type': 'login',
            'description': f'Logged in from {device}',
            'details': json.dumps({'ip_address': ip, 'device': device}),
            'created_at': created_at
        })
    
    # Sort activities by date
    activities.sort(key=lambda x: x['created_at'], reverse=True)
    
    # Add activities to database
    for activity in activities:
        new_activity = Activity(
            user_id=user_id,
            type=activity['type'],
            description=activity['description'],
            details=activity.get('details'),
            created_at=activity['created_at']
        )
        db.session.add(new_activity)
    
    db.session.commit()

@app.route('/api/transactions', methods=['GET'])
def get_transactions():
    try:
        # Get user ID from session or token (adjust based on your auth system)
        user_id = request.args.get('user_id', 1)  # Default to user 1 for demo
        
        # Get filter parameters
        transaction_type = request.args.get('type', '')
        status = request.args.get('status', '')
        currency = request.args.get('currency', '')
        limit = int(request.args.get('limit', 20))
        offset = int(request.args.get('offset', 0))
        
        # Build query
        query = Transaction.query.filter_by(user_id=user_id)
        
        if transaction_type:
            query = query.filter_by(type=transaction_type)
        
        if status:
            query = query.filter_by(status=status)
            
        if currency:
            query = query.filter_by(currency=currency)
        
        # Get transactions with pagination
        transactions = query.order_by(Transaction.created_at.desc()).offset(offset).limit(limit).all()
        
        # If no transactions, generate sample data
        if not transactions:
            generate_sample_transactions(user_id)
            transactions = query.order_by(Transaction.created_at.desc()).offset(offset).limit(limit).all()
        
        # Format transactions for response
        transactions_data = []
        for transaction in transactions:
            transaction_data = {
                'id': transaction.id,
                'amount': transaction.amount,
                'currency': transaction.currency,
                'type': transaction.type,
                'status': transaction.status,
                'fee': transaction.fee,
                'description': transaction.description,
                'created_at': transaction.created_at.isoformat()
            }
            
            # Add completion time if available
            if transaction.completed_at:
                transaction_data['completed_at'] = transaction.completed_at.isoformat()
            
            # Add addresses if available
            if transaction.from_address:
                transaction_data['from_address'] = transaction.from_address
                
            if transaction.to_address:
                transaction_data['to_address'] = transaction.to_address
                
            if transaction.tx_hash:
                transaction_data['tx_hash'] = transaction.tx_hash
            
            transactions_data.append(transaction_data)
        
        return jsonify({
            'status': 'ok',
            'transactions': transactions_data,
            'total': Transaction.query.filter_by(user_id=user_id).count()
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

def generate_sample_transactions(user_id):
    """Generate realistic sample transactions for a user"""
    # Get user to determine account age
    user = User.query.get(user_id)
    if not user:
        return
    
    # Calculate account age in days
    account_age_days = (datetime.utcnow() - user.created_at).days
    
    # Generate transactions based on account age
    num_transactions = min(account_age_days // 3, 50)  # Roughly 1 transaction per 3 days, max 50
    
    currencies = ['BTC', 'ETH', 'LTC', 'XRP', 'BCH', 'USDT', 'BNB']
    types = ['send', 'receive', 'exchange']
    statuses = ['completed', 'pending', 'failed']
    
    for i in range(num_transactions):
        # Random date within account history
        days_ago = random.randint(1, account_age_days)
        hours_ago = random.randint(0, 23)
        minutes_ago = random.randint(0, 59)
        
        created_at = user.created_at + timedelta(
            days=days_ago, 
            hours=hours_ago, 
            minutes=minutes_ago
        )
        
        # Random transaction data
        amount = round(random.uniform(0.001, 1.0), 6)
        currency = random.choice(currencies)
        transaction_type = random.choice(types)
        status = random.choice(statuses) if random.random() > 0.8 else 'completed'  # 80% completed
        
        # Generate description based on type
        if transaction_type == 'send':
            description = f"Sent {amount} {currency} to external wallet"
            from_address = f"{'0x' + ''.join([random.choice('0123456789abcdef') for _ in range(40)])}"
            to_address = f"{'0x' + ''.join([random.choice('0123456789abcdef') for _ in range(40)])}"
            fee = round(amount * 0.001, 6)
            tx_hash = f"{'0x' + ''.join([random.choice('0123456789abcdef') for _ in range(64)])}" if status == 'completed' else None
        elif transaction_type == 'receive':
            description = f"Received {amount} {currency} from external wallet"
            from_address = f"{'0x' + ''.join([random.choice('0123456789abcdef') for _ in range(40)])}"
            to_address = None
            fee = 0
            tx_hash = f"{'0x' + ''.join([random.choice('0123456789abcdef') for _ in range(64)])}" if status == 'completed' else None
        else:  # exchange
            to_currency = random.choice(currencies)
            while to_currency == currency:
                to_currency = random.choice(currencies)
            
            description = f"Exchanged {amount} {currency} to {to_currency}"
            from_address = None
            to_address = None
            fee = round(amount * 0.002, 6)
            tx_hash = f"{'0x' + ''.join([random.choice('0123456789abcdef') for _ in range(64)])}" if status == 'completed' else None
        
        # Create completion time if completed
        completed_at = None
        if status == 'completed':
            completed_at = created_at + timedelta(minutes=random.randint(5, 60))
        
        new_transaction = Transaction(
            user_id=user_id,
            amount=amount,
            currency=currency,
            type=transaction_type,
            status=status,
            fee=fee,
            from_address=from_address,
            to_address=to_address,
            tx_hash=tx_hash,
            created_at=created_at,
            completed_at=completed_at,
            description=description
        )
        db.session.add(new_transaction)
    
    db.session.commit()

@app.route('/api/profile', methods=['GET'])
def get_profile():
    try:
        # Get user ID from session or token (adjust based on your auth system)
        user_id = request.args.get('user_id', 1)  # Default to user 1 for demo
        
        # Get user from database
        user = User.query.get(user_id)
        
        if not user:
            # Create a sample user if not exists
            user = User(
                id=user_id,
                created_at=datetime.utcnow() - timedelta(days=random.randint(30, 365)),
                security_score=random.randint(50, 100),
                transaction_count=0,
                verification_status=random.choice(['verified', 'unverified', 'premium'])
            )
            db.session.add(user)
            db.session.commit()
        
        # Update last login
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        # Get recent activities for the user
        activities = Activity.query.filter_by(user_id=user_id).order_by(Activity.created_at.desc()).limit(5).all()
        
        # Format activities for response
        activities_data = []
        for activity in activities:
            activity_data = {
                'type': activity.type,
                'description': activity.description,
                'created_at': activity.created_at.isoformat()
            }
            
            # Add details if available
            if activity.details:
                try:
                    activity_data['details'] = json.loads(activity.details)
                except:
                    pass
            
            activities_data.append(activity_data)
        
        # Calculate member since with proper formatting
        member_since = user.created_at.strftime('%B %d, %Y')
        
        # Calculate account age in days, months, years
        account_age = datetime.utcnow() - user.created_at
        years = account_age.days // 365
        months = (account_age.days % 365) // 30
        days = account_age.days % 30
        
        account_age_str = ""
        if years > 0:
            account_age_str += f"{years} year{'s' if years > 1 else ''}"
        if months > 0:
            if account_age_str:
                account_age_str += ", "
            account_age_str += f"{months} month{'s' if months > 1 else ''}"
        if days > 0 or not account_age_str:
            if account_age_str:
                account_age_str += ", "
            account_age_str += f"{days} day{'s' if days != 1 else ''}"
        
        # Update transaction count
        transaction_count = Transaction.query.filter_by(user_id=user_id).count()
        user.transaction_count = transaction_count
        db.session.commit()
        
        # Format user profile for response
        profile_data = {
            'id': user.id,
            
            'member_since': member_since,  # This is the key field
            'account_age': account_age_str,
            'created_at': user.created_at.isoformat(),
            'security_score': user.security_score,
            'transaction_count': transaction_count,
            'verification_status': user.verification_status,
            'last_login': user.last_login.isoformat() if user.last_login else None
        }
        
        return jsonify({
            'status': 'ok',
            'profile': profile_data,
            'activities': activities_data
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
# Initialize database











    

if __name__ == '__main__':

    app.run(debug=True)

 
