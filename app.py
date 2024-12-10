import os, logging, json

from flask import Flask
from flask import jsonify
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect, generate_csrf

from _env import *

logging.basicConfig(level=LOG_LEVEL)

logging.info("Env Var LOG_LEVEL = " + LOG_LEVEL)

app = Flask(__name__) 

app.config['SECRET_KEY'] = APP_SECRET_KEY
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "main.login"

db = SQLAlchemy()
from models.user import User
with app.app_context():
    db.init_app(app)
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    # since the user_id is just the primary key of our user table, use it in the query for the user
    return User.get(user_id)

csrf = CSRFProtect(app)
csrf.init_app(app)

@app.route("/get_csrf_token", methods=["GET"])
def get_csrf_token():
    csrf_token = generate_csrf()
    return jsonify({'csrf_token': csrf_token})

@app.after_request
def after_reqeust(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    
    if "CORS_ORIGINS" in os.environ:
        cors_origins = json.loads(os.environ["CORS_ORIGINS"])
        for origin in cors_origins:
            response.headers.add("Access-Control-Allow-Origin", origin) 
    else:
        response.headers.add("Access-Control-Allow-Origin", "*") 

    return response

# blueprint for non-auth parts of app
from main import main as main_blueprint
app.register_blueprint(main_blueprint)