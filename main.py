import base64
from cgitb import reset
import hashlib
import requests
import secrets
import os
import logging
from datetime import timedelta
import jwt

from flask import Blueprint, render_template, send_from_directory, redirect, request, session, g, url_for, current_app as app, jsonify
from flask_login import current_user, login_required, login_user, logout_user
from flask_wtf.csrf import validate_csrf

from _env import *
from models.user import User

main = Blueprint('main', __name__)

@main.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("main.login"))
    return render_template("login.html", user=current_user)

@main.before_request
def before_request():
    session.permanent = True
    session_timeout = int(APP_SESSION_TIMEOUT)
    app.permanent_session_lifetime = timedelta(minutes=session_timeout)
    session.modified = True
    g.user = current_user

@main.route("/login", methods = ['GET', 'POST'])
def login():
    session['app_state'] = secrets.token_urlsafe(64)
    session['code_verifier'] = secrets.token_urlsafe(64)

    # calculate code challenge
    hashed = hashlib.sha256(session['code_verifier'].encode('ascii')).digest()
    encoded = base64.urlsafe_b64encode(hashed)
    code_challenge = encoded.decode('ascii').strip('=')

    query_params = {'client_id': IDP_CLIENT_ID,
                    'redirect_uri': APP_REDIRECT_URI,
                    'scope': APP_SCOPES,
                    'state': session['app_state'], 
                    'code_challenge': code_challenge,
                    'code_challenge_method': 'S256',
                    'response_type': 'code',
                    'response_mode': 'query'}
    
    request_uri = "{base_url}?{query_params}".format(
        base_url=IDP_AUTH_URI,
        query_params=requests.compat.urlencode(query_params)
    )

    logging.debug("Redirect to IdP")
    return redirect(request_uri)

@main.route("/callback")
def callback():
    try:       
        # For non-prod environments, can turn off SSL cert verification
        verify_ssl = True
        verify_ssl_env_var = VERIFY_SSL.lower()
        if verify_ssl_env_var == "false":
            verify_ssl = False

        logging.info(f"Verify SSL = {verify_ssl}")

        logging.debug("Callback from IdP")
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        code = request.args.get("code")
        app_state = request.args.get("state")
        if app_state != session['app_state']:
            raise Exception("The app state does not match")
        if not code:
            raise Exception(request.args.get("error_description"))
        
        logging.debug("Verified IdP state and code")

        query_params = {'grant_type': 'authorization_code',
                        'code': code,
                        'redirect_uri': APP_REDIRECT_URI,
                        'code_verifier': session['code_verifier'], 
                        }
        
        query_params = requests.compat.urlencode(query_params)
        
        logging.debug("Request token from IdP")
        exchange = requests.post(
            IDP_TOKEN_URI,
            headers=headers,
            data=query_params,
            auth=(IDP_CLIENT_ID, IDP_CLIENT_SECRET), 
            verify=verify_ssl 
        ).json()

        logging.debug(f"auth data = {exchange}")

        # Get tokens and validate
        if not exchange.get("token_type"):
           raise Exception("Unsupported token type. Should be 'Bearer'")
        access_token = exchange["access_token"]
        id_token = exchange["id_token"] # Used for logout
        
        logging.debug(f"access token from IdP: {access_token}")

        # Decode access token
        # TODO: Validate the access token
        decoded_access_token = jwt.decode(access_token, options={"verify_signature": False})
        logging.debug(f"decoded access token: {decoded_access_token}")

        logging.debug("Request user info from IdP")
        # Authorization flow successful, get userinfo and login user
        userinfo_response = requests.get(
            IDP_USERINFO_URI,
            headers={'Authorization': f'Bearer {access_token}'}, 
            verify=verify_ssl
        ).json()
        
        user_sub = userinfo_response["sub"]    
        user_email = userinfo_response.get("email", "")
        if not user_email:
            if IDP_DOMAIN == "login.microsoftonline.com":
                user_name = decoded_access_token["upn"]
            else:
                raise Exception("Okta email or username need to be defined")
        else:
            user_name = userinfo_response["email"]        

        logging.debug(f"user info from IdP: sub[{user_sub}], user_name[{user_name}], email[{user_email}]")
       
        idp_user = User(
            id=user_sub, name=user_name, email=user_email, idp_token=id_token
        )

        # Check if the user has logged in previously.
        app_user = User.get(idp_user.id)
        if not app_user:
            idp_user.initial_login()
            app_user = idp_user
            
        else:
            # There may be updates from the IdP so go with that data on the update.
            app_user.name = idp_user.name
            app_user.email = idp_user.email
            app_user.idp_token = idp_user.idp_token

            app_user.update_login()
        
        # Testing session across multiple workers.
        #logging.info(f"/authorization-code/callback: worker_pid[{os.getpid()}], {app_user}")
        
        # TODO: Add Onboarding API for checking if this id.me user is valid for our apps
        
        # Logs in the user, saves user info to DB, and stores user info in a cookie. 
        login_user(app_user) 
        
        return redirect(url_for("main.profile"))
    
    except Exception as ex:
            logging.error(f"Callback exception: {ex}")
            error_msg = str(ex)
            session["errorMsg"] = error_msg
            return redirect(url_for("main.error")) 

@main.route("/profile")
@login_required
def profile():
    try:
        logging.info(f"/profile: worker_pid[{os.getpid()}], {current_user}")

    except Exception as e:        
        logging.error(f"/profile: worker_pid[{os.getpid()}], Exception msg: " + repr(e))
       
    return render_template("profile.html", user=current_user) 

@main.route("/error", methods=['GET'])
def error():
    error_msg = session["errorMsg"] 
    session["errorMsg"] = ""       
    return render_template("error.html", errorMsg=error_msg)

@main.route('/updateprofile')
@login_required
def update_profile():
    nav_pane_pos = request.args.get("NavPanePos", None)
    high_contrast = request.args.get("HighContrast", None)
        
    current_user.update_pbi_prefs(nav_pane_pos, high_contrast)
    
    return redirect(url_for("main.dashboard")) 

@main.route('/dashboard')
@login_required
def dashboard():
    return render_template("dashboard.html", user=current_user)

@main.route('/favicon.ico', methods=['GET'])
def getfavicon():
    '''Returns path of the favicon to be rendered'''

    return send_from_directory(os.path.join(main.root_path, 'static'), 'img/favicon.ico', mimetype='image/vnd.microsoft.icon')

@main.route("/logout")
@login_required
def logout():
    
    # Get OAuth2 id_token and logout user from Identity Provider.
    id_token = current_user.idp_token
        
    main_url = url_for("main.home")

    if id_token is None: 
        return redirect(main_url)
    
    query_params = {
        'id_token_hint': id_token,
        'post_logout_redirect_uri': APP_LOGOUT_URI
    }

    request_uri = "{base_url}?{query_params}".format(
        base_url=IDP_LOGOUT_URI,
        query_params=requests.compat.urlencode(query_params)
    )
    
    logging.info(f"/logout: worker_pid[{os.getpid()}], {current_user}")

    logout_user()

    return redirect(request_uri)