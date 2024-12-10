LOG_LEVEL="DEBUG"

# Default is true if not set here. To not verify ssl set to "false"
VERIFY_SSL="true"

# Optional to restrict origins. If not provided (commented out) or empty, will use "*" for the origin
CORS_ORIGINS=[""] 

 # in minutes
APP_SESSION_TIMEOUT = 90

# For managing sessions across multiple web server workers. Should be 64 characters
APP_SECRET_KEY = ""

APP_REDIRECT_URI = "http://localhost:5000/callback"
APP_LOGOUT_URI = "http://localhost:5000"

# Entra ID
IDP_DOMAIN="login.microsoftonline.com"
IDP_CLIENT_ID=""
IDP_CLIENT_SECRET=""
TENANT_ID=""
IDP_ISS = f"/{TENANT_ID}/v2.0" 
IDP_AUTH = f"/{TENANT_ID}/oauth2/v2.0/authorize"
IDP_TOKEN = f"/{TENANT_ID}/oauth2/v2.0/token"
IDP_LOGOUT = f"/{TENANT_ID}/oauth2/v2.0/logout"
IDP_USERINFO_URI = "https://graph.microsoft.com/oidc/userinfo"
APP_SCOPES = "openid email profile offline_access User.Read"

# Okta
# IDP_DOMAIN=""
# IDP_CLIENT_ID=""
# IDP_CLIENT_SECRET=""
# IDP_ISS="/oauth2/default" 
# IDP_AUTH="/oauth2/default/v1/authorize"
# IDP_TOKEN="/oauth2/default/v1/token"
# IDP_LOGOUT="/oauth2/default/v1/logout"
# IDP_USERINFO="/oauth2/default/v1/userinfo"
# IDP_USERINFO_URI = f"https://{IDP_DOMAIN}{IDP_USERINFO}"
# APP_SCOPES = "openid email profile offline_access"

IDP_AUTH_URI = f"https://{IDP_DOMAIN}{IDP_AUTH}"
IDP_ISSUER = f"https://{IDP_DOMAIN}{IDP_ISS}" 
IDP_TOKEN_URI = f"https://{IDP_DOMAIN}{IDP_TOKEN}"
IDP_LOGOUT_URI = f"https://{IDP_DOMAIN}{IDP_LOGOUT}"