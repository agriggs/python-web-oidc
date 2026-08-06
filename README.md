# Simple Python Flask App for Testing OIDC

Works for Entra ID and Okta 
- Entra ID: https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc
- Okta: https://developer.okta.com/docs/guides/sign-into-web-app-redirect/python/main/

## Setup

This project uses [uv](https://docs.astral.sh/uv/) for dependency management.

```bash
uv sync
cp sample_env.py _env.py  # then fill in your IdP settings
uv run flask run --host=0.0.0.0 -p 5000
```