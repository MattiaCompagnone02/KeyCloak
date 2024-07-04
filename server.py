import json
import os
from urllib.parse import urlencode, quote_plus

from flask import Flask, render_template, url_for, session, abort, redirect
from authlib.integrations.flask_client import OAuth
import json
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

appConf = {
    "OAUTH2_CLIENT_ID": os.getenv("OAUTH2_CLIENT_ID"),
    "OAUTH2_CLIENT_SECRET": os.getenv("OAUTH2_CLIENT_SECRET"),
    "OAUTH2_ISSUER": os.getenv("OAUTH2_ISSUER"),
    "FLASK_SECRET": os.getenv("FLASK_SECRET"),
    "FLASK_PORT": os.getenv("FLASK_PORT"),
}


app.secret_key = appConf["FLASK_SECRET"]
oauth = OAuth(app)
oauth.register(
    name="myApp",
    client_id=appConf.get("OAUTH2_CLIENT_ID"),
    client_secret=appConf.get("OAUTH2_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid email profile",
        "code_challenge_method": "S256", #enable PKCE
    },
    server_metadata_url=f'{appConf.get("OAUTH2_ISSUER")}/.well-known/openid-configuration',
)


@app.route("/")
def home():
    return render_template("home.html", session=session.get("user"), pretty=json.dumps(session.get("user"), indent=4))


@app.route("/callback")
def callback():
    token = oauth.myApp.authorize_access_token()
    session["user"] = token
    return redirect(url_for("home"))


@app.route("/login")
def login():
    if "user" in session:
        abort(404)
    return oauth.myApp.authorize_redirect(redirect_uri=url_for('callback', _external=True))


@app.route("/loggedout")
def loggedout():
    if "user" in session:
        abort(404)
    return redirect(url_for('home'))


@app.route("/logout")
def logout():
    id_token = session["user"]["id_token"]
    session.clear()
    return redirect(
        appConf.get("OAUTH2_ISSUER")
        + "/protocol/openid-connect/logout?"
        + urlencode(
            {
                "post_logout_redirect_uri": url_for('loggedout', _external=True),
                "id_token_hint": id_token
            },
            quote_via=quote_plus
        )
    )


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=3000, debug=True)
