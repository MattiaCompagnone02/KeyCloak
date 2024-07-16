import os

from flask import Flask, session, abort, redirect, request, jsonify
import requests
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
appConf = {
    "CLIENT_ID": os.getenv("CLIENT_ID"),
    "CLIENT_SECRET": os.getenv("CLIENT_SECRET"),
    "URL": os.getenv("URL"),
    "REDIRECT_URI": os.getenv("REDIRECT_URI"),
    "LOGOUT_REDIRECT_URI": os.getenv("LOGOUT_REDIRECT_URI")
}


@app.route("/callback")
def callback():
    code = request.args.get("code")
    if code is None:
        abort(400)
    token_url = f'{appConf.get("URL")}/protocol/openid-connect/token'
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": appConf.get("CLIENT_ID"),
        "client_secret": appConf.get("CLIENT_SECRET"),
        "redirect_uri": f"{appConf.get('REDIRECT_URI')}",
    }
    response = requests.post(token_url, data=data)

    if response.status_code == 200:
        token_response = response.json()
        session["user"] = token_response.get("id_token")
        session["access_token"] = token_response.get("access_token")
        return jsonify(token_response)
    else:
        return jsonify({"error": "Can't retrieve token"}), response.status_code


@app.route("/login")
def login():
    if "user" in session:
        abort(404)
    auth_url = f'{appConf.get("URL")}/protocol/openid-connect/auth'
    params = {
        'client_id': appConf.get("CLIENT_ID"),
        'response_type': 'code',
        'scope': 'openid',
        'redirect_uri': appConf.get("REDIRECT_URI"),
    }
    return redirect(f"{auth_url}?client_id={params['client_id']}&response_type={params['response_type']}&scope={params['scope']}&redirect_uri={params['redirect_uri']}")


@app.route("/token", methods=['POST'])
def token():
    username = request.json.get("username")
    password = request.json.get("password")
    token_url = f'{appConf.get("URL")}/protocol/openid-connect/token'
    data = {
        "grant_type": "password",
        "username": username,
        "password": password,
        "client_id": appConf.get("CLIENT_ID"),
        "client_secret": appConf.get("CLIENT_SECRET"),
    }
    response = requests.post(token_url, data=data)
    return jsonify(response.json())


@app.route("/logout")
def logout():
    session.clear()
    return redirect('/login')


if __name__ == '__main__':
    app.run(debug=True)
