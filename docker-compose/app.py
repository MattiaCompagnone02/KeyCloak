import os
import time
import jwt
from flask import Flask, session, abort, redirect, request, jsonify
import requests
from dotenv import load_dotenv
import urls

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
appConf = {
    "CLIENT_ID": os.getenv("CLIENT_ID"),
    "CLIENT_SECRET": os.getenv("CLIENT_SECRET"),
}


def decode_token(token):
    return jwt.decode(token, verify=False)


def is_token_expired(payload):
    current_time = int(time.time())
    return payload['exp'] < current_time


def refresh_token(refresh_token):
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": appConf["CLIENT_ID"],
        "client_secret": appConf["CLIENT_SECRET"]
    }
    response = requests.post(urls.tokenEndpoint, data=data)
    return response.json()


@app.route("/callback")
def callback():
    code = request.args.get("code")
    if code is None:
        abort(400)
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": appConf.get("CLIENT_ID"),
        "client_secret": appConf.get("CLIENT_SECRET"),
        "redirect_uri": urls.callbackEndpoint,
    }
    response = requests.post(urls.tokenEndpoint, data=data)

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
    params = {
        'client_id': appConf.get("CLIENT_ID"),
        'response_type': 'code',
        'scope': 'openid',
        'redirect_uri': urls.callbackEndpoint
    }
    return redirect(
        f"{urls.authEndpoint}?client_id={params['client_id']}&response_type={params['response_type']}&scope={params['scope']}&redirect_uri={params['redirect_uri']}")


@app.route("/token", methods=['POST'])
def token():
    username = request.json.get("username")
    password = request.json.get("password")
    data = {
        "grant_type": "password",
        "username": username,
        "password": password,
        "client_id": appConf.get("CLIENT_ID"),
        "client_secret": appConf.get("CLIENT_SECRET"),
    }
    response = requests.post(urls.tokenEndpoint, data=data)
    return jsonify(response.json())


@app.route("/protected)", methods=['POST'])
def protected():
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Missing authorization header"}), 401
    try:
        token_type, access_token = auth_header.split()
        if token_type != "Bearer":
            return jsonify({"error": "Invalid token type"}), 401
    except ValueError:
        return jsonify({"error": "Invalid authorization header format"}), 401

    payload = decode_token(access_token)
    if is_token_expired(payload):
        refresh_token_value = request.json.get("refresh_token")
        if not refresh_token_value:
            return jsonify({"error": "Refresh token missing"}), 401

        tokens = refresh_token(refresh_token_value)
        if "access_token" in tokens:
            access_token = tokens["access_token"]
            refresh_token_value = tokens["refresh_token"]
            return jsonify({
                "message": "Access token refreshed",
                "access_token": access_token,
                "refresh_token": refresh_token_value
            })
        else:
            return jsonify({"error": "Refresh token missing"}), 401
    else:
        return jsonify({"message": "Valid access token"})


@app.route("/logout")
def logout():
    session.clear()
    return redirect('/login')


if __name__ == '__main__':
    app.run(debug=True)
