import base64
import json
import math
import urllib3
from flask import Flask, make_response, redirect, render_template, request, Response
from random import random
from urllib.parse import urlencode

app = Flask(__name__)
client_id = 'client_id'
client_secret = 'client_secret'
redirect_uri = 'http://localhost:8888/callback'


def generate_state(length):
    text = ''
    chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    for i in range(length):
        text += chars[math.floor(random() * len(chars))]
    return text


def encode_client_id_and_secret():
    string_to_encode = client_id + ':' + client_secret
    bytes = string_to_encode.encode('ascii')
    b64 = base64.b64encode(bytes)
    return b64.decode('ascii')


def get_access_and_refresh_tokens(code):
    http = urllib3.PoolManager()
    response = http.request('POST', 'https://accounts.spotify.com/api/token',
                            headers={
                                'Authorization': 'Basic ' + encode_client_id_and_secret(),
                                'Content-Type': 'application/x-www-form-urlencoded'
                            },
                            body=urlencode({
                                'code': code,
                                'redirect_uri': redirect_uri,
                                'grant_type': 'authorization_code'
                            }))
    body = json.loads(response.data.decode('utf-8'))
    return body['access_token'], body['refresh_token']


def get_user_info(access_token, refresh_token):
    http = urllib3.PoolManager()
    response = http.request('GET', 'https://api.spotify.com/v1/me',
                            headers={
                                'Authorization': 'Bearer ' + access_token,
                            })
    if response.status == 200:
        return json.loads(response.data.decode('utf-8'))


@app.route("/")
def home():
    return render_template('index.html')


@app.route("/login")
def login():
    state = generate_state(32)
    scope = 'user-read-private user-read-email'
    query = {'response_type': 'code',
             'client_id': client_id,
             'scope':  scope,
             'redirect_uri': redirect_uri,
             'state': state}
    resp = make_response(
        redirect('https://accounts.spotify.com/authorize?'+urlencode(query)))
    resp.set_cookie('state', state)
    return resp


@app.route("/callback")
def callback():
    state_cookie = request.cookies.get('state')
    state = request.args.get('state')
    if state_cookie != state:
        return Response('', status=403)
    access_token, refresh_token = get_access_and_refresh_tokens(
        request.args.get('code'))
    resp = make_response(redirect('/logged'))
    resp.delete_cookie('state')
    resp.set_cookie('access_token', access_token)
    resp.set_cookie('refresh_token', refresh_token)
    return resp


@app.route("/logged")
def logged():
    access_token = request.cookies.get('access_token')
    refresh_token = request.cookies.get('refresh_token')
    info = get_user_info(access_token, refresh_token)
    return render_template('logged.html', user_info=info)


if __name__ == '__main__':
    app.run('0.0.0.0', port=8888)
