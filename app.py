import math
import urllib3
import base64
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
    resp = make_response(redirect('https://accounts.spotify.com/authorize?'+urlencode(query)))
    resp.set_cookie('state', state)
    return resp


@app.route("/callback")
def callback():
    state_cookie = request.cookies.get('state')
    state = request.args.get('state')
    if state_cookie != state:
        return Response('', status=403)
    resp = make_response(render_template('logged.html'))
    resp.delete_cookie('state')
    http = urllib3.PoolManager()
    r = http.request('POST', 'https://accounts.spotify.com/api/token',
                 headers={
                     'Authorization': 'Basic ' + encode_client_id_and_secret()
                     })
    return resp


if __name__ == '__main__':
    app.run('0.0.0.0', port=8888)
