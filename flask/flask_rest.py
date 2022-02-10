#!/usr/bin/python3.6
#-*- coding: utf-8 -*-
from eth_account import Account
from flask import Flask, request, abort, jsonify, make_response
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
import subprocess , shlex
import time
import traceback
import secrets
import random
import string
import json
#from flask_limiter import Limiter
#from flask_limiter.util import get_remote_address

app = Flask(__name__)
auth = HTTPBasicAuth()
auth_users = {
    "igor": generate_password_hash("1234567891011_gala_3003.%3444"),
    "mrwh0": generate_password_hash("1234567891011_gala_3003.%3443")
}
@auth.verify_password
def verify_password(username, password):
    if username in auth_users:
        return check_password_hash(auth_users.get(username), password)
    return False

def NewAccount(userId):
    acct       = Account.create('goodEntropyherealwaysgood')
    priv_key   = acct.privateKey
    v3KeyStore = Account.encrypt(priv_key.hex(), password = '123456')
    with open(f'./data/keys/{v3KeyStore["address"]}.key', 'w') as f:
        f.write(json.dumps(v3KeyStore))
    toml = f'[metadata]\nuser = "{userId}"\n\n[signing]\ntype = "file-based-signer"\nkey-file = "./keys/{v3KeyStore["address"]}.key"\npassword-file = "passwordFile"'
    with open(f'./data/{v3KeyStore["address"]}.toml', 'w') as f:
        f.write(toml)
    return f'0x{v3KeyStore["address"]}'



@app.route("/", methods=['POST'])
@auth.login_required
def inbound():
    current_time = time.localtime()
    localtime    = time.strftime('%d%b%H:%M:%S', current_time)
    try:
        user    = request.json['user']
        address = NewAccount("user123456")
        print(str(localtime), user,address, file=open("./rest.log", "a"))
        return jsonify(address=address, user=user),200
    except:
        print(str(localtime),request.form, request.json, traceback.format_exc() ,file=open("./rest.log", "a"))
        abort(make_response(jsonify(message="Internal Error"), 500))

if __name__ == "__main__":
   app.run(host='0.0.0.0', port=5080,debug = False)

