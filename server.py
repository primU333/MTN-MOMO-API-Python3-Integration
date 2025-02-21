from flask import Flask, request, jsonify, render_template
import requests
import json
import base64
import time
import uuid
import datetime
import hashlib
from connections import *

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html') 


sub_key = 'a0932d27db834ecb8d2a1360d9fceac3'
apiKey = '0bed473d3e804f4e95020784be603395'
apiUser = 'a524f270-6106-4ada-8ef7-1f96a9c89ffb'
uuid_ = '97f88bc9-749a-4f0b-8697-76ed8e8f6a29'


def ApiUser():
    user_uuid = str(uuid.uuid4())
    return user_uuid

def encode_token():
    txt = "{}:{}".format(apiUser, apiKey)
    encodedBytes = base64.b64encode(txt.encode("utf-8"))
    encodedStr = str(encodedBytes, "utf-8")
    return encodedStr


def generate_token():

    url = 'https://sandbox.momodeveloper.mtn.com/collection/token'
    # auth_header = base64.b64encode(f"{API_USER}:{API_KEY}".encode()).decode()
    auth_header = encode_token()

    headers = {
        'Ocp-Apim-Subscription-Key':  '88bfca8c2e1e4169b3e89c74cc34af01',
        'Authorization': 'Basic {}'.format(auth_header)
        # 'X-Target-Environment' : 'sandbox'
    }
    data = ""

    response = requests.request('POST', url, headers=headers, data=data)
    
    print('res', response)

    if response.status_code == 200:
        return response.json()['access_token']

    else:
        print(response.text)
        raise Exception(f"Failed to generate token: {response.text}")


@app.route('/test-paying', methods=['POST'])
def handle():
    try:
        api_user = ApiUser()
       
        # response = createApiUser(api_user, sub_key)
        # response = getCreatedUser(uuid_)
        response = checkAccountBalance(sub_key)
       
        print(response) #Print the error for debugging
        return jsonify({"status": "failed", "message": f"{response}"}), response

    except Exception as e:
        print(f"An error occurred: {e}") # Print the error for debugging
        return jsonify({"status": "failed", "message": "An error occurred"}), 500




if __name__ == '__main__':
    app.run(debug=True)



