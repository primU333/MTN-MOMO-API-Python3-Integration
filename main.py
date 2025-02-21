from flask import Flask, request, jsonify, render_template
import requests
import json
import base64
import time
import uuid
import datetime
import hashlib

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



def createApiUser():
    api_user = ApiUser()
    print('api', api_user)

    url = 'https://sandbox.momodeveloper.mtn.com/v1_0/apiuser'

    headers = {
        'X-Reference-Id' : api_user,
        'Ocp-Apim-Subscription-Key' : sub_key
        # 'X-Target-Environment' : 'sandbox'
    }

    data = {
        'providerCallbackHost' : "https://c7b1-41-210-141-111.ngrok-free.app"
    }

    response = requests.request('POST', url, headers=headers, data=data)
    if response.status_code == 201:
        print('User created Successfully..')
        return api_user
    else:
        return None




def createApiKey():
    api_user = createApiUser()
    print('api', api_user)

    if api_user:

        url = f'https://sandbox.momodeveloper.mtn.com/v1_0/apiuser/{api_user}/apikey'

        headers = {
            'X-Reference-Id' : api_user,
            'Ocp-Apim-Subscription-Key' : sub_key
            # 'X-Target-Environment' : 'sandbox'
        }

        data = {
            'providerCallbackHost' : "https://c7b1-41-210-141-111.ngrok-free.app"
        }

        response = requests.request('POST', url, headers=headers, data=data)
        if response.status_code == 201:
            api_key = response.json()['apiKey']
            return api_key
        else:
            return response
    else:
        return 'API User was not created successfully'




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



def encode_token():
    txt = "{}:{}".format(API_USER, API_KEY)
    encodedBytes = base64.b64encode(txt.encode("utf-8"))
    encodedStr = str(encodedBytes, "utf-8")
    return encodedStr


# def requestPayment():
#     url = f'https://sandbox.momodeveloper.mtn.com/collection/v1_0/requesttopay'

#     headers = {
#         'X-Reference-Id' : apiUser,
#         'Ocp-Apim-Subscription-Key' : sub_key,
#         'X-Target-Environment' : 'sandbox'
#     }

#     data = {
#         'providerCallbackHost' : "https://c7b1-41-210-141-111.ngrok-free.app"
#     }


access_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSMjU2In0.eyJjbGllbnRJZCI6ImE1MjRmMjcwLTYxMDYtNGFkYS04ZWY3LTFmOTZhOWM4OWZmYiIsImV4cGlyZXMiOiIyMDI1LTAyLTEzVDEyOjMzOjA0LjA1MCIsInNlc3Npb25JZCI6IjVkODRmMzg1LTE1MWEtNGI2YS04YWM5LTMyZThkNmVhYzZlNyJ9.IqcInovVi8J6-V_ku3TkHydOAfeYxneF9nWP99vsHfRJR_xI3VWBeeoP3E8K3F__W66PNIqZm4UwmtjLdgPKjtWR-dRlI8yoyK29UsTb48OLmlbUuO1AAOjZLlPSoHi4_0goED-RGurrOo6DMoMZtALAMBEhPsKXk2j1aKve7dKRRt76yLABqKy2Xe2-v6OWT-55-AhOugePVCHyTY4L2eJLyJZtzFHzmHQ5d_spyj0dk4Ss8DCNfBzN4JOtdeQZr484PkNjU_afM8oww4tv848UJictVoimBfQWjkrGpm9SnMBupsEuJ5JLvkx2Uw8Z-KXIEObtmWAtqA768cLLBA'


BASE_URL = 'https://sandbox.momodeveloper.mtn.com/v1_0'

@app.route('/test-paying', methods=['POST'])
def authorize_payment():
    """Authorize a payment request."""
    # print('startin to authorize')
    # try:
    #     token = generate_token()
    #     print('token', token)

    # except Exception as e:
    #     return jsonify({"error": str(e)}), 500

    url = f"{BASE_URL}/v1_0/requesttopay"
    
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json',
        'X-Reference-Id': ApiUser,  # Unique reference ID
        'X-Target-Environment': 'sandbox'  # Change to 'production' in production
    }

    payment_data = {
        "amount": request.json.get("amount"),
        # "currency": request.json.get("currency", "UGX"),
        "currency": 'UGX',
        "externalId": str(int(time.time())),
        "payer": {
            "partyIdType": "MSISDN",
            "partyId": request.json.get("phoneNumber")
        },
        "payee": {
            "partyIdType": "MSISDN",
            # "partyId": request.json.get("phoneNumber")
            "partyId": "+256704809826"
        },
        "payerMessage": request.json.get("payer_message", "Payment for services"),
        "payeeMessage": request.json.get("payee_message", "Payment received")
    }

    try:
        response = requests.post(url, headers=headers, data=json.dumps(payment_data))
        response_data = response.json()
        
        if response.status_code == 202:  # Accepted
            return jsonify({"message": "Payment authorized successfully", "data": response_data}), 202
        else:
            return jsonify({"error": response_data.get("message", "Failed to authorize payment")}), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    


@app.route('/create_invoice', methods=['POST'])
def create_invoice():
    """Create an invoice."""
    try:
        token = generate_token()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    url = f"{BASE_URL}/v2_0/invoice"
    
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
        'X-Reference-Id': str(int(time.time())),
        'X-Target-Environment': 'sandbox'
    }

    invoice_data = {
        "amount": request.json.get("amount"),
        "currency": request.json.get("currency", "EUR"),
        "externalId": str(int(time.time())),
        "payer": {
            "partyIdType": "MSISDN",
            "partyId": request.json.get("payer_msisdn")
        },
        "payee": {
            "partyIdType": "MSISDN",
            "partyId": request.json.get("payee_msisdn")
        },
        "payerMessage": request.json.get("payer_message", "Invoice for services"),
        "payeeMessage": request.json.get("payee_message", "Invoice received")
    }

    try:
        response = requests.post(url, headers=headers, data=json.dumps(invoice_data))
        response_data = response.json()
        
        if response.status_code == 201:  # Created
            return jsonify({"message": "Invoice created successfully", "data": response_data}), 201
        else:
            return jsonify({"error": response_data.get("message", "Failed to create invoice")}), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500




API_KEY = "21de1c40684144f59cb824fedcdd657a"
API_SECRET = "66bd5574e15f414995e8fbd49421287f"
SUBSCRIPTION_KEY = "21de1c40684144f59cb824fedcdd657a" #For Sandbox
CLIENT_ID = "21de1c40684144f59cb824fedcdd657a" #For Production OAuth
CLIENT_SECRET = "66bd5574e15f414995e8fbd49421287f" #For Production OAuth
ENVIRONMENT = "sandbox"  # or "production"
COLLECTION_ENDPOINT = "https://sandbox.momodeveloper.mtn.com/collection/v1_0/requesttopay"
CALLBACK_URL = "https://your-callback-url.com/callback"  # Replace with your callback URL
OAUTH_ENDPOINT = "https://sandbox.momodeveloper.mtn.com/collection/oauth2/token/"  # OAuth endpoint





def generate_reference_id():
    return str(uuid.uuid4())

def generate_authorization_header(method, path, request_body=""):
    nonce = str(uuid.uuid4())
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-1] + "Z"  # ISO 8601 format
    if ENVIRONMENT == "sandbox":
        api_user = SUBSCRIPTION_KEY
        string_to_hash = method.upper() + path + nonce + timestamp + api_user + request_body
        hashed_string = hashlib.sha256(string_to_hash.encode()).hexdigest()
        signature = base64.b64encode(hashed_string.encode()).decode()
        authorization_header = f'Basic {base64.b64encode(f"{api_user}:{signature}".encode()).decode()}'
    else: #Production OAuth
        access_token = get_access_token() #Get OAuth Token
        authorization_header = f"Bearer {access_token}"
    return authorization_header, timestamp, nonce

def get_access_token():
    # Production only: Get OAuth access token
    auth_string = f"{CLIENT_ID}:{CLIENT_SECRET}"
    base64_auth = base64.b64encode(auth_string.encode()).decode()
    headers = {
        "Authorization": f"Basic {base64_auth}",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = "grant_type=client_credentials"  # Client Credentials grant type
    response = requests.post(OAUTH_ENDPOINT, headers=headers, data=data)
    if response.status_code == 200:
        token_data = response.json()
        return token_data.get("access_token")
    else:
        print(f"OAuth Error: {response.status_code} - {response.text}")
        return None  # Or raise an exception







@app.route('/collect', methods=['POST'])
def collect_payment():
    try:
        data = request.get_json()
        amount = data.get('amount')
        phone_number = data.get('phoneNumber')  # In international format (e.g., 25677xxxxxxxx)
        currency = data.get('currency', 'UGX') #Default UGX

        reference_id = generate_reference_id()
        path = "/collection/v1_0/requesttopay"
        request_body = jsonify({
            "amount": str(amount),  # Amount as string
            "currency": currency,
            "externalId": reference_id,
            "payer": {
                "partyIdType": "MSISDN",
                "partyId": phone_number
            },
            "payerMessage": "Payment for your order",
            "payeeNote": "Thank you for your payment",
            "callbackUrl": CALLBACK_URL
        }).data.decode()

        authorization, timestamp, nonce = generate_authorization_header("POST", path, request_body)

        # print("auth header", f'Basic {base64.b64encode(f"{API_KEY}:{API_SECRET}".encode()).decode()}')

        headers = {
            'Authorization': f'Basic {base64.b64encode(f"{API_SECRET}:{API_KEY}".encode()).decode()}',
            'X-Target-Environment': ENVIRONMENT,
            'Ocp-Apim-Subscription-Key': API_KEY,
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Date': timestamp,
            'X-Correlation-ID': generate_reference_id(), #Unique ID for the request
        }


        response = requests.post(COLLECTION_ENDPOINT, headers=headers, data=request_body)

        if response.status_code == 202:  # Accepted
            return jsonify({"status": "pending", "referenceId": reference_id, "message": "Payment request sent"}), 202
        else:
            print(response.content) #Print the error for debugging
            return jsonify({"status": "failed", "message": f"{response.status_code} - {response.text}"}), response.status_code

    except Exception as e:
        print(f"An error occurred: {e}") # Print the error for debugging
        return jsonify({"status": "failed", "message": "An error occurred"}), 500


@app.route('/callback', methods=['POST'])
def callback():
    try:
        callback_data = request.get_json()
        print("Callback received:", callback_data)  # Process the callback data
        # ... your logic to update order status, etc. ...
        return jsonify({"status": "success"}), 200  # Important: Respond to the callback

    except Exception as e:
        print(f"Callback error: {e}")
        return jsonify({"status": "failed"}), 500


@app.route('/payment_status/<transaction_id>', methods=['GET'])
def get_payment_status(transaction_id):
    try:
        path = f"/collection/v1_0/requesttopay/{transaction_id}/status"  # Correct path
        authorization, timestamp, nonce = generate_authorization_header("GET", path)  # GET request
        headers = {
            'Authorization': authorization,
            'X-Target-Environment': ENVIRONMENT,
            'Accept': 'application/json',
            'Date': timestamp,
            'X-Correlation-ID': generate_reference_id(),
        }

        url = f"https://api-{ENVIRONMENT}.mtn.com{path}"  # Construct the full URL
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            payment_status = response.json()
            return jsonify(payment_status), 200
        else:
            print(f"Payment Status Error: {response.status_code} - {response.text}")
            return jsonify({"status": "failed", "message": f"Failed to get payment status: {response.status_code} - {response.text}"}), response.status_code

    except Exception as e:
        print(f"Payment Status Error: {e}")
        return jsonify({"status": "failed", "message": "An error occurred"}), 500





if __name__ == '__main__':
    app.run(debug=True)





# API_USER = eb394fe5-f2fd-43e9-a19a-cd699e026a1c

#  "apiKey": "1e2c3dc12ff54c75a7af2e1c1f58ae12"
