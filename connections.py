import requests
from flask import jsonify

def createApiUser(uuid, subKey):
    headers = {
        'X-Reference-Id' : uuid,
        'Ocp-Apim-Subscription-Key' : subKey,
        'Content-Type' :'Application/json'
    }
    
    body = {
        'providerCallbackHost' : 'https://af81-41-210-155-119.ngrok-free.app'
    }
    
    endpoint = 'https://sandbox.momodeveloper.mtn.com/v1_0/apiuser'
    
    response = requests.post(endpoint, headers=headers, data=body)
    print('Res', response.json())
    if response.json()['statusCode'] == 201:
        return 'Created Successfully'
    else:
        return f"{response.json()['statusCode']}, {response.json()['message']}"
    
    
    
def getCreatedUser(uuid):
    
    headers = {
        'X-Reference-Id' : uuid,
        'Ocp-Apim-Subscription-Key' : 'key'
    }
    
    endpoint = f'https://sandbox.momodeveloper.mtn.com/v1_0/apiuser/{uuid}'
    response = requests.post(endpoint, headers)

    if response.json()['statusCode'] == 201:
        return 'Created Successfully'
    else:
        return f"{response.json()['statusCode']}, {response.json()['message']}"


def getApiKey(apiuser):
    
    headers = {
        'X-Reference-Id' : 'uuid',
        'Ocp-Apim-Subscription-Key' : 'key'
    }
    
    endpoint = f'https://sandbox.momodeveloper.mtn.com/v1_0/apiuser/{apiuser}/apikey'

    response = requests.post(endpoint, headers)
    if response.status_code == 201:
        return response.apiKey
    else:
        return f'{response.status_code}, {response.text}'


def GenerateAPiToken(SubKey):
    headers = {
        'Authorization' : 'Basic {}',#Base64 encoded keys
        'Ocp-Apim-Subscription-Key' : SubKey
    }
    
    body = {
        
    }
    
    endpoint = 'https://sandbox.momodeveloper.mtn.com/collection/token/'
    response = requests.post(endpoint, headers, body)
    
    if response.status_code == 201:
        return response.access_token
    else:
        return f'{response.status_code}, {response.text}'
        

def requestPayment():
    headers = {
        'X-Reference-Id' : 'uuid',
        'X-Target-Environment' : 'sandbox',
        'Ocp-Apim-Subscription-Key' : 'key',
        'Content-Type' : 'Application/json'
    }
    
    body = {
        "amount": "5.0",
        "currency": "EUR",
        "externalId": "6353636",
        "payer": {
            "partyIdType": "MSISDN",
                "partyId": "+256782607681"
                },
        "payerMessage": "Pay for product",
        "payeeNote": "payer note"
    }
    
    endpoint = 'https://sandbox.momodeveloper.mtn.com/collection/v1_0/requesttopay'
    
    response = requests.post(endpoint, headers, body)
    
    if response.status_code == 201:
        return response
    else:
        return f'{response.status_code}, {response.text}'
        
        
def getTransactionStatus(transId):
	headers = {
	    'Ocp-Apim-Subscription-Key' : 'key',
	    'X-Target-Environment' : 'sandbox',
	    'X-Reference-Id' : 'api_user'
	}
	
	body = {
	    
	}
	
	endpoint = f'https://sandbox.momodeveloper.mtn.com/collection/v1_0/requesttopay/{transId}'
	
	response = requests.get(endpoint, headers, body)
	
	return response
	


def checkAccountStatus(mssdn):
    headers = {
        'X-Reference-Id' : 'api_user',
        'Ocp-Apim-Subscription-Key' : 'key',
        'X-Target-Environment' : 'sandbox'
    }
    
    endpoint = f'https://sandbox.momodeveloper.mtn.com/collection/v1_0/accountholder/msisdn/{mssdn}/active?'
    
    response = requests.get(endpoint, headers)
    
    return response
    
    
def checkAccountBalance(subKey):
    headers = {
        'Ocp-Apim-Subscription-Key' : subKey,
        'X-Target-Environment': 'sandbox',
        'Content-Type' : 'Application/json'
    }
    
    endpoint = 'https://sandbox.momodeveloper.mtn.com/collection/v1_0/account/balance'
    
    response = requests.get(endpoint, headers=headers)
    
    return response.json()