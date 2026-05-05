import requests

def invoke_api(endpoint, method, header=None, payload=None):
    if method == 'GET':
        if header:
            response = requests.get(endpoint, headers=header)
        else:
            response = requests.get(endpoint)
        return response
    if method == 'PUT':
        if header:
            response = requests.put(endpoint, headers=header)
        else:
            response = requests.put(endpoint)
        return response
    # TBD : Other request methods