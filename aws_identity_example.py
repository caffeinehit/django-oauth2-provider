import os
import sys
import json

from datetime import datetime
from urllib import request, error
import requests

import boto3
# aws-v4-signature==2.0
from awsv4sign import generate_http11_header

service = 'sts'
region = 'us-west-2'

session = boto3.Session()
creds = session.get_credentials()
access_key = creds.access_key
secret_key = creds.secret_key
session_token = creds.token

print(f"access_key: {access_key[:10]}<redacted...>")
print(f"secret_key: {secret_key[:10]}<redacted...>")
print(f"session_token: {session_token[:20]}<redacted...>")
print(f"profile: {os.environ.get('AWS_PROFILE')}")

url = 'https://sts.{region}.amazonaws.com/'.format(region=region)
httpMethod = 'post'
canonicalHeaders = {
    'host': f'sts.{region}.amazonaws.com',
    'x-amz-date': datetime.utcnow().strftime('%Y%m%dT%H%M%SZ'),
    'content-type': 'application/x-www-form-urlencoded; charset=utf-8',
}
if session_token:
    canonicalHeaders['x-amz-security-token'] = session_token

payload_str = "Action=GetCallerIdentity&Version=2011-06-15"

headers = generate_http11_header(
    service, region, access_key, secret_key,
    url, 'post', canonicalHeaders, {},
    '', payload_str
)

token_request_args = {
    "grant_type": "aws_identity",
    "region": region,
    "post_body": payload_str,
    "headers_json": json.dumps(headers),
}
print(payload_str)
print(json.dumps(headers, indent=4))

req = request.Request("https://sts.us-west-2.amazonaws.com/", data=payload_str.encode('utf-8'), headers=headers, method='POST')
try:
    response = request.urlopen(req)
    print(f"Local request test result: {response.read()}")
except error.HTTPError as e:
    print(f"HTTPError: {e}: {e.fp.read()}")
    sys.exit(1)

print("Attempting access_token grant request with same signed request:\n")

token_response = requests.post("http://localhost:8000/oauth2/access_token",
                               data=token_request_args)
token_info = token_response.json()

print(token_info)
