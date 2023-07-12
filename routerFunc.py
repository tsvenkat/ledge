import os
import re
from urllib.parse import urlencode
import boto3
import uuid
import jwt
from jwt import PyJWKClient
from botocore.exceptions import ClientError


JWKS_URL = "https://sso.common.cloud.hpe.com/pf/JWKS"
COM_CLUSTER_2_ORIGIN = "qa.rugby.hpeserver.management"
APP_INST_ID = "5cf16eff-d5c5-42d6-b791-1d694e9a400f"

'''
Make use of the customer_id value that is passed by the authorizer
to identify the appropriate target COM cluster url.
Build a redirect url using this and return to the caller with a
redirect response.
Note: Cloud Front will make a new request to the Origin *after*
this function returns. Hence it is important that this function
completes quickly to avoid any latency.
'''
def handler(event, context):
    print(f"REQUEST EVENT: {event}")
    request = event["Records"][0]['cf']['request']
    headers = request['headers']

    response = {}

    # Get token from the header
    token_header = headers['authorization'][0]['value']
    token = parse_auth_token(token_header)

    # Authenticate and get claims from the token
    claims, err = get_claims_from_token(token)
    key = 'user_ctx'
    if err or key not in claims:
        print(f"Unable to get claims from token. Error: {err}")
        response['status'] = 401
        response['statusDescription'] = 'Unauthorized'
        return response

    # Get customer id from the token claims
    customer_id = claims[key]

    # Get the COM cluster origin for the customer id
    # Lookup the customer_id in our database
    base_url, err = get_cluster_base_url_from_db(customer_id)
    if err:
        print(f"Unable to get COM base url from db for customer id: {customer_id}")
        response['status'] = 403
        response['statusDescription'] = 'Forbidden'
        return response

    if base_url is None:
        # Update the host/origin
        # hard coding this for now for testing
        com_host = COM_CLUSTER_2_ORIGIN
    else:
        com_host = base_url

    request['origin']['custom']['domainName'] = com_host
    headers['host'] = [{'key':'host', 'value': com_host}]

    # route the caller
    return request

def get_cluster_base_url_from_db(customer_id):
    base_url = None
    err = None

    try:
        # Get the table first
        table = dynamo_table()
        db_response = table.get_item(
            Key={
                'customer_id': customer_id
            }
        )
        # TODO: this check may be removed in favor of handling the
        #       ClientError exception
        if not 'Item' in db_response:
            print(f"Customer {customer_id} not found in DB")
        else:
            data = db_response["Item"]
            base_url = data["com_base_url"]
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
          print(f"DB Exception: Customer {customer_id} not found in DB")
          err = None
        else:
          err = e
    except Exception as e:
        print(f"Error looking up database: {e}")
        err = e

    return base_url, err

def put_cluster_base_url_in_db(customer_id, base_url):
    err = None
    try:
        # Get the table first
        table = dynamo_table()
        table.put_item(
            Item={
                'customer_id': customer_id,
                'com_base_url': base_url
            }
        )
        # status code is in response['ResponseMetadata']['HTTPStatusCode']
    except Exception as e:
        print(f"Error putting item for customer {customer_id} to database: {e}")
        err = e

    return err

'''
Get access to the underlying DB table
'''
def dynamo_table():
    table_name = os.environ.get("DYNAMODB_TABLE", "gel-dev")
    region = os.environ.get("REGION", "us-west-2")

    ddb = boto3.resource("dynamodb", region_name=region)
    return ddb.Table(table_name)

'''
Skip the "Bearer " prefix and extract the token from the token_header
'''
def parse_auth_token(token_header):
    return re.sub('^bearer ', '', token_header, flags=re.IGNORECASE)

def get_claims_from_token(token):
    claims = None
    err = None

    claims, err = decode_token(token)
    if err is None:
        print(f"Request from user[{claims['givenName']} {claims['lastName']}]")

    return claims, err

def decode_token(token):
    err = None
    client = PyJWKClient(JWKS_URL)
    claims = {}

    try:
        pub_key = client.get_signing_key_from_jwt(token).key
        claims = jwt.decode(token, pub_key, algorithms=["RS256"], audience="aud")
        client_id = claims.get('client_id')
        if not client_id or client_id != APP_INST_ID:
            err = ValueError(f"Invalid app instance id: {client_id}")
    except Exception as e:
        print("The provided token is invalid!")
        print(f"Error: {e}")
        err = e

    return claims, err
