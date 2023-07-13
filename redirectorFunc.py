import os
from urllib.parse import urlencode
import boto3

'''
Make use of the customer_id value that is passed by the authorizer
to identify the appropriate target COM cluster url.
Build a redirect url using this and return to the caller with a
redirect response.
'''
def handler(event, context):
    print(f"REQUEST EVENT: {event}")
    customer_id = event['requestContext']['authorizer'].get('customer_id')
    requested_app_inst_id = event['requestContext']['authorizer'].get('app_inst_id')
    authorized_app_inst_id = event['stageVariables']['app_inst_id']
    client_cert = event['requestContext']['identity']['clientCert']

    status_unauthorized = {"statusCode": 403}

    if not customer_id:
        # this should not happen. The authorizer should find and inject
        # the customer_id for us.
        print(f"Error: customer_id is missing in the requestContext")
        return status_unauthorized

    # check if caller is authorized to use this COM app instance
    if requested_app_inst_id != authorized_app_inst_id :
        print (f"Error: Caller[{customer_id}] is not authorized to access this app instance!")
        return status_unauthorized

    # Lookup the customer_id in our database
    base_url, err = get_cluster_base_url_from_db(customer_id)
    if err:
        print(f"Unable to get COM base url from db for customer id: {customer_id}")
    else:
        # if there is no base url in db for this customer yet
        if not base_url:
            # Let's use the default one
            base_url = event['stageVariables']['default_cluster_base_url']
            # and also add this to the DB
            err = put_cluster_base_url_in_db(customer_id, base_url)
            if err:
                print(f"Error assigning cluster for customer {cusomter_id} in DB! Error: {err}")

    redirect_url = base_url + event["path"]
    queryStringParams = event["queryStringParameters"]
    if queryStringParams:
        redirect_url = f"{redirect_url}?{urlencode(queryStringParams)}"

    print (f"Redirect url: {redirect_url}")

    response = {}
    response["statusCode"] = 302
    response["headers"] = {}
    #response["headers"].update(event["headers"])
    response["headers"]["Location"] = redirect_url

    # redirect the caller
    return response

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
        if not 'Item' in db_response:
            print(f"Customer {customer_id} not found in DB")
        else:
            data = db_response["Item"]
            base_url = data["com_base_url"]
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
    table_name = os.environ.get("DYNAMODB_TABLE", "gels-dev")
    region = os.environ.get("REGION", "us-west-2")

    ddb = boto3.resource("dynamodb", region_name=region)
    return ddb.Table(table_name)
