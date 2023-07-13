import re
import json
import os
import uuid
import jwt
from jwt import PyJWKClient

JWKS_URL = "https://sso.common.cloud.hpe.com/pf/JWKS"

'''
This authorizer can handle two types of requests:
1. TOKEN authorization requests
2. REQUEST authorization requests

For (1), the token will be treated as a GLCP issued JWT token.
The token will be validated and the claims in it are looked at
to arrive at the customer_id. The "user_ctx" claim value will
have this id.

For (2), the assumption is, the caller is using a MTLS cert
for auth. In this case, the client cert will be passed in by
API G/w. It can be parsed to obtain the serial number associated
with the calling device. Need to figure how to do this translation.
Alternatively, can also look at the x-activation-key request header
and use that as the customer_id.
'''
def handler(event, context):
    print(f"EVENT: {event}")
    print(f"INPUT CTX: {dir(context)}")
    print("Client token: " + event['authorizationToken'])
    print("Method ARN: " + event['methodArn'])

    '''
    Validate the incoming token and produce the principal user identifier
    associated with the token. This can be accomplished in a number of ways:

    1. Call out to the OAuth provider
    2. Decode a JWT token inline
    3. Lookup in a self-managed DB
    '''
    principalId = 'userA'

    '''
    You can send a 401 Unauthorized response to the client by failing like so:

      raise Exception('Unauthorized')

    If the token is valid, a policy must be generated which will allow or deny
    access to the client. If access is denied, the client will receive a 403
    Access Denied response. If access is allowed, API Gateway will proceed with
    the backend integration configured on the method that was called.

    This function must generate a policy that is associated with the recognized
    principal user identifier. Depending on your use case, you might store
    policies in a DB, or generate them on the fly.

    Keep in mind, the policy is cached for 5 minutes by default (TTL is
    configurable in the authorizer) and will apply to subsequent calls to any
    method/resource in the RestApi made with the same token.

    The example policy below denies access to all resources in the RestApi.
    '''
    tmp = event['methodArn'].split(':')
    apiGatewayArnTmp = tmp[5].split('/')
    awsAccountId = tmp[4]

    token = parse_auth_token(event['authorizationToken'])
    auth_type = event["type"]
    deny = True

    customer_id = None
    app_inst_id = None

    if auth_type == "TOKEN":
        claims, err = get_claims_from_token(token)
        if err:
            print(f"Unable to get claims from token. Error: {err}")
        else:
            customer_id = claims["user_ctx"]
            app_inst_id = claims["client_id"]
            principalId = customer_id
            deny = False
    else:
        # assume this is a request from iLO and hence only MTLS
        customer_id, err = get_customer_id_from_cert(client_cert, event)
        if err:
            print(f"Unable to get customer id from client certificate. Error: {err}")
        else:
            principalId = customer_id
            deny = False

    context = {}
    if not deny:
        context["customer_id"] = customer_id
        # the redirector func will validate this app inst id against the
        # actual COM region app inst id the user is allowed
        context["app_inst_id"] = app_inst_id

    policy = AuthPolicy(principalId, awsAccountId)
    policy.restApiId = apiGatewayArnTmp[0]
    policy.region = tmp[3]
    policy.stage = apiGatewayArnTmp[1]

    if deny:
        policy.denyAllMethods()
    else:
        policy.allowAllMethods()
        #policy.allowMethod(HttpVerb.GET, '/*')

    # Finally, build the policy
    authResponse = policy.build()

    # if mtls is enabled, the following will have the client certitificate
    # in javascript: event.requestContext.identity.clientCert.clientCertPem
    # in python: event['requestContext']['identity']['clientCert']['clientCertPem']


    # context['arr'] = ['foo'] <- this is invalid, APIGW will not accept it
    # context['obj'] = {'foo':'bar'} <- also invalid

    authResponse['context'] = context

    print(authResponse)
    return authResponse


class HttpVerb:
    GET = 'GET'
    POST = 'POST'
    PUT = 'PUT'
    PATCH = 'PATCH'
    HEAD = 'HEAD'
    DELETE = 'DELETE'
    OPTIONS = 'OPTIONS'
    ALL = '*'


class AuthPolicy(object):
    # The AWS account id the policy will be generated for. This is used to create the method ARNs.
    awsAccountId = ''
    # The principal used for the policy, this should be a unique identifier for the end user.
    principalId = ''
    # The policy version used for the evaluation. This should always be '2012-10-17'
    version = '2012-10-17'
    # The regular expression used to validate resource paths for the policy
    pathRegex = '^[/.a-zA-Z0-9-\*]+$'

    '''Internal lists of allowed and denied methods.

    These are lists of objects and each object has 2 properties: A resource
    ARN and a nullable conditions statement. The build method processes these
    lists and generates the approriate statements for the final policy.
    '''
    allowMethods = []
    denyMethods = []

    """Replace the placeholder value with a default API Gateway API id to be used in the policy.
    Beware of using '*' since it will not simply mean any API Gateway API id, because stars will greedily expand over '/' or other separators.
    See https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html for more details."""
    restApiId = "<<restApiId>>"

    """Replace the placeholder value with a default region to be used in the policy.
    Beware of using '*' since it will not simply mean any region, because stars will greedily expand over '/' or other separators.
    See https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html for more details."""
    region = "<<region>>"

    """Replace the placeholder value with a default stage to be used in the policy.
    Beware of using '*' since it will not simply mean any stage, because stars will greedily expand over '/' or other separators.
    See https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html for more details."""
    stage = "<<stage>>"

    def __init__(self, principal, awsAccountId):
        self.awsAccountId = awsAccountId
        self.principalId = principal
        self.allowMethods = []
        self.denyMethods = []

    def _addMethod(self, effect, verb, resource, conditions):
        '''Adds a method to the internal lists of allowed or denied methods. Each object in
        the internal list contains a resource ARN and a condition statement. The condition
        statement can be null.'''
        if verb != '*' and not hasattr(HttpVerb, verb):
            raise NameError('Invalid HTTP verb ' + verb + '. Allowed verbs in HttpVerb class')
        resourcePattern = re.compile(self.pathRegex)
        if not resourcePattern.match(resource):
            raise NameError('Invalid resource path: ' + resource + '. Path should match ' + self.pathRegex)

        if resource[:1] == '/':
            resource = resource[1:]

        resourceArn = 'arn:aws:execute-api:{}:{}:{}/{}/{}/{}'.format(self.region, self.awsAccountId, self.restApiId, self.stage, verb, resource)

        if effect.lower() == 'allow':
            self.allowMethods.append({
                'resourceArn': resourceArn,
                'conditions': conditions
            })
        elif effect.lower() == 'deny':
            self.denyMethods.append({
                'resourceArn': resourceArn,
                'conditions': conditions
            })

    def _getEmptyStatement(self, effect):
        '''Returns an empty statement object prepopulated with the correct action and the
        desired effect.'''
        statement = {
            'Action': 'execute-api:Invoke',
            'Effect': effect[:1].upper() + effect[1:].lower(),
            'Resource': []
        }

        return statement

    def _getStatementForEffect(self, effect, methods):
        '''This function loops over an array of objects containing a resourceArn and
        conditions statement and generates the array of statements for the policy.'''
        statements = []

        if len(methods) > 0:
            statement = self._getEmptyStatement(effect)

            for curMethod in methods:
                if curMethod['conditions'] is None or len(curMethod['conditions']) == 0:
                    statement['Resource'].append(curMethod['resourceArn'])
                else:
                    conditionalStatement = self._getEmptyStatement(effect)
                    conditionalStatement['Resource'].append(curMethod['resourceArn'])
                    conditionalStatement['Condition'] = curMethod['conditions']
                    statements.append(conditionalStatement)

            if statement['Resource']:
                statements.append(statement)

        return statements

    def allowAllMethods(self):
        '''Adds a '*' allow to the policy to authorize access to all methods of an API'''
        self._addMethod('Allow', HttpVerb.ALL, '*', [])

    def denyAllMethods(self):
        '''Adds a '*' allow to the policy to deny access to all methods of an API'''
        self._addMethod('Deny', HttpVerb.ALL, '*', [])

    def allowMethod(self, verb, resource):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods for the policy'''
        self._addMethod('Allow', verb, resource, [])

    def denyMethod(self, verb, resource):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods for the policy'''
        self._addMethod('Deny', verb, resource, [])

    def allowMethodWithConditions(self, verb, resource, conditions):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition'''
        self._addMethod('Allow', verb, resource, conditions)

    def denyMethodWithConditions(self, verb, resource, conditions):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition'''
        self._addMethod('Deny', verb, resource, conditions)

    def build(self):
        '''Generates the policy document based on the internal lists of allowed and denied
        conditions. This will generate a policy with two main statements for the effect:
        one statement for Allow and one statement for Deny.
        Methods that includes conditions will have their own statement in the policy.'''
        if ((self.allowMethods is None or len(self.allowMethods) == 0) and
                (self.denyMethods is None or len(self.denyMethods) == 0)):
            raise NameError('No statements defined for the policy')

        policy = {
            'principalId': self.principalId,
            'policyDocument': {
                'Version': self.version,
                'Statement': []
            }
        }

        policy['policyDocument']['Statement'].extend(self._getStatementForEffect('Allow', self.allowMethods))
        policy['policyDocument']['Statement'].extend(self._getStatementForEffect('Deny', self.denyMethods))

        return policy


'''
Skip the "Bearer " prefix and extract the token from the token_header
'''
def parse_auth_token(token_header):
    return re.sub('^bearer ', '', token_header, flags=re.IGNORECASE)


'''
To uniquely identify a customer, the caller can specify one of:
  serial numner (from MTLS, client cert claim)
  platform customer id (from JWT)

If MTLS is used, event['requestContext']['identity']['clientCert']['clientCertPem'] will have
the serialNumber in the claims. Need to figure out how to get the customer id from this sn.
Validate this: The client sends "x-activation-key" header. This is the platform customer id.

if JWT is used, from the claims, get "user_ctx". This is the customer id.

If neither MTLS nor JWT token is present, then deny with a 401.

The table has the following fields:
customer_id -> partition key
com_cluster

Given the customer_id, search for it in the DB.
If a record is found,
  * retrieve the com_cluster value
  * use that to create a base_url
Else, do the following:
  * lookup the default_com_cluster_url from stage variables
  * use that to create a base_url
  * add a record in the DB for the lookup_key using that base_url
Add base_url as the "url" field to the context map
'''

'''For now, getting this from the request header'''
def get_customer_id_from_cert(cert, event):
    customer_id = None
    err = None
    headers = event.get("headers")
    key = "x-activation-key"

    if key in headers:
        customer_id = headers.get(key)
    else:
        err = ValueError(f"Header[{key}] missing from request headers!")

    return customer_id, err

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
    except Exception as e:
        print("The provided token is invalid!")
        print(f"Error: {e}")
        err = e

    return claims, err
