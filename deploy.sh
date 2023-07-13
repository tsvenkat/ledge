#!/bin/bash
#

profile="${1-rugby}"

echo "export AWS_PROFILE=$profile"
export AWS_PROFILE=$profile
export AWS_REGION="us-west-2"

echo sls info
sls info --config serverless-redirector.yml

echo sls deploy
sls deploy --config serverless-redirector.yml || exit 1

# to list all rest-apis
#aws --profile tsv apigateway get-rest-apis
rest_api_id="$(aws --profile $profile apigateway get-rest-apis --query 'items[?name==`dev-gel-redirector`].id' --output text)"

# to list all stages for an api
#echo "Listing all stages for rest api: $rest_api_id"
#aws apigateway get-stages --rest-api-id $rest_api_id


# set the stagevariables for the dev stage
echo "Setting stage variable for dev stage for rest api with id $rest_api_id..."
echo "Setting the default target COM cluster url"
aws --profile $profile apigateway update-stage --rest-api-id $rest_api_id --stage-name 'dev' --patch-operations op=replace,path=/variables/default_cluster_base_url,value=https://us-west2.compute.cloud.hpe.com

echo "Setting the COM regional application instance id"
aws --profile $profile apigateway update-stage --rest-api-id $rest_api_id --stage-name 'dev' --patch-operations op=replace,path=/variables/app_inst_id,value="5cf16eff-d5c5-42d6-b791-1d694e9a400f"

echo Validating if the deploy went through fine...
# validate if the deploy went fine
# give few mins for the deploy to settle
sleep 5

echo curl -is https://${rest_api_id}.execute-api.us-west-2.amazonaws.com/dev/hello -H"Authorization: Bearer $token"

curl -is https://${rest_api_id}.execute-api.us-west-2.amazonaws.com/dev/hello -H"Authorization: Bearer $token"
