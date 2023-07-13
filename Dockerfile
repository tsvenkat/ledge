FROM public.ecr.aws/lambda/python:3.10

# First, copy the dependencies list
COPY requirements.txt ${LAMBDA_TASK_ROOT}

# Next, our function files
COPY authorizerFunc.py ${LAMBDA_TASK_ROOT}
COPY redirectorFunc.py ${LAMBDA_TASK_ROOT}

# Install dependencies
RUN pip install -r requirements.txt

# Set CMD to the handler
# Note: We default to the customer authorizer, will override 
# CMD as required for other functions.
CMD [ "authorizerFunc.handler" ]
