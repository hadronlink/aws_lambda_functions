import boto3, json

# Bedrock Runtime
bedrock_runtime = boto3.client(
    service_name="bedrock-runtime",
    region_name="us-east-1",
    #region_name="ca-central-1",
)


def respond(error, response=None):
    return {
        'statusCode': '400' if error else '200',
        'body': error.message if error else json.dumps(response),
        'headers': {
            'Content-Type': 'application/json',
        },
    }


def bedrock_translate(text_input, target_language, max_tokens=1000, temperature=0.1, top_k=250, top_p=1):
    # Model configuration
    # model_id = "anthropic.claude-3-haiku-20240307-v1:0"
    model_id = "anthropic.claude-3-5-sonnet-20240620-v1:0"
    model_id = "anthropic.claude-3-haiku-20240307-v1:0"   ################### Teste to be removed
    #model_id = "anthropic.claude-3-sonnet-20240229-v1:0"
    model_kwargs =  {
        "max_tokens": max_tokens, "temperature": temperature,
        "top_k": top_k, "top_p": top_p,
        # "stop_sequences": ["\n\nHuman"],
    }
    # Input configuration
    body = {
        "anthropic_version": "bedrock-2023-05-31",
        # "system": f"""
        #     Identify the language of the text I provide and accurately translate it into {target_language}, preserving the original text's meaning, tone, and nuances.
        #     Please maintain proper grammar, spelling, and punctuation in the translated version.
        #     As output return only the translated text, without additional information. Please do not answer any questions, just translate.
        # """,
        #"system": f"""
        #    We are on a live call with another person who does not speak the same language.
        #    Due to the language barrier, understanding each other is a challenge.
        #    Your sole function is to translate the incoming user message into the corresponding {target_language} language.
        #    As output return only the translated text, without additional information.
        #""",
        "system": f"""
            Translate the text provided to {target_language}. <Example: Tell me about you = Fale me sobre voce>. Do not say anything else, just translate. In case the language of input text is the same of the required translation, just copy and paste the input text.
        """,

        "messages": [
            {"role": "user", "content": [{"type": "text", "text": text_input}]},
        ],
    }
    body.update(model_kwargs)
    print(f'bedrock_translate body: {body}')

    # Invoke model
    response = bedrock_runtime.invoke_model(
        modelId=model_id,
        body=json.dumps(body),
    )
    print(f'bedrock_translate response: {response}')

    # Process and print the response
    response_body = json.loads(response.get("body").read())
    print(f'bedrock_translate response_body: {response_body}')

    # result = respose_body.get("content", [])[0].get("text", "")
    # print(f'bedrock_translate result: {result}')

    response['body'] = {
        "text": response_body['content'][0]['text'],
        "input_tokens": response_body['usage']['input_tokens'],
        "output_tokens": response_body['usage']['output_tokens']
    }
    print(f'final response: {response}')
    return response


def bedrock_improve_text(user_text, system_text, max_tokens=1000, temperature=1, top_k=250, top_p=1):
    # Model configuration
    model_id = "anthropic.claude-3-haiku-20240307-v1:0"
    model_kwargs =  {
        "max_tokens": max_tokens, "temperature": temperature,
        "top_k": top_k, "top_p": top_p,
        # "stop_sequences": ["\n\nHuman"],
    }
    # Input configuration
    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "system": f'{system_text} Make sure your answer is a maximum of 50 words.',
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": user_text}]},
        ],
    }
    body.update(model_kwargs)
    print(f'bedrock body: {body}')

    # Invoke model
    response = bedrock_runtime.invoke_model(
        modelId=model_id,
        body=json.dumps(body),
    )
    print(f'bedrock response: {response}')

    # Process and print the response
    response_body = json.loads(response.get("body").read())
    print(f'bedrock response_body: {response_body}')


    response['body'] = {
        "text": response_body['content'][0]['text'],
        "input_tokens": response_body['usage']['input_tokens'],
        "output_tokens": response_body['usage']['output_tokens']
    }
    return response



def handle_request(event, payload):

    try:
        print("Received event: " + json.dumps(event, indent=2))
        print(f'Event: {event}')
        resource_path = event['path']
        http_method = event['httpMethod']
        print(f'payload: {payload}')

        # RESOURCE TRANSLATE
        if resource_path == "/translate":
            if http_method == "POST":
                print('Invoke Bedrock Translate')
                response = bedrock_translate(
                    text_input=payload['text_input'],
                    target_language=payload['target_language']
                )

        # RESOURCE IMPROVE TEXT
        if resource_path == "/improve_text":
            if http_method == "POST":
                print('Invoke Bedrock Improve Text')
                response = bedrock_improve_text(
                    user_text=payload['user_text'],
                    system_text=payload['system_text']
                )

        print(f'Response: {response}')
        return respond(None, response)

    except Exception as e:
        print(f'Error: {str(e)}')
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": "Internal Server Error",
                "message": str(e)  # Mensagem da exceção para depuração
            })
        }









# import json
# import boto3
# import botocore
# import logging

# # Boto3 clients
# # bedrock_client = boto3.client('bedrock')
# bedrock_runtime_client = boto3.client(
#     service_name="bedrock-runtime",
#     region_name="us-east-1"
# )

# # Setup the logger
# logger = logging.getLogger()
# logger.setLevel(logging.INFO)

# # Constants
# MODEL_ID = "anthropic.claude-3-haiku-20240307-v1:0"
# ACCEPT = "application/json"
# CONTENT_TYPE = "application/json"
# MAX_TOKENS = 2048
# TEMPERATURE = 0.1
# TOP_K = 250
# TOP_P = 1
# STOP_SEQUENCES = ["\n\nHuman"]
# SYSTEM_ROLE = "Be honest bot"
# ANTHROPIC_VERSION = "bedrock-2023-05-31"

# # Auxiliar functions
# def respond(status_code, res=None):
#     """Constructs a standard HTTP response."""
#     return {
#         'statusCode': status_code,
#         'body': json.dumps({'error': str(status_code)}) if status_code else json.dumps(res),
#         'headers': {
#             'Content-Type': 'application/json',
#         },
#     }

# def invoke_bedrock_model(prompt):
#     """Invokes the Bedrock model with the given prompt."""
#     body = {
#         "anthropic_version": ANTHROPIC_VERSION,
#         "max_tokens": MAX_TOKENS,
#         "temperature": TEMPERATURE,
#         "top_k": TOP_K,
#         "top_p": TOP_P,
#         "stop_sequences": STOP_SEQUENCES,
#         "system": SYSTEM_ROLE,
#         "messages": [
#             {"role": "user", "content": [{"type": "text", "text": prompt}]},
#         ],
#     }
#     print(f'body: {body}')
#     response = bedrock_runtime_client.invoke_model(
#         modelId=MODEL_ID,
#         body=json.dumps(body),
#     )
#     print(f'response: {response}')
#     # Log the raw  for debugging
#     logger.info("Raw response: %s", response)

#     # Extract the result from the response
#     response_body = json.loads(response['body'])
#     if 'content' in response_body and response_body['content']:
#         result = response_body['content'][0].get('text', "")
#         return result
#     else:
#         raise ValueError("Unexpected response format: {}".format(response_body))

#     # # Extract the result from the response
#     # result = json.loads(response['body']).get("content", [])[0].get("text", "")
#     # return result

# # Main function
# def lambda_handler(event, context):
#     """AWS Lambda handler function."""
#     try:
#         # payload = event['body']
#         payload = json.loads(event['body'])
#         prompt = payload.get('prompt')
#         print(f'prompt: {prompt}')

#         if not prompt:
#             return respond(400, {"error": "Missing 'prompt' in request body"})

#         model_response = invoke_bedrock_model(prompt)
#         return respond(200, {"response": model_response})

#     except botocore.exceptions.ClientError as error:
#         # Handle client errors from Boto3
#         error_code = error.response['Error']['Code']
#         if error_code == 'AccessDeniedException':
#             return respond(403, {"error": error.response['Error']['Message']})
#         else:
#             return respond(500, {"error": error.response['Error']['Message']})

#     except Exception as e:
#         # Handle any other exceptions
#         logger.error("Exception: %s", e)
#         return respond(500, {"error": str(e)})