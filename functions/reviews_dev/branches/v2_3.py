import json
import boto3
import datetime
from decimal import Decimal
from boto3.dynamodb.conditions import Key
import requests
from requests.auth import HTTPBasicAuth
from botocore.exceptions import ClientError

# OpenSearch configuration for professional profiles
OPENSEARCH_ENDPOINT = 'https://search-connecus-home-xter5mxymdzivmnio2iuvwgg4a.us-east-2.es.amazonaws.com'
OPENSEARCH_PROFILES_INDEX = 'pros_from_xano_dev'
AWS_REGION = 'us-east-2'
SECRETS_MANAGER_SECRET_NAME = 'opensearch-credentials'

def get_secret(secret_name):
    """
    Retrieves a secret from AWS Secrets Manager.
    """
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=AWS_REGION
    )
    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        print(f"Error retrieving secret '{secret_name}': {e}")
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print(f"The requested secret {secret_name} was not found.")
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            print(f"The request was invalid for the secret {secret_name}.")
        raise e
    else:
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            return json.loads(secret)
        else:
            print(f"Secret '{secret_name}' is not a string. This example expects a string.")
            return json.loads(get_secret_value_response['SecretBinary'].decode('utf-8'))

# Get OpenSearch credentials from Secrets Manager
opensearch_credentials = get_secret(SECRETS_MANAGER_SECRET_NAME)
username = opensearch_credentials.get('username')
password = opensearch_credentials.get('password')

# Use HTTPBasicAuth for username/password authentication
auth = HTTPBasicAuth(username, password)
headers = {"Content-Type": "application/json"}

# DynamoDB setup
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('reviews_dev')
services_requests_table = dynamodb.Table('services_requests_dev')
chats_table = dynamodb.Table('chats_dev')


def query_opensearch(payload):
    """
    Queries OpenSearch with a given payload and returns the raw search hits array.

    Args:
        payload (dict): The OpenSearch query body.

    Returns:
        list: A list of raw hit dictionaries from OpenSearch (each containing _source, _score, highlight, etc.),
              or an error dictionary if the query fails.
    """
    print(f"[DEBUG] Initializing OpenSearch query with payload: {json.dumps(payload)}")
    if not auth:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': "OpenSearch authentication not initialized."})
        }

    # The URL for search queries is /{index_name}/_search
    url = f"{OPENSEARCH_ENDPOINT}/{OPENSEARCH_PROFILES_INDEX}/_search"

    # Define a default timeout for the request in seconds
    REQUEST_TIMEOUT = 60 # seconds
    print(f"[DEBUG] Setting OpenSearch request timeout to {REQUEST_TIMEOUT} seconds.")

    try:
        # Use requests.post for sending a query payload with a timeout
        response = requests.post(url, auth=auth, headers=headers, json=payload, timeout=REQUEST_TIMEOUT)
        response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)

        json_response = response.json()
        print(f"[DEBUG] OpenSearch query response: {json.dumps(json_response, indent=2)}")

        # Return the raw 'hits' array, which includes '_score' and 'highlight'
        hits = json_response.get('hits', {}).get('hits', [])
        print(f"[DEBUG] Found {len(hits)} raw hits.")
        return hits

    except requests.exceptions.Timeout:
        print(f"Error: OpenSearch query timed out after {REQUEST_TIMEOUT} seconds.")
        return {
            'statusCode': 504, # Gateway Timeout
            'body': json.dumps({'error': f"OpenSearch query timed out after {REQUEST_TIMEOUT} seconds."})
        }
    except requests.exceptions.RequestException as e:
        print(f"Network or request error during OpenSearch query: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': f"Network or request error: {str(e)}"})
        }
    except json.JSONDecodeError as e:
        print(f"JSON decoding error in OpenSearch response: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': f"JSON decoding error: {str(e)}"})
        }
    except Exception as e:
        print(f"An unexpected error occurred during OpenSearch query: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def get_pro_from_opensearch(role_id):
    print(f"[DEBUG] Retrieving professional profile from OpenSearch index '{OPENSEARCH_PROFILES_INDEX}' for role_id: {role_id}")
    query_payload = {
        "query": {
            "term": {
                "doc.role_id_on_dynamo.keyword": role_id
            }
        },
        "_source": ["doc.user_type", "doc.users_id", "doc.profile_professionals_id", "doc.profile_contractors_id"]
    }

    hits = query_opensearch(query_payload)

    if hits and isinstance(hits, list) and len(hits) > 0:
        source_data = hits[0].get('_source', {})
        doc_data = source_data.get('doc', {})

        if doc_data.get('user_type') == 'Professional':
            profile_id = doc_data.get('profile_professionals_id')
        if doc_data.get('user_type') == 'Contractor':
            profile_id = doc_data.get('profile_contractors_id')

        if doc_data:
            profile_data = {
                'user_type': doc_data.get('user_type'),
                'profile_id': profile_id
            }
            print(f"[DEBUG] Professional profile retrieved: {profile_data}")
        else:
            print(f"[WARNING] OpenSearch hit for role_id {role_id} did not contain a 'doc' object in _source.")
    else:
        print(f"[WARNING] Professional profile not found in OpenSearch for role_id: {role_id}")

    return profile_data if profile_data else None

def handle_request(event, payload):
    operation = event['httpMethod']
    try:
        if operation == 'POST':
            return create_review(payload)
        elif operation == 'GET':
            return handle_get(payload)
        elif operation == 'PUT':
            return update_review(payload)
        elif operation == 'DELETE':
            return delete_review(payload)
        else:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Invalid HTTP method'})
            }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

import json
import datetime
from boto3.dynamodb.conditions import Key

def create_review(payload):
    print('[DEBUG INFO] Initializing create_review...')
    try:
        current_time = datetime.datetime.utcnow().isoformat()
        review_id = payload['review_id']
        service_request_id = payload['service_request_id']
        chat_id = payload['chat_id']
        reviewed = payload['reviewed']
        print(f'[DEBUG INFO] Review ID: {review_id}, Service Request ID: {service_request_id}, Chat ID: {chat_id}, Reviewed: {reviewed}')

        update_pro_rate_on_xano = {"rates_received_from_homeowners": []}

        # Create appropriate review item based on reviewer type
        if 'authenticated_homeowner' in payload:

            # Retrieve current rates received from homeowners over this pro
            print('[DEBUG INFO] Retrieving current rates received from homeowners over this pro...')
            response = table.query(
                IndexName='reviewed-index',
                KeyConditionExpression=Key('reviewed').eq(reviewed)
            )

            if response['Items']:
                # Fixed: Iterate through items to collect all overall_rating_string values
                current_rates = []
                for item in response['Items']:
                    if 'overall_rating_string' in item:
                        current_rates.append(item['overall_rating_string'])

                # Convert to float list
                rates_received_from_homeowners = [float(x) for x in current_rates]
                update_pro_rate_on_xano['rates_received_from_homeowners'] = rates_received_from_homeowners

            # Retrieve pro information from OpenSearch
            pro = get_pro_from_opensearch(reviewed)
            print(f'[DEBUG INFO] Pro: {pro}')
            pro_user_type = pro.get('user_type')
            print(f'[DEBUG INFO] Pro user type: {pro_user_type}')
            pro_profile_id = pro.get('profile_id')
            print(f'[DEBUG INFO] Pro profile ID: {pro_profile_id}')

            # Fixed: Added elif for proper conditional logic
            if pro_user_type == 'Contractor':
                xano_contractor_id = int(pro_profile_id)
                xano_professional_id = 0
            elif pro_user_type == 'Professional':
                xano_professional_id = int(pro_profile_id)
                xano_contractor_id = 0
            else:
                # Handle case where user_type is neither Contractor nor Professional
                print(f'[WARNING] Unknown pro_user_type: {pro_user_type}')
                xano_professional_id = 0
                xano_contractor_id = 0

            print(f'[DEBUG INFO] xano_professional_id: {xano_professional_id}')
            print(f'[DEBUG INFO] xano_contractor_id: {xano_contractor_id}')

            update_pro_rate_on_xano['xano_professional_id'] = xano_professional_id
            update_pro_rate_on_xano['xano_contractor_id'] = xano_contractor_id

            update_service_request_table = True
            reviewer = payload['authenticated_homeowner']
            # Create review item over pro
            item = {
                'review_id': review_id,
                'service_request_id': service_request_id,
                'chat_id': chat_id,
                'reviewer': reviewer,
                'reviewed': reviewed,
                'created_at': current_time,
                'updated_at': current_time,
                'quality': payload['quality'],
                'communication': payload['communication'],
                'organization': payload['organization'],
                'time_management': payload['time_management'],
                'initiative': payload['initiative'],
                'overall_rating_string': payload['overall_rating_string']
            }

            update_pro_rate_on_xano['new_rate_received'] = float(payload['overall_rating_string'])

        elif 'authenticated_professional' in payload:
            reviewer = payload['authenticated_professional']
            update_service_request_table = False
            # Create review item over homeowner
            item = {
                'review_id': review_id,
                'service_request_id': service_request_id,
                'chat_id': chat_id,
                'reviewer': reviewer,
                'reviewed': reviewed,
                'created_at': current_time,
                'updated_at': current_time,
                'comments': payload['comments'],
                'overall_rating_string': payload['overall_rating_string']
            }
        else:
            update_service_request_table = False
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Missing reviewer information'})
            }

        # Create the review in DynamoDB
        table.put_item(Item=item)

        # Update service_request table about the review over the pro
        if update_service_request_table == True:
            print('[DEBUG INFO] Updating service_request table about the review over the pro...')

            # 1. Retrieve the service request to check its current status
            try:
                response = services_requests_table.get_item(
                    Key={
                        'service_request_id': service_request_id
                    }
                )
                service_request = response.get('Item')

                if service_request:
                    current_status = service_request.get('status')
                    update_expression_parts = ['SET #reviewed = :reviewed']
                    expression_attribute_names = {
                        '#reviewed': 'pro_already_reviewed'
                    }
                    expression_attribute_values = {
                        ':reviewed': 'True' # Always set pro_already_reviewed to True
                    }

                    # 2. Check if status is 'Concluded' and update it to 'Reviewed'
                    if current_status == 'Concluded':
                        update_expression_parts.append('#status = :new_status')
                        expression_attribute_names['#status'] = 'status'
                        expression_attribute_values[':new_status'] = 'Reviewed'
                        print(f'[DEBUG INFO] Service request {service_request_id} status changed from Concluded to Reviewed.')

                    # Construct the final UpdateExpression
                    update_expression = ", ".join(update_expression_parts)

                    services_requests_table.update_item(
                        Key={
                            'service_request_id': service_request_id
                        },
                        UpdateExpression=update_expression,
                        ExpressionAttributeNames=expression_attribute_names,
                        ExpressionAttributeValues=expression_attribute_values
                    )
                    print(f'[DEBUG INFO] Service request {service_request_id} updated successfully.')
                else:
                    print(f'[WARNING] Service request with ID {service_request_id} not found.')

            except Exception as e:
                print(f'[ERROR] Failed to update service request {service_request_id}: {e}')

        # Update chat table with review_id in the reviews list
        print('[DEBUG INFO] Updating chat table with review_id...')
        try:
            # First check if the chat exists
            original_chat = chats_table.get_item(
                Key={
                    'chat_id': chat_id
                }
            )

            if 'Item' in original_chat:
                print('[DEBUG INFO] Chat exists, updating...')

            if 'Item' not in original_chat:
                return {
                    'statusCode': 404,
                    'body': json.dumps({'error': 'Correspondent chat not found to be updated'})
                }

            # Create the review info to append to the list
            review_info = {'reviewer': reviewer, 'review_id': review_id}
            print(f'[DEBUG INFO] Review info: {review_info}')

            # Update the reviews list in chats_table
            updated_chat = chats_table.update_item(
                Key={
                    'chat_id': chat_id
                },
                UpdateExpression='SET #reviews = list_append(if_not_exists(#reviews, :empty_list), :review_info_list)',
                ExpressionAttributeNames={
                    '#reviews': 'reviews'
                },
                ExpressionAttributeValues={
                    ':review_info_list': [review_info],
                    ':empty_list': []
                },
                ReturnValues='UPDATED_NEW'
            )

            return {
                'statusCode': 201,
                'body': json.dumps({
                    'message': 'Review created and chat updated successfully',
                    'updated_reviews': updated_chat.get('Attributes', {}).get('reviews'),
                    'update_pro_rate_on_xano': update_pro_rate_on_xano
                }, default=decimal_default)
            }

        except Exception as e:
            print(f'[ERROR] Failed to update chat: {str(e)}')
            # The review was created but chat update failed
            return {
                'statusCode': 500,
                'body': json.dumps({
                    'message': 'Review created but failed to update chat',
                    'error': str(e)
                })
            }

    except Exception as e:
        print(f'[ERROR] Failed to create review: {str(e)}')
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def handle_get(payload):
    print('[DEBUG INFO] Initializing handle_get...')
    try:
        if not payload:
            payload = {}

        # If review_id is provided, get a specific review
        if 'review_id' in payload:
            return get_one(payload['review_id'])
        elif 'service_request_id' in payload:
            return get_reviews_by_service_request(payload['service_request_id'])
        elif 'chat_id' in payload:
            return get_reviews_by_chat(payload['chat_id'])
        elif 'reviewer' in payload:
            return get_reviews_by_reviewer(payload['reviewer'])
        elif 'reviewed' in payload:
            return get_reviews_by_reviewed(payload['reviewed'])
        elif 'concluded_not_reviewed' in payload:
            return get_concluded_not_reviewed()
        else:
            return get_all_reviews()
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def get_one(review_id):
    print('[DEBUG INFO] Initializing get_one...')
    try:
        response = table.get_item(
            Key={
                'review_id': review_id
            }
        )

        if 'Item' in response:
            return {
                'statusCode': 200,
                'body': json.dumps(response['Item'], default=decimal_default)
            }
        else:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Review not found'})
            }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def get_reviews_by_service_request(service_request_id):
    print('[DEBUG INFO] Initializing get_reviews_by_service_request...')
    try:
        response = table.query(
            IndexName='service_request_id-index',
            KeyConditionExpression=Key('service_request_id').eq(service_request_id)
        )

        return {
            'statusCode': 200,
            'body': json.dumps(response['Items'], default=decimal_default)
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def get_reviews_by_chat(chat_id):
    print('[DEBUG INFO] Initializing get_reviews_by_chat...')
    try:
        response = table.query(
            IndexName='chat_id-index',
            KeyConditionExpression=Key('chat_id').eq(chat_id)
        )
        print(f'Response: {response}')
        return {
            'statusCode': 200,
            'body': json.dumps(response['Items'], default=str)
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def get_reviews_by_reviewer(reviewer):
    print('[DEBUG INFO] Initializing get_reviews_by_reviewer...')
    try:
        response = table.query(
            IndexName='reviewer-index',
            KeyConditionExpression=Key('reviewer').eq(reviewer)
        )

        return {
            'statusCode': 200,
            'body': json.dumps(response['Items'], default=str)
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def get_reviews_by_reviewed(reviewed):
    print('[DEBUG INFO] Initializing get_reviews_by_reviewed...')
    try:
        response = table.query(
            IndexName='reviewed-index',
            KeyConditionExpression=Key('reviewed').eq(reviewed)
        )

        return {
            'statusCode': 200,
            'body': json.dumps(response['Items'], default=str)
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def get_all_reviews():
    print('[DEBUG INFO] Initializing get_all_reviews...')
    try:
        response = table.scan()
        print(response)
        items = response.get('Items', [])

        return {
            'statusCode': 200,
            'body': json.dumps(items, default=str)
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def update_review(payload):
    """Update an existing review"""
    try:
        update_pro_rate_on_xano = {}

        update_pro_rate_on_xano['new_rate_received'] = float(payload['overall_rating_string'])

        review_id = payload['review_id']
        current_time = datetime.datetime.utcnow().isoformat()

        # First check if the review exists and get current item
        response = table.get_item(
            Key={
                'review_id': review_id
            }
        )

        if 'Item' not in response:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Review not found'})
            }

        existing_item = response['Item']
        print(f'[DEBUG INFO] Existing review: {existing_item}')

        # Retrieve pro information from OpenSearch
        reviewed = existing_item['reviewed']
        print(f'[DEBUG INFO] Assigned reviewed: {reviewed}')

        pro = get_pro_from_opensearch(reviewed)
        print(f'[DEBUG INFO] Retrieved pro: {pro}')

        if pro:
            if pro['user_type'] == 'Contractor':
                xano_contractor_id = int(pro['profile_id'])
                xano_professional_id = 0
            if pro['user_type'] == 'Professional':
                xano_professional_id = int(pro['profile_id'])
                xano_contractor_id = 0
        update_pro_rate_on_xano['xano_professional_id'] = xano_professional_id
        update_pro_rate_on_xano['xano_contractor_id'] = xano_contractor_id

        # Previous rate under this review
        previous_rate_for_this_review = float(existing_item['overall_rating_string'])
        print(f'[DEBUG INFO] Previous rate for this review: {previous_rate_for_this_review}')

        # Retrieve current rates received from homeowners over this pro
        print('[DEBUG INFO] Retrieving current rates received from homeowners over this pro...')
        response = table.query(
            IndexName='reviewed-index',
            KeyConditionExpression=Key('reviewed').eq(reviewed)
        )
        if response['Items']:
            response_items = response['Items']
            print(f'[DEBUG INFO] Response items: {response_items}')
            current_rates = [item['overall_rating_string'] for item in response_items]
            print(f'[DEBUG INFO] Current rates received from homeowners over this pro: {current_rates}')
            rates_received_from_homeowners = float_list = [float(x) for x in current_rates]
            print(f'[DEBUG INFO] Current rates received from homeowners over this pro: {rates_received_from_homeowners}')

            # Remove the previous rate from the list
            print(f'[DEBUG INFO] Removing previous rate for this review from the general list...')
            rates_received_from_homeowners.remove(previous_rate_for_this_review)
            print(f'[DEBUG INFO] New list: {rates_received_from_homeowners}')

            update_pro_rate_on_xano['rates_received_from_homeowners_less_updated_one'] = rates_received_from_homeowners

        # Prepare update expression
        update_expression = "SET updated_at = :updated_at"
        expression_values = {
            ':updated_at': current_time
        }

        # Fields that should not be modified during updates
        protected_fields = [
            'review_id',         # Primary key - cannot be modified
            'created_at',        # Creation timestamp should not change
            'service_request_id', # Relationship field - should not change
            'chat_id',           # Relationship field - should not change
            'reviewer',          # Relationship field - should not change
            'reviewed'           # Relationship field - should not change
        ]

        # Add fields to update based on payload, skipping protected fields
        for key, value in payload.items():
            if key not in protected_fields and key != 'review_id':
                placeholder = f":{key.replace('-', '_')}"
                update_expression += f", {key} = {placeholder}"

                # Convert Decimal-compatible fields
                if isinstance(value, (int, float)):
                    expression_values[placeholder] = Decimal(str(value))
                else:
                    expression_values[placeholder] = value


        # Update the review
        table.update_item(
            Key={
                'review_id': review_id
            },
            UpdateExpression=update_expression,
            ExpressionAttributeValues=expression_values
        )

        return {
            'statusCode': 200,
            'body': json.dumps({'message': 'Review updated successfully', 'update_pro_rate_on_xano': update_pro_rate_on_xano})
        }
    except KeyError as e:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': f'Missing required field: {str(e)}'})
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def delete_review(payload):
    """Delete a review by its ID"""
    try:
        review_id = payload['review_id']

        # Check if the review exists before deletion
        response = table.get_item(
            Key={
                'review_id': review_id
            }
        )

        if 'Item' not in response:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Review not found'})
            }

        # Delete the review
        table.delete_item(
            Key={
                'review_id': review_id
            }
        )

        return {
            'statusCode': 200,
            'body': json.dumps({'message': 'Review deleted successfully'})
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def decimal_default(obj):
    if isinstance(obj, Decimal):
        if obj % 1 == 0:
            return int(obj)
        else:
            return float(obj)
    raise TypeError