import json
import boto3
import datetime
from boto3.dynamodb.conditions import Key, Attr
import requests
from requests.auth import HTTPBasicAuth
from botocore.exceptions import ClientError

dynamodb = boto3.resource('dynamodb')
chats_table = dynamodb.Table('chats_dev')
services_requests_table = dynamodb.Table('services_requests_dev')
roles_table = dynamodb.Table('roles_dev')
quotes_table = dynamodb.Table('quotes_dev')

current_time = datetime.datetime.utcnow().isoformat()

# OpenSearch configuration for professional profiles
OPENSEARCH_ENDPOINT = 'https://search-connecus-home-xter5mxymdzivmnio2iuvwgg4a.us-east-2.es.amazonaws.com'
OPENSEARCH_PROFILES_INDEX = 'pros_from_xano_dev' # This index is specifically for professionals
AWS_REGION = 'us-east-2'
SECRETS_MANAGER_SECRET_NAME = 'opensearch-credentials'

# Global variables for OpenSearch credentials and auth
opensearch_username = None
opensearch_password = None
opensearch_auth = None

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

# Initialize OpenSearch credentials globally
try:
    opensearch_credentials = get_secret(SECRETS_MANAGER_SECRET_NAME)
    opensearch_username = opensearch_credentials.get('username')
    opensearch_password = opensearch_credentials.get('password')
    opensearch_auth = HTTPBasicAuth(opensearch_username, opensearch_password)
    print("[DEBUG] OpenSearch credentials loaded successfully.")
except Exception as e:
    print(f"[ERROR] Failed to load OpenSearch credentials at global scope: {e}")
    opensearch_auth = None

headers = {"Content-Type": "application/json"}

def query_opensearch(index_name, payload):
    """
    Queries OpenSearch with a given payload and returns the raw search hits array.

    Args:
        index_name (str): The OpenSearch index to query.
        payload (dict): The OpenSearch query body.

    Returns:
        list: A list of raw hit dictionaries from OpenSearch, or an empty list if query fails.
    """
    print(f"[DEBUG] Initializing OpenSearch query on index '{index_name}' with payload: {json.dumps(payload)}")
    if not opensearch_auth:
        print("[ERROR] OpenSearch authentication not initialized. Cannot query.")
        return []

    url = f"{OPENSEARCH_ENDPOINT}/{index_name}/_search"
    REQUEST_TIMEOUT = 60 # seconds

    try:
        response = requests.post(url, auth=opensearch_auth, headers=headers, json=payload, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()

        json_response = response.json()
        hits = json_response.get('hits', {}).get('hits', [])
        print(f"[DEBUG] Found {len(hits)} raw hits on index '{index_name}'.")
        return hits

    except requests.exceptions.Timeout:
        print(f"Error: OpenSearch query on index '{index_name}' timed out after {REQUEST_TIMEOUT} seconds.")
    except requests.exceptions.RequestException as e:
        print(f"Network or request error during OpenSearch query on index '{index_name}': {e}")
    except json.JSONDecodeError as e:
        print(f"JSON decoding error in OpenSearch response from index '{index_name}': {e}")
    except Exception as e:
        print(f"An unexpected error occurred during OpenSearch query on index '{index_name}': {e}")
    return []

def get_profile_details(role_id):
    """
    Fetches profile details from the appropriate source (DynamoDB for homeowners, OpenSearch for professionals).
    Ensures a consistent output format for both, matching the new requirements.
    """
    if not role_id:
        return None

    profile_data = None

    if role_id.startswith('HOMEOWNER#'):
        print(f"[DEBUG] Retrieving homeowner profile from DynamoDB roles_dev table using GSI for role_id: {role_id}")
        try:
            # Use query on the GSI to find the item by role_id
            response = roles_table.query(
                IndexName='role_id-index', # Specify the GSI name
                KeyConditionExpression=Key('role_id').eq(role_id),
                # Assuming these fields exist in your roles_dev table for homeowners
                ProjectionExpression='#n, email, phone, #l, phone_country',
                ExpressionAttributeNames={'#n': 'name', '#l': 'language'}
            )

            items = response.get('Items', [])
            if items:
                # A query returns a list, even if only one item matches
                item = items[0]
                profile_data = {
                    'name': item.get('name'),
                    'email': item.get('email'),
                    'phone': item.get('phone'),
                    'language': item.get('language')
                }
                print(f"[DEBUG] Homeowner profile retrieved: {profile_data}")
            else:
                print(f"[WARNING] Homeowner profile not found in roles_dev GSI for role_id: {role_id}")
        except Exception as e:
            print(f"[ERROR] Error retrieving homeowner profile from DynamoDB for {role_id}: {str(e)}")
            profile_data = None

    elif role_id.startswith('PRO#'):
        print(f"[DEBUG] Retrieving professional profile from OpenSearch index '{OPENSEARCH_PROFILES_INDEX}' for role_id: {role_id}")
        query_payload = {
            "query": {
                "term": {
                    "doc.role_id_on_dynamo.keyword": role_id
                }
            },
            "_source": ["doc.name", "doc.email", "doc.phone", "doc.language", "doc.phone_country", "doc.profile_image_complete_path"]
        }

        hits = query_opensearch(OPENSEARCH_PROFILES_INDEX, query_payload)

        if hits and isinstance(hits, list) and len(hits) > 0:
            source_data = hits[0].get('_source', {})
            doc_data = source_data.get('doc', {})

            if doc_data:
                profile_data = {
                    'name': doc_data.get('name'),
                    'email': doc_data.get('email'),
                    'phone': doc_data.get('phone'),
                    'language': doc_data.get('language'),
                    'profile_image_complete_path': doc_data.get('profile_image_complete_path')
                }
                print(f"[DEBUG] Professional profile retrieved: {profile_data}")
            else:
                print(f"[WARNING] OpenSearch hit for role_id {role_id} did not contain a 'doc' object in _source.")
        else:
            print(f"[WARNING] Professional profile not found in OpenSearch for role_id: {role_id}")
    else:
        print(f"[WARNING] Unknown role_id prefix for profile retrieval: {role_id}")

    return profile_data

def handle_request(event, payload):
    operation = event['httpMethod']

    try:
        if operation == 'POST':
            return create_chat(payload)
        elif operation == 'GET':
            return handle_chat_get(payload)
        elif operation == 'PUT':
            return update_chat(payload)
        elif operation == 'DELETE':
            return delete_chat(payload)
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

def handle_chat_get(payload):
    print('[DEBUG INFO] Initializing handle_chat_get...')
    try:
        # Extract query parameters
        chat_id = payload.get('chat_id')
        services_requests_id = payload.get('services_requests_id')
        homeowner = payload.get('homeowner')
        professional = payload.get('professional')
        status_filter = payload.get('status')
        authenticated_role = payload.get('authenticated_role')
        ai_info = payload.get('ai_info')

        # Route to the appropriate function based on the query parameters
        if chat_id and authenticated_role:
            return get_one(chat_id, authenticated_role)
        elif services_requests_id:
            return get_chats_by_services_request_id(services_requests_id, status_filter)
        elif homeowner:
            return get_chats_by_homeowner(homeowner, status_filter)
        elif professional:
            return get_chats_by_professional(professional, status_filter)
        elif ai_info:
            return get_chat_info_for_ai(chat_id, ai_info)
        else:
            # If no specific filter is provided, return all chats
            return get_all_chats(status_filter)
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def create_chat(payload):
    print('[DEBUG INFO] Initializing create_chat...')
    try:
        current_time = datetime.datetime.utcnow().isoformat()
        service_request_id = payload['service_request']
        chat_id = payload['chat_id']
        professional = payload['professional']
        homeowner = payload['homeowner']
        # Fetch professional info from table roles
        professional_response = roles_table.query(
            IndexName='role_id-index',
            KeyConditionExpression=Key('role_id').eq(professional),
            Limit=1  # Since we only need one item
        )
        professional_name = professional_response.get('Items', [{}])[0].get('name', '')
        professional_phone = professional_response.get('Items', [{}])[0].get('phone', '')

        # Create chat item
        item = {
            'chat_id': chat_id,
            'services_requests_id': service_request_id,
            'chat_status': payload.get('chat_status', 'Open'),  # Default status
            'status_detail': '',
            'homeowner': payload['homeowner'],
            'professional': professional,
            'professional_name': professional_name,
            'professional_phone': professional_phone,
            'quotes': [],
            'invoices': [],
            'appointments': [],
            'reviews': [],
            'comm_messages': [],
            'created_at': current_time,
            'updated_at': current_time,
            'new_messages_to_homeowner': False,
            'new_messages_to_pro': False,
            'last_sms_to_homeowner': None,
            'last_sms_to_pro': None,
            'conversation_is_blocked': False,
            'blocker': ''
        }

        # Retrieve service request information
        service_request_response = services_requests_table.query(
            KeyConditionExpression=Key('service_request_id').eq(service_request_id),
            Limit=1  # Since we only need one item
        )
        service_request_items = service_request_response.get('Items', [])
        service_request = service_request_items[0] if service_request_items else None
        item['service_request_title'] = service_request.get('title', '') if service_request else ''

        # Retrieve homeowner language
        homeowner_response = roles_table.query(
            IndexName='role_id-index',
            KeyConditionExpression=Key('role_id').eq(homeowner),
            Limit=1  # Since we only need one item
        )
        homeowner_items = homeowner_response.get('Items', [])
        homeowner_profile = homeowner_items[0] if homeowner_items else None
        print(f"Homeowner profile: {homeowner_profile}")
        item['homeowner_language'] = homeowner_profile.get('language', '') if homeowner_profile else ''

        # Retrieve professional language
        professional_response = roles_table.query(
            IndexName='role_id-index',
            KeyConditionExpression=Key('role_id').eq(professional),
            Limit=1  # Since we only need one item
        )
        professional_items = professional_response.get('Items', [])
        professional_profile = professional_items[0] if professional_items else None
        print(f"Professional profile: {professional_profile}")
        item['professional_language'] = professional_profile.get('language', '') if professional_profile else ''

        # Create the chat in DynamoDB
        chats_table.put_item(Item=item)

        # Update service request with new chat information
        try:
            # Prepare the chat info to add to service request
            chat_info = {
                'chat_id': chat_id,
                'professional': professional
            }

            # Add the chat to the service request's chats list
            services_requests_table.update_item(
                Key={'service_request_id': service_request_id},
                UpdateExpression="SET #chats = list_append(if_not_exists(#chats, :empty_list), :new_chat), updated_at = :updated_at",
                ExpressionAttributeNames={
                    '#chats': 'chats'
                },
                ExpressionAttributeValues={
                    ':new_chat': [chat_info],
                    ':empty_list': [],
                    ':updated_at': current_time
                }
            )
        except Exception as service_request_error:
            # If updating service request fails, continue but log the error
            # Optionally, you could delete the chat if this update fails for full transactional behavior
            print(f"Error updating service request: {str(service_request_error)}")
            # Consider implementing a retry mechanism or queuing system for critical updates

        return {
            'statusCode': 201,
            'body': json.dumps({'message': 'Chat created successfully', 'chat_id': chat_id})
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def get_one(chat_id, authenticated_role):
    print(f'[DEBUG INFO] Fetching chat with chat_id: {chat_id}')

    try:
        chat_response = chats_table.get_item(Key={'chat_id': chat_id})
        chat_item = chat_response.get('Item')
        professional = chat_item.get('professional') if chat_item else None

        professional_profile = get_profile_details(professional)
        professional_profile_image_path = professional_profile.get('profile_image_complete_path', '') if professional_profile else ''

        if not chat_item:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Chat not found'})
            }

        if chat_item.get('comm_messages'):
            for message in chat_item['comm_messages']:
                message['created_at'] = int(str(message['created_at']))
                # if message['read'] and message['read'] == False and message['sender'] != authenticated_role:
                #     chat_item['there_are_unread_messages'] = True

            # Sort messages by created_at in descending order
            chat_item['comm_messages'].sort(key=lambda msg: msg['created_at'], reverse=True)

        chat_item['professional_image_complete_path'] = professional_profile_image_path

        service_request_id = chat_item.get('services_requests_id')
        service_request = None
        if service_request_id:
            try:
                sr_response = services_requests_table.query(
                    KeyConditionExpression=Key('service_request_id').eq(service_request_id),
                    Limit=1
                )
                service_request_items = sr_response.get('Items', [])
                service_request = service_request_items[0] if service_request_items else None

                if service_request and service_request.get('homeowner'):
                    homeowner_role_id = service_request['homeowner'] # Get the homeowner ID

                    # Fix: Query for homeowner profile
                    homeowner_role_response = roles_table.query(
                        IndexName='role_id-index',
                        KeyConditionExpression=Key('role_id').eq(homeowner_role_id),
                        Limit=1
                    )
                    homeowner_items = homeowner_role_response.get('Items', [])

                    if homeowner_items:
                        homeowner_item = homeowner_items[0] # Correctly retrieve from homeowner_items
                        service_request['homeowner_name'] = homeowner_item.get('name') # Use .get() for safety
                    else:
                        # Optional: Handle case where homeowner profile isn't found
                        print(f"Warning: No homeowner profile found for role_id: {homeowner_role_id}")
                        service_request['homeowner_name'] = None # Or 'Unknown'
            except Exception as e:
                print(f'[ERROR] Failed to get chat: {str(e)}')
                return {
                    'statusCode': 500,
                    'body': json.dumps({'error': f'Failed to get chat: {str(e)}'})
                }

        # After preparing the chat_item to return, update it with messages as read

        current_item = chats_table.get_item(Key={'chat_id': chat_id})

        if 'Item' in current_item:
            comm_messages = current_item['Item'].get('comm_messages', [])

            # Update comm_messages - mark messages from authenticated role as read
            for message in comm_messages:
                if message.get('sender') == authenticated_role:
                    message['read'] = True

            # Single update operation for both scenarios
            if authenticated_role.startswith('PRO'):
                chats_table.update_item(
                    Key={'chat_id': chat_id},
                    UpdateExpression='SET new_messages_to_pro = :new_messages_to_pro, updated_at = :updated_at, comm_messages = :comm_messages',
                    ExpressionAttributeValues={
                        ':new_messages_to_pro': False,
                        ':updated_at': datetime.datetime.utcnow().isoformat(),
                        ':comm_messages': comm_messages
                    },
                    ReturnValues='NONE'
                )

            elif authenticated_role.startswith('HOMEOWNER'):
                chats_table.update_item(
                    Key={'chat_id': chat_id},
                    UpdateExpression='SET new_messages_to_homeowner = :new_messages_to_homeowner, updated_at = :updated_at, comm_messages = :comm_messages',
                    ExpressionAttributeValues={
                        ':new_messages_to_homeowner': False,
                        ':updated_at': datetime.datetime.utcnow().isoformat(),
                        ':comm_messages': comm_messages
                    },
                    ReturnValues='NONE'
                )

        return {
            'statusCode': 200,
            'body': json.dumps({
                'chat_info': chat_item,
                'service_request_info': service_request
            }, default=str)
        }
    except Exception as e:
        print(f'[ERROR] Failed to get chat: {str(e)}')
        return {
            'statusCode': 500,
            'body': json.dumps({'error': f'Failed to get chat: {str(e)}'})
        }

def get_chats_by_services_request_id(services_requests_id, status_filter=None):
    print(f'[DEBUG INFO] Fetching chats for services_requests_id: {services_requests_id}')

    try:
        # Query using GSI
        kwargs = {
            'IndexName': 'services_requests_id-index',
            'KeyConditionExpression': Key('services_requests_id').eq(services_requests_id)
        }

        if status_filter:
            kwargs['FilterExpression'] = Attr('chat_status').eq(status_filter)

        response = chats_table.query(**kwargs)
        items = response.get('Items', [])

        # Handle pagination
        while 'LastEvaluatedKey' in response:
            kwargs['ExclusiveStartKey'] = response['LastEvaluatedKey']
            response = chats_table.query(**kwargs)
            items.extend(response.get('Items', []))

        # Attach service request info to each chat item
        enriched_items = []

        for item in items:

            # Handle comm_messages sorting and get only most recent
            if item.get('comm_messages') and len(item['comm_messages']) > 0:
                # Sort comm_messages by created_at in descending order (newest first)
                sorted_messages = sorted(
                    item['comm_messages'],
                    key=lambda msg: msg.get('created_at', 0),
                    reverse=True
                )

                # Store only the most recent message
                last_message = sorted_messages[0]
                print(f'[DEBUG INFO] Last message: {last_message}')
                last_message['created_at'] = int(str(last_message['created_at']))
                item['last_comm_message'] = last_message

                # Remove the original comm_messages array
                del item['comm_messages']
            elif not item.get('comm_messages') or len(item['comm_messages']) == 0:
                # Create empty JSON object for last_comm_message when comm_messages is empty
                item['last_comm_message'] = {}
                # Remove the original comm_messages array if it exists but is empty
                if 'comm_messages' in item:
                    del item['comm_messages']

            service_request_info = None
            sr_id = item.get('services_requests_id')
            if sr_id:
                sr_response = services_requests_table.query(
                    KeyConditionExpression=Key('service_request_id').eq(sr_id),
                    Limit=1
                )
                sr_items = sr_response.get('Items', [])
                service_request_info = sr_items[0] if sr_items else None

            professional = item.get('professional') if item else None

            # Retrieve professional profile image path
            professional_profile = get_profile_details(professional)
            professional_profile_image_path = professional_profile.get('profile_image_complete_path', '') if professional_profile else ''

            item['professional_image_complete_path'] = professional_profile_image_path

            enriched_items.append({
                'chat_info': item,
                'service_request_info': service_request_info
            })

        return {
            'statusCode': 200,
            'body': json.dumps(enriched_items, default=str)
        }

    except Exception as e:
        print(f'[ERROR] Failed to fetch chats: {e}')
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def get_chats_by_homeowner(homeowner, status_filter=None):
    print('[DEBUG INFO] Initializing get_chats_by_homeowner...')
    try:
        # Use GSI instead of scan
        kwargs = {
            'IndexName': 'homeowner-index',
            'KeyConditionExpression': boto3.dynamodb.conditions.Key('homeowner').eq(homeowner)
        }

        # Add status filter if provided
        if status_filter:
            kwargs['FilterExpression'] = boto3.dynamodb.conditions.Attr('chat_status').eq(status_filter)

        response = chats_table.query(**kwargs)
        items = response.get('Items', [])

        # Handle pagination
        while 'LastEvaluatedKey' in response:
            kwargs['ExclusiveStartKey'] = response['LastEvaluatedKey']
            response = chats_table.query(**kwargs)
            items.extend(response.get('Items', []))

        # Attach service request info to each chat item
        enriched_items = []

        for item in items:

            # Handle comm_messages sorting and get only most recent
            if item.get('comm_messages') and len(item['comm_messages']) > 0:
                # Sort comm_messages by created_at in descending order (newest first)
                sorted_messages = sorted(
                    item['comm_messages'],
                    key=lambda msg: msg.get('created_at', 0),
                    reverse=True
                )
                print(f'[DEBUG INFO] Sorted messages: {sorted_messages}')

                # Store only the most recent message
                last_message = sorted_messages[0]
                print(f'[DEBUG INFO] Last message: {last_message}')
                last_message['created_at'] = int(str(last_message['created_at']))
                item['last_comm_message'] = last_message

                # Remove the original comm_messages array
                del item['comm_messages']
            elif not item.get('comm_messages') or len(item['comm_messages']) == 0:
                # Create empty JSON object for last_comm_message when comm_messages is empty
                item['last_comm_message'] = {}
                # Remove the original comm_messages array if it exists but is empty
                if 'comm_messages' in item:
                    del item['comm_messages']

            service_request_info = None
            sr_id = item.get('services_requests_id')
            if sr_id:
                sr_response = services_requests_table.query(
                    KeyConditionExpression=Key('service_request_id').eq(sr_id),
                    Limit=1
                )
                sr_items = sr_response.get('Items', [])
                service_request_info = sr_items[0] if sr_items else None

            professional = item.get('professional') if item else None

            # Retrieve professional profile image path
            professional_profile = get_profile_details(professional)
            professional_profile_image_path = professional_profile.get('profile_image_complete_path', '') if professional_profile else ''

            item['professional_image_complete_path'] = professional_profile_image_path

            enriched_items.append({
                'chat_info': item,
                'service_request_info': service_request_info
            })

        return {
            'statusCode': 200,
            'body': json.dumps(enriched_items, default=str)
        }

    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def get_chats_by_professional(professional, status_filter=None):
    print('[DEBUG INFO] Initializing get_chats_by_professional...')
    try:
        # Use GSI instead of scan
        kwargs = {
            'IndexName': 'professional-index',
            'KeyConditionExpression': boto3.dynamodb.conditions.Key('professional').eq(professional)
        }

        # Add status filter if provided
        if status_filter:
            kwargs['FilterExpression'] = boto3.dynamodb.conditions.Attr('chat_status').eq(status_filter)

        response = chats_table.query(**kwargs)
        items = response.get('Items', [])

        # Handle pagination
        while 'LastEvaluatedKey' in response:
            kwargs['ExclusiveStartKey'] = response['LastEvaluatedKey']
            response = chats_table.query(**kwargs)
            items.extend(response.get('Items', []))

        # Attach service request info to each chat item
        enriched_items = []

        for item in items:

            # Handle comm_messages sorting and get only most recent
            if item.get('comm_messages') and len(item['comm_messages']) > 0:
                # Sort comm_messages by created_at in descending order (newest first)
                sorted_messages = sorted(
                    item['comm_messages'],
                    key=lambda msg: msg.get('created_at', 0),
                    reverse=True
                )

                # Store only the most recent message
                last_message = sorted_messages[0]
                print(f'[DEBUG INFO] Last message: {last_message}')
                last_message['created_at'] = int(str(last_message['created_at']))
                item['last_comm_message'] = last_message

                # Remove the original comm_messages array
                del item['comm_messages']
            elif not item.get('comm_messages') or len(item['comm_messages']) == 0:
                # Create empty JSON object for last_comm_message when comm_messages is empty
                item['last_comm_message'] = {}
                # Remove the original comm_messages array if it exists but is empty
                if 'comm_messages' in item:
                    del item['comm_messages']

            service_request_info = None
            sr_id = item.get('services_requests_id')
            if sr_id:
                sr_response = services_requests_table.query(
                    KeyConditionExpression=Key('service_request_id').eq(sr_id),
                    Limit=1
                )
                sr_items = sr_response.get('Items', [])
                service_request_info = sr_items[0] if sr_items else None

            professional = item.get('professional') if item else None

            # Retrieve professional profile image path
            professional_profile = get_profile_details(professional)
            professional_profile_image_path = professional_profile.get('profile_image_complete_path', '') if professional_profile else ''

            item['professional_image_complete_path'] = professional_profile_image_path

            enriched_items.append({
                'chat_info': item,
                'service_request_info': service_request_info
            })

        return {
            'statusCode': 200,
            'body': json.dumps(enriched_items, default=str)
        }

    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def get_all_chats(status_filter=None):
    print('[DEBUG INFO] Initializing get_all_chats...')
    try:
        kwargs = {}

        # Add status filter if provided
        if status_filter:
            kwargs['FilterExpression'] = boto3.dynamodb.conditions.Attr('chat_status').eq(status_filter)

        response = chats_table.scan(**kwargs)
        items = response.get('Items', [])

        # Handle pagination
        while 'LastEvaluatedKey' in response:
            kwargs['ExclusiveStartKey'] = response['LastEvaluatedKey']
            response = chats_table.scan(**kwargs)
            items.extend(response.get('Items', []))

        # Attach service request info to each chat item
        enriched_items = []

        for item in items:

            # Handle comm_messages sorting and get only most recent
            if item.get('comm_messages') and len(item['comm_messages']) > 0:
                # Sort comm_messages by created_at in descending order (newest first)
                sorted_messages = sorted(
                    item['comm_messages'],
                    key=lambda msg: msg.get('created_at', 0),
                    reverse=True
                )

                # Store only the most recent message
                last_message = sorted_messages[0]
                print(f'[DEBUG INFO] Last message: {last_message}')
                last_message['created_at'] = int(str(last_message['created_at']))
                item['last_comm_message'] = last_message

                # Remove the original comm_messages array
                del item['comm_messages']
            elif not item.get('comm_messages') or len(item['comm_messages']) == 0:
                # Create empty JSON object for last_comm_message when comm_messages is empty
                item['last_comm_message'] = {}
                # Remove the original comm_messages array if it exists but is empty
                if 'comm_messages' in item:
                    del item['comm_messages']

            service_request_info = None
            sr_id = item.get('services_requests_id')
            if sr_id:
                sr_response = services_requests_table.query(
                    KeyConditionExpression=Key('service_request_id').eq(sr_id),
                    Limit=1
                )
                sr_items = sr_response.get('Items', [])
                service_request_info = sr_items[0] if sr_items else None

            professional = item.get('professional') if item else None

            # Retrieve professional profile image path
            professional_profile = get_profile_details(professional)
            professional_profile_image_path = professional_profile.get('profile_image_complete_path', '') if professional_profile else ''

            item['professional_image_complete_path'] = professional_profile_image_path

            enriched_items.append({
                'chat_info': item,
                'service_request_info': service_request_info
            })

        return {
            'statusCode': 200,
            'body': json.dumps(enriched_items, default=str)
        }

    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def get_chat_info_for_ai(chat_id, ai_info):
    print('[DEBUG INFO] Initializing get_chat_info_for_ai...')
    try:
        chats_response = chats_table.get_item(
            Key={'chat_id': chat_id}
        )
        if 'Item' not in chats_response:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Chat not found'})
            }
        else:
            chat = chats_response['Item']
            comm_messages = chat.get('comm_messages', [])
            quotes = chat.get('quotes', [])
            services_requests_id = chat.get('services_requests_id')

            messages = []
            quotes_items = []
            quotes_comments = []
            sr_info = {}

            # Retrieve messages
            if comm_messages:
                for each_comm_message in comm_messages:
                    messages.append(each_comm_message['message_text'])

            # Retrieve quotes
            if quotes:
                for each_quote in quotes:
                    quote_id = each_quote['quote_id']
                    quote_response = quotes_table.get_item(
                        Key={'quote_id': quote_id, 'chat_id': chat_id}
                    )
                    if 'Item' in quote_response:
                        quote = quote_response['Item']
                        quote_comments_en = quote.get('comments_payments_en')
                        quotes_comments.append(quote_comments_en)
                        quote_comments_fr = quote.get('comments_payments_fr')
                        quotes_comments.append(quote_comments_fr)
                        quote_comments_es = quote.get('comments_payments_es')
                        quotes_comments.append(quote_comments_es)
                        quote_comments_pt = quote.get('comments_payments_pt')
                        quotes_comments.append(quote_comments_pt)
                        quote_line_items = quote.get('quote_line_items', [])
                        if quote_line_items:
                            for each_quote_line_item in quote_line_items:
                                each_quote_line_item['individual_price'] = float(each_quote_line_item['individual_price']) / 100
                                each_quote_line_item['item_quantity'] = float(each_quote_line_item['item_quantity']) / 100
                                each_quote_line_item['sum'] = float(each_quote_line_item['sum']) / 100
                            quotes_items.append(quote_line_items)

            # Retrieve service request info
            if services_requests_id:
                sr_response = services_requests_table.get_item(
                    Key={'service_request_id': services_requests_id}
                )
                if 'Item' in sr_response:
                    sr = sr_response['Item']
                    sr_info['title'] = sr.get('title')
                    sr_info['description'] = sr.get('description')
                    sr_info['themes'] = sr.get('SR_projects_themes')
                    sr_info['trades'] = sr.get ('SR_trades')


        return {
            'statusCode': 200,
            'body': json.dumps({'messages': messages, 'quotes': quotes_items, 'quotes_comments': quotes_comments, 'sr_info': sr_info})
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }


def delete_chat(payload):
    print('[DEBUG INFO] Initializing delete_chat...')
    try:
        chats_table.delete_item(Key={'chat_id': payload['chat_id']})
        return {
            'statusCode': 200,
            'body': json.dumps({'message': 'Chat deleted successfully'})
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def update_chat(payload):
    print('[DEBUG INFO] Initializing update_chat...')
    try:
        chat_id = payload['chat_id']

        new_messages_to_homeowner = False
        new_messages_to_pro = False

        output_data = {} # This dict will store sender/recipient

        if 'conversation_is_blocked' in payload and 'blocker' in payload:
            try:
                response = chats_table.get_item(
                    Key={'chat_id': chat_id}
                )
                if 'Item' not in response:
                    return {
                        'statusCode': 404,
                        'body': json.dumps({'error': 'Chat not found'})
                    }
                else:
                    chat = response['Item']
                    if chat.get('homeowner') == payload.get('blocker'):
                        blocked = chat.get('professional')
                    if chat.get('professional') == payload.get('blocker'):
                        blocked = chat.get('homeowner')
                    blocker = payload.get('blocker')

                if payload.get('conversation_is_blocked') == True:
                    update_response = chats_table.update_item(
                        Key={'chat_id': chat_id},
                        UpdateExpression="SET conversation_is_blocked = :conversation_is_blocked, updated_at = :updated_at, blocker = :blocker",
                        ExpressionAttributeValues={
                            ':conversation_is_blocked': payload.get('conversation_is_blocked'),
                            ':updated_at': datetime.datetime.utcnow().isoformat(),
                            ':blocker': payload.get('blocker')
                        },
                        ReturnValues='UPDATED_NEW'
                    )
                    # update blocked_list for the role_id:

                    role_id_blocked_list_updated = handle_block_unblock(blocker, blocked, 'block')

                    return {
                        'statusCode': 200,
                        'body': json.dumps({
                            'message': f'Successfully blocked conversation message(s)'
                        })
                    }
                else:
                    if payload.get('blocker') != response['Item'].get('blocker'):
                        return {
                            'statusCode': 400,
                            'body': json.dumps({'error': 'Invalid blocker'})
                        }
                    else:
                        update_response = chats_table.update_item(
                            Key={'chat_id': chat_id},
                            UpdateExpression="SET conversation_is_blocked = :conversation_is_blocked, updated_at = :updated_at, blocker = :blocker",
                            ExpressionAttributeValues={
                                ':conversation_is_blocked': payload.get('conversation_is_blocked'),
                                ':updated_at': datetime.datetime.utcnow().isoformat(),
                                ':blocker': ''
                            },
                            ReturnValues='UPDATED_NEW'
                        )
                        # update blocked_list for the role_id:
                        role_id_blocked_list_updated = handle_block_unblock(blocker, blocked, 'unblock')
                        return {
                            'statusCode': 200,
                            'body': json.dumps({
                                'message': f'Successfully unblocked conversation message(s)'
                            })
                        }

            except Exception as e:
                print(f"Error: {str(e)}")
                return {
                    'statusCode': 500,
                    'body': json.dumps({'error': f'Error blocking messages: {str(e)}'})
                }

        # Handle message deletion if requested
        if 'messages_ids_to_delete' in payload and payload['messages_ids_to_delete']:
            message_ids_to_delete = payload['messages_ids_to_delete']
            try:
                response = chats_table.get_item(
                    Key={'chat_id': chat_id}
                )

                if 'Item' not in response:
                    return {
                        'statusCode': 404,
                        'body': json.dumps({'error': 'Chat not found'})
                    }

                messages = response['Item'].get('comm_messages', [])

                new_messages = [msg for msg in messages if msg.get('message_id') not in message_ids_to_delete]

                if len(messages) == len(new_messages):
                    return {
                        'statusCode': 404,
                        'body': json.dumps({'error': 'None of the specified messages were found'})
                    }

                update_response = chats_table.update_item(
                    Key={'chat_id': chat_id},
                    UpdateExpression="SET comm_messages = :new_messages, updated_at = :updated_at",
                    ExpressionAttributeValues={
                        ':new_messages': new_messages,
                        ':updated_at': datetime.datetime.utcnow().isoformat()
                    },
                    ReturnValues='UPDATED_NEW'
                )

                deleted_count = len(messages) - len(new_messages)
                del payload['messages_ids_to_delete']

                return {
                    'statusCode': 200,
                    'body': json.dumps({
                        'message': f'Successfully deleted {deleted_count} message(s)',
                        'deletedCount': deleted_count
                    })
                }

            except Exception as e:
                print(f"Error: {str(e)}")
                return {
                    'statusCode': 500,
                    'body': json.dumps({'error': f'Error deleting messages: {str(e)}'})
                }

        # Regular update processing for all other cases
        update_expression = "SET updated_at = :updated_at" # updated_at will still be part of the DynamoDB update, but not the final response body
        expression_attribute_values = {":updated_at": datetime.datetime.utcnow().isoformat()}
        expression_attribute_names = {}

        print(f'[DEBUG INFO] Payload: {payload}')

        for key, value in payload.items():
            if key in ['chat_id', 'messages_ids_to_delete']:
                continue

            if key in ['quotes', 'invoices', 'appointments', 'reviews', 'comm_messages']:
                if isinstance(value, dict):
                    if 'add' in value:
                        # Only update comm_messages if it's the 'add' operation.
                        # For other list types, you might want them in the response, but for now, we're removing them.
                        update_expression += f", #{key} = list_append(if_not_exists(#{key}, :empty_list), :{key}_add)"
                        expression_attribute_values[f":{key}_add"] = value['add']
                        expression_attribute_values[":empty_list"] = []
                        expression_attribute_names[f"#{key}"] = key

                        if key == 'comm_messages' and value['add']:
                            new_message = value['add'][0]
                            sender_id = new_message.get('sender', '')

                            # Get current chat item to determine recipient
                            chat_response = chats_table.get_item(Key={'chat_id': chat_id})
                            chat_item = chat_response.get('Item', {})

                            service_request_id = chat_item.get('services_requests_id')
                            service_request = None
                            if service_request_id:
                                    sr_response = services_requests_table.query(
                                        KeyConditionExpression=Key('service_request_id').eq(service_request_id),
                                        Limit=1
                                    )
                                    service_request_items = sr_response.get('Items', [])
                                    service_request = service_request_items[0] if service_request_items else None

                                    if service_request:
                                        service_request_title = service_request['title']
                                        service_request_public_address = service_request['public_address']
                                        output_data['project'] = {f'name': service_request_title + ' - ' + service_request_public_address}

                            homeowner_id = chat_item.get('homeowner')
                            professional_id = chat_item.get('professional')
                            last_sms_to_homeowner = chat_item.get('last_sms_to_homeowner', None)
                            if last_sms_to_homeowner is not None:
                                last_sms_to_homeowner = datetime.datetime.fromisoformat(last_sms_to_homeowner)
                            last_sms_to_pro = chat_item.get('last_sms_to_pro', None)
                            if last_sms_to_pro is not None:
                                last_sms_to_pro = datetime.datetime.fromisoformat(last_sms_to_pro)


                            # Parse current_time string to datetime object
                            current_time = datetime.datetime.utcnow().isoformat()
                            current_dt = datetime.datetime.fromisoformat(current_time)
                            # Subtract 30 minutes
                            threshold_time = current_dt - datetime.timedelta(minutes=30)

                            sender_profile = None
                            recipient_profile = None

                            if sender_id == homeowner_id:
                                new_messages_to_pro = True
                                sender_profile = get_profile_details(homeowner_id)
                                recipient_profile = get_profile_details(professional_id)
                                recipient_role_id = professional_id
                                if last_sms_to_pro is None or last_sms_to_pro < threshold_time:
                                    send_sms_notification = True
                                    chats_table.update_item(
                                        Key={'chat_id': chat_id},
                                        UpdateExpression='SET last_sms_to_pro = :last_sms_to_pro',
                                        ExpressionAttributeValues={
                                            ':last_sms_to_pro': current_time
                                        },
                                        ReturnValues='NONE'
                                    )

                            elif sender_id == professional_id:
                                new_messages_to_homeowner = True
                                sender_profile = get_profile_details(professional_id)
                                recipient_profile = get_profile_details(homeowner_id)
                                recipient_role_id = homeowner_id
                                if last_sms_to_homeowner is None or last_sms_to_homeowner < threshold_time:
                                    send_sms_notification = True
                                    chats_table.update_item(
                                        Key={'chat_id': chat_id},
                                        UpdateExpression='SET last_sms_to_homeowner = :last_sms_to_homeowner',
                                        ExpressionAttributeValues={
                                            ':last_sms_to_homeowner': current_time
                                        },
                                        ReturnValues='NONE'
                                    )

                            else:
                                print(f"[WARNING] Sender ID {sender_id} does not match homeowner or professional ID for chat {chat_id}. Attempting to retrieve sender profile.")
                                sender_profile = get_profile_details(sender_id)

                            if sender_profile:
                                output_data['sender'] = {'name': sender_profile.get('name')}
                            else:
                                print(f"[WARNING] Could not retrieve sender profile for ID: {sender_id}")

                            if recipient_profile:
                                output_data['recipient'] = {
                                    'name': recipient_profile.get('name'),
                                    'email': recipient_profile.get('email'),
                                    'phone': recipient_profile.get('phone'),
                                    'language': recipient_profile.get('language'),
                                    'role_id': recipient_role_id
                                }
                            else:
                                print(f"[WARNING] Could not retrieve recipient profile for chat {chat_id}. Sender was {sender_id}.")

                    elif 'remove' in value:
                        # For 'remove' operations on comm_messages, or other lists, these fields
                        # are also not desired in the final simplified 'result' output.
                        update_expression += f", #{key} = list_remove(#{key}, :{key}_remove)"
                        expression_attribute_values[f":{key}_remove"] = value['remove']
                        expression_attribute_names[f"#{key}"] = key
                else:
                    # For updates to whole lists (e.g., if a list is entirely replaced, not added/removed from)
                    # these fields are also not desired in the final simplified 'result' output.
                    update_expression += f", #{key} = :{key}"
                    expression_attribute_values[f":{key}"] = value
                    expression_attribute_names[f"#{key}"] = key

            else:
                # For any other top-level attributes in the payload (e.g., status, new_messages_to_homeowner/pro if they were
                # explicitly set as top-level payload keys to be updated in DB), they will be updated in DynamoDB,
                # but NOT included in the simplified 'result' output.
                update_expression += f", #{key} = :{key}"
                expression_attribute_values[f":{key}"] = value
                expression_attribute_names[f"#{key}"] = key

        # These flags are specifically for DB updates, not for the simplified response body
        if new_messages_to_homeowner:
            update_expression += ", #new_messages_to_homeowner = :new_messages_to_homeowner"
            expression_attribute_values[":new_messages_to_homeowner"] = True
            expression_attribute_names["#new_messages_to_homeowner"] = "new_messages_to_homeowner"

        if new_messages_to_pro:
            update_expression += ", #new_messages_to_pro = :new_messages_to_pro"
            expression_attribute_values[":new_messages_to_pro"] = True
            expression_attribute_names["#new_messages_to_pro"] = "new_messages_to_pro"

        # Perform the DynamoDB update
        response = chats_table.update_item(
            Key={'chat_id': chat_id},
            UpdateExpression=update_expression,
            ExpressionAttributeValues=expression_attribute_values,
            ExpressionAttributeNames=expression_attribute_names,
            ReturnValues="UPDATED_NEW" # We still ask for updated attributes, but only use 'output_data' for response
        )

        # Construct the response_body to contain ONLY sender and recipient
        # Initialize with output_data which already has 'sender' and 'recipient' if they were found.
        response_body = {}
        response_body['send_sms_notification'] = send_sms_notification
        if 'sender' in output_data:
            response_body['sender'] = output_data['sender']
        if 'recipient' in output_data:
            response_body['recipient'] = output_data['recipient']
        if 'project' in output_data:
            response_body['project'] = output_data['project']

        # No other attributes from response['Attributes'] are included,
        # thereby removing new_messages_to_homeowner, updated_at, and comm_messages from the result.

        return {
            'statusCode': 200,
            'body': json.dumps(response_body, default=str)
        }

    except Exception as e:
        print(f"Error in update_chat: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def handle_block_unblock(author_role_id, blocked_role_id, action):
    print("[DEBUG] Starting handle_block_unblock function...")
    author_response = roles_table.query(
        IndexName='role_id-index',
        KeyConditionExpression=Key('role_id').eq(author_role_id),
        Limit=1
    )
    print(f"[DEBUG] Author role: {author_response}")

    author_items = author_response.get('Items', [])
    author = author_items[0] if author_items else None

    if not author:
        print("[ERROR] Author not found")
        return create_error_response(404, "Author not found")

    blocked_list = author.get('blocked_list', [])
    if blocked_role_id not in blocked_list and action == 'block':
        blocked_list.append(blocked_role_id)
    if blocked_role_id in blocked_list and action == 'unblock':
        blocked_list.remove(blocked_role_id)

    update_author = roles_table.update_item(
        Key={'xano_user_id': author['xano_user_id'], 'role_id': author['role_id']},
        UpdateExpression='SET blocked_list = :blocked_list',
        ExpressionAttributeValues={':blocked_list': blocked_list}
    )
    print("[DEBUG] Blocked list updated successfully")
