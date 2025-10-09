import boto3
import os
import uuid
import json
import datetime
import traceback
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from decimal import Decimal
from boto3.dynamodb.types import TypeSerializer, TypeDeserializer
import requests
from requests.auth import HTTPBasicAuth

# Initialize DynamoDB resources
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('roles_dev')

# OpenSearch configuration for professional profiles
OPENSEARCH_ENDPOINT = 'https://search-connecus-home-xter5mxymdzivmnio2iuvwgg4a.us-east-2.es.amazonaws.com'
OPENSEARCH_PROFILES_INDEX = 'pros_from_xano_dev'  # This index is specifically for professionals
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

def create_error_response(status_code, message):
    """
    Helper function to create standardized error responses.
    """
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps({'error': message if isinstance(message, str) else str(message)})
    }

def create_success_response(data, status_code=200):
    """
    Helper function to create standardized success responses.
    """
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps(data, default=str)
    }

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
    REQUEST_TIMEOUT = 60  # seconds

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
            response = table.query(
                IndexName='role_id-index',  # Specify the GSI name
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

def lambda_handler(event, context):
    """
    Main Lambda handler function that routes requests based on HTTP method.
    """
    try:
        operation = event.get('httpMethod')
        if not operation:
            return create_error_response(400, 'HTTP method not specified')

        # Parse payload based on operation
        if operation == 'GET':
            payload = event.get('queryStringParameters') or {}
        else:
            body = event.get('body')
            if body:
                try:
                    payload = json.loads(body)
                except json.JSONDecodeError:
                    return create_error_response(400, 'Invalid JSON in request body')
            else:
                payload = {}

        print(f"[DEBUG] Processing {operation} request with payload: {payload}")

        # Route to appropriate handler
        if operation == 'PUT':
            if 'author_role_id' in payload and 'blocked_role_id' in payload and 'action' in payload:
                author_role_id = payload['author_role_id']
                blocked_role_id = payload['blocked_role_id']
                action = payload['action']
                return handle_block_unblock(author_role_id, blocked_role_id, action)
            else:
                return update_item(payload)
        elif operation == 'POST':
            return create_item(payload)
        elif operation == 'GET':
            return handle_get(event, payload)
        elif operation == 'DELETE':
            return delete_item(payload)
        else:
            return create_error_response(400, f'Unsupported HTTP method: {operation}')

    except Exception as e:
        print(f"[ERROR] Unexpected error in lambda_handler: {e}")
        traceback.print_exc()
        return create_error_response(500, 'Internal server error')

def create_item(payload):
    """
    Creates a new item in the DynamoDB table.
    """
    print('[DEBUG] Creating a new item...')

    # Validate required fields
    required_fields = ['xano_user_id', 'role_id', 'role_type', 'role_display_name', 
                      'xano_user_type', 'xano_acct_id', 'language', 'is_premium', 
                      'email', 'location']
    
    missing_fields = [field for field in required_fields if field not in payload]
    if missing_fields:
        return create_error_response(400, f'Missing required fields: {missing_fields}')

    today = datetime.datetime.now().date()
    today_str = today.strftime('%Y-%m-%d')
    
    try:
        item = {
            'xano_user_id': payload['xano_user_id'],  # Partition key
            'role_id': payload['role_id'],            # Sort key
            'role_type': payload['role_type'],
            'role_display_name': payload['role_display_name'],
            'xano_user_type': payload['xano_user_type'],
            'xano_acct_id': payload['xano_acct_id'],
            'language': payload['language'],
            'is_premium': payload['is_premium'],
            'email': payload['email'],
            'location': payload['location'],
            'created_at': today_str,
            'updated_at': today_str,
            'blocked_list': []
        }
        
        # Add optional fields with defaults
        optional_fields = {
            'name': '',
            'phone_country': '',
            'phone': '',
            'xano_profile_id': None
        }
        
        for field, default_value in optional_fields.items():
            item[field] = payload.get(field, default_value)

        # Check if item with this composite key already exists
        response = table.put_item(
            Item=item,
            ConditionExpression='attribute_not_exists(xano_user_id) AND attribute_not_exists(role_id)'
        )
        
        print(f"[DEBUG] Created item: {item}")
        return create_success_response({'message': 'Item created successfully', 'item': item})
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
            print(f"[WARNING] Item already exists: xano_user_id={payload['xano_user_id']}, role_id={payload['role_id']}")
            return create_error_response(409, f"Item with xano_user_id: {payload['xano_user_id']} and role_id: {payload['role_id']} already exists")
        else:
            print(f"[ERROR] ClientError creating item: {e}")
            return create_error_response(500, f'Error creating item: {e.response["Error"]["Message"]}')
    except Exception as e:
        print(f"[ERROR] Unexpected error creating item: {e}")
        traceback.print_exc()
        return create_error_response(500, f'Unexpected error creating item: {str(e)}')

def handle_get(event, payload):
    """
    Handles GET requests by routing to appropriate retrieval function.
    """
    print('[DEBUG] ===== HANDLE GET FUNCTION START =====')
    print(f'[DEBUG] Event received: {event}')
    print(f'[DEBUG] Payload received: {payload}')
    
    try:
        # Check if role_id exists in payload
        if 'role_id' in payload and payload['role_id']:
            if 'only_xano_ids' in payload:
                print('[DEBUG] Calling get_one_with_only_xano_ids function...')
                result = get_one_with_only_xano_ids (payload['role_id'])
            else:
                print(f'[DEBUG] Found role_id: {payload["role_id"]}')
                print('[DEBUG] Calling get_one function to retrieve a specific item...')
                
                result = get_one(payload['role_id'])
                print(f'[DEBUG] get_one function returned: status code {result["statusCode"]}')
            return result
        # If no role_id but xano_user_id exists
        elif 'xano_user_id' in payload and payload['xano_user_id']:
            print(f'[DEBUG] Found xano_user_id: {payload["xano_user_id"]}')
            print('[DEBUG] Calling get_by_user function to retrieve all items for this user...')
            
            result = get_by_user(payload['xano_user_id'])
            print(f'[DEBUG] get_by_user function returned: status code {result["statusCode"]}')
            return result
        else:
            print('[ERROR] Neither role_id nor xano_user_id found in payload!')
            return create_error_response(400, 'Either role_id or xano_user_id is required')
            
    except Exception as e:
        print(f'[ERROR] EXCEPTION in handle_get: {type(e).__name__}')
        print(f'[ERROR] Exception message: {str(e)}')
        traceback.print_exc()
        return create_error_response(500, str(e))
    finally:
        print('[DEBUG] ===== HANDLE GET FUNCTION END =====')

def get_one(role_id):
    """
    Retrieves a single item by role_id using GSI.
    """
    print(f'[DEBUG] Initializing get_one function with role_id={role_id}...')
    
    if not role_id:
        return create_error_response(400, 'role_id is required')
    
    try:
        # Query using the role_id-index (GSI)
        response = table.query(
            IndexName='role_id-index',
            KeyConditionExpression=Key('role_id').eq(role_id)
        )
        
        items = response.get('Items', [])
        
        if items and len(items) > 0:
            person = items[0]
            print(f"[DEBUG] Retrieved item: {person}")
            
            # Process blocked list if it exists and user is a homeowner
            if (person.get('blocked_list') and 
                person['blocked_list'] != [] and 
                person.get('role_type') == 'HOMEOWNER'):
                
                print(f"[DEBUG] Processing blocked list: {person['blocked_list']}")
                new_blocked_list = []
                
                for blocked_item in person['blocked_list']:
                    print(f"[DEBUG] Processing blocked item: {blocked_item}")
                    try:
                        blocked_profile = get_pro_by_role_id(blocked_item)
                        if blocked_profile.get('statusCode') == 200:
                            blocked_data = json.loads(blocked_profile['body'])
                            new_blocked_list.append(blocked_data.get('professional', {}))
                        else:
                            print(f"[WARNING] Could not retrieve blocked profile for {blocked_item}")
                    except Exception as e:
                        print(f"[ERROR] Error processing blocked item {blocked_item}: {e}")
                
                # Update the item with processed blocked list
                person['blocked_list'] = new_blocked_list

            # Process blocked list if it exists and user is a professional
            if (person.get('blocked_list') and 
                person['blocked_list'] != [] and 
                person.get('role_type') == 'PRO'):
                
                print(f"[DEBUG] Processing blocked list: {person['blocked_list']}")
                new_blocked_list = []
                
                for blocked_item in person['blocked_list']:
                    print(f"[DEBUG] Processing blocked item: {blocked_item}")
                    try:
                        # blocked_profile = get_pro_by_role_id(blocked_item)
                        blocked_response = table.query(
                            IndexName='role_id-index',
                            KeyConditionExpression=Key('role_id').eq(blocked_item)
                        )
                        blocked_response_items = blocked_response.get('Items', [])
                        
                        if blocked_response_items and len(blocked_response_items) > 0:
                            person = blocked_response_items[0]
                            person_to_return = {
                                'role_id': person['role_id'],
                                'name': person['name']
                            }
                            new_blocked_list.append(person_to_return)
                        else:
                            print(f"[WARNING] Could not retrieve blocked profile for {blocked_item}")
                    except Exception as e:
                        print(f"[ERROR] Error processing blocked item {blocked_item}: {e}")
                
                # Update the item with processed blocked list
                person['blocked_list'] = new_blocked_list

            return create_success_response(person)

        else:
            print("[WARNING] Item not found")
            return create_error_response(404, 'Item not found')
            
    except Exception as e:
        print(f"[ERROR] Error getting item: {e}")
        traceback.print_exc()
        return create_error_response(500, f'Error getting item: {str(e)}')

def get_one_with_only_xano_ids (role_id):
    try:
        response = table.query(
            IndexName='role_id-index',
            KeyConditionExpression=Key('role_id').eq(role_id)
        )
        items = response.get('Items', [])
        if items and len(items) > 0:
            person = items[0]
        
        xano_info = {}
        xano_info['xano_user_id'] = int(person.get('xano_user_id'))
        xano_info['xano_user_type'] = person.get('xano_user_type')
        xano_info['xano_profile_id'] = int(person.get('xano_profile_id', 0))
        xano_info['xano_acct_id'] = int(person.get('xano_acct_id'))

        return create_success_response(xano_info)
    except Exception as e:
        print(f"[ERROR] Error getting item: {e}")
        traceback.print_exc()
        return create_error_response(500, f'Error getting item: {str(e)}')

def get_by_user(xano_user_id):
    """
    Retrieves all items for a specific user.
    """
    print(f'[DEBUG] Initializing get_by_user function with xano_user_id={xano_user_id}...')
    
    if not xano_user_id:
        return create_error_response(400, 'xano_user_id is required')
    
    try:
        print(f"[DEBUG] Preparing to query for xano_user_id: {xano_user_id}")
        
        # Use query to get all items for this user
        response = table.query(
            KeyConditionExpression=Key('xano_user_id').eq(xano_user_id)
        )
        
        print(f"[DEBUG] Query response received: {response}")
        
        items = response.get('Items', [])
        print(f"[DEBUG] Number of items found: {len(items)}")
        
        return create_success_response(items)
        
    except Exception as e:
        print(f"[ERROR] Error type: {type(e).__name__}")
        print(f"[ERROR] Error message: {str(e)}")
        traceback.print_exc()
        return create_error_response(500, f'Error getting items: {str(e)}')

def delete_item(payload):
    """
    Deletes an item from the DynamoDB table.
    """
    print('[DEBUG] Deleting an item...')
    
    try:
        # Ensure we have the role_id to identify the item
        role_id = payload.get('role_id')
        if not role_id:
            return create_error_response(400, 'role_id is required for deletion')
        
        # First, get the item to delete using GSI
        get_response = table.query(
            IndexName='role_id-index',
            KeyConditionExpression=Key('role_id').eq(role_id)
        )
        
        items = get_response.get('Items', [])
        if not items:
            return create_error_response(404, 'Item not found')
        
        # Get the partition key value from the found item
        xano_user_id = items[0]['xano_user_id']
        
        # Delete the item using the composite key
        table.delete_item(
            Key={
                'xano_user_id': xano_user_id,
                'role_id': role_id
            }
        )
        
        print(f"[DEBUG] Deleted item with xano_user_id: {xano_user_id}, role_id: {role_id}")
        return create_success_response({'message': 'Item deleted successfully'})
        
    except Exception as e:
        print(f"[ERROR] Error deleting item: {e}")
        traceback.print_exc()
        return create_error_response(500, f'Error deleting item: {str(e)}')

def update_item(payload):
    """
    Update an item in DynamoDB table using the provided payload.
    Since the table has composite keys (xano_user_id + role_id), we need both keys.
    If only role_id is provided, we'll query the GSI first to get the xano_user_id.
    
    Args:
        payload (dict): Dictionary containing role_id and fields to update
        
    Returns:
        dict: Updated item or error information
    """
    # Reserved keywords that need to be handled with expression attribute names
    DDB_RESERVED_KEYWORDS = {'NAME', 'LOCATION', 'SIZE', 'TYPE', 'STATUS'}

    try:
        print(f"[DEBUG] Starting update_item with payload: {payload}")
        
        # Extract the role_id (this is required to identify the item)
        role_id = payload.get('role_id')
        xano_user_id = payload.get('xano_user_id')
        
        print(f"[DEBUG] Extracted role_id: {role_id}")
        print(f"[DEBUG] Extracted xano_user_id: {xano_user_id}")
        
        if not role_id:
            print("[ERROR] role_id is missing from payload")
            return create_error_response(400, 'role_id is required in payload')
        
        # If xano_user_id is not provided, query the GSI to find it
        if not xano_user_id:
            print("[DEBUG] xano_user_id not provided, querying GSI to find it")
            try:
                print(f"[DEBUG] Querying GSI 'role_id-index' with role_id: {role_id}")
                gsi_response = table.query(
                    IndexName='role_id-index',
                    KeyConditionExpression=Key('role_id').eq(role_id),
                    Limit=1
                )
                
                print(f"[DEBUG] GSI query response: {gsi_response}")
                
                if not gsi_response['Items']:
                    print("[WARNING] No items found in GSI query")
                    return create_error_response(404, 'Item with specified role_id not found')
                
                xano_user_id = gsi_response['Items'][0]['xano_user_id']
                print(f"[DEBUG] Found xano_user_id from GSI: {xano_user_id}")
                
            except ClientError as e:
                print(f"[ERROR] ClientError during GSI query: {e}")
                return create_error_response(500, f'Error querying GSI: {e.response["Error"]["Message"]}')
        else:
            print("[DEBUG] xano_user_id provided in payload, skipping GSI query")
        
        # Create update fields (exclude keys)
        update_fields = {k: v for k, v in payload.items() 
                        if k not in ['xano_user_id', 'role_id']}
        
        print(f"[DEBUG] Update fields to process: {update_fields}")
        
        if not update_fields:
            print("[WARNING] No fields to update found")
            return create_error_response(400, 'No fields to update provided')
        
        # Add updated_at timestamp
        today = datetime.datetime.now().date()
        today_str = today.strftime('%Y-%m-%d')
        update_fields['updated_at'] = today_str
        
        # Build the update expression components
        update_expression_parts = []
        expression_attribute_names = {}
        expression_attribute_values = {}
        
        print("[DEBUG] Building update expression...")
        
        for field_name, field_value in update_fields.items():
            print(f"[DEBUG] Processing field '{field_name}' with value '{field_value}'")
            
            # Check if field name is a reserved keyword
            if field_name.upper() in DDB_RESERVED_KEYWORDS:
                print(f"[DEBUG] '{field_name}' is a reserved keyword, using expression attribute name")
                # Use expression attribute name for reserved keywords
                attr_name_key = f"#{field_name}"
                expression_attribute_names[attr_name_key] = field_name
                attr_value_key = f":{field_name}"
                update_expression_parts.append(f"{attr_name_key} = {attr_value_key}")
            else:
                print(f"[DEBUG] '{field_name}' is not a reserved keyword")
                # Use field name directly for non-reserved keywords
                attr_value_key = f":{field_name}"
                update_expression_parts.append(f"{field_name} = {attr_value_key}")
            
            # Convert numeric values to Decimal for DynamoDB compatibility
            if isinstance(field_value, (int, float)):
                print(f"[DEBUG] Converting numeric value {field_value} to Decimal")
                expression_attribute_values[attr_value_key] = Decimal(str(field_value))
            else:
                print(f"[DEBUG] Using value as-is: {field_value}")
                expression_attribute_values[attr_value_key] = field_value
        
        # Construct the complete update expression
        update_expression = "SET " + ", ".join(update_expression_parts)
        print(f"[DEBUG] Final update expression: {update_expression}")
        print(f"[DEBUG] Expression attribute names: {expression_attribute_names}")
        print(f"[DEBUG] Expression attribute values: {expression_attribute_values}")
        
        # Prepare the update_item parameters with composite keys
        update_params = {
            'Key': {
                'xano_user_id': xano_user_id,  # partition key
                'role_id': role_id             # sort key
            },
            'UpdateExpression': update_expression,
            'ExpressionAttributeValues': expression_attribute_values,
            'ReturnValues': 'ALL_NEW'
        }
        
        # Add expression attribute names only if we have reserved keywords
        if expression_attribute_names:
            update_params['ExpressionAttributeNames'] = expression_attribute_names
            print("[DEBUG] Added expression attribute names to update params")
        
        print(f"[DEBUG] Final update_item parameters: {update_params}")
        
        # Execute the update
        print("[DEBUG] Executing DynamoDB update_item...")
        response = table.update_item(**update_params)
        
        print(f"[DEBUG] Update successful! Response: {response}")
        
        updated_item = response.get('Attributes', {})
        return create_success_response({
            'message': 'Item updated successfully',
            'item': updated_item
        })
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        
        print(f"[ERROR] ClientError occurred - Code: {error_code}, Message: {error_message}")
        
        if error_code == 'ResourceNotFoundException':
            return create_error_response(404, 'Table not found')
        elif error_code == 'ConditionalCheckFailedException':
            return create_error_response(404, 'Item not found')
        else:
            return create_error_response(500, f'DynamoDB error: {error_message}')
    
    except Exception as e:
        print(f"[ERROR] Unexpected exception occurred: {type(e).__name__}")
        print(f"[ERROR] Exception message: {str(e)}")
        traceback.print_exc()
        return create_error_response(500, f'Unexpected error: {str(e)}')

def handle_block_unblock(author_role_id, blocked_role_id, action):
    print("[DEBUG] Starting handle_block_unblock function...")
    author_response = table.query(
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

    update_author = table.update_item(
        Key={'xano_user_id': author['xano_user_id'], 'role_id': author['role_id']},
        UpdateExpression='SET blocked_list = :blocked_list',
        ExpressionAttributeValues={':blocked_list': blocked_list}
    )
    print("[DEBUG] Blocked list updated successfully")
    return create_success_response({"message": "Blocked list updated successfully"})

def get_pro_by_role_id(role_id):
    """
    Get professional profile from OpenSearch by role_id using two-step process.
    """
    try:
        if not role_id:
            return create_error_response(400, "role_id is required")
            
        # Step 1: Get role data from DynamoDB
        role_response = table.query(
            IndexName='role_id-index',
            KeyConditionExpression=Key('role_id').eq(role_id),
            Limit=1
        )
        
        if not role_response.get('Items'):
            print(f"[WARNING] No role found for role_id: {role_id}")
            return create_error_response(404, "Role not found")
            
        role_data = role_response['Items'][0]
        xano_user_type = role_data.get('xano_user_type')
        xano_profile_id = role_data.get('xano_profile_id')
        
        if not xano_user_type or not xano_profile_id:
            print(f"[WARNING] Missing xano_user_type or xano_profile_id for role_id: {role_id}")
            return create_error_response(404, "Invalid role data")
            
        # Step 2: Construct OpenSearch document ID and get professional
        open_search_document_id = f"{xano_user_type}_{xano_profile_id}"
        
        return get_pro_by_opensearch_doc_id(open_search_document_id, role_id)
      
    except Exception as e:
        print(f"[ERROR] Error getting professional by role_id {role_id}: {e}")
        traceback.print_exc()
        return create_error_response(500, "Error retrieving professional")

def get_pro_by_opensearch_doc_id(opensearch_doc_id, role_id):
    """
    Retrieves a single professional document from OpenSearch by its document ID.
    """
    print(f"[DEBUG] Getting professional from OpenSearch with doc_id: {opensearch_doc_id}")

    if not opensearch_doc_id:
        return create_error_response(400, "Document ID is required")
        
    if not opensearch_auth:
        return create_error_response(500, "OpenSearch authentication not available")

    url = f"{OPENSEARCH_ENDPOINT}/{OPENSEARCH_PROFILES_INDEX}/_doc/{opensearch_doc_id}"

    try:
        response = requests.get(url, auth=opensearch_auth, headers=headers)
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)

        json_response = response.json()
        print(f"[DEBUG] OpenSearch response for doc ID {opensearch_doc_id}: {json_response}")

        if not json_response.get('found', False):
            return create_error_response(404, "Professional not found")

        # Safely access the document data - note the nested 'doc' structure
        source_data = json_response.get('_source', {})
        doc = source_data.get('doc', {})
        print(f"[DEBUG] OpenSearch doc: {doc}")
        
        if not doc:
            return create_error_response(404, "Professional document is empty")
        
        # Extract only the required fields
        profile_to_return = {
            'role_id': doc.get('role_id_on_dynamo', role_id),  # Use role_id_on_dynamo from doc, fallback to parameter
            'name': doc.get('name', ''),
            'profile_image_complete_path': doc.get('profile_image_complete_path', '')
        }

        return create_success_response({
            'professional': profile_to_return
        })

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Request error getting professional from OpenSearch: {e}")
        return create_error_response(500, f"Request error: {str(e)}")
    except json.JSONDecodeError as e:
        print(f"[ERROR] JSON decoding error in OpenSearch response: {e}")
        return create_error_response(500, f"JSON decoding error: {str(e)}")
    except Exception as e:
        print(f"[ERROR] Unexpected error getting professional from OpenSearch: {e}")
        traceback.print_exc()
        return create_error_response(500, "Error retrieving professional")