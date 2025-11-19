import json
import boto3
import datetime
from boto3.dynamodb.conditions import Key, Attr
import base64
import os
from google.oauth2 import service_account
from google.cloud import storage

# Initialize DynamoDB resource
dynamodb = boto3.resource('dynamodb')
tasks_communications_table = dynamodb.Table('tasks_communications_dev')
tasks_documentation_table = dynamodb.Table('tasks_documentation_dev')

# Initialize Google Storage client with credentials
creds_json = base64.b64decode(os.environ['GOOGLE_CREDENTIALS_JSON'])
creds = service_account.Credentials.from_service_account_info(json.loads(creds_json))
storage_client = storage.Client(credentials=creds)

# Google Cloud Storage configuration
GCS_BUCKET_NAME = 'hadronlink_pictures'


def add_file_urls_to_messages(messages):
    """
    Adds file_url field to messages that have file_complete_google_name
    Generates signed URLs that are valid for 30 minutes

    Args:
        messages: List of message dictionaries

    Returns:
        List of messages with file_url added where applicable
    """
    if not messages:
        return messages

    bucket = storage_client.bucket(GCS_BUCKET_NAME)

    for msg in messages:
        file_name = msg.get('file_complete_google_name', '')
        if file_name:
            try:
                # Generate signed URL valid for 30 minutes
                blob = bucket.blob(file_name)
                signed_url = blob.generate_signed_url(
                    version="v4",
                    expiration=datetime.timedelta(minutes=30),
                    method="GET"
                )
                msg['file_url'] = signed_url
            except Exception as e:
                print(f"[ERROR] Failed to generate signed URL for {file_name}: {str(e)}")
                msg['file_url'] = ''
        else:
            msg['file_url'] = ''

    return messages


def lambda_handler(event, context):
    """
    Main Lambda handler for tasks_communications CRUD operations
    """
    operation = event['httpMethod']
    payload = event['queryStringParameters'] if operation == 'GET' else json.loads(event['body']) if event.get('body') else {}

    try:
        if operation == 'POST':
            if payload.get('is_task_documentation'):
                return create_task_documentation(payload)
            elif payload.get('duplicate_documentation') and payload.get('original_task_id'):
                return duplicate_task_documentation(payload)
            else:
                return create_task_communication(payload)
        elif operation == 'GET':
            return handle_get(payload)
        elif operation == 'PUT':
            return update_task_communication(payload)
        elif operation == 'DELETE':
            return delete_task_communication(payload)
        else:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Invalid HTTP method'})
            }
    except Exception as e:
        print(f"[ERROR] Lambda handler error: {str(e)}")
        import traceback
        print(f"[ERROR] Full traceback: {traceback.format_exc()}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }


def create_task_communication(payload):
    """
    Creates a new task communication record or updates existing if supervisor was previously assigned

    If a supervisor is being reassigned (supervisor_xano_profile_contractor_id exists in another
    task_communication for the same task), the existing record will be updated instead of creating a new one.

    Required fields:
    - xano_task_id
    - task_communication_id (must start with "TASKCOMM#")
    - task_owner_xano_profile_contractor_id
    - task_owner_name
    """
    print('[DEBUG INFO] Initializing create_task_communication...')

    try:
        # Validate required fields
        required_fields = ['xano_task_id', 'task_communication_id', 'task_owner_xano_profile_contractor_id', 'task_owner_name']
        for field in required_fields:
            if field not in payload:
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': f'Missing required field: {field}'})
                }

        # Validate task_communication_id format
        task_communication_id = payload['task_communication_id']
        if not task_communication_id.startswith('TASKCOMM#'):
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'task_communication_id must start with "TASKCOMM#"'})
            }

        xano_task_id = payload['xano_task_id']
        supervisor_id = payload.get('supervisor_xano_profile_contractor_id', '')

        # If a supervisor is being assigned, check if they were previously assigned to this task
        if supervisor_id:
            print(f'[DEBUG INFO] Checking for existing task_communication for supervisor: {supervisor_id}')

            # Query all task_communications for this task
            response = tasks_communications_table.query(
                KeyConditionExpression=Key('xano_task_id').eq(xano_task_id)
            )

            existing_items = response.get('Items', [])

            # Handle pagination if needed
            while 'LastEvaluatedKey' in response:
                response = tasks_communications_table.query(
                    KeyConditionExpression=Key('xano_task_id').eq(xano_task_id),
                    ExclusiveStartKey=response['LastEvaluatedKey']
                )
                existing_items.extend(response.get('Items', []))

            # Check if supervisor already has a task_communication for this task
            existing_supervisor_record = None
            for item in existing_items:
                if item.get('supervisor_xano_profile_contractor_id') == supervisor_id:
                    existing_supervisor_record = item
                    print(f'[DEBUG INFO] Found existing task_communication for supervisor: {item["task_communication_id"]}')
                    break

            # If supervisor was previously assigned, update the existing record
            if existing_supervisor_record:
                current_time = datetime.datetime.utcnow().isoformat()
                existing_task_communication_id = existing_supervisor_record['task_communication_id']

                print(f'[DEBUG INFO] Updating existing task_communication: {existing_task_communication_id}')

                tasks_communications_table.update_item(
                    Key={
                        'xano_task_id': xano_task_id,
                        'task_communication_id': existing_task_communication_id
                    },
                    UpdateExpression='''SET
                        supervisor_xano_profile_contractor_id = :supervisor_id,
                        supervisor_name = :supervisor_name,
                        supervisor_access_is_active = :active,
                        supervisor_acceptance_date = :acceptance_date,
                        supervisor_end_date = :end_date,
                        updated_at = :updated_at''',
                    ExpressionAttributeValues={
                        ':supervisor_id': supervisor_id,
                        ':supervisor_name': payload.get('supervisor_name', ''),
                        ':active': True,
                        ':acceptance_date': current_time,
                        ':end_date': '',
                        ':updated_at': current_time
                    },
                    ReturnValues='NONE'
                )

                print(f"[DEBUG INFO] Task communication updated for reassigned supervisor: {existing_task_communication_id}")

                return {
                    'statusCode': 200,
                    'body': json.dumps({
                        'message': 'Task communication updated for reassigned supervisor',
                        'task_communication_id': existing_task_communication_id
                    })
                }

        # If no existing supervisor record found, create a new task_communication
        current_time = datetime.datetime.utcnow().isoformat()

        # Build the item
        item = {
            'xano_task_id': xano_task_id,
            'task_communication_id': task_communication_id,
            'task_owner_xano_profile_contractor_id': payload['task_owner_xano_profile_contractor_id'],
            'task_owner_name': payload['task_owner_name'],
            'supervisor_xano_profile_contractor_id': supervisor_id,
            'supervisor_name': payload.get('supervisor_name', ''),
            'supervisor_access_is_active': payload.get('supervisor_access_is_active', False),
            'supervisor_acceptance_date': current_time,
            'supervisor_end_date': payload.get('supervisor_end_date', ''),
            'messages': [],
            'new_messages_to_task_owner': False,
            'new_messages_to_supervisor': False,
            'created_at': current_time,
            'updated_at': current_time
        }

        # Create the item in DynamoDB with condition to prevent overwrites
        tasks_communications_table.put_item(
            Item=item,
            ConditionExpression='attribute_not_exists(xano_task_id) AND attribute_not_exists(task_communication_id)'
        )

        print(f"[DEBUG INFO] Task communication created successfully: {task_communication_id}")

        return {
            'statusCode': 201,
            'body': json.dumps({
                'message': 'Task communication created successfully',
                'task_communication_id': task_communication_id
            })
        }

    except Exception as e:
        print(f"[ERROR] Failed to create task communication: {str(e)}")
        import traceback
        print(f"[ERROR] Full traceback: {traceback.format_exc()}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }



def duplicate_task_documentation(payload):
    """
    Duplicates a task documentation from an original task to a new task, bringing over all images.

    Required fields:
    - xano_task_id
    - project_owner_xano_profile_contractor_id
    - project_owner_name
    - task_owner_xano_profile_contractor_id
    - task_owner_name
    - original_task_id
    """
    print('[DEBUG INFO] Initializing duplicate_task_documentation...')

    try:
        # Validate required fields
        required_fields = ['xano_task_id', 'task_communication_id', 'project_owner_xano_profile_contractor_id', 'project_owner_name', 
                           'task_owner_xano_profile_contractor_id', 'task_owner_name', 'original_task_id']
        for field in required_fields:
            if field not in payload:
                print({'error': f'Missing required field: {field}'})
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': f'Missing required field: {field}'})
                }
        
        # Build the item
        item = {
            'xano_task_id': payload['xano_task_id'],
            'task_owner_xano_profile_contractor_id': payload['task_owner_xano_profile_contractor_id'],
            'task_owner_name': payload['task_owner_name'],
            'project_owner_xano_profile_contractor_id': payload['project_owner_xano_profile_contractor_id'],
            'project_owner_name': payload.get('project_owner_name', ''),
            'messages': [],
            'new_messages_to_task_owner': False,
            'new_messages_to_project_owner': False,
            'created_at': current_time,
            'updated_at': current_time
        }

        # Fetch the original task documentation
        original_task_id = payload['original_task_id']
        response = tasks_documentation_table.get_item(
            Key={
                'xano_task_id': original_task_id
            }
        )

        if 'Item' not in response:
            print({'[DEBUG INFO] error: Original task documentation not found'})
        else:
            original_item = response['Item']
            original_messages = original_item.get('messages', [])
            print(f"[DEBUG INFO] Found original task documentation with {len(original_messages)} messages")

            duplicate_messages = []

            # Only duplicate messages that have file_complete_google_name (images)
            for message in original_messages:
                if 'file_complete_google_name' in message and message['file_complete_google_name']:
                    duplicate_messages.append(message)
            
            item['messages'] = duplicate_messages

        # Create a new task documentation
        current_time = datetime.datetime.utcnow().isoformat()

        # Create the item in DynamoDB with condition to prevent overwrites
        tasks_documentation_table.put_item(
            Item=item,
            ConditionExpression='attribute_not_exists(xano_task_id)'
        )

        print(f"[DEBUG INFO] Task documentation created successfully.")

        return {
            'statusCode': 201,
            'body': json.dumps({
                'message': 'Task documentation created successfully'
            })
        }

    except Exception as e:
        print(f"[ERROR] Failed to create task documentation: {str(e)}")
        import traceback
        print(f"[ERROR] Full traceback: {traceback.format_exc()}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }


def create_task_documentation(payload):
    """
    Creates a new task documentation record.

    Each task may have multiple task_communications, but only one task_documentation, so it's not necessary to have a task_documentation_id.

    Required fields:
    - xano_task_id
    - project_owner_xano_profile_contractor_id
    - project_owner_name
    - task_owner_xano_profile_contractor_id
    - task_owner_name
    """
    print('[DEBUG INFO] Initializing create_task_documentation...')

    try:
        # Validate required fields
        required_fields = ['xano_task_id', 'task_communication_id', 'project_owner_xano_profile_contractor_id', 'project_owner_name', 'task_owner_xano_profile_contractor_id', 'task_owner_name']
        for field in required_fields:
            if field not in payload:
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': f'Missing required field: {field}'})
                }

        # create a new task_documentation
        current_time = datetime.datetime.utcnow().isoformat()

        # Build the item
        item = {
            'xano_task_id': payload['xano_task_id'],
            'task_owner_xano_profile_contractor_id': payload['task_owner_xano_profile_contractor_id'],
            'task_owner_name': payload['task_owner_name'],
            'project_owner_xano_profile_contractor_id': payload['project_owner_xano_profile_contractor_id'],
            'project_owner_name': payload.get('project_owner_name', ''),
            'messages': [],
            'new_messages_to_task_owner': False,
            'new_messages_to_project_owner': False,
            'created_at': current_time,
            'updated_at': current_time
        }

        # Create the item in DynamoDB with condition to prevent overwrites
        tasks_documentation_table.put_item(
            Item=item,
            ConditionExpression='attribute_not_exists(xano_task_id)'
        )

        print(f"[DEBUG INFO] Task documentation created successfully.")

        return {
            'statusCode': 201,
            'body': json.dumps({
                'message': 'Task documentation created successfully'
            })
        }

    except Exception as e:
        print(f"[ERROR] Failed to create task documentation: {str(e)}")
        import traceback
        print(f"[ERROR] Full traceback: {traceback.format_exc()}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }


def handle_get(payload):
    """
    Routes GET requests to appropriate functions
    """
    print('[DEBUG INFO] Initializing handle_get...')

    try:
        # Get specific task communication
        if 'xano_task_id' in payload and 'task_communication_id' in payload:
            return get_task_communication(payload)

        # Get task communication by supervisor and task
        elif 'xano_task_id' in payload and 'supervisor_xano_profile_contractor_id' in payload:
            return get_task_communication_by_supervisor_and_task(payload)

        # Get task communication by task_owner and task
        elif 'xano_task_id' in payload and 'task_owner_xano_profile_contractor_id' in payload:
            return get_task_communication_by_task_owner_and_task(payload)
        
        # Get all task communications for a task
        elif 'xano_task_id' in payload:
            return get_task_communications_by_task(payload)

        # Get all task communications for a supervisor (with active access check)
        elif 'supervisor_xano_profile_contractor_id' in payload:
            return get_task_communications_by_supervisor(payload)

        else:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Missing required query parameters'})
            }

    except Exception as e:
        print(f"[ERROR] Failed to handle GET: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }


def get_task_communication(payload):
    """
    Gets a specific task communication by composite key
    Also marks messages as read based on authenticated_is_task_owner_or_supervisor
    """
    print('[DEBUG INFO] Getting single task communication...')

    try:
        xano_task_id = payload['xano_task_id']
        task_communication_id = payload['task_communication_id']
        authenticated_is_task_owner_or_supervisor = payload.get('authenticated_is_task_owner_or_supervisor', '')

        response = tasks_communications_table.get_item(
            Key={
                'xano_task_id': xano_task_id,
                'task_communication_id': task_communication_id
            }
        )

        if 'Item' not in response:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Task communication not found'})
            }

        item = response['Item']

        # Sort messages by timestamp (newest first)
        if item.get('messages'):
            item['messages'].sort(key=lambda msg: msg.get('timestamp', ''), reverse=True)
            # Add file URLs to messages
            item['messages'] = add_file_urls_to_messages(item['messages'])

        # Mark messages as read based on authenticated role
        if authenticated_is_task_owner_or_supervisor:
            current_time = datetime.datetime.utcnow().isoformat()

            if authenticated_is_task_owner_or_supervisor == 'task_owner':
                tasks_communications_table.update_item(
                    Key={
                        'xano_task_id': xano_task_id,
                        'task_communication_id': task_communication_id
                    },
                    UpdateExpression='SET new_messages_to_task_owner = :false, updated_at = :updated_at',
                    ExpressionAttributeValues={
                        ':false': False,
                        ':updated_at': current_time
                    },
                    ReturnValues='NONE'
                )
                print('[DEBUG INFO] Marked messages as read for task_owner')

            elif authenticated_is_task_owner_or_supervisor == 'supervisor':
                tasks_communications_table.update_item(
                    Key={
                        'xano_task_id': xano_task_id,
                        'task_communication_id': task_communication_id
                    },
                    UpdateExpression='SET new_messages_to_supervisor = :false, updated_at = :updated_at',
                    ExpressionAttributeValues={
                        ':false': False,
                        ':updated_at': current_time
                    },
                    ReturnValues='NONE'
                )
                print('[DEBUG INFO] Marked messages as read for supervisor')

        return {
            'statusCode': 200,
            'body': json.dumps(item, default=str)
        }

    except Exception as e:
        print(f"[ERROR] Failed to get task communication: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }


def get_task_communications_by_task(payload):
    """
    Gets all task communications for a specific task
    """
    print('[DEBUG INFO] Getting task communications by task...')

    try:
        xano_task_id = payload['xano_task_id']

        response = tasks_communications_table.query(
            KeyConditionExpression=Key('xano_task_id').eq(xano_task_id)
        )

        items = response.get('Items', [])

        # Handle pagination
        while 'LastEvaluatedKey' in response:
            response = tasks_communications_table.query(
                KeyConditionExpression=Key('xano_task_id').eq(xano_task_id),
                ExclusiveStartKey=response['LastEvaluatedKey']
            )
            items.extend(response.get('Items', []))

        # Sort messages in each item and add file URLs
        for item in items:
            if item.get('messages'):
                item['messages'].sort(key=lambda msg: msg.get('timestamp', ''), reverse=True)
                # Add file URLs to messages
                item['messages'] = add_file_urls_to_messages(item['messages'])

        return {
            'statusCode': 200,
            'body': json.dumps({
                'count': len(items),
                'items': items
            }, default=str)
        }

    except Exception as e:
        print(f"[ERROR] Failed to get task communications by task: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }


def get_task_communication_by_supervisor_and_task(payload):
    """
    Gets the task communication for a specific supervisor and task
    Queries by xano_task_id and filters by supervisor_xano_profile_contractor_id
    Automatically marks messages as read for the supervisor

    Required parameters:
    - xano_task_id
    - supervisor_xano_profile_contractor_id
    """
    print('[DEBUG INFO] Getting task communication by supervisor and task...')

    try:
        xano_task_id = payload['xano_task_id']
        supervisor_id = payload['supervisor_xano_profile_contractor_id']

        # Query all task communications for this task
        response = tasks_communications_table.query(
            KeyConditionExpression=Key('xano_task_id').eq(xano_task_id)
        )

        items = response.get('Items', [])

        # Handle pagination
        while 'LastEvaluatedKey' in response:
            response = tasks_communications_table.query(
                KeyConditionExpression=Key('xano_task_id').eq(xano_task_id),
                ExclusiveStartKey=response['LastEvaluatedKey']
            )
            items.extend(response.get('Items', []))

        # Find the task communication for this supervisor
        task_communication = None
        for item in items:
            if item.get('supervisor_xano_profile_contractor_id') == supervisor_id:
                task_communication = item
                break

        if not task_communication:
            # Return empty object
            print(f'[DEBUG INFO] No task communication found for supervisor {supervisor_id} on task {xano_task_id}')
            empty_communication = {}
            return {
                'statusCode': 200,
                'body': json.dumps(empty_communication, default=str)
            }

        task_communication_id = task_communication['task_communication_id']

        # Sort messages and add file URLs
        if task_communication.get('messages'):
            task_communication['messages'].sort(key=lambda msg: msg.get('timestamp', ''), reverse=True)
            task_communication['messages'] = add_file_urls_to_messages(task_communication['messages'])

        # Mark messages as read for supervisor
        current_time = datetime.datetime.utcnow().isoformat()
        tasks_communications_table.update_item(
            Key={
                'xano_task_id': xano_task_id,
                'task_communication_id': task_communication_id
            },
            UpdateExpression='SET new_messages_to_supervisor = :false, updated_at = :updated_at',
            ExpressionAttributeValues={
                ':false': False,
                ':updated_at': current_time
            },
            ReturnValues='NONE'
        )
        print('[DEBUG INFO] Marked messages as read for supervisor')

        print(f"[DEBUG INFO] Found task communication for supervisor {supervisor_id} on task {xano_task_id}")

        return {
            'statusCode': 200,
            'body': json.dumps(task_communication, default=str)
        }

    except Exception as e:
        print(f"[ERROR] Failed to get task communication by supervisor and task: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }



def get_task_communication_by_task_owner_and_task(payload):
    """
    Gets the task communication for a specific task owner and task
    Queries by xano_task_id and filters by task_owner_xano_profile_contractor_id
    Automatically marks messages as read for the task owner

    Required parameters:
    - xano_task_id
    - task_owner_xano_profile_contractor_id
    """
    print('[DEBUG INFO] Getting task communication by task owner and task...')

    try:
        xano_task_id = payload['xano_task_id']
        task_owner_id = payload['task_owner_xano_profile_contractor_id']

        # Query all task communications for this task
        response = tasks_communications_table.query(
            KeyConditionExpression=Key('xano_task_id').eq(xano_task_id)
        )

        items = response.get('Items', [])

        # Handle pagination
        while 'LastEvaluatedKey' in response:
            response = tasks_communications_table.query(
                KeyConditionExpression=Key('xano_task_id').eq(xano_task_id),
                ExclusiveStartKey=response['LastEvaluatedKey']
            )
            items.extend(response.get('Items', []))

        # Find the task communication for this task owner
        task_communication = None
        for item in items:
            if item.get('task_owner_xano_profile_contractor_id') == task_owner_id:
                task_communication = item
                break

        if not task_communication:
            # Return empty object
            print(f'[DEBUG INFO] No task communication found for task owner {task_owner_id} on task {xano_task_id}')
            empty_communication = {}
            return {
                'statusCode': 200,
                'body': json.dumps(empty_communication, default=str)
            }

        task_communication_id = task_communication['task_communication_id']

        # Sort messages and add file URLs
        if task_communication.get('messages'):
            task_communication['messages'].sort(key=lambda msg: msg.get('timestamp', ''), reverse=True)
            task_communication['messages'] = add_file_urls_to_messages(task_communication['messages'])

        # Mark messages as read for task owner
        current_time = datetime.datetime.utcnow().isoformat()
        tasks_communications_table.update_item(
            Key={
                'xano_task_id': xano_task_id,
                'task_communication_id': task_communication_id
            },
            UpdateExpression='SET new_messages_to_task_owner = :false, updated_at = :updated_at',
            ExpressionAttributeValues={
                ':false': False,
                ':updated_at': current_time
            },
            ReturnValues='NONE'
        )
        print('[DEBUG INFO] Marked messages as read for task owner')

        print(f"[DEBUG INFO] Found task communication for task owner {task_owner_id} on task {xano_task_id}")

        return {
            'statusCode': 200,
            'body': json.dumps(task_communication, default=str)
        }

    except Exception as e:
        print(f"[ERROR] Failed to get task communication by task owner and task: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }


def get_task_communications_by_supervisor(payload):
    """
    Gets all task communications for a supervisor where access is active
    Uses the supervisor-index GSI
    """
    print('[DEBUG INFO] Getting task communications by supervisor...')

    try:
        supervisor_id = payload['supervisor_xano_profile_contractor_id']

        # Query using GSI
        response = tasks_communications_table.query(
            IndexName='supervisor-index',
            KeyConditionExpression=Key('supervisor_xano_profile_contractor_id').eq(supervisor_id),
            FilterExpression=Attr('supervisor_access_is_active').eq(True)
        )

        items = response.get('Items', [])

        # Handle pagination
        while 'LastEvaluatedKey' in response:
            response = tasks_communications_table.query(
                IndexName='supervisor-index',
                KeyConditionExpression=Key('supervisor_xano_profile_contractor_id').eq(supervisor_id),
                FilterExpression=Attr('supervisor_access_is_active').eq(True),
                ExclusiveStartKey=response['LastEvaluatedKey']
            )
            items.extend(response.get('Items', []))

        # Sort messages in each item and add file URLs
        for item in items:
            if item.get('messages'):
                item['messages'].sort(key=lambda msg: msg.get('timestamp', ''), reverse=True)
                # Add file URLs to messages
                item['messages'] = add_file_urls_to_messages(item['messages'])

        print(f"[DEBUG INFO] Found {len(items)} task communications with active supervisor access")

        return {
            'statusCode': 200,
            'body': json.dumps({
                'count': len(items),
                'items': items
            }, default=str)
        }

    except Exception as e:
        print(f"[ERROR] Failed to get task communications by supervisor: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }


def update_task_communication(payload):
    """
    Updates a task communication record
    Supports:
    - Adding messages
    - Deleting messages (with optional file deletion from Google Storage)
    - Updating supervisor information
    - Updating supervisor access status
    - Removing supervisor by task_id and supervisor_id (when remove_this_supervisor=true)
    - Marking messages as read (when mark_as_read=true, requires authenticated_contractor_profile_id)
    """
    print('[DEBUG INFO] Initializing update_task_communication...')

    try:
        # Handle mark as read requests
        if payload.get('mark_as_read') is True:
            return mark_messages_as_read(payload)

        # Handle supervisor removal (only requires xano_task_id and supervisor_id)
        if payload.get('remove_this_supervisor') is True:
            if 'xano_task_id' not in payload or 'supervisor_xano_profile_contractor_id' not in payload:
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': 'Missing required fields for supervisor removal: xano_task_id and supervisor_xano_profile_contractor_id'})
                }

            xano_task_id = payload['xano_task_id']
            supervisor_id = payload['supervisor_xano_profile_contractor_id']

            print(f'[DEBUG INFO] Removing supervisor {supervisor_id} from task {xano_task_id}')

            # Query all communications for this task to find the one with this supervisor
            response = tasks_communications_table.query(
                KeyConditionExpression=Key('xano_task_id').eq(xano_task_id)
            )

            items = response.get('Items', [])

            # Handle pagination if needed
            while 'LastEvaluatedKey' in response:
                response = tasks_communications_table.query(
                    KeyConditionExpression=Key('xano_task_id').eq(xano_task_id),
                    ExclusiveStartKey=response['LastEvaluatedKey']
                )
                items.extend(response.get('Items', []))

            # Find the communication with this supervisor
            target_communication = None
            for item in items:
                if item.get('supervisor_xano_profile_contractor_id') == supervisor_id:
                    target_communication = item
                    break

            if not target_communication:
                return {
                    'statusCode': 404,
                    'body': json.dumps({'error': f'No communication found for supervisor {supervisor_id} on task {xano_task_id}'})
                }

            # Update the communication to remove supervisor access
            current_time = datetime.datetime.utcnow().isoformat()
            task_communication_id = target_communication['task_communication_id']

            tasks_communications_table.update_item(
                Key={
                    'xano_task_id': xano_task_id,
                    'task_communication_id': task_communication_id
                },
                UpdateExpression='SET supervisor_end_date = :end_date, supervisor_access_is_active = :inactive, updated_at = :updated_at',
                ExpressionAttributeValues={
                    ':end_date': current_time,
                    ':inactive': False,
                    ':updated_at': current_time
                },
                ReturnValues='NONE'
            )

            print(f'[DEBUG INFO] Successfully removed supervisor {supervisor_id} from task {xano_task_id}')

            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'Supervisor removed successfully',
                    'task_communication_id': task_communication_id,
                    'supervisor_end_date': current_time
                })
            }

        # Validate required keys for other operations
        if 'xano_task_id' not in payload or 'task_communication_id' not in payload:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Missing required fields: xano_task_id and task_communication_id'})
            }

        xano_task_id = payload['xano_task_id']
        task_communication_id = payload['task_communication_id']

        # Handle message deletion if requested
        if 'messages_ids_to_delete' in payload and payload['messages_ids_to_delete']:
            return delete_messages(xano_task_id, task_communication_id, payload['messages_ids_to_delete'])

        # Handle adding new messages
        if 'messages' in payload and isinstance(payload['messages'], dict):
            return add_messages(xano_task_id, task_communication_id, payload)

        # Handle general field updates
        update_expression = "SET updated_at = :updated_at"
        expression_attribute_values = {":updated_at": datetime.datetime.utcnow().isoformat()}
        expression_attribute_names = {}

        # Build update expression for allowed fields
        skip_fields = ['xano_task_id', 'task_communication_id', 'messages', 'messages_ids_to_delete', 'created_at']

        for key, value in payload.items():
            if key not in skip_fields:
                attr_name = f"#{key}"
                expression_attribute_names[attr_name] = key
                update_expression += f", {attr_name} = :{key}"
                expression_attribute_values[f":{key}"] = value

        if len(expression_attribute_names) == 0:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'No fields to update'})
            }

        # Update the item
        response = tasks_communications_table.update_item(
            Key={
                'xano_task_id': xano_task_id,
                'task_communication_id': task_communication_id
            },
            UpdateExpression=update_expression,
            ExpressionAttributeNames=expression_attribute_names,
            ExpressionAttributeValues=expression_attribute_values,
            ReturnValues='ALL_NEW'
        )

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Task communication updated successfully',
                'updated_item': response.get('Attributes', {})
            }, default=str)
        }

    except Exception as e:
        print(f"[ERROR] Failed to update task communication: {str(e)}")
        import traceback
        print(f"[ERROR] Full traceback: {traceback.format_exc()}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }


def mark_messages_as_read(payload):
    """
    Marks messages as read for task owner or supervisor
    Automatically detects whether the authenticated user is the supervisor or task owner

    Required fields:
    - xano_task_id
    - task_communication_id
    - authenticated_contractor_profile_id
    - mark_as_read (set to true)

    Usage:
    PUT request with payload:
    {
        "xano_task_id": "123",
        "task_communication_id": "TASKCOMM#...",
        "authenticated_contractor_profile_id": "456",
        "mark_as_read": true
    }
    """
    print('[DEBUG INFO] Marking messages as read...')

    try:
        # Validate required fields
        if 'xano_task_id' not in payload or 'task_communication_id' not in payload:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Missing required fields: xano_task_id and task_communication_id'})
            }

        if 'authenticated_contractor_profile_id' not in payload:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Missing required field: authenticated_contractor_profile_id'})
            }

        if not payload.get('mark_as_read'):
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'mark_as_read must be set to true'})
            }

        xano_task_id = payload['xano_task_id']
        task_communication_id = payload['task_communication_id']
        authenticated_id = payload['authenticated_contractor_profile_id']
        current_time = datetime.datetime.utcnow().isoformat()

        # Get the task communication to determine the user's role
        response = tasks_communications_table.get_item(
            Key={
                'xano_task_id': xano_task_id,
                'task_communication_id': task_communication_id
            }
        )

        if 'Item' not in response:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Task communication not found'})
            }

        item = response['Item']
        task_owner_id = item.get('task_owner_xano_profile_contractor_id', '')
        supervisor_id = item.get('supervisor_xano_profile_contractor_id', '')

        # Determine user role and update appropriate field
        if authenticated_id == supervisor_id:
            tasks_communications_table.update_item(
                Key={
                    'xano_task_id': xano_task_id,
                    'task_communication_id': task_communication_id
                },
                UpdateExpression='SET new_messages_to_supervisor = :false, updated_at = :updated_at',
                ExpressionAttributeValues={
                    ':false': False,
                    ':updated_at': current_time
                },
                ReturnValues='NONE'
            )
            print('[DEBUG INFO] Marked messages as read for supervisor')
            message = 'Messages marked as read for supervisor'
            user_role = 'supervisor'

        elif authenticated_id == task_owner_id:
            tasks_communications_table.update_item(
                Key={
                    'xano_task_id': xano_task_id,
                    'task_communication_id': task_communication_id
                },
                UpdateExpression='SET new_messages_to_task_owner = :false, updated_at = :updated_at',
                ExpressionAttributeValues={
                    ':false': False,
                    ':updated_at': current_time
                },
                ReturnValues='NONE'
            )
            print('[DEBUG INFO] Marked messages as read for task_owner')
            message = 'Messages marked as read for task_owner'
            user_role = 'task_owner'

        else:
            return {
                'statusCode': 403,
                'body': json.dumps({'error': 'Authenticated user is neither the task owner nor the supervisor for this task communication'})
            }

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': message,
                'user_role': user_role,
                'xano_task_id': xano_task_id,
                'task_communication_id': task_communication_id
            })
        }

    except Exception as e:
        print(f"[ERROR] Failed to mark messages as read: {str(e)}")
        import traceback
        print(f"[ERROR] Full traceback: {traceback.format_exc()}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }


def add_messages(xano_task_id, task_communication_id, payload):
    """
    Adds or updates messages in a task communication

    Message types:
    - text: Add-only (never deleted) - sent directly as payload.messages.text
    - file_complete_google_name: Can be added or deleted with action flags

    Payload formats:
    - Add text:
      payload = {
          "xano_task_id": "abc",
          "task_communication_id": "def",
          "messages": {"text": "Hello", "sender": "task_owner"}
      }

    - Add files:
      payload = {
          "xano_task_id": "abc",
          "task_communication_id": "def",
          "messages": {"add": true, "file_complete_google_name": ["file1.jpg", "file2.pdf"], "sender": "task_owner"}
      }

    - Delete files:
      payload = {
          "xano_task_id": "abc",
          "task_communication_id": "def",
          "messages": {"delete": true, "file_complete_google_name": ["file3.jpg", "file4.pdf"], "sender": "task_owner"}
      }

    Handles sender name resolution (task_owner or supervisor)
    Sets notification flags and returns notification data
    """
    print('[DEBUG INFO] Processing messages for task communication...')

    try:
        # Get current task communication to resolve sender names
        current_response = tasks_communications_table.get_item(
            Key={
                'xano_task_id': xano_task_id,
                'task_communication_id': task_communication_id
            }
        )

        if 'Item' not in current_response:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Task communication not found'})
            }

        current_item = current_response['Item']
        task_owner_name = current_item.get('task_owner_name', '')
        supervisor_name = current_item.get('supervisor_name', '')
        task_owner_id = current_item.get('task_owner_xano_profile_contractor_id', '')
        supervisor_id = current_item.get('supervisor_xano_profile_contractor_id', '')

        # Check current unread status (to avoid duplicate notifications)
        new_messages_to_task_owner = current_item.get('new_messages_to_task_owner', False)
        new_messages_to_supervisor = current_item.get('new_messages_to_supervisor', False)

        current_messages = current_item.get('messages', [])
        current_time = datetime.datetime.utcnow().isoformat()

        messages_data = payload['messages']

        # Get sender from messages object
        sender = messages_data.get('sender', '')

        # Initialize tracking variables
        sender_type = ''
        recipient_name = ''
        recipient_id = ''
        notification_needed = False
        operation_count = 0

        # Handle DELETE operation for file_complete_google_name
        if messages_data.get('delete') is True and 'file_complete_google_name' in messages_data:
            print('[DEBUG INFO] Processing file deletion from messages...')
            files_to_delete = messages_data['file_complete_google_name']

            if not isinstance(files_to_delete, list):
                files_to_delete = [files_to_delete]

            # Filter out messages with files in the deletion list
            updated_messages = []

            for msg in current_messages:
                file_name = msg.get('file_complete_google_name', '')

                # If this message has a file in the deletion list, remove it
                if file_name and file_name in files_to_delete:
                    operation_count += 1
                    print(f'[DEBUG INFO] Removing file name from messages: {file_name}')
                else:
                    updated_messages.append(msg)

            if operation_count == 0:
                return {
                    'statusCode': 404,
                    'body': json.dumps({'error': 'None of the specified files were found in messages'})
                }

            # Update messages in DynamoDB
            tasks_communications_table.update_item(
                Key={
                    'xano_task_id': xano_task_id,
                    'task_communication_id': task_communication_id
                },
                UpdateExpression='SET messages = :updated_messages, updated_at = :updated_at',
                ExpressionAttributeValues={
                    ':updated_messages': updated_messages,
                    ':updated_at': current_time
                },
                ReturnValues='NONE'
            )

            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': f'Successfully removed {operation_count} file name(s) from messages',
                    'deleted_count': operation_count
                }, default=str)
            }

        # Handle ADD operations (text and/or file_complete_google_name)
        else:
            print('[DEBUG INFO] Processing message addition...')

            new_messages = []

            # Handle text message (always add, no flag required)
            if 'text' in messages_data and messages_data['text']:
                print('[DEBUG INFO] Adding text message...')

                text_message = {
                    'message_id': f"MSG#{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}",
                    'timestamp': current_time,
                    'text': messages_data['text'],
                    'file_complete_google_name': ''
                }

                # Resolve sender information from messages object
                if sender == 'task_owner':
                    text_message['sender'] = 'task_owner'
                    text_message['sender_name'] = task_owner_name
                    sender_type = 'task_owner'
                    recipient_name = supervisor_name
                    recipient_id = supervisor_id
                    if not new_messages_to_supervisor:
                        notification_needed = True
                elif sender == 'supervisor':
                    text_message['sender'] = 'supervisor'
                    text_message['sender_name'] = supervisor_name
                    sender_type = 'supervisor'
                    recipient_name = task_owner_name
                    recipient_id = task_owner_id
                    if not new_messages_to_task_owner:
                        notification_needed = True
                else:
                    text_message['sender'] = sender
                    text_message['sender_name'] = messages_data.get('sender_name', '')

                new_messages.append(text_message)
                operation_count += 1

            # Handle file_complete_google_name with add flag
            if messages_data.get('add') is True and 'file_complete_google_name' in messages_data:
                print('[DEBUG INFO] Adding file message(s)...')

                files_to_add = messages_data['file_complete_google_name']
                if not isinstance(files_to_add, list):
                    files_to_add = [files_to_add]

                for file_name in files_to_add:
                    if file_name:  # Only add non-empty file names
                        file_message = {
                            'message_id': f"MSG#{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}",
                            'timestamp': current_time,
                            'text': '',
                            'file_complete_google_name': file_name
                        }

                        # Resolve sender information from messages object
                        if sender == 'task_owner':
                            file_message['sender'] = 'task_owner'
                            file_message['sender_name'] = task_owner_name
                            sender_type = 'task_owner'
                            recipient_name = supervisor_name
                            recipient_id = supervisor_id
                            if not new_messages_to_supervisor:
                                notification_needed = True
                        elif sender == 'supervisor':
                            file_message['sender'] = 'supervisor'
                            file_message['sender_name'] = supervisor_name
                            sender_type = 'supervisor'
                            recipient_name = task_owner_name
                            recipient_id = task_owner_id
                            if not new_messages_to_task_owner:
                                notification_needed = True
                        else:
                            file_message['sender'] = sender
                            file_message['sender_name'] = messages_data.get('sender_name', '')

                        new_messages.append(file_message)
                        operation_count += 1

            if not new_messages:
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': 'No valid messages to add'})
                }

            # Build update expression
            update_expression = 'SET messages = list_append(if_not_exists(messages, :empty_list), :new_messages), updated_at = :updated_at'
            expression_values = {
                ':new_messages': new_messages,
                ':empty_list': [],
                ':updated_at': current_time
            }

            # Set the appropriate notification flag based on sender
            if sender_type == 'task_owner':
                update_expression += ', new_messages_to_supervisor = :true'
                expression_values[':true'] = True
            elif sender_type == 'supervisor':
                update_expression += ', new_messages_to_task_owner = :true'
                expression_values[':true'] = True

            # Update the item with new messages
            tasks_communications_table.update_item(
                Key={
                    'xano_task_id': xano_task_id,
                    'task_communication_id': task_communication_id
                },
                UpdateExpression=update_expression,
                ExpressionAttributeValues=expression_values,
                ReturnValues='ALL_NEW'
            )

            # Build notification response data
            notification_data = {
                'notification_needed': notification_needed,
                'sender_type': sender_type,
                'sender_name': task_owner_name if sender_type == 'task_owner' else supervisor_name,
                'recipient_name': recipient_name,
                'recipient_id': recipient_id,
                'task_communication_id': task_communication_id,
                'xano_task_id': xano_task_id
            }

            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': f'Successfully added {operation_count} message(s)',
                    'added_count': operation_count,
                    'notification_data': notification_data
                }, default=str)
            }

    except Exception as e:
        print(f"[ERROR] Failed to process messages: {str(e)}")
        import traceback
        print(f"[ERROR] Full traceback: {traceback.format_exc()}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }


def delete_messages(xano_task_id, task_communication_id, messages_ids_to_delete):
    """
    Deletes messages from a task communication by their message IDs
    Note: File deletion from Google Cloud Storage is handled by Xano
    """
    print('[DEBUG INFO] Deleting messages from task communication...')

    try:
        # Get current task communication
        response = tasks_communications_table.get_item(
            Key={
                'xano_task_id': xano_task_id,
                'task_communication_id': task_communication_id
            }
        )

        if 'Item' not in response:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Task communication not found'})
            }

        messages = response['Item'].get('messages', [])

        # Filter messages to keep only those not in the deletion list
        new_messages = []
        deleted_count = 0

        for msg in messages:
            message_id = msg.get('message_id')
            if message_id in messages_ids_to_delete:
                deleted_count += 1
                print(f'[DEBUG INFO] Deleting message: {message_id}')
            else:
                new_messages.append(msg)

        if deleted_count == 0:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'None of the specified messages were found'})
            }

        # Update the item with filtered messages
        # Note: File deletion from Google Cloud Storage is handled by Xano
        current_time = datetime.datetime.utcnow().isoformat()
        update_response = tasks_communications_table.update_item(
            Key={
                'xano_task_id': xano_task_id,
                'task_communication_id': task_communication_id
            },
            UpdateExpression="SET messages = :new_messages, updated_at = :updated_at",
            ExpressionAttributeValues={
                ':new_messages': new_messages,
                ':updated_at': current_time
            },
            ReturnValues='UPDATED_NEW'
        )

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': f'Successfully deleted {deleted_count} message(s)',
                'deleted_count': deleted_count
            })
        }

    except Exception as e:
        print(f"[ERROR] Failed to delete messages: {str(e)}")
        import traceback
        print(f"[ERROR] Full traceback: {traceback.format_exc()}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }


def delete_task_communication(payload):
    """
    Deletes a task communication record
    Note: This is a hard delete. Consider implementing soft delete if needed.
    File deletion from Google Cloud Storage is handled by Xano.
    """
    print('[DEBUG INFO] Initializing delete_task_communication...')

    try:
        if 'xano_task_id' not in payload or 'task_communication_id' not in payload:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Missing required fields: xano_task_id and task_communication_id'})
            }

        xano_task_id = payload['xano_task_id']
        task_communication_id = payload['task_communication_id']

        # Check if the item exists
        response = tasks_communications_table.get_item(
            Key={
                'xano_task_id': xano_task_id,
                'task_communication_id': task_communication_id
            }
        )

        if 'Item' not in response:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Task communication not found'})
            }

        # Delete the item from DynamoDB
        tasks_communications_table.delete_item(
            Key={
                'xano_task_id': xano_task_id,
                'task_communication_id': task_communication_id
            }
        )

        print(f'[DEBUG INFO] Successfully deleted task communication: {task_communication_id}')

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Task communication deleted successfully'
            })
        }

    except Exception as e:
        print(f"[ERROR] Failed to delete task communication: {str(e)}")
        import traceback
        print(f"[ERROR] Full traceback: {traceback.format_exc()}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
