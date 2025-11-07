import json
import boto3
import datetime
import os
import base64
from boto3.dynamodb.conditions import Key, Attr
from google.oauth2 import service_account
from google.cloud import storage

# Initialize DynamoDB resource
dynamodb = boto3.resource('dynamodb')
tasks_communications_table = dynamodb.Table('tasks_communications_dev')

# Initialize Google Storage client for file deletion
creds_json = base64.b64decode(os.environ['GOOGLE_CREDENTIALS_JSON'])
creds = service_account.Credentials.from_service_account_info(json.loads(creds_json))
storage_client = storage.Client(credentials=creds)

# Constants
BUCKET_NAME = 'hadronlink_pictures'
BUCKET_FOLDER = 'web_tasks_communications'


def lambda_handler(event, context):
    """
    Main Lambda handler for tasks_communications CRUD operations
    """
    operation = event['httpMethod']
    payload = event['queryStringParameters'] if operation == 'GET' else json.loads(event['body']) if event.get('body') else {}

    try:
        if operation == 'POST':
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
    Creates a new task communication record

    Required fields:
    - xano_task_id
    - task_communication_id (must start with "TASKCOMM#")
    - owner_xano_profile_contractor_id
    - owner_name
    """
    print('[DEBUG INFO] Initializing create_task_communication...')

    try:
        # Validate required fields
        required_fields = ['xano_task_id', 'task_communication_id', 'owner_xano_profile_contractor_id', 'owner_name']
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

        current_time = datetime.datetime.utcnow().isoformat()

        # Build the item
        item = {
            'xano_task_id': payload['xano_task_id'],
            'task_communication_id': task_communication_id,
            'owner_xano_profile_contractor_id': payload['owner_xano_profile_contractor_id'],
            'owner_name': payload['owner_name'],
            'supervisor_xano_profile_contractor_id': payload.get('supervisor_xano_profile_contractor_id', ''),
            'supervisor_name': payload.get('supervisor_name', ''),
            'supervisor_access_is_active': payload.get('supervisor_access_is_active', False),
            'supervisor_acceptance_date': payload.get('supervisor_acceptance_date', ''),
            'supervisor_end_date': payload.get('supervisor_end_date', ''),
            'messages': [],
            'new_messages_to_owner': False,
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


def handle_get(payload):
    """
    Routes GET requests to appropriate functions
    """
    print('[DEBUG INFO] Initializing handle_get...')

    try:
        # Get specific task communication
        if 'xano_task_id' in payload and 'task_communication_id' in payload:
            return get_task_communication(payload)

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
    Also marks messages as read based on authenticated_is_owner_or_supervisor
    """
    print('[DEBUG INFO] Getting single task communication...')

    try:
        xano_task_id = payload['xano_task_id']
        task_communication_id = payload['task_communication_id']
        authenticated_is_owner_or_supervisor = payload.get('authenticated_is_owner_or_supervisor', '')

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

        # Mark messages as read based on authenticated role
        if authenticated_is_owner_or_supervisor:
            current_time = datetime.datetime.utcnow().isoformat()

            if authenticated_is_owner_or_supervisor == 'owner':
                tasks_communications_table.update_item(
                    Key={
                        'xano_task_id': xano_task_id,
                        'task_communication_id': task_communication_id
                    },
                    UpdateExpression='SET new_messages_to_owner = :false, updated_at = :updated_at',
                    ExpressionAttributeValues={
                        ':false': False,
                        ':updated_at': current_time
                    },
                    ReturnValues='NONE'
                )
                print('[DEBUG INFO] Marked messages as read for owner')

            elif authenticated_is_owner_or_supervisor == 'supervisor':
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

        # Sort messages in each item
        for item in items:
            if item.get('messages'):
                item['messages'].sort(key=lambda msg: msg.get('timestamp', ''), reverse=True)

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

        # Sort messages in each item
        for item in items:
            if item.get('messages'):
                item['messages'].sort(key=lambda msg: msg.get('timestamp', ''), reverse=True)

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
    """
    print('[DEBUG INFO] Initializing update_task_communication...')

    try:
        # Validate required keys
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
        if 'messages' in payload and isinstance(payload['messages'], dict) and 'add' in payload['messages']:
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


def add_messages(xano_task_id, task_communication_id, payload):
    """
    Adds new messages to a task communication
    Handles sender name resolution (owner or supervisor)
    Sets notification flags and returns notification data
    """
    print('[DEBUG INFO] Adding messages to task communication...')

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
        owner_name = current_item.get('owner_name', '')
        supervisor_name = current_item.get('supervisor_name', '')
        owner_id = current_item.get('owner_xano_profile_contractor_id', '')
        supervisor_id = current_item.get('supervisor_xano_profile_contractor_id', '')

        # Check current unread status (to avoid duplicate notifications)
        new_messages_to_owner = current_item.get('new_messages_to_owner', False)
        new_messages_to_supervisor = current_item.get('new_messages_to_supervisor', False)

        # Process new messages
        new_messages = payload['messages']['add']
        current_time = datetime.datetime.utcnow().isoformat()

        # Determine sender and recipient for notifications
        sender_type = ''
        recipient_name = ''
        recipient_id = ''
        notification_needed = False

        for message in new_messages:
            # Set timestamp if not provided
            if 'timestamp' not in message or not message['timestamp']:
                message['timestamp'] = current_time

            # Generate message_id if not provided
            if 'message_id' not in message or not message['message_id']:
                message['message_id'] = f"MSG#{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}"

            # Resolve sender_name based on sender field
            sender = message.get('sender', '')
            if sender == 'owner':
                message['sender_name'] = owner_name
                sender_type = 'owner'
                recipient_name = supervisor_name
                recipient_id = supervisor_id
                # Only send notification if this is the FIRST unread message
                if not new_messages_to_supervisor:
                    notification_needed = True
            elif sender == 'supervisor':
                message['sender_name'] = supervisor_name
                sender_type = 'supervisor'
                recipient_name = owner_name
                recipient_id = owner_id
                # Only send notification if this is the FIRST unread message
                if not new_messages_to_owner:
                    notification_needed = True
            else:
                # If sender is not specified or invalid, use the provided sender_name or empty
                if 'sender_name' not in message:
                    message['sender_name'] = ''

            # Ensure text field exists
            if 'text' not in message:
                message['text'] = ''

            # Ensure file_complete_google_name field exists
            if 'file_complete_google_name' not in message:
                message['file_complete_google_name'] = ''

        # Determine which notification flag to set
        update_expression = 'SET messages = list_append(if_not_exists(messages, :empty_list), :new_messages), updated_at = :updated_at'
        expression_values = {
            ':new_messages': new_messages,
            ':empty_list': [],
            ':updated_at': current_time
        }

        # Set the appropriate notification flag based on sender
        if sender_type == 'owner':
            update_expression += ', new_messages_to_supervisor = :true'
            expression_values[':true'] = True
        elif sender_type == 'supervisor':
            update_expression += ', new_messages_to_owner = :true'
            expression_values[':true'] = True

        # Update the item with new messages
        response = tasks_communications_table.update_item(
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
            'sender_name': owner_name if sender_type == 'owner' else supervisor_name,
            'recipient_name': recipient_name,
            'recipient_id': recipient_id,
            'task_communication_id': task_communication_id,
            'xano_task_id': xano_task_id
        }

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': f'Successfully added {len(new_messages)} message(s)',
                'added_count': len(new_messages),
                'notification_data': notification_data
            }, default=str)
        }

    except Exception as e:
        print(f"[ERROR] Failed to add messages: {str(e)}")
        import traceback
        print(f"[ERROR] Full traceback: {traceback.format_exc()}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }


def delete_messages(xano_task_id, task_communication_id, messages_ids_to_delete):
    """
    Deletes messages from a task communication
    Also deletes associated files from Google Cloud Storage if present
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

        # Track files to delete and messages to keep
        files_to_delete = []
        new_messages = []
        deleted_count = 0

        for msg in messages:
            message_id = msg.get('message_id')
            if message_id in messages_ids_to_delete:
                deleted_count += 1
                # Check if message has a file to delete
                file_name = msg.get('file_complete_google_name', '')
                if file_name:
                    files_to_delete.append(file_name)
            else:
                new_messages.append(msg)

        if deleted_count == 0:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'None of the specified messages were found'})
            }

        # Delete files from Google Cloud Storage
        files_deleted_count = 0
        files_failed_count = 0

        for file_complete_google_name in files_to_delete:
            try:
                print(f"[DEBUG INFO] Attempting to delete file: {file_complete_google_name}")

                # The file_complete_google_name already includes the bucket folder path
                # Example: "hadronlink_pictures/web_tasks_communications/dev_123456_789123"
                # We need to extract just the blob path after the bucket name

                # Split the path to get bucket and blob path
                path_parts = file_complete_google_name.split('/', 1)
                if len(path_parts) == 2:
                    blob_path = path_parts[1]  # e.g., "web_tasks_communications/dev_123456_789123"
                else:
                    blob_path = file_complete_google_name

                bucket = storage_client.bucket(BUCKET_NAME)
                blob = bucket.blob(blob_path)

                # Check if blob exists before attempting to delete
                if blob.exists():
                    blob.delete()
                    files_deleted_count += 1
                    print(f"[DEBUG INFO] Successfully deleted file: {blob_path}")
                else:
                    print(f"[WARNING] File not found in storage: {blob_path}")
                    files_failed_count += 1

            except Exception as file_error:
                print(f"[ERROR] Failed to delete file {file_complete_google_name}: {str(file_error)}")
                files_failed_count += 1

        # Update the item with filtered messages
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

        response_message = {
            'message': f'Successfully deleted {deleted_count} message(s)',
            'deleted_messages_count': deleted_count,
            'files_deleted_count': files_deleted_count,
            'files_failed_count': files_failed_count
        }

        return {
            'statusCode': 200,
            'body': json.dumps(response_message)
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
    Also deletes all associated files from Google Cloud Storage.
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

        # Get the item first to retrieve any files that need to be deleted
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
        messages = item.get('messages', [])

        # Collect all files to delete
        files_to_delete = []
        for msg in messages:
            file_name = msg.get('file_complete_google_name', '')
            if file_name:
                files_to_delete.append(file_name)

        # Delete files from Google Cloud Storage
        files_deleted_count = 0
        files_failed_count = 0

        for file_complete_google_name in files_to_delete:
            try:
                print(f"[DEBUG INFO] Attempting to delete file: {file_complete_google_name}")

                # Extract blob path from complete google name
                path_parts = file_complete_google_name.split('/', 1)
                if len(path_parts) == 2:
                    blob_path = path_parts[1]
                else:
                    blob_path = file_complete_google_name

                bucket = storage_client.bucket(BUCKET_NAME)
                blob = bucket.blob(blob_path)

                if blob.exists():
                    blob.delete()
                    files_deleted_count += 1
                    print(f"[DEBUG INFO] Successfully deleted file: {blob_path}")
                else:
                    print(f"[WARNING] File not found in storage: {blob_path}")
                    files_failed_count += 1

            except Exception as file_error:
                print(f"[ERROR] Failed to delete file {file_complete_google_name}: {str(file_error)}")
                files_failed_count += 1

        # Delete the item from DynamoDB
        tasks_communications_table.delete_item(
            Key={
                'xano_task_id': xano_task_id,
                'task_communication_id': task_communication_id
            }
        )

        response_message = {
            'message': 'Task communication deleted successfully',
            'files_deleted_count': files_deleted_count,
            'files_failed_count': files_failed_count
        }

        return {
            'statusCode': 200,
            'body': json.dumps(response_message)
        }

    except Exception as e:
        print(f"[ERROR] Failed to delete task communication: {str(e)}")
        import traceback
        print(f"[ERROR] Full traceback: {traceback.format_exc()}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
