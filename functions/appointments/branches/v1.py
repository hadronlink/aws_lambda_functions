import boto3
import uuid
import datetime
from boto3.dynamodb.conditions import Key
import json
import base64
import os
from google.oauth2 import service_account
from google.cloud import storage
import tempfile

# Initialize DynamoDB client
dynamodb = boto3.resource('dynamodb')

# Initialize Google Storage client
creds_json = base64.b64decode(os.environ['GOOGLE_CREDENTIALS_JSON'])
creds = service_account.Credentials.from_service_account_info(json.loads(creds_json))
client = storage.Client(credentials=creds)

# Constants
BUCKET_NAME = 'hadronlink_pictures'
BUCKET_FOLDER = 'web_appointments_cards'
TEMP_DIR = '/tmp/temp_images'

# Create temp directory if it doesn't exist
os.makedirs(TEMP_DIR, exist_ok=True)

# Declare tables directly
appointments_table = dynamodb.Table('appointments')
chats_table = dynamodb.Table('chats')
roles_table = dynamodb.Table('roles')

def handle_request(event, payload):
    operation = event.get('httpMethod')
    print(f"[DEBUG] Operation: {operation}")
    print(f"[DEBUG] Event: {json.dumps(event, default=str)}")
    print(f"[DEBUG] Parsed payload: {payload}")

    try:
        if operation == 'POST':
            return create_appointment(payload)
        elif operation == 'GET':
            return handle_appointment_get(payload)
        elif operation == 'PUT':
            # Try to get appointment_id from path parameters first, then from payload
            path_params = event.get('pathParameters') or {}
            appointment_id = path_params.get('appointment_id')

            # If not in path, try to get it from the payload
            if not appointment_id and payload:
                appointment_id = payload.get('appointment_id')

            if not appointment_id:
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': 'Missing appointment_id in path or body for PUT request.'})
                }

            print(f"[DEBUG] Using appointment_id: {appointment_id}")
            return update_appointment(appointment_id, payload)
        elif operation == 'DELETE':
            return delete_appointment(payload)
        else:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Invalid HTTP method'})
            }
    except Exception as e:
        print(f"An unexpected error occurred in handle_request: {e}")
        import traceback
        print(f"Full traceback: {traceback.format_exc()}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def handle_appointment_get(payload):
    print('[DEBUG INFO] Initializing handle_appointment_get...')
    try:
        if not payload:
            payload = {}

        appointment_id = payload.get('appointment_id')
        chat_id = payload.get('chat_id')
        homeowner = payload.get('homeowner')
        professional = payload.get('professional')

        if appointment_id:
            return get_appointment(appointment_id)
        elif chat_id:
            return get_appointments_by_chat_id(chat_id)
        elif homeowner:
            return get_appointments_by_homeowner(homeowner)
        elif professional:
            return get_appointments_by_professional(professional)
        else:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Missing query parameter (appointment_id, chat_id, homeowner, or professional) for GET request.'})
            }
    except Exception as e:
        print(f"Error in handle_appointment_get: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def create_appointment(payload):
    print('[DEBUG INFO] Initializing create_appointment...')
    try:
        if not payload:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Missing payload for appointment creation'})
            }

        chat_response = chats_table.get_item(
            Key={
                'chat_id': payload.get('chat_id')
            },
            ProjectionExpression='appointments'
        )
        if 'Item' not in chat_response:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Chat not found.'})
            }
        if 'Item' in chat_response and 'soft_delete' in chat_response['Item'] and chat_response['Item']['soft_delete']:
            return {
                'statusCode': 403,
                'body': json.dumps({'error': 'Chat has been soft-deleted and cannot be modified.'})
            }
        if 'Item' in chat_response:
            chat = chat_response['Item']
            print(f"[DEBUG] Chat found: {chat}")

        # Required fields from the payload, including appointment_id
        appointment_id = payload['appointment_id'] # Expect appointment_id in input
        chat_id = payload['chat_id']
        homeowner = payload['homeowner']
        professional = payload['professional']
        appointment_location = payload['appointment_location']
        appointment_date = payload['appointment_date']
        appointment_time = payload['appointment_time']
        details = payload.get('details', '') # Optional field with a default empty string
        homeowner_name = payload.get('homeowner_name')
        professional_name = payload.get('professional_name')

        # Timestamps
        now = datetime.datetime.utcnow().isoformat()
        created_at = now
        updated_at = now

        # 1. Put item into appointments
        # ConditionExpression still ensures unique appointment_id to prevent accidental overwrites
        appointments_table.put_item(
            Item={
                'appointment_id': appointment_id,
                'chat_id': chat_id,
                'homeowner': homeowner,
                'professional': professional,
                'appointment_location': appointment_location,
                'appointment_date': appointment_date,
                'appointment_time': appointment_time,
                'details': details,
                'homeowner_name': homeowner_name,
                'professional_name': professional_name,
                'created_at': created_at,
                'updated_at': updated_at,
                'soft_delete': False,
                'soft_deleted_by': '',
                'status': 'Created'
            },
            ConditionExpression='attribute_not_exists(appointment_id)'
        )

        # 2. Update chats table
        existing_appointments = chat_response['Item'].get('appointments', []) if 'Item' in chat_response else []

        new_chat_appointment_entry = {
            'appointment_id': appointment_id,
            'professional': professional,
            'appointment_date': appointment_date,
            'appointment_time': appointment_time,
            'details': details
        }
        existing_appointments.append(new_chat_appointment_entry)

        chats_table.update_item(
            Key={
                'chat_id': chat_id
            },
            UpdateExpression='SET appointments = :appointments, updated_at = :updated_at',
            ExpressionAttributeValues={
                ':appointments': existing_appointments,
                ':updated_at': now
            },
            ReturnValues='UPDATED_NEW'
        )

        # Fetch Role Information for both parties
        one_party_role_response = roles_table.query(
            IndexName='role_id-index',
            KeyConditionExpression=Key('role_id').eq(professional),
            ProjectionExpression='#n, email, #l',
            ExpressionAttributeNames={'#n': 'name', '#l': 'language'},
            Limit=1
        )
        one_party_details = one_party_role_response['Items'][0]
        print(f"[DEBUG INFO] one_party details: {one_party_details}")

        other_party_role_response = roles_table.query(
            IndexName='role_id-index',
            KeyConditionExpression=Key('role_id').eq(homeowner),
            ProjectionExpression='#n, email, #l',
            ExpressionAttributeNames={'#n': 'name', '#l': 'language'},
            Limit=1
        )
        other_party_details = other_party_role_response['Items'][0]
        print(f"[DEBUG INFO] other_party details: {other_party_details}")

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Appointment created successfully and chat updated.',
                'appointment_id': appointment_id,
                'one_party_details': one_party_details,
                'other_party_details': other_party_details
            })
        }

    except Exception as e:
        print(f"Error creating appointment: {e}")
        import traceback
        print(f"Full traceback: {traceback.format_exc()}")
        return {
            'statusCode': 500,
            'body': json.dumps({'message': f'Error creating appointment: {str(e)}'})
        }

def get_appointment(appointment_id):
    # This function's signature doesn't change, it still takes appointment_id directly
    try:
        response = appointments_table.get_item(
            Key={
                'appointment_id': appointment_id
            }
        )
        item = response.get('Item')

        if item:
            return {
                'statusCode': 200,
                'body': json.dumps(item)
            }
        else:
            return {
                'statusCode': 404,
                'body': json.dumps({'message': 'Appointment not found.'})
            }
    except Exception as e:
        print(f"Error getting appointment: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'message': f'Error getting appointment: {str(e)}'})
        }

def get_appointments_by_chat_id(chat_id):
    try:
        response = appointments_table.query(
            IndexName='chat_id-index',
            KeyConditionExpression=Key('chat_id').eq(chat_id)
        )
        items = response.get('Items', [])
        return {
            'statusCode': 200,
            'body': json.dumps({'appointments': items})
        }
    except Exception as e:
        print(f"Error getting appointments by chat_id: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'message': f'Error getting appointments by chat_id: {str(e)}'})
        }

def get_appointments_by_homeowner(homeowner):
    try:
        response = appointments_table.query(
            IndexName='homeowner-index',
            KeyConditionExpression=Key('homeowner').eq(homeowner)
        )
        items = response.get('Items', [])
        return {
            'statusCode': 200,
            'body': json.dumps({'appointments': items})
        }
    except Exception as e:
        print(f"Error getting appointments by homeowner: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'message': f'Error getting appointments by homeowner: {str(e)}'})
        }

def get_appointments_by_professional(professional):
    try:
        response = appointments_table.query(
            IndexName='professional-index',
            KeyConditionExpression=Key('professional').eq(professional)
        )
        items = response.get('Items', [])
        return {
            'statusCode': 200,
            'body': json.dumps({'appointments': items})
        }
    except Exception as e:
        print(f"Error getting appointments by professional: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'message': f'Error getting appointments by professional: {str(e)}'})
        }

import datetime
from google.cloud import storage # Assuming this is available

def update_ics_file_status(datasource, appointment_id, new_status):
    try:
        print(f"[DEBUG] Starting ICS update: datasource={datasource}, appointment_id={appointment_id}, new_status={new_status}")

        # --- NEW LOGIC: Determine the calendar method and get current timestamp ---
        # A 'CANCELLED' status should trigger a 'CANCEL' method in the ICS file.
        new_method = 'CANCEL' if new_status and new_status.upper() == 'CANCELLED' else 'PUBLISH'
        now_dtstamp = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')

        # Construct the file name (keep original case)
        ics_filename = f"{datasource}_{appointment_id}"
        print(f"[DEBUG] Constructed ICS filename: {ics_filename}")

        # Get the bucket and blob reference (assuming 'client' and 'BUCKET_NAME' are defined)
        bucket = client.bucket(BUCKET_NAME)
        blob_path = f"{BUCKET_FOLDER}/{ics_filename}"
        blob = bucket.blob(blob_path)

        print(f"[DEBUG] Full blob path: {blob_path}")
        print(f"[DEBUG] Bucket name: {BUCKET_NAME}")

        # Check if file exists
        print(f"[DEBUG] Checking if blob exists...")
        blob_exists = blob.exists()
        print(f"[DEBUG] Blob exists result: {blob_exists}")

        if not blob_exists:
            print(f"[ERROR] ICS file {blob_path} does not exist in bucket {BUCKET_NAME}")
            # List files in the bucket folder to help debug
            try:
                blobs = bucket.list_blobs(prefix=BUCKET_FOLDER)
                print(f"[DEBUG] Files in {BUCKET_FOLDER}:")
                for blob_item in blobs:
                    print(f"[DEBUG]   - {blob_item.name}")
            except Exception as list_error:
                print(f"[DEBUG] Could not list bucket contents: {list_error}")
            return False

        # Download the ICS file content
        print(f"[DEBUG] Downloading ICS file content...")
        ics_content = blob.download_as_text()
        print(f"[DEBUG] Original ICS content length: {len(ics_content)}")

        # Update the status in the ICS content
        lines = ics_content.split('\n')
        status_updated = False
        method_updated = False
        dtstamp_updated = False
        sequence_updated = False

        print(f"[DEBUG] Looking for lines to update in {len(lines)} lines...")
        for i, line in enumerate(lines):
            # --- NEW LOGIC: Update METHOD line ---
            if line.strip().startswith('METHOD:'):
                lines[i] = f'METHOD:{new_method}'.upper()
                method_updated = True
                print(f"[DEBUG] Updated METHOD to: {lines[i].strip()}")

            # --- NEW LOGIC: Update DTSTAMP line with current timestamp ---
            elif line.strip().startswith('DTSTAMP:'):
                lines[i] = f'DTSTAMP:{now_dtstamp}'
                dtstamp_updated = True
                print(f"[DEBUG] Updated DTSTAMP to: {lines[i].strip()}")

            elif line.strip().startswith('STATUS:'):
                lines[i] = f'STATUS:{new_status}'.upper()
                status_updated = True
                print(f"[DEBUG] Updated existing STATUS to: {lines[i].strip()}")

            elif line.strip().startswith('SEQUENCE:'):
                old_sequence_num = int(line.split(':')[1])
                lines[i] = f'SEQUENCE:{old_sequence_num + 1}'
                sequence_updated = True
                print(f"[DEBUG] Updated existing SEQUENCE from {old_sequence_num} to: {lines[i].strip()}")

        # If STATUS line was not found, add it before END:VEVENT
        if not status_updated:
            print(f"[DEBUG] No existing STATUS found, looking for END:VEVENT to add new STATUS...")
            for i, line in enumerate(lines):
                if line.strip() == 'END:VEVENT':
                    lines.insert(i, f'STATUS:{new_status}'.upper())
                    status_updated = True
                    print(f"[DEBUG] Added new STATUS line: STATUS:{new_status}")
                    break

        if not status_updated:
            print("[ERROR] Could not find appropriate place to add STATUS in ICS file")
            return False

        # Join the lines back together
        updated_ics_content = '\n'.join(lines)
        print(f"[DEBUG] Updated ICS content length: {len(updated_ics_content)}")

        # Upload the updated content back to the bucket (overwrite)
        print(f"[DEBUG] Uploading updated content to Google Cloud Storage...")
        blob.upload_from_string(updated_ics_content, content_type='text/calendar')
        print(f"[DEBUG] Successfully updated ICS file {blob_path}")

        return True

    except Exception as e:
        print(f"[ERROR] Error updating ICS file: {e}")
        import traceback
        print(f"[ERROR] Full traceback: {traceback.format_exc()}")
        return False

def update_appointment(appointment_id, payload):
    try:
        print(f"[DEBUG] Starting update_appointment: appointment_id={appointment_id}")
        print(f"[DEBUG] Payload type: {type(payload)}")
        print(f"[DEBUG] Payload: {payload}")

        # Ensure payload is not None
        if payload is None:
            payload = {}
            print("[WARNING] Payload was None, using empty dict")

        # First, get the current appointment to check the current status
        current_response = appointments_table.get_item(
            Key={
                'appointment_id': appointment_id
            }
        )

        print(f"[DEBUG] Current response: {current_response}")

        if 'Item' not in current_response:
            return {
                'statusCode': 404,
                'body': json.dumps({'message': 'Appointment not found.'})
            }

        current_appointment = current_response['Item']
        current_status = current_appointment.get('status') if current_appointment else None
        new_status = payload.get('status') if payload else None

        print(f"[DEBUG] Status comparison: current={current_status}, new={new_status}")

        # Check if we need to update the ICS file
        ics_update_required = False
        ics_update_successful = False

        if new_status and new_status != current_status:
            print(f"[DEBUG] Status change detected: {current_status} -> {new_status}")
            ics_update_required = True

            datasource = payload.get('datasource') if payload else None
            print(f"[DEBUG] Datasource: {datasource}")

            if datasource:
                ics_update_successful = update_ics_file_status(datasource, appointment_id, new_status)
            else:
                print("[WARNING] No datasource provided for ICS update")

        # Continue with the regular update process
        update_expression_parts = []
        expression_attribute_values = {}
        expression_attribute_names = {}

        now = datetime.datetime.utcnow().isoformat()
        update_expression_parts.append('updated_at = :updated_at')
        expression_attribute_values[':updated_at'] = now

        # Reserved keywords in DynamoDB that need expression attribute names
        reserved_keywords = ['status', 'name', 'date', 'time', 'location', 'details']

        if payload:
            for key, value in payload.items():
                if key not in ['appointment_id', 'created_at', 'chat_id']:
                    if key.lower() in reserved_keywords:
                        # Use expression attribute name for reserved keywords
                        attr_name = f'#{key}'
                        expression_attribute_names[attr_name] = key
                        update_expression_parts.append(f'{attr_name} = :{key}')
                    else:
                        # Use regular attribute name
                        update_expression_parts.append(f'{key} = :{key}')

                    expression_attribute_values[f':{key}'] = value

        if len(update_expression_parts) <= 1:  # Only updated_at
            return {
                'statusCode': 400,
                'body': json.dumps({'message': 'No fields provided for update.'})
            }

        update_expression = 'SET ' + ', '.join(update_expression_parts)
        print(f"[DEBUG] Update expression: {update_expression}")
        print(f"[DEBUG] Expression values: {expression_attribute_values}")
        print(f"[DEBUG] Expression attribute names: {expression_attribute_names}")

        # Build the update_item parameters
        update_params = {
            'Key': {
                'appointment_id': appointment_id
            },
            'UpdateExpression': update_expression,
            'ExpressionAttributeValues': expression_attribute_values,
            'ReturnValues': 'ALL_NEW'
        }

        # Only add ExpressionAttributeNames if we have any
        if expression_attribute_names:
            update_params['ExpressionAttributeNames'] = expression_attribute_names

        update_response = appointments_table.update_item(**update_params)

        print(f"[DEBUG] Update response: {update_response}")

        if not update_response or 'Attributes' not in update_response:
            print("[ERROR] Update response is invalid")
            return {
                'statusCode': 500,
                'body': json.dumps({'message': 'Database update failed'})
            }

        attributes = update_response['Attributes']
        chat_id = attributes.get('chat_id')
        updated_professional = attributes.get('professional')
        updated_appointment_date = attributes.get('appointment_date')
        updated_appointment_time = attributes.get('appointment_time')
        updated_details = attributes.get('details')

        print(f"[DEBUG] Chat ID: {chat_id}")

        if not chat_id:
            print("[WARNING] No chat_id found, skipping chat update")
        else:
            chat_response = chats_table.get_item(
                Key={
                    'chat_id': chat_id
                },
                ProjectionExpression='appointments'
            )

            print(f"[DEBUG] Chat response: {chat_response}")

            existing_appointments = []
            if chat_response and 'Item' in chat_response and chat_response['Item']:
                existing_appointments = chat_response['Item'].get('appointments', [])

            print(f"[DEBUG] Existing appointments count: {len(existing_appointments)}")

            appointment_found = False
            for i, appt in enumerate(existing_appointments):
                if appt and appt.get('appointment_id') == appointment_id:
                    existing_appointments[i]['professional'] = updated_professional
                    existing_appointments[i]['appointment_date'] = updated_appointment_date
                    existing_appointments[i]['appointment_time'] = updated_appointment_time
                    existing_appointments[i]['details'] = updated_details
                    appointment_found = True
                    print(f"[DEBUG] Updated appointment in chat at index {i}")
                    break

            if appointment_found:
                chats_table.update_item(
                    Key={
                        'chat_id': chat_id
                    },
                    UpdateExpression='SET appointments = :appointments, updated_at = :updated_at',
                    ExpressionAttributeValues={
                        ':appointments': existing_appointments,
                        ':updated_at': now
                    },
                    ReturnValues='UPDATED_NEW'
                )
                print("[DEBUG] Chat updated successfully")
            else:
                print(f"Warning: Appointment {appointment_id} not found in chat {chat_id}'s appointments list during update.")

        # Fetch Role Information for both parties
        attributes = update_response['Attributes']
        professional_id = attributes.get('professional')
        homeowner_id = attributes.get('homeowner')

        # Fetch professional details (one_party)
        one_party_details = {}
        if professional_id:
            try:
                one_party_role_response = roles_table.query(
                    IndexName='role_id-index',
                    KeyConditionExpression=Key('role_id').eq(professional_id),
                    ProjectionExpression='#n, email, #l',
                    ExpressionAttributeNames={'#n': 'name', '#l': 'language'},
                    Limit=1
                )
                if one_party_role_response['Items']:
                    one_party_details = one_party_role_response['Items'][0]
                    print(f"[DEBUG INFO] one_party details: {one_party_details}")
            except Exception as e:
                print(f"[WARNING] Failed to fetch professional details: {e}")

        # Fetch homeowner details (other_party)
        other_party_details = {}
        if homeowner_id:
            try:
                other_party_role_response = roles_table.query(
                    IndexName='role_id-index',
                    KeyConditionExpression=Key('role_id').eq(homeowner_id),
                    ProjectionExpression='#n, email, #l',
                    ExpressionAttributeNames={'#n': 'name', '#l': 'language'},
                    Limit=1
                )
                if other_party_role_response['Items']:
                    other_party_details = other_party_role_response['Items'][0]
                    print(f"[DEBUG INFO] other_party details: {other_party_details}")
            except Exception as e:
                print(f"[WARNING] Failed to fetch homeowner details: {e}")

        # Prepare response body
        response_body = {
            'message': 'Appointment updated successfully and chat updated.',
            'one_party_details': one_party_details,
            'other_party_details': other_party_details
        }

        # Always add ICS update status in the response
        if ics_update_required:
            response_body['ics_card_is_successfully_updated'] = ics_update_successful
        else:
            response_body['ics_card_is_successfully_updated'] = False
            response_body['ics_update_reason'] = 'No status change detected'

        print(f"[DEBUG] Final response body: {response_body}")

        return {
            'statusCode': 200,
            'body': json.dumps(response_body)
        }

    except Exception as e:
        print(f"Error updating appointment: {e}")
        import traceback
        print(f"Full traceback: {traceback.format_exc()}")
        return {
            'statusCode': 500,
            'body': json.dumps({'message': f'Error updating appointment: {str(e)}'})
        }

def delete_appointment(payload):
    print(f'[DEBUG INFO] Initializing delete_appointment function')
    try:
        if not payload:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Missing payload for appointment deletion'})
            }

        appointment_id = payload['appointment_id']
        author_id = payload['author_id']

        # 1. Get the full appointment item before deleting
        get_response = appointments_table.get_item(
            Key={
                'appointment_id': appointment_id
            }
        )
        appointment_item = get_response.get('Item')

        if not appointment_item:
            return {
                'statusCode': 404,
                'body': json.dumps({'message': 'Appointment not found.'})
            }

        chat_id = appointment_item['chat_id']
        homeowner_id = appointment_item['homeowner']
        professional_id = appointment_item['professional']

        now = datetime.datetime.utcnow().isoformat()

        # 2. Soft-delete the appointment item
        appointments_table.update_item(
            Key={
                'appointment_id': appointment_id
            },
            UpdateExpression='SET soft_delete = :soft_delete, soft_deleted_by = :soft_deleted_by, updated_at = :updated_at',
            ExpressionAttributeValues={
                ':soft_delete': True,
                ':soft_deleted_by': author_id,
                ':updated_at': now
            },
            ReturnValues='UPDATED_NEW'
        )

        # 3. Hard delete the appointment from the chat's appointments list
        chat_response = chats_table.get_item(
            Key={
                'chat_id': chat_id
            },
            ProjectionExpression='appointments'
        )
        existing_appointments = chat_response['Item'].get('appointments', []) if 'Item' in chat_response else []
        updated_appointments = [appt for appt in existing_appointments if appt.get('appointment_id') != appointment_id]

        chats_table.update_item(
            Key={
                'chat_id': chat_id
            },
            UpdateExpression='SET appointments = :appointments, updated_at = :updated_at',
            ExpressionAttributeValues={
                ':appointments': updated_appointments,
                ':updated_at': now
            },
            ReturnValues='UPDATED_NEW'
        )

        # 4. Fetch Role Information for both parties for the response body
        # For the response, 'one_party' will be the professional and 'other_party' the homeowner,
        # mirroring the structure of the create function.
        one_party_role_response = roles_table.query(
            IndexName='role_id-index',
            KeyConditionExpression=Key('role_id').eq(professional_id),
            ProjectionExpression='#n, email, #l',
            ExpressionAttributeNames={'#n': 'name', '#l': 'language'},
            Limit=1
        )
        one_party_details = one_party_role_response['Items'][0] if one_party_role_response['Items'] else {}
        print(f"[DEBUG INFO] one_party details: {one_party_details}")

        other_party_role_response = roles_table.query(
            IndexName='role_id-index',
            KeyConditionExpression=Key('role_id').eq(homeowner_id),
            ProjectionExpression='#n, email, #l',
            ExpressionAttributeNames={'#n': 'name', '#l': 'language'},
            Limit=1
        )
        other_party_details = other_party_role_response['Items'][0] if other_party_role_response['Items'] else {}
        print(f"[DEBUG INFO] other_party details: {other_party_details}")

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Appointment soft-deleted successfully and chat updated.',
                'appointment_id': appointment_id,
                'one_party_details': one_party_details,
                'other_party_details': other_party_details
            })
        }

    except Exception as e:
        print(f"Error deleting (soft) appointment: {e}")
        import traceback
        print(f"Full traceback: {traceback.format_exc()}")
        return {
            'statusCode': 500,
            'body': json.dumps({'message': f'Error soft-deleting appointment: {str(e)}'})
        }
