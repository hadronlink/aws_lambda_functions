import boto3
import json
import os
import base64
import tempfile
import socket
from decimal import Decimal, ROUND_HALF_UP
from itertools import count
import urllib.request
from datetime import datetime
from boto3.dynamodb.conditions import Key
from quote_generator import lambda_handler_generate_quote
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Flowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus.flowables import HRFlowable
from reportlab.platypus.frames import Frame
from reportlab.platypus.doctemplate import PageTemplate
from reportlab.graphics.shapes import Drawing, Circle
from google.oauth2 import service_account
from google.cloud import storage

# Debug PIL location and conflicts
import sys

# print(f"[DEBUG] Python path: {sys.path}")
# print(f"[DEBUG] Contents of /var/task: {os.listdir('/var/task') if os.path.exists('/var/task') else 'No /var/task'}")

# # Check if PIL exists in task directory
# task_pil_dir = '/var/task/PIL'
# if os.path.exists(task_pil_dir):
#     # print(f"[DEBUG] PIL found in task directory: {os.listdir(task_pil_dir)[:5]}...")  # Show first 5 files
# else:
#     # print("[DEBUG] No PIL directory in /var/task")

# # Check layer directory
# layer_paths = [path for path in sys.path if '/opt/' in path]
# # print(f"[DEBUG] Layer paths: {layer_paths}")

# for layer_path in layer_paths:
#     pil_in_layer = os.path.join(layer_path, 'PIL')
#     if os.path.exists(pil_in_layer):
#         # print(f"[DEBUG] PIL found in layer: {pil_in_layer}")

# # Try importing without PIL for now
# try:
#     # Skip PIL import entirely for now
#     PIL_AVAILABLE = False
#     # print("[DEBUG] Skipping PIL import to avoid conflicts")
# except Exception as e:
#     # print(f"[ERROR] Unexpected error: {e}")
#     PIL_AVAILABLE = False

# Initialize DynamoDB resources
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('quotes_dev')
table_services_requests = dynamodb.Table('services_requests_dev')
table_chats = dynamodb.Table('chats_dev')
table_roles = dynamodb.Table('roles_dev')

# Initialize Google Storage client for PDF storage
creds_json = base64.b64decode(os.environ['GOOGLE_CREDENTIALS_JSON'])
creds = service_account.Credentials.from_service_account_info(json.loads(creds_json))
client = storage.Client(credentials=creds)

# Constants
BUCKET_NAME = 'hadronlink_pictures'
BUCKET_FOLDER = 'web_quotes'
TEMP_DIR = '/tmp/temp_images'

# Create temp directory if it doesn't exist
os.makedirs(TEMP_DIR, exist_ok=True)

# Define placeholders for multilingual support
PLACEHOLDERS = {
    "quote_number": {
        "en": "QUOTE#",
        "fr": "DEVIS nº",
        "es": "COTIZACIÓN nº",
        "pt": "ORÇAMENTO nº"
    },
    "date": {
        "en": "Quote date: ",
        "fr": "Date du devis : ",
        "es": "Fecha de la cotización: ",
        "pt": "Data do orçamento: "
    },
    "to": {
        "en": "TO:",
        "fr": "À:",
        "es": "PARA:",
        "pt": "PARA:"
    },
    "from": {
        "en": "FROM:",
        "fr": "DE:",
        "es": "DE:",
        "pt": "DE:"
    },
    "location_of_service": {
        "en": "LOCATION OF SERVICE:",
        "fr": "LIEU DE PRESTATION:",
        "es": "LUGAR DEL SERVICIO:",
        "pt": "LOCAL DO SERVIÇO:"
    },
    "items_table_first_column": {
        "en": "ITEM DESCRIPTION",
        "fr": "DESCRIPTION DE L'ARTICLE",
        "es": "DESCRIPCIÓN DEL ARTÍCULO",
        "pt": "DESCRIÇÃO DO ITEM"
    },
    "items_table_second_column": {
        "en": "QTY",
        "fr": "QTÉ",
        "es": "CANT",
        "pt": "QTD"
    },
    "items_table_third_column": {
        "en": "RATE",
        "fr": "PRIX UNITAIRE",
        "es": "PRECIO UNITARIO",
        "pt": "UNITÁRIO"
    },
    "items_table_fourth_column": {
        "en": "AMOUNT",
        "fr": "MONTANT",
        "es": "IMPORTE",
        "pt": "VALOR"
    },
    "comments": {
        "en": "Comments:",
        "fr": "Commentaires:",
        "es": "Comentarios:",
        "pt": "Comentários:"
    },
    "total": {
        "en": "Total",
        "fr": "Total",
        "es": "Total",
        "pt": "Total"
    },
    "taxes": {
        "en": "+ taxes",
        "fr": "+ taxes",
        "es": "+ impuestos",
        "pt": "+ impostos"
    },
    "time_frame": {
        "en": "Time Frame",
        "fr": "Délai",
        "es": "Plazo",
        "pt": "Prazo"
    },
    "estimated_start_date": {
        "en": "Estimated Start Date",
        "fr": "Date de début estimée",
        "es": "Fecha estimada de inicio",
        "pt": "Data estimada de início"
    },
    "acceptance_person": {
        "en": "Accepted by",
        "fr": "Accepté par",
        "es": "Aceptado por",
        "pt": "Aceito por"
    },
    "acceptance_date": {
        "en": "Acceptance Date",
        "fr": "Date d'acceptation",
        "es": "Fecha de aceptación",
        "pt": "Data de aceitação"
    },
    "valid_until": {
        "en": "Valid until: ",
        "fr": "Valide jusqu'au: ",
        "es": "Válido hasta: ",
        "pt": "Válido até: "
    }
}

def handle_request(event, payload):

    operation = event['httpMethod']

    try:
        if operation == 'GET' and payload and 'quote_id' in payload:
            print(f'[DEBUG INFO] Payload: {payload}')
            return read_item_by_quote_id(payload)
        elif operation == 'GET' and payload and 'chat_id' in payload:
            print(f'[DEBUG INFO] Payload: {payload}')
            return read_items_by_chat_id(payload)
        elif operation == 'POST':
            if payload.get('action') == 'generate_pdf':
                return generate_pdf_quote(payload)
            else:
                return create_item(payload)
        elif operation == 'PUT':
            return update_item(payload)
        elif operation == 'DELETE' and payload:
            return delete_item(payload)
        else:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Invalid operation or missing parameters'})
            }
    except json.JSONDecodeError:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Invalid JSON in request body'})
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def create_item(payload):
    print('[DEBUG INFO] Initializing create_item...')
    print(f'[DEBUG INFO] Payload: {payload}')
    try:
        # Validate required fields (chat_id and quote_id only)
        required_fields = ['chat_id', 'quote_id']
        for field in required_fields:
            if field not in payload:
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': f'Missing required field: {field}'})
                }

        # Validate date format if provided
        if 'estimated_start_date' in payload:
            try:
                datetime.strptime(payload['estimated_start_date'], '%Y-%m-%d')
            except ValueError:
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': 'Invalid date format. Expected YYYY-MM-DD'})
                }

        # Retrieve homeowner information from table_chats
        try:
            original_chat = table_chats.get_item(
                Key={
                    'chat_id': payload['chat_id']
                },
                ProjectionExpression='homeowner_language, professional_language, homeowner'
            )
            if 'Item' in original_chat:
                homeowner = original_chat['Item'].get('homeowner')
                homeowner_language = original_chat['Item'].get('homeowner_language')
                professional_language = original_chat['Item'].get('professional_language')
                payload['homeowner_language'] = homeowner_language
                payload['professional_language'] = professional_language

                # Retrieve homeowner information from table_roles
                homeowner_contact_info = {}
                if homeowner:
                    homeowner_response = table_roles.query(
                        IndexName='role_id-index',
                        KeyConditionExpression=Key('role_id').eq(homeowner),
                        Limit=1  # Since we only need one item
                    )
                    homeowner_items = homeowner_response.get('Items', [])
                    homeowner_profile = homeowner_items[0] if homeowner_items else None
                    homeowner_name = homeowner_profile.get('name', '') if homeowner_profile else ''
                    homeowner_email = homeowner_profile.get('email', '') if homeowner_profile else ''
                    homeowner_system_phone = homeowner_profile.get('phone', '') if homeowner_profile else ''
                    homeowner_language = payload.get('homeowner_language', '')
                    homeowner_location = homeowner_profile.get('location', '') if homeowner_profile else ''
                    homeowner_contact_info = {
                        'homeowner_name': homeowner_name,
                        'homeowner_email': homeowner_email,
                        'homeowner_system_phone': homeowner_system_phone,
                        'homeowner_language': homeowner_language,
                        'homeowner_role_id': homeowner
                    }
            else:
                print(f"[WARNING] Chat with id {payload['chat_id']} not found when trying to retrieve language information.")
                homeowner = None
                homeowner_contact_info = {}

        except Exception as e:
            print(f'[ERROR] Failed to retrieve language information from chat: {str(e)}')
            homeowner = None
            homeowner_contact_info = {}
            # Proceed without language information in case of an error

        # =============== Generate the quote pdf =========================
        try:
            # Check if generate_single_language_quote function exists
            try:
                generate_single_language_quote
                missing_function = False
            except NameError:
                missing_function = True
                print("[ERROR] The generate_single_language_quote function is not defined")

            if missing_function:
                print("[ERROR] Cannot generate quote PDF: Missing required function")
                pdf_file_name = ""
            else:
                # The function exists, let's call it
                payload['homeowner_name'] = homeowner_contact_info.get('homeowner_name', '')
                payload['homeowner_location'] = homeowner_contact_info.get('homeowner_location', '')
                pdf_file_name = generate_single_language_quote(payload)
                if pdf_file_name is None:
                    print("[ERROR] quote generation returned None instead of a file path")
                    pdf_file_name = ""
        except Exception as e:
            print(f"[ERROR] Error generating pdf: {str(e)}")
            pdf_file_name = "" # Provide a default empty string in case of error

        # Initialize quote_pdf_files as empty
        payload['quote_pdf_files'] = {'en': '', 'fr': '', 'es': '', 'pt': ''}

        # Add the file if generation was successful
        language = payload.get('language', 'en')  # Default to English if no language specified
        if pdf_file_name:
            payload['quote_pdf_files'].update({language: pdf_file_name})

        payload['created_at'] = int(datetime.now().strftime("%Y%m%d%H%M%S"))
        payload['updated_at'] = int(datetime.now().strftime("%Y%m%d%H%M%S"))

        # Convert any float values to Decimal before storing in DynamoDB
        decimal_payload = convert_floats_to_decimal(payload)

        # Safely remove logo URLs if they exist
        decimal_payload.pop('hadronlink_logo_url', None)
        decimal_payload.pop('sender_logo_url', None)
        decimal_payload.pop('homeowner_name', None)
        decimal_payload.pop('homeowner_location', None)
        decimal_payload['quote_language'] = language
        decimal_payload.pop('language', None)

        # =============== Store the quote in the quotes_dev table ===========

        table.put_item(Item=decimal_payload)

        # Update chat table with quote_id in the quotes list
        print('[DEBUG INFO] Updating chat table with quote_id...')
        try:
            # First check if the chat exists
            original_chat_for_update = table_chats.get_item(
                Key={
                    'chat_id': payload['chat_id']
                }
            )

            if 'Item' not in original_chat_for_update:
                return {
                    'statusCode': 404,
                    'body': json.dumps({'error': 'Correspondent chat not found to be updated'})
                }

            # Create the quote info to append to the list
            quote_info = {'professional': payload['professional'], 'quote_id': payload['quote_id']}

            # Update the quotes list in table_chats
            updated_chat = table_chats.update_item(
                Key={
                    'chat_id': payload['chat_id']
                },
                UpdateExpression='SET #quotes = list_append(if_not_exists(#quotes, :empty_list), :quote_info_list)',
                ExpressionAttributeNames={
                    '#quotes': 'quotes'
                },
                ExpressionAttributeValues={
                    ':quote_info_list': [quote_info],
                    ':empty_list': []
                },
                ReturnValues='UPDATED_NEW'
            )

            return {
                'statusCode': 201,
                'body': json.dumps({
                    'message': 'Quote created and chat updated successfully',
                    'updated_quotes': updated_chat.get('Attributes', {}).get('quotes'),
                    'homeowner_contact_info': homeowner_contact_info
                }, default=decimal_default)
            }

        except Exception as e:
            print(f'[ERROR] Failed to update chat: {str(e)}')
            # The quote was created but chat update failed
            return {
                'statusCode': 500,
                'body': json.dumps({
                    'message': 'Quote created but failed to update chat',
                    'error': str(e)
                })
            }

    except Exception as e:
        print(f'[ERROR] Failed to create quote: {str(e)}')
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def update_item(payload):
    """Updates an item in the DynamoDB table, keeping existing values for unspecified columns."""
    print('[DEBUG INFO] Initializing update_item...')

    try:
        chat_id = payload['chat_id']
        print(f'[DEBUG INFO] Chat ID: {chat_id}')
        quote_id = payload['quote_id']
        print(f'[DEBUG INFO] Quote ID: {quote_id}')

        # Fetch the existing item
        response = table.get_item(Key={'chat_id': chat_id, 'quote_id': quote_id})
        if 'Item' not in response:
            return {
                'statusCode': 404,
                'body': json.dumps({'message': 'Item not found'})
            }
        existing_item = response['Item']
        print(existing_item)

        # Update quote_line_items if provided
        if 'quote_line_items' in payload:
            action = payload.get('action')
            quote_line_items_to_update = payload.get('quote_line_items', [])
            existing_quote_line_items = existing_item.get('quote_line_items', [])
            updated_quote_line_items = existing_quote_line_items.copy()

            if action == 'add':
                for item in quote_line_items_to_update:
                    item_exists = any(existing_item.get('id') == item.get('id') for existing_item in updated_quote_line_items if 'id' in existing_item and 'id' in item)
                    if not item_exists:
                        updated_quote_line_items.append(item)

            elif action == 'remove':
                item_ids_to_remove = [item_id for item_id in quote_line_items_to_update]
                updated_quote_line_items = [item for item in updated_quote_line_items
                                        if item.get('id') not in item_ids_to_remove]

            payload['quote_line_items'] = updated_quote_line_items

            total_amount = 0
            for item in updated_quote_line_items:
                total_amount += item.get('item_quantity', 0) * item.get('individual_price', 0)
            payload['amount'] = total_amount

        if 'action' in payload:
            del payload['action']

        # Update photos if provided
        if 'photos' in payload:
            action = payload.get('photo_action')
            photos_to_update = payload.get('photos', [])
            existing_photos = existing_item.get('photos', [])

            updated_photos = existing_photos.copy()
            print(existing_photos)

            if action == 'add':
                for photo in photos_to_update:
                    if photo not in updated_photos:
                        updated_photos.append(photo)
                print(updated_photos)

            elif action == 'remove':
                for photo in photos_to_update:
                    if photo in updated_photos:
                        updated_photos.remove(photo)

            payload['photos'] = updated_photos
            del payload['photo_action']

        # Check if status is "Accepted"
        if payload.get('status') == 'Accepted':
            # Update quote status
            print('[DEBUG INFO] Updating the quote table...')
            table.update_item(
                Key={'chat_id': chat_id, 'quote_id': quote_id},
                UpdateExpression='SET #s = :s, updated_at = :u',
                ExpressionAttributeNames={'#s': 'status'},
                ExpressionAttributeValues={':s': 'Accepted', ':u': int(datetime.now().strftime("%Y%m%d%H%M%S"))}
            )

            # Update related service request
            print('[DEBUG INFO] Updating the service request status and selected professional info...')

            service_request_response = table_services_requests.get_item(Key={'service_request_id': existing_item.get('service_request_id')})

            if 'Item' not in service_request_response:
                return {
                    'statusCode': 404,
                    'body': json.dumps({'message': 'Service request not found'})
                }
            else:
                existing_service_request = service_request_response['Item']
                print(f'[DEBUG INFO] Processing service request: {existing_service_request}')

                main_chat_response = table_chats.get_item(Key={'chat_id': chat_id})
                main_chat = main_chat_response['Item']
                print(f'[DEBUG INFO] Main chat: {main_chat}')

                table_services_requests.update_item(
                    Key={'service_request_id': existing_service_request.get('service_request_id')},
                    UpdateExpression='SET #p = :p, #pn = :pn, #pp = :pp, #ss = :ss, updated_at = :u',
                    ExpressionAttributeNames={'#p': 'selected_professional', '#pn': 'professional_name', '#pp': 'professional_phone', '#ss': 'status'},
                    ExpressionAttributeValues={':p': existing_item.get('professional'), ':pn': main_chat.get('professional_name'), ':pp': main_chat.get('professional_phone'), ':ss': 'InProgress', ':u': int(datetime.now().strftime("%Y%m%d%H%M%S"))}
                )
                print(f'[DEBUG INFO] Service request updated.')

                list_of_all_chats = existing_service_request.get('chats', [])
                other_chats = [chat for chat in list_of_all_chats if chat.get('chat_id') != chat_id]
                print(f'[DEBUG INFO] Other chats under this service request: {other_chats}')
                if len(other_chats) == 0:
                    print('[DEBUG INFO] No other chats under this service request')
                else:
                    for chat in other_chats:
                        other_chat_id = chat.get('chat_id')
                        print(f'[DEBUG INFO] Processing chat: {other_chat_id}')
                        other_chat_response = table_chats.get_item(Key={'chat_id': other_chat_id})
                        if 'Item' not in other_chat_response:
                            print(f'[DEBUG INFO] Chat not found')
                        else:
                            existing_other_chat = other_chat_response['Item']
                            table_chats.update_item(
                                Key={'chat_id': other_chat_id},
                                UpdateExpression='SET #s = :s, #sd = :sd, updated_at = :u',
                                ExpressionAttributeNames={'#s': 'chat_status', '#sd': 'status_detail'},
                                ExpressionAttributeValues={':s': 'Closed', ':sd': 'Related quote(s) not selected', ':u': int(datetime.now().strftime("%Y%m%d%H%M%S"))}
                            )

                            list_of_all_other_quotes = existing_other_chat.get('quotes', [])
                            other_quotes = [other_quote for other_quote in list_of_all_other_quotes if other_quote.get('quote_id') != quote_id]
                            print(f'[DEBUG INFO] Other quotes under this chat: {other_quotes}')
                            if len(other_quotes) != 0:
                                for other_quote in other_quotes:
                                    other_quote_id = other_quote.get('quote_id')
                                    table.update_item(
                                        Key={'chat_id': other_chat_id, 'quote_id': other_quote_id},
                                        UpdateExpression='SET #s = :s, updated_at = :u',
                                        ExpressionAttributeNames={'#s': 'status'},
                                        ExpressionAttributeValues={':s': 'Closed - not selected', ':u': int(datetime.now().strftime("%Y%m%d%H%M%S"))}
                                    )
                        print(f'[DEBUG INFO] End of this chat processing')

                        list_of_all_main_chat_quotes = main_chat.get('quotes', [])
                        other_main_chat_quotes = [other_main_chat_quote for other_main_chat_quote in list_of_all_main_chat_quotes if other_main_chat_quote.get('quote_id') != quote_id]
                        if len(other_main_chat_quotes) != 0:
                            print(f'[DEBUG INFO]  Other quotes under main chat to be closed: {other_main_chat_quotes}')
                            for other_main_chat_quote in other_main_chat_quotes:
                                other_main_chat_quote_id = other_main_chat_quote.get('quote_id')
                                table.update_item(
                                    Key={'chat_id': chat_id, 'quote_id': other_main_chat_quote_id},
                                    UpdateExpression='SET #s = :s, updated_at = :u',
                                    ExpressionAttributeNames={'#s': 'status'},
                                    ExpressionAttributeValues={':s': 'Closed - not selected', ':u': int(datetime.now().strftime("%Y%m%d%H%M%S"))}
                                )

        if payload.get('status') == 'Withdrawn':
            print('[DEBUG INFO] Updating the quote table status to Withdrawn...')
            table.update_item(
                Key={'chat_id': chat_id, 'quote_id': quote_id},
                UpdateExpression='SET #s = :s, updated_at = :u',
                ExpressionAttributeNames={'#s': 'status'},
                ExpressionAttributeValues={':s': 'Withdrawn', ':u': int(datetime.now().strftime("%Y%m%d%H%M%S"))}
            )

            print(f'[DEBUG INFO] Removing quote_id {quote_id} from chat {chat_id}...')
            chat_item_response = table_chats.get_item(Key={'chat_id': chat_id})
            if 'Item' in chat_item_response:
                chat_item = chat_item_response['Item']
                if 'quotes_ids' in chat_item and quote_id in chat_item['quotes_ids']:
                    updated_quotes_ids = [q_id for q_id in chat_item['quotes_ids'] if q_id != quote_id]
                    table_chats.update_item(
                        Key={'chat_id': chat_id},
                        UpdateExpression='SET quotes_ids = :qids, updated_at = :u',
                        ExpressionAttributeValues={':qids': updated_quotes_ids, ':u': int(datetime.now().strftime("%Y%m%d%H%M%S"))}
                    )
                    print(f'[DEBUG INFO] Quote_id {quote_id} removed from chat {chat_id}.')
                else:
                    print(f'[DEBUG INFO] Quote_id {quote_id} not found in chat {chat_id}.')
            else:
                print(f'[DEBUG INFO] Chat {chat_id} not found.')

        update_expression = 'SET '
        expression_attribute_values = {}
        expression_attribute_names = {}

        for key, value in payload.items():
            if key not in ['chat_id', 'quote_id'] and existing_item.get(key) != value:
                if key == 'status':
                    update_expression += '#s = :s, '
                    expression_attribute_values[':s'] = value
                    expression_attribute_names['#s'] = 'status'
                else:
                    update_expression += f'{key} = :{key}, '
                    expression_attribute_values[f':{key}'] = value

        if update_expression != 'SET':
            update_expression += 'updated_at = :u'
            expression_attribute_values[':u'] = int(datetime.now().strftime("%Y%m%d%H%M%S"))

            update_kwargs = {
                'Key': {'chat_id': chat_id, 'quote_id': quote_id},
                'UpdateExpression': update_expression,
                'ExpressionAttributeValues': expression_attribute_values,
                'ReturnValues': 'ALL_NEW'
            }

            if expression_attribute_names:
                update_kwargs['ExpressionAttributeNames'] = expression_attribute_names

            table.update_item(**update_kwargs)

        return {
            'statusCode': 200,
            'body': json.dumps({'message': 'Item updated successfully'})
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def delete_item(payload):
    try:
        chat_id = payload['chat_id']
        quote_id = payload['quote_id']

        print(f"Deleting item with chat_id: {chat_id}, quote_id: {quote_id}")

        key = {'chat_id': chat_id, 'quote_id': quote_id}
        print(f"DynamoDB Key: {key}")

        photo_list = get_photo_list(chat_id, quote_id)

        table.delete_item(Key=key)

        print("Item deleted successfully")

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Item deleted successfully',
                'photos_to_delete': photo_list
            })
        }
    except Exception as e:
        print(f"Error deleting item: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def get_photo_list(chat_id, quote_id):
    try:
        response = table.get_item(Key={'chat_id': chat_id, 'quote_id': quote_id})
        if 'Item' in response and 'photos' in response['Item']:
            return response['Item']['photos']
        else:
            return []  # Return an empty list if no photos are found
    except Exception as e:
        print(f"Error retrieving photo list: {str(e)}")
        return []  # Return an empty list in case of errors

def read_items_by_chat_id(payload):
    print(f'[DEBUG INFO] Initializing read_items_by_chat_id')
    try:
        chat_id = payload['chat_id']

        response = table.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key('chat_id').eq(chat_id)
        )

        items = response.get('Items', [])

        for quote in items:

            if quote.get('amount'):
                print(f"[DEBUG INFO] Quote original amount: {quote['amount']}; data type: {type(quote['amount'])}")
                quote['amount'] = f"{quote['amount'] / 100:,.2f}"
                print(f"[DEBUG INFO] Quote transformed amount: {quote['amount']}; data type: {type(quote['amount'])}")

            if quote.get('quote_line_items'):
                for item in quote['quote_line_items']:
                    # Individual price
                    print(f"[DEBUG INFO] Item original individual price: {item['individual_price']}; data type: {type(item['individual_price'])}")
                    item['individual_price'] = f"{item['individual_price'] / 100:,.2f}"
                    print(f"[DEBUG INFO] Item transformed individual price: {item['individual_price']}; data type: {type(item['individual_price'])}")

                    # Sum
                    print(f"[DEBUG INFO] Item original sum: {item['sum']}; data type: {type(item['sum'])}")
                    item['sum'] = f"{item['sum'] / 100:,.2f}"
                    print(f"[DEBUG INFO] Item transformed sum: {item['sum']}; data type: {type(item['sum'])}")

                    # Quantity (if it's also stored in cents — confirm if this is correct)
                    print(f"[DEBUG INFO] Item original quantity: {item['item_quantity']}; data type: {type(item['item_quantity'])}")
                    item['item_quantity'] = f"{item['item_quantity'] / 100:,.2f}"
                    print(f"[DEBUG INFO] Item transformed quantity: {item['item_quantity']}; data type: {type(item['item_quantity'])}")

        return {
            'statusCode': 200,
            'body': json.dumps(items, default=str)
        }

    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def read_item_by_quote_id(payload):
    print(f'[DEBUG INFO] Initializing read_item_by_quote_id')
    try:
        quote_id = payload['quote_id']

        response = table.scan(
            FilterExpression=boto3.dynamodb.conditions.Attr('quote_id').eq(quote_id)
        )

        items = response.get('Items', [])
        quote = items[0] if items else None

        print(f"[DEBUG INFO] Retrieved items: {items}")
        print(f"[DEBUG INFO] Quote: {quote}")

        if quote:
            if quote.get('amount'):
                print(f"[DEBUG INFO] Quote original amount: {quote['amount']}; data type: {type(quote['amount'])}")
                quote['amount'] = f"{quote['amount'] / 100:,.2f}"
                print(f"[DEBUG INFO] Quote transformed amount: {quote['amount']}; data type: {type(quote['amount'])}")

            if quote.get('quote_line_items'):
                for item in quote['quote_line_items']:
                    # Individual price
                    print(f"[DEBUG INFO] Item original individual price: {item['individual_price']}; data type: {type(item['individual_price'])}")
                    item['individual_price'] = f"{item['individual_price'] / 100:,.2f}"
                    print(f"[DEBUG INFO] Item transformed individual price: {item['individual_price']}; data type: {type(item['individual_price'])}")

                    # Sum
                    print(f"[DEBUG INFO] Item original sum: {item['sum']}; data type: {type(item['sum'])}")
                    item['sum'] = f"{item['sum'] / 100:,.2f}"
                    print(f"[DEBUG INFO] Item transformed sum: {item['sum']}; data type: {type(item['sum'])}")

                    # Quantity (if it's also stored in cents — confirm if this is correct)
                    print(f"[DEBUG INFO] Item original quantity: {item['item_quantity']}; data type: {type(item['item_quantity'])}")
                    item['item_quantity'] = f"{item['item_quantity'] / 100:,.2f}"
                    print(f"[DEBUG INFO] Item transformed quantity: {item['item_quantity']}; data type: {type(item['item_quantity'])}")



            return {
                'statusCode': 200,
                'body': json.dumps(quote, default=str)
            }
        else:
            return {
                'statusCode': 404,
                'body': json.dumps({'message': 'Item not found'})
            }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def decimal_default(obj):
    if isinstance(obj, Decimal):
        return float(obj)
    raise TypeError

def convert_floats_to_decimal(obj):
    if isinstance(obj, float):
        return Decimal(str(obj))
    elif isinstance(obj, dict):
        return {k: convert_floats_to_decimal(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_floats_to_decimal(item) for item in obj]
    return obj

# =================== quote PDF Generation Functions ======================

class CircularImage(Flowable):
    def __init__(self, image_path, diameter):
        Flowable.__init__(self)
        self.image_path = image_path
        self.diameter = diameter
        self.width = diameter
        self.height = diameter

    def draw(self):
        canvas = self.canv
        radius = self.diameter / 2.0
        x = 0
        y = 0
        path = canvas.beginPath()
        path.circle(x + radius, y + radius, radius)
        canvas.clipPath(path, stroke=0, fill=0) # Apply the clipping path
        # Use a check here before drawing, as self.image_path might be None
        if self.image_path and os.path.exists(self.image_path):
            try:
                canvas.drawImage(self.image_path, x, y, width=self.diameter, height=self.diameter, mask='auto')
            except Exception as e:
                # Fallback if image drawing fails, e.g., corrupted image or unsupported format
                print(f"[ERROR] Failed to draw image from {self.image_path}: {e}")
                canvas.setFillColor(colors.grey) # Draw a grey circle as a fallback
                canvas.circle(x + radius, y + radius, radius, stroke=0, fill=1)
        else:
            # If path is None or file doesn't exist, draw a placeholder circle
            canvas.setFillColor(colors.lightgrey)
            canvas.circle(x + radius, y + radius, radius, stroke=0, fill=1)

def transform_quote_data(input_data):
    """Transform the input quote data to the required format"""
    print(f"[DEBUG] Starting transform_quote_data with input: {json.dumps(input_data, default=str)[:500]}...")

    transformed_data = {
        "quote_number": input_data.get("customized_number") or input_data.get("quote_id", "")[6:],
        "date": datetime.now().date().isoformat(),
        "valid_until": input_data.get("valid_until", ""),
        "currency": input_data.get("currency", "USD"),
        "currency_symbol": "$",  # Default currency symbol
        "language": input_data.get("language", "en"),
        "location_of_service": input_data.get("service_address", ""),
        "quote_id": input_data.get("quote_id", "")
    }

    print(f"[DEBUG] Basic transformed_data: {transformed_data}")

    # Set appropriate currency symbol based on currency
    currency_map = {
        "USD": "$",
        "EUR": "€",
        "GBP": "£",
        "CAD": "C$"
    }
    transformed_data["currency_symbol"] = currency_map.get(transformed_data["currency"], "$")
    print(f"[DEBUG] Currency symbol set to: {transformed_data['currency_symbol']}")

    # Create temporary files for logos in /tmp directory (Lambda writable location)
    temp_sender_logo = tempfile.NamedTemporaryFile(suffix='.jpg', delete=False, dir='/tmp')
    temp_hadronlink_logo = tempfile.NamedTemporaryFile(suffix='.jpg', delete=False, dir='/tmp')

    # Track the paths so the caller can clean them up later
    transformed_data["_temp_files_to_cleanup"] = []

    # Download and save the logo images from URLs
    sender_logo_url = input_data.get("sender_logo_url", "")
    hadronlink_logo_url = input_data.get("hadronlink_logo_url", "")

    print(f"[DEBUG] Logo URLs - Sender: {sender_logo_url[:100] if sender_logo_url else 'None'}...")
    print(f"[DEBUG] Logo URLs - Hadronlink: {hadronlink_logo_url[:100] if hadronlink_logo_url else 'None'}...")

    # Initialize paths to None; they will be set if download is successful
    transformed_data["sender_logo_path"] = None
    transformed_data["hadronlink_logo_path"] = None

    try:
        if sender_logo_url:
            print(f"[DEBUG] Attempting to download sender logo...")
            opener = urllib.request.build_opener()
            opener.addheaders = [('User-Agent', 'HadronLink quote Generator')]
            urllib.request.install_opener(opener)
            try:
                urllib.request.urlretrieve(sender_logo_url, temp_sender_logo.name)
                transformed_data["sender_logo_path"] = temp_sender_logo.name
                transformed_data["_temp_files_to_cleanup"].append(temp_sender_logo.name)
                temp_sender_logo.close()
                print(f"[DEBUG] Sender logo downloaded successfully to: {temp_sender_logo.name}")
            except urllib.error.URLError as url_err:
                print(f"[ERROR] Failed to download sender logo from {sender_logo_url}: {str(url_err)}")
            except Exception as e:
                print(f"[ERROR] Unexpected error with sender logo download {sender_logo_url}: {str(e)}")
        else:
            print(f"[DEBUG] No sender logo URL provided")

        if hadronlink_logo_url:
            print(f"[DEBUG] Attempting to download hadronlink logo...")
            try:
                urllib.request.urlretrieve(hadronlink_logo_url, temp_hadronlink_logo.name)
                transformed_data["hadronlink_logo_path"] = temp_hadronlink_logo.name
                transformed_data["_temp_files_to_cleanup"].append(temp_hadronlink_logo.name)
                temp_hadronlink_logo.close()
                print(f"[DEBUG] Hadronlink logo downloaded successfully to: {temp_hadronlink_logo.name}")
            except urllib.error.URLError as url_err:
                print(f"[ERROR] Failed to download HadronLink logo from {hadronlink_logo_url}: {str(url_err)}")
            except Exception as e:
                print(f"[ERROR] Unexpected error with HadronLink logo download {hadronlink_logo_url}: {str(e)}")
        else:
            print(f"[DEBUG] No hadronlink logo URL provided")
    except Exception as e:
        print(f"[ERROR] General error during logo download process: {str(e)}")

    # Ensure temporary file handles are closed even if download failed
    try:
        temp_sender_logo.close()
    except Exception:
        pass
    try:
        temp_hadronlink_logo.close()
    except Exception:
        pass

    # Format the "to" section using actual input schema fields
    to_details = []

    # Use customer_name if provided
    customer_name = (input_data.get("customer_name") or "").strip() or (input_data.get("homeowner_name") or "").strip()
    if customer_name:
        to_details.append(customer_name)
        print(f"[DEBUG] Added customer_name: {customer_name}")

    # Use service_address if provided
    service_address = (input_data.get("service_address") or "").strip() or (input_data.get("homeowner_location") or "").strip()
    if service_address:
        to_details.append(service_address)
        print(f"[DEBUG] Added service_address: {service_address}")

    # Use customer_phone if provided and not empty
    customer_phone = input_data.get("customer_phone", "").strip()
    if customer_phone:
        to_details.append(customer_phone)
        print(f"[DEBUG] Added customer_phone: {customer_phone}")

    # If no customer details, add a placeholder
    if not to_details:
        to_details.append("Customer information to be provided")
        print(f"[DEBUG] Added placeholder for customer info")

    transformed_data["to"] = {"details": to_details}
    print(f"[DEBUG] TO section: {transformed_data['to']}")

    # Format the "from" section using actual input schema fields
    from_details = []

    # Use professional_name if provided and not empty
    professional_name = input_data.get("professional_name", "").strip()
    if professional_name:
        from_details.append(professional_name)
        print(f"[DEBUG] Added professional_name: {professional_name}")

    # Use professional_phone if provided and not empty
    professional_phone = input_data.get("professional_phone", "").strip()
    if professional_phone:
        from_details.append(professional_phone)
        print(f"[DEBUG] Added professional_phone: {professional_phone}")

    transformed_data["from"] = {"details": from_details}
    print(f"[DEBUG] FROM section: {transformed_data['from']}")

    # Transform line items using actual input schema
    items = []
    quote_line_items = input_data.get("quote_line_items", [])
    print(f"[DEBUG] Processing {len(quote_line_items)} line items")

    for i, item in enumerate(quote_line_items):
        print(f"[DEBUG] Processing item {i}: {item}")

        if item.get("item_description_en") != '':
            description = item.get("item_description_en")
        elif item.get("item_description_fr") != '':
            description = item.get("item_description_fr")
        elif item.get("item_description_es") != '':
            description = item.get("item_description_es")
        elif item.get("item_description_pt") != '':
            description = item.get("item_description_pt")

        raw_rate = item.get("individual_price", 0)
        raw_quantity = item.get("item_quantity", 0)/100
        raw_amount = item.get("sum", 0)

        rate = Decimal(str(raw_rate)) / Decimal('100')
        quantity = Decimal(str(raw_quantity))  # Not in cents
        amount = Decimal(str(raw_amount)) / Decimal('100')

        print(f"[DEBUG] Item {i} - Raw: rate={raw_rate}, quantity={raw_quantity}, amount={raw_amount}")
        print(f"[DEBUG] Item {i} - Processed: rate={rate}, quantity={quantity}, amount={amount}")

        items.append({
            "description": description,
            "quantity": quantity,
            "rate": rate,
            "amount": amount
        })

    transformed_data["items"] = items
    print(f"[DEBUG] Processed {len(items)} items successfully")

    transformed_data["taxes"] = []
    print(f"[DEBUG] Set empty taxes list")

    # Get comments using actual schema fields
    comments = ""
    lang = transformed_data["language"]

    print(f"[DEBUG] Looking for comments in language: {lang}")

    # Try the comment fields that exist in your schema
    comment_fields = [
        f"comments_payments_{lang}",
        "comments_payments_en",
        "description"  # Use description as fallback comment
    ]

    for field in comment_fields:
        field_value = input_data.get(field, "").strip()
        print(f"[DEBUG] Checking comment field '{field}': '{field_value}'")
        if field_value:
            comments = field_value
            print(f"[DEBUG] Using comments from field '{field}': '{comments}'")
            break

    transformed_data["comments"] = comments

    # Add additional fields from your schema that might be useful
    transformed_data["estimated_start_date"] = input_data.get("estimated_start_date", "")
    transformed_data["time_frame"] = input_data.get("time_frame", "")
    transformed_data["status"] = input_data.get("status", "")

    print(f"[DEBUG] Additional fields - start_date: {transformed_data['estimated_start_date']}, time_frame: {transformed_data['time_frame']}")
    print(f"[DEBUG] Transform completed successfully. Final data keys: {list(transformed_data.keys())}")

    return transformed_data

def generate_quote(data, quote_id, lang='en'):
    print(f"[DEBUG] Starting generate_quote for quote_id: {quote_id}, language: {lang}")
    print(f"[DEBUG] Input data keys: {list(data.keys())}")

    # Custom colors
    purple = colors.HexColor("#313886")
    blue = colors.HexColor("#4B85D2")
    grey80 = colors.HexColor("#7E8BB4")
    grey60 = colors.HexColor("#A8B0CC")
    grey20 = colors.HexColor("#EFF2FA")
    red = colors.red
    green = colors.green
    blue_grid = colors.blue

    # Get file information with a unique timestamp to prevent overwriting
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    quote_filename = f"/tmp/{quote_id}_{lang}_{timestamp}.pdf"
    print(f"[DEBUG] PDF will be saved as: {quote_filename}")

    # Track temporary files for cleanup
    # Start with the PDF itself. We'll add downloaded images from 'data' later.
    temp_files_to_cleanup = [quote_filename]

    currency = data.get("currency", "USD")
    currency_symbol = data.get("currency_symbol", "$")
    print(f"[DEBUG] Currency: {currency}, Symbol: {currency_symbol}")

    try:
        # Create document with 0.5 inch margins
        print(f"[DEBUG] Creating PDF document...")
        doc = SimpleDocTemplate(quote_filename, pagesize=letter,
                                leftMargin=0.5 * inch, rightMargin=0.5 * inch,
                                topMargin=0.5 * inch, bottomMargin=0.5 * inch)

        # Get and extend styles
        styles = getSampleStyleSheet()

        # Add custom styles (your existing style definitions)
        styles.add(ParagraphStyle(name='quoteTitle',
                                     parent=styles['Normal'],
                                     fontName='Helvetica-Bold',
                                     textColor=purple,
                                     fontSize=14))

        styles.add(ParagraphStyle(name='SectionTitle',
                                     parent=styles['Normal'],
                                     textColor=grey80,
                                     fontName='Helvetica-Bold'))

        styles.add(ParagraphStyle(name='FooterText',
                                     parent=styles['Normal'],
                                     textColor=grey80,
                                     fontSize=8))

        styles.add(ParagraphStyle(name='GrandTotalStyle',
                                     parent=styles['Normal'],
                                     fontName='Helvetica-Bold',
                                     textColor=purple))

        styles.add(ParagraphStyle(name='GrandTotalAmountStyle',
                                     parent=styles['Normal'],
                                     fontName='Helvetica-Bold',
                                     alignment=2,
                                     textColor=purple))

        styles.add(ParagraphStyle(name='MixedStyle',
                                     parent=styles['Normal'],
                                     textColor=grey80,
                                     fontName='Helvetica-Bold'))

        styles.add(ParagraphStyle(name='NormalText',
                                     parent=styles['Normal'],
                                     textColor=colors.black,
                                     fontName='Helvetica'))

        styles.add(ParagraphStyle(name='RightAlign',
                                     parent=styles['Normal'],
                                     alignment=2))

        styles.add(ParagraphStyle(name='SectionTitleRight',
                                     parent=styles['SectionTitle'],
                                     fontName='Helvetica-Bold',
                                     textColor=grey80,
                                     alignment=2))

        print(f"[DEBUG] Document and styles created successfully")

        story = []
        top_line = HRFlowable(width="100%", thickness=2, color=purple,
                                spaceBefore=0, spaceAfter=0.1 * inch)
        story.append(top_line)
        story.append(Spacer(1, 0.1 * inch))

        # Get local paths from transformed_data
        sender_logo_path = data.get("sender_logo_path")
        hadronlink_logo_path = data.get("hadronlink_logo_path")
        print(f"[DEBUG] Logo paths - Sender: {sender_logo_path}, Hadronlink: {hadronlink_logo_path}")

        # Add any downloaded temporary image files to the cleanup list
        temp_files_to_cleanup.extend(data.get("_temp_files_to_cleanup", []))

        # quote Header with purple bold title and sender logo in the same row
        # Use your CircularImage class with the downloaded path
        if sender_logo_path and os.path.exists(sender_logo_path):
            print(f"[DEBUG] Using sender logo from: {sender_logo_path}")
            sender_logo = CircularImage(sender_logo_path, 0.8 * inch)
        else:
            print(f"[DEBUG] No sender logo available, using placeholder")
            # Fallback to placeholder if download failed or path is None
            drawing = Drawing(0.8 * inch, 0.8 * inch)
            circle = Circle(0.4 * inch, 0.4 * inch, 0.4 * inch,
                            fillColor=colors.transparent,
                            strokeColor=colors.transparent)
            drawing.add(circle)
            sender_logo = drawing

        # Date text for header
        date_text = f'<font name="Helvetica-Bold" color="{grey80.hexval()}">{PLACEHOLDERS["date"][lang]}</font><font name="Helvetica">{data["date"]}</font>'
        print(f"[DEBUG] Header text created: {date_text}")
        valid_until_text = f'<font name="Helvetica-Bold" color="{grey80.hexval()}">{PLACEHOLDERS["valid_until"][lang]}</font><font name="Helvetica">{data["valid_until"]}</font>'

        header_data = [
            [Paragraph(f"{PLACEHOLDERS['quote_number'][lang]}{data['quote_number']}", styles['quoteTitle']), "", "", sender_logo],
            [Paragraph(date_text, styles['Normal']), "", "", ""],
            [Paragraph(f"<u>{valid_until_text}</u>", styles['Normal']), "", "", ""]
        ]

        header_table = Table(header_data, colWidths=[260, 0, 130, 140])

        header_table.setStyle(TableStyle([
            ("SPAN", (0, 0), (2, 0)),
            ("SPAN", (0, 1), (2, 1)),
            ("SPAN", (3, 0), (3, 1)),
            ("ALIGN", (3, 0), (3, 1), "RIGHT"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))

        story.append(header_table)
        story.append(Spacer(1, 0.2 * inch))
        print(f"[DEBUG] Header section added to story")

        # TO and FROM sections
        to_data = data.get("to", {})
        from_data = data.get("from", {})
        print(f"[DEBUG] TO data: {to_data}")
        print(f"[DEBUG] FROM data: {from_data}")

        to_section = [
            Paragraph(PLACEHOLDERS['to'][lang], styles['SectionTitle']),
        ]
        for item in to_data.get("details", []):
            to_section.append(Paragraph(item, styles['Normal']))

        from_section = [
            Paragraph(PLACEHOLDERS['from'][lang], styles['SectionTitle']),
        ]
        for item in from_data.get("details", []):
            from_section.append(Paragraph(item, styles['Normal']))

        max_rows = max(len(to_section), len(from_section))

        info_table_data = []
        for i in range(max_rows):
            row = ["", ""]
            if i < len(to_section):
                row[0] = to_section[i]
            if i < len(from_section):
                row[1] = from_section[i]
            info_table_data.append(row)

        info_table = Table(info_table_data, colWidths=[doc.width * 0.65, doc.width * 0.35])

        info_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ALIGN', (0, 0), (1, -1), 'LEFT'),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))

        story.append(info_table)
        story.append(Spacer(1, 0.2 * inch))
        print(f"[DEBUG] TO/FROM sections added to story")

        # Location of service and additional info
        location_data = [
            [Paragraph(PLACEHOLDERS['location_of_service'][lang], styles['SectionTitle'])],
            [Paragraph(data.get("location_of_service", ""), styles['Normal'])],
            [''],
        ]

        # Add estimated start date if available
        if data.get("estimated_start_date"):
            location_data.append([Paragraph(PLACEHOLDERS['estimated_start_date'][lang], styles['SectionTitle'])])
            location_data.append([Paragraph(data.get("estimated_start_date", ""), styles['Normal'])])
            print(f"[DEBUG] Added estimated start date: {data.get('estimated_start_date')}")

        # Add time frame if available
        if data.get("time_frame"):
            location_data.append([Paragraph(PLACEHOLDERS['time_frame'][lang], styles['SectionTitle'])])
            location_data.append([Paragraph(data.get("time_frame", ""), styles['Normal'])])
            print(f"[DEBUG] Added time frame: {data.get('time_frame')}")

        location_table = Table(location_data)
        location_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ]))
        story.append(location_table)
        story.append(Spacer(1, 0.3 * inch))
        print(f"[DEBUG] Location section added to story")

        # Item Description Table with styled headers
        item_data = [
            [Paragraph(PLACEHOLDERS['items_table_first_column'][lang], styles['SectionTitle']),
             Paragraph(PLACEHOLDERS['items_table_second_column'][lang], styles['SectionTitleRight']),
             Paragraph(PLACEHOLDERS['items_table_third_column'][lang], styles['SectionTitleRight']),
             Paragraph(PLACEHOLDERS['items_table_fourth_column'][lang], styles['SectionTitleRight'])],
        ]

        items_list = data.get("items", [])
        print(f"[DEBUG] Processing {len(items_list)} items for PDF")

        for i, item in enumerate(items_list):
            description = item.get("description", "")
            quantity = float(item.get('quantity', 0))
            rate = float(item.get('rate', 0))
            amount = float(item.get('amount', 0))

            print(f"[DEBUG] Item {i}: desc='{description}', qty={quantity}, rate={rate}, amount={amount}")

            item_data.append([
                description,
                f"{quantity:.2f}",
                f"{rate:.2f}",
                f"{amount:.2f}"
            ])

        colWidths = [doc.width * 0.55, doc.width * 0.15, doc.width * 0.15, doc.width * 0.15]
        rowHeights = [30] + [None] * (len(item_data) - 1)

        item_table = Table(item_data, colWidths=colWidths, rowHeights=rowHeights)
        item_table.setStyle(TableStyle([
            ('LINEABOVE', (0, 0), (-1, 0), 1, grey80),
            ('LINEBELOW', (0, 0), (-1, 0), 1, grey80),
            ('LINEBELOW', (0, -1), (-1, -1), 1, grey80),
            ('ALIGN', (1, 1), (-1, -1), 'RIGHT'),
            ('VALIGN', (0, 0), (-1, 0), 'CENTER'),
        ]))

        story.append(item_table)
        story.append(Spacer(1, 0.2 * inch))
        print(f"[DEBUG] Items table added to story")

        # Calculate subtotal
        subtotal = sum(item.get("amount", Decimal('0')) for item in data.get("items", []))
        print(f"[DEBUG] Calculated subtotal: {subtotal}")

        summary_data = [
            [Paragraph(PLACEHOLDERS['total'][lang], styles['GrandTotalStyle']), "", "", f"{currency_symbol} {subtotal:,.2f}"],
            ["", "", "", Paragraph(PLACEHOLDERS['taxes'][lang], styles['GrandTotalAmountStyle'])],
        ]

        tax_total = 0
        taxes_list = data.get("taxes", [])
        print(f"[DEBUG] Processing {len(taxes_list)} taxes")

        for tax in taxes_list:
            tax_name = tax.get("name", "")
            tax_rate = float(tax.get("rate", 0))/100
            tax_amount = (subtotal * Decimal(str(tax_rate))).quantize(Decimal('.01'), rounding=ROUND_HALF_UP)
            tax_total += tax_amount
            tax_label = f"{tax_name} {tax_rate*100:.1f}%"
            # summary_data.append([Paragraph(tax_label, styles['SectionTitle']), "", "", f"{currency_symbol} {tax_amount:,.2f}"])
            print(f"[DEBUG] Added tax: {tax_label}, amount: {tax_amount}")

        grand_total = subtotal + tax_total
        print(f"[DEBUG] Grand total: {grand_total}")

        # summary_data.append([
        #     Paragraph(PLACEHOLDERS['total'][lang], styles['GrandTotalStyle']),
        #     "",
        #     "",
        #     Paragraph(f"{currency_symbol} {grand_total:,.2f}", styles['GrandTotalAmountStyle'])
        # ])

        summary_table = Table(summary_data, colWidths=[doc.width*0.55, doc.width*0.15, doc.width*0.15, doc.width*0.15])
        summary_table.setStyle(TableStyle([
            ('ALIGN', (2, 0), (3, -1), 'RIGHT'),
        ]))

        story.append(summary_table)
        story.append(Spacer(1, 0.3 * inch))
        print(f"[DEBUG] Summary table added to story")

        # Add comments if present

        comments_data = [
            [Paragraph(PLACEHOLDERS['comments'][lang], styles['SectionTitle'])],
        ]
        comments_table = Table(comments_data)
        comments_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ]))
        story.append(comments_table)

        comments = data.get("comments", "")
        if comments:
            print(f"[DEBUG] Adding comments: {comments}")
            story.append(Spacer(1, 0.2*inch))
            comments_style = ParagraphStyle(
                'Comments',
                parent=styles['Normal'],
                textColor=colors.black
            )
            comments_para = Paragraph(comments, comments_style)
            story.append(comments_para)
        else:
            print(f"[DEBUG] No comments to add")

        story.append(Spacer(1, 0.5 * inch))

        # Footer Canvas
        class FooterCanvas:
            def __init__(self, doc_ref, local_hadronlink_logo_path_ref):
                self.doc = doc_ref
                self.width = letter[0]
                self.height = letter[1]
                self.top_frame_coords = (doc_ref.leftMargin, doc_ref.topMargin, doc_ref.width, doc_ref.height + 0 * inch)
                self.bottom_frame_coords = (doc_ref.leftMargin, doc_ref.bottomMargin, doc_ref.width, 1 * inch)
                self.local_hadronlink_logo_path = local_hadronlink_logo_path_ref

            def __call__(self, canvas, doc):
                canvas.saveState()

                # Draw the purple line above footer
                canvas.setStrokeColor(purple)
                canvas.setLineWidth(1)
                canvas.line(0.5 * inch, 1.1 * inch, self.width - 0.5 * inch, 1.1 * inch)

                # Draw the hadronlink logo or placeholder
                if self.local_hadronlink_logo_path and os.path.exists(self.local_hadronlink_logo_path):
                    canvas.drawImage(self.local_hadronlink_logo_path, self.width - 2.5 * inch, 0.5 * inch,
                                     width=2 * inch, height=0.5 * inch)
                else:
                    canvas.setFont('Helvetica', 10)
                    canvas.setFillColor(grey80)
                    canvas.drawString(self.width - 2.5 * inch, 0.7 * inch, "HADRONLINK LOGO MISSING")

                # Draw "Powered by" text
                canvas.setFont('Helvetica', 10)
                canvas.setFillColor(grey80)
                canvas.drawString(0.5 * inch, 0.8 * inch, "Powered by")

                # Draw website URL
                canvas.drawString(self.width - 1.92 * inch, 0.5 * inch, "www.hadronlink.com")

                canvas.restoreState()

        # Create frames and page template
        top_frame = Frame(doc.leftMargin, doc.topMargin, doc.width, doc.height, id='top_frame')
        bottom_frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, 1 * inch, id='bottom_frame')

        page_template = PageTemplate(
            id='quote_template',
            frames=[top_frame, bottom_frame],
            onPage=FooterCanvas(doc, hadronlink_logo_path)
        )

        doc.addPageTemplates([page_template])
        print(f"[DEBUG] Page template and footer created")

        # Build the document
        print(f"[DEBUG] Building PDF document with {len(story)} elements...")

        doc.build(story)
        print(f"[DEBUG] Successfully built PDF at: {quote_filename}")

        # Verify file was created
        if os.path.exists(quote_filename):
            file_size = os.path.getsize(quote_filename)
            print(f"[DEBUG] PDF file created successfully, size: {file_size} bytes")
        else:
            print(f"[ERROR] PDF file was not created at expected location: {quote_filename}")
            return None, temp_files_to_cleanup

        return quote_filename, temp_files_to_cleanup

    except Exception as e:
        print(f"[ERROR] Failed to build PDF document for quote {quote_id} ({lang}): {str(e)}")
        print(f"[ERROR] Exception type: {type(e).__name__}")
        import traceback
        print(f"[ERROR] Traceback: {traceback.format_exc()}")

        # Clean up any partially created PDF if build fails
        if os.path.exists(quote_filename):
            os.remove(quote_filename)
        return None, temp_files_to_cleanup

def generate_multilingual_quotes(json_file):
    try:
        # Load the JSON data
        with open(json_file, 'r', encoding='utf-8') as f:
            input_data = json.load(f)

        # Transform the input data
        data = transform_quote_data(input_data)

        # Generate quotes for each language
        languages = ['en', 'fr', 'es', 'pt']
        generated_files = []

        for lang in languages:
            quote_file = generate_quote(data, lang)
            generated_files.append(quote_file)

        print(f"All quotes generated successfully: {', '.join(generated_files)}")

    except Exception as e:
        print(f"Error generating quotes: {str(e)}")

def cleanup_temp_files(file_list):
    for file_path in file_list:
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                print(f"[DEBUG INFO] Removed temporary file: {file_path}")
        except Exception as e:
            print(f"[ERROR] Failed to remove temporary file {file_path}: {str(e)}")

def upload_pdf_to_google_storage(local_file_path, quote_id, language):
    """
    Uploads a PDF file to Google Cloud Storage

    Args:
        local_file_path (str): Path to the local PDF file
        quote_id (str): ID of the quote
        language (str): Language code of the quote (en, fr, es, pt)

    Returns:
        str: Public URL of the uploaded file
    """
    try:
        # Get the bucket
        bucket = client.bucket(BUCKET_NAME)

        # Define the destination path in the bucket
        destination_blob_name = f"{BUCKET_FOLDER}/{quote_id}_{language}.pdf"

        # Create a blob object
        blob = bucket.blob(destination_blob_name)

        # Upload the file
        blob.upload_from_filename(local_file_path)

        print(f"[DEBUG INFO] File {local_file_path} uploaded to {destination_blob_name}")

        # Return the public URL
        filename_to_save_in_table = os.path.basename(destination_blob_name)

        # Return this filename for storage
        return filename_to_save_in_table

    except Exception as e:
        print(f"[ERROR] Failed to upload PDF to Google Storage: {str(e)}")
        return None

def generate_single_language_quote(payload):
    print(f"[DEBUG] Starting generate_single_language_quote")
    print(f"[DEBUG] Payload keys: {list(payload.keys())}")

    try:
        # Transform the input data to the required format
        print(f"[DEBUG] Calling transform_quote_data...")
        quote_data = transform_quote_data(payload)
        print(f"[DEBUG] Transform completed successfully")

        # Get the desired language from the quote data
        language = quote_data.get("language", "en")  # Default to 'en' if not specified
        quote_id = quote_data.get("quote_id")

        print(f"[DEBUG] Quote ID: {quote_id}, Language: {language}")

        # If language is empty, default to 'en'
        if not language:
            language = "en"
            print(f"[DEBUG] Language was empty, defaulted to 'en'")

        # Generate the quote for the specified language
        print(f"[DEBUG] Calling generate_quote...")
        quote_file, temp_files = generate_quote(quote_data, quote_id, language)

        # Check if PDF generation was successful
        if quote_file is None:
            print("[ERROR] Failed to generate quote PDF - generate_quote returned None")
            cleanup_temp_files(temp_files)
            return None

        print(f"[DEBUG] PDF generation completed successfully: {quote_file}")

        # Upload the generated PDF to Google Cloud Storage
        print(f"[DEBUG] Uploading PDF to Google Cloud Storage...")
        pdf_url = upload_pdf_to_google_storage(quote_file, quote_id, language)

        if pdf_url:
            print(f"[DEBUG] PDF uploaded successfully, filename: {pdf_url}")
        else:
            print("[ERROR] Failed to upload PDF to storage")

        # Clean up temporary files
        print(f"[DEBUG] Cleaning up {len(temp_files)} temporary files...")
        cleanup_temp_files(temp_files)

        if pdf_url:
            print(f"[DEBUG] Quote generation process completed successfully")
            return pdf_url
        else:
            print("[ERROR] PDF upload failed, returning None")
            return None

    except Exception as e:
        print(f"[ERROR] Exception in generate_single_language_quote: {str(e)}")
        print(f"[ERROR] Exception type: {type(e).__name__}")
        import traceback
        print(f"[ERROR] Traceback: {traceback.format_exc()}")
        return None
