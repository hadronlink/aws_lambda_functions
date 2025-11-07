import os
import json
import base64
import socket
import tempfile
from datetime import datetime
from decimal import Decimal, ROUND_HALF_UP
import urllib.request
import requests
from requests.auth import HTTPBasicAuth

import boto3
from boto3.dynamodb.conditions import Key

from PIL import Image

from google.oauth2 import service_account
from google.cloud import storage

from opensearchpy import OpenSearch, RequestsHttpConnection
from aws_requests_auth.aws_auth import AWSRequestsAuth

from invoice_generator import lambda_handler_generate_invoice

from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Flowable, HRFlowable, Frame
)
from reportlab.platypus.doctemplate import PageTemplate
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.graphics.shapes import Drawing, Circle


# Initialize DynamoDB resources
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('invoices')
table_services_requests = dynamodb.Table('services_requests')
table_chats = dynamodb.Table('chats')
table_roles = dynamodb.Table('roles')

# Initialize Google Storage client for PDF storage
creds_json = base64.b64decode(os.environ['GOOGLE_CREDENTIALS_JSON'])
creds = service_account.Credentials.from_service_account_info(json.loads(creds_json)) # type: ignore
client = storage.Client(credentials=creds)

# Constants
BUCKET_NAME = 'hadronlink_pictures'
BUCKET_FOLDER = 'web_invoices'
TEMP_DIR = '/tmp/temp_images'

# Create temp directory if it doesn't exist
os.makedirs(TEMP_DIR, exist_ok=True)

# Define placeholders for multilingual support
PLACEHOLDERS = {
    "invoice_number": {
        "en": "Invoice Nº ",
        "fr": "Facture nº ",
        "es": "Factura nº ",
        "pt": "Fatura nº "
    },
    "due_date": {
        "en": "DUE DATE: ",
        "fr": "DATE D'ÉCHÉANCE: ",
        "es": "VENCIMIENTO: ",
        "pt": "VENCIMENTO: "
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
    "subtotal": {
        "en": "Subtotal",
        "fr": "Sous-total",
        "es": "Subtotal",
        "pt": "Subtotal"
    },
    "grandtotal": {
        "en": "Grand Total",
        "fr": "Total général",
        "es": "Total general",
        "pt": "Total geral"
    }
}


# OpenSearch configuration for profiles
OPENSEARCH_ENDPOINT = 'https://search-connecus-home-xter5mxymdzivmnio2iuvwgg4a.us-east-2.es.amazonaws.com'
OPENSEARCH_INDEX = 'pros_from_xano_live'
AWS_REGION = 'us-east-2'
SECRETS_MANAGER_SECRET_NAME = 'opensearch-credentials'

def get_secret(secret_name):
    """
    Retrieves a secret from AWS Secrets Manager.
    """
    # Create a Secrets Manager client
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
        # Depending on the error, you might want to re-raise or handle it gracefully
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print(f"The requested secret {secret_name} was not found.")
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            print(f"The request was invalid for the secret {secret_name}.")
        # Add more specific error handling as needed
        raise e # Re-raise the exception to stop function execution

    else:
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            return json.loads(secret)
        else:
            # Handle binary secret if needed
            print(f"Secret '{secret_name}' is not a string. This example expects a string.")
            return json.loads(get_secret_value_response['SecretBinary'].decode('utf-8'))
  
# Get OpenSearch credentials from Secrets Manager
opensearch_credentials = get_secret(SECRETS_MANAGER_SECRET_NAME)
username = opensearch_credentials.get('username')
password = opensearch_credentials.get('password')

# Use HTTPBasicAuth for username/password authentication
auth = HTTPBasicAuth(username, password)
headers = {"Content-Type": "application/json"} 


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
    url = f"{OPENSEARCH_ENDPOINT}/{OPENSEARCH_INDEX}/_search"

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

def get_professional_from_opensearch(opensearch_doc_id):
    """
    Retrieves a single professional document from OpenSearch by its document ID.
    """
    print(f"[DEBUG] Initializing get professional from open search ...")
    url = f"{OPENSEARCH_ENDPOINT}/{OPENSEARCH_INDEX}/_doc/{opensearch_doc_id}"

    try:
        response = requests.get(url, auth=auth, headers=headers)
        response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
        json_response = response.json()
        print(f"[DEBUG] OpenSearch response for doc ID {opensearch_doc_id}: {json_response}")

        # Safely access the 'doc' inside '_source'
        doc = json_response.get('_source', {}).get('doc')

        if doc is None:
            # Document not found or '_source.doc' is missing
            return {
                'statusCode': 404,
                'body': json.dumps({'error': "Professional document not found or 'doc' field is missing."})
            }

        return doc

    except requests.exceptions.RequestException as e:
        print(f"Network or request error getting professional from OpenSearch: {e}")
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
        print(f"An unexpected error occurred getting professional from OpenSearch: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def get_professional_by_role_id(role_id):
    """Get professional profile from OpenSearch by role_id using two-step process"""
    try:
        # Step 1: Get role data from DynamoDB
        role_response = table_roles.query(
            IndexName='role_id-index',
            KeyConditionExpression=Key('role_id').eq(role_id),
            Limit=1
        )
        
        if not role_response.get('Items'):
            print(f"No role found for role_id: {role_id}")
            return None
            
        role_data = role_response['Items'][0]
        xano_user_type = role_data.get('xano_user_type')
        xano_profile_id = role_data.get('xano_profile_id')
        
        if not xano_user_type or not xano_profile_id:
            print(f"Missing xano_user_type or xano_profile_id for role_id: {role_id}")
            return None
            
        # Step 2: Construct OpenSearch document ID
        opensearch_doc_id = f"{xano_user_type}_{xano_profile_id}"
        print(f"[DEBUG] Looking for professional with document ID: {opensearch_doc_id}")
        
        # Step 3: Get professional from OpenSearch
        profile = get_professional_from_opensearch(opensearch_doc_id)
        print(f"[DEBUG] Found profile: {profile}")
        return profile
        
    except Exception as e:
        print(f"Error getting professional by role_id {role_id}: {e}")
        return None


def lambda_handler(event, context):
    operation = event['httpMethod']
    payload = event['queryStringParameters'] if operation == 'GET' else json.loads(event['body']) if event.get('body') else {}

    try:
        if operation == 'PUT':
            return update_item(payload)
        elif operation == 'POST':
            # Check if this is a request to generate a PDF invoice
            if payload.get('action') == 'generate_pdf':
                return generate_pdf_invoice(payload)
            else:
                return create_item(payload)
        elif operation == 'GET':
            return handle_get(event, payload)
        elif operation == 'DELETE':
            return delete_item(payload)
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

def create_item(payload):
    print(f' Payload: {payload}')
    print('[DEBUG INFO] Check if it is premium or has enough credits...')
    
    # Retrieve authenticated pro information
    professional = payload.get('professional')
    
    try:
        pro_response = table_roles.query(
            IndexName='role_id-index',
            KeyConditionExpression=Key('role_id').eq(professional),
            Limit=1
        )

        professional_data = get_professional_by_role_id (professional)
        print(f'[DEBUG INFO] Professional data: {professional_data}')
        if professional_data:
            pro_credits = professional_data.get('credits_balance', 0)

        if pro_response.get('Items'):
            pro_profile = pro_response['Items'][0]
            pro_premium = pro_profile.get('is_premium', False)
            pro_xano_acct_id = pro_profile.get('xano_acct_id')
            pro_xano_user_type = pro_profile.get('xano_user_type')
            pro_xano_user_id = pro_profile.get('xano_user_id')

            if pro_premium == True:
                print('[DEBUG INFO] Professional is premium.')
                deduct_credits = False

            if pro_premium == False and pro_credits >= payload['necessary_credits']:
                print('[DEBUG INFO] Professional has enough credits.')
                deduct_credits = True

            if pro_premium == False and pro_credits < payload['necessary_credits']:
                print('[DEBUG INFO] Professional does not have enough credits.')
                return {
                    'statusCode': 402,
                    'body': json.dumps({'error': 'Insufficient credits'})
                }

            if pro_premium == True or pro_credits >= payload['necessary_credits']:
                print('[DEBUG INFO] Initiating create_item for invoice...')
                try:
                    # Validate required fields
                    required_fields = ['chat_id', 'invoice_id']
                    for field in required_fields:
                        if field not in payload:
                            return {
                                'statusCode': 400,
                                'body': json.dumps({'error': f'Missing required field: {field}'})
                            }

                    # Validate date formats if provided
                    date_fields = ['work_start_date', 'work_end_date', 'invoice_due_date']
                    for date_field in date_fields:
                        if date_field in payload and payload[date_field]:  # Checks existence and that it's not None or empty string
                            try:
                                datetime.strptime(payload[date_field], '%Y-%m-%d')
                            except ValueError:
                                return {
                                    'statusCode': 400,
                                    'body': json.dumps({'error': f'Invalid date format for {date_field}. Expected YYYY-MM-DD'})
                                }

                    # Retrieve homeowner_language and professional_language from table_chats
                    try:
                        original_chat = table_chats.get_item(
                            Key={'chat_id': payload['chat_id']},
                            ProjectionExpression='homeowner_language, professional_language, homeowner'
                        )
                        if 'Item' in original_chat:
                            homeowner = original_chat['Item'].get('homeowner')
                            homeowner_language = original_chat['Item'].get('homeowner_language')
                            professional_language = original_chat['Item'].get('professional_language')
                            payload['homeowner_language'] = homeowner_language
                            payload['professional_language'] = professional_language
                        else:
                            print(f"[WARNING] Chat with id {payload['chat_id']} not found when trying to retrieve language information.")
                    except Exception as e:
                        print(f'[ERROR] Failed to retrieve language information from chat: {str(e)}')
                        # Proceed without language information in case of an error

                    # =============== Generate the invoice pdf =========================
                    try:
                        # Check if generate_single_language_invoice function exists and is available in the scope
                        # This will help us identify if the function is missing or not imported correctly
                        missing_function = False
                        try:
                            if 'generate_single_language_invoice' not in globals():
                                print("[ERROR] The generate_single_language_invoice function is not in globals")
                                missing_function = True
                        except Exception as e:
                            print(f"[ERROR] Error checking for generate_single_language_invoice: {str(e)}")
                            missing_function = True
                            
                        if missing_function:
                            print("[ERROR] Cannot generate invoice PDF: Missing required function")
                            pdf_file_name = ""
                        else:
                            # The function exists, let's call it
                            pdf_file_name = generate_single_language_invoice(payload)
                            if pdf_file_name is None:
                                print("[ERROR] Invoice generation returned None instead of a file path")
                                pdf_file_name = "" 
                    except Exception as e:
                        print(f"[ERROR] Error generating pdf: {str(e)}")
                        pdf_file_name = "" # Provide a default empty string in case of error

                    payload['invoice_pdf_files'] = {lang: "" for lang in ["en", "fr", "es", "pt"]}

                    # Set the file if the language is supported
                    language = payload.get('language', 'en')  # Default to English if no language specified
                    if language in payload['invoice_pdf_files'] and pdf_file_name:
                        payload['invoice_pdf_files'][language] = pdf_file_name

                    # Convert any float values to Decimal before storing in DynamoDB
                    decimal_payload = convert_floats_to_decimal(payload)

                    # =============== Store the invoice in the invoices_dev table ===========
                    del decimal_payload['hadronlink_logo_url']
                    del decimal_payload['sender_logo_url']
                    decimal_payload['invoice_language'] = language
                    del decimal_payload['language']
                    decimal_payload['created_at'] = int(datetime.now().strftime("%Y%m%d%H%M%S"))
                    table.put_item(Item=decimal_payload)

                    # Update all roles credits_balance under the same xano_user_id
                    if deduct_credits == True:
                        print('[DEBUG INFO] Deducting credits...')
                        try:
                            # Since xano_user_id is the partition key, use query to efficiently find all roles
                            roles_with_same_user = table_roles.query(
                                KeyConditionExpression=Key('xano_user_id').eq(pro_xano_user_id)
                            )
                            
                            if roles_with_same_user.get('Items'):
                                roles_count = len(roles_with_same_user['Items'])
                                print(f'[DEBUG INFO] Found {roles_count} roles with xano_user_id: {pro_xano_user_id}')
                                
                                for role in roles_with_same_user['Items']:
                                    role_id = role.get('role_id', 'unknown')
                                    print(f'[DEBUG INFO] Updating credits for role: {role_id}')
                                    
                                    # We need to use both xano_user_id AND role_id as the key
                                    # Get the role's specific key elements
                                    role_id = role.get('role_id')
                                    
                                    # Create the proper composite key based on the table schema
                                    # Adjust these key elements based on your actual DynamoDB table's primary key structure
                                    item_key = {
                                        'xano_user_id': pro_xano_user_id,
                                        'role_id': role_id  # Add this if your table uses a composite key
                                    }
                                    
                                    # Update the item's credits balance
                                    update_response = table_roles.update_item(
                                        Key=item_key,
                                        UpdateExpression='SET credits_balance = credits_balance - :val',
                                        ExpressionAttributeValues={':val': payload['necessary_credits']},
                                        ReturnValues='UPDATED_NEW'
                                    )
                                    
                                    updated_credits = update_response.get('Attributes', {}).get('credits_balance')
                                    print(f'[DEBUG INFO] Updated role {role_id}, new credits: {updated_credits}')
                            else:
                                print(f'[WARNING] No roles found with xano_user_id: {pro_xano_user_id}')
                                
                        except Exception as e:
                            print(f'[ERROR] Failed to update role credits_balance: {str(e)}')

                    # Retrieve homeowner information from table_roles if available
                    homeowner_contact_info = {}
                    if 'homeowner' in locals():
                        try:
                            homeowner_response = table_roles.query(
                                IndexName='role_id-index',
                                KeyConditionExpression=Key('role_id').eq(homeowner),
                                Limit=1
                            )
                            homeowner_items = homeowner_response.get('Items', [])
                            homeowner_profile = homeowner_items[0] if homeowner_items else None
                            homeowner_name = homeowner_profile.get('name', '') if homeowner_profile else ''
                            homeowner_email = homeowner_profile.get('email', '') if homeowner_profile else ''
                            homeowner_system_phone = homeowner_profile.get('phone', '') if homeowner_profile else ''
                            homeowner_contact_info = {
                                'homeowner_name': homeowner_name, 
                                'homeowner_email': homeowner_email, 
                                'homeowner_system_phone': homeowner_system_phone, 
                                'homeowner_language': homeowner_language if 'homeowner_language' in locals() else '',
                                'homeowner_role_id': homeowner
                            }
                        except Exception as e:
                            print(f'[ERROR] Failed to retrieve homeowner info: {str(e)}')

                    # Update chat table with invoice_id in the invoices list
                    print('[DEBUG INFO] Updating chat table with invoice_id...')
                    try:
                        # First check if the chat exists
                        original_chat_for_update = table_chats.get_item(
                            Key={'chat_id': payload['chat_id']}
                        )

                        if 'Item' not in original_chat_for_update:
                            return {
                                'statusCode': 404,
                                'body': json.dumps({'error': 'Correspondent chat not found to be updated'})
                            }

                        # Create the invoice info to append to the list
                        invoice_info = {
                            'professional': payload['professional'],
                            'invoice_id': payload['invoice_id']
                        }

                        # Update the invoices list in table_chats
                        updated_chat = table_chats.update_item(
                            Key={'chat_id': payload['chat_id']},
                            UpdateExpression='SET #invoices = list_append(if_not_exists(#invoices, :empty_list), :invoice_info_list)',
                            ExpressionAttributeNames={'#invoices': 'invoices'},
                            ExpressionAttributeValues={
                                ':invoice_info_list': [invoice_info],
                                ':empty_list': []
                            },
                            ReturnValues='UPDATED_NEW'
                        )

                        return {
                            'statusCode': 201,
                            'body': json.dumps({
                                'message': 'Invoice created and chat updated successfully',
                                'homeowner_contact_info': homeowner_contact_info,
                                'deduct_credits': deduct_credits,
                                'pro_xano_user_type': pro_xano_user_type,
                                'pro_xano_acct_id': pro_xano_acct_id,
                                'invoice_pdf_file': pdf_file_name
                            }, default=decimal_default)
                        }

                    except Exception as e:
                        print(f'[ERROR] Failed to update chat: {str(e)}')
                        return {
                            'statusCode': 500,
                            'body': json.dumps({
                                'message': 'Invoice created but failed to update chat',
                                'error': str(e)
                            })
                        }

                except Exception as e:
                    print(f'[ERROR] Failed to create invoice: {str(e)}')
                    return {
                        'statusCode': 500,
                        'body': json.dumps({'error': str(e)})
                    }

    except Exception as e:
        print(f'[ERROR] Failed to verify professional: {str(e)}')
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def handle_get(event, payload):
    print('[DEBUG INFO] Handling GET request...')
    try:
        # Check if the request is for a specific invoice
        if 'invoice_id' in payload and 'chat_id' in payload:
            return read_item_by_invoice_id(payload)
        elif 'chat_id' in payload and 'invoice_id' not in payload:
            return read_items_by_chat_id(payload)
        else:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Missing required field: invoice_id or chat_id'})
            }
    except Exception as e:
        print(f'[ERROR] Failed to handle GET request: {str(e)}')
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def read_item_by_invoice_id(payload):
    print('[DEBUG INFO] Reading invoice by invoice_id...')
    try:
        invoice_id = payload['invoice_id']
        chat_id = payload['chat_id']
        
        response = table.get_item(
            Key={
                'invoice_id': invoice_id,
                'chat_id': chat_id
            }
        )
        
        if 'Item' in response:
            invoice = response['Item']

            if invoice.get('amount'):
                print(f"[DEBUG INFO] Quote original amount: {invoice['amount']}; data type: {type(invoice['amount'])}")
                invoice['amount'] = f"{invoice['amount'] / 100:,.2f}"
                print(f"[DEBUG INFO] Quote transformed amount: {invoice['amount']}; data type: {type(invoice['amount'])}")
            
            if invoice.get('invoice_line_items'):
                for item in invoice['invoice_line_items']:
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
                'body': json.dumps(invoice, default=decimal_default)
            }
        else:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Invoice not found'})
            }
    except Exception as e:
        print(f'[ERROR] Failed to read invoice: {str(e)}')
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def read_items_by_chat_id(payload):
    print('[DEBUG INFO] Reading invoices by chat_id...')
    try:
        chat_id = payload['chat_id']
        print(f'[DEBUG INFO] Chat ID: {chat_id}')

        existing_invoices = table.query(
            KeyConditionExpression=Key('chat_id').eq(chat_id)
        )
        
        print(f'[DEBUG INFO] Existing invoices: {existing_invoices}')
               
        if 'Items' in existing_invoices:
            invoices = existing_invoices['Items']
            for invoice in invoices:
                if invoice.get('amount'):
                    print(f"[DEBUG INFO] Invoice original amount: {invoice['amount']}; data type: {type(invoice['amount'])}")
                    invoice_subtotal = invoice['amount']
                    print(f"[DEBUG INFO] Invoice subtotal: {invoice_subtotal}; data type: {type(invoice_subtotal)}")
                    invoice['amount'] = f"{invoice['amount'] / 100:,.2f}"
                    print(f"[DEBUG INFO] Invoice transformed amount: {invoice['amount']}; data type: {type(invoice['amount'])}")

                tax_total = 0
                for tax in invoice.get("taxes", []):
                    tax_name = tax.get("tax_name", "")
                    print(f"[DEBUG INFO] Tax name: {tax_name}")
                    tax_rate = float(tax.get("tax_rate_decimal", 0))/100
                    print(f"[DEBUG INFO] Tax rate: {tax_rate}")
                    tax_amount = (invoice_subtotal * tax.get("tax_rate_decimal", 0))/100
                    print(f"[DEBUG INFO] Tax amount: {tax_amount}")
                    tax['tax_amount'] = f"{tax_amount / 100:,.2f}"
                    print(f"[DEBUG INFO] Tax: {tax}")
                    tax_total += tax_amount
                    print(f"[DEBUG INFO] Tax total: {tax_total}; data_type: {type(tax_total)}")
                             
                invoice['total_general'] = f"{(tax_total + invoice_subtotal)/ 100:,.2f}"

                if invoice.get('invoice_line_items'):
                    for item in invoice['invoice_line_items']:
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
                'body': json.dumps(invoices, default=decimal_default)
            }
        else:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'No invoices found for this chat'})
            }
    except Exception as e:
        print(f'[ERROR] Failed to read invoices by chat_id: {str(e)}')
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def update_item(payload):
    print('[DEBUG INFO] Updating invoice...')
    try:
        if 'invoice_id' not in payload:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Missing required field: invoice_id'})
            }
        
        invoice_id = payload['invoice_id']
        
        # Check if the invoice exists
        existing_invoice = table.get_item(
            Key={
                'invoice_id': invoice_id
            }
        )
        
        if 'Item' not in existing_invoice:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Invoice not found'})
            }
            
        # Build update expression
        update_expression = "SET "
        expression_attribute_values = {}
        expression_attribute_names = {}
        
        # Don't update the primary key (invoice_id)
        skip_fields = ['invoice_id']
        
        i = 0
        for key, value in payload.items():
            if key not in skip_fields:
                update_expression += f"#{i} = :{key}, "
                expression_attribute_names[f"#{i}"] = key
                expression_attribute_values[f":{key}"] = value
                i += 1
        
        # Remove trailing comma and space
        update_expression = update_expression[:-2]
        
        if i > 0:  # If there's something to update
            response = table.update_item(
                Key={
                    'invoice_id': invoice_id
                },
                UpdateExpression=update_expression,
                ExpressionAttributeNames=expression_attribute_names,
                ExpressionAttributeValues=expression_attribute_values,
                ReturnValues='ALL_NEW'
            )
            
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'Invoice updated successfully',
                    'updated_invoice': response.get('Attributes', {})
                }, default=decimal_default)
            }
        else:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'No fields to update'})
            }
            
    except Exception as e:
        print(f'[ERROR] Failed to update invoice: {str(e)}')
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def delete_item(payload):
    print('[DEBUG INFO] Deleting invoice...')
    try:
        if 'invoice_id' not in payload or 'chat_id' not in payload:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Missing required fields: invoice_id and chat_id'})
            }
        
        invoice_id = payload['invoice_id']
        chat_id = payload['chat_id']
        
        # Retrieve the invoice to get the pdf files names
        invoice_response = table.get_item(
            Key={
                'invoice_id': invoice_id,
                'chat_id': chat_id
            }
        )
        if 'Item' not in invoice_response:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Invoice not found'})
            }
        else:
            # Retrieve the pdf files names
            pdf_files = invoice_response['Item'].get('invoice_pdf_files', [])
            pdf_names = []
            
            # Add type checking to prevent string index errors
            if isinstance(pdf_files, list):
                for item in pdf_files:
                    if isinstance(item, dict):  # Ensure item is a dictionary
                        if item.get('en'):
                            pdf_names.append(item['en'])
                        if item.get('fr'):
                            pdf_names.append(item['fr'])
                        if item.get('es'):
                            pdf_names.append(item['es'])
                        if item.get('pt'):
                            pdf_names.append(item['pt'])

            # Delete the pdf files from Google Storage Bucket
            for pdf_file_name in pdf_names:
                print(f'[DEBUG INFO] Deleting PDF file: {pdf_file_name}')
                try:
                    pdf_file_path = BUCKET_NAME + '/' + BUCKET_FOLDER
                    bucket = storage_client.bucket(pdf_file_path)
                    blob = bucket.blob(pdf_file_name)
                    blob.delete()
                except Exception as e:
                    print(f'[ERROR] Failed to delete PDF file: {str(e)}')
                    return {
                        'statusCode': 500,
                        'body': json.dumps({'error': str(e)})
                    }

        # Delete the invoice from the main table
        table.delete_item(
            Key={
                'invoice_id': invoice_id,
                'chat_id': chat_id  # Include chat_id if it's part of the composite key
            }
        )
        
        # Now we should update the chat to remove this invoice from its list
        try:
            # Get the current chat to find the invoice's position in the list
            chat_response = table_chats.get_item(
                Key={
                    'chat_id': chat_id
                }
            )
            
            if 'Item' in chat_response and 'invoices' in chat_response['Item']:
                invoices = chat_response['Item']['invoices']
                
                # Ensure invoices is a list
                if not isinstance(invoices, list):
                    print(f'[WARNING] Expected invoices to be a list, got {type(invoices)}')
                    return {
                        'statusCode': 200,
                        'body': json.dumps({
                            'message': 'Invoice deleted successfully, but chat invoices structure is invalid'
                        })
                    }
                
                # Find the invoice and create a new list without it
                updated_invoices = []
                invoice_found = False
                
                for invoice in invoices:
                    if isinstance(invoice, dict) and invoice.get('invoice_id') != invoice_id:
                        updated_invoices.append(invoice)
                    elif isinstance(invoice, dict) and invoice.get('invoice_id') == invoice_id:
                        invoice_found = True
                
                if invoice_found:
                    # Update the entire invoices list
                    table_chats.update_item(
                        Key={
                            'chat_id': chat_id
                        },
                        UpdateExpression="SET invoices = :updated_invoices",
                        ExpressionAttributeValues={
                            ':updated_invoices': updated_invoices
                        }
                    )
                    
                    return {
                        'statusCode': 200,
                        'body': json.dumps({
                            'message': 'Invoice deleted and chat updated successfully'
                        })
                    }
                else:
                    print(f'[WARNING] Invoice {invoice_id} not found in chat {chat_id} invoices list')
            
            # If we get here, either the chat doesn't exist, doesn't have an invoices list,
            # or we couldn't find the invoice in the list - still return success for the deletion
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'Invoice deleted successfully, but could not update chat'
                })
            }
            
        except Exception as e:
            print(f'[ERROR] Failed to update chat after invoice deletion: {str(e)}')
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'Invoice deleted successfully, but failed to update chat',
                    'error': str(e)
                })
            }
            
    except Exception as e:
        print(f'[ERROR] Failed to delete invoice: {str(e)}')
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

def convert_floats_to_decimal(obj):
    if isinstance(obj, float):
        return Decimal(str(obj))
    elif isinstance(obj, dict):
        return {k: convert_floats_to_decimal(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_floats_to_decimal(item) for item in obj]
    return obj

# =================== Invoice PDF Generation Functions ======================

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

def transform_invoice_data(input_data):
    """Transform the input invoice data to the required format"""
    # Start with the basic structure
    transformed_data = {
        "invoice_number": input_data.get("customized_number", ""),
        "due_date": input_data.get("invoice_due_date", ""),
        "currency": input_data.get("currency", "USD"),
        "currency_symbol": "$",  # Default currency symbol
        "language": input_data.get("language", "en"),
        "location_of_service": input_data.get("service_address", ""),
        "invoice_id": input_data.get("invoice_id", "")
    }
    
    # Set appropriate currency symbol based on currency
    currency_map = {
        "USD": "$",
        "EUR": "€",
        "GBP": "£",
        "CAD": "C$"
    }
    transformed_data["currency_symbol"] = currency_map.get(transformed_data["currency"], "$")
    
    # Create temporary files for logos in /tmp directory (Lambda writable location)
    # Using tempfile.NamedTemporaryFile is good for unique names and handles creation
    temp_sender_logo = tempfile.NamedTemporaryFile(suffix='.jpg', delete=False, dir='/tmp')
    temp_hadronlink_logo = tempfile.NamedTemporaryFile(suffix='.jpg', delete=False, dir='/tmp')
    
    # Track the paths so the caller can clean them up later
    # This is critical for the `generate_invoice` to know what to clean.
    # We'll return these in the transformed_data.
    transformed_data["_temp_files_to_cleanup"] = []

    # Download and save the logo images from URLs
    sender_logo_url = input_data.get("sender_logo_url", "")
    hadronlink_logo_url = input_data.get("hadronlink_logo_url", "")
    
    # Initialize paths to None; they will be set if download is successful
    transformed_data["sender_logo_path"] = None
    transformed_data["hadronlink_logo_path"] = None

    try:
        if sender_logo_url:
            opener = urllib.request.build_opener()
            opener.addheaders = [('User-Agent', 'HadronLink Invoice Generator')]
            urllib.request.install_opener(opener)
            try:
                urllib.request.urlretrieve(sender_logo_url, temp_sender_logo.name)
                transformed_data["sender_logo_path"] = temp_sender_logo.name
                transformed_data["_temp_files_to_cleanup"].append(temp_sender_logo.name)
                temp_sender_logo.close() # Close the file handle after urlretrieve
            except urllib.error.URLError as url_err:
                print(f"[ERROR] Failed to download sender logo from {sender_logo_url}: {str(url_err)}")
            except Exception as e: # Catch any other exceptions during download/save
                print(f"[ERROR] Unexpected error with sender logo download {sender_logo_url}: {str(e)}")
        
        if hadronlink_logo_url:
            try:
                urllib.request.urlretrieve(hadronlink_logo_url, temp_hadronlink_logo.name)
                transformed_data["hadronlink_logo_path"] = temp_hadronlink_logo.name
                transformed_data["_temp_files_to_cleanup"].append(temp_hadronlink_logo.name)
                temp_hadronlink_logo.close() # Close the file handle after urlretrieve
            except urllib.error.URLError as url_err:
                print(f"[ERROR] Failed to download HadronLink logo from {hadronlink_logo_url}: {str(url_err)}")
            except Exception as e:
                print(f"[ERROR] Unexpected error with HadronLink logo download {hadronlink_logo_url}: {str(e)}")
    except Exception as e:
        print(f"[ERROR] General error during logo download process: {str(e)}")
    
    # Ensure temporary file handles are closed even if download failed for one
    try:
        temp_sender_logo.close()
    except Exception:
        pass
    try:
        temp_hadronlink_logo.close()
    except Exception:
        pass


    # Format the "to" section
    to_details = []
    if "customer_name" in input_data:
        to_details.append(input_data["customer_name"])
    if "service_address" in input_data:
        to_details.append(input_data["service_address"])
    if "customer_phone" in input_data:
        to_details.append(input_data["customer_phone"])
    
    transformed_data["to"] = {"details": to_details}
    
    # Format the "from" section
    from_details = []
    if "professional_name" in input_data:
        from_details.append(input_data["professional_name"])
    if "professional_phone" in input_data:
        from_details.append(input_data["professional_phone"])
    
    # Add business numbers
    for business_num in input_data.get("pro_business_numbers_to_display", []):
        display_name = business_num.get("business_number_display_name", "")
        display_number = business_num.get("business_number_display_number", "")
        if display_name and display_number:
            from_details.append(f"{display_name}: {display_number}")
    
    # Add insurance info
    for insurance_info in input_data.get("pro_insurance_info_to_display", []):
        company = insurance_info.get("insurance_company", "")
        policy = insurance_info.get("policy_number", "")
        valid_from = insurance_info.get("valid_from", "")
        valid_to = insurance_info.get("valid_to", "")
        if company and policy:
            from_details.append(f"Insurance: {company} Policy: {policy}")
            if valid_from and valid_to:
                from_details.append(f"Valid: {valid_from} - {valid_to}")

    transformed_data["from"] = {"details": from_details}
    
    # Transform line items
    items = []
    for item in input_data.get("invoice_line_items", []):
        # Get appropriate item description based on language
        lang = transformed_data["language"]
        # If language is empty or description in that language is empty, default to English
        if not lang or not item.get(f"item_description_{lang}", ""):
            lang = "en"
        
        description = item.get(f"item_description_{lang}", item.get("item_description_en", ""))
        
        # Convert cents to dollars
        rate = Decimal(str(item.get("individual_price", 0))) / Decimal('100')
        quantity = Decimal(str(item.get("item_quantity", 0)/100))
        amount = Decimal(str(item.get("sum", 0))) / Decimal('100')
        
        items.append({
            "description": description,
            "quantity": quantity,
            "rate": rate,
            "amount": amount
        })
    
    transformed_data["items"] = items
    
    # Transform taxes
    taxes = []
    for tax in input_data.get("taxes", []):
        taxes.append({
            "name": tax.get("tax_name", ""),
            "rate": tax.get("tax_rate_decimal", 0)
        })
    
    transformed_data["taxes"] = taxes
    
    # Get comments in the appropriate language
    comments = ""
    # Prioritize the requested language, then fall back to English
    requested_lang_comment = input_data.get(f"sender_comments_{transformed_data['language']}", "")
    if requested_lang_comment:
        comments = requested_lang_comment
    else:
        comments = input_data.get("sender_comments_en", "") # Fallback to English

    transformed_data["comments"] = comments
    
    return transformed_data

def generate_invoice(data, invoice_id, lang='en'):
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
    invoice_filename = f"/tmp/{invoice_id}_{lang}_{timestamp}.pdf"
    
    # Track temporary files for cleanup
    # Start with the PDF itself. We'll add downloaded images from 'data' later.
    temp_files_to_cleanup = [invoice_filename]

    currency = data.get("currency", "USD")
    currency_symbol = data.get("currency_symbol", "$")

    # Create document with 0.5 inch margins
    doc = SimpleDocTemplate(invoice_filename, pagesize=letter,
                            leftMargin=0.5 * inch, rightMargin=0.5 * inch,
                            topMargin=0.5 * inch, bottomMargin=0.5 * inch)

    # Get and extend styles
    styles = getSampleStyleSheet()

    # Add custom styles (your existing style definitions)
    styles.add(ParagraphStyle(name='InvoiceTitle',
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

    story = []
    top_line = HRFlowable(width="100%", thickness=2, color=purple,
                            spaceBefore=0, spaceAfter=0.1 * inch)
    story.append(top_line)
    story.append(Spacer(1, 0.1 * inch))

    # Get local paths from transformed_data
    sender_logo_path = data.get("sender_logo_path")
    hadronlink_logo_path = data.get("hadronlink_logo_path")

    # Add any downloaded temporary image files to the cleanup list
    temp_files_to_cleanup.extend(data.get("_temp_files_to_cleanup", []))

    # Invoice Header with purple bold title and sender logo in the same row
    # Use your CircularImage class with the downloaded path
    if sender_logo_path and os.path.exists(sender_logo_path):
        sender_logo = CircularImage(sender_logo_path, 0.8 * inch)
    else:
        # Fallback to placeholder if download failed or path is None
        drawing = Drawing(0.8 * inch, 0.8 * inch)
        circle = Circle(0.4 * inch, 0.4 * inch, 0.4 * inch,
                        fillColor=colors.transparent,
                        strokeColor=colors.transparent)
        drawing.add(circle)
        sender_logo = drawing

    due_date_text = f'<font name="Helvetica-Bold" color="{grey80.hexval()}">{PLACEHOLDERS["due_date"][lang]}</font><font name="Helvetica">{data["due_date"]}</font>'
    
    header_data = [
        [Paragraph(f"{PLACEHOLDERS['invoice_number'][lang]}{data['invoice_number']}", styles['InvoiceTitle']), "", "", sender_logo],
        [Paragraph(due_date_text, styles['Normal']), "", "", ""]
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

    # TO and FROM sections (your existing code, referencing transformed_data)
    to_data = data.get("to", {})
    from_data = data.get("from", {})

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

    # Location of service (your existing code, referencing transformed_data)
    location_data = [
        [Paragraph(PLACEHOLDERS['location_of_service'][lang], styles['SectionTitle'])],
        [Paragraph(data.get("location_of_service", ""), styles['Normal'])],
    ]
    location_table = Table(location_data)
    location_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
    ]))
    story.append(location_table)
    story.append(Spacer(1, 0.3 * inch))

    # Item Description Table with styled headers (your existing code, referencing transformed_data)
    item_data = [
        [Paragraph(PLACEHOLDERS['items_table_first_column'][lang], styles['SectionTitle']),
         Paragraph(PLACEHOLDERS['items_table_second_column'][lang], styles['SectionTitleRight']),
         Paragraph(PLACEHOLDERS['items_table_third_column'][lang], styles['SectionTitleRight']),
         Paragraph(PLACEHOLDERS['items_table_fourth_column'][lang], styles['SectionTitleRight'])],
    ]

    for item in data.get("items", []): 
        item_data.append([
            item.get("description", ""),
            f"{float(item.get('quantity', 0)):.2f}",
            f"{float(item.get('rate', 0)):.2f}",
            f"{float(item.get('amount', 0)):.2f}"
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

    # Calculate subtotal (your existing code, referencing transformed_data)
    subtotal = sum(item.get("amount", Decimal('0')) for item in data.get("items", []))
    
    summary_data = [
        [Paragraph(PLACEHOLDERS['subtotal'][lang], styles['SectionTitle']), "", "", f"{currency_symbol} {subtotal:,.2f}"],
    ]
    
    tax_total = 0
    for tax in data.get("taxes", []): # Use the 'taxes' key from transformed data
        tax_name = tax.get("name", "")
        tax_rate = float(tax.get("rate", 0))/100
        tax_amount = (subtotal * Decimal(str(tax_rate))).quantize(Decimal('.01'), rounding=ROUND_HALF_UP)
        tax_total += tax_amount
        tax_label = f"{tax_name} {tax_rate*100:.1f}%" # Display percentage from decimal rate
        summary_data.append([Paragraph(tax_label, styles['SectionTitle']), "", "", f"{currency_symbol} {tax_amount:,.2f}"])
    
    grand_total = subtotal + tax_total
    summary_data.append([
        Paragraph(PLACEHOLDERS['grandtotal'][lang], styles['GrandTotalStyle']), 
        "", 
        "", 
        Paragraph(f"{currency_symbol} {grand_total:,.2f}", styles['GrandTotalAmountStyle'])
    ])

    summary_table = Table(summary_data, colWidths=[doc.width*0.55, doc.width*0.15, doc.width*0.15, doc.width*0.15])
    summary_table.setStyle(TableStyle([
        ('ALIGN', (2, 0), (3, -1), 'RIGHT'),
    ]))

    story.append(summary_table)
    story.append(Spacer(1, 0.3 * inch))
    
    # Add comments if present (your existing code, referencing transformed_data)
    if "comments" in data and data["comments"]:
        story.append(Spacer(1, 0.2*inch))
        comments_style = ParagraphStyle(
            'Comments',
            parent=styles['Normal'],
            textColor=grey80,
        )
        comments = Paragraph(data["comments"], comments_style)
        story.append(comments)
        
    story.append(Spacer(1, 0.5 * inch))

    # --- FooterCanvas remains largely the same, but now uses passed local_hadronlink_logo_path ---
    class FooterCanvas:
        def __init__(self, doc_ref, local_hadronlink_logo_path_ref):
            self.doc = doc_ref
            self.width = letter[0]
            self.height = letter[1]
            # These frame coords are typically defined once and apply to the whole page.
            # Using them here as properties that match doc margins.
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

    # Pass the local_hadronlink_logo_path to the FooterCanvas constructor
    # The frames themselves don't need the path, but the onPage callback does.
    top_frame = Frame(doc.leftMargin, doc.topMargin, doc.width, doc.height, id='top_frame')
    bottom_frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, 1 * inch, id='bottom_frame')


    # Create a PageTemplate with both frames and the footer canvas
    page_template = PageTemplate(
        id='invoice_template',
        frames=[top_frame, bottom_frame],
        onPage=FooterCanvas(doc, hadronlink_logo_path) # Pass the path here
    )

    doc.addPageTemplates([page_template])

    # Build the document, the story will automatically flow into the defined frames
    # This is the try-except block that replaces the original doc.build(story)
    try:
        doc.build(story)
        print(f"[DEBUG] Successfully built PDF at: {invoice_filename}")
        return invoice_filename, temp_files_to_cleanup
    except Exception as e:
        print(f"[ERROR] Failed to build PDF document for invoice {invoice_id} ({lang}): {str(e)}")
        # Clean up any partially created PDF if build fails
        if os.path.exists(invoice_filename):
            os.remove(invoice_filename)
        # We need to clean up downloaded images specifically if an error occurs here.
        # The calling function should be responsible for cleaning up 'temp_files_to_cleanup'
        # based on the returned list. So, return the list here for proper cleanup.
        return None, temp_files_to_cleanup # Return None for filename on failure

def generate_multilingual_invoices(json_file):  # Function to generate invoices in multiple languages if needed in the future
    try:
        # Load the JSON data
        with open(json_file, 'r', encoding='utf-8') as f:
            input_data = json.load(f)
        
        # Transform the input data
        data = transform_invoice_data(input_data)
        
        # Generate invoices for each language
        languages = ['en', 'fr', 'es', 'pt']
        generated_files = []
        
        for lang in languages:
            invoice_file = generate_invoice(data, lang)
            generated_files.append(invoice_file)
            
        print(f"All invoices generated successfully: {', '.join(generated_files)}")
        
    except Exception as e:
        print(f"Error generating invoices: {str(e)}")

# At the end of your processes, clean up temp files
def cleanup_temp_files(file_list):
    for file_path in file_list:
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                print(f"[DEBUG INFO] Removed temporary file: {file_path}")
        except Exception as e:
            print(f"[ERROR] Failed to remove temporary file {file_path}: {str(e)}")

def upload_pdf_to_google_storage(local_file_path, invoice_id, language):
    """
    Uploads a PDF file to Google Cloud Storage
    
    Args:
        local_file_path (str): Path to the local PDF file
        invoice_id (str): ID of the invoice
        language (str): Language code of the invoice (en, fr, es, pt)
        
    Returns:
        str: Public URL of the uploaded file
    """
    try:
        # Get the bucket
        bucket = client.bucket(BUCKET_NAME)
        
        # Define the destination path in the bucket
        destination_blob_name = f"{BUCKET_FOLDER}/{invoice_id}_{language}.pdf"
        
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

def generate_single_language_invoice(payload):
    try:
        # Transform the input data to the required format
        invoice_data = transform_invoice_data(payload)

        # Get the desired language from the invoice data
        language = invoice_data.get("language", "en")  # Default to 'en' if not specified
        invoice_id = invoice_data.get("invoice_id")
        
        # If language is empty, default to 'en'
        if not language:
            language = "en"

        # Generate the invoice for the specified language
        invoice_file, temp_files = generate_invoice(invoice_data, invoice_id, language)
        print(f"[DEBUG INFO] Invoice '{invoice_file}' generated successfully in {language.upper()}.")
        
        # Upload the generated PDF to Google Cloud Storage
        pdf_url = upload_pdf_to_google_storage(invoice_file, invoice_id, language)
        
        # Initialize invoice_pdf_files list if it doesn't exist
        if 'invoice_pdf_files' not in payload:
            payload['invoice_pdf_files'] = []
        
        # Add this PDF file to the invoice_pdf_files list
        pdf_info = {language: pdf_url}
        payload['invoice_pdf_files'].append(pdf_info)
        
        # Clean up temporary files
        cleanup_temp_files(temp_files)
        
        print(f"[DEBUG INFO] PDF uploaded successfully, URL added to payload")
        
        # Return the invoice PDF filename for the response
        return pdf_url

    except FileNotFoundError:
        print(f"[ERROR] JSON file not found. Please create a JSON file with invoice data.")
        return None
    except json.JSONDecodeError:
        print(f"[ERROR] Could not decode JSON. Please ensure the file is valid JSON.")
        return None
    except Exception as e:
        print(f"[ERROR] Error generating invoice: {str(e)}")
        return None
                    