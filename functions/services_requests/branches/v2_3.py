import json
import boto3
import datetime
import json
import math
import sys
import os
import re
import base64
import geohash2
import decimal
from decimal import Decimal
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key, Attr, And, Not, Contains
from opensearchpy import OpenSearch, RequestsHttpConnection
from aws_requests_auth.aws_auth import AWSRequestsAuth
import requests
from requests.auth import HTTPBasicAuth

# Add the 'package' directory to the Python path
sys.path.insert(0, os.path.join(os.getcwd(), 'package'))

import geohash2  # Importing again after adding to path

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

# DynamoDB setup
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('services_requests')
table_chats = dynamodb.Table('chats')
table_roles = dynamodb.Table('roles')
table_quotes = dynamodb.Table('quotes')

# Constants for geohash precision
GEOHASH_PRECISION = 5
# Approximate distance in meters for different geohash precision levels (for reference)
# precision 1 ~= 5,000km
# precision 2 ~= 1,250km
# precision 3 ~= 156km
# precision 4 ~= 39km
# precision 5 ~= 4.9km
# precision 6 ~= 1.2km
# precision 7 ~= 153m
# precision 8 ~= 38m


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

def create_item(payload):
    print('[DEBUG INFO] Creating a new item...')
    print('[DEBUG INFO] Payload:', payload)
    try:
        # Generate geohash if coordinates are provided
        if payload.get('latitude') and payload.get('longitude'):
            geohash = geohash2.encode(
                float(payload['latitude']),
                float(payload['longitude']),
                precision=GEOHASH_PRECISION
            )
        else:
            geohash = None

        item = {
            'service_request_id': payload['service_request_id'],
            'homeowner': payload['homeowner'],
            'created_at_timestamp': payload['created_at'],
            'created_at': format_timestamp(payload['created_at']),
            'updated_at': format_timestamp(payload['created_at']),
            'title': payload['title'],
            'description': payload['description'],
            'public_address': payload.get('public_address', ''),
            'complete_address': payload.get('complete_address', ''),
            'city': payload.get('city', ''),
            'latitude': payload.get('latitude', None),
            'longitude': payload.get('longitude', None),
            'geohash': geohash,
            'desired_start_date': payload.get('desired_start_date', '1900-01-01'),
            'desired_deadline': payload.get('desired_deadline', '1900-01-01'),
            'status': payload.get('status', 'Open'),
            'chats': payload.get('chats', []),
            'files': payload.get('files', []),
            'lead_for_professionals': payload.get('lead_for_professionals', []),
            'priority': payload.get('priority', 'medium'),
            'credits_required': payload.get('credits_required', 0),
            'views_count': 0,
            'SR_projects_themes': payload.get('SR_projects_themes', {}),
            'SR_projects_themes_ids': payload.get('SR_projects_themes_ids', {}),
            'SR_trades': payload.get('SR_trades', {}),
            'SR_trades_ids': payload.get('SR_trades_ids', {}),
            'max_distance_in_meters': payload.get('max_distance_in_meters', '1000000'),
            'selected_professional': payload.get('selected_professional', ''),
            'pro_already_reviewed': 'False',
            'homeowner_asked_to_review_pro_date': ''
        }
        max_distance_in_meters = payload.get('max_distance_in_meters')

        table.put_item(Item=item)

        return {
            'statusCode': 201,
            'body': json.dumps({'message': 'Item created successfully', 'service_request': payload['service_request_id']})
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def handle_request(event, payload):
    operation = event['httpMethod']
    print(f'[DEBUG INFO] Operation: {operation}')
    print(f'[DEBUG INFO] Payload: {payload}')

    try:
        if operation == 'PUT':
            return update_item(payload)
        elif operation == 'POST':
            if payload and payload.get('service_request_id') and \
            payload.get('max_recommended_professionals') is not None and \
            payload.get('max_distance_in_meters') is not None:
                service_request_id = payload.get('service_request_id')
                max_recommended_professionals = payload.get('max_recommended_professionals')
                max_distance_in_meters = payload.get('max_distance_in_meters')
                include_pro = None
                if payload.get('include_pro'):
                    include_pro = payload.get('include_pro')
                return find_matching_professionals(service_request_id, max_recommended_professionals, max_distance_in_meters, include_pro)
            elif payload and payload.get('service_request_id') and not\
               payload.get('min_match_percentage') and not \
               payload.get('max_distance_in_meters'):
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

def handle_get(event, payload):
    print('[DEBUG INFO] Calling handle_get function to decide which get to execute')
    try:
        if 'service_request_id' in payload:
            print("handle_get: calling get_one")
            return get_one(payload['service_request_id'], event)
        elif 'homeowner' in payload:
            print("handle_get: calling get_by_homeowner")
            search_query = payload.get('search_query', '')
            start_date_filter = payload.get('start_date_filter')
            end_date_filter = payload.get('end_date_filter')
            status_filter = payload.get('status')
            return get_by_homeowner(payload['homeowner'], event, search_query, start_date_filter, end_date_filter, status_filter)
        elif 'professional' in payload:
            print("handle_get: calling get_by_pro")
            pro = payload['professional']
            search_query = payload.get('search_query', '')
            start_date_filter = payload.get('start_date_filter')
            end_date_filter = payload.get('end_date_filter')
            status_filter = payload.get('status')
            return get_by_pro(pro, search_query, start_date_filter, end_date_filter, status_filter)
        elif 'concluded_not_reviewed' in payload:
            print("handle_get: calling get_concluded_not_reviewed")
            return get_concluded_not_reviewed(payload['when_ask_again_list'])
        elif 'in_progress_with_expired_deadline' in payload:
            print("handle_get: calling get_in_progress_with_expired_deadline")
            return get_in_progress_with_expired_deadline()
        elif 'emails_to_eliminate' in payload:
            print("handle_get: calling get_sr_by_pros_closed_to_work")
            emails_to_eliminate = payload.get('emails_to_eliminate', [])
            # Handle if it comes as a comma-separated string
            if isinstance(emails_to_eliminate, str):
                emails_to_eliminate = [email.strip() for email in emails_to_eliminate.split(',') if email.strip()]
            return get_sr_by_pros_closed_to_work(emails_to_eliminate)
        else:
            print("handle_get: calling get_all")
            search_query = payload.get('search_query', '')
            start_date_filter = payload.get('start_date_filter')
            end_date_filter = payload.get('end_date_filter')
            status_filter = payload.get('status')
            return get_all(event, search_query, start_date_filter, end_date_filter, status_filter)
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def get_one(service_request_id, event):
    print('[DEBUG INFO] Initializing get_one function...')
    try:
        response = table.get_item(Key={'service_request_id': service_request_id})

        if 'Item' in response:
            item = response['Item']

            if item.get('chats') and len(item['chats']) > 0:
                for chat in item['chats']:
                    # Get professional info from OpenSearch
                    professional_data = get_professional_by_role_id(chat['professional'])
                    if professional_data:
                        chat['professional_name'] = professional_data.get('name', '')
                        chat['professional_profile_image_complete_path'] = professional_data.get('profile_image_complete_path', '')

            homeowner_role_id = item['homeowner']

            # Query for homeowner profile
            homeowner_role_response = table_roles.query(
                IndexName='role_id-index',
                KeyConditionExpression=Key('role_id').eq(homeowner_role_id),
                Limit=1
            )
            homeowner_items = homeowner_role_response.get('Items', [])

            if homeowner_items:
                homeowner_item = homeowner_items[0]
                item['homeowner_name'] = homeowner_item.get('name')
            else:
                print(f"Warning: No homeowner profile found for role_id: {homeowner_role_id}")
                item['homeowner_name'] = None

            return {
                'statusCode': 200,
                'body': json.dumps(item, default=dynamo_json_serializer)
            }
        else:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Item not found'})
            }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def get_all(event, search_query=None, start_date_filter=None, end_date_filter=None, status_filter=None):
    print('[DEBUG INFO] Initializing get_all function...')
    try:
        # Initial scan to get all items
        response = table.scan()
        items = response.get('Items', [])

        # Filter by date range if provided
        if start_date_filter or end_date_filter:
            filtered_items = []
            for item in items:
                created_at = item.get('created_at', '')

                if start_date_filter and end_date_filter:
                    if start_date_filter <= created_at <= end_date_filter:
                        filtered_items.append(item)
                elif start_date_filter:
                    if start_date_filter <= created_at:
                        filtered_items.append(item)
                elif end_date_filter:
                    if created_at <= end_date_filter:
                        filtered_items.append(item)

            items = filtered_items

        # Filter by status if provided, unless the filter is 'All'
        if status_filter:
            if isinstance(status_filter, str) and status_filter.lower() == 'all':
                print('[DEBUG INFO] Status filter is "All", no status filtering applied.')
            else:
                if not isinstance(status_filter, list):
                    status_filter = [status_filter]

                status_filter_lower = [s.lower() for s in status_filter]

                filtered_items_by_status = []
                for item in items:
                    item_status = item.get('status', '').lower()
                    if item_status in status_filter_lower:
                        filtered_items_by_status.append(item)
                items = filtered_items_by_status
                print(f'[DEBUG INFO] Filtered by status: {status_filter}')

        # Filter and sort by search query if provided
        if search_query:
            search_results = []

            for item in items:
                # Collect themes from all languages
                themes = item.get('SR_projects_themes', {})
                all_themes = []
                for lang_key in ['themes_en', 'themes_es', 'themes_fr', 'themes_pt']:
                    all_themes.extend(themes.get(lang_key, []))

                # Collect trades from all languages
                trades = item.get('SR_trades', {})
                all_trades = []
                for lang_key in ['trades_en', 'trades_es', 'trades_fr', 'trades_pt']:
                    all_trades.extend(trades.get(lang_key, []))

                # Combine everything into searchable text
                themes_text = ' '.join(all_themes)
                trades_text = ' '.join(all_trades)

                searchable_text = f"{item.get('title', '')} {item.get('description', '')} {item.get('city', '')} {themes_text} {trades_text}".lower()

                print(f'[DEBUG INFO] Searchable text: {searchable_text}')


                if search_query.lower() in searchable_text:
                    search_results.append(item)

            items = search_results

        if items:
            for item in items:
                if item.get('chats') and len(item['chats']) > 0:
                    for chat in item['chats']:
                        professional_data = get_professional_by_role_id(chat['professional'])
                        if professional_data:
                            chat['professional_name'] = professional_data.get('name', '')
                            chat['professional_profile_image_complete_path'] = professional_data.get('profile_image_complete_path', '')

        return {
            'statusCode': 200,
            'body': json.dumps(items, default=dynamo_json_serializer)
        }
    except Exception as e:
        print(f'[ERROR] Exception in get_all: {str(e)}')
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def get_by_homeowner(homeowner, event, search_query=None, start_date_filter=None, end_date_filter=None, status_filter=None):
    print('[DEBUG INFO] Initializing get_by_homeowner function...')
    try:
        # Initial query to get all items for the homeowner
        response = table.query(
            IndexName='homeowner-index',
            KeyConditionExpression=boto3.dynamodb.conditions.Key('homeowner').eq(homeowner)
        )
        items = response.get('Items', [])

        # Filter by date range if provided
        if start_date_filter or end_date_filter:
            filtered_items = []
            for item in items:
                created_at = item.get('created_at', '')

                if start_date_filter and end_date_filter:
                    if start_date_filter <= created_at <= end_date_filter:
                        filtered_items.append(item)
                elif start_date_filter:
                    if start_date_filter <= created_at:
                        filtered_items.append(item)
                elif end_date_filter:
                    if created_at <= end_date_filter:
                        filtered_items.append(item)

            items = filtered_items

        # Filter by status if provided, unless the filter is 'All'
        if status_filter:
            if isinstance(status_filter, str) and status_filter.lower() == 'all':
                print('[DEBUG INFO] Status filter is "All", no status filtering applied.')
            else:
                if not isinstance(status_filter, list):
                    status_filter = [status_filter]

                status_filter_lower = [s.lower() for s in status_filter]

                filtered_items_by_status = []
                for item in items:
                    item_status = item.get('status', '').lower()
                    if item_status in status_filter_lower:
                        filtered_items_by_status.append(item)
                items = filtered_items_by_status
                print(f'[DEBUG INFO] Filtered by status: {status_filter}')

        # Filter and sort by search query if provided
        if search_query:
            search_results = []

            for item in items:
                searchable_text = f"{item.get('title', '')} {item.get('description', '')} {item.get('city', '')}".lower()

                if search_query.lower() in searchable_text:
                    search_results.append(item)

            items = search_results

        if items:
            for item in items:
                if item.get('chats') and len(item['chats']) > 0:
                    for chat in item['chats']:
                        professional_data = get_professional_by_role_id(chat['professional'])
                        if professional_data:
                            chat['professional_name'] = professional_data.get('name', '')
                            chat['professional_profile_image_complete_path'] = professional_data.get('profile_image_complete_path', '')
                        chat_data = table_chats.get_item(Key={'chat_id': chat['chat_id']}).get('Item', {})
                        if chat_data:
                            chat['new_messages_to_homeowner'] = chat_data.get('new_messages_to_homeowner', False)
                            chat['new_messages_to_pro'] = chat_data.get('new_messages_to_pro', False)
        return {
            'statusCode': 200,
            'body': json.dumps(items, default=dynamo_json_serializer)
        }
    except Exception as e:
        print(f'[ERROR] Exception in get_by_homeowner: {str(e)}')
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def get_concluded_not_reviewed(when_ask_again_list=None):
    print('[DEBUG INFO] Getting concluded service requests not yet reviewed by homeowner...')
    try:

        # Default to empty list if not provided
        if when_ask_again_list is None:
            when_ask_again_list = []

        # Get current date for calculating days difference
        today = datetime.datetime.now().date()
        today_str = today.strftime('%Y-%m-%d')

        # Query the GSI for concluded but not reviewed items
        response = table.query(
            IndexName='concluded_not_reviewed-index',
            KeyConditionExpression=Key('status').eq('Completed') & Key('pro_already_reviewed').eq('False'),
            FilterExpression=Attr('selected_professional').ne('') # a professional is assigned
        )

        result_items = []
        items = response['Items']

        # Handle pagination if there are more items
        while 'LastEvaluatedKey' in response:
            response = table.query(
                IndexName='ConcludedNotReviewed-index',
                KeyConditionExpression=Key('status').eq('Completed') & Key('pro_already_reviewed').eq('False'),
                ExclusiveStartKey=response['LastEvaluatedKey']
            )
            items.extend(response['Items'])

        # For each service request, get the homeowner details from roles table
        for item in items:
            service_data = {
                'service_request_id': item.get('service_request_id'),
                'homeowner': item.get('homeowner'),
                'professional_name': item.get('professional_name'),
                'homeowner_asked_to_review_date': item.get('homeowner_asked_to_review_date', '')
            }

            # Check if homeowner_asked_to_review_date is empty
            if not service_data['homeowner_asked_to_review_date']:
                days_since_asked = 0
                should_include = True
            else:
                try:
                    review_date = datetime.datetime.strptime(service_data['homeowner_asked_to_review_date'], '%Y-%m-%d').date()
                    if review_date == today:
                        should_include = False
                        days_since_asked = 0
                    else:
                        days_since_asked = (today - review_date).days
                        should_include = not when_ask_again_list or days_since_asked in when_ask_again_list
                except ValueError:
                    days_since_asked = 0
                    should_include = True

            service_data['days_since_asked_to_review'] = days_since_asked

            # Only proceed if we should include this service
            if should_include:
                # Get homeowner data from roles table
                if item.get('homeowner'):
                    try:
                        homeowner = item.get('homeowner')
                        print(f'[DEBUG] Querying for homeowner ID: {homeowner}')

                        # Query the roles table to get homeowner details
                        homeowner_response = table_roles.query(
                            IndexName='role_id-index',
                            KeyConditionExpression=Key('role_id').eq(homeowner),
                            Limit=1
                        )

                        homeowner_items = homeowner_response.get('Items', [])
                        print(f'[DEBUG] Homeowner items found: {len(homeowner_items)}')

                        if homeowner_items:
                            homeowner_data = homeowner_items[0]

                            # Add homeowner details to service_data
                            service_data.update({
                                'homeowner_name': homeowner_data.get('name', ''),
                                'homeowner_phone': homeowner_data.get('phone', ''),
                                'homeowner_email': homeowner_data.get('email', ''),
                                'homeowner_language': homeowner_data.get('language', '')
                            })
                        else:
                            print(f'[WARNING] No homeowner data found for ID: {homeowner}')
                    except Exception as e:
                        print(f'[ERROR] Failed to get homeowner data: {str(e)}')

                # Update the service request with today's date as homeowner_asked_to_review_date
                try:
                    service_request_id = item.get('service_request_id')
                    if service_request_id:
                        table.update_item(
                            Key={'service_request_id': service_request_id},
                            UpdateExpression='SET homeowner_asked_to_review_date = :date',
                            ExpressionAttributeValues={':date': today_str}
                        )
                        print(f'[DEBUG] Updated homeowner_asked_to_review_date for service_request_id: {service_request_id}')
                except Exception as e:
                    print(f'[ERROR] Failed to update homeowner_asked_to_review_date: {str(e)}')

                result_items.append(service_data)

        return {
            'statusCode': 200,
            'body': json.dumps({'data': result_items})
        }
    except Exception as e:
        print(f'[ERROR] Failed to get concluded not reviewed items: {str(e)}')
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def get_in_progress_with_expired_deadline():
    print('[DEBUG INFO] Getting services requests with status InProgress with expired desired deadline...')
    try:
        # Get current date for comparison
        today = datetime.datetime.now().date()
        today_str = today.strftime('%Y-%m-%d')

        # We need to scan the table since we can't query directly for "less than" conditions on GSI
        response = table.scan(
            FilterExpression=Attr('status').eq('InProgress') & Attr('desired_deadline').lt(today_str)
        )

        result_items = []
        items = response['Items']

        # Handle pagination if there are more items
        while 'LastEvaluatedKey' in response:
            response = table.scan(
                FilterExpression=Attr('status').eq('InProgress') & Attr('desired_deadline').lt(today_str),
                ExclusiveStartKey=response['LastEvaluatedKey']
            )
            items.extend(response['Items'])

        # For each service request, get the homeowner details from roles table
        for item in items:
            service_data = {
                'service_request_id': item.get('service_request_id'),
                'homeowner': item.get('homeowner'),
                'professional_name': item.get('professional_name'),
                'desired_deadline': item.get('desired_deadline', '')
            }

            # Get homeowner data from roles table
            if item.get('homeowner'):
                try:
                    homeowner = item.get('homeowner')
                    print(f'[DEBUG] Querying for homeowner ID: {homeowner}')

                    # Query the roles table to get homeowner details
                    homeowner_response = table_roles.query(
                        IndexName='role_id-index',
                        KeyConditionExpression=Key('role_id').eq(homeowner),
                        Limit=1
                    )

                    homeowner_items = homeowner_response.get('Items', [])
                    print(f'[DEBUG] Homeowner items found: {len(homeowner_items)}')

                    if homeowner_items:
                        homeowner_data = homeowner_items[0]

                        # Add homeowner details to service_data as required
                        service_data.update({
                            'homeowner_name': homeowner_data.get('name', ''),
                            'homeowner_phone': homeowner_data.get('phone', ''),
                            'homeowner_email': homeowner_data.get('email', ''),
                            'homeowner_language': homeowner_data.get('language', '')
                        })
                    else:
                        print(f'[WARNING] No homeowner data found for ID: {homeowner}')
                except Exception as e:
                    print(f'[ERROR] Failed to get homeowner data: {str(e)}')

            result_items.append(service_data)

        return {
            'statusCode': 200,
            'body': json.dumps({'data': result_items})
        }
    except Exception as e:
        print(f'[ERROR] Failed to get ongoing with expired deadline items: {str(e)}')
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def update_views_count(service_request_id, event=None):
    print(f'Updating the number of views for service request {service_request_id}')
    try:
        table.update_item(
            Key={'service_request_id': service_request_id},
            UpdateExpression="SET views_count = views_count + :val",
            ExpressionAttributeValues={':val': 1}
        )
    except Exception as e:
        print(f"Error updating views_count: {e}")

def update_item(payload):
    """
    Updates an item in the services_requests table and cascades changes
    to related chats and quotes based on the new status.
    """
    print('[DEBUG INFO] Initializing update_item function...')
    try:
        service_request_id = payload['service_request_id']

        # Fetch the existing item from services_requests
        print('[DEBUG INFO] Fetching the existing service request')
        current_response = table.get_item(Key={'service_request_id': service_request_id})
        if 'Item' not in current_response:
            return {
                'statusCode': 404,
                'body': json.dumps({'message': 'Item not found'})
            }
        existing_item = current_response['Item']
        print(f'[DEBUG INFO] Existing service request: {existing_item}')

        # Determine the new status from the payload
        new_status = payload.get('status')

        # Initialize a list to store cancelled appointment IDs
        cancelled_appointment_info = []

        # ---------------------------------------------------------------------
        # --- Conditional updates based on the SR status change ---
        # ---------------------------------------------------------------------

        # Case 1: Status change to 'InProgress', 'Reviewed', or 'Completed'
        if new_status in ['InProgress', 'Reviewed', 'Completed']:
            selected_professional_id = payload.get('selected_professional')

            # Check if a selected professional is provided, otherwise use the existing one.
            if not selected_professional_id:
                existing_professional = existing_item.get('selected_professional')
                if existing_professional:
                    print(f"Using existing selected_professional: {existing_professional}")
                    selected_professional_id = existing_professional
                else:
                    return {
                        'statusCode': 400,
                        'body': json.dumps({'message': 'A selected_professional must be provided or already exist for this status.'})
                    }

            print(f'Updating SR to {new_status} and processing related chats/quotes...')

            # Update the services_requests table
            table.update_item(
                Key={'service_request_id': service_request_id},
                UpdateExpression='SET #s = :s, selected_professional = :sp',
                ExpressionAttributeNames={'#s': 'status'},
                ExpressionAttributeValues={':s': new_status, ':sp': selected_professional_id}
            )

            # Process all related chats
            chats = existing_item.get('chats', [])
            for chat in chats:
                chat_id = chat['chat_id']
                professional_in_chat = chat['professional']

                if professional_in_chat == selected_professional_id:
                    # Update the winning chat (chat_status = 'Open')
                    print(f'Processing winning chat: {chat_id}')
                    table_chats.update_item(
                        Key={'chat_id': chat_id},
                        UpdateExpression='SET #cs = :cs',
                        ExpressionAttributeNames={'#cs': 'chat_status'},
                        ExpressionAttributeValues={':cs': 'Open'}
                    )

                    # If only one quote exists in the winning chat, approve it
                    quotes_in_chat = chat.get('quotes', [])
                    if len(quotes_in_chat) == 1:
                        print(f'Approving single quote in chat {chat_id}')
                        quote_id = quotes_in_chat[0]['quote_id']
                        table_quotes.update_item(
                            Key={'chat_id': chat_id, 'quote_id': quote_id},
                            UpdateExpression='SET #qs = :qs',
                            ExpressionAttributeNames={'#qs': 'status'},
                            ExpressionAttributeValues={':qs': 'Approved'}
                        )
                else:
                    # Update all other chats (chat_status = 'Closed')
                    print(f'Processing other chat: {chat_id}')
                    table_chats.update_item(
                        Key={'chat_id': chat_id},
                        UpdateExpression='SET #cs = :cs, status_detail = :sd',
                        ExpressionAttributeNames={'#cs': 'chat_status'},
                        ExpressionAttributeValues={':cs': 'Closed', ':sd': 'related quotes not selected'}
                    )

                    # Update all quotes in the other chats (status = 'Closed')
                    quotes_in_chat = chat.get('quotes', [])
                    for quote in quotes_in_chat:
                        print(f'Closing quote {quote["quote_id"]} in chat {chat_id}')
                        quote_id = quote['quote_id']
                        table_quotes.update_item(
                            Key={'chat_id': chat_id, 'quote_id': quote_id},
                            UpdateExpression='SET #qs = :qs, #qsd = :qsd',
                            ExpressionAttributeNames={'#qs': 'status', '#qsd': 'status_detail'},
                            ExpressionAttributeValues={':qs': 'Closed', ':qsd': 'not selected'}
                        )

        # Case 2: Status change to 'Cancelled'
        elif new_status == 'Cancelled':
            # Update the services_requests table
            print('Updating the service request status to Cancelled...')
            table.update_item(
                Key={'service_request_id': service_request_id},
                UpdateExpression='SET #s = :s',
                ExpressionAttributeNames={'#s': 'status'},
                ExpressionAttributeValues={':s': 'Cancelled'}
            )

            # Update all related chats AND quotes AND future appointments
            print('Updating all related chats, quotes, and appointments...')
            chats = existing_item.get('chats')
            print(f'Chats: {chats}')
            for chat in chats:
                chat_id = chat['chat_id']

                # Update chat status
                table_chats.update_item(
                    Key={'chat_id': chat_id},
                    UpdateExpression='SET #cs = :cs, status_detail = :sd',
                    ExpressionAttributeNames={'#cs': 'chat_status'},
                    ExpressionAttributeValues={':cs': 'Closed', ':sd': 'service request was cancelled'}
                )

                # Fetch chat
                print('[DEBUG INFO] Fetching the existing chat')
                chats_response = table_chats.get_item(Key={'chat_id': chat_id})
                print(f'[DEBUG INFO] Chat response: {chats_response}')
                if 'Item' in chats_response:
                    existing_chat = chats_response['Item']
                    print(f'[DEBUG INFO] Processing chat: {existing_chat}')

                    # Update all quotes in this chat
                    quotes_in_chat = existing_chat.get('quotes', [])
                    print(f'[DEBUG INFO] Quotes in chat: {quotes_in_chat}')
                    for quote in quotes_in_chat:
                        quote_id = quote['quote_id']
                        table_quotes.update_item(
                            Key={'chat_id': chat_id, 'quote_id': quote_id},
                            UpdateExpression='SET #qs = :qs, #qsd = :qsd',
                            ExpressionAttributeNames={'#qs': 'status', '#qsd': 'status_detail'},
                            ExpressionAttributeValues={':qs': 'Closed', ':qsd': 'service request was cancelled'}
                        )

                    # --- Cancel future appointments ---
                    appointments_in_chat = existing_chat.get('appointments', [])
                    print(f'[DEBUG INFO] Appointments in chat: {appointments_in_chat}')

                    for appointment in appointments_in_chat:
                        appointment_date_str = appointment.get('appointment_date')
                        appointment_time_str = appointment.get('appointment_time')

                        print(f'[DEBUG INFO] Appointment date: {appointment_date_str}')
                        print(f'[DEBUG INFO] Appointment time: {appointment_time_str}')

                        if appointment_date_str and appointment_time_str:
                            # Combine date and time strings
                            appointment_datetime_str = f"{appointment_date_str} {appointment_time_str}"
                            print(f'[DEBUG INFO] Combined datetime string: {appointment_datetime_str}')

                            # Parse the combined datetime string
                            appointment_datetime = datetime.datetime.fromisoformat(appointment_datetime_str)
                            print(f'[DEBUG INFO] Appointment datetime: {appointment_datetime}')

                            if appointment_datetime > datetime.datetime.now():
                                print(f'[DEBUG INFO] Appointment {appointment["appointment_id"]} is in the future.')

                                professional_id = existing_chat.get('professional')
                                homeowner_id = existing_chat.get('homeowner')

                                # Fetch professional details (one_party)
                                one_party_details = {}
                                if professional_id:
                                    try:
                                        one_party_role_response = table_roles.query(
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
                                        other_party_role_response = table_roles.query(
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

                                # Prepare response body for each appointment
                                appointment_body = {
                                    'appointment_id': appointment["appointment_id"],
                                    'one_party_details': one_party_details,
                                    'other_party_details': other_party_details
                                }

                                cancelled_appointment_info.append(appointment_body)
                            else:
                                print(f'[DEBUG INFO] Appointment {appointment["appointment_id"]} is in the past.')

        # Case 3: Status change to 'OnHold'
        elif new_status == 'OnHold':
            # Only update the services_requests table
            print('Updating the service request status to OnHold...')
            table.update_item(
                Key={'service_request_id': service_request_id},
                UpdateExpression='SET #s = :s',
                ExpressionAttributeNames={'#s': 'status'},
                ExpressionAttributeValues={':s': 'OnHold'}
            )

        # ---------------------------------------------------------------------
        # --- ORIGINAL LOGIC: Generic updates for other fields ---
        # ---------------------------------------------------------------------

        # Update location information and geohash if coordinates changed
        if ('latitude' in payload and 'longitude' in payload and
            (existing_item.get('latitude') != payload['latitude'] or
             existing_item.get('longitude') != payload['longitude'])):

            # Generate new geohash
            try:
                geohash = geohash2.encode(
                    float(payload['latitude']),
                    float(payload['longitude']),
                    precision=GEOHASH_PRECISION
                )
                payload['geohash'] = geohash
                print(f"Generated new geohash: {geohash}")
            except Exception as e:
                print(f"Error generating geohash: {e}")

        # Update files if provided
        if 'files' in payload:
            print('[DEBUG INFO] Updating the files names list...')
            action = payload.get('files_action')
            print(f'[DEBUG INFO] Action: {action}')
            files_to_update = payload.get('files', [])
            print(f'[DEBUG INFO] Files to update: {files_to_update}')
            existing_files = existing_item.get('files', [])
            print(f'[DEBUG INFO] Existing files: {existing_files}')

            updated_files = existing_files.copy()

            if action == 'add':
                for file in files_to_update:
                    if file not in updated_files:
                        updated_files.append(file)
                print(updated_files)

            elif action == 'remove':
                for file in files_to_update:
                    if file in updated_files:
                        updated_files.remove(file)

            payload['files'] = updated_files
            del payload['files_action']

        # Update lead_for_professionals if provided
        if 'lead_for_professionals' in payload:
            print('Updating the professionals leads ids list...')
            action = payload.get('leads_action')
            leads_to_update = payload.get('lead_for_professionals', [])
            existing_leads = existing_item.get('lead_for_professionals', [])

            updated_leads = existing_leads.copy()
            print(existing_leads)

            if action == 'add':
                for lead in leads_to_update:
                    if lead not in updated_leads:
                        updated_leads.append(lead)
                print(updated_leads)

            elif action == 'remove':
                for lead in leads_to_update:
                    if lead in updated_leads:
                        updated_leads.remove(lead)

            payload['lead_for_professionals'] = updated_leads
            del payload['leads_action']

        # Build update expression for all other fields
        update_expression = 'SET '
        expression_attribute_values = {}
        expression_attribute_names = {}

        # Exclude 'service_request_id' and the fields already handled
        keys_to_exclude = ['service_request_id', 'status', 'selected_professional']
        for key, value in payload.items():
            if key not in keys_to_exclude and existing_item.get(key) != value:
                update_expression += f'#{key} = :{key}, '
                expression_attribute_values[f':{key}'] = value
                expression_attribute_names[f'#{key}'] = key

        update_expression = update_expression.rstrip(', ')

        # Final update to the SR item for all other changes
        if update_expression != 'SET':
            update_kwargs = {
                'Key': {'service_request_id': service_request_id},
                'UpdateExpression': update_expression,
                'ExpressionAttributeValues': expression_attribute_values,
                'ReturnValues': 'ALL_NEW'
            }

            if expression_attribute_names:
                update_kwargs['ExpressionAttributeNames'] = expression_attribute_names

            table.update_item(**update_kwargs)

        # --- Update the return body to include cancelled appointments ---
        body = {'message': 'Item updated successfully'}
        if cancelled_appointment_info:
            body['cancelled_appointments'] = {
                'message': 'Appointments cancelled to advise the other party',
                'appointment_info': cancelled_appointment_info
            }

        print(f'Response: {body}')

        return {
            'statusCode': 200,
            'body': json.dumps(body)
        }

    except Exception as e:
        print(f"An error occurred: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def delete_item(payload):
    try:
        table.delete_item(Key={'service_request_id': payload['service_request_id']})

        return {
            'statusCode': 200,
            'body': json.dumps({'message': 'Item deleted successfully'})
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def format_timestamp(timestamp_ms):
    """Converts a timestamp in milliseconds to 'YYYY-MM-DD' format."""
    print('Converting timestamp in milliseconds to YYYY-MM-DD format')
    dt = datetime.datetime.fromtimestamp(timestamp_ms / 1000.0)
    return dt.strftime('%Y-%m-%d')

def calculate_distance(profile_latitude, profile_longitude, item_latitude, item_longitude):
    """
    Calculates the distance between two points (latitude, longitude) in kilometers.

    Args:
        profile_latitude (str or float): Latitude of the role point.
        profile_longitude (str or float): Longitude of the role point.
        item_latitude (str or float): Latitude of the item point.
        item_longitude (str or float): Longitude of the item point.

    Returns:
        float: Distance between the two points in kilometers.
    """
    try:
        # Convert string values to floats
        role_lat = float(profile_latitude)
        role_lon = float(profile_longitude)
        item_lat = float(item_latitude)
        item_lon = float(item_longitude)

        # Convert latitude and longitude from degrees to radians
        role_lat_rad = math.radians(role_lat)
        role_lon_rad = math.radians(role_lon)
        item_lat_rad = math.radians(item_lat)
        item_lon_rad = math.radians(item_lon)

        # Haversine formula
        dlat = item_lat_rad - role_lat_rad
        dlon = item_lon_rad - role_lon_rad
        a = math.sin(dlat / 2)**2 + math.cos(role_lat_rad) * math.cos(item_lat_rad) * math.sin(dlon / 2)**2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        radius = 6371  # Radius of the Earth in kilometers
        distance = radius * c
        rounded_distance = round(distance, 1)

        return rounded_distance

    except ValueError:
        print("Error: Invalid latitude or longitude values.")
        return None  # Or raise an exception

def dynamo_json_serializer(obj):
    if isinstance(obj, Decimal):
        # If we expect all relevant Decimals to be converted to int/float already,
        # this path will only hit Decimals that *should* remain as float (e.g., from DynamoDB that are not integers)
        return float(obj)
    # Add other non-standard types if they appear (e.g., datetime objects)
    # from datetime import datetime
    # if isinstance(obj, datetime):
    #     return obj.isoformat()
    raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")

def find_matching_professionals(service_request_id, max_recommended_professionals, max_distance_in_meters, include_pro):
    """
    Function to find matching professionals using OpenSearch,
    ensuring the payload structure matches the required format.
    """
    print('[DEBUG INFO] Finding matching professionals using OpenSearch approach...')

    # Retrieve service request details from DynamoDB
    service_request_response = table.get_item(Key={'service_request_id': service_request_id})
    if 'Item' not in service_request_response:
        print(f'[ERROR] Service request {service_request_id} not found')
        return {
            'statusCode': 404,
            'body': json.dumps({'error': 'Service request not found'})
        }

    service_request = service_request_response['Item']

    try:
        # Extract service request data
        sr_selected_professional = service_request.get('selected_professional', '')
        sr_lead_for_professionals = service_request.get('lead_for_professionals', [])
        sr_latitude = service_request.get('latitude')
        sr_longitude = service_request.get('longitude')
        sr_geohash = service_request.get('geohash')
        sr_title = service_request.get('title', '')
        sr_description = service_request.get('description', '')
        sr_projects_themes = service_request.get('SR_projects_themes', {})
        sr_trades = service_request.get('SR_trades', {})
        sr_homeowner = service_request.get('homeowner', '')

        print(f'[DEBUG] Selected professional: {sr_selected_professional}')
        print(f'[DEBUG] Lead for professionals: {sr_lead_for_professionals}')

        # Retrieve homeowner email
        homeowner_response = table_roles.get_item(Key={'role_id': sr_homeowner})
        if 'Item' not in homeowner_response:
            print(f'[ERROR] Homeowner {sr_homeowner} not found')
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Homeowner not found'})
            }

        homeowner_info = homeowner_response['Item']
        homeowner_email = homeowner_info.get('email')

        # Check if we have specific professionals to analyze
        specific_professionals = []

        # Add selected_professional if it exists and is not empty
        if sr_selected_professional and sr_selected_professional.strip():
            specific_professionals.append(sr_selected_professional.strip())
            print(f'[DEBUG] Added selected_professional: {sr_selected_professional}')

        # Handle lead_for_professionals based on list size
        if sr_lead_for_professionals and len(sr_lead_for_professionals) > 0:
            if len(sr_lead_for_professionals) == 1:
                # If only one element, add it directly without further checks
                prof = sr_lead_for_professionals[0]
                if prof and prof.strip() and prof.strip() not in specific_professionals:
                    specific_professionals.append(prof.strip())
                print(f'[DEBUG] Single lead_for_professional added directly: {prof}')
            else:
                # If more than one element, add all to be analyzed
                for prof in sr_lead_for_professionals:
                    if prof and prof.strip() and prof.strip() not in specific_professionals:
                        specific_professionals.append(prof.strip())
                print(f'[DEBUG] Multiple lead_for_professionals added for analysis: {sr_lead_for_professionals}')

        # Special case: if lead_for_professionals has exactly one element and no selected_professional,
        # return that professional immediately with default info
        if (not sr_selected_professional or not sr_selected_professional.strip()) and \
           sr_lead_for_professionals and len(sr_lead_for_professionals) == 1:

            prof_id = sr_lead_for_professionals[0].strip()
            print(f'[DEBUG] Returning single lead_for_professional immediately: {prof_id}')

            try:
                # Query OpenSearch for this specific professional
                opensearch_payload = {
                    "query": {
                        "term": {
                            "doc.role_id_on_dynamo.keyword": prof_id
                        }
                    },
                    "size": 1
                }

                response_hits = query_opensearch(opensearch_payload)

                if response_hits and len(response_hits) > 0:
                    hit = response_hits[0]
                    professional = hit.get('_source', {}).get('doc')
                    if professional:
                        # Calculate distance if coordinates are available
                        distance_meters = None
                        prof_latitude = professional.get('latitude')
                        prof_longitude = professional.get('longitude')

                        if (sr_latitude and sr_longitude and prof_latitude and prof_longitude):
                            try:
                                distance_meters = calculate_distance(
                                    float(sr_latitude), float(sr_longitude),
                                    float(prof_latitude), float(prof_longitude)
                                )
                                print(f'[DEBUG] Distance calculated for single lead: {distance_meters}m')
                            except (ValueError, TypeError) as e:
                                print(f'[DEBUG] Error calculating distance for single lead: {e}')
                                distance_meters = None

                        matching_professional = {
                            'name': professional.get('name', ''),
                            'email': professional.get('email', ''),
                            'language': professional.get('language', ''),
                            'phone': professional.get('phone', ''),
                            'country': professional.get('country', ''),
                            'profile_on_xano': professional.get('profile_on_xano', ''),
                            'role_id_on_dynamo': professional.get('role_id_on_dynamo', ''),
                            'distance_meters': distance_meters,
                            'distance_km': distance_meters / 1000.0 if distance_meters is not None else None,
                            'opensearch_score': hit.get('_score', 0.0),
                            'trades_and_skills': professional.get('trades_and_skills', ''),
                            'trades_list': professional.get('trades_list', {}),
                            'projects_themes_list': professional.get('projects_themes_list', {}),
                            'open_to_work': professional.get('open_to_work', False)
                        }

                        print(f'[DEBUG] Returning single lead professional: {professional.get("email", "unknown")}')
                        return {
                            'statusCode': 200,
                            'body': json.dumps([matching_professional])
                        }

                # If professional not found, return empty list
                print(f'[DEBUG] Single lead professional not found: {prof_id}')
                return {
                    'statusCode': 200,
                    'body': json.dumps([])
                }

            except Exception as e:
                print(f"[ERROR] Failed to retrieve single lead professional {prof_id}: {str(e)}")
                return {
                    'statusCode': 200,
                    'body': json.dumps([])
                }

        # If we have specific professionals (multiple or selected_professional), analyze them
        if specific_professionals:

            # Query for homeowner profile
            homeowner_role_response = table_roles.query(
                IndexName='role_id-index',
                KeyConditionExpression=Key('role_id').eq(sr_homeowner),
                Limit=1
            )
            homeowner_items = homeowner_role_response.get('Items', [])

            if homeowner_items:
                homeowner = homeowner_items[0]
                homeowner_blocked_list = homeowner.get('blocked_list')
            else:
                print(f"Warning: No homeowner profile found for role_id: {homeowner_role_id}")
                homeowner_blocked_list = []

            print(f'[DEBUG] Homeowner blocked_list: {blocked_list}')

            specific_professionals = [p for p in specific_professionals if p not in homeowner_blocked_list]

            print(f'[DEBUG] Analyzing only specific professionals after removing the ones that are in the blocked_list: {specific_professionals}')
            matching_professionals = []

            for prof_id in specific_professionals:
                try:
                    # Query OpenSearch for this specific professional
                    opensearch_payload = {
                        "query": {
                            "term": {
                                "doc.role_id_on_dynamo.keyword": prof_id
                            }
                        },
                        "size": 1
                    }

                    response_hits = query_opensearch(opensearch_payload)

                    if response_hits and len(response_hits) > 0:
                        hit = response_hits[0]
                        professional = hit.get('_source', {}).get('doc')
                        if professional:
                            # Calculate distance if coordinates are available
                            distance_meters = None
                            prof_latitude = professional.get('latitude')
                            prof_longitude = professional.get('longitude')

                            if (sr_latitude and sr_longitude and prof_latitude and prof_longitude):
                                try:
                                    distance_meters = calculate_distance(
                                        float(sr_latitude), float(sr_longitude),
                                        float(prof_latitude), float(prof_longitude)
                                    )
                                    print(f'[DEBUG] Distance calculated for {prof_id}: {distance_meters}m')
                                except (ValueError, TypeError) as e:
                                    print(f'[DEBUG] Error calculating distance for {prof_id}: {e}')
                                    distance_meters = None

                            matching_professional = {
                                'name': professional.get('name', ''),
                                'email': professional.get('email', ''),
                                'language': professional.get('language', ''),
                                'phone': professional.get('phone', ''),
                                'country': professional.get('country', ''),
                                'profile_on_xano': professional.get('profile_on_xano', ''),
                                'role_id_on_dynamo': professional.get('role_id_on_dynamo', ''),
                                'distance_meters': distance_meters,
                                'distance_km': distance_meters / 1000.0 if distance_meters is not None else None,
                                'opensearch_score': hit.get('_score', 0.0),
                                'trades_and_skills': professional.get('trades_and_skills', ''),
                                'trades_list': professional.get('trades_list', {}),
                                'projects_themes_list': professional.get('projects_themes_list', {}),
                                'open_to_work': professional.get('open_to_work', False)
                            }
                            matching_professionals.append(matching_professional)
                            print(f'[DEBUG] Added specific professional: {professional.get("email", "unknown")}')

                except Exception as e:
                    print(f"[ERROR] Failed to retrieve professional {prof_id}: {str(e)}")
                    continue

            print(f'[DEBUG] Retrieved {len(matching_professionals)} specific professionals')

            # Sort by distance if available, otherwise maintain original order
            matching_professionals.sort(key=lambda x: x.get('distance_meters') or float('inf'))

            return {
                'statusCode': 200,
                'body': json.dumps(matching_professionals)
            }

        # If no specific professionals, proceed with the full search logic
        print('[DEBUG] No specific professionals found, proceeding with full search')

        # Convert coordinates to float
        try:
            sr_lat_float = float(sr_latitude) if sr_latitude is not None else None
            sr_lon_float = float(sr_longitude) if sr_longitude is not None else None
        except (ValueError, TypeError):
            print("[WARNING] Invalid coordinates, geographic filtering disabled")
            sr_lat_float = None
            sr_lon_float = None

        print(f'[DEBUG] Max recommended professionals: {max_recommended_professionals}')
        print(f'[DEBUG] Max distance: {max_distance_in_meters}m')

        # Build the search query string from service request data
        search_terms = []

        # Extract terms from trades (all languages) - prioritize these
        trade_terms = []
        if isinstance(sr_trades, dict):
            for lang_terms in sr_trades.values():
                if isinstance(lang_terms, list):
                    trade_terms.extend([term.strip() for term in lang_terms if term and term.strip()])
                elif lang_terms:
                    trade_terms.append(str(lang_terms).strip())

        # Extract terms from themes (all languages) - prioritize these
        theme_terms = []
        if isinstance(sr_projects_themes, dict):
            for lang_terms in sr_projects_themes.values():
                if isinstance(lang_terms, list):
                    theme_terms.extend([term.strip() for term in lang_terms if term and term.strip()])
                elif lang_terms:
                    theme_terms.append(str(lang_terms).strip())

        # Add key terms from title and description (extract meaningful words)
        title_words = []
        description_words = []
        if sr_title:
            # Extract meaningful words from title (avoid common words)
            title_words = [word for word in sr_title.split() if len(word) > 2 and word.lower() not in ['the', 'and', 'for', 'with', 'some', 'have', 'need', 'fix', 'issues']]
        if sr_description:
            # Extract meaningful words from description (limit to avoid very long queries)
            desc_words = [word for word in sr_description.split() if len(word) > 2 and word.lower() not in ['the', 'and', 'for', 'with', 'some', 'have', 'need', 'fix', 'issues']]
            description_words = desc_words[:10]  # Limit to first 10 meaningful words

        # Build prioritized search terms (trades and themes first, then title/description)
        search_terms = trade_terms + theme_terms + title_words + description_words

        # Limit total terms to avoid very long queries (OpenSearch works better with focused queries)
        if len(search_terms) > 20:
            search_terms = search_terms[:20]

        # Create the multi_match query string
        query_string = ' '.join(search_terms) if search_terms else 'professional service'

        print(f'[DEBUG] Trade terms: {trade_terms}')
        print(f'[DEBUG] Theme terms: {theme_terms}')
        print(f'[DEBUG] Title words: {title_words}')
        print(f'[DEBUG] Description words: {description_words}')
        print(f'[DEBUG] Final search query string ({len(search_terms)} terms): "{query_string}"')

        # === Constructing the OpenSearch payload to match the required format ===
        opensearch_payload = {
            "explain": True,
            "query": {
                "bool": {
                    "must": [
                        {
                            "term": {
                                "doc.open_to_work": True
                            }
                        },
                        {
                            "term": {
                                "doc.soft_delete": False
                            }
                        }
                    ]
                }
            },
            "size": max_recommended_professionals # Sets the number of results to return
        }

        # Add geographic filtering if location data and max_distance_in_meters are provided
        if max_distance_in_meters and sr_lat_float is not None and sr_lon_float is not None:
            geo_filters = []

            # Calculate geohash prefix for filtering to narrow down search space
            if sr_geohash:
                max_distance_km = max_distance_in_meters / 1000.0
                if max_distance_km > 600:
                    prefix_length = 1
                elif max_distance_km > 150:
                    prefix_length = 2
                elif max_distance_km > 40:
                    prefix_length = 3
                elif max_distance_km > 5:
                    prefix_length = 4
                else:
                    prefix_length = 5

                geohash_prefix = sr_geohash[:prefix_length]

                geo_filters.append({
                    "prefix": {
                        "doc.geohash": geohash_prefix
                    }
                })
                print(f'[DEBUG] Added geohash prefix filter: "{geohash_prefix}"')

            # Add geo_distance filter to find professionals within the specified radius
            geo_filters.append({
                "geo_distance": {
                    "distance": f"{max_distance_in_meters}m",
                    "doc.location": {
                        "lat": sr_lat_float,
                        "lon": sr_lon_float
                    }
                }
            })
            print(f'[DEBUG] Added geo_distance filter: {max_distance_in_meters}m from ({sr_lat_float}, {sr_lon_float})')

            # This 'filter' clause is added to the 'bool' query when geographic data is available
            opensearch_payload["query"]["bool"]["filter"] = [
                {
                    "bool": {
                        "must": geo_filters
                    }
                }
            ]

        # This 'should' clause handles the relevance search using multi_match
        opensearch_payload["query"]["bool"]["should"] = [
            {
                "multi_match": {
                    "query": query_string, # The combined search terms
                    "fields": [ # Fields to search across for relevance
                        "doc.portfolio.category_name_en",
                        "doc.portfolio.category_name_fr",
                        "doc.portfolio.category_name_es",
                        "doc.portfolio.category_name_pt",
                        "doc.portfolio.category_description_en",
                        "doc.portfolio.category_description_fr",
                        "doc.portfolio.category_description_es",
                        "doc.portfolio.category_description_pt",
                        "doc.trades_list.en",
                        "doc.trades_list.fr",
                        "doc.trades_list.es",
                        "doc.trades_list.pt",
                        "doc.projects_themes_list.en",
                        "doc.projects_themes_list.fr",
                        "doc.projects_themes_list.es",
                        "doc.projects_themes_list.pt",
                        "doc.profile_experience.en",
                        "doc.profile_experience.fr",
                        "doc.profile_experience.es",
                        "doc.profile_experience.pt"
                    ],
                    "type": "best_fields", # Prioritizes the best matching field
                    "operator": "or",     # Matches if any term is found in any field
                    "fuzziness": "AUTO"   # Allows for minor typos/variations
                }
            }
        ]
        # At least one 'should' clause must match
        opensearch_payload["query"]["bool"]["minimum_should_match"] = 1

        print(f'[DEBUG] Final OpenSearch payload: {json.dumps(opensearch_payload, ensure_ascii=False, indent=2)}')

        # Execute OpenSearch query
        print('[DEBUG] Executing OpenSearch query...')
        response_hits = query_opensearch(opensearch_payload)

        # Check for errors from the OpenSearch query
        if isinstance(response_hits, dict) and 'statusCode' in response_hits:
            print(f'[ERROR] OpenSearch query failed: {response_hits}')
            return response_hits

        print(f'[DEBUG] OpenSearch returned {len(response_hits)} hits')

        # Process results
        matching_professionals = []

        for i, hit in enumerate(response_hits):
            professional = hit.get('_source', {}).get('doc')
            if not professional:
                print(f"[WARNING] No 'doc' found in hit {i}, skipping")
                continue

            # Get OpenSearch score for relevance
            opensearch_score = hit.get('_score', 0.0)
            if opensearch_score is None:
                opensearch_score = 0.0

            # Get distance from sort results if available (from geo_distance sort)
            distance_meters = None
            if 'sort' in hit and len(hit['sort']) > 0:
                distance_meters = hit['sort'][0]

            # exclude professionals with same email as the homeowner
            if professional.get('email', '') == homeowner_email:
                print(f'[DEBUG] Excluding professional with same email as homeowner: {professional.get("email", "unknown")}')
            else:
                # Build professional result object
                matching_professional = {
                    'name': professional.get('name', ''),
                    'email': professional.get('email', ''),
                    'language': professional.get('language', ''),
                    'phone': professional.get('phone', ''),
                    'country': professional.get('country', ''),
                    'profile_on_xano': professional.get('profile_on_xano', ''),
                    'user_type': professional.get('user_type', ''),
                    'profile_professionals_id': professional.get('profile_professionals_id', ''),
                    'profile_contractors_id': professional.get('profile_contractors_id', ''),
                    'role_id_on_dynamo': professional.get('role_id_on_dynamo', ''),
                    'distance_meters': distance_meters,
                    'distance_km': distance_meters / 1000.0 if distance_meters is not None else None,
                    'opensearch_score': opensearch_score,
                    'trades_and_skills': professional.get('trades_and_skills', ''),
                    'trades_list': professional.get('trades_list', {}),
                    'projects_themes_list': professional.get('projects_themes_list', {}),
                    'open_to_work': professional.get('open_to_work', False)
                }

                matching_professionals.append(matching_professional)
                print(f'[DEBUG] Added professional: {professional.get("email", "unknown")} (score: {opensearch_score:.2f})')

        # Handle include_pro parameter - add the specified professional if provided
        if include_pro is not None:
            print(f'[DEBUG] Adding include_pro professional: {include_pro}')
            try:
                # Query OpenSearch for the include_pro professional
                opensearch_payload_include = {
                    "query": {
                        "term": {
                            "doc.role_id_on_dynamo.keyword": include_pro
                        }
                    },
                    "size": 1
                }

                include_response_hits = query_opensearch(opensearch_payload_include)

                if include_response_hits and len(include_response_hits) > 0:
                    hit = include_response_hits[0]
                    professional = hit.get('_source', {}).get('doc')
                    if professional:
                        # Check if this professional is already in the list
                        already_included = any(p.get('role_id_on_dynamo') == include_pro for p in matching_professionals)

                        if not already_included:
                            # Calculate distance if coordinates are available
                            distance_meters = None
                            prof_latitude = professional.get('latitude')
                            prof_longitude = professional.get('longitude')

                            if (sr_latitude and sr_longitude and prof_latitude and prof_longitude):
                                try:
                                    distance_meters = calculate_distance(
                                        float(sr_latitude), float(sr_longitude),
                                        float(prof_latitude), float(prof_longitude)
                                    )
                                    print(f'[DEBUG] Distance calculated for include_pro: {distance_meters}m')
                                except (ValueError, TypeError) as e:
                                    print(f'[DEBUG] Error calculating distance for include_pro: {e}')
                                    distance_meters = None

                            # Skip if professional has same email as homeowner
                            if professional.get('email', '') != homeowner_email:
                                matching_professional = {
                                    'name': professional.get('name', ''),
                                    'email': professional.get('email', ''),
                                    'language': professional.get('language', ''),
                                    'phone': professional.get('phone', ''),
                                    'country': professional.get('country', ''),
                                    'profile_on_xano': professional.get('profile_on_xano', ''),
                                    'user_type': professional.get('user_type', ''),
                                    'profile_professionals_id': professional.get('profile_professionals_id', ''),
                                    'profile_contractors_id': professional.get('profile_contractors_id', ''),
                                    'role_id_on_dynamo': professional.get('role_id_on_dynamo', ''),
                                    'distance_meters': distance_meters,
                                    'distance_km': distance_meters / 1000.0 if distance_meters is not None else None,
                                    'opensearch_score': hit.get('_score', 0.0),
                                    'trades_and_skills': professional.get('trades_and_skills', ''),
                                    'trades_list': professional.get('trades_list', {}),
                                    'projects_themes_list': professional.get('projects_themes_list', {}),
                                    'open_to_work': professional.get('open_to_work', False)
                                }

                                matching_professionals.append(matching_professional)
                                print(f'[DEBUG] Added include_pro professional: {professional.get("email", "unknown")}')
                            else:
                                print(f'[DEBUG] Skipping include_pro professional with same email as homeowner: {professional.get("email", "unknown")}')
                        else:
                            print(f'[DEBUG] include_pro professional already in results: {include_pro}')
                else:
                    print(f'[DEBUG] include_pro professional not found: {include_pro}')

            except Exception as e:
                print(f"[ERROR] Failed to retrieve include_pro professional {include_pro}: {str(e)}")

        print(f'[DEBUG] Before deduplication: {len(matching_professionals)} professionals')

        # Remove duplicates based on phone number
        seen_phones = set()
        unique_professionals = []
        for professional in matching_professionals:
            phone = professional.get('phone', '')
            if phone and phone not in seen_phones:
                seen_phones.add(phone)
                unique_professionals.append(professional)
            elif not phone:
                # Keep professionals with empty/missing phone
                unique_professionals.append(professional)

        matching_professionals = unique_professionals
        print(f'[DEBUG] After deduplication: {len(matching_professionals)} unique professionals')

        print(f'[DEBUG] Final result: {len(matching_professionals)} matching professionals')

        return {
            'statusCode': 200,
            'body': json.dumps(matching_professionals)
        }

    except Exception as e:
        print(f"[ERROR] Exception in find_matching_professionals: {str(e)}")
        import traceback
        traceback.print_exc()
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def get_by_pro(pro, search_query=None, start_date_filter=None, end_date_filter=None, status_filter=None):
    print(f'[DEBUG INFO] Initializing get_by_pro function for pro: {pro}')
    try:
        # Get professional profile from OpenSearch
        profile = get_professional_by_role_id(pro)
        if not profile:
            print(f"Professional profile not found: {pro}")
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Professional profile not found'})
            }

        # Extract profile data for distance calculations and other logic
        profile_latitude = profile.get('latitude')
        profile_longitude = profile.get('longitude')
        profile_geohash = profile.get('geohash')
        profile_country = profile.get('country')
        credits_balance = profile.get('credits_balance', 0)
        credits_balance = int(credits_balance)

        use_miles = (profile_country == 'US')
        distance_unit = 'mi' if use_miles else 'km'
        print(f"[DEBUG] Professional country: {profile_country}, using {distance_unit}")
        print(f'Professional credits balance: {credits_balance}')

        pro_id = pro

        # Query for pro profile in Dynamo table 'roles'
        pro_role_response = table_roles.query(
            IndexName='role_id-index',
            KeyConditionExpression=Key('role_id').eq(pro_id),
            Limit=1
        )
        pro_items = pro_role_response.get('Items', [])

        if pro_items:
            pro = pro_items[0]
            print(f'[DEBUG] Professional profile found: {pro}')
            pro_blocked_list = pro.get('blocked_list', [])
        else:
            print(f"Warning: No pro profile found for role_id: {pro_id}")
            pro_blocked_list = []

        print(f'[DEBUG] Professional blocked_list: {pro_blocked_list}')


        # Build filter expression based on status requirements
        items = []

        print(f"[DEBUG] Status filter to check: {status_filter}")

        if status_filter == 'All':
            # Get all SRs with status InProgress, Complete, Reviewed, and Open (with requisites fulfilled)
            statuses_to_check = ['Open', 'InProgress', 'Complete', 'Reviewed']
        else:
            # Get SRs with specific status (with requisites fulfilled)
            statuses_to_check = [status_filter] if status_filter else ['Open', 'InProgress', 'Complete', 'Reviewed']

        for status in statuses_to_check:
            print(f"[DEBUG] Checking status: {status}")

            # Query based on status requisites
            if status == 'Open':
                # SR status==Open and (selected_pro == pro_id) or (pro_id in lead_for_professionals) or (lead_for_professionals is empty)
                response = table.scan(
                    FilterExpression=boto3.dynamodb.conditions.Attr('status').eq('Open') & (
                        boto3.dynamodb.conditions.Attr('selected_professional').eq(pro_id) |
                        boto3.dynamodb.conditions.Attr('lead_for_professionals').contains(pro_id) |
                        boto3.dynamodb.conditions.Attr('lead_for_professionals').eq([])
                    )
                )
            elif status == 'InProgress':
                # SR status==InProgress and selected_pro == pro_id
                response = table.scan(
                    FilterExpression=boto3.dynamodb.conditions.Attr('status').eq('InProgress') &
                    boto3.dynamodb.conditions.Attr('selected_professional').eq(pro_id)
                )
            elif status == 'Complete':
                # SR status==Complete and selected_pro == pro_id
                response = table.scan(
                    FilterExpression=boto3.dynamodb.conditions.Attr('status').eq('Complete') &
                    boto3.dynamodb.conditions.Attr('selected_professional').eq(pro_id)
                )
            elif status == 'Reviewed':
                # SR status==Reviewed and selected_pro == pro_id
                response = table.scan(
                    FilterExpression=boto3.dynamodb.conditions.Attr('status').eq('Reviewed') &
                    boto3.dynamodb.conditions.Attr('selected_professional').eq(pro_id)
                )

            status_items = response.get('Items', [])
            print(f"Found {len(status_items)} items for status: {status}")
            items.extend(status_items)

        print(f"Total items before filtering: {len(items)}")

        unique_items = {}

        for item in items:

            homeowner_id = item.get('homeowner', '')
            # Query for homeowner profile
            homeowner_role_response = table_roles.query(
                IndexName='role_id-index',
                KeyConditionExpression=Key('role_id').eq(homeowner_id),
                Limit=1
            )
            homeowner_items = homeowner_role_response.get('Items', [])

            if homeowner_items:
                homeowner = homeowner_items[0]
                homeowner_blocked_list = homeowner.get('blocked_list')
            else:
                print(f"Warning: No homeowner profile found for role_id: {homeowner_id}")
                item['homeowner_name'] = None

            print(f'[DEBUG] Homeowner blocked_list: {homeowner_blocked_list}')

            if pro_id not in homeowner_blocked_list and homeowner_id not in pro_blocked_list:
                print(f'[DEBUG] Professional is not in homeowner blocked list and Homeowner is not in professional blocked list')
                # Remove duplicates based on service_request_id
                service_request_id = item.get('service_request_id')
                if service_request_id not in unique_items:
                    unique_items[service_request_id] = item

        items = list(unique_items.values())
        print(f"Items after removing blocked list and deduplication: {len(items)}")

        # Apply the other filters, if it is the case:

        print(f"[DEBUG] Start date and end date filters to be applied: {start_date_filter} - {end_date_filter}")

        # Filter by date range if provided
        if start_date_filter or end_date_filter:
            filtered_items = []
            for item in items:
                created_at = item.get('created_at', '')

                if start_date_filter and end_date_filter:
                    if start_date_filter <= created_at <= end_date_filter:
                        filtered_items.append(item)
                elif start_date_filter:
                    if start_date_filter <= created_at:
                        filtered_items.append(item)
                elif end_date_filter:
                    if created_at <= end_date_filter:
                        filtered_items.append(item)

            items = filtered_items

        print(f"[DEBUG] Query search filter to be applied: {search_query}")

        # Filter and sort by search query if provided
        if search_query:
            search_results = []

            for item in items:
                # Collect themes from all languages
                themes = item.get('SR_projects_themes', {})
                all_themes = []
                for lang_key in ['themes_en', 'themes_es', 'themes_fr', 'themes_pt']:
                    all_themes.extend(themes.get(lang_key, []))

                # Collect trades from all languages
                trades = item.get('SR_trades', {})
                all_trades = []
                for lang_key in ['trades_en', 'trades_es', 'trades_fr', 'trades_pt']:
                    all_trades.extend(trades.get(lang_key, []))

                # Combine everything into searchable text
                themes_text = ' '.join(all_themes)
                trades_text = ' '.join(all_trades)

                searchable_text = f"{item.get('title', '')} {item.get('description', '')} {item.get('city', '')} {themes_text} {trades_text}".lower()

                print(f'[DEBUG INFO] Searchable text: {searchable_text}')


                if search_query.lower() in searchable_text:
                    search_results.append(item)

            items = search_results

        # Extract profile IDs for matching
        profile_trades_ids = profile.get('trades_id', [])
        profile_projects_themes_id = profile.get('dict_projects_themes_id', [])

        print(f"[DEBUG] Professional trades IDs: {profile_trades_ids}")
        print(f"[DEBUG] Professional projects themes IDs: {profile_projects_themes_id}")

        # Process each item for distance calculation and other attributes
        for item in items:
            # Convert Decimal types to appropriate types
            for key in ['max_distance_in_meters', 'views_count', 'credits_required', 'created_at_timestamp']:
                if key in item and isinstance(item[key], Decimal):
                    item[key] = int(item[key])

            for list_key in ['SR_projects_themes_ids', 'SR_trades_ids']:
                if list_key in item and isinstance(item[list_key], list):
                    item[list_key] = [int(val) if isinstance(val, Decimal) else val for val in item[list_key]]

            if 'chats' in item and isinstance(item['chats'], list):
                for chat in item['chats']:
                    if 'created_at_timestamp' in chat and isinstance(chat['created_at_timestamp'], Decimal):
                        chat['created_at_timestamp'] = int(chat['created_at_timestamp'])

            # Check for theme or trade coincidence
            item_trades_ids = item.get('SR_trades_ids', [])
            item_projects_themes_ids = item.get('SR_projects_themes_ids', [])

            # Convert to sets and check for intersection
            profile_trades_set = set(profile_trades_ids) if profile_trades_ids else set()
            profile_themes_set = set(profile_projects_themes_id) if profile_projects_themes_id else set()
            item_trades_set = set(item_trades_ids) if item_trades_ids else set()
            item_themes_set = set(item_projects_themes_ids) if item_projects_themes_ids else set()

            # Check if there's any intersection between professional and service request
            trades_match = bool(profile_trades_set.intersection(item_trades_set))
            themes_match = bool(profile_themes_set.intersection(item_themes_set))

            item['theme_or_trade_coincidence'] = trades_match or themes_match

            print(f"[DEBUG] Item {item.get('service_request_id')}: trades_match={trades_match}, themes_match={themes_match}, coincidence={item['theme_or_trade_coincidence']}")
            if item['theme_or_trade_coincidence']:
                print(f"[DEBUG] Matching trades: {profile_trades_set.intersection(item_trades_set)}")
                print(f"[DEBUG] Matching themes: {profile_themes_set.intersection(item_themes_set)}")

            # Calculate distance
            item_geohash = item.get('geohash')
            item_latitude = item.get('latitude')
            item_longitude = item.get('longitude')
            max_distance_in_meters = item.get('max_distance_in_meters')

            # Set default max distance if not specified (1000km = 1,000,000 meters)
            if not max_distance_in_meters or max_distance_in_meters == '':
                max_distance_limit = 1000000  # 1000km default
            else:
                max_distance_limit = int(max_distance_in_meters) if isinstance(max_distance_in_meters, (str, Decimal)) else max_distance_in_meters

            print(f"[DEBUG] Processing item {item.get('service_request_id')} with max_distance_limit: {max_distance_limit}m")

            # Always calculate real distance if coordinates are available
            distance_meters = None
            if item_latitude and item_longitude and profile_latitude and profile_longitude:
                try:
                    # Use geohash for optimization - only calculate exact distance if potentially within range
                    should_calculate_exact = True

                    if profile_geohash and item_geohash:
                        # Quick geohash check for very distant locations
                        common_prefix_length = 0
                        for i in range(min(len(profile_geohash), len(item_geohash))):
                            if profile_geohash[i] == item_geohash[i]:
                                common_prefix_length += 1
                            else:
                                break

                        # If geohash suggests very distant (less than 3 common chars),
                        # and max_distance is small, skip exact calculation for performance
                        if common_prefix_length < 3 and max_distance_limit < 100000:  # Less than 100km
                            should_calculate_exact = False
                            distance_meters = float('inf')  # Will be filtered out anyway
                            print(f"[DEBUG] Skipped exact calculation for distant item {item.get('service_request_id')} (geohash optimization)")

                    if should_calculate_exact:
                        # calculate_distance returns KILOMETERS, so convert to meters
                        distance_km = calculate_distance(
                            float(profile_latitude), float(profile_longitude),
                            float(item_latitude), float(item_longitude)
                        )

                        if distance_km is not None:
                            distance_meters = distance_km * 1000  # Convert km to meters
                            print(f"[DEBUG] Calculated distance for item {item.get('service_request_id')}: {distance_km}km = {distance_meters}m")
                        else:
                            distance_meters = float('inf')
                            print(f"[DEBUG] calculate_distance returned None for item {item.get('service_request_id')}")

                except (ValueError, TypeError) as e:
                    print(f"[DEBUG] Error calculating distance for item {item.get('service_request_id')}: {e}")
                    distance_meters = float('inf')
            else:
                print(f"[DEBUG] Missing coordinates for item {item.get('service_request_id')}")
                print(f"[DEBUG] Professional coords: ({profile_latitude}, {profile_longitude})")
                print(f"[DEBUG] Item coords: ({item_latitude}, {item_longitude})")
                distance_meters = float('inf')

            # Set distance values for display
            if distance_meters is not None and distance_meters != float('inf'):
                if use_miles:
                    distance_value = distance_meters * 0.000621371
                    distance_unit_str = 'mi'
                    # Remove trailing zeros: 15.100mi -> 15.1mi, 1.000mi -> 1mi
                    item['distance_display'] = f"{distance_value:.3f}".rstrip('0').rstrip('.') + distance_unit_str
                else:
                    distance_value = distance_meters / 1000.0
                    distance_unit_str = 'km'
                    # Remove trailing zeros: 15.100km -> 15.1km, 1.000km -> 1km
                    item['distance_display'] = f"{distance_value:.3f}".rstrip('0').rstrip('.') + distance_unit_str

                item['distance'] = distance_meters
            else:
                item['distance'] = float('inf')
                item['distance_display'] = f"∞{distance_unit}"

            # Apply max_distance filtering - mark items for removal if they exceed the limit
            if distance_meters is not None and distance_meters != float('inf'):
                if distance_meters > max_distance_limit:
                    item['_should_remove'] = True
                    print(f"[DEBUG] Item {item.get('service_request_id')} exceeds max distance: {distance_meters}m > {max_distance_limit}m")
                else:
                    print(f"[DEBUG] Item {item.get('service_request_id')} within max distance: {distance_meters}m <= {max_distance_limit}m")
            else:
                # Items with no valid distance are removed
                item['_should_remove'] = True
                print(f"[DEBUG] Item {item.get('service_request_id')} marked for removal (no valid distance)")

            # Set chat-related attributes
            item['chat_started'] = False
            item['chat_id'] = None
            current_chats = item.get('chats', [])
            for chat in current_chats:
                if chat.get('professional') == pro:
                    item['chat_started'] = True
                    item['chat_id'] = chat.get('chat_id', None)
                    break

        # Remove items that exceed max_distance_in_meters or have invalid distances
        items = [item for item in items if not item.get('_should_remove', False)]
        print(f"Items after max distance filtering: {len(items)}")

        # Sort by chat status first, then theme/trade coincidence, then by distance within each group
        def sort_key(item):
            # Primary sort: chat started (True first)
            # Secondary sort: theme/trade coincidence (True first within non-chat group)
            # Tertiary sort: distance (ascending)
            chat_started = item.get('chat_started', False)
            coincidence = item.get('theme_or_trade_coincidence', False)
            distance = item.get('distance', float('inf'))

            # Create sorting tuple:
            # - not chat_started: False (0) for items with chat, True (1) for items without chat
            # - not coincidence: False (0) for items with coincidence, True (1) for items without
            # - distance: ascending order
            return (not chat_started, not coincidence, distance)

        items.sort(key=sort_key)

        # Debug logging for sorted order
        chat_started_count = sum(1 for item in items if item.get('chat_started', False))
        coincidence_count = sum(1 for item in items if item.get('theme_or_trade_coincidence', False) and not item.get('chat_started', False))
        other_count = len(items) - chat_started_count - coincidence_count

        print(f"[DEBUG] Sorted items: {chat_started_count} with chat started, {coincidence_count} with theme/trade coincidence (no chat), {other_count} others")
        for i, item in enumerate(items[:10]):  # Log first 10 items
            chat_started = item.get('chat_started', False)
            coincidence = item.get('theme_or_trade_coincidence', False)
            distance = item.get('distance', 'inf')
            print(f"[DEBUG] Item {i+1}: {item.get('service_request_id')} - chat: {chat_started}, coincidence: {coincidence}, distance: {distance}")


        # Process items for credits and final output
        final_output_items = []
        for item in items:
            credits_required = item.get('credits_required', 0)
            print(f"Credits required for {item.get('service_request_id')}: {credits_required}")

            if credits_balance < credits_required:
                print(f"Insufficient credits for {item.get('service_request_id')}")
                item['insufficient_credits'] = True
            else:
                item['insufficient_credits'] = False
                print(f"Sufficient credits for {item.get('service_request_id')}")

            # Update views count
            try:
                update_views_count(item['service_request_id'])
            except Exception as e:
                print(f"Error updating views_count for {item['service_request_id']}: {e}")

            # Remove the temporary marker
            if '_should_remove' in item:
                del item['_should_remove']

            final_output_items.append(item)

        print(f"[DEBUG INFO] Returning {len(final_output_items)} items")
        print(f"[DEBUG INFO] End of get_by_pro processing")

        return {
            'statusCode': 200,
            'body': json.dumps({
                'available_leads': final_output_items,
                'credits_balance': credits_balance
            }, default=str)
        }

    except Exception as e:
        print(f"[ERROR] Error in get_by_pro: {e}")
        import traceback
        traceback.print_exc()
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def get_sr_by_pros_closed_to_work(emails_to_eliminate):
    """
    Find professionals with open_to_work=false who match open service requests
    based on geohash, trades, and project themes, excluding specified emails.

    Args:
        emails_to_eliminate (list): List of emails to exclude from results

    Returns:
        dict: Response with matched professionals and their language/phone
    """
    print('[DEBUG INFO] Initializing get_sr_by_pros_closed_to_work function...')
    print(f'[DEBUG INFO] Emails to eliminate: {emails_to_eliminate}')

    try:
        # Calculate date range: today and 15 days ago
        today = datetime.datetime.now()
        fifteen_days_ago = today - datetime.timedelta(days=15)

        # Convert to ISO format for comparison with created_at timestamps
        fifteen_days_ago_str = fifteen_days_ago.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        today_str = today.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

        print(f'[DEBUG INFO] Date range: {fifteen_days_ago_str} to {today_str}')

        # Query DynamoDB for open service requests created in the last 15 days
        # First, scan all items and filter in memory (DynamoDB doesn't support date range on non-key attributes efficiently)
        response = table.scan()
        items = response.get('Items', [])

        # Handle pagination
        while 'LastEvaluatedKey' in response:
            response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
            items.extend(response.get('Items', []))

        print(f'[DEBUG INFO] Total service requests scanned: {len(items)}')

        # Filter for open service requests within date range
        filtered_service_requests = []
        for item in items:
            created_at = item.get('created_at', '')
            status = item.get('status', '').lower()

            # Check if status is "Open" and created within last 15 days
            if status == 'open' and created_at >= fifteen_days_ago_str:
                # Calculate if created_at + 15 days >= today
                try:
                    created_datetime = datetime.datetime.strptime(created_at, '%Y-%m-%dT%H:%M:%S.%fZ')
                except ValueError:
                    # Try alternative format if needed
                    try:
                        created_datetime = datetime.datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                    except:
                        print(f"[WARNING] Could not parse created_at: {created_at}")
                        continue

                expiration_date = created_datetime + datetime.timedelta(days=15)

                if expiration_date >= today:
                    # Extract only needed fields
                    sr_data = {
                        'service_request_id': item.get('service_request_id'),
                        'SR_trades_ids': item.get('SR_trades_ids', []),
                        'SR_projects_themes_ids': item.get('SR_projects_themes_ids', []),
                        'geohash': item.get('geohash', '')
                    }
                    filtered_service_requests.append(sr_data)

        print(f'[DEBUG INFO] Filtered service requests (open, within date range): {len(filtered_service_requests)}')

        if not filtered_service_requests:
            print('[DEBUG INFO] No matching service requests found')
            return {
                'statusCode': 200,
                'body': json.dumps({'matched_professionals': []})
            }

        # Build OpenSearch query to find professionals with open_to_work=false
        # and email not in emails_to_eliminate
        must_conditions = [
            {
                "term": {
                    "doc.open_to_work": False
                }
            }
        ]

        # Add email exclusion if emails_to_eliminate is provided
        if emails_to_eliminate and len(emails_to_eliminate) > 0:
            must_not_conditions = []
            for email in emails_to_eliminate:
                must_not_conditions.append({
                    "term": {
                        "doc.email.keyword": email
                    }
                })

            opensearch_payload = {
                "query": {
                    "bool": {
                        "must": must_conditions,
                        "must_not": must_not_conditions
                    }
                },
                "size": 10000  # Get all matching professionals
            }
        else:
            opensearch_payload = {
                "query": {
                    "bool": {
                        "must": must_conditions
                    }
                },
                "size": 10000
            }

        print(f'[DEBUG INFO] OpenSearch query: {json.dumps(opensearch_payload, indent=2)}')

        # Query OpenSearch for professionals
        response_hits = query_opensearch(opensearch_payload)

        if isinstance(response_hits, dict) and 'statusCode' in response_hits:
            print(f'[ERROR] OpenSearch query failed: {response_hits}')
            return response_hits

        print(f'[DEBUG INFO] Found {len(response_hits)} professionals with open_to_work=false')

        # Extract professionals from hits
        professionals = []
        for hit in response_hits:
            professional = hit.get('_source', {}).get('doc')
            if professional:
                professionals.append(professional)

        print(f'[DEBUG INFO] Extracted {len(professionals)} professionals')

        # Match professionals with service requests
        matched_professionals = []
        matched_combinations = set()  # Track unique email+phone combinations

        for professional in professionals:
            prof_geohash = professional.get('geohash', '')
            prof_trades_ids = professional.get('trades_id', [])
            prof_themes_ids = professional.get('dict_projects_themes_id', [])
            prof_email = professional.get('email', '')
            prof_language = professional.get('language', '')
            prof_phone = professional.get('phone', '')

            # Skip if no geohash (can't match)
            if not prof_geohash or len(prof_geohash) < 2:
                continue

            # Get first 2 digits of professional's geohash
            prof_geohash_prefix = prof_geohash[:2]

            # Check against each service request
            for sr in filtered_service_requests:
                sr_geohash = sr.get('geohash', '')

                # Skip if no geohash
                if not sr_geohash or len(sr_geohash) < 2:
                    continue

                # Check if first 2 digits match
                sr_geohash_prefix = sr_geohash[:2]

                if prof_geohash_prefix != sr_geohash_prefix:
                    continue

                # Geohash matches, now check trades or themes intersection
                sr_trades_ids = sr.get('SR_trades_ids', [])
                sr_themes_ids = sr.get('SR_projects_themes_ids', [])

                # Convert to sets for intersection check
                prof_trades_set = set(prof_trades_ids) if prof_trades_ids else set()
                prof_themes_set = set(prof_themes_ids) if prof_themes_ids else set()
                sr_trades_set = set(sr_trades_ids) if sr_trades_ids else set()
                sr_themes_set = set(sr_themes_ids) if sr_themes_ids else set()

                # Check if there's intersection in trades or themes
                trades_match = bool(prof_trades_set.intersection(sr_trades_set))
                themes_match = bool(prof_themes_set.intersection(sr_themes_set))

                if trades_match or themes_match:
                    # Professional matches this service request
                    # Create unique key from email+phone to eliminate duplicates
                    unique_key = (prof_email, prof_phone)

                    # Add to results if not already added
                    if unique_key not in matched_combinations:
                        matched_combinations.add(unique_key)
                        matched_professionals.append({
                            'email': prof_email,
                            'language': prof_language,
                            'phone': prof_phone
                        })
                        print(f'[DEBUG INFO] Matched professional: {prof_email}')
                    # Break to avoid adding same professional multiple times for different SRs
                    break

        print(f'[DEBUG INFO] Total matched professionals: {len(matched_professionals)}')

        return {
            'statusCode': 200,
            'body': json.dumps({'matched_professionals': matched_professionals})
        }

    except Exception as e:
        print(f'[ERROR] Exception in get_sr_by_pros_closed_to_work: {str(e)}')
        import traceback
        traceback.print_exc()
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
