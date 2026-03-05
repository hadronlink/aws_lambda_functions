import json
import boto3
import datetime
import math
import sys
import os
import re
import geohash2
from decimal import Decimal
from boto3.dynamodb.conditions import Key, Attr, And, Not, Contains
from opensearchpy import OpenSearch, RequestsHttpConnection
from aws_requests_auth.aws_auth import AWSRequestsAuth
import traceback
import requests
from requests.auth import HTTPBasicAuth
from datetime import date
from botocore.exceptions import ClientError

# DynamoDB setup
dynamodb = boto3.resource('dynamodb')
table_roles = dynamodb.Table('roles_dev')
table_reviews = dynamodb.Table('reviews_dev')

# OpenSearch configuration for profiles
OPENSEARCH_ENDPOINT = 'https://search-connecus-home-xter5mxymdzivmnio2iuvwgg4a.us-east-2.es.amazonaws.com'
OPENSEARCH_INDEX = 'pros_from_xano_dev'
AWS_REGION = 'us-east-2'
SECRETS_MANAGER_SECRET_NAME = 'opensearch-credentials'

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

def create_error_response(status_code, message):
    """Create a standardized error response"""
    return {
        'statusCode': status_code,
        'body': json.dumps({'error': message}),
        'headers': {'Content-Type': 'application/json'}
    }

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

def parse_boolean_param(param_value, default=False):
    """
    Helper function to consistently parse boolean parameters.
    Returns the default value for None or empty string.
    """
    if param_value is None or param_value == '':
        return default
    if param_value == '0':
        return False
    if param_value == '1':
        return True
    if isinstance(param_value, str) and param_value.lower() == 'true':
        return True
    if isinstance(param_value, str) and param_value.lower() == 'false':
        return False
    return bool(param_value)

def handle_request(event, payload):

    operation = event['httpMethod']

    if operation == 'GET':
        print(f'Input payload: {payload}')
        if "role_id" in payload:
            role_id = payload["role_id"]
            return getone_by_role_id(role_id)

        elif "open_search_document_id" in payload:
            open_search_document_id = payload["open_search_document_id"]
            return getone_by_opensearch_doc_id(open_search_document_id)

        elif "profile_on_xano" in payload:
            profile_on_xano = payload["profile_on_xano"]
            return getone_by_profile_on_xano(profile_on_xano)

        else:
            search_query = payload.get('search_query', '')

            # Ensure nearby_geohash_with_three_digits is a string, default to empty
            nearby_geohash_with_three_digits = payload.get('nearby_geohash_with_three_digits', '')
            if nearby_geohash_with_three_digits is None: # Handle case where it's explicitly null/None
                nearby_geohash_with_three_digits = ''

            # Convert 'only_insured' to boolean
            only_insured = parse_boolean_param(payload.get('only_insured'), default=False)
            print(f"only_insured_raw: {payload.get('only_insured')}, only_insured: {only_insured}")

            # Convert 'minimum_rating' to integer
            try:
                minimum_rating = int(payload.get('minimum_rating', 0))
            except (ValueError, TypeError):
                minimum_rating = 0 # Fallback for invalid int conversion

            # Handle 'languages' (string to list conversion)
            languages_raw = payload.get('languages')
            if languages_raw is None:
                languages = ['en', 'fr', 'es', 'pt'] # Default if not provided
            elif isinstance(languages_raw, str):
                try:
                    parsed_languages = json.loads(languages_raw)
                    if isinstance(parsed_languages, list):
                        languages = parsed_languages
                    else:
                        languages = ['en', 'fr', 'es', 'pt'] # Fallback if parsed but not a list
                except json.JSONDecodeError:
                    languages = ['en', 'fr', 'es', 'pt'] # Fallback if invalid JSON string
            else: # Already a list (e.g., from direct JSON body or other source)
                languages = languages_raw

            # Convert 'max_results_to_bring' to integer
            try:
                max_results_to_bring = int(payload.get('max_results_to_bring', 10))
            except (ValueError, TypeError):
                max_results_to_bring = 10 # Fallback for invalid int conversion

            # Convert 'page' to integer
            try:
                page = int(payload.get('page', 1))
                if page < 1:
                    page = 1
            except (ValueError, TypeError):
                page = 1 # Fallback for invalid int conversion

            # Handle 'only_profile_professionals_id' (string to list conversion)
            only_profile_professionals_id_raw = payload.get('only_profile_professionals_id')
            if only_profile_professionals_id_raw is None:
                only_profile_professionals_id = []
            elif isinstance(only_profile_professionals_id_raw, str):
                try:
                    parsed_ids = json.loads(only_profile_professionals_id_raw)
                    if isinstance(parsed_ids, list):
                        only_profile_professionals_id = [int(id) for id in parsed_ids if str(id).isdigit()]
                    else:
                        only_profile_professionals_id = []
                except (json.JSONDecodeError, ValueError):
                    only_profile_professionals_id = []
            else:  # Already a list
                only_profile_professionals_id = [int(id) for id in only_profile_professionals_id_raw if str(id).isdigit()]

            # Handle 'only_profile_contractors_id' (string to list conversion)
            only_profile_contractors_id_raw = payload.get('only_profile_contractors_id')
            if only_profile_contractors_id_raw is None:
                only_profile_contractors_id = []
            elif isinstance(only_profile_contractors_id_raw, str):
                try:
                    parsed_ids = json.loads(only_profile_contractors_id_raw)
                    if isinstance(parsed_ids, list):
                        only_profile_contractors_id = [int(id) for id in parsed_ids if str(id).isdigit()]
                    else:
                        only_profile_contractors_id = []
                except (json.JSONDecodeError, ValueError):
                    only_profile_contractors_id = []
            else:  # Already a list
                only_profile_contractors_id = [int(id) for id in only_profile_contractors_id_raw if str(id).isdigit()]

            # Convert all boolean parameters using the helper function
            only_contractors = parse_boolean_param(payload.get('only_contractors'), default=False)
            print(f"only_contractors_raw: {payload.get('only_contractors')}, only_contractors: {only_contractors}")

            only_professionals = parse_boolean_param(payload.get('only_professionals'), default=False)
            only_certified = parse_boolean_param(payload.get('only_certified'), default=False)
            only_aboriginal = parse_boolean_param(payload.get('only_aboriginal'), default=False)
            only_disability = parse_boolean_param(payload.get('only_disability'), default=False)
            only_open_to_work = parse_boolean_param(payload.get('only_open_to_work'), default=False)
            only_with_car = parse_boolean_param(payload.get('only_with_car'), default=False)
            only_unionized = parse_boolean_param(payload.get('only_unionized'), default=False)

            # Handle 'country' parameter
            country = payload.get('country', '')
            if country is None:
                country = ''

            return search_professionals_open_to_work(search_query, nearby_geohash_with_three_digits, only_insured, minimum_rating, languages, max_results_to_bring, page, only_profile_professionals_id, only_profile_contractors_id, only_contractors, country, only_professionals, only_certified, only_aboriginal, only_disability, only_open_to_work, only_with_car, only_unionized)

def getone_by_role_id(role_id):
    """Get professional profile from OpenSearch by role_id using two-step process"""
    try:
        if not role_id:
            return create_error_response(400, "role_id is required")

        # Step 1: Get role data from DynamoDB
        role_response = table_roles.query(
            IndexName='role_id-index',
            KeyConditionExpression=Key('role_id').eq(role_id),
            Limit=1
        )

        if not role_response.get('Items'):
            print(f"No role found for role_id: {role_id}")
            return create_error_response(404, "Role not found")

        role_data = role_response['Items'][0]
        xano_user_type = role_data.get('xano_user_type')
        xano_profile_id = role_data.get('xano_profile_id')

        if not xano_user_type or not xano_profile_id:
            print(f"Missing xano_user_type or xano_profile_id for role_id: {role_id}")
            return create_error_response(404, "Invalid role data")

        # Step 2: Construct OpenSearch document ID and get professional
        open_search_document_id = f"{xano_user_type}_{xano_profile_id}"

        return getone_by_opensearch_doc_id(open_search_document_id)

    except Exception as e:
        print(f"Error getting professional by role_id {role_id}: {e}")
        traceback.print_exc()
        return create_error_response(500, "Error retrieving professional")

def getone_by_opensearch_doc_id(opensearch_doc_id):
    """
    Retrieves a single professional document from OpenSearch by its document ID.
    """
    print(f"[DEBUG] Initializing get professional from open search ...")

    if not opensearch_doc_id:
            return create_error_response(400, "Document ID is required")

    if not auth:
        return create_error_response(500, "OpenSearch authentication not available")

    print(f"[DEBUG] Initializing get professional from open search ...")
    url = f"{OPENSEARCH_ENDPOINT}/{OPENSEARCH_INDEX}/_doc/{opensearch_doc_id}"

    try:
        response = requests.get(url, auth=auth, headers=headers)
        response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)

        json_response = response.json()
        print(f"[DEBUG] OpenSearch response for doc ID {opensearch_doc_id}: {json_response}")

        if not json_response.get('found', False):
            return create_error_response(404, "Professional not found")

        # Safely access the 'doc' inside '_source'
        doc = json_response.get('_source', {})
        print(f"[DEBUG] OpenSearch doc: {doc}")
        if not doc:
            return create_error_response(404, "Professional document is empty")

        role_id_on_dynamo = doc['doc']['role_id_on_dynamo']
        print(f'[DEBUG] Role id on dynamo: {role_id_on_dynamo}')

        # Calculate currently_insured and currently_certified for single document retrieval
        professional = doc.get('doc', {})
        today = date.today().isoformat()

        # Check insurance
        insurance_info = professional.get('insurance_info', [])
        currently_insured = any(
            insurance.get('soft_delete') == False and
            insurance.get('valid_from') and insurance.get('valid_to') and
            insurance['valid_from'] <= today and
            insurance['valid_to'] >= today
            for insurance in insurance_info
        )

        # Check certification
        certifications_list = professional.get('certifications_list', [])
        currently_certified = any(
            cert.get('soft_delete') == False and
            cert.get('certification_issue_date') and
            cert['certification_issue_date'] <= today and
            (
                cert.get('certification_expire_date') is None or
                cert['certification_expire_date'] >= today
            )
            for cert in certifications_list
        )

        # Get reviews details
        reviews_details = get_reviews_for_professional(role_id_on_dynamo)

        # Add currently_insured, currently_certified, and reviews_details to the professional.doc
        doc['doc']['currently_insured'] = currently_insured
        doc['doc']['currently_certified'] = currently_certified
        doc['doc']['reviews_details'] = reviews_details

        return {
            'statusCode': 200,
            'body': json.dumps({
                'professional': doc
            })
        }

        # # Append reviews to doc
        # doc['reviews_details'] = reviews_details

        # return {
        #     'statusCode': 200,
        #     'body': json.dumps(doc),
        #     'headers': {'Content-Type': 'application/json'}
        # }

    except requests.exceptions.RequestException as e:
        print(f"Request error getting professional from OpenSearch: {e}")
        return create_error_response(500, f"Request error: {str(e)}")
    except json.JSONDecodeError as e:
        print(f"JSON decoding error in OpenSearch response: {e}")
        return create_error_response(500, f"JSON decoding error: {str(e)}")
    except Exception as e:
        print(f"Unexpected error getting professional from OpenSearch: {e}")
        traceback.print_exc()
        return create_error_response(500, "Error retrieving professional")

def get_reviews_for_professional(role_id_on_dynamo):
    """Get reviews for a professional by role ID"""
    reviews_details = []

    if not role_id_on_dynamo:
        print("[DEBUG] No role ID provided. Returning empty reviews list.")
        return reviews_details

    try:
        reviews_response = table_reviews.query(
            IndexName='reviewed-index',
            KeyConditionExpression=Key('reviewed').eq(role_id_on_dynamo)
        )

        reviews = reviews_response.get('Items', [])
        print(f"[DEBUG] Found {len(reviews)} reviews for professional {role_id_on_dynamo}")

        for review in reviews:
            review_details = {
                'created_at': review.get('updated_at'),
                'reviewer': review.get('reviewer'),
                'overall_rating_string': str(review.get('overall_rating_string')),
                'comments': review.get('comments')
            }

            # Optionally enrich with reviewer details
            reviewer_id = review_details['reviewer']
            if reviewer_id:
                reviewer_details = get_reviewer_details(reviewer_id)
                if reviewer_details:
                    review_details['reviewer_details'] = reviewer_details

            reviews_details.append(review_details)

    except Exception as e:
        print(f"[ERROR] Failed to get reviews for professional {role_id_on_dynamo}: {e}")

    print(f"[DEBUG] Final reviews details for {role_id_on_dynamo}: {reviews_details}")
    return reviews_details

def get_reviewer_details(reviewer):
    """Get reviewer details"""
    try:
        reviewer_response = table_roles.query(
            IndexName='role_id-index',
            KeyConditionExpression=Key('role_id').eq(reviewer),
            Limit=1
        )

        if not reviewer_response.get('Items'):
            return None

        reviewer_profile = reviewer_response['Items'][0]
        print(f"[DEBUG] Reviewer profile: {reviewer_profile}")

        if not reviewer_profile:
            return None

        return {
            'name': reviewer_profile.get('name'),
            'location': reviewer_profile.get('location'),
            'joined_on': reviewer_profile.get('created_at'),
            'profile_picture_url': reviewer_profile.get('profile_picture_url', '')
        }

    except Exception as e:
        print(f"Error getting reviewer details for {reviewer}: {e}")
        return None

def getone_by_profile_on_xano(profile_on_xano):
    """Get professional profile from OpenSearch by profile_on_xano using two-step process"""
    try:
        # Step 1: Get role data from DynamoDB using profile_on_xano-index
        role_response = table_roles.query(
            IndexName='profile_on_xano-index',
            KeyConditionExpression=Key('profile_on_xano').eq(profile_on_xano),
            Limit=1
        )

        if not role_response.get('Items'):
            print(f"No role found for profile_on_xano: {profile_on_xano}")
            return None

        role_data = role_response['Items'][0]
        xano_user_type = role_data.get('xano_user_type')
        xano_profile_id = role_data.get('xano_profile_id')

        if not xano_user_type or not xano_profile_id:
            print(f"Missing xano_user_type or xano_profile_id for profile_on_xano: {profile_on_xano}")
            return None

        # Step 2: Construct OpenSearch document ID
        opensearch_doc_id = f"{xano_user_type}_{xano_profile_id}"
        print(f"[DEBUG] Looking for professional with document ID: {opensearch_doc_id}")

        # Step 3: Get professional from OpenSearch
        return getone_by_opensearch_doc_id(opensearch_doc_id)

    except Exception as e:
        print(f"Error getting professional by profile_on_xano {profile_on_xano}: {e}")
        return None

def query_opensearch(opensearch_payload, include_total=False):
    """
    Queries OpenSearch with a given payload and returns the raw search hits array.

    Args:
        payload (dict): The OpenSearch query body.
        include_total (bool): Whether to include the total count in the response.

    Returns:
        dict: A dictionary containing 'hits' (list of raw hit dictionaries) and optionally 'total' (int),
              or an error dictionary if the query fails.
    """
    print(f"[DEBUG] Initializing OpenSearch query with payload: {json.dumps(opensearch_payload)}")
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
        response = requests.post(url, auth=auth, headers=headers, json=opensearch_payload, timeout=REQUEST_TIMEOUT)
        response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)

        json_response = response.json()
        print(f"[DEBUG] OpenSearch query response: {json.dumps(json_response, indent=2)}")

        # Return the raw 'hits' array, which includes '_score' and 'highlight'
        hits = json_response.get('hits', {}).get('hits', [])
        print(f"[DEBUG] Found {len(hits)} raw hits.")

        if include_total:
            total = json_response.get('hits', {}).get('total', {}).get('value', 0)
            return {'hits': hits, 'total': total}

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

def search_professionals_open_to_work(search_query, nearby_geohash_with_three_digits, only_insured, minimum_rating, languages, max_results_to_bring, page, only_profile_professionals_id, only_profile_contractors_id, only_contractors, country, only_professionals, only_certified, only_aboriginal, only_disability, only_open_to_work, only_with_car, only_unionized):
    """Search for professionals who are open to work with pagination"""

    print('[DEBUG INFO] Finding matching professionals using OpenSearch approach...')

    # Calculate offset based on page
    offset = (page - 1) * max_results_to_bring

    # Start with the base query
    opensearch_payload = {
        "explain": False,
        "query": {
            "bool": {
                "must": [
                    {
                        "term": {
                            "doc.soft_delete": False
                        }
                    },
                    {
                        "range": {
                            "doc.profile_completion": {
                                "gt": 0
                            }
                        }
                    }
                ],
                "should": [],
                "filter": [],
                "must_not": [
                    {
                        "term": {
                            "_id": "Contractor_139"
                        }
                    }
                ]
            }
        },
        "size": max_results_to_bring,
        "from": offset,
        "track_total_hits": True
    }

    # Add sorting logic based on the search_query
    if search_query != '':
        # Now you can use the proper language-specific analyzers!
        opensearch_payload["query"]["bool"]["should"].extend([
            {
                # English fields with English analyzer
                "multi_match": {
                    "query": search_query,
                    "type": "most_fields",
                    "tie_breaker": 0.0,
                    "fields": [
                        "doc.trades_and_skills",
                        "doc.profile_experience.en",
                        "doc.projects_themes_list.en",
                        "doc.portfolio.category_name_en",
                        "doc.portfolio.category_description_en",
                        "doc.unions"
                    ]
                }
            },
            {
                # Spanish fields with Spanish analyzer
                "multi_match": {
                    "query": search_query,
                    "type": "most_fields",
                    "tie_breaker": 0.0,
                    "fields": [
                        "doc.trades_and_skills",
                        "doc.profile_experience.es",
                        "doc.projects_themes_list.es",
                        "doc.portfolio.category_name_es",
                        "doc.portfolio.category_description_es",
                        "doc.unions"
                    ]
                }
            },
            {
                # French fields with French analyzer
                "multi_match": {
                    "query": search_query,
                    "type": "most_fields",
                    "tie_breaker": 0.0,
                    "fields": [
                        "doc.trades_and_skills",
                        "doc.profile_experience.fr",
                        "doc.projects_themes_list.fr",
                        "doc.portfolio.category_name_fr",
                        "doc.portfolio.category_description_fr",
                        "doc.unions"
                    ]
                }
            },
            {
                # Portuguese fields with Portuguese analyzer
                "multi_match": {
                    "query": search_query,
                    "type": "most_fields",
                    "tie_breaker": 0.0,
                    "fields": [
                        "doc.trades_and_skills",
                        "doc.profile_experience.pt",
                        "doc.projects_themes_list.pt",
                        "doc.portfolio.category_name_pt",
                        "doc.portfolio.category_description_pt",
                        "doc.unions"
                    ]
                }
            },
            {
                # Standard fields for names, addresses
                "multi_match": {
                    "query": search_query,
                    "type": "most_fields",
                    "tie_breaker": 0.0,
                    "fields": [
                        "doc.name^0.1",
                        "doc.address"
                    ]
                }
            }
        ])
        opensearch_payload["query"]["bool"]["minimum_should_match"] = 1

        # Sort by relevance score, then by profile completion
        opensearch_payload["sort"] = [
            {
                "_score": {
                    "order": "desc"
                }
            },
            {
                "doc.profile_completion": {
                    "order": "desc"
                }
            }
        ]
    else:
        # If no search query, sort only by profile completion
        opensearch_payload["sort"] = [
            {
                "doc.profile_completion": {
                    "order": "desc"
                }
            }
        ]

    # Handle only_open_to_work logic
    if only_open_to_work:
        # If True, filter to only include professionals open to work
        opensearch_payload["query"]["bool"]["must"].append({
            "term": {
                "doc.open_to_work": True
            }
        })
    else:
        # If False, sort to show open_to_work=True first, then False
        opensearch_payload["sort"].insert(0, {
            "doc.open_to_work": {
                "order": "desc"  # true comes before false
            }
        })

    if nearby_geohash_with_three_digits != '':
        opensearch_payload["query"]["bool"]["filter"].append({
            "prefix": {
                "doc.geohash": nearby_geohash_with_three_digits
            }
        })

    if only_insured:  # checks if the field exists and is not empty
        opensearch_payload["query"]["bool"]["must"].append({
            "exists": {
                "field": "doc.insurance_info"
            }
        })

    if minimum_rating > 0:
        opensearch_payload["query"]["bool"]["must"].append({
            "range": {
                "doc.pro_rate": {
                    "gte": minimum_rating
                }
            }
        })

    if languages != "[]" and len(languages) > 0:
        opensearch_payload["query"]["bool"]["must"].append({
                "terms": {
                    "doc.language": languages
                }
            })

    # Add profile ID filtering if provided
    if (only_profile_professionals_id and len(only_profile_professionals_id) > 0) or (only_profile_contractors_id and len(only_profile_contractors_id) > 0):
        profile_filter = {
            "bool": {
                "should": [],
                "minimum_should_match": 1
            }
        }

        if only_profile_professionals_id and len(only_profile_professionals_id) > 0:
            profile_filter["bool"]["should"].append({
                "terms": {
                    "doc.profile_professionals_id": only_profile_professionals_id
                }
            })

        if only_profile_contractors_id and len(only_profile_contractors_id) > 0:
            profile_filter["bool"]["should"].append({
                "terms": {
                    "doc.profile_contractors_id": only_profile_contractors_id
                }
            })

        opensearch_payload["query"]["bool"]["must"].append(profile_filter)

    # Add only_contractors filter if true
    if only_contractors:
        opensearch_payload["query"]["bool"]["must"].append({
            "range": {
                "doc.profile_contractors_id": {
                    "gt": 0
                }
            }
        })

    # Add only_professionals filter if true
    if only_professionals:
        opensearch_payload["query"]["bool"]["must"].append({
            "range": {
                "doc.profile_professionals_id": {
                    "gt": 0
                }
            }
        })

    # Add only_certified filter if true
    if only_certified:
        opensearch_payload["query"]["bool"]["must"].append({
            "exists": {
                "field": "doc.certifications_list"
            }
        })

    # Add only_aboriginal filter if true
    if only_aboriginal:
        opensearch_payload["query"]["bool"]["must"].append({
            "term": {
                "doc.aboriginal": True
            }
        })

    # Add only_disability filter if true
    if only_disability:
        opensearch_payload["query"]["bool"]["must"].append({
            "term": {
                "doc.disability": True
            }
        })

    # Add only_with_car filter if true
    if only_with_car:
        opensearch_payload["query"]["bool"]["must"].append({
            "term": {
                "doc.has_car": True
            }
        })

    # Add only_unionized filter if true
    if only_unionized:
        opensearch_payload["query"]["bool"]["must"].append({
            "exists": {
                "field": "doc.unions"
            }
        })

    # Add country filter if provided and not "all"
    if country and country != '' and country.lower() != 'all':
        # Try both with and without .keyword suffix to handle different field mappings
        opensearch_payload["query"]["bool"]["must"].append({
            "bool": {
                "should": [
                    {
                        "term": {
                            "doc.country": country
                        }
                    },
                    {
                        "term": {
                            "doc.country.keyword": country
                        }
                    }
                ],
                "minimum_should_match": 1
            }
        })

    print(f"[DEBUG] OpenSearch payload: {json.dumps(opensearch_payload, indent=2)}")

    # Execute OpenSearch query with total count
    print('[DEBUG] Executing OpenSearch query...')
    response_data = query_opensearch(opensearch_payload, include_total=True)

    # Check for errors from OpenSearch
    if isinstance(response_data, dict) and 'statusCode' in response_data:
        print(f"[ERROR] OpenSearch query failed: {response_data}")
        return response_data

    # Extract hits and total
    try:
        if isinstance(response_data, dict):
            response_hits = response_data.get('hits', [])
            total = response_data.get('total', 0)
        else:
            response_hits = response_data  # Fallback if it's just the hits list
            total = len(response_hits)

        print(f"[DEBUG] Successfully extracted {len(response_hits)} hits, total: {total}")

    except Exception as e:
        print(f"[ERROR] Failed to extract hits from response: {e}")
        return create_error_response(500, f"Error processing OpenSearch response: {str(e)}")

    # Process hits with the missing logic - ALWAYS calculate currently_insured and currently_certified
    matching_professionals = []

    for i, hit in enumerate(response_hits):
        professional = hit.get('_source', {}).get('doc')
        if not professional:
            print(f"[WARNING] No 'doc' found in hit {i}, skipping")
            continue

        # Get OpenSearch score for relevance
        opensearch_score = hit.get('_score') or 0.0
        today = date.today().isoformat()  # e.g., '2025-07-10'

        # # Get distance from sort results if available (from geo_distance sort)
        # distance_meters = None
        # if 'sort' in hit and len(hit['sort']) > 0:
        #     distance_meters = hit['sort'][0]

        # Check insurance - ALWAYS calculate this field
        insurance_info = professional.get('insurance_info', [])
        currently_insured = any(
            insurance.get('soft_delete') == False and
            insurance.get('valid_from') and insurance.get('valid_to') and
            insurance['valid_from'] <= today and
            insurance['valid_to'] >= today
            for insurance in insurance_info
        )

        # Apply only_insured filter if requested
        if only_insured and not currently_insured:
            print(f"[DEBUG] Skipping professional {professional.get('name', 'unknown')} because not currently insured")
            continue

        # Check certification - ALWAYS calculate this field
        certifications_list = professional.get('certifications_list', [])
        currently_certified = any(
            cert.get('soft_delete') == False and
            cert.get('certification_issue_date') and
            cert['certification_issue_date'] <= today and
            (
                cert.get('certification_expire_date') is None or
                cert['certification_expire_date'] >= today
            )
            for cert in certifications_list
        )

        # Get reviews for this professional
        role_id_on_dynamo = professional.get('role_id_on_dynamo')
        if role_id_on_dynamo:
            try:
                reviews_details = get_reviews_for_professional(role_id_on_dynamo)
                print(f"[DEBUG] Got {len(reviews_details)} reviews for professional {i+1}")
            except Exception as review_error:
                print(f"[ERROR] Failed to get reviews: {review_error}")
                reviews_details = []
        else:
            reviews_details = []

        # Build and append result - ALWAYS include currently_insured and currently_certified
        matching_professionals.append({
            'opensearch_score': opensearch_score,
            'profile_completion': professional.get('profile_completion', 0),
            'name': professional.get('name', ''),
            'city': professional.get('city', ''),
            'state': professional.get('state', ''),
            'country': professional.get('country', ''),
            'profile_on_xano': professional.get('profile_on_xano', ''),
            'role_id_on_dynamo': professional.get('role_id_on_dynamo', ''),
            'trades_list': professional.get('trades_list', []),
            'projects_themes_list': professional.get('projects_themes_list', []),
            'pro_rate': professional.get('pro_rate', 0.0),
            'reviews_received': professional.get('reviews_received', 0),
            'profile_experience': professional.get('profile_experience', ''),
            'open_to_work': professional.get('open_to_work'),
            'currently_insured': currently_insured,  # ALWAYS included
            'currently_certified': currently_certified,  # ALWAYS included
            'profile_image_complete_path': professional.get('profile_image_complete_path', ''),
            'reviews_details': reviews_details,  # Add the reviews details
            'unions': professional.get('unions', [])
        })

    print(f"[DEBUG] Successfully processed {len(matching_professionals)} professionals")

    print(f"[DEBUG] Items for output: {matching_professionals}")

    # Create final response in the format: response.result.items
    try:
        response_body = {
            'items': matching_professionals,
            'total': total,
            'page': page,
            'max_results_to_bring': max_results_to_bring,
            'has_more': total > (page * max_results_to_bring)
        }

        return {
            'statusCode': 200,
            'body': json.dumps(response_body, default=str),
            'headers': {'Content-Type': 'application/json'}
        }

    except Exception as response_error:
        print(f"[ERROR] Failed to create response: {response_error}")
        traceback.print_exc()
        return create_error_response(500, f"Error creating response: {str(response_error)}")