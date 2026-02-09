import json
import boto3
import datetime
import math
import sys
import os
import re
from decimal import Decimal
from opensearchpy import OpenSearch, RequestsHttpConnection
from aws_requests_auth.aws_auth import AWSRequestsAuth
import traceback
import requests
from requests.auth import HTTPBasicAuth
from datetime import date
from botocore.exceptions import ClientError

# OpenSearch configuration for jobs
OPENSEARCH_ENDPOINT = 'https://search-connecus-home-xter5mxymdzivmnio2iuvwgg4a.us-east-2.es.amazonaws.com'
OPENSEARCH_INDEX = 'jobs_from_xano_live'
AWS_REGION = 'us-east-2'
SECRETS_MANAGER_SECRET_NAME = 'opensearch-credentials'

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

def decode_geohash(geohash_str):
    """Decode a geohash string into (latitude, longitude) center coordinates."""
    base32 = '0123456789bcdefghjkmnpqrstuvwxyz'
    lat_range = [-90.0, 90.0]
    lon_range = [-180.0, 180.0]
    is_lon = True
    for char in geohash_str:
        val = base32.index(char)
        for bit in range(4, -1, -1):
            if is_lon:
                mid = (lon_range[0] + lon_range[1]) / 2
                if val & (1 << bit):
                    lon_range[0] = mid
                else:
                    lon_range[1] = mid
            else:
                mid = (lat_range[0] + lat_range[1]) / 2
                if val & (1 << bit):
                    lat_range[0] = mid
                else:
                    lat_range[1] = mid
            is_lon = not is_lon
    lat = (lat_range[0] + lat_range[1]) / 2
    lon = (lon_range[0] + lon_range[1]) / 2
    return (lat, lon)

def haversine_distance(lat1, lon1, lat2, lon2):
    """Calculate distance between two points in kilometers using Haversine formula."""
    R = 6371.0
    lat1_rad = math.radians(float(lat1))
    lon1_rad = math.radians(float(lon1))
    lat2_rad = math.radians(float(lat2))
    lon2_rad = math.radians(float(lon2))
    dlat = lat2_rad - lat1_rad
    dlon = lon2_rad - lon1_rad
    a = math.sin(dlat / 2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon / 2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c

def query_opensearch(opensearch_payload, include_total=False):
    """
    Queries OpenSearch with a given payload and returns the raw search hits array.
    """
    print(f"[DEBUG] Initializing OpenSearch query with payload: {json.dumps(opensearch_payload)}")
    if not auth:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': "OpenSearch authentication not initialized."})
        }

    url = f"{OPENSEARCH_ENDPOINT}/{OPENSEARCH_INDEX}/_search"
    REQUEST_TIMEOUT = 60  # seconds
    print(f"[DEBUG] Setting OpenSearch request timeout to {REQUEST_TIMEOUT} seconds.")

    try:
        response = requests.post(url, auth=auth, headers=headers, json=opensearch_payload, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()

        json_response = response.json()
        print(f"[DEBUG] OpenSearch query response: {json.dumps(json_response, indent=2)}")

        hits = json_response.get('hits', {}).get('hits', [])
        print(f"[DEBUG] Found {len(hits)} raw hits.")

        if include_total:
            total = json_response.get('hits', {}).get('total', {}).get('value', 0)
            return {'hits': hits, 'total': total}

        return hits

    except requests.exceptions.Timeout:
        print(f"Error: OpenSearch query timed out after {REQUEST_TIMEOUT} seconds.")
        return {
            'statusCode': 504,
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

def search_jobs(search_query, page, only_certified, only_unionized, only_with_car, long_term_job, hourly_pay_min, trade_id, city, trades_on_top, reference_geohash, geohash_precision, max_results_to_bring=60):
    """Search for jobs with pagination and filters"""

    print('[DEBUG INFO] Finding matching jobs using OpenSearch approach...')

    # Calculate offset based on page
    offset = (page - 1) * max_results_to_bring

    # Decode reference location for distance sorting
    ref_lat = None
    ref_lon = None
    if reference_geohash and reference_geohash.strip() != '':
        try:
            ref_lat, ref_lon = decode_geohash(reference_geohash)
            print(f"[DEBUG] Decoded reference_geohash '{reference_geohash}' to lat={ref_lat}, lon={ref_lon}")
        except Exception as e:
            print(f"[WARN] Failed to decode reference_geohash '{reference_geohash}': {e}")

    # When custom sorting is needed, fetch more results from offset 0
    needs_custom_sort = (trades_on_top and len(trades_on_top) > 0) or ref_lat is not None
    if needs_custom_sort:
        fetch_size = max_results_to_bring * 3
        fetch_offset = 0
    else:
        fetch_size = max_results_to_bring
        fetch_offset = offset

    opensearch_payload = {
        "explain": False,
        "query": {
            "bool": {
                "must": [],
                "should": [],
                "filter": []
            }
        },
        "size": fetch_size,
        "from": fetch_offset,
        "track_total_hits": True,
        "sort": [
            {"created_at": {"order": "desc"}}
        ],
        "_source": True
    }

    # Add search query if provided
    if search_query and search_query.strip() != '':
        opensearch_payload["query"]["bool"]["should"].append({
            "multi_match": {
                "query": search_query,
                "fields": [
                    "title",
                    "trades_and_skills",
                    "additional_info",
                    "address",
                    "city",
                    "owner_company_name",
                    "job_trade_name.en",
                    "job_trade_name.fr",
                    "job_trade_name.es",
                    "job_trade_name.pt"
                ]
            }
        })
        # Ensure at least one should clause must match when search query is present
        opensearch_payload["query"]["bool"]["minimum_should_match"] = 1

    # Add only_certified filter if true
    if only_certified:
        opensearch_payload["query"]["bool"]["must"].append({
            "term": {
                "certified": True
            }
        })

    # Add only_unionized filter if true
    if only_unionized:
        opensearch_payload["query"]["bool"]["must"].append({
            "term": {
                "unionized": True
            }
        })

    # Add only_with_car filter if true
    if only_with_car:
        opensearch_payload["query"]["bool"]["must"].append({
            "term": {
                "has_car": True
            }
        })

    # Add long_term_job filter if specified
    if long_term_job is not None:
        opensearch_payload["query"]["bool"]["must"].append({
            "term": {
                "long_term_job": long_term_job
            }
        })

    # Add hourly_pay_min filter if provided
    if hourly_pay_min is not None and hourly_pay_min > 0:
        opensearch_payload["query"]["bool"]["must"].append({
            "range": {
                "hourly_pay_min": {
                    "gte": hourly_pay_min
                }
            }
        })

    # Add trade_id filter if provided
    if trade_id is not None and trade_id > 0:
        opensearch_payload["query"]["bool"]["must"].append({
            "term": {
                "trade_id": trade_id
            }
        })

    # Add city filter if provided and not empty
    if city and city.strip() != '' and city.lower() != 'all':
        opensearch_payload["query"]["bool"]["must"].append({
            "bool": {
                "should": [
                    {
                        "term": {
                            "city": city.upper()
                        }
                    },
                    {
                        "term": {
                            "city.keyword": city.upper()
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
            response_hits = response_data
            total = len(response_hits)

        print(f"[DEBUG] Successfully extracted {len(response_hits)} hits, total: {total}")

    except Exception as e:
        print(f"[ERROR] Failed to extract hits from response: {e}")
        return create_error_response(500, f"Error processing OpenSearch response: {str(e)}")

    # Process hits
    all_jobs = []

    for i, hit in enumerate(response_hits):
        job = hit.get('_source')
        if not job:
            print(f"[WARNING] No '_source' found in hit {i}, skipping")
            continue

        # Get OpenSearch score for relevance
        opensearch_score = hit.get('_score') or 0.0

        # Build job result with ALL fields from the document
        job_result = job.copy()
        job_result['opensearch_score'] = opensearch_score

        all_jobs.append(job_result)

    # Apply custom sorting: trade priority, then distance, then created_at
    if needs_custom_sort:
        print(f"[DEBUG] Applying custom sorting with trades_on_top: {trades_on_top}, ref_lat: {ref_lat}, ref_lon: {ref_lon}")

        def sort_key(job):
            # Trade priority: matching trades first, in order
            job_trade_id = job.get('trade_id')
            if trades_on_top and job_trade_id in trades_on_top:
                priority = trades_on_top.index(job_trade_id)
            else:
                priority = 999

            # Distance from reference point (ascending - nearest first)
            if ref_lat is not None:
                location = job.get('location', {})
                job_lat = location.get('lat')
                job_lon = location.get('lon')
                if job_lat is not None and job_lon is not None:
                    distance = haversine_distance(ref_lat, ref_lon, job_lat, job_lon)
                else:
                    distance = 999999.0
            else:
                distance = 0

            # Created_at descending (newest first)
            created_at = job.get('created_at', 0)
            return (priority, distance, -created_at)

        all_jobs.sort(key=sort_key)
        print(f"[DEBUG] Applied custom sorting to {len(all_jobs)} jobs")

    # Apply pagination after sorting
    start_index = (page - 1) * max_results_to_bring
    end_index = start_index + max_results_to_bring
    matching_jobs = all_jobs[start_index:end_index]

    print(f"[DEBUG] Pagination: showing jobs {start_index + 1}-{min(end_index, len(all_jobs))} of {len(all_jobs)} total")
    print(f"[DEBUG] Successfully processed {len(matching_jobs)} jobs for this page")

    # Create final response
    try:
        if needs_custom_sort:
            response_total = len(all_jobs)
        else:
            response_total = total

        response_body = {
            'items': matching_jobs,
            'total': response_total,
            'page': page,
            'max_results_to_bring': max_results_to_bring,
            'has_more': response_total > (page * max_results_to_bring)
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

def handle_request(event, payload):
    """Main handler function"""
    operation = event['httpMethod']

    if operation == 'GET':
        print(f'Input payload: {payload}')

        # Parse search parameters
        search_query = payload.get('search_query', '')

        # Convert 'page' to integer
        try:
            page = int(payload.get('page', 1))
            if page < 1:
                page = 1
        except (ValueError, TypeError):
            page = 1

        # Convert boolean parameters
        only_certified = parse_boolean_param(payload.get('only_certified'), default=False)
        only_unionized = parse_boolean_param(payload.get('only_unionized'), default=False)
        only_with_car = parse_boolean_param(payload.get('only_with_car'), default=False)

        # Handle long_term_job - can be True, False, or None (no filter)
        long_term_job_param = payload.get('long_term_job')
        if long_term_job_param is None or long_term_job_param == '':
            long_term_job = None  # No filter
        else:
            long_term_job = parse_boolean_param(long_term_job_param)

        # Handle trades_on_top parameter (list of integers)
        trades_on_top_raw = payload.get('trades_on_top')
        if trades_on_top_raw is None:
            trades_on_top = []
        elif isinstance(trades_on_top_raw, str):
            try:
                parsed_trades = json.loads(trades_on_top_raw)
                if isinstance(parsed_trades, list):
                    trades_on_top = [int(trade_id) for trade_id in parsed_trades if str(trade_id).isdigit()]
                else:
                    trades_on_top = []
            except (json.JSONDecodeError, ValueError):
                trades_on_top = []
        else:  # Already a list
            trades_on_top = [int(trade_id) for trade_id in trades_on_top_raw if str(trade_id).isdigit()]

        # Convert trade_id to integer
        trade_id = None
        if payload.get('trade_id'):
            try:
                trade_id = int(payload.get('trade_id'))
            except (ValueError, TypeError):
                trade_id = None

        # Handle city parameter
        city = payload.get('city', '')
        if city is None:
            city = ''

        # Convert hourly_pay_min to decimal
        hourly_pay_min = None
        if payload.get('hourly_pay_min'):
            try:
                hourly_pay_min = float(payload.get('hourly_pay_min'))
            except (ValueError, TypeError):
                hourly_pay_min = None

        # Handle reference_geohash and geohash_precision parameters
        reference_geohash = payload.get('reference_geohash', '')
        if reference_geohash is None:
            reference_geohash = ''

        geohash_precision = None
        if payload.get('geohash_precision'):
            try:
                geohash_precision = int(payload.get('geohash_precision'))
            except (ValueError, TypeError):
                geohash_precision = None

        # Default results per page
        max_results_to_bring = 60

        print(f"[DEBUG] Parsed parameters:")
        print(f"  search_query: '{search_query}'")
        print(f"  page: {page}")
        print(f"  only_certified: {only_certified}")
        print(f"  only_unionized: {only_unionized}")
        print(f"  only_with_car: {only_with_car}")
        print(f"  long_term_job: {long_term_job}")
        print(f"  hourly_pay_min: {hourly_pay_min}")
        print(f"  trade_id: {trade_id}")
        print(f"  city: '{city}'")
        print(f"  trades_on_top: {trades_on_top}")
        print(f"  reference_geohash: '{reference_geohash}'")
        print(f"  geohash_precision: {geohash_precision}")


        return search_jobs(
            search_query=search_query,
            page=page,
            only_certified=only_certified,
            only_unionized=only_unionized,
            only_with_car=only_with_car,
            long_term_job=long_term_job,
            hourly_pay_min=hourly_pay_min,
            trade_id=trade_id,
            city=city,
            trades_on_top=trades_on_top,
            reference_geohash=reference_geohash,
            geohash_precision=geohash_precision,
            max_results_to_bring=max_results_to_bring
        )

    else:
        return create_error_response(405, "Method not allowed")
