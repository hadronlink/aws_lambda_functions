import json
import boto3
import datetime
from decimal import Decimal
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key, Attr
import geohash2

# Number of cards to bring on each call
PAGE_SIZE = 6 

# DynamoDB setup
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('perks')

def lambda_handler(event, context):
    operation = event['httpMethod']
    payload = event.get('queryStringParameters') if operation == 'GET' else {}
    if event.get('body'):
        payload = json.loads(event['body'])
    
    print(f'[DEBUG] Operation: {operation}, Payload: {payload}')

    try:
        if operation == 'PUT':
            return update_item(payload)
        elif operation == 'POST':
            return create_item(payload)
        elif operation == 'GET':
            return handle_get(payload)
        else:
            return {'statusCode': 400, 'body': json.dumps({'error': 'Invalid HTTP method'})}
    except Exception as e:
        print(f'[ERROR] Unhandled exception: {str(e)}')
        return {'statusCode': 500, 'body': json.dumps({'error': str(e)})}

def create_item(payload):
    print('[DEBUG INFO] Creating item...')
    try:
        # Convert numeric values to Decimal for DynamoDB
        item = {
            'perk_id': payload['perk_id'],
            'created_at': format_timestamp(payload.get('created_at')),
            'updated_at': format_timestamp(payload.get('created_at')),
            'only_for_pros': payload['only_for_pros'],
            'start_date': payload['start_date'],
            'end_date': payload['end_date'],
            'soft_delete': 'False',  # String type to match your existing data
            'main_card_picture_complete_google_name': payload['main_card_picture_complete_google_name'],
            'detail_page_picture_complete_google_name': payload['detail_page_picture_complete_google_name'],
            'title': payload['title'],
            'description': payload['description'],
            'external_url': payload['external_url'],
            'latitude': Decimal(str(payload['latitude'])),  # Convert to Decimal
            'longitude': Decimal(str(payload['longitude'])),  # Convert to Decimal
            'geohash': payload['geohash'], 
            'geohash_precision': payload['geohash_precision'],
            'geohash_reference': payload['geohash_reference'], 
            'maximum_distance': payload['maximum_distance'], 
            'advertiser_name': payload['advertiser_name'], 
            'advertiser_contact_person': payload['advertiser_contact_person'], 
            'advertiser_email': payload['advertiser_email'], 
            'advertiser_phone': payload['advertiser_phone'], 
            'advertiser_details': payload['advertiser_details'], 
            'visualizations_count': 0, 
            'main_card_clicks_count': 0, 
            'external_url_clicks_count': 0,
            'visualizations_events': [],
            'main_card_clicks_events': [],
            'external_url_clicks_events': [] 
        }
        table.put_item(Item=item)
        return {'statusCode': 201, 'body': json.dumps({'message': 'Perk created successfully'})}
    except KeyError as e:
        return {'statusCode': 400, 'body': json.dumps({'error': f'Missing required field: {str(e)}'})}
    except Exception as e:
        print(f'[ERROR] Exception in create_item: {str(e)}')
        return {'statusCode': 500, 'body': json.dumps({'error': str(e)})}

def handle_get(payload):    
    print('[DEBUG INFO] Routing GET request...')
    try:
        if 'perk_id' in payload:
            return get_one(payload['perk_id'])
        elif 'is_bigquery' in payload and payload['is_bigquery'] == True:
            return get_all_from_bigquery()
        else:
            return get_all(payload)
    except Exception as e:
        print(f'[ERROR] Exception in handle_get: {str(e)}')
        return {'statusCode': 500, 'body': json.dumps({'error': str(e)})}

def get_one(perk_id):
    print('[DEBUG INFO] Getting single perk...')
    try:
        response = table.get_item(Key={'perk_id': perk_id})
        if 'Item' in response:
            return {'statusCode': 200, 'body': json.dumps(response['Item'], default=dynamo_json_serializer)}
        return {'statusCode': 404, 'body': json.dumps({'error': 'Perk not found'})}
    except Exception as e:
        return {'statusCode': 500, 'body': json.dumps({'error': str(e)})}

def get_all_from_bigquery():
    """
    Retrieves ALL perks without any filtering (for BigQuery export/data analysis).
    Returns ALL perks including deleted ones.
    """
    print('[DEBUG INFO] Executing get_all_from_bigquery function...')

    try:
        response = table.scan()
        items = response.get('Items', [])
        print(f"[DEBUG] Retrieved {len(items)} total perks")

        return {
            'statusCode': 200,
            'body': json.dumps({
                'perks': items,
                'count': len(items)
            }, default=dynamo_json_serializer)
        }

    except ClientError as e:
        print(f"[ERROR] DynamoDB error: {e.response['Error']['Message']}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': f"Database error: {e.response['Error']['Message']}"})
        }
    except Exception as e:
        import traceback
        print('[ERROR] Unexpected exception in get_all_from_bigquery:')
        print(traceback.format_exc())
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Internal server error'})
        }

def get_all(payload):
    """
    Retrieves and filters active perks based on date, user type, and geohash.

    Optimizations:
    1. Simplified filter expression building
    2. Early validation of required parameters
    3. Extracted helper functions for better readability
    4. Uses Attr() for cleaner filter expressions
    5. Proper boolean handling for DynamoDB
    """
    print('[DEBUG INFO] Initializing get_all function...')
    
    # Validate required parameters
    today = payload.get('today')
    if not today:
        return {
            'statusCode': 400, 
            'body': json.dumps({'error': 'Missing required parameter: today'})
        }
    
    try:
        # Parse user pro status
        user_is_pro = parse_boolean(payload.get('user_is_a_pro', False))
        print(f"[DEBUG] User is pro: {user_is_pro}")
        
        # Get user's geohash and coordinates
        user_geohash = parse_geohash_from_payload(payload)
        user_lat = float(payload.get('latitude', 0))
        user_lon = float(payload.get('longitude', 0))
        print(f"[DEBUG] User geohash: {user_geohash}")
        print(f"[DEBUG] User location: {user_lat}, {user_lon}")
        print(f"[DEBUG] Today's date: {today}")
        
        # Build filter expression using boto3.dynamodb.conditions
        # Date range filter (always applied)
        filter_expr = Attr('start_date').lte(today) & Attr('end_date').gte(today)
        
        # Access control: if user is NOT pro, only show perks available to all
        if not user_is_pro:
            filter_expr = filter_expr & Attr('only_for_pros').eq(False)
        # If user IS pro, they can see ALL perks (no additional filter needed)
        
        print(f"[DEBUG] Filter expression built for pro={user_is_pro}")
        
        # Handle pagination
        exclusive_start_key = None
        lek_param = payload.get('last_evaluated_key')
        if lek_param:
            try:
                exclusive_start_key = json.loads(lek_param)
                if not exclusive_start_key:
                    exclusive_start_key = None
            except json.JSONDecodeError:
                print('[WARN] Invalid last_evaluated_key format')
                exclusive_start_key = None
        
        # Build query parameters
        query_params = {
            'IndexName': 'soft_delete-index',
            'KeyConditionExpression': Key('soft_delete').eq('False'),
            'FilterExpression': filter_expr,
            'Limit': PAGE_SIZE
        }
        
        if exclusive_start_key:
            query_params['ExclusiveStartKey'] = exclusive_start_key
        
        # Execute query
        print('[DEBUG] Executing DynamoDB query...')
        response = table.query(**query_params)
        items = response.get('Items', [])
        print(f"[DEBUG] Retrieved {len(items)} items from DynamoDB")
        
        # Debug: Print first item if available
        if items:
            print(f"[DEBUG] First item dates - start: {items[0].get('start_date')}, end: {items[0].get('end_date')}")
            print(f"[DEBUG] First item geohash_reference: {items[0].get('geohash_reference')}, precision: {items[0].get('geohash_precision')}")
        
        # Apply geohash filtering first (coarse filter)
        geohash_filtered = [
            perk for perk in items 
            if matches_geohash_filter(perk, user_geohash)
        ]
        print(f"[DEBUG] {len(geohash_filtered)} perks match geohash filter")
        
        # Apply precise distance filtering (fine filter)
        matching_perks = [
            perk for perk in geohash_filtered
            if matches_distance_filter(perk, user_lat, user_lon)
        ]
        print(f"[DEBUG] {len(matching_perks)} perks within distance limit")
        
        # Prepare pagination token
        last_key = response.get('LastEvaluatedKey')
        next_token = json.dumps(last_key, default=dynamo_json_serializer) if last_key else None
        
        # Override has_more: if we got fewer results than page size, there's no more
        has_more = bool(next_token) and len(matching_perks) == PAGE_SIZE
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'perks': matching_perks,
                'next_page_token': next_token,
                'has_more': has_more
            }, default=dynamo_json_serializer)
        }
        
    except ValueError as e:
        print(f'[ERROR] Validation error: {str(e)}')
        return {
            'statusCode': 400,
            'body': json.dumps({'error': str(e)})
        }
    except ClientError as e:
        print(f"[ERROR] DynamoDB error: {e.response['Error']['Message']}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': f"Database error: {e.response['Error']['Message']}"})
        }
    except Exception as e:
        import traceback
        print('[ERROR] Unexpected exception in get_all:')
        print(traceback.format_exc())
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Internal server error'})
        }

def update_item(payload):
    print('[DEBUG INFO] Updating item...')
    perk_id = payload.get('perk_id')
    if not perk_id:
        return {'statusCode': 400, 'body': json.dumps({'error': 'Missing perk_id'})}

    try:
        update_parts = ["SET #ua = :ua"]
        attr_names = {"#ua": "updated_at"}
        attr_values = {":ua": format_timestamp()}
        
        updateable_fields = [
            'only_for_pros', 'start_date', 'end_date', 'soft_delete', 
            'main_card_picture_complete_google_name', 'detail_page_picture_complete_google_name',
            'title', 'description', 'external_url', 'latitude', 'longitude', 
            'geohash', 'geohash_precision', 'geohash_reference', 'maximum_distance', 
            'advertiser_name', 'advertiser_contact_person', 'advertiser_email', 
            'advertiser_phone', 'advertiser_details'
        ]

        for idx, field in enumerate(updateable_fields, 1):
            if field in payload:
                attr_names[f"#k{idx}"] = field
                # Convert lat/lon to Decimal for DynamoDB
                value = payload[field]
                if field in ('latitude', 'longitude') and not isinstance(value, Decimal):
                    value = Decimal(str(value))
                attr_values[f":v{idx}"] = value
                update_parts.append(f"#k{idx} = :v{idx}")

        update_expr = "SET " + ", ".join([p.replace("SET ", "") for p in update_parts])
        
        response = table.update_item(
            Key={'perk_id': perk_id},
            UpdateExpression=update_expr,
            ExpressionAttributeNames=attr_names,
            ExpressionAttributeValues=attr_values,
            ReturnValues="UPDATED_NEW"
        )

        return {
            'statusCode': 200, 
            'body': json.dumps({
                'message': 'Perk updated successfully', 
                'updated_attributes': response.get('Attributes')
            }, default=dynamo_json_serializer)
        }
    except ClientError as e:
        print(f"[ERROR] DynamoDB error: {e.response['Error']['Message']}")
        return {'statusCode': 500, 'body': json.dumps({'error': str(e)})}

def dynamo_json_serializer(obj):
    """Helper function to serialize DynamoDB items to JSON"""
    if isinstance(obj, Decimal):
        return int(obj) if obj % 1 == 0 else float(obj)
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    if isinstance(obj, dict) and ('S' in obj or 'N' in obj):
         if 'S' in obj: return obj['S']
         if 'N' in obj: return int(obj['N']) if '.' not in obj['N'] else float(obj['N'])
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")

def format_timestamp(timestamp=None):
    if timestamp:
        return timestamp
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def parse_boolean(value):
    """Safely parse boolean values from various input formats"""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ('true', '1', 'yes')
    if isinstance(value, int):
        return bool(value)
    return False

def parse_geohash_from_payload(payload):
    """Extract or generate geohash from payload"""
    if 'geohash' in payload and payload['geohash']:
        return payload['geohash']
    
    if 'latitude' in payload and 'longitude' in payload:
        try:
            lat = float(payload['latitude'])
            lon = float(payload['longitude'])
            return geohash2.encode(lat, lon)
        except (ValueError, TypeError):
            raise ValueError('Invalid latitude or longitude format')
    
    raise ValueError("Either 'geohash' or both 'latitude' and 'longitude' must be provided")

def matches_geohash_filter(perk, user_geohash):
    """Check if perk matches user's geohash based on precision"""
    try:
        precision = int(perk.get('geohash_precision', 0))
        reference = perk.get('geohash_reference')
        
        if not reference or precision <= 0:
            return False
        
        user_partial = user_geohash[:precision]
        return user_partial == reference
    except (ValueError, TypeError):
        return False

def calculate_distance(lat1, lon1, lat2, lon2):
    """
    Calculate distance between two points using Haversine formula.
    Returns distance in kilometers.
    """
    from math import radians, sin, cos, sqrt, atan2
    
    # Earth's radius in kilometers
    R = 6371.0
    
    # Convert to radians
    lat1_rad = radians(float(lat1))
    lon1_rad = radians(float(lon1))
    lat2_rad = radians(float(lat2))
    lon2_rad = radians(float(lon2))
    
    # Haversine formula
    dlat = lat2_rad - lat1_rad
    dlon = lon2_rad - lon1_rad
    
    a = sin(dlat / 2)**2 + cos(lat1_rad) * cos(lat2_rad) * sin(dlon / 2)**2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))
    
    distance = R * c
    return distance

def matches_distance_filter(perk, user_lat, user_lon):
    """Check if perk is within maximum_distance of user location"""
    try:
        perk_lat = perk.get('latitude')
        perk_lon = perk.get('longitude')
        max_distance = float(perk.get('maximum_distance', 0))
        
        if not perk_lat or not perk_lon or max_distance <= 0:
            return False
        
        distance = calculate_distance(user_lat, user_lon, perk_lat, perk_lon)
        print(f"[DEBUG] Perk '{perk.get('title')}' distance: {distance:.2f}km (max: {max_distance}km)")
        
        return distance <= max_distance
    except (ValueError, TypeError) as e:
        print(f"[DEBUG] Distance calculation error: {e}")
        return False



