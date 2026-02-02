import json
import boto3
import datetime
from collections import Counter
from boto3.dynamodb.conditions import Key

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('profiles_translations_requisitions_dev')

def handle_request(event, payload):
    """Main entry point for v2_3 branch"""
    operation = event['httpMethod']
    print(f"[DEBUG INFO] Payload: {payload}")
    
    try:
        if operation == 'POST':
            return create_item(payload)
        elif operation == 'GET':
            role_id = payload.get('role_id')
            if not role_id:
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': 'role_id is required'})
                }
            return get_summary_by_role_id(role_id)
        else:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Invalid HTTP method'})
            }
    except Exception as e:
        print(f"[ERROR] {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def create_item(payload):
    current_time = datetime.datetime.utcnow().isoformat()
    item = {
        'created_at': current_time,
        'updated_at': current_time,
        'role_id': payload['role_id'],
        'language': payload['language']
    }
    table.put_item(Item=item)
    return {
        'statusCode': 201,
        'body': json.dumps({'message': 'Item created successfully'})
    }

def get_summary_by_role_id(role_id):
    print(f'[DEBUG INFO] Getting summary by role_id: {role_id}')
    items = []
    
    # Query and handle pagination
    response = table.query(
        KeyConditionExpression=Key("role_id").eq(role_id)
    )
    items.extend(response.get("Items", []))

    while 'LastEvaluatedKey' in response:
        response = table.query(
            KeyConditionExpression=Key("role_id").eq(role_id),
            ExclusiveStartKey=response['LastEvaluatedKey']
        )
        items.extend(response.get("Items", []))

    # Count languages
    languages = [item.get("language") for item in items if "language" in item]
    counts = dict(Counter(languages))

    return {
        "statusCode": 200,
        "body": json.dumps({
            "role_id": role_id,
            "counts": counts
        })
    }
