import json
import boto3
import datetime
import math
import re
from boto3.dynamodb.conditions import Attr, Key, And, Not, Contains
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('notifications_dev')

def lambda_handler(event, context):
    operation = event['httpMethod']
    payload = event['queryStringParameters'] if operation == 'GET' else json.loads(event['body']) if event.get('body') else {}
    try:
        if operation == 'PUT':
            return update_item(payload)
        elif operation == 'POST':
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
    print('[DEBUG INFO] Creating a new item...')
    try:
        current_time = datetime.datetime.utcnow().isoformat()
        item = {
            'created_at': current_time,
            'updated_at': current_time,
            'notification_id': payload['notification_id'],
            'roles_id': payload['roles_id'],
            'sendgrid_template_id': payload['sendgrid_template_id'],
            'subject_detail': payload['subject_detail'],
            'body_detail': payload['body_detail'],
            'action_author_name': payload['action_author_name']
        }
        table.put_item(Item=item)
        return {
            'statusCode': 201,
            'body': json.dumps({'message': 'Item created successfully'})
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def handle_get(event, payload):
    print('[DEBUG INFO] Handling GET request...')
    try:
        # Check if a specific notification_id is requested
        if 'notification_id' in payload:
            return get_item_by_id(payload['notification_id'])
        
        # Check if we're querying by roles_id
        elif 'roles_id' in payload:
            roles_id = payload.get('roles_id')
            return get_items_by_role(payload['roles_id'])
        
        # Otherwise, return all items with pagination
        else:
            page = int(payload.get('page', 1))
            limit = int(payload.get('limit', 20))
            return get_all_items(page, limit)
    except Exception as e:
        print(f"[ERROR] Exception in handle_get: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def get_item_by_id(notification_id):
    print(f'[DEBUG INFO] Getting item by ID: {notification_id}')
    try:
        response = table.get_item(Key={'notification_id': notification_id})
        item = response.get('Item')
        
        if not item:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Notification not found'})
            }
            
        return {
            'statusCode': 200,
            'body': json.dumps(item, default=str)
        }
    except Exception as e:
        print(f"[ERROR] Exception in get_item_by_id: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def get_items_by_role(roles_id):
    print(f'[DEBUG INFO] Getting items by roles_id: {roles_id}')
    try:
        response = table.query(
            IndexName='roles_id-index',
            KeyConditionExpression=Key('roles_id').eq(roles_id)
        )
        items = response.get('Items', [])
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'count': len(items),
                'items': items
            }, default=str)
        }
    except Exception as e:
        print(f"[ERROR] Exception in get_items_by_role: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def get_all_items(page, limit):
    print(f'[DEBUG INFO] Getting all items (page: {page}, limit: {limit})')
    try:
        scan_kwargs = {
            'Limit': limit
        }
        
        # Calculate ExclusiveStartKey for pagination
        if page > 1:
            # We need to scan until we reach the starting point for the requested page
            # This is a simplified approach - in production, you'd want to use LastEvaluatedKey
            # from previous scans to make pagination more efficient
            start_index = (page - 1) * limit
            count = 0
            last_evaluated_key = None
            
            while count < start_index:
                if last_evaluated_key:
                    scan_kwargs['ExclusiveStartKey'] = last_evaluated_key
                
                temp_response = table.scan(**scan_kwargs)
                count += len(temp_response.get('Items', []))
                last_evaluated_key = temp_response.get('LastEvaluatedKey')
                
                if not last_evaluated_key:
                    break
            
            if last_evaluated_key:
                scan_kwargs['ExclusiveStartKey'] = last_evaluated_key
        
        response = table.scan(**scan_kwargs)
        items = response.get('Items', [])
        
        # Sort by created_at in descending order (newest first)
        items.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        
        # Get total count for pagination info
        count_response = table.scan(Select='COUNT')
        total_items = count_response.get('Count', 0)
        total_pages = math.ceil(total_items / limit)
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'page': page,
                'limit': limit,
                'total_items': total_items,
                'total_pages': total_pages,
                'has_more': page < total_pages,
                'items': items
            }, default=str)
        }
    except Exception as e:
        print(f"[ERROR] Exception in get_all_items: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def update_item(payload):
    print('[DEBUG INFO] Updating an item...')
    try:
        notification_id = payload.get('notification_id')
        if not notification_id:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'notification_id is required'})
            }
            
        # Check if the item exists
        response = table.get_item(Key={'notification_id': notification_id})
        if 'Item' not in response:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Notification not found'})
            }
        
        # Build update expression
        update_expression = "SET updated_at = :updated_at"
        expression_attribute_values = {
            ':updated_at': datetime.datetime.utcnow().isoformat()
        }
        
        # Add other fields to update expression if they exist in payload
        fields_to_update = ['roles_id', 'action_author_name', 'body_detail', 
                           'sendgrid_template_id', 'subject_detail']
        
        for field in fields_to_update:
            if field in payload:
                update_expression += f", {field} = :{field}"
                expression_attribute_values[f':{field}'] = payload[field]
        
        # Perform update
        table.update_item(
            Key={'notification_id': notification_id},
            UpdateExpression=update_expression,
            ExpressionAttributeValues=expression_attribute_values
        )
        
        return {
            'statusCode': 200,
            'body': json.dumps({'message': 'Item updated successfully'})
        }
    except Exception as e:
        print(f"[ERROR] Exception in update_item: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def delete_item(payload):
    print('[DEBUG INFO] Deleting an item...')
    try:
        notification_id = payload.get('notification_id')
        if not notification_id:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'notification_id is required'})
            }
        
        # Check if the item exists
        response = table.get_item(Key={'notification_id': notification_id})
        if 'Item' not in response:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Notification not found'})
            }
        
        # Delete the item
        table.delete_item(Key={'notification_id': notification_id})
        
        return {
            'statusCode': 200,
            'body': json.dumps({'message': 'Item deleted successfully'})
        }
    except Exception as e:
        print(f"[ERROR] Exception in delete_item: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }