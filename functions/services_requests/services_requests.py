import json

def create_error_response(status_code, message):
    return {
        'statusCode': status_code,
        'body': json.dumps({'error': message}),
        'headers': {'Content-Type': 'application/json'}
    }

def lambda_handler(event, context):
    try:
        operation = event.get('httpMethod')
        if operation == 'GET':
            payload = event.get('queryStringParameters') or {}
        else:
            body = event.get('body', '{}')
            if body is None:
                body = '{}'
            payload = json.loads(body)

        branch = payload.get('branch', 'v1')
        print(f"[INFO] Routing to branch: {branch}, operation: {operation}")
        branch_module_name = branch.replace('.', '_')

        try:
            branch_module = __import__(f'branches.{branch_module_name}', fromlist=['handle_request'])
        except ImportError:
            print(f"[WARN] Branch '{branch}' not found, falling back to 'v1'")
            branch_module = __import__('branches.v1', fromlist=['handle_request'])

        return branch_module.handle_request(event, payload)
    except json.JSONDecodeError as e:
        return create_error_response(400, 'Invalid JSON in request body')
    except Exception as e:
        import traceback
        traceback.print_exc()
        return create_error_response(500, "Internal server error")
