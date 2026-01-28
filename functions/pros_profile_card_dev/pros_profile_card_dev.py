import json

def create_error_response(status_code, message):
    """Create a standardized error response"""
    headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'OPTIONS,POST,GET',
        'Content-Type': 'application/json'
    }
    return {
        'statusCode': status_code,
        'body': json.dumps({'error': message}),
        'headers': headers
    }

def lambda_handler(event, context):
    """
    Main router - delegates everything to branch-specific modules.
    """
    headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
    }

    try:
        operation = event.get('httpMethod')

        # Handle CORS preflight
        if operation == 'OPTIONS':
            return {'statusCode': 200, 'headers': headers, 'body': ''}

        # Extract payload
        if operation == 'GET':
            payload = event.get('queryStringParameters') or {}
        elif operation == 'POST':
            body = event.get('body', '{}')
            if body is None:
                body = '{}'
            payload = json.loads(body)
        else:
            payload = event

        # Get branch from payload
        branch = payload.get('branch', 'dev')

        print(f"[INFO] Routing to branch: {branch}, operation: {operation}")

        # Convert dots to underscores for module name (v2.3 -> v2_3)
        branch_module_name = branch.replace('.', '_')

        # Import the correct branch module dynamically
        try:
            branch_module = __import__(f'branches.{branch_module_name}', fromlist=['handle_request'])
        except ImportError:
            print(f"[WARN] Branch '{branch}' not found, falling back to 'dev'")
            branch_module = __import__('branches.dev', fromlist=['handle_request'])

        # Delegate everything to the branch module
        return branch_module.handle_request(event, payload)

    except json.JSONDecodeError as e:
        print(f"[ERROR] JSON decode error: {e}")
        return create_error_response(400, 'Invalid JSON in request body')
    except Exception as e:
        print(f"[ERROR] Router error: {e}")
        import traceback
        traceback.print_exc()
        return create_error_response(500, "Internal server error")
