import json
import boto3
from boto3.dynamodb.conditions import Attr, Key
from datetime import datetime, timedelta
import os


# LOADING DATABASE RESOURCES
print('Loading function')
dynamo = boto3.client('dynamodb')
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(os.environ.get('table_name'))
index1 = 'pending_profile_ref-shift_id-index'
index2 = 'accepted_profile_ref-shift_id-index'


# AUXILIAR FUNCTIONS
def respond(err, res=None):
    return {
        'statusCode': '400' if err else '200',
        'body': err.message if err else json.dumps(res),
        'headers': {
            'Content-Type': 'application/json',
        },
    }

def get_date_day(string_datetime):
    date = datetime.fromisoformat(string_datetime)
    string_date = date.strftime('%Y-%m-%d')
    return string_date

def get_item(partition_key, sort_key):
    key = {
        'task_id': partition_key,
        'shift_id': sort_key
    }
    response = table.get_item(Key = key)
    return response

def query_all(partition_key, index_name=''):
    if index_name != '':
        response = table.query(
            IndexName=index_name,
            KeyConditionExpression = Key(index_name.split('-')[0]).eq(partition_key)
    )
    else:
        response = table.query(
            KeyConditionExpression = Key('task_id').eq(partition_key)
        )
    response['Items'] = sorted(response['Items'], key=lambda x: x['start_datetime'])
    return response

def query_filter(partition_key, prefix_sort_key='group', attribute_name='', attribute_value='', filter_condition='', index_name=''):
    key_condition_expression = '#pk = :pk AND begins_with(#sk, :sk)'
    if index_name != '':
        if filter_condition != '':

            if filter_condition == 'begins_with':
                filter_expression = 'begins_with(#att, :att)'
            elif filter_condition == 'between':
                value1 = json.loads(attribute_value)[0]
                print(f'value1: {value1}')
                value2 = json.loads(attribute_value)[1]
                print(f'value2: {value2}')
                filter_expression = '#att BETWEEN :att1 AND :att2'
                print(f'filter_expression: {filter_expression}')
            else:
                filter_expression = f'#att {filter_condition} :att'

            expression_attribute_names = {'#pk': index_name.split('-')[0], '#sk': 'shift_id', '#att': attribute_name}

            if filter_condition == 'between':
                expression_attribute_values = {':pk': partition_key, ':sk': prefix_sort_key, ':att1': json.loads(attribute_value)[0], ':att2': json.loads(attribute_value)[1]}
            else:
                expression_attribute_values = {':pk': partition_key, ':sk': prefix_sort_key, ':att': attribute_value}

            response = table.query(
                IndexName=index_name,
                KeyConditionExpression=key_condition_expression,
                FilterExpression = filter_expression,
                ExpressionAttributeNames=expression_attribute_names,
                ExpressionAttributeValues=expression_attribute_values
            )
        else:
            expression_attribute_names = {'#pk': index_name.split('-')[0], '#sk': 'shift_id'}
            expression_attribute_values = {':pk': partition_key, ':sk': prefix_sort_key}
            response = table.query(
                IndexName=index_name,
                KeyConditionExpression=key_condition_expression,
                ExpressionAttributeNames=expression_attribute_names,
                ExpressionAttributeValues=expression_attribute_values
            )
    else:
        if filter_condition != '':

            if filter_condition == 'begins_with':
                filter_expression = 'begins_with(#att, :att)'
            elif filter_condition == 'between':
                value1 = json.loads(attribute_value)[0]
                print(f'value1: {value1}')
                value2 = json.loads(attribute_value)[1]
                print(f'value2: {value2}')
                filter_expression = '#att BETWEEN :att1 AND :att2'
                print(f'filter_expression: {filter_expression}')
            else:
                filter_expression = f'#att {filter_condition} :att'

            expression_attribute_names = {'#pk': 'task_id', '#sk': 'shift_id', '#att': attribute_name}

            if filter_condition == 'between':
                expression_attribute_values = {':pk': partition_key, ':sk': prefix_sort_key, ':att1': json.loads(attribute_value)[0], ':att2': json.loads(attribute_value)[1]}
            else:
                expression_attribute_values = {':pk': partition_key, ':sk': prefix_sort_key, ':att': attribute_value}

            response = table.query(
                KeyConditionExpression=key_condition_expression,
                FilterExpression = filter_expression,
                ExpressionAttributeNames=expression_attribute_names,
                ExpressionAttributeValues=expression_attribute_values
            )
        else:
            expression_attribute_names = {'#pk': 'task_id', '#sk': 'shift_id'}
            expression_attribute_values = {':pk': partition_key, ':sk': prefix_sort_key}
            response = table.query(
                KeyConditionExpression=key_condition_expression,
                ExpressionAttributeNames=expression_attribute_names,
                ExpressionAttributeValues=expression_attribute_values
            )
    response['Items'] = sorted(response['Items'], key=lambda x: x['start_datetime'])
    return response

def update_item(partition_key, sort_key, update_attributes):
    update_expression = 'SET '
    expression_attribute_names = {}
    expression_attribute_values = {}
    for index, (key, value) in enumerate(update_attributes.items()):
        update_expression += f'#attr{index+1}_name = :attr{index+1}_value, '
        expression_attribute_names[f'#attr{index+1}_name'] = key
        expression_attribute_values[f':attr{index+1}_value'] = value
    update_expression = update_expression[:-2]
    response = table.update_item(
        Key={
            'task_id': partition_key,
            'shift_id': sort_key
        },
        UpdateExpression=update_expression,
        ExpressionAttributeNames=expression_attribute_names,
        ExpressionAttributeValues=expression_attribute_values,
        ReturnValues = 'ALL_NEW')
    return response

def generate_time_slots(date_str, slot_size_minutes, initial_time_minutes):
    # Parse the input date
    start_date = datetime.strptime(date_str, "%Y-%m-%d") + timedelta(minutes=initial_time_minutes)


    # Initialize an empty list to store time slots
    time_slots = []

    # Iterate through the day and generate time slots
    while start_date.date() == datetime.strptime(date_str, "%Y-%m-%d").date():
        end_date = start_date + timedelta(minutes=slot_size_minutes)
        time_slots.append({
            "start_datetime": start_date.isoformat() + "+00:00",
            "end_datetime": end_date.isoformat() + "+00:00",
            "available_workers": []
        })
        start_date = end_date

    return time_slots

def generate_time_slots_v2(date_str_utc, slot_size_minutes):
    print(f'Initiate function generate_time_slots_v2')
    # Parse the input date
    start_date = datetime.fromisoformat(date_str_utc)

    # Initialize an empty list to store time slots
    time_slots = []

    # Iterate through the day and generate time slots
    while start_date < datetime.fromisoformat(date_str_utc) + timedelta(days=1):
        end_date = start_date + timedelta(minutes=slot_size_minutes)
        time_slots.append({
            "start_datetime": start_date.isoformat(),
            "end_datetime": end_date.isoformat(),
            "available_workers": []
        })
        start_date = end_date

    print(f'Generated slots: {time_slots}')

    return time_slots

def is_available(shifts, new_shift):
    # Converting date/time strings to datetime objects
    new_start = datetime.fromisoformat(new_shift["start_datetime"])
    new_end = datetime.fromisoformat(new_shift["end_datetime"])

   # Checks if there is an intersection between the new shift and the existing shifts
    for shift in shifts:
        start = datetime.fromisoformat(shift["start_datetime"])
        end = datetime.fromisoformat(shift["end_datetime"])

        if new_start < end and new_end > start:
            return False  # The employee is not available for the new shift

    return True  # The employee is available for the new shift



# MAIN FUNCTION
def handle_request(event, payload):
    """Main entry point for dev branch"""
    try:
        print("Received event: " + json.dumps(event, indent=2))
        operation = event['httpMethod']
        print(f'payload: {payload}')

        # GET Method
        if operation == "GET":
            if 'get_pending_invitations' in payload:
                print('Inside get_pending_invitations')
                profile_ref = payload['profile_ref']
                other_profiles = payload.get('other_profiles', [])

                # Query all shifts with pending invitation of this profile
                all_shifts_pending_invitation = query_all(
                    partition_key=payload['profile_ref'],
                    index_name=index1
                )

                for shift_pending in all_shifts_pending_invitation['Items']:
                    initial_search_datetime = datetime.fromisoformat(shift_pending["start_datetime"]) - timedelta(hours=24)
                    initial_search_datetime_iso = initial_search_datetime.isoformat()
                    end_search_datetime = datetime.fromisoformat(shift_pending["start_datetime"]) + timedelta(hours=24)
                    end_search_datetime_iso = end_search_datetime.isoformat()
                    search_value = json.dumps([initial_search_datetime_iso, end_search_datetime_iso])

                    # Query filtered shifts where main profile is already accepted worker
                    query_response = query_filter(
                        partition_key = payload['profile_ref'],
                        attribute_name = 'start_datetime',
                        attribute_value = search_value,
                        filter_condition = 'between',
                        index_name=index2
                    )
                    shifts_accepted_main_profile = query_response['Items']

                    # Query filtered shifts where other profiles are already accepted workers
                    all_shifts_other_profiles = []
                    for other_profile_ref in other_profiles:
                        query_response = query_filter(
                            partition_key = other_profile_ref,
                            attribute_name = 'start_datetime',
                            attribute_value = search_value,
                            filter_condition = 'between',
                            index_name=index2
                        )
                        all_shifts_other_profiles.extend(query_response['Items'])

                    # Check availability with main profile
                    worker_is_available = is_available(shifts=shifts_accepted_main_profile, new_shift=shift_pending)

                    # Check availability with all other profiles
                    all_other_profiles_available = True
                    if other_profiles:
                        all_other_profiles_available = is_available(shifts=all_shifts_other_profiles, new_shift=shift_pending)

                    shift_pending['schedule_conflict'] = not (worker_is_available and all_other_profiles_available)

                response = all_shifts_pending_invitation


            elif 'pending_profile_ref' in payload:
                response = query_all(
                    partition_key=payload['pending_profile_ref'],
                    index_name=index1
                )
            elif 'accepted_profile_ref' in payload:
                response = query_filter(
                    partition_key = payload['accepted_profile_ref'],
                    prefix_sort_key = payload['prefix_shift_id'],
                    attribute_name = payload['attribute_name'],
                    attribute_value = payload['attribute_value'],
                    filter_condition = payload['filter_condition'],
                    index_name=index2
                )
            elif 'tasks_id_in_batch' in payload:
                batch_response = []
                for i in payload['tasks_id_in_batch']:
                    response = table.query(
                        KeyConditionExpression = Key('task_id').eq(i)
                    )
                    batch_response.extend(response.get('Items', []))
                response = batch_response
            elif 'filter_condition' in payload:
                response = query_filter(
                    partition_key = payload['task_id'],
                    prefix_sort_key = payload['prefix_shift_id'],
                    attribute_name = payload['attribute_name'],
                    attribute_value = payload['attribute_value'],
                    filter_condition = payload['filter_condition']
                )
            elif 'prefix_shift_id' in payload:
                response = query_filter(
                    partition_key = payload['task_id'],
                    prefix_sort_key = payload['prefix_shift_id'],
                )
            elif 'shift_id' in payload:
                response = get_item(payload['task_id'], payload['shift_id'])
            else:
                response = query_all(payload['task_id'])
            return respond(None, response)

        # POST Method
        if operation == "POST":
            if 'shifts_in_batch' in payload:
                with table.batch_writer() as batch:
                    for i in payload['shifts_in_batch']:
                        batch.put_item(Item=i)
                response = 'Successfully written to database'

            elif 'get_availability_by_shifts' in payload:
                print('Inside get_availability_by_shifts')
                batch_response = []
                my_workforce = payload['my_workforce']
                query_response = query_filter(
                    partition_key=payload['task_id'],
                    prefix_sort_key=payload['prefix_shift_id'],
                    attribute_name = 'start_datetime',
                    attribute_value = payload['start_datetime'],
                    filter_condition = '>=',
                )
                print(query_response['Items'])

                if 'only_shifts_without_accepted_profiles' in payload:
                    query_response['Items'] = [
                        item for item in query_response['Items']
                        if (item.get('accepted_profile_ref') == 'null' or item.get('accepted_profile_ref') == None)
                    ]

                for item in query_response['Items']:
                    new_shift = {
                        "task_id": item['task_id'],
                        "shift_id": item['shift_id'],
                        "start_datetime": item['start_datetime'],
                        "end_datetime": item['end_datetime'],
                        "available_workers": []
                    }
                    initial_search_date = f'{item['start_datetime'][0:10]}T00:00:00+00:00'
                    end_search_date = f'{item['end_datetime'][0:10]}T23:59:59+00:00'
                    search_value = json.dumps([initial_search_date, end_search_date])
                    for worker in my_workforce:
                        profile_ref = f'Professional_{worker['worker_professional_id']}' if (worker['worker_professional_id'] != 0) else f'Contractor_{worker['worker_contractor_id']}'
                        other_profiles = worker.get('other_profiles', [])
                        print(f'profile_ref: {profile_ref}, and other_profiles: {other_profiles}')

                        # Query for main profile
                        response = query_filter(
                            partition_key = profile_ref,
                            attribute_name = 'start_datetime',
                            attribute_value = search_value,
                            filter_condition = 'between',
                            index_name=index2
                        )
                        shifts = response['Items']
                        print(f'shifts: {shifts}')

                        # Query for all other profiles
                        all_shifts_other_profiles = []
                        for other_profile_ref in other_profiles:
                            response_other_profile = query_filter(
                                partition_key = other_profile_ref,
                                attribute_name = 'start_datetime',
                                attribute_value = search_value,
                                filter_condition = 'between',
                                index_name=index2
                            )
                            all_shifts_other_profiles.extend(response_other_profile['Items'])
                            print(f'shifts for {other_profile_ref}: {response_other_profile['Items']}')

                        # Check availability with main profile
                        worker_is_available = is_available(shifts=shifts, new_shift=new_shift)

                        # Check availability with all other profiles
                        all_other_profiles_available = True
                        if other_profiles:
                            all_other_profiles_available = is_available(shifts=all_shifts_other_profiles, new_shift=new_shift)

                        if worker_is_available and all_other_profiles_available:
                            new_shift['available_workers'].append(worker)

                    batch_response.append(new_shift)

                # Check if each available worker has already been invited to another conflicted shift
                for item in batch_response:
                    initial_search_date = f'{item['start_datetime'][0:10]}T00:00:00+00:00'
                    end_search_date = f'{item['end_datetime'][0:10]}T23:59:59+00:00'
                    search_value = json.dumps([initial_search_date, end_search_date])
                    for worker in item['available_workers']:
                        profile_ref = f'Professional_{worker['worker_professional_id']}' if (worker['worker_professional_id'] != 0) else f'Contractor_{worker['worker_contractor_id']}'
                        query_pending_profile = query_filter(
                            partition_key = profile_ref,
                            attribute_name = 'start_datetime',
                            attribute_value = search_value,
                            filter_condition = 'between',
                            index_name=index1
                        )
                        shifts = query_pending_profile['Items']
                        worker_is_available = is_available(shifts=shifts, new_shift=item)
                        if worker_is_available == True:
                            worker['has_other_invite'] = False
                        else:
                            worker['has_other_invite'] = True

                # Propagate has_other_invite to other profiles of the same user
                for item in batch_response:
                    for worker in item['available_workers']:
                        if worker.get('has_other_invite') == True:
                            other_profiles = worker.get('other_profiles', [])
                            # Find all workers in available_workers that belong to other_profiles
                            for other_item in batch_response:
                                for other_worker in other_item['available_workers']:
                                    other_profile_ref = f'Professional_{other_worker['worker_professional_id']}' if (other_worker['worker_professional_id'] != 0) else f'Contractor_{other_worker['worker_contractor_id']}'
                                    if other_profile_ref in other_profiles:
                                        other_worker['has_other_invite'] = True

                response = batch_response

            elif 'get_availability' in payload:
                date = datetime.fromisoformat(payload['initial_date'])
                slot_size_minutes = int(payload['slot_size_minutes'])
                my_workforce = payload['my_workforce']
                print(f'Initial datetime: {date}')
                print(f'Initial slot size minutes: {slot_size_minutes}')
                final_response_7days = []
                for day in range(7):
                    final_response = generate_time_slots_v2(
                        date_str_utc=date.isoformat(),
                        slot_size_minutes=slot_size_minutes,
                    )
                    for worker in my_workforce:
                        profile_ref = f'Professional_{worker['worker_professional_id']}' if (worker['worker_professional_id'] != 0) else f'Contractor_{worker['worker_contractor_id']}'
                        other_profiles = worker.get('other_profiles', [])

                        # Query for main profile
                        response = query_filter(
                            partition_key = profile_ref,
                            prefix_sort_key = payload['prefix_shift_id'],
                            attribute_name = payload['attribute_name'],
                            attribute_value = date.strftime("%Y-%m-%d"),
                            filter_condition = payload['filter_condition'],
                            index_name=index2
                        )
                        shifts = response['Items']

                        # Query for all other profiles
                        all_shifts_other_profiles = []
                        for other_profile_ref in other_profiles:
                            response_other_profile = query_filter(
                                partition_key = other_profile_ref,
                                prefix_sort_key = payload['prefix_shift_id'],
                                attribute_name = payload['attribute_name'],
                                attribute_value = date.strftime("%Y-%m-%d"),
                                filter_condition = payload['filter_condition'],
                                index_name=index2
                            )
                            all_shifts_other_profiles.extend(response_other_profile['Items'])

                        for new_shift in final_response:
                            # Check availability with main profile
                            worker_is_available = is_available(shifts=shifts, new_shift=new_shift)

                            # Check availability with all other profiles
                            all_other_profiles_available = True
                            if other_profiles:
                                all_other_profiles_available = is_available(shifts=all_shifts_other_profiles, new_shift=new_shift)

                            if worker_is_available and all_other_profiles_available:
                                new_shift['available_workers'].append(worker)

                    final_response_7days.append(final_response)
                    date = date + timedelta(days=1)
                response = final_response_7days

            else:
                response = table.put_item(Item=payload)

            # start_date = get_date_day(payload['start_datetime'])
            # end_date = get_date_day(payload['end_datetime'])
            # if start_date == end_date:
            #     table2.put_item(
            #         Item={
            #             'profile_ref': payload['profile_ref'],
            #             'calendar_date': start_date,
            #             'start_datetime': payload['start_datetime'],
            #             'end_datetime': payload['end_datetime']
            #         }
            #     )
            # else:
            #     with table2.batch_writer() as batch:
            #         batch.put_item(
            #             Item={
            #                 'profile_ref': payload['profile_ref'],
            #                 'calendar_date': start_date,
            #                 'start_datetime': payload['start_datetime'],
            #                 'end_datetime': payload['start_datetime'].split('T')[0] + 'T23:59:59'
            #             }
            #         )
            #         batch.put_item(
            #             Item={
            #                 'profile_ref': payload['profile_ref'],
            #                 'calendar_date': end_date,
            #                 'start_datetime': payload['end_datetime'].split('T')[0] + 'T00:00:00',
            #                 'end_datetime': payload['end_datetime']
            #             }
            #         )
            return respond(None, response)

        # PUT Method
        if operation == "PUT":
            if 'update_shifts_in_batch' in payload:
                query_response = query_filter(
                    partition_key=payload['task_id'],
                    prefix_sort_key=payload['prefix_shift_id'],
                    attribute_name=payload['attribute_name'],
                    attribute_value=payload['attribute_value'],
                    filter_condition=payload['filter_condition']
                )
                batch_response = []
                for item in query_response['Items']:
                    response = update_item(
                        partition_key = item['task_id'],
                        sort_key = item['shift_id'],
                        update_attributes = payload['update_attributes']
                    )
                    batch_response.extend(response.get('Items', []))
                response = batch_response
            else:
                response = update_item(
                    partition_key = payload['task_id'],
                    sort_key = payload['shift_id'],
                    update_attributes = payload['update_attributes']
                )
            return respond(None, response)

        # DELETE Method
        if operation == "DELETE":
            if 'delete_recurrent_group' in payload:
                query_response = query_filter(
                    partition_key=payload['task_id'],
                    prefix_sort_key=payload['prefix_shift_id'],
                    attribute_name=payload['attribute_name'],
                    attribute_value=payload['attribute_value'],
                    filter_condition=payload['filter_condition']
                )
                with table.batch_writer() as batch:
                    for item in query_response['Items']:
                        batch.delete_item(
                            Key = {
                                'task_id': item['task_id'],
                                'shift_id': item['shift_id']
                            }
                        )
                response = 'Successfully deleted from the database'
            elif 'shifts_in_batch' in payload:
                with table.batch_writer() as batch:
                    for i in payload['shifts_in_batch']:
                        batch.delete_item(
                            Key = {
                                'task_id': i['task_id'],
                                'shift_id': i['shift_id']
                            }
                        )
                response = 'Successfully deleted from the database'
            else:
                response = table.delete_item(
                    Key = {
                        'task_id': payload['task_id'],
                        'shift_id': payload['shift_id']
                    }
                )
            return respond(None, response)



    except Exception as e:
        return respond(None, f'Exception caught: {e}')