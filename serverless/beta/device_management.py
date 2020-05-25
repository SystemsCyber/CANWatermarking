import boto3
from utils import lambdaResponse as response


def list_devices(event, context):
    """
    Read post data to create a new key based on a new device
    """
    # Check Authorization
    # requester_data = event["requestContext"]
    # if requester_data["authorizer"]["claims"]["email_verified"]:
    #     identity_data = event["requestContext"]["identity"]
    #     ip_address = identity_data["sourceIp"]
    #     email = requester_data["authorizer"]["claims"]["email"].lower()
    # else:
    #     return response(400, "Email not verified.")
    # print(email)

    dbClient = boto3.resource('dynamodb', region_name='us-east-1')
    table = dbClient.Table("Devices")

    db_response = table.scan()
    data = db_response['Items']
    while 'LastEvaluatedKey' in db_response:
        db_response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
        data.extend(db_response['Items'])
    # print(data)

    return response(200, data)