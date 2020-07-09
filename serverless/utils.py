import json
import time
import requests
import jwkest
from jwkest.jwk import load_jwks_from_url, load_jwks
from jwkest.jws import JWS
jws = JWS()

def get_timestamp(seconds):
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(seconds))
    except ValueError:
        return "Not Available"

def decode_jwt(token):
    """
    Validate and decode the web token from the Amazon Cognito.
    Stores the public key needed to decrypt the token.
    Returns 
    """
    url="https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json".format(AWS_REGION,USER_POOL_ID)
    try:
        r = requests.get(url)
        logger.debug(r.status_code)
        key_set = load_jwks(r.text)
    except:
        logger.debug(traceback.format_exc())
        return False
    try:
        token_dict = jws.verify_compact(token, keys=key_set)
        logger.info(token_dict)
        if token_dict['exp'] < time.time():
            logger.debug("Token Expired")
            return False
        if token_dict['email_verified']:
            return {"user_id":token_dict['sub'], 
                    "user_email":token_dict['email']}
        else:
            logger.debug("E-mail not verfied.")
            return False
    except:
        logger.debug(traceback.format_exc())
        return False

def lambdaResponse(statusCode,
                   body,
                   headers={},
                   isBase64Encoded=False):
    """
    A utility to wrap the lambda function call returns with the right status code,
    body, and switches.
    """

    # Make sure the body is a json object
    if not isinstance(body, str):
        body = json.dumps(body)
    # Make sure the content type is json
    header = headers
    header['Access-Control-Allow-Headers'] = 'Content-Type'
    header['Access-Control-Allow-Origin'] = '*'
    header['Access-Control-Allow-Methods'] = 'OPTIONS,POST,GET'
    header["Content-Type"] = "application/json"  
    response = {
        "isBase64Encoded": isBase64Encoded,
        "statusCode": statusCode,
        "headers": header,
        "body": body
    }
    return response