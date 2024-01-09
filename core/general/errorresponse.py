import json

def error_response(message, status_code=500):
    """
    Creates a standardized error response.

    Args:
    message (str): A descriptive error message.
    status_code (int, optional): The HTTP status code associated with the error. 
                                 Defaults to 500 (Internal Server Error).

    Returns:
    dict: A dictionary containing the status code and a JSON-encoded body with the error message.
    """
    return {
        'statusCode': status_code,
        'body': json.dumps({'error': message})
    }
