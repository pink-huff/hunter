import socket
import re

def is_ip(query):
    """
    Validates if the input string is a valid ip address.
    
    Args:
    domain (str): The ip address to validate.
    
    Returns:
    bool: True if the ip address is valid, False otherwise.
    """
    try:
        socket.inet_aton(query)
        return True
    except socket.error:
        return False

def is_domain(domain):
    """
    Validates if the input string is a valid domain name.
    
    Args:
    domain (str): The domain name to validate.
    
    Returns:
    bool: True if the domain name is valid, False otherwise.
    """

    # Regular expression for validating a domain
    domain_regex = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$"
    )

    # Checking if the domain matches the pattern
    if domain_regex.match(domain):
        return True
    else:
        return False

def is_url(url):
    """
    Validates if the input string is a valid url.
    
    Args:
    url (str): The url to validate.
    
    Returns:
    bool: True if the url is valid, False otherwise.
    """

    # Regular expression for validating a url
    url_regex = re.compile(
        r"^(?:http|ftp)s?://" # http:// or https://
        # domain...
        r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+" # domain name
        r"[a-zA-Z]{2,6}" # first level domain
        r"(?:/?|[/?]\S+)$" # path
    )

    # Checking if the url matches the pattern
    if url_regex.match(url):
        return True
    else:
        return False

def is_email(email):
    """
    Validates if the input string is a valid email address.
    
    Args:
    email (str): The email address to validate.
    
    Returns:
    bool: True if the email address is valid, False otherwise.
    """

    # Regular expression for validating an email address
    email_regex = re.compile(
        r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
    )

    # Checking if the email address matches the pattern
    if email_regex.match(email):
        return True
    else:
        return False