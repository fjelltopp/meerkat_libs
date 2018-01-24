import logging
import requests
import json
import os
import jwt
from meerkat_libs.auth_client import auth

# Configs from environment variables
HERMES_ROOT = os.environ.get("HERMES_API_ROOT", "")
AUTH_ROOT = os.environ.get('MEERKAT_AUTH_ROOT', 'http://nginx/auth')
SERVER_AUTH_USERNAME = os.environ.get('SERVER_AUTH_USERNAME', 'server')
SERVER_AUTH_PASSWORD = os.environ.get('SERVER_AUTH_PASSWORD', 'password')


def authenticate(username=SERVER_AUTH_USERNAME,
                 password=SERVER_AUTH_PASSWORD,
                 auth_root=AUTH_ROOT,
                 current_token=None):
    """
    Makes an authentication request to meerkat_auth using the specified
    username and password, or the server username and password by default
    by default.

    Args:
        username (str): The username to be used in the authentication process.
                        Defaults to the server authntication account.
        password (str): The password to be used in the authentication process.
                        Defaults to the server authentication account.
        current_token (str): The current token. This function will only fetch
                             a new token if the current token has expired.
    Returns:
        str The JWT token.
    """
    # Perform a check to see if the current token has expired...
    # If expired, get a new token, otherwise just return the current token.
    if current_token:
        try:
            auth.decode_token(current_token)
            return current_token
        except jwt.ExpiredSignatureError:
            logging.info("Current token expired. Getting new token.")

    # Assemble auth request params
    url = auth_root + '/api/login'
    data = {'username': username, 'password': password}
    headers = {'content-type': 'application/json'}

    # Make the auth request and log the result
    try:
        r = requests.request('POST', url, json=data, headers=headers)
        logging.info("Received authentication response: " + str(r))

        # Log an error if authentication fails, and return an empty token
        if r.status_code != 200:
            logging.error('Authentication as {} failed'.format(username))
            return ''

        # Return the token
        return r.cookies.get('meerkat_jwt', '')

    except requests.exceptions.RequestException as e:
        logging.error("Failed to access Auth.")
        logging.error(e)


def hermes(url, method, data={}, config=None):
    """
    Makes a Hermes API request.
    Args:
       url (str): The Meerkat Hermes url for the desired function.
       method (str):  The desired HTML function: GET, POST or PUT.
       data (optional dict): The data to be sent to the url. Defaults
       to ```{}```.
    Returns:
       dict: a dictionary formed from the json data in the response.
    """
    # If no Hermes root is set log a warning and don't bother to continue.

    if config:
        hermes_root = config.hermes_api_root
        server_auth_username = config.server_auth_username
        server_auth_password = config.server_auth_password
        auth_root = config.auth_root
    else:
        hermes_root = HERMES_ROOT
        server_auth_username = SERVER_AUTH_USERNAME
        server_auth_password = SERVER_AUTH_PASSWORD
        auth_root = AUTH_ROOT
    if not hermes_root:
        logging.warning("No Hermes ROOT set")
        return

    # Assemble the request params.
    url = hermes_root + url
    headers = {'content-type': 'application/json',
               'authorization': 'Bearer {}'.format(authenticate(
                   auth_root=auth_root,
                   username=server_auth_username,
                   password=server_auth_password))}
    logging.debug("Sending json: {}\nTo url: {}\nwith headers: {}".format(
                  json.dumps(data), url, headers))

    # Make the request and handle the response.
    try:
        r = requests.request(method, url, json=data, headers=headers)
    except requests.exceptions.RequestException as e:
        logging.error("Failed to access Hermes.")
        logging.error(e)
    except requests.exceptions.HTTPError as e:
        logging.error("Hermes request failed with HTTP Error")
        logging.error(e)

    try:
        return r.json()
    except Exception as e:
        logging.error('Failed to convert Hermes response to json.')
        logging.error(e)
