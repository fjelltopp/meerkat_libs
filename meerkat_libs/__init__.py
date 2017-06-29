import logging
import requests
import json
import os

# Configs from environment variables
HERMES_ROOT = os.environ.get("HERMES_API_ROOT", "")
AUTH_ROOT = os.environ.get('MEERKAT_AUTH_ROOT', 'http://dev_nginx_1/auth')
SERVER_AUTH_USERNAME = os.environ.get('SERVER_AUTH_USERNAME', 'root')
SERVER_AUTH_PASSWORD = os.environ.get('SERVER_AUTH_PASSWORD', 'password')


def authenticate(username=SERVER_AUTH_USERNAME,
                 password=SERVER_AUTH_PASSWORD):
    """
    Makes an authentication request to meerkat_auth using the specified
    username and password, or the server username and password by default by
    default.

    Returns:
        str The JWT token.
    """
    # Assemble auth request params
    url = AUTH_ROOT + '/api/login'
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


def hermes(url, method, data={}):
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
    # Assemble the request params.
    url = HERMES_ROOT + url
    headers = {'content-type': 'application/json',
               'authorization': 'Bearer {}'.format(authenticate())}
    logging.warning("Sending json: {}\nTo url: {}\nwith headers: {}".format(
                  json.dumps(data), url, headers))

    # Make the request and handle the response.
    try:
        r = requests.request(method, url, json=data, headers=headers)
    except requests.exceptions.RequestException as e:
        logging.error("Failed to access Hermes.")
        logging.error(e)

    try:
        return r.json()
    except Exception as e:
        logging.error('Failed to convert Hermes response to json.')
        logging.error(e)
