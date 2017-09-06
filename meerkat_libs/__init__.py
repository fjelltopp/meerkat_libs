import logging
import requests
import json
import os
import jwt

# Configs from environment variables
HERMES_ROOT = os.environ.get("HERMES_API_ROOT", "")
AUTH_ROOT = os.environ.get('MEERKAT_AUTH_ROOT', 'http://nginx/auth')
SERVER_AUTH_USERNAME = os.environ.get('SERVER_AUTH_USERNAME', 'root')
SERVER_AUTH_PASSWORD = os.environ.get('SERVER_AUTH_PASSWORD', 'password')


def authenticate(username=SERVER_AUTH_USERNAME,
                 password=SERVER_AUTH_PASSWORD,
                 current_token=None,
                 jwt_algorithm=None,
                 jwt_public_key=None):
    """
    Makes an authentication request to meerkat_auth using the specified
    username and password, or the server username and password by default by
    default.

    Returns:
        str The JWT token.
    """

    # Code by Gunnar.  Solving what purpose?
    if current_token:
        if jwt_algorithm is None or jwt_public_key is None:
            raise ValueError("With the current_cookie we need "
                             "both jwt algorithm and public key.")
        try:
            jwt.decode(
                current_token,
                jwt_public_key,
                jwt_algorithm
            )
            return current_token
        except jwt.ExpiredSignatureError:
            logging.info("Getting new jwt token")

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
    if not HERMES_ROOT:
        logging.warning("No Hermes ROOT set")
        return
    url = HERMES_ROOT + url
    headers = {'content-type': 'application/json',
               'authorization': 'Bearer {}'.format(authenticate())}
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


