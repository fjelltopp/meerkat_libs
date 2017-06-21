from flask import abort, request, g
from functools import wraps
from jwt import InvalidTokenError
from datetime import datetime
import jwt
import logging
import os
import requests

# Need this module to be importable without the whole of meerkat_auth config.
# Directly load the secret settings file from which to import configs.
# File must define JWT_COOKIE_NAME, JWT_ALGORITHM and JWT_PUBLIC_KEY variables.
filename = os.environ.get('MEERKAT_AUTH_SETTINGS')
exec(compile(open(filename, "rb").read(), filename, 'exec'))


class Authorise:
    """
    A class that provides tools to authorise requests using meerkat_auth
    tokens.
    """
    SESSIONS = {}

    @staticmethod
    def check_access(access, countries, acc, logic='OR'):
        """
        Compares the access levels specified in the require_jwt decorator with
        the access levels specified in the given jwt. Returns a boolean stating
        whether there is a match.

        Accepts "" as a wildcard country, meaning any country.

        Args:
            access ([str]) A list of role titles that meet the authorisation
                requirements.
            countries ([str]) An optional list of countries for which each role
                title correspond to. access[0] corresponds to country[0] etc...
                If the length of countries is smaller than the length of
                access, then the final element of countries is repeated to make
                the length match. Accepts wildcard value "" for any country.
                Default value is [""], meaning all specified access levels will
                be valid for any country if countires is not specified.
            acc (dict) The user's access dictionary from the user's payload.
            logic (string): Default 'OR'. Specify the logic used for checking
                access. Can be 'OR' or 'AND'. The former grants access if the
                user carries any of specified access levels.  The latter denies
                access if the user doesn't carry any of the specified access
                levels.

        Returns:
            bool True if authorised, False if unauthorised.
        """
        # Set the countries array to match the length of the access array.
        if len(countries) < len(access):
            j = len(countries)
            for i in range(j, len(access)):
                countries.append(countries[j-1])

        # Inclusive access checking looks for an access level in common
        # If there is a shared access level, the authorisation granted.
        authorised = False
        if logic == 'OR':
            # For each country specified by the decorator
            for i in range(0, len(countries)):
                country = countries[i]
                # ...if that country is specified in the token
                if country in acc:
                    # ...and if corresponding country's role is in token
                    if access[i] in acc[country] or access[i] == "":
                        # ...then authorise.
                        authorised = True
                        break

                # ...Else if the country specified by the decorator is wildcard
                elif country == "":
                    # ...Look through all countries specified in the jwt
                    for c in acc:
                        # ...if an access level in jwt matches a level in args
                        if access[i] in acc[c] or access[i] == "":
                            # ...then authorise.
                            authorised = True
                            break

        # Exclusive access checking looks for an access level difference.
        # If there is a difference the access is not granted.
        elif logic == 'AND':
            authorised = True
            # Look at each access level the account has.
            for i in range(len(access)):
                acc_role = access[i]
                acc_country = countries[i]
                # If there is an access level not in the current users access
                # (If the current user has access in that country...)
                if acc_role not in acc.get(acc_country, []):
                    authorised = False
                    break

        return authorised

    @staticmethod
    def get_token():
        """
        Get's the Json Web Token. From the cookies or authorization headers.

        This function defines how the token should be retrieved.  It exists
        because we need to look for the token in multiple places depending on
        the type of request.

        Returns:
            The token or an empty string.
        """
        # Extract the token from the cookies
        token = request.cookies.get(JWT_COOKIE_NAME)

        # Extract the token from the headers if it doesn't exist in the cookies
        auth_headers = request.headers.get('authorization')
        if not token and auth_headers:
            token = auth_headers[len(JWT_HEADER_PREFIX):]

        # Extract the token from the GET args if it is still not found
        if not token:
            token = request.args.get(JWT_COOKIE_NAME)

        return token if token else ""

    def get_user(self, token):
        """
        A function that get's the details of the specified user and combines it
        with the specified token's payload.

        Args:
            token (str): The JWT token corresponding to the requested user.

        Returns:
            (dict) The combined payload of the authentication token and the
                remote user token i.e. complete set of information about the
                use specified in the token.
        """
        # Clean all sessions.
        # If this process takes too long, it may need to be run in background.
        self.__clean_sessions()

        # Decode the jwt.
        payload = jwt.decode(
            token,
            JWT_PUBLIC_KEY,
            algorithms=[JWT_ALGORITHM]
        )

        # Get session
        session_key = '{}-{}'.format(payload['usr'], payload['exp'])
        session_value = self.SESSIONS.get(session_key, False)
        logging.warning('SESSION VALUE: {}'.format(session_value))

        # If session doesn't exist create session.
        if not session_value:
            try:
                logging.warning('No pre-existing user data. Fetching remotly.')
                r = requests.post(
                    AUTH_ROOT + '/api/get_user',
                    json={'jwt': token}
                )
                user_token = r.json()['jwt']
                user = jwt.decode(
                    user_token,
                    JWT_PUBLIC_KEY,
                    algorithms=[JWT_ALGORITHM]
                )
                logging.warning("REMOTE USER TOKEN: {}".format(user))
            except Exception as e:
                logging.warning(
                    "Failed to get remote user details: " + repr(e)
                )
                user = {}
            session_value = {**user, **payload}
            self.SESSIONS[session_key] = session_value

        return session_value

    def __clean_sessions(self):
        """
        Filters out expired sessions. All sessions should include a 'exp'
        key that is a unix time stamp of the expiry date.
        """
        s = self.SESSIONS.items()
        now = datetime.now().timestamp()
        self.SESSIONS = {k: v for k, v in s if v.get('exp', 0) >= now}

    def check_auth(self, access, countries, logic='OR'):
        """
        A function that checks whether the user is authorised to continue with
        the current request. It does this by verifying the jwt stored as a
        cookie. If the user isn't authorised the request is aborted with an
        Invalid Token Error.

        If access is granted the user details are stored in flask g, under the
        property "payload", i.e.`g.payload`.

        NOTE: By default the roles specifed are ORed to figure out access. i.e.
        ANY of the given access roles will grant access (we don't require ALL
        of them). Setting logical='AND' will AND the roles to figure out
        access. i.e. the user must have all the specified access roles in order
        to proceed.

        Args:
            access ([str]) A list of role titles that have access to this
                function.
            countries ([str]) An optional list of countries for which each role
                title correspond to. access[0] corresponds to country[0] and
                etc... If the length of countries is smaller than the length of
                access, then the final element of countries is repeated to make
                the length match. Accepts wildcard value "" for any country.
                Default value is [""], meaning all specified access levels will
                be valid for any country if countires is not specified.

                E.g.(['manager', 'shared'], countries=['jordan','demo'])
                Gives access to jordan managers, and demo shared accounts.
                E.g. (['manager', 'shared'])
                Gives access to managers and shared accounts from any country.
                E.g. (['manager','shared'], countries=['jordan'])
                Gives access to managers and shared accounts only from Jordan.
            logic (str): Default 'OR', alernative: 'AND'.  The former grants
                access if the user carries any of the specified access levels.
                The latter only grants access if the user carries ALL of the
                specified access levels.
        """

        # Only translate error strings if Bable is up and running.
        # Bable runs in Frontend not API - both import this module & can't fail
        not_authenticated = ("You have not authenticated yet. "
                             "Please login before viewing this page.")
        incorrect_access = ("User doesn't have required access levels "
                            "for this page: {}.")

        try:
            from flask.ext.babel import gettext
            not_authenticated = gettext(not_authenticated)
            incorrect_access = gettext(incorrect_access)
        except (ImportError, KeyError):
            logging.warning('Flask babel not installed - can\'t translate.')

        # Get the jwt.
        token = Authorise.get_token()

        # If no token is found return an "not authenticated" message
        if not token:
            abort(401, not_authenticated)

        try:
            # Get complete user details from the token.
            user = self.get_user(token)

            # Check user has required access, if so, store user details in g.
            if Authorise.check_access(access, countries, user['acc'], logic):
                g.payload = user

            # Token is invalid if it doesn't have the required accesss levels.
            else:
                raise InvalidTokenError(
                    incorrect_access.format(', '.join(map(str, access)))
                )

        # Return 403 if logged in but the jwt isn't valid.
        except InvalidTokenError as e:
            logging.warning('Invalid token - Access Denied: ' + str(e))
            logging.warning('Token: ' + str(token))
            abort(403, str(e))

        # Otherwise abort with an internal server error page.
        except Exception as e:
            logging.warning('Error in authentication: ' + str(e))
            abort(500, str(e))

    def authorise(self, access, countries):
        """
        Returns decorator that wraps a route function with another function
        that requires a valid jwt.

        Args:
            access ([str]) A list of role titles with access to this function.
            countries ([str]) An optional list of countries for which each role
                title correspond to. access[0] corresponds to country[0] etc...
                If the length of countries is smaller than the length of
                access, then the final element of countries is repeated to make
                the length match. Accepts wildcard value "" for any country.
                Default value is [""], meaning all specified access levels will
                be valid for any country if countires is not specified.

        Returns:
            function: The decorator or abort(401)
        """
        def decorator(f):

            @wraps(f)
            def decorated(*args, **kwargs):

                self.check_auth(access, countries)
                return f(*args, **kwargs)

            return decorated

        return decorator


# Store an instance of the class in this module.
# So it can be easily imported into other modules.
logging.warning('Creating auth')
auth = Authorise()
