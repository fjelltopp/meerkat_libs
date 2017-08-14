import requests
import datetime
import time
from flask import g, request
from flask import request_started
from flask import request_finished
from meerkat_libs import authenticate
from meerkat_libs.auth_client import JWT_ALGORITHM, JWT_PUBLIC_KEY


class FlaskActivityLogger:
    def __init__(self, app, exclude=None):
        self.app = app
        self.logging_url = app.config.get("LOGGING_URL", None)
        self.source = app.config.get("LOGGING_SOURCE", None)
        self.source_type = app.config.get("LOGGING_SOUCRE_TYPE", None)
        self.implementation = app.config.get("LOGGING_IMPLEMENTAION", None)
        self.event_type = "user_event"

        if self.logging_url is None:
            raise ValueError("No logging URL specified")
        if self.source is None:
            raise ValueError("No logging source specified")
        if self.source_type is None:
            raise ValueError("No logging source type specified")
        if self.implementation is None:
            raise ValueError("No implementation type specified")
        logger = Logger(self.logging_url,
                        self.event_type,
                        self.source,
                        self.source_type,
                        self.implementation)
        app.logger.info("Logging clinent setup")
        app.logger.debug("Logging URL: %s", self.logging_url)
        
        @request_started.connect_via(app)
        def request_start(sender, **extra):
            g.time = time.time()
        excluded = []
        if exclude:
            excluded = exclude
            
        @request_finished.connect_via(app)
        def send_log_request(sender, response, **extra):
            try:
                path = request.path#.split("/")[-1]
                if not path:
                    path = "root"
                
                if path not in excluded and self.logging_url:
                    print(path, excluded)
                    status_code = logger.send(
                        {"path": request.path,
                         "base_url": request.base_url,
                         "full_url": request.url,
                         "status_code": response.status_code,
                         "user": g.get("payload", {}).get("usr", None),
                         "role": g.get("payload", {}).get("acc",
                                                          {}).get(self.implementation,
                                                                  []),
                         "request_time": time.time() - g.time})
                    if status_code != 200:
                        self.app.logger.warning("Logging error, returned status code %s",
                                                status_code)
            except:
                self.app.logger.warning("Logging error", exc_info=True)

                
class Logger:
    def __init__(self, logging_url, event_type, source,
                 source_type, implementation):
        self.event_type = event_type
        self.source = source
        self.source_type = source_type
        self.implementation = implementation
        self.url = logging_url
        self.jwt_auth_token = None# authenticate()

    def send(self, event_data):
        self.jwt_auth_token = authenticate(current_token=self.jwt_auth_token,
                                            jwt_algorithm=JWT_ALGORITHM,
                                            jwt_public_key=JWT_PUBLIC_KEY)
        
        return send_log(self.url,
                        self.event_type,
                        self.source,
                        self.source_type,
                        self.implementation,
                        event_data,
                        token=self.jwt_auth_token)


def send_log(url, event_type, source, source_type, implementation,
             event_data, timestamp=None, token=None):
    """
    Sends http post request to url with all the data
    """
    if not timestamp:
        timestamp = datetime.datetime.now().isoformat()
    headers = {'content-type': 'application/json'}
    if token:
        headers['authorization'] = 'Bearer {}'.format(token)
    result = requests.post(url + "/event",
                           json={
                               "timestamp": timestamp,
                               "type": event_type,
                               "source": source,
                               "source_type": source_type,
                               "implementation": implementation,
                               "event_data": event_data
                           },
                           headers=headers)
    return result.status_code
