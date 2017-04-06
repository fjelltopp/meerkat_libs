import requests
import datetime
import time
from flask import g, request
from flask import request_started
from flask import request_finished


class FlaskActivityLogger:
    def __init__(self, app, exclude=None):
        self.app = app
        self.logging_url = app.config.get("LOGGING_URL", None)
        self.source = app.config.get("LOGGING_SOURCE", None)
        self.source_type = app.config.get("LOGGING_SOUCRE_TYPE", None)
        self.implementation = app.config.get("LOGGING_IMPLEMENTAION", None)
        self.event_type = "user_event"
        logger = Logger(self.logging_url,
                        self.event_type,
                        self.source,
                        self.source_type,
                        self.implementation)
        
        @request_started.connect_via(app)
        def request_start(sender, **extra):
            g.time = time.time()
        excluded = []
        if exclude:
            excluded = exclude
            
        @request_finished.connect_via(app)
        def send_log_request(sender, response, **extra):
            path = request.path.split("/")[-1]
            if not path:
                path = "root"
            print(g.payload)
            if path not in excluded:
                logger.send({"path": request.path,
                             "base_url": request.base_url,
                             "full_url": request.url,
                             "user": g.payload.get("usr", None),
                             "role": g.payload.get("acc",
                                                   {}).get(self.implementation,
                                                           []),
                             "request_time": time.time() - g.time})


class Logger:
    def __init__(self, logging_url, event_type, source,
                 source_type, implementation):
        self.event_type = event_type
        self.source = source
        self.source_type = source_type
        self.implementation = implementation
        self.url = logging_url

    def send(self, event_data):
        send_log(self.url,
                 self.event_type,
                 self.source,
                 self.source_type,
                 self.implementation,
                 event_data)


def send_log(url, event_type, source, source_type, implementation,
             event_data, timestamp=None):
    """
    Sends http post request to url with all the data
    """
    if not timestamp:
        timestamp = datetime.datetime.now().isoformat()
    result = requests.post(url + "/event",
                           json={
                               "timestamp": timestamp,
                               "type": event_type,
                               "source": source,
                               "source_type": source_type,
                               "implementation": implementation,
                               "event_data": event_data
                           })
    if result.status_code == 200:
        return True
    else:
        return False
