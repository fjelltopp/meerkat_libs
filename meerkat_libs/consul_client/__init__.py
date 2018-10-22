import json
import logging
import jwt
import collections
from os import environ

import backoff as backoff
import requests

from meerkat_libs import authenticate

CONSUL_URL = environ.get("CONSUL_URL", "http://nginx/consul")
SUBMISSIONS_BUFFER_SIZE = int(environ.get("CONSUL_SUBMISSIONS_BUFFER_SIZE", "1"))
DHIS2_EXPORT_ENABLED = environ.get("DHIS2_EXPORT_ENABLED", False)

events_buffer = collections.defaultdict(list)


def send_dhis2_events(uuid=None, raw_row=None, form_id=None, auth_token=None, force=False):
    if not force and not DHIS2_EXPORT_ENABLED:
        return
    if not auth_token:
        logging.error("No authentication token provided.")
        return
    global events_buffer
    upload_payload = {'token': '', 'content': 'record', 'formId': form_id, 'formVersion': '',
                      'data': raw_row,
                      'uuid': uuid
                      }
    # TODO: Should md5 be generated here?
    md5_of_body = ""
    events_buffer[form_id].append(
        {
            'MessageId': uuid,
            'ReceiptHandle': 'test-receipt-handle-1',
            'MD5OfBody': md5_of_body,
            'Body': upload_payload,
            'Attributes': {
                'test-attribute': 'test-attribute-value'
            }
        }
    )
    if len(events_buffer[form_id]) > SUBMISSIONS_BUFFER_SIZE:
        logging.info("Sending batch of events to consul. Size: %s", len(events_buffer[form_id]))
        __send_events_from_buffer(form_id=form_id, auth_token=auth_token)


def flush_dhis2_events(auth_token=None):
    if not DHIS2_EXPORT_ENABLED:
        return
    if not auth_token:
        logging.error("No authentication token provided.")
        return
    for form_id in events_buffer:
        logging.info("Clearing Consul Client event buffer for %s.", form_id)
        __send_events_from_buffer(form_id=form_id, auth_token=auth_token)


def __send_events_from_buffer(form_id=None, auth_token=None):
    global events_buffer
    json_payload = json.dumps(
        {"formId": form_id,
         "Messages": events_buffer[form_id]}
    )
    try:
        requests.post(CONSUL_URL + "/dhis2/export/submissions", headers=_auth_headers(auth_token), json=json_payload)
        events_buffer[form_id] = []
    except requests.exceptions.ChunkedEncodingError:
        logging.error("Failed to send chunk of events. Form: %s Count %i", form_id, len(events_buffer[form_id]))


def backoff_hdlr(details):
    logging.info("Backing off {wait:0.1f} seconds afters {tries} tries "
          "calling function {target} with args {args} and kwargs "
          "{kwargs}".format(**details))


@backoff.on_exception(backoff.expo, requests.exceptions.ConnectionError, max_tries=2, max_value=4,
                      on_backoff=backoff_hdlr)
@backoff.on_predicate(backoff.expo,
                      lambda x: False,
                      max_tries=10,
                      max_value=60,
                      on_backoff=backoff_hdlr)
def wait_for_consul_start():
    logging.info("Waiting for consul to initialize.")
    result = 'meerkat_consul' in requests.get(CONSUL_URL).text
    logging.info("Got %s", result)
    return result


def _auth_headers(token):
    return {'authorization': f"Bearer {token}"}
