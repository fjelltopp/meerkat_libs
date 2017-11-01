import json
import logging
from os import environ

import backoff as backoff
import requests

CONSUL_URL = environ.get("CONSUL_URL", "http://nginx/consul")
DHIS2_EXPORT_ENABLED = environ.get("DHIS2_EXPORT_ENABLED", False)


@backoff.on_exception(backoff.expo, requests.exceptions.ConnectionError, max_tries=8, max_value=30)
def initialize_dhis2():
    logging.info("Initializing consul publisher")
    requests.post(CONSUL_URL + '/dhis2/export/locationTree')
    requests.post(CONSUL_URL + '/dhis2/export/formFields')
    logging.info("DONE: Initializing consul publisher")


events_buffer = []


def send_dhis2_events(uuid=None, raw_row=None, form_id=None):
    if not DHIS2_EXPORT_ENABLED:
        return
    global events_buffer
    upload_payload = {'token': '', 'content': 'record', 'formId': form_id, 'formVersion': '',
                      'data': raw_row,
                      'uuid': uuid
                      }
    # TODO: Should md5 be generated here?
    md5_of_body = ""
    events_buffer.append(
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
    if len(events_buffer) > 500:
        logging.info("Sending batch of events to consul.")
        __send_events_from_buffer()


def flush_dhis2_events():
    if not DHIS2_EXPORT_ENABLED:
        return
    logging.info("Clearing Consul Client event buffer.")
    __send_events_from_buffer()


def __send_events_from_buffer():
    global events_buffer
    json_payload = json.dumps(
        {"Messages": events_buffer}
    )
    requests.post(CONSUL_URL + "/dhis2/export/events", json=json_payload)
    events_buffer = []
