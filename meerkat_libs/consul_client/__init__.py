import json
import logging

import backoff as backoff
import requests

CONSUL_URL = "http://nginx/consul"


@backoff.on_exception(backoff.expo, requests.exceptions.ConnectionError, max_tries=8, max_value=30)
def initialize_dhis2():
    logging.info("Initializing consul publisher")
    requests.post(CONSUL_URL + '/dhis2/export/locationTree')
    requests.post(CONSUL_URL + '/dhis2/export/formFields')
    logging.info("DONE: Initializing consul publisher")


events_buffer = []


def send_dhis2_events(uuid=None, raw_row=None, form_id=None):
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
    if len(events_buffer) > 1000:
        logging.info("Sending batch of events to consul.")
        json_payload = json.dumps(
            {"Messages": events_buffer}
        )
        requests.post(CONSUL_URL + "/dhis2/export/events", json=json_payload)
        events_buffer = []
