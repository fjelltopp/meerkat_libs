import boto3
import logging


class DynamoDBAdapter():

    def __init__(self, db_url, structure):
        self.structure = structure
        self.db_url = db_url
        self.keys = self._extract_keys()
        self.conn = boto3.resource(
            'dynamodb',
            endpoint_url=db_url,
            region_name='eu-west-1'
        )

    def _extract_keys(self):
        keys = {}
        for table, structure in self.structure.items():
            keys[table] = [key['AttributeName'] for key in structure['KeySchema']]
        return keys

    def drop(self):
        logging.info('Cleaning the dev db.')
        for table in self.structure.keys():
            try:
                response = self.conn.Table(table).delete()
                logging.debug(response)
            except Exception as e:
                logging.error(e)
                logging.error('There has been error, probably because no tables'
                              'currently exist. Skipping the clean process.')
        logging.info('Cleaned the db.')

    def setup(self):
        logging.info('Creating dev db')
        for table, structure in self.structure.items():
            response = self.conn.create_table(**structure)
            logging.debug(response)

    def read(self, table, keys, attributes=[]):
        args = {'Key': keys}
        if attributes:
            args['ProjectionExpression'] = ", ".join(attributes)
        table = self.conn.Table(table)
        return table.get_item(**args).get('Item', None)

    def write(self, table, keys, attributes):
        for key, value in attributes.items():
            if value is None:
                attributes[key] = {'Value': value, 'Action': 'DELETE'}
            else:
                attributes[key] = {'Value': value, 'Action': 'PUT'}
        table = self.conn.Table(table)
        return table.update_item(
            Key=keys,
            AttributeUpdates=attributes
        )

    def delete(self, table, keys):
        self.table = self.conn.Table(table)
        response = table.delete_item(Key=keys)
        if response['ResponseMetadata']['HTTPStatusCode'] != 200:
            raise Exception("DynamoDB response not 200")
        return response

    def get_all(self, table, conditions={}, attributes=[]):
        db_table = self.conn.Table(table)

        # Assemble scan arguments programatically, by building a dictionary.
        kwargs = {}

        # Include AttributesToGet if any are specified.
        # By not including them we get them all.
        if attributes:
            kwargs["AttributesToGet"] = attributes

        if not conditions:
            # If no conditions are specified, get all users and return as list.
            return db_table.scan(**kwargs).get("Items", [])

        else:
            items = {}
            # Load data separately for each country
            # ...because Scan can't perform OR on CONTAINS
            for field, values in conditions.items():
                for value in values:
                    kwargs["ScanFilter"] = {
                        field: {
                            'AttributeValueList': [value],
                            'ComparisonOperator': 'CONTAINS'
                        }
                    }

                    # Get and combine the users together in a no-duplications dict.
                    for item in db_table.scan(**kwargs).get("Items", []):
                        key = ''.join([item[k] for k in self.keys[table]])
                        items[key] = item

            return list(items.values())
