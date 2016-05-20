import pymongo
# from pymongo.errors import AutoReconnect

class MongoDB(pymongo.mongo_client.MongoClient):
    '''
    '''
    def __init__(self, uri, db_name='ap', **kwargs):
        '''
            mongodb://[username:password]@host1[:port1][,host2[:port2]]...[,hostN[:portN]][/[database][?options]
        '''
        super(MongoDB, self).__init__(uri, **kwargs)
        self.db = getattr(self, db_name)

    def find_one(self, collection, filter_or_id=None, *args, **kwargs):
        coll = getattr(self.db, collection)
        return coll.find_one(filter_or_id, *args, **kwargs)

    # def find(self, collection, **kwargs):
    #     coll = getattr(self.db, collection)
    #     return coll.find_one(**kwargs)


import config
import sys
mongo_config = config['mongo_config']
# cloud = mongo_config.pop('db_name')
# mongo_config['read_preference'] = pymongo.ReadPreference.PRIMARY_PREFERRED;

uri = ''

mongo = MongoDB(uri=mongo_config['uri'], db_name='ap')

sys.modules[__name__] = mongo

