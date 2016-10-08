'''
    Portal template module
    get groups' config from mp server
    if portal config's default=1, portal page user pn_policy['portal']
    else use config settings

    portal server cache image 
'''

from __future__ import absolute_import, division, print_function, with_statement

import tornado.httpclient
import tornado.gen
from tornado.log import access_log, gen_log, app_log

import collections
import datetime

import utility

import os.path

class PortalConfig(Exception):
    def __init__(self, **kwargs):
        '''
            value: (int, str | dict)
        '''
        self.value = kwargs
    
PN_PORTAL = collections.defaultdict(dict)
# {pn:{expired:'', portal:'', mask:'', config:{}}}
# mask : 
#       0 : config
#       1 : error, use login.html as portal page, the expired set to 1 hours
#       2 : pn_policy['portal'] as default page  

DEFAULT_PATH = '/static/images/nsimgs/banner_tpl.jpg'

@tornado.gen.coroutine
def get_portal(pn, platform, prefix='/www/bidong'):
    '''
        get template page from mp
        _location: the network owner
        platform: h5(mobile)|pc
            pc: /www/portal/
            h5: /www/portal/m/

        return:
            1, login.html : error, user default portal page
            2, login.html : default configure
            0, result['config'] : customer define
    '''
    key = '_'.join([pn, platform])
    config = PN_PORTAL.get(key, {})
    now = datetime.datetime.now()
    if config:
        # check expired
        if now < config['expired']:
            raise PortalConfig(**config)

    url = 'http://mp.bidongwifi.com/portal/config?pn={}&tpl={}'.format(pn, platform)
    client = tornado.httpclient.AsyncHTTPClient()
    response = yield client.fetch(url)

    if response.error:
        expired = now + datetime.timedelta(hours=3)
        config = {'mask':1, 'portal':'login.html', 'expired':expired}
        PN_PORTAL[key] = config
        raise PortalConfig(**config)

    result = utility.json_decoder(response.buffer.read())


    expired = now + datetime.timedelta(days=1)
    if result['default']:
        config = {'mask':2, 'portal':'login.html', 'expired':expired}
        PN_PORTAL[key] = config
        raise PortalConfig(**config)

    config = {'mask':0, 'config':result['config'], 'expired':expired}
    path = config['config']['pic']
    pos = path.rfind('/')
    img_path = ''.join([prefix, '/mp_img', path[pos:]])

    # get portal picture
    client = tornado.httpclient.AsyncHTTPClient()
    response = yield client.fetch(path)

    if response.error:
        expired = now + datetime.timedelta(hours=3)
        config = {'mask':1, 'portal':'login.html', 'expired':expired}
        PN_PORTAL[key] = config
        raise PortalConfig(**config)

    with open(img_path, 'wb') as fportal:
        fportal.write(response.buffer.read())

    config['config']['pic'] = '/mp_img' + path[pos:]
    PN_PORTAL[key] = config
        
    raise PortalConfig(**config)
    
