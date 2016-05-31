'''
'''
from __future__ import absolute_import, division, print_function, with_statement

from tornado.web import HTTPError

import time

import collections

from MySQLdb import (IntegrityError)

import logging
logger = logging.getLogger()

import datetime
import utility
# import settings
# import config
from radiusd.store import store
from bd_err import bd_errs

import mongo

_REQUESTES_ = {}

BAS_PORT = 2000
_BUFSIZE=1024

PORTAL_PORT = 50100

PN_PROFILE = collections.defaultdict(dict)
AP_MAPS = {}

EXPIRE = 7200

def setup(config):
    store.setup(config)

def get_billing_policy(nas_addr, ap_mac, ssid):
    '''
        1. check ap profile
        2. check ssid profile
        3. check ac profile
    '''
    # check ap prifile in cache?
    if ap_mac and ap_mac in AP_MAPS:
        profile = PN_PROFILE[AP_MAPS[ap_mac]].get(ssid, None)
        if profile and int(time.time()) < profile['expired']:
            return profile

    if ap_mac:
        # get pn by ap mac
        result = mongo.find_one('aps_bind', {'mac':ap_mac})

        if result and result['_location']:
            pn = result['_location'].split(',')[-1]
            # get pn policy by ap mac & ssid
            profile = store.query_pn_policy(pn=pn, ssid=ssid)
            # profile = store.query_ap_policy(ap_mac, ssid)
            logger.info('mac:{} ssid:{} ---- {}'.format(ap_mac, ssid, profile))

            if profile:
                profile['expired'] = int(time.time()) + EXPIRE
                AP_MAPS[ap_mac] = profile['pn']
                PN_PROFILE[profile['pn']][profile['ssid']] = profile

                return profile

    # get pn policy by ssid
    profile = store.query_pn_policy(ssid=ssid)

    if profile:
        return profile

    raise HTTPError(400, 'Abnormal, query pn failed, {} {}'.format(ap_mac, ssid))

    # if (configure['mask'])>>2 & 1:
    #     # check ap prifile in cache?
    #     if ap_mac in AP_MAPS:
    #         profile = PN_PROFILE[AP_MAPS[ap_mac]].get(ssid, None)
    #         if profile and int(time.time()) < profile['expired']:
    #             return profile

    #     # get policy by ap
    #     result = mongo.find_one('aps', mac=ap_mac)
    #     if not result['_location']:
    #         pn,ssid = 10002,'NanSha_City'
    #     else:
    #         pn = result['_location'].split(',')[1]

    #     profile = store.query_pn_policy(pn=pn, ssid=ssid)
    #     # profile = store.query_ap_policy(ap_mac, ssid)
    #     logger.info('mac:{} ssid:{} ---- {}'.format(ap_mac, ssid, profile))

    #     if not profile:
    #         raise HTTPError(400, 'Abnormal, query pn failed, {} {}'.format(ap_mac, ssid))

    #     profile['expired'] = int(time.time()) + EXPIRE
    #     AP_MAPS[ap_mac] = profile['pn']
    #     PN_PROFILE[profile['pn']][profile['ssid']] = profile
    #         
    #     return PN_PROFILE[AP_MAPS[ap_mac]][ssid]

    # if (configure['mask'])>>1 & 1:
    #     # return store.query_pn_policy(pn=configure['pns'][ssid], ssid=ssid)
    #     # only based ssid, ssid must be unique
    #     return store.query_pn_policy(ssid=ssid)

    # if (configure['mask'] & 1):
    #     return store.query_pn_policy(pn=configure['pn'], ssid=ssid)

def get_billing_policy2(req):
    ac_ip = req.get_nas_addr()
    
    ap_mac, ssid = parse_called_stationid(req)

    return get_billing_policy(ac_ip, ap_mac, ssid)


def check_pn_privilege(pn, user):            
    record = store.check_pn_privilege(pn, user)
    if not record:
        return False, HTTPError(427, reason='{} can\'t access private network : {}'.format(user, pn))

    mask = int(record.get('mask', 0))
    if mask>>30 & 1:
        return False, HTTPError(433, reason=bd_errs[433])

    return True, None

def bind_avaiable_pns(user, mobile):
    store.bind_avaiable_pns(user, mobile)

def _check_expire_date(_user): 
    '''
    '''
    now = datetime.datetime.now()
    if now > _user['expired']:
        return True
    return False

def _check_left_time(_user):
    return _user['coin'] <= 0

def check_account_balance(_user):
    '''
        check account expired & left time
    '''
    return _check_expire_date(_user)

def get_user_by_mac(mac, ac):
    records = store.get_user_records_by_mac(mac)
    if records:
        return records[-1]['user']
    return ''

def get_current_billing_policy(**kwargs):
    '''
        user's billing policy based on the connected ap 
    '''
    profile = get_billing_policy(kwargs['ac_ip'], kwargs['ap_mac'], kwargs['ssid'])
    return profile

def get_bd_user(user):
    '''
        get bd_account user record
    '''
    return store.get_bd_user(user) or store.get_bd_user2(user)

def add_user(user, appid='', tid='', mobile='', ends=2**5):
    password = utility.generate_password(6)
    return store.add_user(user, password, appid, tid, mobile, ends)

def get_user(value, column='weixin', appid=''):
    _user = store.get_user(value, column=column, appid=appid) or store.get_user2(value, column=column, appid=appid)
    return _user

def create_user(user, appid='', tid='', mobile='', ends=2**5):
    _user = store.add_user(user, utility.generate_password(), appid=appid, 
                           tid=tid, mobile=mobile, ends=ends)
    return _user

def get_onlines(user):
    return store.get_onlines(user)

def update_mac_record(user, mac, agent):
    is_update = False
    record = store.get_user_mac_record(user, mac)
    if record:
        is_update = True
    try:
        store.update_mac_record(user, mac, agent, is_update)
    except IntegrityError:
        # duplicate entry
        pass


def query_ap_policy(ap_mac, ssid):
    return store.query_ap_policy(ap_mac, ssid)

def query_pn_policy(**kwargs):
    return store.query_pn_policy(**kwargs)

#************************************************************

def get_bas(ip):
    return store.get_bas(ip)

def list_bas():
    return store.list_bas()

def unlock_online(nas_addr, session_id , status):
    store.unlock_online(nas_addr, session_id , status)

def update_billing(billing):
    store.update_billing(billing)

def add_online(online):
    store.add_online(online)

def get_online(nas_addr, session_id):
    return store.get_online(nas_addr, session_id)

def del_online(nas_addr, session_id):
    store.del_online(nas_addr, session_id)

def add_ticket(ticket):
    store.add_ticket(ticket)
    
def parse_called_stationid(req):
    data = req.get_called_stationid()
    ap_mac, ssid = data.split(':')
    ap_mac = utility.format_mac(ap_mac) 
    return ap_mac, ssid
