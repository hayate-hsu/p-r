'''
'''
from __future__ import absolute_import, division, print_function, with_statement

from tornado.web import HTTPError
import tornado.httpclient

import time

import collections
import functools

from MySQLdb import (IntegrityError)

from tornado.log import access_log, gen_log, app_log

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

# {pn:{ssid:policy}}
PN_PROFILE = collections.defaultdict(dict)
# {ap_mac:{'pn':pn, 'ap_groups':ap_groups}}
AP_MAPS = collections.defaultdict(dict)

APP_PROFILE = collections.defaultdict(dict)

EXPIRE = 7200

def setup(config):
    store.setup(config)

def get_billing_policy(ac_ip, ap_mac, ssid):
    '''
        1. check ap profile
        2. check ssid profile
        3. check ac profile
    '''
    # check ap prifile in cache?
    if ap_mac and ap_mac in AP_MAPS:
        pn = AP_MAPS[ap_mac]['pn']
        ap_groups = AP_MAPS[ap_mac]['ap_groups']
        profile = PN_PROFILE[pn].get(ssid, None)
        if profile and int(time.time()) < profile['expired']:
            return profile, ap_groups

    if ac_ip in ('172.201.2.251', '172.201.2.252'):
        if ssid and ssid in PN_PROFILE:
            profile = PN_PROFILE[ssid]
            if profile and int(time.time()) < profile['expired']:
                return profile, ''

        # get & update pn profile
        profile = store.query_pn_policy(ssid=ssid)

        if profile:
            profile['expired'] = int(time.time()) + EXPIRE
            PN_PROFILE[ssid] = profile
            return profile, ''


    if ap_mac:
        # get pn by ap mac
        result = {}
        client = tornado.httpclient.HTTPClient()
        try:
            response = client.fetch('http://mp.bidongwifi.com/ap/{}'.format(ap_mac))
            result = utility.json_decoder(response.buffer.read())
        except:
            pass
        ap_groups = ''

        if result and '_location' in result and result['_location']:
            pn = result['_location'].split(',')[-1]
            ap_groups = result.get('ap_groups', '')
            # get pn policy by ap mac & ssid
            profile = store.query_pn_policy(pn=pn, ssid=ssid)
            # profile = store.query_ap_policy(ap_mac, ssid)
            logger.info('mac:{} ssid:{} ---- {}, {}'.format(ap_mac, ssid, profile, ap_groups))

            # if profile:
            #     profile['expired'] = int(time.time()) + EXPIRE
            #     AP_MAPS[ap_mac] = {'pn':profile['pn'], 'ap_groups':ap_groups}
            #     PN_PROFILE[profile['pn']][profile['ssid']] = profile

            #     return profile, ap_groups

        # get pn policy by ssid
        if not profile:
            profile = store.query_pn_policy(ssid=ssid)

        if profile:
            profile['expired'] = int(time.time()) + EXPIRE
            AP_MAPS[ap_mac] = {'pn':profile['pn'], 'ap_groups':ap_groups}
            PN_PROFILE[profile['pn']][profile['ssid']] = profile
            return profile, ap_groups
    else:
        # ap_mac is False, query by nas_addr
        profile = store.get_gw_pn_policy(ac_ip)

        if profile:
            return profile, ''
            
    raise HTTPError(400, reason='Abnormal, query pn failed, {} {}'.format(ap_mac, ssid))

def get_billing_policy2(req):
    ac_ip = req.get_nas_addr()
    
    ap_mac, ssid = parse_called_stationid(req)

    return get_billing_policy(ac_ip, ap_mac, ssid)

def check_account_privilege(user, profile):
    # check private network
    err = None
    if user['mask']>>30 & 1:
        raise HTTPError(433, reason=bd_errs[433])

    if profile['pn'] in (15914,):
        # if account is nvxiao teacher, allow his access 15914
        ret, err = check_pn_privilege(59484, user['user'])
        if ret:
            user['is_teacher'] = 1 
            return err

        holder = user.get('holder', '')
        if holder in (59484,):
            user['is_teacher'] = 1
            return err

        err = None


    if profile['policy'] & 2:
        ret, err = check_pn_privilege(profile['pn'], user['user'])
        if not ret:
            raise err

    # check account has billing? 
    if not (profile['policy'] & 1):
        if check_account_balance(user):
            raise HTTPError(403, reason=bd_errs[450])

    return err

def notify_offline(bas_config):
    if bas_config['mask'] == 1:
        pass

def get_gw_pn_policy(gw_ip):
    '''
    '''
    return store.get_gw_pn_policy(gw_ip)

def check_pn_privilege(pn, user):            
    try:
        record = store.check_pn_privilege(pn, user)
    except:
        record = None
    if not record:
        return False, HTTPError(427, reason='{} can\'t access private network : {}'.format(user, pn))

    mask = int(record.get('mask', 0))
    if mask>>30 & 1:
        return False, HTTPError(433, reason=bd_errs[433])

    return True, record 

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

def check_auto_login_expired(_user):
    now = datetime.datetime.now()
    if 'auto_expired' in _user and now > _user['auto_expired']:
        return True
    return False

def get_current_billing_policy(**kwargs):
    '''
        user's billing policy based on the connected ap 
    '''
    profile = get_billing_policy(kwargs['ac_ip'], kwargs['ap_mac'], kwargs['ssid'])
    return profile

def get_bd_user(user, ismac=False):
    '''
        get bd_account user record
    '''
    return store.get_bd_user(user, ismac=ismac)
    # return store.get_bd_user(user, ismac=ismac) or store.get_bd_user2(user, ismac=ismac)

def check_weixin_user(openid, appid='', tid='', mobile='', mac='', ends=2**5):
    '''
        check account existes?
        if existes: return existed account
        else: create new
    '''
    # first get user by mac address
    _user = store.get_weixin_user(openid, appid, mac)
    if _user:
        if _user['weixin']:
            kwargs = {}
            if tid and _user['tid']!=tid:
                kwargs['tid'] = tid
            if (not _user['appid']) and _user['weixin'] == openid :
                kwargs['appid'] = appid
            if kwargs:
                store.update_account(_user['user'], **kwargs)
        else:
            # found previous account by mac, update account's weixin
            kwargs = {'weixin':openid, 'appid':appid}
            if tid:
                kwargs['tid'] = tid
            store.update_account(_user['user'], **kwargs)

        return _user

    _user = store.add_user(openid, utility.generate_password(), appid=appid, 
                           tid=tid, mobile=mobile, ends=ends)
    return _user

def get_onlines(user, macs='', onlymac=True):
    results = store.get_onlines(user, macs)
    if onlymac:
        return set([item['mac_addr'] for item in results]) if results else set()

    return results

def update_mac_record(user, mac, duration, agent, pn):
    is_update = False
    if pn==29946:
        expired = utility.now('%Y-%m-%d', hours=duration) + ' 23:59:59'
    else:
        expired = utility.now('%Y-%m-%d', days=duration) + ' 23:59:59'

    record = store.get_user_mac_record(user, mac)
    if record:
        is_update = True
    try:
        store.update_mac_record(user, mac, expired, agent, is_update)
    except IntegrityError:
        # duplicate entry
        pass

def get_appid(appid):
    assert appid
    now = datetime.datetime.now()
    if appid in APP_PROFILE and now < APP_PROFILE[appid]['expired']:
        return APP_PROFILE[appid]

    record = store.get_appid(appid)
    if not record:
        raise HTTPError(404, reason='Can\'t found app({}) profile'.format(appid))

    expired = now + datetime.timedelta(days=1)
    record['expired'] = expired
    APP_PROFILE[appid] = record
    return APP_PROFILE[appid]


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

def add_online2(user, nas_addr, ap_mac, mac, user_ip, _location, ssid):
    store.add_online2(user, nas_addr, ap_mac, mac, user_ip, _location, ssid)

def get_online(nas_addr, session_id):
    return store.get_online(nas_addr, session_id)

def del_online(nas_addr, session_id):
    store.del_online(nas_addr, session_id)

def del_online2(nas_addr, mac):
    store.del_online2(nas_addr, mac)

def del_online3(nas_addr, user_ip):
    store.del_online3(nas_addr, user_ip)

def add_ticket(ticket):
    store.add_ticket(ticket)
    
def parse_called_stationid(req):
    data = req.get_called_stationid()
    ap_mac, ssid = data.split(':')
    ap_mac = utility.format_mac(ap_mac) 
    return ap_mac, ssid

def check_token(user, token):
    token,expired = token.split('|')
    token2 = utility.token2(user, expired)

    if token != token2:
        raise HTTPError(400, reason='Abnormal token')
