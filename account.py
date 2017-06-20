#!/usr/bin/env python
#coding=utf-8
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

# import mongo

_REQUESTES_ = {}

BAS_PORT = 2000
_BUFSIZE=1024

PORTAL_PORT = 50100

# {pn:{ssid:policy}}
PN_PROFILE = collections.defaultdict(dict)
# {ap_mac:{'pn':pn, 'ap_groups':ap_groups}}
AP_MAPS = collections.defaultdict(dict)

APP_PROFILE = collections.defaultdict(dict)

ONLINE_RECORDS = collections.defaultdict(list)

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

    # if ac_ip in ('172.201.2.251', '172.201.2.252') or ssid.startswith('BD_TEST'):

    if (not ap_mac) or ssid.startswith('BD_TEST'):
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


    profile, ap_groups = '',''
    if ap_mac:
        # get pn by ap mac
        result = query_ap(ap_mac)
        # result = {}
        # client = tornado.httpclient.HTTPClient()
        # try:
        #     response = client.fetch('http://mp.bidongwifi.com/ap/{}'.format(ap_mac))
        #     result = utility.json_decoder(response.buffer.read())
        # except:
        #     pass

        if result and result['_location']:
            pn = result['_location'].split(',')[-1]
            ap_groups = result.get('ap_groups', '')
            # get pn policy by ap mac & ssid
            profile = store.query_pn_policy(pn=pn, ssid=ssid)
            # profile = store.query_ap_policy(ap_mac, ssid)
            logger.info('mac:{} ssid:{} ---- {}, {}'.format(ap_mac, ssid, profile, ap_groups))

        # get pn policy by ssid
    if not profile:
        profile = store.query_pn_policy(ssid=ssid)

    if profile:
        profile['expired'] = int(time.time()) + EXPIRE
        AP_MAPS[ap_mac] = {'pn':profile['pn'], 'ap_groups':ap_groups}
        PN_PROFILE[profile['pn']][profile['ssid']] = profile
        return profile, ap_groups
    # else:
    #     # ap_mac is False, query by nas_addr
    #     profile = store.get_gw_pn_policy(ac_ip)

    #     if profile:
    #         return profile, ''
            
    raise HTTPError(400, reason='Abnormal, query pn failed, {} {}'.format(ap_mac, ssid))

def get_billing_policy2(req):
    ac_ip = req.get_nas_addr()
    
    ap_mac, ssid = parse_called_stationid(req)

    return get_billing_policy(ac_ip, ap_mac, ssid)

def check_account_privilege(user, profile):
    # check private network
    err = None
    if user['mask']>>30 & 1:
        raise HTTPError(431)

    holder = user.get('holder', '')

    if profile['policy'] & 2 and holder not in (profile['pn'],):
        ret, err = check_pn_privilege(profile['pn'], user['user'])
        if not ret:
            raise err

    # check account has billing? 
    if not (profile['policy'] & 1):
        if check_account_balance(user):
            raise HTTPError(435)

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
        access_log.warning('{} can\'t access private network : {}'.format(user, pn))
        return False, HTTPError(427)

    mask = int(record.get('mask', 0))
    if mask>>30 & 1:
        return False, HTTPError(431)

    return True, record 

@utility.check_codes
def get_pn_user(pn, name, mobile):
    assert mobile
    return store.get_pn_user(pn, name, mobile)

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

def check_account_by_mobile_or_mac(mobile, mac):
    '''
        1. first check mac_history 
         
        2. check user has been register?
               mobile : 
               mac : android register by mac address 
    '''
    _user = store.get_account_by_mobile_or_mac(mobile, mac)
    if not _user:
        # register account by mobile
        password = utility.generate_password()
        if mobile:
            _user = store.add_user(mobile, password, mobile=mobile, ends=2**8)
        _user['existed'] = 0
        # _user = {'user':user, 'password':password, 'existed':0}
    else:
        if mobile and (_user['amobile'] != mobile or _user['mobile'] != mobile):
            store.update_account(_user['user'], mobile=mobile)

        _user['existed'] = 1
    return _user

def check_account_by_mac(mac):
    _user = store.get_account_by_mac(mac)
    if not _user:
        password = utility.generate_password()
        _user = store.add_user(mac, password, ends=2**6)

    return _user

def check_ssid(ssid, mac=None):
    return db.check_ssid(ssid, mac)

def check_pn_account_by_mobile(mobile, pn):
    assert mobile
    _user = store.get_account_by_mobile(mobile, '')
    if not _user:
        # register account by mobile
        password = utility.generate_password()
        _user = store.add_renter(mobile, password, pn, mobile=mobile)
    else:
        if _user['mobile'] != mobile:
            store.update_account(_user['user'], mobile=mobile)
    return _user

def check_app_account(uuid, mask):
    assert uuid
    _user = store.get_account(uuid=uuid)
    if not _user:
        _user = store.add_user(uuid, utility.generate_password(), ends=mask)
    return _user


def get_bd_user(user, ismac=False):
    '''
        get bd_account user record
    '''
    return store.get_bd_user(user, ismac=ismac)
    # return store.get_bd_user(user, ismac=ismac) or store.get_bd_user2(user, ismac=ismac)

def query_ap(ap_mac):
    return store.query_ap(ap_mac)

def get_pn_bd_user(user):
    return store.get_pn_bd_user(user)

def update_bd_user(user, **kwargs):
    if kwargs:
        store.update_bd_user(user, **kwargs)

def get_weixin_user(openid, appid, tid, mac):
   _user = store.get_weixin_user(openid, appid, mac)
   return _user


def check_weixin_user(user, mac, openid, appid, tid):
    '''
        check account existes?
        if existes: return existed account
        else: create new
    '''
    # first get user by mac address
    _account = store.get_account2(int(user))

    if not _account['weixin']:
        kwargs =  {'weixin':openid, 'tid':tid, 'appid':appid}
        kwargs['mask'] = _account['mask'] + 2**5
        try:
            store.update_account(_account['id'], **kwargs)
        except IntegrityError:
            # user's weixin account has been registered
            pass

    return _account 

   #  _user = store.get_weixin_user(openid, appid, mac)
   #  if _user:
   #      if _user['weixin']:
   #          kwargs = {}
   #          if tid and _user['tid']!=tid:
   #              kwargs['tid'] = tid
   #          if (not _user['appid']) and _user['weixin'] == openid :
   #              kwargs['appid'] = appid
   #          if kwargs:
   #              store.update_account(_user['user'], **kwargs)
   #      else:
   #          # found previous account by mac, update account's weixin
   #          kwargs = {'weixin':openid, 'appid':appid}
   #          if tid:
   #              kwargs['tid'] = tid
   #          store.update_account(_user['user'], **kwargs)

   #      return _user

   #  _user = store.add_user(openid, utility.generate_password(), appid=appid, 
   #                         tid=tid, mobile=mobile, ends=ends)
   #  return _user

def get_onlines(user, macs='', onlymac=True):
    results = store.get_onlines(user, macs)
    if onlymac:
        return set([item['mac_addr'] for item in results]) if results else set()

    return results

def update_mac_record(user, mac, duration, agent, device, profile):
    '''
        agent : user agents
        device: client device's type (IPhone|IPad|Android|Windows NT)
    '''
    is_update = False
    expired = utility.now('%Y-%m-%d %H:%M:%S', hours=duration)

    record = store.get_user_mac_record(user, mac)
    if record:
        is_update = True
    try:
        store.update_mac_record(user, mac, expired, agent, device, profile['ssid'], is_update)
    except IntegrityError:
        # duplicate entry
        pass

def delete_mac_record(user, mac):
    '''
        delete user or mac records
    '''
    store.delete_mac_record(user, mac)

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

def update_version(mask, **kwargs):
    pt = ''
    if mask>>6 & 1:
        pt = 'Android'
    elif mask>>7 & 1:
        pt = 'IOS'
    else:
        raise HTTPError(400, reason='Unknown platform')
    store.update_app_version(pt, **kwargs)

def get_version(mask):
    pt = ''
    if mask>>6 & 1:
        pt = 'Android'
    elif mask>>7 & 1:
        pt = 'IOS'
    else:
        raise HTTPError(400, reason='Unknown platform')
    return store.get_app_version(pt)

def create_version(ver, mask, note):
    '''
        create app version
    '''
    pt = ''
    if mask>>6 & 1:
        pt = 'Android'
    elif mask>>7 & 1:
        pt = 'IOS'
    else:
        raise HTTPError(400, reason='Unknown platform')
    record = get_version(mask)
    if record:
        store.update_app_version(pt, newest=ver, least=ver, note=note)
    else:
        store.add_app_version(pt, ver, note)

def query_avaiable_pns(user, mobile):
    '''
    '''
    return store.query_avaiable_pns(user, mobile)

@utility.check_codes
def create_portal_tmp(name, title='羊城晚报社', h5_pic='/images/nsimgs/bg_tpl.jpg', 
                      pc_pic='/images/nsimgs/banner_tpl.jpg', mask=1792):
    assert name
    store.create_portal_tmp(name, title, h5_pic, pc_pic, mask)

@utility.check_codes
def update_portal_tmp(name, **kwargs):
    if kwargs:
        assert name
        store.update_portal_tmp(name, **kwargs)

@utility.check_codes
def delete_portal_tmp(name):
    assert name
    store.delete_portal_tmp(name)

@utility.check_codes
def get_portal_tmp(name):
    return store.get_portal_tmp(name)

#************************************************************
def clear_user_records(user, macs=[]):
    '''
    '''
    macs = ','.join(['"{}"'.format(item) for item in macs])
    store.clear_user_records(user, macs)

def add_online_record(user, mac, ap_mac, ssid):
    '''
        1. add online
    '''
    _id = store.add_online_record(user, mac, ap_mac, ssid)
    key = '{}_{}'.format(user, mac)
    ONLINE_RECORDS[key] = (_id, ap_mac)

def update_online_record(user, mac, ap_mac, ssid, status='alive'):
    '''
        1. update stop record
        2. if ap change, create new records, change id
        3. stop: remove record from ONLINE_RECORDS
    '''
    key = '{}_{}'.format(user, mac)
    if key in ONLINE_RECORDS:
        _id, pre_ap_mac = ONLINE_RECORDS[key]
        stop = utility.now()
        # update records
        _id = store.update_online_record(_id, stop, user, mac, ap_mac, ssid, pre_ap_mac)
        if ap_mac != pre_ap_mac:
            # update new record
            ONLINE_RECORDS[key] = (_id, ap_mac)
    else:
        # create new record
        add_online_record(user, mac, ap_mac, ssid)

    if status=='stop':
        # clear cache
        ONLINE_RECORDS.pop(key, '')

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

def get_online2(nas_addr, user_mac):
    return store.get_online2(nas_addr, user_mac)

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
