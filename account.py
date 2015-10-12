'''
'''
from __future__ import absolute_import, division, print_function, with_statement
from tornado.web import HTTPError

import datetime
import time

import functools

from MySQLdb import (IntegrityError)

import utility
# import settings
from radiusd.store import store

def get_user_by_mac(mac, ac):
    records = store.get_user_records_by_mac(mac)
    if records:
        return records[-1]['user']
    return None

def update_mac_record(user, mac, agent_str):
    records = store.get_mac_records(user['user'])
    m_records = {record['mac']:record for record in records}
    if mac not in m_records:
        # update mac record 
        if (not records) or len(records) < user['ends']:
            store.update_mac_record(user['user'], mac, '', agent_str, False)
        else:
            store.update_mac_record(user['user'], mac, records[0]['mac'], agent_str, True)

def get_bd_user(user):
    return store.get_bd_user(user)

def get_user(openid):
    return store.get_user(openid)

def get_onlines(user):
    return store.get_onlines(user)

def check_mac_online_recently(self, mac, flag):
    '''
        check ruijie client's online
        if last_start is '': use hasn't been online
        else : check last_start & now timedelta
    '''
    last_start = store.get_online_by_mac(mac, flag)
    if last_start:
        seconds = utility.cala_delta(last_start)
        if seconds < 60:
            # check user online(if user login in 1 minutes, assume use has been login)
            return True
    return False

def get_holder(ap_mac):
    '''
        query holder id by ap_mac
    '''
    return store.get_holder_by_mac(ap_mac)

def check_mac_account(mac):
    '''
        # only ruijie ac go to this branch
        check mac address binded acocunt
        not found : 
            reate bd_account by mac
    '''
    mac = mac.replace(':', '')
    user = store.get_bd_user(mac)
    if not user:
        user = store.add_user_by_mac(mac, utility.generate_password())
    else:
        user = user['user']
    return user

def check_account_avaiable(user, profile):
    '''
        
    '''
    pass

'''
    nan sha account manage
'''
def get_ns_employee(**kwargs):
    '''
        kwargs: nan sha employee table fields
    '''
    return store.get_ns_employee(**kwargs)

def add_ns_employee(**kwargs):
    '''
       name mobile gender position department ctime mtime
       if add successfully, return new added id
    '''
    assert 'mobile' in kwargs
    employee = get_ns_employee(mobile=kwargs['mobile'])
    if employee:
        raise HTTPError(400, reason='employee has been existed')

    _id = store.add_ns_employee(**kwargs)

def update_ns_employee(_id, **kwargs):
    '''
        update  existed employee's info
    '''
    try:
        store.update_ns_employee(_id, **kwargs)
    except IntegrityError:
        raise HTTPError(400, reason='mobile number has been existed')

def get_binded_account(_id):
    '''
    '''
    return store.get_binded_account(_id)

def delete_ns_employee(_id):
    '''
    '''
    store.delete_ns_employee(_id)

def bind_ns_account(mobile, mac, ac):
    '''
        bind account operator:
            1. get ns_employee account
            2. get mac correspond bd_account
            3. add bind record
    '''
    employee = get_ns_employee(mobile=mobile)
    if not employee:
        raise HTTPError(404, reason='Mobile numberi: {} can\'t found'.format(mobile))
    user = get_user_by_mac(mac, ac) 

    assert user

    store.bind_ns_account(employee, user)

