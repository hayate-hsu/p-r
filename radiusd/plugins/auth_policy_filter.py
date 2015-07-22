#!/usr/bin/env python
#coding=utf-8
from radiusd.plugins import error_auth
from radiusd.settings import *
from radiusd.store import store
from radiusd import utils
import datetime

def process(req=None,resp=None,user=None,**kwargs):
    """执行计费策略校验，用户到期检测，用户余额，时长检测"""

    #
    if user['policy']:
        return resp

    expired, rejected = _check_account(user)
    if rejected:
        resp['Framed-Pool'] = 'expire'
        return error_auth(resp, 'user time_length poor')
    return resp

    acct_policy = user['product_policy'] or PPMonth
    if acct_policy in ( PPMonth,BOMonth):
        if utils.is_expire(user.get('expire_date')):
            resp['Framed-Pool'] = store.get_param("expire_addrpool")
            
    elif acct_policy in (PPTimes,PPFlow):
        user_balance = store.get_user_balance(user['account_number'])
        if user_balance <= 0:
            return error_auth(resp,'user balance poor')    
            
    elif acct_policy == BOTimes:
        time_length = store.get_user_time_length(user['account_number'])
        if time_length <= 0:
            return error_auth(resp,'user time_length poor')
            
    elif acct_policy == BOFlows:
        flow_length = store.get_user_flow_length(user['account_number'])
        if flow_length <= 0:
            return error_auth(resp,'user flow_length poor')

    if user['user_concur_number'] > 0 :
        if store.count_online(user['account_number']) >= user['user_concur_number']:
            return error_auth(resp,'user session to limit')    

    return resp


def _calculate_left_time(_user):
    date, time = _user['expire_date'], ''
    if _user['expire_date']:
        now = datetime.datetime.now()
        _expire_datetime = datetime.datetime.strptime(_user['expire_date'] + ' 23:59:59', 
                                                      '%Y-%m-%d %H:%M:%S')
        if now > _expire_datetime:
            date = ''

    if _user['coin']:
        times = _user['coin']*3*60
        time = '{:02d}:{:02d}'.format(int(times/3600), int(times%3600/60))

    _user['left_time'] = ' + '.join([date, time])

def _check_expire_date(_user):
    '''
    '''
    if not _user['expire_date']:
        return True
    now = datetime.datetime.now()
    _expire_datetime = datetime.datetime.strptime(_user['expire_date'], '%Y-%m-%d')
    if now > _expire_datetime:
        return True
    return False

def _check_left_time(_user):
    return _user['coin'] <= 0

def _check_account(_user):
    '''
        bd_account
    '''
    expired, rejected = False, False
    expired = _check_expire_date(_user)
    if expired:
        rejected = _check_left_time(_user)
    return expired, rejected
