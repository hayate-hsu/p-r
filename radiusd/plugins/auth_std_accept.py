#!/usr/bin/env python
#coding=utf-8
# from twisted.python import log
# from radiusd.store import store
from radiusd.settings import *
import datetime
import decimal

decimal.getcontext().prec = 32
decimal.getcontext().rounding = decimal.ROUND_UP

def get_type_val(typ,src):
    if typ == 'integer' or typ == 'date':
        return int(src)
    else:
        return src

def process(req=None, resp=None, user=None, **kwargs):
    '''
        current doesn't implement check
        only return accept
    '''
    profile = user['profile']
    is_teacher = user.get('is_teacher', 0)

    hours = profile.get('session_timeout', 24)
    session_timeout = CONFIG['SESSION_TIMEOUT'] if hours==24 else hours*3600

    if profile['policy'] & 1 or is_teacher:
        # free network or teacher
        pass
    else:
        # normal billing pocily
        # user is not nansha wireless city account
        _now = datetime.datetime.now()
        if user['expired'] > _now:
            timedelta = user['expired'] - _now
            seconds = timedelta.seconds

            if timedelta.days:
                seconds = CONFIG['SESSION_TIMEOUT']

            session_timeout = CONFIG['SESSION_TIMEOUT'] if seconds > CONFIG['SESSION_TIMEOUT'] else seconds
        else:
            session_timeout = 0

        if session_timeout < 0:
            session_timeout = 0

        if 'Framed-Pool' in resp:
            session_timeout = 60

        # if session_timeout <= 60:
        #     if user['coin']>0:
        #         session_timeout = session_timeout + user['coin']*180

    resp['Session-Timeout'] = session_timeout
    # resp['Session-Timeout'] = 300
    # resp['Session-Timeout'] = 600
    resp['Class'] = ''.zfill(32)

    if hasattr(user, 'ip'):
        resp['Framed-IP-Address'] = user['ip']

    return resp

# def process2(req=None,resp=None,user=None,**kwargs):
#     product = store.get_product(user['product_id'])
#     session_timeout = int(store.get_param("max_session_timeout"))
#     acct_policy = user['product_policy'] or BOMonth
#     if acct_policy in (PPMonth,BOMonth):
#         expire_date = user.get('expire_date')
#         _expire_datetime = datetime.datetime.strptime(expire_date+' 23:59:59',"%Y-%m-%d %H:%M:%S")
#         _datetime = datetime.datetime.now()
#         if _datetime > _expire_datetime:
#             session_timeout += (_expire_datetime - _datetime).seconds 
# 
#     elif acct_policy  == BOTimes:
#         session_timeout = user.get("time_length",0)
# 
#     if "Framed-Pool" in resp:
#         if store.get_param("expire_addrpool") in resp['Framed-Pool']:
#             session_timeout = 120
#     
#     resp['Session-Timeout'] = session_timeout
# 
#     input_limit = str(product['input_max_limit'])
#     output_limit = str(product['output_max_limit'])
#     _class = input_limit.zfill(8) + input_limit.zfill(8) + output_limit.zfill(8) + output_limit.zfill(8)
#     resp['Class'] = _class
# 
#     if user['ip_address']:
#         resp['Framed-IP-Address'] = user['ip_address']
# 
#     for attr in store.get_product_attrs(user['product_id']):
#         try:
#             _type = resp.dict[attr['attr_name']].type
#             print _type
#             resp[str(attr['attr_name'])] = get_type_val(_type,attr['attr_value'])
#         except:
#             import traceback
#             traceback.print_exc()
# 
#     
#     # for attr in store.get_user_attrs(user['account_number']):
#     #     try:resp[attr.attr_name] = attr.attr_value
#     #     except:pass
# 
#     return resp


