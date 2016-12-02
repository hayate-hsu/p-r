#!/usr/bin/env python
#coding=utf-8
from twisted.python import log
from radiusd.pyrad import packet
# from radiusd.store import store
from radiusd.settings import *
from radiusd import utils
import logging
import datetime
import decimal

import account

decimal.getcontext().prec = 32
decimal.getcontext().rounding = decimal.ROUND_UP

def send_dm(coa_clients,online):
    try:
        coa_client = coa_clients.get(online['nas_addr'])
        attrs = {
            'User-Name' : online['user'],
            'Acct-Session-Id' : online['acct_session_id'],
            'NAS-IP-Address' : online['nas_addr'],
            'Framed-IP-Address' : online['framed_ipaddr']
        }
        if 'None' == attrs['Framed-IP-Address'] or not attrs['Framed-IP-Address']:
            attrs['Framed-IP-Address'] = '0.0.0.0'
        dmeq = coa_client.createDisconnectPacket(**attrs)
        coa_client.sendCoA(dmeq)
    except:
        log.err('send dm error')
        import traceback
        import sys
        log.err('{}'.format(traceback.format_exception(*sys.exc_info())))

def process(req=None, user=None, runstat=None, coa_clients=None, **kwargs):
    if req.get_acct_status_type() not in (STATUS_TYPE_UPDATE,STATUS_TYPE_STOP):
        return   

    online = account.get_online(req.get_nas_addr(),req.get_acct_sessionid())  
    if not online:
        return

    log.msg('{} > Prepaid long time billing '.format(req.get_user_name()),level=logging.INFO)

    # check user pay type, only pay by times account record billing 
    # now = datetime.datetime.now()
    # if user['expired'] < now:
    #     # account has been expired, 
    #     send_dm(coa_clients,online)
    #     return
    # account has expired, send offline notify   
    return
    coin = int(user['coin'])
    # fisrt value may be 179, so add 1
    session_time = int(req.get_acct_sessiontime()) + 1
    billing_times = int(online['billing_times']) 
    acct_times = session_time - billing_times
    coin_fee = int(acct_times/180)
    coin_left = coin - coin_fee
    

    # billing_coin = int(req.get_acct_sessiontime())
    # coin_left = coin - billing_coin

    account.update_billing(utils.Storage(
        user = online['user'],
        nas_addr = online['nas_addr'],
        acct_session_id = online['acct_session_id'],
        acct_start_time = online['acct_start_time'],
        acct_session_time = req.get_acct_sessiontime(),
        input_total = req.get_input_total(),
        output_total = req.get_output_total(),
        # acct_times = user_time_left,
        acct_coins = coin_fee,
        acct_flows = 0,
        balance = 0,
        is_deduct = 1,
        time = datetime.datetime.now().strftime( "%Y-%m-%d %H:%M:%S")
    ))

    if coin_left == 0:
        send_dm(coa_clients,online)

def process2(req=None,user=None,runstat=None,coa_clients=None,**kwargs):
    if req.get_acct_status_type() not in (STATUS_TYPE_UPDATE,STATUS_TYPE_STOP):
        return   
        
    online = store.get_online(req.get_nas_addr(),req.get_acct_sessionid())  
    if not online:
        return

    product = store.get_product(user['product_id'])
    if not product or product['product_policy'] not in (PPTimes,BOTimes,PPFlow,BOFlows):
        online['billing_times'] = req.get_acct_sessiontime()
        online['input_total'] = req.get_input_total()
        online['output_total'] = req.get_output_total()
        store.update_online(online)
        return

    def process_pptimes():
        # 预付费时长
        log.msg('%s > Prepaid long time billing '%req.get_user_name(),level=logging.INFO)
        user_balance = store.get_user_balance(user['account_number'])
        sessiontime = decimal.Decimal(req.get_acct_sessiontime())
        billing_times = decimal.Decimal(online['billing_times'])
        acct_times = sessiontime - billing_times
        fee_price = decimal.Decimal(product['fee_price'])
        usedfee = acct_times/decimal.Decimal(3600) * fee_price
        usedfee = actual_fee = int(usedfee.to_integral_value())
        balance = user_balance - usedfee
        
        if balance < 0 :  
            balance = 0
            actual_fee = user_balance
            
        store.update_billing(utils.Storage(
            account_number = online['account_number'],
            nas_addr = online['nas_addr'],
            acct_session_id = online['acct_session_id'],
            acct_start_time = online['acct_start_time'],
            acct_session_time = req.get_acct_sessiontime(),
            input_total = req.get_input_total(),
            output_total = req.get_output_total(),
            acct_times = int(acct_times.to_integral_value()),
            acct_flows = 0,
            acct_fee = usedfee,
            actual_fee = actual_fee,
            balance = balance,
            is_deduct = 1,
            create_time = datetime.datetime.now().strftime( "%Y-%m-%d %H:%M:%S")
        ))
        
        if balance == 0 :
            send_dm(coa_clients,online)
        
    def process_botimes():
        #买断时长
        log.msg('%s > Buyout long time billing '%req.get_user_name(),level=logging.INFO)
        time_length = store.get_user_time_length(user['account_number'])
        sessiontime = req.get_acct_sessiontime()
        billing_times = online['billing_times']
        acct_times = sessiontime - billing_times
        user_time_length = time_length - acct_times
        if user_time_length < 0 :
            user_time_length = 0

        store.update_billing(utils.Storage(
            account_number = online['account_number'],
            nas_addr = online['nas_addr'],
            acct_session_id = online['acct_session_id'],
            acct_start_time = online['acct_start_time'],
            acct_session_time = req.get_acct_sessiontime(),
            input_total = req.get_input_total(),
            output_total = req.get_output_total(),
            acct_times = acct_times,
            acct_flows = 0,
            acct_fee = 0,
            actual_fee = 0,
            balance = 0,
            is_deduct = 1,
            create_time = datetime.datetime.now().strftime( "%Y-%m-%d %H:%M:%S")
        ),time_length=user_time_length)
    
        if user_time_length == 0 :
            send_dm(coa_clients,online)
        
    def process_ppflows():
        #预付费流量
        log.msg('%s > Prepaid flow billing '%req.get_user_name(),level=logging.INFO)
        user_balance = store.get_user_balance(user['account_number'])
        output_total = decimal.Decimal(req.get_output_total())
        billing_output_total = decimal.Decimal(online['output_total'])
        acct_flows = output_total - billing_output_total
        fee_price = decimal.Decimal(product['fee_price'])
        usedfee = acct_flows/decimal.Decimal(1024) * fee_price
        usedfee = actual_fee = int(usedfee.to_integral_value())
        balance = user_balance - usedfee
        
        if balance < 0 :  
            balance = 0
            actual_fee = user_balance
            
        store.update_billing(utils.Storage(
            account_number = online['account_number'],
            nas_addr = online['nas_addr'],
            acct_session_id = online['acct_session_id'],
            acct_start_time = online['acct_start_time'],
            acct_session_time = req.get_acct_sessiontime(),
            input_total = req.get_input_total(),
            output_total = req.get_output_total(),
            acct_times = 0,
            acct_flows = int(acct_flows.to_integral_value()),
            acct_fee = usedfee,
            actual_fee = actual_fee,
            balance = balance,
            is_deduct = 1,
            create_time = datetime.datetime.now().strftime( "%Y-%m-%d %H:%M:%S")
        ))
        
        if balance == 0 :  
            send_dm(coa_clients,online)
        
    def process_boflows():
        #买断流量
        log.msg('%s > Buyout flow billing '%req.get_user_name(),level=logging.INFO)
        flow_length = store.get_user_flow_length(user['account_number'])
        output_total = req.get_output_total()
        billing_output_total = online['output_total']
        acct_flows = output_total - billing_output_total
        use_flow_length = flow_length - acct_flows
        if use_flow_length < 0 :
            use_flow_length = 0
            send_dm(coa_clients,online)
            
        store.update_billing(utils.Storage(
            account_number = online['account_number'],
            nas_addr = online['nas_addr'],
            acct_session_id = online['acct_session_id'],
            acct_start_time = online['acct_start_time'],
            acct_session_time = req.get_acct_sessiontime(),
            input_total = req.get_input_total(),
            output_total = req.get_output_total(),
            acct_times = 0,
            acct_flows = acct_flows,
            acct_fee = 0,
            actual_fee = 0,
            balance = 0,
            is_deduct = 1,
            create_time = datetime.datetime.now().strftime( "%Y-%m-%d %H:%M:%S")
        ),flow_length=use_flow_length)
        
        if use_flow_length == 0 :
            send_dm(coa_clients,online)
    
    process_funcs = {
        PPTimes:process_pptimes,
        BOTimes:process_botimes,
        PPFlow:process_ppflows,
        BOFlows:process_boflows
    }
    
    process_funcs[product['product_policy']]()
