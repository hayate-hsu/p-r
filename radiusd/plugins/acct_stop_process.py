#!/usr/bin/env python
#coding=utf-8
from twisted.python import log
from radiusd.pyrad import packet
# from radiusd.store import store
from radiusd.settings import *
from radiusd import utils
import logging
import datetime
import account

def process(req=None,user=None,runstat=None,**kwargs):
    if not req.get_acct_status_type() == STATUS_TYPE_STOP:
        return  
    runstat.acct_stop += 1   
    ticket = req.get_ticket()
    if not ticket.nas_addr:
        ticket.nas_addr = req.source[0]

    ticket.user = user['user']

    _datetime = datetime.datetime.now() 
    online = account.get_online(ticket.nas_addr,ticket.acct_session_id)    
    if not online:
        session_time = ticket.acct_session_time 
        # stop_time = _datetime.strftime( "%Y-%m-%d %H:%M:%S")
        start_time = (_datetime - datetime.timedelta(seconds=int(session_time))).strftime( "%Y-%m-%d %H:%M:%S")
        ticket.acct_start_time = start_time
        # ticket.acct_stop_time = stop_time
        ticket.start_source= STATUS_TYPE_STOP
        ticket.stop_source = STATUS_TYPE_STOP
        account.add_ticket(ticket)
    else:
        account.del_online(ticket.nas_addr, ticket.acct_session_id)
        _location=user['profile'].get('_location', '')
        if _location.startswith('29946'):
            called_stationid = req.get_called_stationid()
            ap_mac,ssid = called_stationid.split(':')
            ap_mac = utils.format_mac(ap_mac)
            account.update_online_record(online['user'], online['mac_addr'], 
                                         ap_mac, ssid, status='stop')
        ticket.acct_start_time = online['acct_start_time']
        # ticket.acct_stop_time= _datetime.strftime( "%Y-%m-%d %H:%M:%S")
        ticket.start_source = online['start_source']
        ticket.stop_source = STATUS_TYPE_STOP
        ticket.mac_addr = online['mac_addr']
        ticket.ap_mac = online['ap_mac']
        account.add_ticket(ticket)

    log.msg('%s Accounting stop request, remove online'%req.get_user_name(),level=logging.INFO)



        



        
