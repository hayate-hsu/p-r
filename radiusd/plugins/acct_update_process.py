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
    if not req.get_acct_status_type() == STATUS_TYPE_UPDATE:
        return   

    if not user:
        return log.err("[Acct] Received an accounting update request but user[%s] not exists"%req.get_user_name())      

    runstat.acct_update += 1  
    online = account.get_online(req.get_nas_addr(),req.get_acct_sessionid())  

    if not online:         
        log.msg('%s Accounting update request, update online, but can\'t found online record'%req.get_user_name(),level=logging.INFO)
        return
        ap_mac,ssid = '',''
        called_stationid = req.get_called_stationid()
        ap_mac,ssid = called_stationid.split(':')
        ap_mac = utils.format_mac(ap_mac)

        # calculate start time
        sessiontime = req.get_acct_sessiontime()
        updatetime = datetime.datetime.now()
        _starttime = updatetime - datetime.timedelta(seconds=sessiontime)       
        online = utils.Storage(
            user = user['user'],
            is_auto = user.get('is_auto', 0),
            nas_addr = req.get_nas_addr(),
            acct_session_id = req.get_acct_sessionid(),
            acct_start_time = _starttime.strftime("%Y-%m-%d %H:%M:%S"),
            framed_ipaddr = req.get_framed_ipaddr(),
            mac_addr = utils.format_mac(req.get_mac_addr()),
            ap_mac = ap_mac,
            ssid=ssid,
            _location=user['profile'].get('_location', ''),
            billing_times = req.get_acct_sessiontime(),
            input_total = req.get_input_total(),
            output_total = req.get_output_total(),
            start_source = STATUS_TYPE_UPDATE
        )
        account.add_online(online)   
    else:
        # update records 
        # {user, ap_mac, ssid, _location, tiemstamp, }
        _location=user['profile'].get('_location', '')
        if _location.startswith('29946'):
            called_stationid = req.get_called_stationid()
            ap_mac,ssid = called_stationid.split(':')
            ap_mac = utils.format_mac(ap_mac)
            account.update_online_record(online['user'], online['mac_addr'], 
                                         ap_mac, ssid)
        pass

    log.msg('%s Accounting update request, update online'%req.get_user_name(),level=logging.INFO)
        
