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
    if not req.get_acct_status_type() == STATUS_TYPE_START:
        return
    
    # if store.is_online(req.get_nas_addr(),req.get_acct_sessionid()):
    #      runstat.acct_drop += 1
    #      return log.err('online %s is exists'%req.get_acct_sessionid())

    if not user:
        runstat.acct_drop += 1
        return log.err('user %s not exists'%req.get_user_name())

    runstat.acct_start += 1    
    ap_mac,ssid = '',''
    called_stationid = req.get_called_stationid()
    ap_mac,ssid = called_stationid.split(':')
    ap_mac = utils.format_mac(ap_mac)

    online = utils.Storage(
        user = user['user'],
        nas_addr = req.get_nas_addr(),
        acct_session_id = req.get_acct_sessionid(),
        framed_ipaddr = req.get_framed_ipaddr(),
        mac_addr = utils.format_mac(req.get_mac_addr()),
        ap_mac = ap_mac,
        ssid=ssid,
        _location=user['policy'].get('_location', ''),
        billing_times = 0,
        input_total = 0,
        output_total = 0,
        start_source = STATUS_TYPE_START
    )

    account.add_online(online)

    log.msg('%s Accounting start request, add new online'%req.get_user_name(),level=logging.INFO)
