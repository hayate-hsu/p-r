#!/usr/bin/env python
#coding=utf-8
'''
    radius server main server
'''
from __future__ import absolute_import, division, print_function, with_statement

import sys
reload(sys)
sys.setdefaultencoding('utf-8')

import os
import radiusd.acct_server
import config
import account

if __name__ == '__main__':
    with open('/var/run/acct_radius.pid', 'w') as f:
        f.write('{}'.format(os.getpid()))
    account.setup(config['database'])
    radiusd.acct_server.run(config)

