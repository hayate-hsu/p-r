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
import os.path
import radiusd.auth_server
import config
import account

if __name__ == '__main__':
    with open(os.path.join(config['pid_path'], 'auth_radius.pid'), 'w') as f:
        f.write('{}'.format(os.getpid()))
    account.setup(config['database'])
    config['logfile'] = config['auth_logfile']
    radiusd.auth_server.run(config)

