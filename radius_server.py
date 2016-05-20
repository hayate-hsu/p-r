'''
    radius server main server
'''
from __future__ import absolute_import, division, print_function, with_statement

import os
import radiusd.server
import config
import account

if __name__ == '__main__':
    with open('/var/run/radius.pid', 'w') as f:
        f.write('{}'.format(os.getpid()))
    account.setup(config['database'])
    radiusd.server.run(config)

