import os
import radiusd.server
import config

if __name__ == '__main__':
    with open('/var/run/radius.pid', 'w') as f:
        f.write('{}'.format(os.getpid()))
    radiusd.server.run(config)

