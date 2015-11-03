#!/usr/bin/env python
#coding=utf-8
from DBUtils.PooledDB import PooledDB
# from beaker.cache import CacheManager
# import functools
# import settings
import datetime
try:
    import MySQLdb
except:
    pass

# import string
__PASSWORD__ = ''.join(('abcdefghijkmnpqrstuvwxyz', 'ABCDEFGHJKLMNPQRSTUVWXYZ', '123456789', '~!@#$^&*<>=_'))

__cache_timeout__ = 600

# cache = CacheManager(cache_regions= {'short_term':{'type':'memory', 
#                                                    'expire':__cache_timeout__}})

ticket_fds = [
    'user', 'acct_input_octets', 'acct_output_octets', 'acct_input_packets', 'acct_output_packets', 
    'acct_session_id', 'acct_session_time', 'acct_start_time', 'acct_stop_time', 
    'acct_terminate_cause', 'frame_netmask', 'framed_ipaddr', 'is_deduct', 'nas_addr',
    'session_timeout', 'start_source', 'stop_source', 'mac_addr'
]

class Connect:
    def __init__(self, dbpool):
        self.conn = dbpool.connect()

    def __enter__(self):
        return self.conn

    def __exit__(self, exc_type, exc_value, exc_tb):
        self.conn.close()

class Cursor:
    def __init__(self, dbpool):
        self.conn = dbpool.connect()
        self.cursor = dbpool.cursor(self.conn)

    def __enter__(self):
        return self.cursor

    def __exit__(self, exc_type, exc_value, exc_tb):
        self.conn.close()

class MySQLPool():
    def __init__(self, config):
        self.dbpool = PooledDB(
            creator=MySQLdb,
            db=config['db'],
            host=config['host'],
            port=config['port'],
            user=config['user'],
            passwd=config['passwd'],
            charset=config['charset'],
            maxusage=config['maxusage']
        )

    def cursor(self, conn):
        return conn.cursor(MySQLdb.cursors.DictCursor)

    def connect(self):
        return self.dbpool.connection()

pool_class = {'mysql':MySQLPool}

class Store():
    def setup(self, config):
        self.dbpool = MySQLPool(config['database'])
        # global __cache_timeout__
        # __cache_timeout__ = config['cache_timeout']


    def list_bas(self):
        '''
            Get ac lists
        '''
        with Cursor(self.dbpool) as cur:
            cur.execute('select * from bas')
            return list(cur)
            # return [bas for bas in cur]

    def get_bas(self, ip):
        '''
        '''
        with Cursor(self.dbpool) as cur:
            cur.execute('select * from bas where ip = "{}"'.format(ip))
            bas = cur.fetchone()
            return bas

    def add_holder(self, weixin, password, mobile, expire_date,
                      email='', address='', realname=''):
        '''
            add hold user, user must with tel & address
            mask = 0 + 2**1 + [2**8]
        '''
        with Connect(self.dbpool) as conn:
            cur = conn.cursor(MySQLdb.cursors.DictCursor)
            now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            mask = 0 + 2**1
            # if weixin:
            #     mask = mask + 2**5
            # insert holder account
            sql = '''insert into account 
            (mobile, weixin, uuid, email, mask, address, 
            realname, create_time, expire_date) 
            values("{}", "{}", "", "{}", {}, "{}", "{}", "{}", "{}")
            '''.format(mobile, weixin, email, mask, address, 
                       realname, now, expire_date)
            cur.execute(sql)
            sql = 'select id from account where mobile = "{}" and weixin = "{}"'.format(mobile, weixin)
            cur.execute(sql)
            user = cur.fetchone()

            mask = mask + 2**8

            sql = '''insert into bd_account (user, password, mask, 
            expire_date, coin, holder) values("{}", "{}", {}, 
            "{}", 0, {})
            '''.format(str(user['id']), password, mask, expire_date, user['id'])
            cur.execute(sql)
            conn.commit()
            return user['id']

    def add_holder_aps(self, holder, aps):
        '''
            aps : ((vendor, model, mac),)
        '''
        with Connect(self.dbpool) as conn:
            cur = conn.cursor()
            for vendor, model, mac_addr in aps:
                sql = '''insert into holder_ap (holder, vendor, model, 
                mac_addr) values({}, "{}", "{}", "{}")
                '''.format(holder, vendor, model, mac_addr)
                cur.execute(sql)
            conn.commit()

    def get_holder_aps(self, holder):
        '''
        '''
        with Cursor(self.dbpool) as cur:
            sql = 'select mac_addr, vendor from holder_ap where holder = "{}"'.format(int(holder))
            cur.execute(sql)
            results = cur.fetchall()
            return results if results else ()

    def get_holder_by_mac(self, ap_mac):
        with Cursor(self.dbpool) as cur:
            sql = 'select holder from holder_ap where mac = "{}"'.format(ap_mac)
            cur.execute(sql)
            holder = cur.fetchone()
            return holder['holder'] if holder else ''


    def add_holder_rooms(self, holder, expire_date, rooms):
        '''
            holder: int
            rooms: ((room, password), )
        '''
        with Connect(self.dbpool) as conn:
            cur = conn.cursor()
            mask = 2**1 + 2**8
            for room,password in rooms:
                # insert room to holder_room
                sql = 'insert into holder_room (holder, room) values({}, "{}")'.format(holder, room)
                cur.execute(sql)
                # insert holder's account
                sql = '''insert into bd_account (user, password, mask, expire_date, coin, holder) 
                values("{}", "{}", {}, "{}", 0, {})
                '''.format(str(holder)+str(room), password, mask, expire_date, holder)
                cur.execute(sql)
            conn.commit()

    def get_holder_rooms(self, holder):
        '''
        '''
        with Cursor(self.dbpool) as cur:
            sql = 'select room from holder_room where holder = "{}"'.format(holder)
            cur.execute(sql)
            results = cur.fetchall()

            return results if results else ()

    def get_holder_renters(self, holder):
        '''
        '''
        with Cursor(self.dbpool) as cur:
            sql = 'select * from bd_account where holder = "{}"'.format(holder)
            cur.execute(sql)
            results = cur.fetchall()
            return results

    def add_user(self, user, password, ends=0):
        '''
            user : uuid or weixin openid
            password : user encrypted password
            ends : special the end type         data
                0 : unknown                     
                2^5 : weixin                      opendid
                2^6 : app(android)                opendid or other unique id 
                2^7 : app(ios)
                2**9: user pay by time

                2**28 : acount forzened
                # 4 : web                         token & account
        '''
        with Connect(self.dbpool) as conn:
            cur = conn.cursor(MySQLdb.cursors.DictCursor)
            now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            column = 'weixin'
            weixin, uuid = user, ''
            mask = 0 + 2**2 + 2**5
            if ends>>6 & 1:
                weixin, uuid = '', user
                column = 'uuid'
                mask = 0 + 2**2 + 2**6
            elif ends>>7 & 1:
                weixin, uuid = '', user
                column = 'uuid'
                mask = 0 + 2**2 + 2**7

            sql = '''insert into account 
            (mobile, weixin, uuid, email, mask, address, realname, create_time) 
            values("", "{}", "{}", "", {}, "", "", "{}")
            '''.format(weixin, uuid, mask, now)
            cur.execute(sql)

            sql = 'select id from account where {} = "{}"'.format(column, user)
            cur.execute(sql)
            user = cur.fetchone()
            #
            mask = mask + 2**9
            coin = 60

            sql = '''insert into bd_account (user, password, mask, coin, holder, ends) 
            values("{}", "{}", {}, {}, 0, 5)
            '''.format(str(user['id']), password, mask, coin)
            cur.execute(sql)
            conn.commit()
            return user['id']

    def add_user_by_mac(self, mac, password):
        '''
            create user account by mac (remove ':') 
        '''
        with Connect(self.dbpool) as conn:
            cur = conn.cursor(MySQLdb.cursors.DictCursor)
            # now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            # mask = 0 + 2**4
            # sql = '''insert into account 
            # (mobile, weixin, uuid, email, mask, address, realname, create_time) 
            # values("", "", "{}", "", {}, "", "", "{}")
            # '''.format(uuid, mask, now)
            # cur.execute(sql)

            # sql = 'select id from account where uuid = "{}"'.format(uuid)
            # cur.execute(sql)
            # user = cur.fetchone()
    
            # nansha holder is 10002
            holder = 10002

            mask = 1<<4

            coin = 60
            sql = '''insert into bd_account (user, password, mask, 
            coin, holder, ends) values("{}", "{}", {}, {}, {}, 2)
            '''.format(mac, password, mask, coin, holder)
            cur.execute(sql)
            conn.commit()
            return mac

    def get_user(self, user, ends=0):
        '''
            arguments as add_user
            ends:
                    6&7 : app
                    0 : weixin
        '''
        with Cursor(self.dbpool) as cur:
            # default from weixin
            column = 'weixin'
            if ends:
                # from app
                column = 'uuid'
            cur.execute('select * from account where {} = "{}"'.format(column, user))
            user = cur.fetchone()
            return user

    def add_bd_user(self, user, password):
        '''
        '''
        with Connect(self.dbpool) as conn:
            cur = conn.cursor()
            # password = random.sample(__PASSWORD__, 8)
            sql = '''insert into bd_account (user, password, mask, coin) values(%s, %s, 3, 60)'''
            cur.execute(sql, user, password)
            conn.commit()


    def get_bd_user(self, user, password=None):
        '''
            support auto login, user may be mac address or user account
            user:
                account
                mac : [##:##:##:##:##:##]
        '''
        with Cursor(self.dbpool) as cur:
            sql = ''
            if user.count(':') == 5:
                sql = '''select bd_account.* from mac_history, bd_account 
                where mac_history.mac = "{}" and mac_history.user = bd_account.user'''.format(user)
            else:
                sql = 'select * from bd_account where user = "{}"'.format(user)
                if password:
                    sql = 'select * from bd_account where user = "{}" and password = "{}"'.format(user, password)
            cur.execute(sql)
            user = cur.fetchone()
            if user and user['mask'] & 1<<5:
                # query weixin account binded renter
                sql = 'select * from bind where weixin = "{}"'.format(user)
                cur.execute(sql)
                record = cur.fetchone()
                if record:
                    sql = 'select expire_date from bd_account where user = "{}"'.format(record['renter'])
                    cur.execute(sql)
                    ret = cur.fetchone()
                    if ret:
                        user['expire_date'] = ret['expire_date']
            return user

    def get_block_user(self, mac):
        '''
            mac : mac address
        '''
        pass

    def merge_app_account(self, _id, user_mac):
        '''
            merge mac account to app account
        '''
        with Connect(self.dbpool) as conn:
            cur = conn.cursor(MySQLdb.cursors.DictCursor)
            mac = user_mac.replace(':', '')
            sql = 'select * from bd_account where user = "{}"'.format(mac)
            cur.execute(sql)
            user = cur.fetchone()
            if user:
                # delete mac_history record
                sql = 'delete from mac_history where user = "{}"'.format(mac)
                cur.execute(sql)
                # delete mac account
                sql = 'delete from bd_account where user = "{}"'.format(mac)
                cur.execute(sql)

                # update _id recordds
                sql = '''update bd_account set 
                expire_date="{}" and coin={} where user="{}"
                '''.format(user['expire_date'], user['coin'], _id)
                cur.execute(sql)

                # update bind account
                sql = 'update bind set weixin="{}" where weixin="{}"'.format(_id, mac)
                cur.execute(sql)

                # update nansha bind account
                if user['mask'] & 1<<16:
                    sql = 'update bind set renter="{}" where renter="{}"'.format(_id, mac)
                    cur.execute(sql)

                conn.commit()


    def update_mac_record(self, user, new_mac, old_mac, agent, isupdate=True):
        with Connect(self.dbpool) as conn:
            cur = conn.cursor()
            now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            sql = ''
            if isupdate:
                sql = '''update mac_history set mac = "{}", tlogin = "{}", platform = "{}" 
                where user = "{}" and mac = "{}" '''.format(new_mac, now, agent, user, old_mac)
            else:
                sql = '''insert into mac_history (user, mac, tlogin, platform) 
                values('{}', '{}', '{}', '{}')'''.format(user, new_mac, now, agent)
            cur.execute(sql)
            conn.commit()

    def query_ap_policy(self, ap_mac):
        '''
            query who own the ap and its' policy
        '''
        with Cursor(self.dbpool) as cur:
            # cur = conn.cursor()
            sql = '''select account.portal, account.policy from account, holder_ap 
            where holder_ap.mac = "{}" and holder_ap.holder = account.id'''.format(ap_mac)
            cur.execute(sql)
            result = cur.fetchone()
            return result if result else {}

    def get_user_records_by_mac(self, mac):
        with Cursor(self.dbpool) as cur:
            sql = 'select user, mac, tlogin from mac_history where mac = "{}" order by tlogin'.format(mac)
            cur.execute(sql)
            records = cur.fetchall()
            return records if records else []

    def get_mac_records(self, user):
        '''
        '''
        with Cursor(self.dbpool) as cur:
            sql = 'select user, mac, tlogin from mac_history where user = "{}" order by tlogin'.format(user)
            cur.execute(sql)
            records = cur.fetchall()
            return records if records else []

    def is_online(self, nas_addr, acct_session_id):
        '''
        '''
        with Cursor(self.dbpool) as cur:
            sql = 'select count(id) as online from online where \
                    nas_addr = "{}" and acct_session_id = "{}"'.format(nas_addr, acct_session_id)
            cur.execute(sql)
            return cur.fetchone()['online'] > 0

    def get_online_by_mac(self, mac, flag=0):
        '''
            flag:   0 
            1 mac address need deal with(remove ':|', lower)
        '''
        with Cursor(self.dbpool) as cur:
            if flag:
                mac = mac.replace(':', '').lower()
            sql = 'select acct_start_time as start from online where mac_addr = "{}"'.format(mac)
            cur.execute(sql)
            result = cur.fetchone()
            return result['start'] if result else ''

    def count_online(self, account):
        '''
        '''
        with Cursor(self.dbpool) as cur:
            sql = 'select count(id) as online from online where user = "{}"'.format(account)
            cur.execute(sql)
            return cur.fetchone()['online']

    def get_onlines(self, account):
        '''
        '''
        with Cursor(self.dbpool) as cur:
            sql = 'select mac_addr from online where user = "{}"'.format(account)
            cur.execute(sql)
            results = cur.fetchall()
            if results:
                results = set([item['mac_addr'] for item in results])
            return results if results else set()

    def get_online(self, nas_addr, acct_session_id):
        with Cursor(self.dbpool) as cur:
            sql = 'select * from online where \
                    nas_addr = "{}" and acct_session_id = "{}"'.format(nas_addr, acct_session_id)
            cur.execute(sql)
            return cur.fetchone()

    def add_unauth_online(self, nas_addr, user, user_mac):
        with Connect(self.dbpool) as conn:
            cur = conn.cursor()
            sql = '''insert into online (user, nas_addr, acct_session_id, 
                acct_start_time, framed_ipaddr, mac_addr, billing_times, 
                input_total, output_total, start_source) values("{}", 
                "{}", "", "", "", "{}", 0, 0, 0, 0)
                '''.format(user, nas_addr, user_mac)
            cur.execute(sql)
            conn.commit()

    def add_online(self, online):
        with Connect(self.dbpool) as conn:
            cur = conn.cursor(MySQLdb.cursors.DictCursor)
            # temporary scheme
            nas_addr = online['nas_addr']
            if nas_addr in ['10.10.0.60', ]:
                mac_addr = online['mac_addr']
                mac_addr = mac_addr.upper()
                online['mac_addr'] = ':'.join([mac_addr[:2], mac_addr[2:4], mac_addr[4:6], 
                                               mac_addr[6:8], mac_addr[8:10], mac_addr[10:12]])
                ap_mac = online['ap_mac']
                online['ap_mac'] = ':'.join([ap_mac[:2], ap_mac[2:4], ap_mac[4:6], ap_mac[6:8], ap_mac[8:10], ap_mac[10:12]])

            sql = 'delete from online where mac_addr = "{}"'.format(online['mac_addr'])
            cur.execute(sql)

            keys = ','.join(online.keys())
            vals = ','.join(['"%s"'%c for c in online.values()])
            sql = 'insert into online ({}) values({})'.format(keys, vals)
            cur.execute(sql)
            conn.commit()

    def update_online(self, online):
        with Connect(self.dbpool) as conn:
            cur = conn.cursor()
            online_sql = '''update online set 
                billing_times = "{}",
                input_total = "{}",
                output_total = "{}",
                where nas_addr = "{}" and acct_session_id = "{}"
            '''.format(online['billing_times'], online['input_total'], 
                       online['output_total'], online['nas_addr'], 
                       online['acct_session_id'])
            cur.execute(online_sql)
            conn.commit()

    def update_billing(self, billing, coin=0):
        '''  '''
        with Connect(self.dbpool) as conn:
            cur = conn.cursor()
            # update account
            balance_sql = '''update bd_account set
                coin = {} where user = "{}"
            '''.format(coin, billing['user'])
            cur.execute(balance_sql)

            # update online
            online_sql = '''update online set
                billing_times = {},
                input_total = {},
                output_total = {}
                where nas_addr = "{}" and acct_session_id = "{}"
            '''.format(billing['acct_session_time'], 
                       billing['input_total'], 
                       billing['output_total'],
                       billing['nas_addr'],
                       billing['acct_session_id'],
                      )
            cur.execute(online_sql)

            # update billing
            keys = ','.join(billing.keys())
            vals = ','.join(['"{}"'.format(c) for c in billing.values()])
            billing_sql = 'insert into billing ({}) values({})'.format(keys, vals)
            cur.execute(billing_sql)
            conn.commit()

    def del_online(self, nas_addr, acct_session_id):
        with Connect(self.dbpool) as conn:
            cur = conn.cursor()
            sql = '''delete from online where nas_addr = "{}" and 
                acct_session_id = "{}"'''.format(nas_addr, acct_session_id)
            cur.execute(sql)
            conn.commit()

    def add_ticket(self, ticket):
        _ticket = ticket.copy()
        for _key in _ticket:
            if _key not in ticket_fds:
                del ticket[_key]
        with Connect(self.dbpool) as conn:
            cur = conn.cursor()
            keys = ','.join(ticket.keys())
            vals = ','.join(['"{}"'.format(c) for c in ticket.values()])
            sql = 'insert into ticket ({}) values({})'.format(keys, vals)
            cur.execute(sql)
            conn.commit()

    def unlock_online(self, nas_addr, acct_session_id, stop_source):
        bsql = '''insert into ticket (
            user, acct_session_id, acct_start_time, nas_addr, framed_ipaddr, start_source,
            acct_session_time, acct_stop_time, stop_source) values(
            "{}", "{}", "{}", "{}", "{}", "{}", "{}", "{}", "{}")
        '''
        def _ticket(online):
            ticket = []
            ticket.append(online['user'])
            ticket.append(online['acct_session_id'])
            ticket.append(online['acct_start_time'])
            ticket.append(online['nas_addr'])
            ticket.append(online['framed_ipaddr'])
            ticket.append(online['start_source'])
            _datetime = datetime.datetime.now()
            _starttime = datetime.datetime.strptime(online['acct_start_time'], '%Y-%m-%d %H:%M:%S')
            session_time = (_datetime - _starttime).seconds
            stop_time = _datetime.strftime('%Y-%m-%d %H:%M:%S')
            ticket.append(session_time)
            ticket.append(stop_time)
            ticket.append(stop_source)
            return ticket

        def _unlock_one():
            ticket = None
            with Connect(self.dbpool) as conn:
                cur = conn.cursor(MySQLdb.cursors.DictCursor)
                sql = 'select * from online where nas_addr = "{}" and \
                        acct_session_id = "{}"'.format(nas_addr, acct_session_id)
                cur.execute(sql)
                online = cur.fetchone()
                if online:
                    ticket = _ticket(online)
                    dsql = 'delete from online where nas_addr = "{}" and \
                            acct_session_id = "{}"'.format(nas_addr, acct_session_id)
                    cur.execute(dsql)
                    cur.execute(bsql, ticket)
                    conn.commit()

        def _unlock_many():
            tickets = None
            with Connect(self.dbpool) as conn:
                cur = conn.cursor(MySQLdb.cursors.DictCursor)
                sql = 'select * from online where nas_addr = "{}" and \
                        acct_session_id = "{}"'.format(nas_addr, acct_session_id)
                cur.execute(sql)
                for online in cur:
                    tickets.append(_ticket(online))
                if tickets:
                    cur.executemany(bsql, tickets)
                    cur.execute('delete from online where nas_addr = "{}"'.format(nas_addr))
                    conn.commit()
        if acct_session_id:
            _unlock_one()
        else:
            _unlock_many()


store = Store()
