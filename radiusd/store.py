#!/usr/bin/env python
import logging

#coding=utf-8
# from DBUtils.PooledDB import PooledDB
from DBUtils.PersistentDB import PersistentDB
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
    'session_timeout', 'start_source', 'stop_source', 'mac_addr', 'ap_mac'
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
        self.dbpool = PersistentDB(
            creator=MySQLdb,
            db=config['db'],
            host=config['host'],
            port=config['port'],
            user=config['user'],
            passwd=config['passwd'],
            charset=config['charset'],
            maxusage=config['maxusage'],
            # MySQLdb support, version > 1.2.5, mysql > 5.1.12
            read_timeout=config['read_timeout'],
            write_timeout=config['write_timeout'],
        )

    def cursor(self, conn):
        return conn.cursor(MySQLdb.cursors.DictCursor)

    def connect(self):
        return self.dbpool.connection()

pool_class = {'mysql':MySQLPool}

class Store():
    def setup(self, db_config):
        self.dbpool = MySQLPool(db_config)
        # global __cache_timeout__
        # __cache_timeout__ = config['cache_timeout']

    def _combine_query_kwargs(self, **kwargs):
        '''
            convert query kwargs to str
        '''
        query_list = []
        for key, value in kwargs.iteritems():
            if isinstance(value, int):
                query_list.append('{}={}'.format(key, value))
            else:
                query_list.append('{}="{}"'.format(key, value))

        return ' and '.join(query_list) 


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

    def get_appid(self, appid):
        '''
        '''
        with Cursor(self.dbpool) as cur:
            cur.execute('select * from app where appid = "{}"'.format(appid))
            record = cur.fetchone()
            return record

    def get_account_by_mobile_or_mac(self, mobile, mac):
        with Cursor(self.dbpool) as cur:
            # search account by mobile
            if mobile:
                sql = '''select bd_account.*, account.mobile as amobile from bd_account 
                left join account on bd_account.user=cast(account.id as char)  
                where account.mobile="{}"'''.format(mobile)
                cur.execute(sql)

                result = cur.fetchone()
                if result:
                    return result
            
            # search account by mac_history
            if mac:
                sql = '''select bd_account.*, account.mobile as amobile from bd_account 
                left join mac_history on bd_account.user=mac_history.user 
                left join account on bd_account.user=cast(account.id as char) 
                where mac_history.mac="{}" order by account.ctime'''.format(mac)
                cur.execute(sql)
                result = cur.fetchone()
                if result: 
                    return result
                # check uuid
                cur.execute('select bd_account.*, account.mobile as amobile from bd_account \
                            right join account on bd_account.user=cast(account.id as char) \
                            where account.uuid=%s', (mac,))
                result = cur.fetchone()
                return result


            return None

    def get_account_by_mobile(self, mobile, mac):
        with Cursor(self.dbpool) as cur:
            # mask = 2**1 + 2**8 + 2**9
            sql = 'select * from bd_account where mobile="{}"'.format(mobile)
            
            cur.execute(sql)

            return cur.fetchone()

    def get_account_by_mac(self, mac):
        with Cursor(self.dbpool) as cur:
            cur.execute('select account.* from account where uuid=%s', (mac,))
            _account = cur.fetchone()
            if not _account:
                cur.execute('select account.* from account \
                            left join mac_history on mac_history.user=cast(account.id as char) \
                            where mac_history.mac=%s', (mac,))
                _account = cur.fetchone()

            if _account:
                cur.execute('select * from bd_account where user=%s', (str(_account['id']),))
                return cur.fetchone()

            return None

    def add_renter(self, user, password, holder, mobile=''):
        with Connect(self.dbpool) as conn:
            cur = conn.cursor(MySQLdb.cursors.DictCursor)
            mask = 1+ 2**9 + 2**10

            sql = '''insert into bd_account (user, password, mobile, mask, coin, holder, ends) 
            values("{}", "{}", "{}", {}, 0, {}, 2)
            '''.format(user, password, mobile, mask, holder)

            cur.execute(sql)
            sql = 'select * from bd_account where user="{}"'.format(user)
            cur.execute(sql)
            record = cur.fetchone()
            cur.commit()

            return record
        
    def add_user(self, user, password, appid='', tid='', mobile='', ends=2**5):
        '''
            user : uuid or weixin openid
            password : user encrypted password
            ends : special the end type         data
                0 : unknown                     
                2^5 : weixin                      opendid

                2^6 : app(android)                opendid or other unique id 
                2^7 : app(ios)
                2^8 : mobile (verify mobile number)

                2**28 : acount forzened
                # 4 : web                         token & account
        '''
        with Connect(self.dbpool) as conn:
            cur = conn.cursor(MySQLdb.cursors.DictCursor)
            now = datetime.datetime.now()
            expired = now + datetime.timedelta(hours=6)
            now = now.strftime('%Y-%m-%d %H:%M:%S')
            expired = expired.strftime('%Y-%m-%d %H:%M:%S')
            sql, filters = '', ''
            column = 'uuid'
            if ends>>6 & 1:
                weixin, uuid = '', user
                mask = 0 + 2**2 + 2**6
                sql = 'insert into account (uuid, mask) values ("{}", {})'.format(user, mask)
                filters = 'account.uuid="{}" and account.mask={}'.format(user, mask)
            elif ends>>7 & 1:
                mask = 0 + 2**2 + 2**7
                sql = 'insert into account (uuid, mask) values ("{}", {})'.format(user, mask)
                filters = 'account.uuid="{}" and account.mask={}'.format(user, mask)
            elif ends>>8 & 1:
                column = 'mobile'
                mask = 0 + 2**2 + 2**8
                sql = 'insert into account (mobile, mask) values ("{}", {})'.format(mobile, mask)
                filters = 'account.mobile="{}" and account.mask={}'.format(user, mask)
            elif (ends>>5 & 1) and appid:
                # from weixin
                column = 'weixin'
                mask = 0 + 2**2 + 2**5
                sql = 'insert into account (appid, weixin, tid, mask)values ("{}", "{}", "{}", {})'.format(appid, user, tid, mask)
                filters = 'account.weixin="{}" and account.appid="{}" and account.mask={}'.format(user, appid, mask)

            cur.execute(sql)

            sql = 'select id from account where {} = "{}"'.format(column, user)
            if appid:
                sql = sql + ' and appid="{}"'.format(appid)

            cur.execute(sql)
            user = cur.fetchone()
            #
            # mask = mask + 2**9
            coin = 60
            user = str(user['id'])

            sql = '''insert into bd_account (user, password, mask, coin, expired, holder, ends, mobile) 
            values("{}", "{}", {}, {}, "{}", 0, 2, "{}")
            '''.format(user, password, mask, coin, expired, mobile)
            cur.execute(sql)

            sql = '''select bd_account.* from bd_account 
            left join account on bd_account.user=cast(account.id as char) 
            where {}'''.format(filters)
            cur.execute(sql)
            user = cur.fetchone()
            conn.commit()

            return user

    def get_bd_user(self, user, password=None, ismac=False):
        '''
            support auto login, user may be mac address or user account
            user:
                account
                mac : [##:##:##:##:##:##]
        '''
        with Cursor(self.dbpool) as cur:
            sql = ''
            if ismac:
            # if user.count(':') == 5:
                sql = '''select bd_account.*, mac_history.ssid, mac_history.expired as auto_expired from bd_account 
                left join mac_history on bd_account.user=mac_history.user 
                where mac_history.mac="{}" order by bd_account.expired desc, mac_history.expired desc'''.format(user)
            else:
                sql = 'select * from bd_account where user = "{}"'.format(user)
                if password:
                    sql = sql + ' and password = "{}"'.format(password)
            cur.execute(sql)
            user = cur.fetchone()
            if user and user['mask'] and user['mask']>>5 & 1:
                # query weixin account binded renter
                sql = 'select * from bind where weixin = "{}"'.format(user)
                cur.execute(sql)
                record = cur.fetchone()
                if record:
                    sql = 'select expired, ends from bd_account where user = "{}"'.format(record['renter'])
                    cur.execute(sql)
                    ret = cur.fetchone()
                    if ret:
                        user['expired'] = ret['expired']
                        user['ends'] = ret['ends']
            return user

    # def get_pn_bd_user(self, user, pn):
    #     with Cursor(self.dbpool) as cur:
    #         sql = 'select * from bd_account where user = "{}"'.format(user)
    #         cur.execute(sql)
    #         user = cur.fetchone()


    def get_bd_user2(self, user, password=None, ismac=False):
        '''
            support auto login, user may be mac address or user account
            user:
                account
                mac : [##:##:##:##:##:##]
        '''
        # with Cursor(self.dbpool) as cur:
        with Connect(self.dbpool) as conn:
            conn.commit()
            cur = conn.cursor(MySQLdb.cursors.DictCursor)
            sql = ''
            if ismac:
            # if user.count(':') == 5:
                sql = '''select bd_account.*, mac_history.expired as auto_expired from bd_account 
                left join mac_history on bd_account.user=mac_history.user 
                where mac_history.mac="{}" order by bd_account.expired desc, mac_history.expired desc'''.format(user)
            else:
                sql = 'select * from bd_account where user = "{}"'.format(user)
                if password:
                    sql = sql + ' and password = "{}"'.format(password)
            cur.execute(sql)
            user = cur.fetchone()
            return user

    def update_bd_user(self, user, **kwargs):
        with Connect(self.dbpool) as conn:
            cur = conn.cursor(MySQLdb.cursors.DictCursor)
            update_str = ', '.join(['{}="{}"'.format(key, value) for key,value in kwargs.iteritems()])
            sql = 'update bd_account set {} where user="{}"'.format(update_str, user)
            cur.execute(sql)

            if 'mobile' in kwargs:
                sql = 'update account set mobile="{}" where id={}'.format(kwargs['mobile'], user)
                cur.execute(sql)

            conn.commit()

    def get_account(self, uuid):
        '''
            get account's info
        '''
        with Cursor(self.dbpool) as cur:
            sql = '''select bd_account.*, account.mask as amask, account.realname, account.address
            from bd_account 
            left join account on bd_account.user=cast(account.id as char)  
            where account.uuid="{}"'''.format(uuid)
            cur.execute(sql)
            return cur.fetchone()

    def get_account2(self, _id):
        with Cursor(self.dbpool) as cur:
            cur.execute('select * from account where id=%s', (_id,))
            return cur.fetchone()


    def get_weixin_user(self, openid, appid, mac):
        '''
            1. get weixin account by openid & appid
            2. get account by mac where weixin column is ''
            3. else return None
        '''
        with Cursor(self.dbpool) as cur:
            # get account by openid & appid
            sql = '''select bd_account.*, account.weixin, account.tid, account.appid from bd_account 
            left join account on bd_account.user=cast(account.id as char)  
            where account.weixin="{}" and account.appid="{}"'''.format(openid, appid)
            cur.execute(sql)
            result = cur.fetchone()
            if result:
                return result

            if mac:
                # get account by uuid (android)
                sql = '''select bd_account.*, account.weixin, account.tid, account.appid from bd_account 
                left join account on bd_account.user=cast(account.id as char) 
                where account.uuid="{}" and account.mask>>6&1'''.format(mac)
                cur.execute(sql)
                result = cur.fetchone()
                if result:
                    return result

                # get account by mac address
                sql = '''select bd_account.*, account.weixin, account.tid, account.appid from bd_account 
                left join mac_history on bd_account.user=mac_history.user 
                left join account on bd_account.user=cast(account.id as char) 
                where mac_history.mac="{}" and account.weixin is null order by account.ctime'''.format(mac)
                print(sql)
                cur.execute(sql)

                return cur.fetchone()

            return None

    def get_gw_pn_policy(self, gw_ip):
        '''
        '''
        with Cursor(self.dbpool) as cur:
            sql = 'select * from gw_bind where ip="{}"'.format(gw_ip)
            cur.execute(sql)
            result = cur.fetchone()
            if not result:
                return None

            pn = result['_location'].split(',')[-1]

            sql = 'select * from pn_policy where pn={}'.format(pn)
            cur.execute(sql)
            return cur.fetchone()

    def update_account(self, _id, **kwargs):
        '''
            update account's column
        '''
        with Connect(self.dbpool) as conn:
            cur = conn.cursor(MySQLdb.cursors.DictCursor)
            kwargs.pop('id', '')
            if kwargs:
                modify_str = ', '.join(['{}="{}"'.format(key,value) for key,value in kwargs.items()])
                sql = 'update account set {} where id={}'.format(modify_str, _id)
                cur.execute(sql)

                mobile = kwargs.get('mobile', '')
                if mobile:
                    sql = 'update bd_account set mobile={} where user="{}"'.format(mobile, _id)
                    cur.execute(sql)
                conn.commit()

    def update_bd_account(self, user, mobile):
        with Connect(self.dbpool) as conn:
            cur = conn.cursor(MySQLdb.cursors.DictCursor)
            sql = 'update bd_account set mobile={} where user="{}"'.format(mobile, user)
            cur.execute(sql)
            conn.commit()


    def check_pn_privilege(self, pn, user):
        '''
        '''
        with Cursor(self.dbpool) as cur:
            sql = '''select pn_{pn}.mask, pn_{pn}.name, pn_{pn}.mobile from pn_{pn} 
            left join bd_account on pn_{pn}.mobile=bd_account.mobile 
            where bd_account.user="{user}" and bd_account.mobile'''.format(pn=pn, user=user)
            cur.execute(sql)
            return cur.fetchone()

    def update_mac_record(self, user, mac, expired, agent, device, ssid, isupdate=True):
        with Connect(self.dbpool) as conn:
            cur = conn.cursor()
            # now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            if isupdate:
                sql = 'update mac_history set expired=%s, platform=%s, phone_type=%s, ssid=%s where user=%s and mac=%s'
                args = (expired, agent, device, ssid, user, mac)
            else:
                sql = 'insert into mac_history (user, mac, expired, platform, phone_type, ssid) values(%s, %s, %s, %s, %s, %s)'
                args = (user, mac, expired, agent, device, ssid)
            # if isupdate:
            #     sql = '''update mac_history set expired="{}", platform = "{}", device="{}", ssid="{}"  
            #     where user = "{}" and mac = "{}"'''.format(expired, agent, ssid, user, mac)
            # else:
            #     sql = '''insert into mac_history (user, mac, expired, platform, phone_type, ssid) 
            #     values("{}", "{}", "{}", "{}", "{}")'''.format(user, mac, expired, agent, device, ssid)
            # cur.execute(sql)
            cur.execute(sql, args)
            conn.commit()

    def delete_mac_record(self, user, mac):
        with Connect(self.dbpool) as conn:
            cur = conn.cursor()
            cur.execute('delete from mac_history where user="%s" or mac="%s"', user, mac)
            conn.commit()


    def query_pn_policy(self, **kwargs):
        '''
            query network profile
        '''
        with Cursor(self.dbpool) as cur:
            query_str = self._combine_query_kwargs(**kwargs)
            sql = 'select * from pn_policy where {}'.format(query_str)

            cur.execute(sql)
            return cur.fetchone()

    def query_ap(self, ap_mac):
        '''
        '''
        with Cursor(self.dbpool) as cur:
            assert ap_mac
            cur.execute('select `_location` from ap where `mac` = %s', (ap_mac,))
            return cur.fetchone()

    def get_pn_user(self, pn, name, mobile):
        with Cursor(self.dbpool) as cur:
            sql = 'select * from pn_{} where name="{}" and mobile="{}"'.format(pn, name, mobile)
            cur.execute(sql)

            return cur.fetchone()


    def get_user_mac_record(self, user, mac):
        '''
        '''
        with Cursor(self.dbpool) as cur:
            sql = 'select * from mac_history where user = "{}" and mac="{}"'.format(user, mac)
            cur.execute(sql)
            return cur.fetchone()


    def is_online(self, nas_addr, acct_session_id):
        '''
        '''
        with Cursor(self.dbpool) as cur:
            sql = 'select count(mac_addr) as online from online where \
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

    def get_onlines(self, user, macs):
        '''
        '''
        with Cursor(self.dbpool) as cur:
            sql = '''select nas_addr, acct_session_id, acct_start_time, mac_addr, ap_mac, 
            ssid, framed_ipaddr from online where user = "{}"'''.format(user)
            if macs:
                macs = ','.join(['"{}"'.format(mac) for mac in macs])
                sql = sql + ' and mac_addr in ({})'.format(macs)
            cur.execute(sql)
            return cur.fetchall()

    def get_online(self, nas_addr, acct_session_id):
        with Cursor(self.dbpool) as cur:
            sql = 'select * from online where \
                    nas_addr = "{}" and acct_session_id = "{}"'.format(nas_addr, acct_session_id)
            cur.execute(sql)
            return cur.fetchone()

    def get_online2(self, nas_addr, user_mac):
        with Cursor(self.dbpool) as cur:
            cur.execute('select * from online where nas_addr=%s and mac_addr=%s', (nas_addr, user_mac))
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

            sql = 'delete from online where mac_addr = "{}"'.format(online['mac_addr'])
            cur.execute(sql)

            keys = ','.join(online.keys())
            vals = ','.join(['"%s"'%c for c in online.values()])
            sql = 'insert into online ({}) values({})'.format(keys, vals)
            cur.execute(sql)
            conn.commit()

    def add_online2(self, user, nas_addr, ap_mac, mac, user_ip, _location, ssid):
        with Connect(self.dbpool) as conn:
            cur = conn.cursor(MySQLdb.cursors.DictCursor)

            sql = 'delete from online where mac_addr = "{}"'.format(mac)
            cur.execute(sql)

            sql = '''insert into online (user, nas_addr, ap_mac, mac_addr, framed_ipaddr, _location, ssid) 
            values("{}", "{}", "{}", "{}", "{}", "{}", "{}")'''.format(user, nas_addr, ap_mac, mac, user_ip, _location, ssid)
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

    def delete_online2(self, mac):
        '''
            mac : '##:##:##:##:##:##'
        '''
        with Connect(self.dbpool) as conn:
            cur = conn.cursor()
            cur.execute('delete from online where mac_addr="{}"'.format(mac))
            conn.commit()

    def update_billing(self, billing):
        '''  '''
        with Connect(self.dbpool) as conn:
            cur = conn.cursor()
            # update account
            # balance_sql = '''update bd_account set
            #     coin = {} where user = "{}"
            # '''.format(coin, billing['user'])
            # cur.execute(balance_sql)

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
        '''
        '''
        with Connect(self.dbpool) as conn:
            cur = conn.cursor(MySQLdb.cursors.DictCursor)

            sql = '''delete from online where nas_addr = "{}" and 
                acct_session_id = "{}"'''.format(nas_addr, acct_session_id)
            cur.execute(sql)
            conn.commit()

    def del_online2(self, nas_addr, mac_addr):
        with Connect(self.dbpool) as conn:
            cur = conn.cursor(MySQLdb.cursors.DictCursor)
            sql = 'select * from online where nas_addr="{}" and mac_addr="{}"'.format(nas_addr, mac_addr)
            cur.execute(sql)
            result = cur.fetchone()
            if not result:
                return

            sql = '''insert into ticket (user, nas_addr, ap_mac, mac_addr, acct_start_time) 
            values("{}", "{}", "{}", "{}", "{}")
            '''.format(result['user'], result['nas_addr'], result['ap_mac'], result['mac_addr'], result['acct_start_time'])
            cur.execute(sql)


            sql = 'delete from online where nas_addr = "{}" and mac_addr = "{}"'.format(nas_addr, mac_addr)
            cur.execute(sql)
            conn.commit()

    def del_online3(self, nas_addr, user_ip):
        with Connect(self.dbpool) as conn:
            cur = conn.cursor(MySQLdb.cursors.DictCursor)
            # sql = 'select * from online where nas_addr="{}" and framed_ipaddr="{}"'.format(nas_addr, user_ip)
            # cur.execute(sql)
            # result = cur.fetchone()
            # if not result:
            #     return

            # sql = '''insert into ticket (user, nas_addr, ap_mac, mac_addr, acct_start_time) 
            # values("{}", "{}", "{}", "{}", "{}")
            # '''.format(result['user'], result['nas_addr'], result['ap_mac'], result['mac_addr'], result['acct_start_time'])
            # cur.execute(sql)

            sql = 'delete from online where nas_addr = "{}" and framed_ipaddr = "{}"'.format(nas_addr, user_ip)
            cur.execute(sql)
            conn.commit()

    def clear_user_records(self, user, macs):
        '''
            macs: "mac1","macs2"
        '''
        with Connect(self.dbpool) as conn:
            cur = conn.cursor(MySQLdb.cursors.DictCursor)

            # remove mac_history records
            sql = 'delete from mac_history where user="{}"'.format(user)
            if macs:
                sql += ' and mac in ({})'.format(macs)
            cur.execute(sql)
            # clear online records
            sql = 'delete from online where user="{}"'.format(user)
            if macs:
                sql += ' and mac_addr in ({})'.format(macs)
            cur.execute(sql)

            conn.commit()

    def add_online_record(self, user, mac, ap_mac, ssid):
        '''
            id : auto_increment
        '''
        with Connect(self.dbpool) as conn:
            cur = conn.cursor(MySQLdb.cursors.DictCursor)
            
            sql = '''insert into online_records (user, mac, ap_mac, ssid) 
            values("{}", "{}", "{}", "{}")'''.format(user, mac, ap_mac, ssid)
            cur.execute(sql)

            sql = 'select id from online_records where user="{}" and mac="{}" order by start desc'.format(user, mac)
            cur.execute(sql)

            _id = cur.fetchone()['id']
            conn.commit()

            return _id


    def update_online_record(self, _id, stop, user, mac, ap_mac, ssid, pre_ap_mac):
        '''
        '''
        with Connect(self.dbpool) as conn:
            cur = conn.cursor(MySQLdb.cursors.DictCursor)
            _id = _id

            sql = 'update online_records set stop="{}" where id={}'.format(stop, _id)
            cur.execute(sql)
            if ap_mac != pre_ap_mac:
                # ap changed
                sql = '''insert into online_records (user, mac, ap_mac, ssid) 
                values("{}", "{}", "{}", "{}")'''.format(user, mac, ap_mac, ssid)
                cur.execute(sql)
                sql = 'select id from online_records where user="{}" and mac="{}" order by start desc'.format(user, mac)
                cur.execute(sql)

                _id = cur.fetchone()['id']

            conn.commit()
            return _id

    def create_portal_tmp(self, name, title, h5_pic, pc_pic, mask):
        '''
        '''
        with Connect(self.dbpool) as conn:
            cur = conn.cursor(MySQLdb.cursors.DictCursor)
            sql = 'insert into portal_tmp (name, title, h5_pic, pc_pic, mask) values("{}", "{}", "{}", "{}", {})'.format(name, title, h5_pic, pc_pic, mask)
            cur.execute(sql)

            conn.commit()

    def update_portal_tmp(self, name, **kwargs):
        with Connect(self.dbpool) as conn:
            cur = conn.cursor(MySQLdb.cursors.DictCursor)
            update_str = ', '.join(['{}="{}"'.format(key, value) for key,value in kwargs.iteritems()])
            sql = 'update portal_tmp set {} where name="{}"'.format(update_str, name)
            cur.execute(sql)

            conn.commit()

    def delete_portal_tmp(self, name):
        with Connect(self.dbpool) as conn:
            cur = conn.cursor(MySQLdb.cursors.DictCursor)
            sql = 'delete from portal_tmp where name="{}"'.format(name) 
            cur.execute(sql)

            conn.commit()

    def get_portal_tmp(self, name):
        with Cursor(self.dbpool) as cur:
            sql = 'select * from portal_tmp'
            if name:
                sql += ' where name="{}"'.format(name)
            cur.execute(sql)
            results = cur.fetchall()
            return results if results else []

    # ************************************************
    #
    # app version operator
    #
    # ************************************************ 
    def add_app_version(self, pt, version, note):
        '''
        '''
        with Connect(self.dbpool) as conn:
            cur = conn.cursor(MySQLdb.cursors.DictCursor)
            sql = 'insert into app_ver (pt, newest, least, note) values("{}", "{}", "{}", "{}")'.format(pt, version, version, note)
            cur.execute(sql)
            conn.commit()

    def update_app_version(self, pt, **kwargs):
        '''
        '''
        with Connect(self.dbpool) as conn:
            cur = conn.cursor(MySQLdb.cursors.DictCursor)
            modify_str = ', '.join('{} = "{}"'.format(key, value) for key,value in kwargs.iteritems())
            sql = 'update app_ver set {} where pt = {}'.format(modify_str, pt)
            cur.execute(sql)
            conn.commit()

    def get_app_version(self, pt):
        with Cursor(self.dbpool) as cur:
            cur.execute('select * from app_ver where pt="{}"'.format(pt))
            return cur.fetchone()

    def query_avaiable_pns(self, user, mobile):
        '''
        '''
        with Cursor(self.dbpool) as cur:
            sql = '''select pn_policy.* from pn_policy 
            right join information_schema.tables on concat('pn_', `pn`) = information_schema.tables.table_name 
            where pn_policy.policy&2
            '''
            cur.execute(sql)
            tables = cur.fetchall()

            results = []
            for item in tables:
                sql = 'select id from pn_{} where mobile="{}"'.format(item['pn'], mobile)
                cur.execute(sql)
                if cur.fetchone():
                    results.append(item)

            return results


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
